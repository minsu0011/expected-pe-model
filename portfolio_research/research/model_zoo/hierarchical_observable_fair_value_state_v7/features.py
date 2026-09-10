"""Causal feature and identity adapter for H-OFS V7.

Lag/history groups are fixed to the production entity key before any research
DGP or seed labels are considered.  No caller-controlled grouping argument is
accepted, closing the group-partition defect found in H-OFS V1.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

import numpy as np
import pandas as pd

from research.model_zoo.observable_fair_value_state_v1.features import (
    generate_observable_state_features,
)

from .contracts import (
    DGP_MEMBERSHIP_COLUMN,
    DGP_MEMBERSHIP_COLUMNS,
    EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY,
    FORBIDDEN_INFERENCE_COLUMNS,
    IDENTITY_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    OFFSET_COLUMN,
    PARENT_FEATURE_CONTRACT_SHA256,
    PARENT_TO_MODEL_FEATURE,
    REGIME_COLUMNS,
    REGIME_FALLBACK_MAX_COUNT,
    REGIME_FALLBACK_MAX_FRACTION,
    REGIME_RENORMALIZATION_ABS_TOLERANCE,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
)
from .validation import (
    require_exact_int,
    require_exact_str,
    require_exact_tuple,
    require_sha256,
)


@dataclass(frozen=True)
class HierarchicalStateFrameV7:
    """Compact causal feature surface with one-to-one entity/date custody."""

    features: pd.DataFrame
    identities: pd.DataFrame
    entity_source_column: str
    parent_group_columns: tuple[str, ...]
    parent_contract_sha256: str
    warm_rows: int
    expected_regime_warmup_prefix_count: int
    expected_regime_warmup_prefix_sha256: str
    expected_regime_warmup_prefix_mask: pd.Series
    regime_fallback_count: int
    regime_renormalized_count: int
    regime_fallback_mask: pd.Series
    regime_renormalized_mask: pd.Series
    state_binding_sha256: str

    def __post_init__(self) -> None:
        if type(self.features) is not pd.DataFrame or type(self.identities) is not pd.DataFrame:
            raise HierarchicalStateV7ContractError("state frames require exact DataFrame types")
        if (
            type(self.expected_regime_warmup_prefix_mask) is not pd.Series
            or type(self.regime_fallback_mask) is not pd.Series
            or type(self.regime_renormalized_mask) is not pd.Series
        ):
            raise HierarchicalStateV7ContractError("state masks require exact Series types")
        object.__setattr__(self, "features", self.features.copy(deep=True))
        object.__setattr__(self, "identities", self.identities.copy(deep=True))
        object.__setattr__(
            self,
            "expected_regime_warmup_prefix_mask",
            self.expected_regime_warmup_prefix_mask.copy(deep=True),
        )
        object.__setattr__(self, "regime_fallback_mask", self.regime_fallback_mask.copy(deep=True))
        object.__setattr__(
            self,
            "regime_renormalized_mask",
            self.regime_renormalized_mask.copy(deep=True),
        )
        self.assert_live_integrity()

    def assert_live_integrity(self) -> None:
        """Revalidate every mutable frame/mask and its comprehensive binding."""

        require_exact_str(self.entity_source_column, label="state entity source")
        require_exact_tuple(self.parent_group_columns, label="state parent groups")
        if any(type(value) is not str for value in self.parent_group_columns):
            raise HierarchicalStateV7ContractError("state parent groups require exact strings")
        require_sha256(self.parent_contract_sha256, label="state parent contract")
        require_sha256(self.state_binding_sha256, label="state binding")
        require_exact_int(self.warm_rows, label="state warm rows", minimum=0)
        require_exact_int(
            self.expected_regime_warmup_prefix_count,
            label="state expected regime warmup count",
            minimum=0,
        )
        require_sha256(
            self.expected_regime_warmup_prefix_sha256,
            label="state expected regime warmup hash",
        )
        require_exact_int(self.regime_fallback_count, label="state fallback count", minimum=0)
        require_exact_int(
            self.regime_renormalized_count,
            label="state renormalized count",
            minimum=0,
        )
        if tuple(self.features.columns) != MODEL_FEATURE_COLUMNS:
            raise HierarchicalStateV7ContractError("H-OFS V7 feature schema drifted")
        if tuple(self.identities.columns) != IDENTITY_COLUMNS:
            raise HierarchicalStateV7ContractError("H-OFS V7 identity schema drifted")
        if self.features.columns.has_duplicates or not self.features.index.is_unique:
            raise HierarchicalStateV7ContractError("feature schema and index must be unique")
        if self.identities.columns.has_duplicates or not self.identities.index.is_unique:
            raise HierarchicalStateV7ContractError("identity schema and index must be unique")
        if not self.features.index.equals(self.identities.index):
            raise HierarchicalStateV7ContractError("features and identities are not index-bound")
        validated_identities = validate_bound_identities(
            self.identities, expected_index=self.features.index
        )
        if not self.identities.equals(validated_identities):
            raise HierarchicalStateV7ContractError("state identities are not canonical")
        if self.identities.duplicated(list(IDENTITY_COLUMNS)).any():
            raise HierarchicalStateV7ContractError("entity/date identity must be one-to-one")
        if self.parent_group_columns != (self.entity_source_column,):
            raise HierarchicalStateV7ContractError("history grouping is not fixed to entity only")
        if self.parent_contract_sha256 != PARENT_FEATURE_CONTRACT_SHA256:
            raise HierarchicalStateV7ContractError("parent feature contract receipt drifted")
        if self.warm_rows > len(self.features):
            raise HierarchicalStateV7ContractError("warm row count is invalid")
        if self.expected_regime_warmup_prefix_count > len(self.features):
            raise HierarchicalStateV7ContractError(
                "expected regime warmup prefix receipt is invalid"
            )
        if self.regime_fallback_count > len(self.features):
            raise HierarchicalStateV7ContractError("regime fallback receipt is invalid")
        if self.regime_renormalized_count > len(self.features):
            raise HierarchicalStateV7ContractError("regime renormalization receipt is invalid")
        for label, mask, count in (
            (
                "expected warmup",
                self.expected_regime_warmup_prefix_mask,
                self.expected_regime_warmup_prefix_count,
            ),
            ("fallback", self.regime_fallback_mask, self.regime_fallback_count),
            (
                "renormalized",
                self.regime_renormalized_mask,
                self.regime_renormalized_count,
            ),
        ):
            if (
                type(mask) is not pd.Series
                or mask.dtype != bool
                or not mask.index.equals(self.features.index)
                or int(mask.sum()) != count
            ):
                raise HierarchicalStateV7ContractError(
                    f"regime {label} row-mask receipt is invalid"
                )
        _validate_expected_warmup_geometry(
            self.identities,
            self.expected_regime_warmup_prefix_mask,
        )
        expected_warmup_sha256 = _expected_regime_warmup_prefix_sha256(
            self.identities,
            self.expected_regime_warmup_prefix_mask,
        )
        if self.expected_regime_warmup_prefix_sha256 != expected_warmup_sha256:
            raise HierarchicalStateV7ContractError("expected regime warmup prefix hash drifted")
        if bool((self.expected_regime_warmup_prefix_mask & self.regime_fallback_mask).any()):
            raise HierarchicalStateV7ContractError(
                "expected warmup and unexpected fallback masks overlap"
            )
        if any(dtype != np.dtype("float64") for dtype in self.features.dtypes):
            raise HierarchicalStateV7ContractError("state features require exact float64 columns")
        if np.isinf(self.features.to_numpy(dtype=np.float64)).any():
            raise HierarchicalStateV7ContractError("feature frame contains infinity")
        expected = _state_binding_sha256_v7(
            self.features,
            self.identities,
            entity_source_column=self.entity_source_column,
            parent_group_columns=self.parent_group_columns,
            parent_contract_sha256=self.parent_contract_sha256,
            warm_rows=self.warm_rows,
            expected_regime_warmup_prefix_count=(self.expected_regime_warmup_prefix_count),
            expected_regime_warmup_prefix_sha256=(self.expected_regime_warmup_prefix_sha256),
            expected_regime_warmup_prefix_mask=(self.expected_regime_warmup_prefix_mask),
            regime_fallback_count=self.regime_fallback_count,
            regime_renormalized_count=self.regime_renormalized_count,
            regime_fallback_mask=self.regime_fallback_mask,
            regime_renormalized_mask=self.regime_renormalized_mask,
        )
        if self.state_binding_sha256 != expected:
            raise HierarchicalStateV7ContractError("state feature/identity binding drifted")


def _resolve_fixed_entity_column(source: pd.DataFrame) -> str:
    if "entity_id" in source.columns:
        return "entity_id"
    if "symbol" in source.columns:
        return "symbol"
    raise HierarchicalStateV7ContractError("source requires entity_id or symbol")


def _strict_string_series(values: pd.Series, *, label: str) -> pd.Series:
    raw = values.to_numpy(dtype=object)
    if any(type(value) is not str for value in raw):
        raise HierarchicalStateV7ContractError(
            f"{label} requires exact Python str values without coercion"
        )
    if any(not value.strip() for value in raw):
        raise HierarchicalStateV7ContractError(f"{label} cannot be blank")
    return values.copy()


def _bound_identities(source: pd.DataFrame, entity_column: str) -> pd.DataFrame:
    entities = _strict_string_series(source[entity_column], label="entity identity")
    dates = pd.to_datetime(source["date"], errors="coerce")
    if dates.isna().any():
        raise HierarchicalStateV7ContractError("decision date identity is invalid")
    if getattr(dates.dt, "tz", None) is not None:
        raise HierarchicalStateV7ContractError("decision dates must be timezone-naive")
    identities = pd.DataFrame(
        {
            IDENTITY_COLUMNS[0]: entities.to_numpy(dtype=object, copy=True),
            IDENTITY_COLUMNS[1]: dates.to_numpy(dtype="datetime64[ns]"),
        },
        index=source.index.copy(),
    )
    if identities.duplicated(list(IDENTITY_COLUMNS)).any():
        raise HierarchicalStateV7ContractError("each entity/date identity must be unique")
    return identities


def validate_bound_identities(
    identities: pd.DataFrame,
    *,
    expected_index: pd.Index,
) -> pd.DataFrame:
    """Return a defensive identity copy after exact index and key validation."""

    if type(identities) is not pd.DataFrame:
        raise HierarchicalStateV7ContractError("identities must be a DataFrame")
    if not isinstance(expected_index, pd.Index):
        raise HierarchicalStateV7ContractError("expected identity index must be a pandas Index")
    if tuple(identities.columns) != IDENTITY_COLUMNS:
        raise HierarchicalStateV7ContractError("identities require the exact entity/date schema")
    if not identities.index.equals(expected_index):
        raise HierarchicalStateV7ContractError("identities are not bound to the feature index")
    if identities.columns.has_duplicates or not identities.index.is_unique:
        raise HierarchicalStateV7ContractError("identity schema and index must be unique")
    output = identities.copy()
    output[IDENTITY_COLUMNS[0]] = _strict_string_series(
        output[IDENTITY_COLUMNS[0]], label="entity identity"
    )
    dates = pd.to_datetime(output[IDENTITY_COLUMNS[1]], errors="coerce")
    if dates.isna().any() or getattr(dates.dt, "tz", None) is not None:
        raise HierarchicalStateV7ContractError("decision identity dates are invalid")
    output[IDENTITY_COLUMNS[1]] = dates.to_numpy(dtype="datetime64[ns]")
    if output.duplicated(list(IDENTITY_COLUMNS)).any():
        raise HierarchicalStateV7ContractError("entity/date identities must be one-to-one")
    return output


def _normalize_soft_regime(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    raw = frame.loc[:, list(REGIME_COLUMNS)].to_numpy(dtype=np.float64)
    valid = np.isfinite(raw).all(axis=1) & (raw >= 0.0).all(axis=1)
    totals = raw.sum(axis=1)
    valid &= totals > 0.0
    fallback_mask = pd.Series(~valid, index=frame.index.copy(), dtype=bool)
    probabilities = np.full_like(raw, 1.0 / 3.0, dtype=np.float64)
    probabilities[valid] = raw[valid] / totals[valid, None]
    output = frame.copy()
    output.loc[:, list(REGIME_COLUMNS)] = probabilities
    return output, fallback_mask


def _validate_expected_warmup_geometry(
    identities: pd.DataFrame,
    expected_mask: pd.Series,
) -> tuple[tuple[str, int], ...]:
    """Validate a contiguous leading expected-warmup prefix for every entity."""

    order = identities.loc[:, list(IDENTITY_COLUMNS)].copy()
    order["_position"] = np.arange(len(order), dtype=np.int64)
    order = order.sort_values(list(IDENTITY_COLUMNS), kind="mergesort")
    per_entity: list[tuple[str, int]] = []
    for entity, group in order.groupby(IDENTITY_COLUMNS[0], sort=False):
        positions = group["_position"].to_numpy(dtype=np.int64)
        values = expected_mask.iloc[positions].to_numpy(dtype=bool)
        true_count = int(values.sum())
        expected = np.zeros(len(values), dtype=bool)
        expected[:true_count] = True
        if not np.array_equal(values, expected):
            raise HierarchicalStateV7ContractError(
                "expected regime warmup is not a contiguous leading entity prefix"
            )
        if true_count > EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY:
            raise HierarchicalStateV7ContractError(
                "expected regime warmup exceeds the per-entity sealed maximum"
            )
        per_entity.append((str(entity), true_count))
    return tuple(per_entity)


def _expected_regime_warmup_prefix_sha256(
    identities: pd.DataFrame,
    expected_mask: pd.Series,
) -> str:
    per_entity = _validate_expected_warmup_geometry(identities, expected_mask)
    rows = [
        {
            "entity_id": entity,
            "expected_prefix_row_count": count,
        }
        for entity, count in per_entity
    ]
    selected = identities.loc[expected_mask, list(IDENTITY_COLUMNS)]
    membership = [
        [entity, pd.Timestamp(date).isoformat()]
        for entity, date in selected.itertuples(index=False, name=None)
    ]
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "per_entity": rows,
                "membership": membership,
                "max_per_entity": EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY,
                "uniform_causal_fallback": True,
            }
        )
    ).hexdigest()


def _source_regime_masks(
    source: pd.DataFrame,
    identities: pd.DataFrame,
) -> tuple[pd.Series, pd.Series, pd.Series, str]:
    raw = (
        source.loc[:, ["p_bear", "p_sideways", "p_bull"]]
        .apply(pd.to_numeric, errors="coerce")
        .to_numpy(dtype=np.float64)
    )
    exact_all_missing = source.loc[:, ["p_bear", "p_sideways", "p_bull"]].isna().all(axis=1)
    order = identities.loc[:, list(IDENTITY_COLUMNS)].copy()
    order["_position"] = np.arange(len(order), dtype=np.int64)
    order = order.sort_values(list(IDENTITY_COLUMNS), kind="mergesort")
    expected_values = np.zeros(len(source), dtype=bool)
    for _, group in order.groupby(IDENTITY_COLUMNS[0], sort=False):
        positions = group["_position"].to_numpy(dtype=np.int64)
        missing = exact_all_missing.iloc[positions].to_numpy(dtype=bool)
        prefix_count = 0
        while prefix_count < len(missing) and bool(missing[prefix_count]):
            prefix_count += 1
        if prefix_count > EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY:
            raise HierarchicalStateV7ContractError(
                "expected regime warmup exceeds the per-entity sealed maximum"
            )
        expected_values[positions[:prefix_count]] = True
    expected_warmup = pd.Series(expected_values, index=source.index.copy(), dtype=bool)
    valid = np.isfinite(raw).all(axis=1) & (raw >= 0.0).all(axis=1)
    totals = raw.sum(axis=1)
    valid &= totals > 0.0
    fallback = pd.Series(
        ~valid & ~expected_values,
        index=source.index.copy(),
        dtype=bool,
    )
    renormalized = pd.Series(
        valid
        & ~np.isclose(
            totals,
            1.0,
            atol=REGIME_RENORMALIZATION_ABS_TOLERANCE,
            rtol=0.0,
        ),
        index=source.index.copy(),
        dtype=bool,
    )
    warmup_sha256 = _expected_regime_warmup_prefix_sha256(
        identities,
        expected_warmup,
    )
    return expected_warmup, fallback, renormalized, warmup_sha256


def _state_binding_sha256_v7(
    features: pd.DataFrame,
    identities: pd.DataFrame,
    *,
    entity_source_column: str,
    parent_group_columns: tuple[str, ...],
    parent_contract_sha256: str,
    warm_rows: int,
    expected_regime_warmup_prefix_count: int,
    expected_regime_warmup_prefix_sha256: str,
    expected_regime_warmup_prefix_mask: pd.Series,
    regime_fallback_count: int,
    regime_renormalized_count: int,
    regime_fallback_mask: pd.Series,
    regime_renormalized_mask: pd.Series,
) -> str:
    """Bind values, identities, custody metadata, and immutable mask snapshots."""

    rows: list[dict[str, object]] = []
    feature_values = features.to_numpy(dtype=np.float64)
    identity_values = identities.loc[:, list(IDENTITY_COLUMNS)].itertuples(index=False, name=None)
    for index_value, (entity, date), values in zip(
        features.index.tolist(), identity_values, feature_values, strict=True
    ):
        rows.append(
            {
                "index_type": f"{type(index_value).__module__}.{type(index_value).__qualname__}",
                "index_repr": repr(index_value),
                "entity_id": entity,
                "decision_date": pd.Timestamp(date).isoformat(),
                "features": [
                    None if not np.isfinite(value) else float(value).hex() for value in values
                ],
            }
        )
    payload = {
        "columns": list(features.columns),
        "rows": rows,
        "entity_source_column": entity_source_column,
        "parent_group_columns": list(parent_group_columns),
        "parent_contract_sha256": parent_contract_sha256,
        "warm_rows": warm_rows,
        "expected_regime_warmup_prefix_count": expected_regime_warmup_prefix_count,
        "expected_regime_warmup_prefix_sha256": expected_regime_warmup_prefix_sha256,
        "expected_regime_warmup_prefix_mask": [
            bool(value) for value in expected_regime_warmup_prefix_mask.tolist()
        ],
        "regime_fallback_count": regime_fallback_count,
        "regime_renormalized_count": regime_renormalized_count,
        "regime_fallback_mask": [bool(value) for value in regime_fallback_mask.tolist()],
        "regime_renormalized_mask": [bool(value) for value in regime_renormalized_mask.tolist()],
        "regime_renormalization_abs_tolerance": float(REGIME_RENORMALIZATION_ABS_TOLERANCE).hex(),
        "regime_fallback_gate": {
            "max_count": REGIME_FALLBACK_MAX_COUNT,
            "max_fraction": float(REGIME_FALLBACK_MAX_FRACTION).hex(),
            "expected_warmup_excluded": True,
        },
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_hierarchical_state_features_v7(source: pd.DataFrame) -> HierarchicalStateFrameV7:
    """Build the fixed 17-feature state surface and bound entity/date identities."""

    if type(source) is not pd.DataFrame or source.empty:
        raise HierarchicalStateV7ContractError("source must be a non-empty DataFrame")
    if source.columns.has_duplicates or not source.index.is_unique:
        raise HierarchicalStateV7ContractError("source schema and index must be unique")
    entity_column = _resolve_fixed_entity_column(source)
    identities = _bound_identities(source, entity_column)
    (
        expected_warmup_mask,
        source_fallback_mask,
        source_renormalized_mask,
        expected_warmup_sha256,
    ) = _source_regime_masks(source, identities)

    # The only history partition is the production entity.  Research labels may
    # remain in source custody but can neither split nor join feature histories.
    parent = generate_observable_state_features(source, group_columns=(entity_column,))
    if parent.contract_sha256 != PARENT_FEATURE_CONTRACT_SHA256:
        raise HierarchicalStateV7ContractError("parent feature generator contract drifted")
    if parent.group_columns != (entity_column,):
        raise HierarchicalStateV7ContractError("parent accepted an unexpected history group")

    selected = parent.features.loc[:, list(PARENT_TO_MODEL_FEATURE)].rename(
        columns=PARENT_TO_MODEL_FEATURE
    )
    selected, selected_fallback_mask = _normalize_soft_regime(selected)
    if not selected_fallback_mask.equals(expected_warmup_mask | source_fallback_mask):
        raise HierarchicalStateV7ContractError("parent/source regime fallback receipt diverged")
    selected = selected.loc[:, list(MODEL_FEATURE_COLUMNS)]
    selected = selected.astype("float64").replace([np.inf, -np.inf], np.nan)
    leaked = sorted(set(selected.columns).intersection(FORBIDDEN_INFERENCE_COLUMNS))
    if leaked:
        raise HierarchicalStateV7ContractError(f"forbidden inference field leaked: {leaked}")
    warm_rows = int(np.isfinite(selected[OFFSET_COLUMN].to_numpy(dtype=np.float64)).sum())
    expected_warmup_count = int(expected_warmup_mask.sum())
    fallback_count = int(source_fallback_mask.sum())
    renormalized_count = int(source_renormalized_mask.sum())
    binding = _state_binding_sha256_v7(
        selected,
        identities,
        entity_source_column=entity_column,
        parent_group_columns=parent.group_columns,
        parent_contract_sha256=parent.contract_sha256,
        warm_rows=warm_rows,
        expected_regime_warmup_prefix_count=expected_warmup_count,
        expected_regime_warmup_prefix_sha256=expected_warmup_sha256,
        expected_regime_warmup_prefix_mask=expected_warmup_mask,
        regime_fallback_count=fallback_count,
        regime_renormalized_count=renormalized_count,
        regime_fallback_mask=source_fallback_mask,
        regime_renormalized_mask=source_renormalized_mask,
    )
    return HierarchicalStateFrameV7(
        features=selected,
        identities=identities,
        entity_source_column=entity_column,
        parent_group_columns=parent.group_columns,
        parent_contract_sha256=parent.contract_sha256,
        warm_rows=warm_rows,
        expected_regime_warmup_prefix_count=expected_warmup_count,
        expected_regime_warmup_prefix_sha256=expected_warmup_sha256,
        expected_regime_warmup_prefix_mask=expected_warmup_mask,
        regime_fallback_count=fallback_count,
        regime_renormalized_count=renormalized_count,
        regime_fallback_mask=source_fallback_mask,
        regime_renormalized_mask=source_renormalized_mask,
        state_binding_sha256=binding,
    )


def bind_research_dgp_nuisance_groups_v7(
    values: pd.Series,
    *,
    identities: pd.DataFrame,
) -> pd.DataFrame:
    """Create an identity-keyed nuisance membership table from an indexed Series."""

    if type(identities) is not pd.DataFrame:
        raise HierarchicalStateV7ContractError("DGP identity binding must be a DataFrame")
    canonical_identities = validate_bound_identities(identities, expected_index=identities.index)
    if not identities.equals(canonical_identities):
        raise HierarchicalStateV7ContractError("DGP identities are not canonical")
    if type(values) is not pd.Series or not values.index.equals(identities.index):
        raise HierarchicalStateV7ContractError("DGP nuisance labels are not identity-index-bound")
    labels = _strict_string_series(values, label="DGP nuisance label")
    output = identities.loc[:, list(IDENTITY_COLUMNS)].copy()
    output[DGP_MEMBERSHIP_COLUMN] = labels.to_numpy(dtype=object, copy=True)
    return output.loc[:, list(DGP_MEMBERSHIP_COLUMNS)]


def validate_research_dgp_nuisance_groups_v7(
    memberships: pd.DataFrame,
    *,
    identities: pd.DataFrame,
) -> tuple[str, ...]:
    """Join training-only DGP memberships by exact entity/date keys, never position."""

    if type(identities) is not pd.DataFrame:
        raise HierarchicalStateV7ContractError("fit identities must be a DataFrame")
    canonical_fit_identities = validate_bound_identities(
        identities, expected_index=identities.index
    )
    if not identities.equals(canonical_fit_identities):
        raise HierarchicalStateV7ContractError("fit identities are not canonical")
    if type(memberships) is not pd.DataFrame:
        raise HierarchicalStateV7ContractError("DGP memberships must be a keyed DataFrame")
    if tuple(memberships.columns) != DGP_MEMBERSHIP_COLUMNS:
        raise HierarchicalStateV7ContractError("DGP membership schema drifted")
    if memberships.columns.has_duplicates or not memberships.index.is_unique:
        raise HierarchicalStateV7ContractError("DGP membership schema/index must be unique")
    membership_identities = validate_bound_identities(
        memberships.loc[:, list(IDENTITY_COLUMNS)],
        expected_index=memberships.index,
    )
    labels = _strict_string_series(memberships[DGP_MEMBERSHIP_COLUMN], label="DGP nuisance label")
    if membership_identities.duplicated(list(IDENTITY_COLUMNS)).any():
        raise HierarchicalStateV7ContractError("DGP membership identity is duplicated")
    expected_keys = pd.MultiIndex.from_frame(identities.loc[:, list(IDENTITY_COLUMNS)])
    membership_keys = pd.MultiIndex.from_frame(membership_identities)
    positions = membership_keys.get_indexer(expected_keys)
    if (positions < 0).any() or len(memberships) != len(identities):
        raise HierarchicalStateV7ContractError(
            "DGP memberships do not exactly cover fit identities"
        )
    if len(set(int(value) for value in positions)) != len(positions):
        raise HierarchicalStateV7ContractError("DGP membership join is not one-to-one")
    return tuple(labels.iloc[positions].tolist())


__all__ = [
    "HierarchicalStateFrameV7",
    "bind_research_dgp_nuisance_groups_v7",
    "build_hierarchical_state_features_v7",
    "validate_bound_identities",
    "validate_research_dgp_nuisance_groups_v7",
]
