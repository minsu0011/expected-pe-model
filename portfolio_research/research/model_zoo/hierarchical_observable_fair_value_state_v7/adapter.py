"""Identity-bound deterministic inference adapter for H-OFS V7."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math

import numpy as np
import pandas as pd

from .contracts import (
    CONTEXT_COLUMNS,
    IDENTITY_COLUMNS,
    INNOVATION_COLUMN,
    INTERVAL_NORMAL_QUANTILE,
    LOG_PE_BOUNDS,
    MODEL_FEATURE_COLUMNS,
    OFFSET_COLUMN,
    OUTPUT_COLUMNS,
    REGIME_COLUMNS,
    REGIME_FALLBACK_MAX_COUNT,
    REGIME_FALLBACK_MAX_FRACTION,
    REGIME_RENORMALIZATION_ABS_TOLERANCE,
    ROBUST_SCALE_CEILING,
    ROBUST_SCALE_FLOOR,
    STANDARDIZED_COLUMNS,
    STATE_DISPLACEMENT_COLUMN,
    TAIL_SOFT_LIMIT_MAX_LOG,
    TAIL_SOFT_LIMIT_MIN_LOG,
    TAIL_SOFT_LIMIT_SIGMAS,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
    contract_sha256,
)
from .custody import (
    decision_block_canonical_endpoints_v7,
    decision_block_ordered_membership_sha256_v7,
    decision_block_set_membership_sha256_v7,
    decision_source_positions_sha256_v7,
    require_canonical_decision_identity_order_v7,
)
from .estimator import FrozenHierarchicalParametersV7
from .runtime import ResourceReceiptV7, capture_runtime_receipt_v7
from .validation import (
    require_exact_int,
    require_exact_str,
    require_exact_tuple,
    require_sha256,
)


_DECISION_BATCH_FACTORY_TOKEN = object()


@dataclass(frozen=True, init=False)
class DecisionBatchV7:
    """One exact multi-date decision block with feature/identity custody."""

    features: pd.DataFrame
    identities: pd.DataFrame
    source_state_sha256: str
    decision_batch_sha256: str
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_block_start_date: str
    decision_block_end_date: str
    decision_block_first_entity_id: str
    decision_block_last_entity_id: str
    decision_distinct_date_count: int
    source_positions: tuple[int, ...]
    decision_source_positions_sha256: str
    source_row_count: int
    decision_expected_regime_warmup_prefix_mask: tuple[bool, ...]
    decision_expected_regime_warmup_prefix_count: int
    decision_regime_fallback_mask: tuple[bool, ...]
    decision_regime_renormalized_mask: tuple[bool, ...]
    decision_regime_fallback_count: int
    decision_regime_renormalized_count: int

    def __init__(
        self,
        *,
        features: pd.DataFrame,
        identities: pd.DataFrame,
        source_state_sha256: str,
        decision_batch_sha256: str,
        decision_block_ordered_membership_sha256: str,
        decision_block_set_membership_sha256: str,
        decision_block_start_date: str,
        decision_block_end_date: str,
        decision_block_first_entity_id: str,
        decision_block_last_entity_id: str,
        decision_distinct_date_count: int,
        source_positions: tuple[int, ...],
        decision_source_positions_sha256: str,
        source_row_count: int,
        decision_expected_regime_warmup_prefix_mask: tuple[bool, ...],
        decision_expected_regime_warmup_prefix_count: int,
        decision_regime_fallback_mask: tuple[bool, ...],
        decision_regime_renormalized_mask: tuple[bool, ...],
        decision_regime_fallback_count: int,
        decision_regime_renormalized_count: int,
        _factory_token: object | None = None,
    ) -> None:
        if _factory_token is not _DECISION_BATCH_FACTORY_TOKEN:
            raise HierarchicalStateV7ContractError(
                "DecisionBatchV7 must be created by the exact identity-join factory"
            )
        require_exact_tuple(source_positions, label="decision source positions")
        require_exact_tuple(
            decision_expected_regime_warmup_prefix_mask,
            label="decision expected warmup mask",
        )
        require_exact_tuple(decision_regime_fallback_mask, label="decision fallback mask")
        require_exact_tuple(decision_regime_renormalized_mask, label="decision renormalized mask")
        object.__setattr__(self, "features", features.copy())
        object.__setattr__(self, "identities", identities.copy())
        object.__setattr__(self, "source_state_sha256", source_state_sha256)
        object.__setattr__(self, "decision_batch_sha256", decision_batch_sha256)
        object.__setattr__(
            self,
            "decision_block_ordered_membership_sha256",
            decision_block_ordered_membership_sha256,
        )
        object.__setattr__(
            self, "decision_block_set_membership_sha256", decision_block_set_membership_sha256
        )
        object.__setattr__(self, "decision_block_start_date", decision_block_start_date)
        object.__setattr__(self, "decision_block_end_date", decision_block_end_date)
        object.__setattr__(self, "decision_block_first_entity_id", decision_block_first_entity_id)
        object.__setattr__(self, "decision_block_last_entity_id", decision_block_last_entity_id)
        object.__setattr__(self, "decision_distinct_date_count", decision_distinct_date_count)
        object.__setattr__(self, "source_positions", tuple(source_positions))
        object.__setattr__(
            self, "decision_source_positions_sha256", decision_source_positions_sha256
        )
        object.__setattr__(self, "source_row_count", source_row_count)
        object.__setattr__(
            self,
            "decision_expected_regime_warmup_prefix_mask",
            tuple(decision_expected_regime_warmup_prefix_mask),
        )
        object.__setattr__(
            self,
            "decision_expected_regime_warmup_prefix_count",
            decision_expected_regime_warmup_prefix_count,
        )
        object.__setattr__(
            self,
            "decision_regime_fallback_mask",
            tuple(decision_regime_fallback_mask),
        )
        object.__setattr__(
            self,
            "decision_regime_renormalized_mask",
            tuple(decision_regime_renormalized_mask),
        )
        object.__setattr__(
            self,
            "decision_regime_fallback_count",
            decision_regime_fallback_count,
        )
        object.__setattr__(
            self,
            "decision_regime_renormalized_count",
            decision_regime_renormalized_count,
        )
        self.__post_init__()

    def __post_init__(self) -> None:
        if type(self.features) is not pd.DataFrame or self.features.empty:
            raise HierarchicalStateV7ContractError("decision features must be non-empty")
        if tuple(self.features.columns) != MODEL_FEATURE_COLUMNS:
            raise HierarchicalStateV7ContractError("decision feature schema drifted")
        if self.features.columns.has_duplicates or not self.features.index.is_unique:
            raise HierarchicalStateV7ContractError("decision feature schema/index must be unique")
        validated_identities = require_canonical_decision_identity_order_v7(
            self.identities, expected_index=self.features.index
        )
        if not self.identities.equals(validated_identities):
            raise HierarchicalStateV7ContractError("decision identities are not canonical")
        first_entity, start, last_entity, end, distinct_date_count = (
            decision_block_canonical_endpoints_v7(self.identities)
        )
        if (
            self.decision_block_start_date != start
            or self.decision_block_end_date != end
            or self.decision_block_first_entity_id != first_entity
            or self.decision_block_last_entity_id != last_entity
            or self.decision_distinct_date_count != distinct_date_count
        ):
            raise HierarchicalStateV7ContractError(
                "decision block endpoints are not the exact canonical first/last rows"
            )
        require_exact_str(self.decision_block_start_date, label="decision block start")
        require_exact_str(self.decision_block_end_date, label="decision block end")
        require_exact_str(self.decision_block_first_entity_id, label="decision block first entity")
        require_exact_str(self.decision_block_last_entity_id, label="decision block last entity")
        require_exact_int(
            self.decision_distinct_date_count,
            label="decision distinct date count",
            minimum=2,
        )
        require_sha256(self.source_state_sha256, label="decision source state binding")
        require_sha256(self.decision_batch_sha256, label="decision batch binding")
        require_sha256(
            self.decision_block_ordered_membership_sha256,
            label="decision ordered entity/date membership",
        )
        require_sha256(
            self.decision_block_set_membership_sha256,
            label="decision set entity/date membership",
        )
        require_sha256(
            self.decision_source_positions_sha256,
            label="decision source-position binding",
        )
        if (
            self.decision_block_ordered_membership_sha256
            != decision_block_ordered_membership_sha256_v7(self.identities)
        ):
            raise HierarchicalStateV7ContractError("decision ordered membership hash drifted")
        if self.decision_block_set_membership_sha256 != decision_block_set_membership_sha256_v7(
            self.identities
        ):
            raise HierarchicalStateV7ContractError("decision membership hash drifted")
        require_exact_int(self.source_row_count, label="decision source rows", minimum=1)
        positions = require_exact_tuple(
            self.source_positions,
            label="decision source positions",
            length=len(self.features),
        )
        for position, value in enumerate(positions):
            require_exact_int(
                value,
                label=f"decision source positions[{position}]",
                minimum=0,
            )
        for label, mask in (
            (
                "expected warmup",
                self.decision_expected_regime_warmup_prefix_mask,
            ),
            ("fallback", self.decision_regime_fallback_mask),
            ("renormalized", self.decision_regime_renormalized_mask),
        ):
            values = require_exact_tuple(
                mask, label=f"decision {label} mask", length=len(self.features)
            )
            if any(type(value) is not bool for value in values):
                raise HierarchicalStateV7ContractError(
                    f"decision {label} mask requires exact bool values"
                )
        if (
            self.source_row_count < len(self.features)
            or len(set(self.source_positions)) != len(self.source_positions)
            or any(
                position < 0 or position >= self.source_row_count
                for position in self.source_positions
            )
        ):
            raise HierarchicalStateV7ContractError("decision source-position custody is invalid")
        if self.decision_source_positions_sha256 != decision_source_positions_sha256_v7(
            self.identities,
            source_state_sha256=self.source_state_sha256,
            source_positions=self.source_positions,
            source_row_count=self.source_row_count,
        ):
            raise HierarchicalStateV7ContractError(
                "decision ordered membership/source-position cross-seal drifted"
            )
        for label, count in (
            (
                "expected warmup",
                self.decision_expected_regime_warmup_prefix_count,
            ),
            ("fallback", self.decision_regime_fallback_count),
            ("renormalized", self.decision_regime_renormalized_count),
        ):
            require_exact_int(count, label=f"decision regime {label} count", minimum=0)
            if count > len(self.features):
                raise HierarchicalStateV7ContractError(f"decision regime {label} count is invalid")
        if self.decision_expected_regime_warmup_prefix_count != 0 or any(
            self.decision_expected_regime_warmup_prefix_mask
        ):
            raise HierarchicalStateV7ContractError(
                "expected regime warmup is forbidden in a decision block"
            )
        if (
            self.decision_regime_fallback_count > REGIME_FALLBACK_MAX_COUNT
            or self.decision_regime_fallback_count / len(self.features)
            > REGIME_FALLBACK_MAX_FRACTION
        ):
            raise HierarchicalStateV7ContractError(
                "malformed decision regimes exceed the exact decision-row fallback limit"
            )
        if self.decision_regime_fallback_count != sum(
            self.decision_regime_fallback_mask
        ) or self.decision_regime_renormalized_count != sum(self.decision_regime_renormalized_mask):
            raise HierarchicalStateV7ContractError("decision regime mask/count binding drifted")
        self.assert_live_integrity()

    def assert_live_integrity(self) -> None:
        expected = decision_batch_sha256_v7(
            self.features,
            self.identities,
            source_state_sha256=self.source_state_sha256,
            decision_block_ordered_membership_sha256=(
                self.decision_block_ordered_membership_sha256
            ),
            decision_block_set_membership_sha256=self.decision_block_set_membership_sha256,
            decision_block_start_date=self.decision_block_start_date,
            decision_block_end_date=self.decision_block_end_date,
            decision_block_first_entity_id=self.decision_block_first_entity_id,
            decision_block_last_entity_id=self.decision_block_last_entity_id,
            decision_distinct_date_count=self.decision_distinct_date_count,
            source_positions=self.source_positions,
            decision_source_positions_sha256=self.decision_source_positions_sha256,
            source_row_count=self.source_row_count,
            decision_expected_regime_warmup_prefix_mask=(
                self.decision_expected_regime_warmup_prefix_mask
            ),
            decision_expected_regime_warmup_prefix_count=(
                self.decision_expected_regime_warmup_prefix_count
            ),
            decision_regime_fallback_mask=self.decision_regime_fallback_mask,
            decision_regime_renormalized_mask=self.decision_regime_renormalized_mask,
            decision_regime_fallback_count=self.decision_regime_fallback_count,
            decision_regime_renormalized_count=self.decision_regime_renormalized_count,
        )
        if expected != self.decision_batch_sha256:
            raise HierarchicalStateV7ContractError(
                "decision batch feature/identity binding drifted"
            )

    @property
    def identity_order_sha256(self) -> str:
        return self.decision_block_ordered_membership_sha256


@dataclass(frozen=True)
class HierarchicalModelOutputV7:
    values: pd.DataFrame
    identities: pd.DataFrame
    parameter_sha256: str
    design_contract_sha256: str
    feature_sha256: str
    identity_order_sha256: str
    decision_batch_sha256: str
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_source_positions_sha256: str
    inference_resource_receipt: ResourceReceiptV7
    inference_resource_receipt_sha256: str
    input_rows: int
    fallback_context_cells: int
    regime_fallback_count: int
    regime_renormalized_count: int
    fit_end_date: str
    decision_block_start_date: str
    decision_block_end_date: str
    decision_block_first_entity_id: str
    decision_block_last_entity_id: str
    decision_distinct_date_count: int
    within_block_parameter_update_count: int

    def __post_init__(self) -> None:
        if type(self.values) is not pd.DataFrame or type(self.identities) is not pd.DataFrame:
            raise HierarchicalStateV7ContractError("output frames require exact DataFrame types")
        object.__setattr__(self, "values", self.values.copy(deep=True))
        object.__setattr__(self, "identities", self.identities.copy(deep=True))
        if tuple(self.values.columns) != OUTPUT_COLUMNS:
            raise HierarchicalStateV7ContractError("H-OFS V7 output schema drifted")
        if tuple(self.identities.columns) != IDENTITY_COLUMNS:
            raise HierarchicalStateV7ContractError("H-OFS V7 output identity schema drifted")
        if not self.values.index.equals(self.identities.index):
            raise HierarchicalStateV7ContractError("output is not identity-index-bound")
        validated_identities = require_canonical_decision_identity_order_v7(
            self.identities, expected_index=self.values.index
        )
        if not self.identities.equals(validated_identities):
            raise HierarchicalStateV7ContractError("output identities are not canonical")
        if self.identities.duplicated(list(IDENTITY_COLUMNS)).any():
            raise HierarchicalStateV7ContractError("output entity/date identity is duplicated")
        if any(dtype != np.dtype("float64") for dtype in self.values.dtypes):
            raise HierarchicalStateV7ContractError("output values require exact float64 columns")
        numeric = self.values.to_numpy(dtype=np.float64)
        if not np.isfinite(numeric).all():
            raise HierarchicalStateV7ContractError("H-OFS V7 output contains non-finite values")
        if not (
            self.values[OUTPUT_COLUMNS[1]].le(self.values[OUTPUT_COLUMNS[0]]).all()
            and self.values[OUTPUT_COLUMNS[0]].le(self.values[OUTPUT_COLUMNS[2]]).all()
        ):
            raise HierarchicalStateV7ContractError("H-OFS V7 interval is inverted")
        if (
            not self.values[OUTPUT_COLUMNS[3]]
            .between(
                math.log(ROBUST_SCALE_FLOOR),
                math.log(ROBUST_SCALE_CEILING),
                inclusive="both",
            )
            .all()
        ):
            raise HierarchicalStateV7ContractError("H-OFS V7 log scale leaves fixed bounds")
        for label, value in (
            ("parameter", self.parameter_sha256),
            ("contract", self.design_contract_sha256),
            ("feature", self.feature_sha256),
            ("identity", self.identity_order_sha256),
            ("decision batch", self.decision_batch_sha256),
            ("decision ordered membership", self.decision_block_ordered_membership_sha256),
            ("decision set membership", self.decision_block_set_membership_sha256),
            ("decision source positions", self.decision_source_positions_sha256),
            ("inference resource", self.inference_resource_receipt_sha256),
        ):
            require_sha256(value, label=f"output {label} hash")
        if (
            type(self.inference_resource_receipt) is not ResourceReceiptV7
            or self.inference_resource_receipt.purpose != "INFERENCE"
            or self.inference_resource_receipt.sha256() != self.inference_resource_receipt_sha256
        ):
            raise HierarchicalStateV7ContractError("output inference resource binding failed")
        for label, count in (
            ("input rows", self.input_rows),
            ("fallback context cells", self.fallback_context_cells),
            ("regime fallback", self.regime_fallback_count),
            ("regime renormalized", self.regime_renormalized_count),
            ("decision distinct dates", self.decision_distinct_date_count),
            (
                "within-block parameter updates",
                self.within_block_parameter_update_count,
            ),
        ):
            require_exact_int(count, label=f"output {label}", minimum=0)
        for label, value in (
            ("fit end", self.fit_end_date),
            ("block start", self.decision_block_start_date),
            ("block end", self.decision_block_end_date),
            ("block first entity", self.decision_block_first_entity_id),
            ("block last entity", self.decision_block_last_entity_id),
        ):
            require_exact_str(value, label=f"output {label}")
        if self.input_rows != len(self.values) or self.input_rows < 1:
            raise HierarchicalStateV7ContractError("output row receipt is invalid")
        if (
            self.regime_fallback_count > REGIME_FALLBACK_MAX_COUNT
            or self.regime_fallback_count / self.input_rows > REGIME_FALLBACK_MAX_FRACTION
        ):
            raise HierarchicalStateV7ContractError("output fallback receipt is invalid")
        fit_end = pd.Timestamp(self.fit_end_date)
        block_start = pd.Timestamp(self.decision_block_start_date)
        block_end = pd.Timestamp(self.decision_block_end_date)
        if not fit_end < block_start <= block_end:
            raise HierarchicalStateV7ContractError("output block chronology receipt is invalid")
        first_entity, first_date, last_entity, last_date, distinct_date_count = (
            decision_block_canonical_endpoints_v7(self.identities)
        )
        if (
            first_date != self.decision_block_start_date
            or last_date != self.decision_block_end_date
            or first_entity != self.decision_block_first_entity_id
            or last_entity != self.decision_block_last_entity_id
            or distinct_date_count != self.decision_distinct_date_count
            or self.decision_distinct_date_count < 2
        ):
            raise HierarchicalStateV7ContractError("output decision-date coverage drifted")
        if self.within_block_parameter_update_count != 0:
            raise HierarchicalStateV7ContractError("within-block parameter updates are forbidden")
        if (
            self.identity_order_sha256 != self.decision_block_ordered_membership_sha256
            or self.decision_block_ordered_membership_sha256
            != decision_block_ordered_membership_sha256_v7(self.identities)
            or self.decision_block_set_membership_sha256
            != decision_block_set_membership_sha256_v7(self.identities)
        ):
            raise HierarchicalStateV7ContractError("output decision order custody drifted")

    def output_manifest_payload(self) -> dict[str, object]:
        """Return the sealed prediction/output custody manifest for serialization."""

        return {
            "schema_version": "expected_pe.hofs_v7.prediction_output_manifest.v1",
            "parameter_sha256": self.parameter_sha256,
            "design_contract_sha256": self.design_contract_sha256,
            "feature_sha256": self.feature_sha256,
            "identity_order_sha256": self.identity_order_sha256,
            "decision_batch_sha256": self.decision_batch_sha256,
            "decision_block_ordered_membership_sha256": (
                self.decision_block_ordered_membership_sha256
            ),
            "decision_block_set_membership_sha256": (self.decision_block_set_membership_sha256),
            "decision_source_positions_sha256": self.decision_source_positions_sha256,
            "inference_resource_receipt_sha256": (self.inference_resource_receipt_sha256),
            "input_rows": self.input_rows,
            "fit_end_date": self.fit_end_date,
            "decision_block_start_date": self.decision_block_start_date,
            "decision_block_end_date": self.decision_block_end_date,
            "decision_block_first_entity_id": self.decision_block_first_entity_id,
            "decision_block_last_entity_id": self.decision_block_last_entity_id,
            "decision_distinct_date_count": self.decision_distinct_date_count,
            "within_block_parameter_update_count": (self.within_block_parameter_update_count),
            "prediction_values_sha256": _feature_sha256(self.values),
        }

    @property
    def output_manifest_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.output_manifest_payload())).hexdigest()


def _feature_sha256(frame: pd.DataFrame) -> str:
    payload = {
        "columns": list(frame.columns),
        "values": [
            [None if not np.isfinite(value) else float(value).hex() for value in row]
            for row in frame.to_numpy(dtype=np.float64)
        ],
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def decision_batch_sha256_v7(
    features: pd.DataFrame,
    identities: pd.DataFrame,
    *,
    source_state_sha256: str,
    decision_block_ordered_membership_sha256: str,
    decision_block_set_membership_sha256: str,
    decision_block_start_date: str,
    decision_block_end_date: str,
    decision_block_first_entity_id: str,
    decision_block_last_entity_id: str,
    decision_distinct_date_count: int,
    source_positions: tuple[int, ...],
    decision_source_positions_sha256: str,
    source_row_count: int,
    decision_expected_regime_warmup_prefix_mask: tuple[bool, ...],
    decision_expected_regime_warmup_prefix_count: int,
    decision_regime_fallback_mask: tuple[bool, ...],
    decision_regime_renormalized_mask: tuple[bool, ...],
    decision_regime_fallback_count: int,
    decision_regime_renormalized_count: int,
) -> str:
    payload = {
        "selected_feature_sha256": _feature_sha256(features),
        "selected_identity_rows": [
            {
                "index_type": f"{type(index_value).__module__}.{type(index_value).__qualname__}",
                "index_repr": repr(index_value),
                "entity_id": entity,
                "decision_date": pd.Timestamp(date).isoformat(),
            }
            for index_value, (entity, date) in zip(
                identities.index.tolist(),
                identities.loc[:, list(IDENTITY_COLUMNS)].itertuples(index=False, name=None),
                strict=True,
            )
        ],
        "source_state_sha256": source_state_sha256,
        "decision_block_ordered_membership_sha256": (decision_block_ordered_membership_sha256),
        "decision_block_set_membership_sha256": decision_block_set_membership_sha256,
        "decision_block_start_date": decision_block_start_date,
        "decision_block_end_date": decision_block_end_date,
        "decision_block_first_entity_id": decision_block_first_entity_id,
        "decision_block_last_entity_id": decision_block_last_entity_id,
        "decision_distinct_date_count": decision_distinct_date_count,
        "source_positions": list(source_positions),
        "decision_source_positions_sha256": decision_source_positions_sha256,
        "source_row_count": source_row_count,
        "decision_expected_regime_warmup_prefix_mask": list(
            decision_expected_regime_warmup_prefix_mask
        ),
        "decision_expected_regime_warmup_prefix_count": (
            decision_expected_regime_warmup_prefix_count
        ),
        "decision_regime_fallback_mask": list(decision_regime_fallback_mask),
        "decision_regime_renormalized_mask": list(decision_regime_renormalized_mask),
        "decision_regime_fallback_count": decision_regime_fallback_count,
        "decision_regime_renormalized_count": decision_regime_renormalized_count,
        "regime_fallback_max_count": REGIME_FALLBACK_MAX_COUNT,
        "regime_fallback_max_fraction": float(REGIME_FALLBACK_MAX_FRACTION).hex(),
        "regime_renormalization_abs_tolerance": float(REGIME_RENORMALIZATION_ABS_TOLERANCE).hex(),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _create_decision_batch_v7(
    *,
    features: pd.DataFrame,
    identities: pd.DataFrame,
    source_state_sha256: str,
    source_positions: tuple[int, ...],
    source_row_count: int,
    decision_expected_regime_warmup_prefix_mask: tuple[bool, ...],
    decision_expected_regime_warmup_prefix_count: int,
    decision_regime_fallback_mask: tuple[bool, ...],
    decision_regime_renormalized_mask: tuple[bool, ...],
    decision_regime_fallback_count: int,
    decision_regime_renormalized_count: int,
) -> DecisionBatchV7:
    """Private factory used only after the runner's exact one-to-one key join."""

    features_copy = features.copy()
    identities_copy = require_canonical_decision_identity_order_v7(
        identities.copy(), expected_index=features_copy.index
    )
    ordered_membership_sha256 = decision_block_ordered_membership_sha256_v7(identities_copy)
    set_membership_sha256 = decision_block_set_membership_sha256_v7(identities_copy)
    first_entity, block_start, last_entity, block_end, distinct_date_count = (
        decision_block_canonical_endpoints_v7(identities_copy)
    )
    source_positions_sha256 = decision_source_positions_sha256_v7(
        identities_copy,
        source_state_sha256=source_state_sha256,
        source_positions=source_positions,
        source_row_count=source_row_count,
    )
    digest = decision_batch_sha256_v7(
        features_copy,
        identities_copy,
        source_state_sha256=source_state_sha256,
        decision_block_ordered_membership_sha256=ordered_membership_sha256,
        decision_block_set_membership_sha256=set_membership_sha256,
        decision_block_start_date=block_start,
        decision_block_end_date=block_end,
        decision_block_first_entity_id=first_entity,
        decision_block_last_entity_id=last_entity,
        decision_distinct_date_count=distinct_date_count,
        source_positions=source_positions,
        decision_source_positions_sha256=source_positions_sha256,
        source_row_count=source_row_count,
        decision_expected_regime_warmup_prefix_mask=(decision_expected_regime_warmup_prefix_mask),
        decision_expected_regime_warmup_prefix_count=(decision_expected_regime_warmup_prefix_count),
        decision_regime_fallback_mask=decision_regime_fallback_mask,
        decision_regime_renormalized_mask=decision_regime_renormalized_mask,
        decision_regime_fallback_count=decision_regime_fallback_count,
        decision_regime_renormalized_count=decision_regime_renormalized_count,
    )
    return DecisionBatchV7(
        features=features_copy,
        identities=identities_copy,
        source_state_sha256=source_state_sha256,
        decision_batch_sha256=digest,
        decision_block_ordered_membership_sha256=ordered_membership_sha256,
        decision_block_set_membership_sha256=set_membership_sha256,
        decision_block_start_date=block_start,
        decision_block_end_date=block_end,
        decision_block_first_entity_id=first_entity,
        decision_block_last_entity_id=last_entity,
        decision_distinct_date_count=distinct_date_count,
        source_positions=source_positions,
        decision_source_positions_sha256=source_positions_sha256,
        source_row_count=source_row_count,
        decision_expected_regime_warmup_prefix_mask=(decision_expected_regime_warmup_prefix_mask),
        decision_expected_regime_warmup_prefix_count=(decision_expected_regime_warmup_prefix_count),
        decision_regime_fallback_mask=decision_regime_fallback_mask,
        decision_regime_renormalized_mask=decision_regime_renormalized_mask,
        decision_regime_fallback_count=decision_regime_fallback_count,
        decision_regime_renormalized_count=decision_regime_renormalized_count,
        _factory_token=_DECISION_BATCH_FACTORY_TOKEN,
    )


def _normalized_regime(frame: pd.DataFrame) -> tuple[np.ndarray, int, int]:
    values = frame.loc[:, list(REGIME_COLUMNS)].to_numpy(dtype=np.float64)
    valid = np.isfinite(values).all(axis=1) & (values >= 0.0).all(axis=1)
    totals = values.sum(axis=1)
    valid &= totals > 0.0
    fallback_count = int((~valid).sum())
    if (
        fallback_count > REGIME_FALLBACK_MAX_COUNT
        or fallback_count / len(frame) > REGIME_FALLBACK_MAX_FRACTION
    ):
        raise HierarchicalStateV7ContractError(
            "malformed decision regimes exceed the fixed fallback limit"
        )
    renormalized_count = int(
        (
            valid
            & ~np.isclose(
                totals,
                1.0,
                atol=REGIME_RENORMALIZATION_ABS_TOLERANCE,
                rtol=0.0,
            )
        ).sum()
    )
    output = np.full_like(values, 1.0 / 3.0, dtype=np.float64)
    output[valid] = values[valid] / totals[valid, None]
    return output, fallback_count, renormalized_count


def apply_frozen_parameters_v7(
    batch: DecisionBatchV7,
    parameters: FrozenHierarchicalParametersV7,
) -> HierarchicalModelOutputV7:
    """Apply one frozen parameter object unchanged across one exact block."""

    if type(batch) is not DecisionBatchV7:
        raise HierarchicalStateV7ContractError("inference requires a DecisionBatchV7")
    if type(parameters) is not FrozenHierarchicalParametersV7:
        raise HierarchicalStateV7ContractError("inference requires frozen H-OFS V7 parameters")
    batch.assert_live_integrity()
    inference_resource_receipt = capture_runtime_receipt_v7(purpose="INFERENCE")
    fit_end = pd.to_datetime(parameters.fit_end_date, errors="coerce")
    block_start = pd.Timestamp(batch.decision_block_start_date)
    block_end = pd.Timestamp(batch.decision_block_end_date)
    if pd.isna(fit_end) or not pd.Timestamp(fit_end) < block_start <= block_end:
        raise HierarchicalStateV7ContractError("fit prefix must end before the decision block")
    if (
        block_start != pd.Timestamp(parameters.decision_block_start_date)
        or block_end != pd.Timestamp(parameters.decision_block_end_date)
        or batch.decision_block_first_entity_id != parameters.decision_block_first_entity_id
        or batch.decision_block_last_entity_id != parameters.decision_block_last_entity_id
        or batch.decision_block_ordered_membership_sha256
        != parameters.decision_block_ordered_membership_sha256
        or batch.decision_block_set_membership_sha256
        != parameters.decision_block_set_membership_sha256
        or batch.decision_source_positions_sha256 != parameters.decision_source_positions_sha256
        or len(batch.features) != parameters.decision_row_count
    ):
        raise HierarchicalStateV7ContractError(
            "parameter bundle is frozen for another exact decision block"
        )

    raw = batch.features.loc[:, list(STANDARDIZED_COLUMNS)].to_numpy(dtype=np.float64)
    centers = np.asarray(parameters.robust_centers, dtype=np.float64)
    scales = np.asarray(parameters.robust_scales, dtype=np.float64)
    standardized = (raw - centers[None, :]) / scales[None, :]
    missing = ~np.isfinite(standardized)
    fallback_context_cells = int(missing.sum())
    standardized[missing] = 0.0
    offset = pd.to_numeric(batch.features[OFFSET_COLUMN], errors="coerce").to_numpy(
        dtype=np.float64
    )
    if not np.isfinite(offset).all():
        raise HierarchicalStateV7ContractError("decision offset must be warm and finite")
    regime, adapter_fallback_count, renormalized_count = _normalized_regime(batch.features)

    state_position = STANDARDIZED_COLUMNS.index(STATE_DISPLACEMENT_COLUMN)
    innovation_position = STANDARDIZED_COLUMNS.index(INNOVATION_COLUMN)
    context_positions = [STANDARDIZED_COLUMNS.index(column) for column in CONTEXT_COLUMNS]
    intercept = parameters.global_intercept + regime @ np.asarray(
        parameters.regime_intercept_deviations, dtype=np.float64
    )
    persistence = parameters.global_persistence + regime @ np.asarray(
        parameters.regime_persistence_deviations, dtype=np.float64
    )
    innovation = parameters.global_innovation + regime @ np.asarray(
        parameters.regime_innovation_deviations, dtype=np.float64
    )
    context = standardized[:, context_positions] @ np.asarray(
        parameters.context_coefficients, dtype=np.float64
    )
    raw_correction = (
        intercept
        + persistence * standardized[:, state_position]
        + innovation * standardized[:, innovation_position]
        + context
    )

    log_scale = parameters.global_log_scale + regime @ np.asarray(
        parameters.regime_log_scale_deviations, dtype=np.float64
    )
    base_scale = np.exp(log_scale)
    innovation_stress = np.minimum(np.abs(standardized[:, innovation_position]), 4.0)
    uncertainty_scale = base_scale * np.sqrt(1.0 + np.square(innovation_stress) / 16.0)
    uncertainty_scale = np.clip(uncertainty_scale, ROBUST_SCALE_FLOOR, ROBUST_SCALE_CEILING)
    soft_limit = np.clip(
        TAIL_SOFT_LIMIT_SIGMAS * uncertainty_scale,
        TAIL_SOFT_LIMIT_MIN_LOG,
        TAIL_SOFT_LIMIT_MAX_LOG,
    )
    guarded_correction = soft_limit * np.tanh(raw_correction / soft_limit)
    guard_weight = np.ones(len(batch.features), dtype=np.float64)
    nonzero = np.abs(raw_correction) > 1e-15
    guard_weight[nonzero] = guarded_correction[nonzero] / raw_correction[nonzero]
    guard_weight = np.clip(guard_weight, 0.0, 1.0)

    point_log = np.clip(offset + guarded_correction, *LOG_PE_BOUNDS)
    lower_log = np.clip(
        point_log - INTERVAL_NORMAL_QUANTILE * uncertainty_scale,
        *LOG_PE_BOUNDS,
    )
    upper_log = np.clip(
        point_log + INTERVAL_NORMAL_QUANTILE * uncertainty_scale,
        *LOG_PE_BOUNDS,
    )
    output = pd.DataFrame(
        {
            OUTPUT_COLUMNS[0]: np.exp(point_log),
            OUTPUT_COLUMNS[1]: np.exp(lower_log),
            OUTPUT_COLUMNS[2]: np.exp(upper_log),
            OUTPUT_COLUMNS[3]: np.log(uncertainty_scale),
            OUTPUT_COLUMNS[4]: guard_weight,
        },
        index=batch.features.index.copy(),
    ).loc[:, list(OUTPUT_COLUMNS)]
    return HierarchicalModelOutputV7(
        values=output,
        identities=batch.identities.copy(),
        parameter_sha256=parameters.sha256(),
        design_contract_sha256=contract_sha256(),
        feature_sha256=_feature_sha256(batch.features),
        identity_order_sha256=batch.identity_order_sha256,
        decision_batch_sha256=batch.decision_batch_sha256,
        decision_block_ordered_membership_sha256=(batch.decision_block_ordered_membership_sha256),
        decision_block_set_membership_sha256=batch.decision_block_set_membership_sha256,
        decision_source_positions_sha256=batch.decision_source_positions_sha256,
        inference_resource_receipt=inference_resource_receipt,
        inference_resource_receipt_sha256=inference_resource_receipt.sha256(),
        input_rows=len(batch.features),
        fallback_context_cells=fallback_context_cells,
        regime_fallback_count=(batch.decision_regime_fallback_count + adapter_fallback_count),
        regime_renormalized_count=(batch.decision_regime_renormalized_count + renormalized_count),
        fit_end_date=parameters.fit_end_date,
        decision_block_start_date=batch.decision_block_start_date,
        decision_block_end_date=batch.decision_block_end_date,
        decision_block_first_entity_id=batch.decision_block_first_entity_id,
        decision_block_last_entity_id=batch.decision_block_last_entity_id,
        decision_distinct_date_count=batch.decision_distinct_date_count,
        within_block_parameter_update_count=0,
    )


__all__ = [
    "DecisionBatchV7",
    "HierarchicalModelOutputV7",
    "apply_frozen_parameters_v7",
    "decision_batch_sha256_v7",
    "decision_block_ordered_membership_sha256_v7",
    "decision_block_set_membership_sha256_v7",
    "decision_source_positions_sha256_v7",
]
