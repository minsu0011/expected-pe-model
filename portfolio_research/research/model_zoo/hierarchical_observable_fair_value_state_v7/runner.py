"""Chronological fit-prefix and frozen decision-block capability for H-OFS V7."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .adapter import (
    DecisionBatchV7,
    HierarchicalModelOutputV7,
    _create_decision_batch_v7,
    apply_frozen_parameters_v7,
)
from .artifacts import load_frozen_parameter_bundle
from .contracts import IDENTITY_COLUMNS, HierarchicalStateV7ContractError
from .custody import (
    decision_block_canonical_endpoints_v7,
    decision_block_ordered_membership_sha256_v7,
    decision_block_set_membership_sha256_v7,
    require_canonical_decision_identity_order_v7,
)
from .estimator import (
    FrozenHierarchicalParametersV7,
    HierarchicalFitResultV7,
    fit_hierarchical_state_v7,
)
from .features import (
    HierarchicalStateFrameV7,
    bind_research_dgp_nuisance_groups_v7,
    build_hierarchical_state_features_v7,
)


@dataclass(frozen=True)
class ChronologicalFitCapabilityResultV7:
    fit: HierarchicalFitResultV7
    training_state: HierarchicalStateFrameV7
    decision_block_start_date: str
    decision_block_end_date: str
    decision_block_first_entity_id: str
    decision_block_last_entity_id: str
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_source_positions_sha256: str

    def __post_init__(self) -> None:
        if type(self.fit) is not HierarchicalFitResultV7:
            raise HierarchicalStateV7ContractError("fit capability result fit type drifted")
        if type(self.training_state) is not HierarchicalStateFrameV7:
            raise HierarchicalStateV7ContractError("fit capability state type drifted")
        for value in (
            self.decision_block_start_date,
            self.decision_block_end_date,
            self.decision_block_first_entity_id,
            self.decision_block_last_entity_id,
            self.decision_block_ordered_membership_sha256,
            self.decision_block_set_membership_sha256,
            self.decision_source_positions_sha256,
        ):
            if type(value) is not str:
                raise HierarchicalStateV7ContractError("fit capability block type drifted")
        self.training_state.assert_live_integrity()
        fit_end = pd.Timestamp(self.fit.parameters.fit_end_date)
        block_start = pd.Timestamp(self.decision_block_start_date)
        block_end = pd.Timestamp(self.decision_block_end_date)
        if not fit_end < block_start <= block_end:
            raise HierarchicalStateV7ContractError("fit capability crossed its block boundary")
        if (
            block_start != pd.Timestamp(self.fit.parameters.decision_block_start_date)
            or block_end != pd.Timestamp(self.fit.parameters.decision_block_end_date)
            or self.decision_block_first_entity_id
            != self.fit.parameters.decision_block_first_entity_id
            or self.decision_block_last_entity_id
            != self.fit.parameters.decision_block_last_entity_id
            or self.decision_block_ordered_membership_sha256
            != self.fit.parameters.decision_block_ordered_membership_sha256
            or self.decision_block_set_membership_sha256
            != self.fit.parameters.decision_block_set_membership_sha256
            or self.decision_source_positions_sha256
            != self.fit.parameters.decision_source_positions_sha256
        ):
            raise HierarchicalStateV7ContractError("fit capability block binding drifted")
        if self.fit.parameters.fit_state_sha256 != self.training_state.state_binding_sha256:
            raise HierarchicalStateV7ContractError("fit capability state binding drifted")


def _normalize_requested_identities(requested: pd.DataFrame) -> pd.DataFrame:
    if type(requested) is not pd.DataFrame or requested.empty:
        raise HierarchicalStateV7ContractError("requested decision identities must be non-empty")
    if not requested.index.is_unique:
        raise HierarchicalStateV7ContractError("requested decision row identity must be unique")
    output = require_canonical_decision_identity_order_v7(requested, expected_index=requested.index)
    dates = pd.to_datetime(output[IDENTITY_COLUMNS[1]], errors="coerce")
    if len(pd.Index(dates.unique())) < 2:
        raise HierarchicalStateV7ContractError(
            "requested identities must span multiple decision dates"
        )
    return output


def _block_endpoints(requested: pd.DataFrame) -> tuple[pd.Timestamp, pd.Timestamp]:
    _, start, _, end, _ = decision_block_canonical_endpoints_v7(requested)
    return pd.Timestamp(start), pd.Timestamp(end)


def _require_exact_block_coverage(
    state: HierarchicalStateFrameV7,
    requested: pd.DataFrame,
) -> None:
    block_start, block_end = _block_endpoints(requested)
    dates = pd.to_datetime(state.identities[IDENTITY_COLUMNS[1]], errors="coerce")
    expected = state.identities.loc[
        dates.between(block_start, block_end, inclusive="both"),
        list(IDENTITY_COLUMNS),
    ]
    expected = require_canonical_decision_identity_order_v7(
        expected,
        expected_index=expected.index,
    )
    expected_rows = list(expected.itertuples(index=False, name=None))
    requested_rows = list(
        requested.loc[:, list(IDENTITY_COLUMNS)].itertuples(index=False, name=None)
    )
    if expected_rows != requested_rows:
        raise HierarchicalStateV7ContractError(
            "requested ordered entity/date membership does not exactly cover the test block"
        )


def build_decision_batch_v7(
    state: HierarchicalStateFrameV7,
    requested_identities: pd.DataFrame,
) -> DecisionBatchV7:
    """Select one decision batch by an exact one-to-one entity/date key join."""

    if type(state) is not HierarchicalStateFrameV7:
        raise HierarchicalStateV7ContractError("decision join requires a bound V7 state")
    state.assert_live_integrity()
    requested = _normalize_requested_identities(requested_identities)
    _require_exact_block_coverage(state, requested)
    state_keys = pd.MultiIndex.from_frame(state.identities.loc[:, list(IDENTITY_COLUMNS)])
    requested_keys = pd.MultiIndex.from_frame(requested.loc[:, list(IDENTITY_COLUMNS)])
    positions = state_keys.get_indexer(requested_keys)
    if (positions < 0).any():
        raise HierarchicalStateV7ContractError("requested decision identity is absent from state")
    if len(set(int(value) for value in positions)) != len(positions):
        raise HierarchicalStateV7ContractError("decision identity join is not one-to-one")
    selected = state.features.iloc[positions].copy()
    selected.index = requested.index.copy()
    selected_fallback_mask = tuple(
        bool(value) for value in state.regime_fallback_mask.iloc[positions].tolist()
    )
    selected_renormalized_mask = tuple(
        bool(value) for value in state.regime_renormalized_mask.iloc[positions].tolist()
    )
    selected_fallback_count = sum(selected_fallback_mask)
    selected_renormalized_count = sum(selected_renormalized_mask)
    selected_expected_warmup_mask = tuple(
        bool(value) for value in state.expected_regime_warmup_prefix_mask.iloc[positions].tolist()
    )
    selected_expected_warmup_count = sum(selected_expected_warmup_mask)
    return _create_decision_batch_v7(
        features=selected,
        identities=requested,
        source_state_sha256=state.state_binding_sha256,
        source_positions=tuple(int(value) for value in positions),
        source_row_count=len(state.features),
        decision_expected_regime_warmup_prefix_mask=selected_expected_warmup_mask,
        decision_expected_regime_warmup_prefix_count=selected_expected_warmup_count,
        decision_regime_fallback_mask=selected_fallback_mask,
        decision_regime_renormalized_mask=selected_renormalized_mask,
        decision_regime_fallback_count=selected_fallback_count,
        decision_regime_renormalized_count=selected_renormalized_count,
    )


def fit_chronological_prefix_v7(
    source: pd.DataFrame,
    *,
    decision_block_identities: pd.DataFrame,
    observed_pe: pd.Series,
    research_dgp_groups: pd.Series,
) -> ChronologicalFitCapabilityResultV7:
    """Fit once before, and freeze for, one exact multi-date decision block."""

    if type(source) is not pd.DataFrame or source.empty:
        raise HierarchicalStateV7ContractError("chronological source must be non-empty")
    if type(observed_pe) is not pd.Series or not observed_pe.index.equals(source.index):
        raise HierarchicalStateV7ContractError("observed proxy is not source-index-bound")
    if type(research_dgp_groups) is not pd.Series or not research_dgp_groups.index.equals(
        source.index
    ):
        raise HierarchicalStateV7ContractError("DGP nuisance groups are not source-index-bound")
    requested = _normalize_requested_identities(decision_block_identities)
    block_start, block_end = _block_endpoints(requested)
    dates = pd.to_datetime(source["date"], errors="coerce")
    if (
        block_start.tzinfo is not None
        or block_end.tzinfo is not None
        or dates.isna().any()
        or getattr(dates.dt, "tz", None) is not None
    ):
        raise HierarchicalStateV7ContractError("chronological decision/date is invalid")
    bounded_source = source.loc[dates <= block_end].copy()
    bounded_state = build_hierarchical_state_features_v7(bounded_source)
    decision_batch = build_decision_batch_v7(bounded_state, requested)
    prefix = dates < block_start
    if int(prefix.sum()) < 1:
        raise HierarchicalStateV7ContractError("chronological fit prefix is empty")
    prefix_source = source.loc[prefix].copy()
    state = build_hierarchical_state_features_v7(prefix_source)
    memberships = bind_research_dgp_nuisance_groups_v7(
        research_dgp_groups.loc[prefix].copy(),
        identities=state.identities,
    )
    fit = fit_hierarchical_state_v7(
        state,
        decision_block_identities=requested,
        decision_source_state_sha256=decision_batch.source_state_sha256,
        decision_source_positions=decision_batch.source_positions,
        decision_source_row_count=decision_batch.source_row_count,
        observed_pe=observed_pe.loc[prefix].copy(),
        research_dgp_memberships=memberships,
    )
    first_entity, block_start_date, last_entity, block_end_date, _ = (
        decision_block_canonical_endpoints_v7(requested)
    )
    return ChronologicalFitCapabilityResultV7(
        fit=fit,
        training_state=state,
        decision_block_start_date=block_start_date,
        decision_block_end_date=block_end_date,
        decision_block_first_entity_id=first_entity,
        decision_block_last_entity_id=last_entity,
        decision_block_ordered_membership_sha256=(
            decision_block_ordered_membership_sha256_v7(requested)
        ),
        decision_block_set_membership_sha256=decision_block_set_membership_sha256_v7(requested),
        decision_source_positions_sha256=decision_batch.decision_source_positions_sha256,
    )


def run_frozen_decision_block_v7(
    source: pd.DataFrame,
    *,
    requested_identities: pd.DataFrame,
    parameters: FrozenHierarchicalParametersV7,
) -> HierarchicalModelOutputV7:
    """Build causal state through one block and apply one unchanged parameter set."""

    if type(source) is not pd.DataFrame or source.empty:
        raise HierarchicalStateV7ContractError("decision source must be a non-empty DataFrame")
    if type(parameters) is not FrozenHierarchicalParametersV7:
        raise HierarchicalStateV7ContractError("decision parameters require exact V7 type")
    requested = _normalize_requested_identities(requested_identities)
    block_start, block_end = _block_endpoints(requested)
    first_entity, _, last_entity, _, _ = decision_block_canonical_endpoints_v7(requested)
    if (
        block_start != pd.Timestamp(parameters.decision_block_start_date)
        or block_end != pd.Timestamp(parameters.decision_block_end_date)
        or first_entity != parameters.decision_block_first_entity_id
        or last_entity != parameters.decision_block_last_entity_id
        or decision_block_ordered_membership_sha256_v7(requested)
        != parameters.decision_block_ordered_membership_sha256
        or decision_block_set_membership_sha256_v7(requested)
        != parameters.decision_block_set_membership_sha256
    ):
        raise HierarchicalStateV7ContractError(
            "requested block does not match frozen parameter custody"
        )
    dates = pd.to_datetime(source["date"], errors="coerce")
    if dates.isna().any():
        raise HierarchicalStateV7ContractError("source dates are invalid")
    bounded_source = source.loc[dates <= block_end].copy()
    state = build_hierarchical_state_features_v7(bounded_source)
    batch = build_decision_batch_v7(state, requested)
    return apply_frozen_parameters_v7(batch, parameters)


def load_and_run_frozen_decision_block_v7(
    source: pd.DataFrame,
    *,
    requested_identities: pd.DataFrame,
    bundle_directory: str | Path,
    expected_checksums_raw_sha256: str,
) -> HierarchicalModelOutputV7:
    """Load one exact frozen bundle, then run one bound decision block."""

    fit = load_frozen_parameter_bundle(
        bundle_directory,
        expected_checksums_raw_sha256=expected_checksums_raw_sha256,
    )
    return run_frozen_decision_block_v7(
        source,
        requested_identities=requested_identities,
        parameters=fit.parameters,
    )


__all__ = [
    "ChronologicalFitCapabilityResultV7",
    "build_decision_batch_v7",
    "fit_chronological_prefix_v7",
    "load_and_run_frozen_decision_block_v7",
    "run_frozen_decision_block_v7",
]
