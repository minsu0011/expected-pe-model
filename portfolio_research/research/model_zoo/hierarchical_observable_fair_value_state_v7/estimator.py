"""Deterministic chronological robust fitter for H-OFS V7.

The estimator is executable capability only.  It accepts caller-supplied,
production-observable prefix data and performs no file discovery, prediction
output, evaluation, score, registry, or promotion operation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import math
import struct
from typing import Any

import numpy as np
import pandas as pd

from .contracts import (
    ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY,
    CANDIDATE_ID,
    CONTEXT_COLUMNS,
    CONTEXT_RIDGE,
    DGP_NUISANCE_RIDGE,
    GLOBAL_RIDGE,
    HUBER_DELTA,
    IDENTITY_COLUMNS,
    INNOVATION_BOUNDS,
    INNOVATION_COLUMN,
    IRLS_MAX_ITERATIONS,
    IRLS_TOLERANCE,
    MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY,
    MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY,
    MIN_WARM_PREFIX_ROWS_PER_ENTITY,
    OFFSET_COLUMN,
    PERSISTENCE_BOUNDS,
    QP_KKT_TOLERANCE,
    QP_MAX_SWEEPS,
    REGIME_COLUMNS,
    REGIME_DEVIATION_RIDGE,
    REGIME_FALLBACK_MAX_COUNT,
    REGIME_FALLBACK_MAX_FRACTION,
    REGIME_SCALE_PSEUDO_COUNT,
    DGP_SCALE_PSEUDO_COUNT,
    ROBUST_SCALE_CEILING,
    ROBUST_SCALE_FLOOR,
    ROBUST_STANDARDIZATION_SCALE_FLOOR,
    STANDARDIZED_COLUMNS,
    STATE_DISPLACEMENT_COLUMN,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
    contract_sha256,
)
from .custody import (
    CANONICAL_DECISION_ORDER,
    decision_block_canonical_endpoints_v7,
    decision_block_ordered_membership_sha256_v7,
    decision_block_set_membership_sha256_v7,
    decision_source_positions_sha256_v7,
    require_canonical_decision_identity_order_v7,
)
from .features import (
    HierarchicalStateFrameV7,
    validate_research_dgp_nuisance_groups_v7,
)
from .runtime import ResourceReceiptV7, capture_runtime_receipt_v7
from .validation import (
    require_exact_bool,
    require_exact_float,
    require_exact_int,
    require_exact_str,
    require_exact_tuple,
    require_float_tuple,
    require_sha256,
)


_ZERO_SUM_TOLERANCE = 1e-10
_CANONICAL_NAN_BYTES = bytes.fromhex("000000000000f87f")


def _canonical_timestamp(value: str, *, label: str) -> pd.Timestamp:
    require_exact_str(value, label=label)
    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        raise HierarchicalStateV7ContractError(f"{label} is invalid")
    timestamp = pd.Timestamp(parsed)
    if timestamp.tzinfo is not None or timestamp.isoformat() != value:
        raise HierarchicalStateV7ContractError(f"{label} is not canonical timezone-naive ISO")
    return timestamp


def _validate_decision_custody_receipt(
    *,
    ordered_identity_rows: tuple[tuple[str, str], ...],
    source_state_sha256: str,
    source_positions: tuple[int, ...],
    source_row_count: int,
    block_start_date: str,
    block_end_date: str,
    block_first_entity_id: str,
    block_last_entity_id: str,
    ordered_membership_sha256: str,
    set_membership_sha256: str,
    source_positions_sha256: str,
    decision_row_count: int,
    decision_distinct_date_count: int,
    label: str,
) -> None:
    rows = require_exact_tuple(
        ordered_identity_rows,
        label=f"{label} ordered identity rows",
        length=decision_row_count,
    )
    records: list[tuple[str, pd.Timestamp]] = []
    for position, row in enumerate(rows):
        values = require_exact_tuple(
            row,
            label=f"{label} ordered identity rows[{position}]",
            length=2,
        )
        entity = require_exact_str(
            values[0], label=f"{label} ordered identity rows[{position}].entity"
        )
        date_text = require_exact_str(
            values[1], label=f"{label} ordered identity rows[{position}].date"
        )
        records.append((entity, _canonical_timestamp(date_text, label=f"{label} identity date")))
    identities = pd.DataFrame.from_records(records, columns=list(IDENTITY_COLUMNS))
    canonical = require_canonical_decision_identity_order_v7(
        identities,
        expected_index=identities.index,
    )
    first_entity, first_date, last_entity, last_date, distinct_count = (
        decision_block_canonical_endpoints_v7(canonical)
    )
    if (
        block_start_date != first_date
        or block_end_date != last_date
        or block_first_entity_id != first_entity
        or block_last_entity_id != last_entity
        or decision_distinct_date_count != distinct_count
        or ordered_membership_sha256 != decision_block_ordered_membership_sha256_v7(canonical)
        or set_membership_sha256 != decision_block_set_membership_sha256_v7(canonical)
        or source_positions_sha256
        != decision_source_positions_sha256_v7(
            canonical,
            source_state_sha256=source_state_sha256,
            source_positions=source_positions,
            source_row_count=source_row_count,
        )
    ):
        raise HierarchicalStateV7ContractError(
            f"{label} ordered/set/endpoint/source-position custody drifted"
        )


@dataclass(frozen=True)
class FitReceiptV7:
    candidate_id: str
    design_contract_sha256: str
    fit_config_sha256: str
    fit_identity_sha256: str
    fit_feature_sha256: str
    fit_state_sha256: str
    fit_target_sha256: str
    dgp_partition_sha256: str
    resource_receipt_sha256: str
    fit_start_date: str
    fit_end_date: str
    decision_block_start_date: str
    decision_block_end_date: str
    decision_block_first_entity_id: str
    decision_block_last_entity_id: str
    decision_ordered_identity_rows: tuple[tuple[str, str], ...]
    decision_source_state_sha256: str
    decision_source_positions: tuple[int, ...]
    decision_source_row_count: int
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_source_positions_sha256: str
    decision_row_count: int
    decision_distinct_date_count: int
    within_block_parameter_update_count: int
    prefix_entity_count: int
    prefix_entity_row_counts: tuple[tuple[str, int, int, int], ...]
    prefix_entity_row_counts_sha256: str
    prefix_entity_causal_invalid_positions: tuple[tuple[str, tuple[int, ...]], ...]
    prefix_entity_causal_invalid_positions_sha256: str
    requested_row_count: int
    fit_row_count: int
    dropped_nonwarm_row_count: int
    causal_prefix_nonwarm_row_count: int
    dgp_group_count: int
    missing_context_cell_count: int
    source_regime_fallback_count: int
    source_regime_renormalized_count: int
    expected_regime_warmup_prefix_count: int
    expected_regime_warmup_prefix_sha256: str
    irls_iterations: int
    irls_converged: bool
    final_coefficient_delta: float
    final_weight_delta: float
    final_huber_objective: float
    final_conditional_huber_scale: float
    deploy_marginalized_scale: float
    active_bound_count: int
    final_kkt_violation: float
    total_qp_coordinate_sweeps: int
    dgp_mean_nuisance_sha256: str
    dgp_scale_nuisance_sha256: str
    dgp_effects_marginalized_for_deploy: bool
    fixed_row_order: str
    fixed_normal_equation_accumulation: str

    def __post_init__(self) -> None:
        for label, value in (
            ("candidate", self.candidate_id),
            ("fit start", self.fit_start_date),
            ("fit end", self.fit_end_date),
            ("block start", self.decision_block_start_date),
            ("block end", self.decision_block_end_date),
            ("block first entity", self.decision_block_first_entity_id),
            ("block last entity", self.decision_block_last_entity_id),
            ("fixed row order", self.fixed_row_order),
            ("fixed accumulation", self.fixed_normal_equation_accumulation),
        ):
            require_exact_str(value, label=f"fit receipt {label}")
        for label, value in (
            ("requested rows", self.requested_row_count),
            ("fit rows", self.fit_row_count),
            ("dropped rows", self.dropped_nonwarm_row_count),
            (
                "causal prefix nonwarm rows",
                self.causal_prefix_nonwarm_row_count,
            ),
            ("decision rows", self.decision_row_count),
            ("decision distinct dates", self.decision_distinct_date_count),
            ("within-block updates", self.within_block_parameter_update_count),
            ("prefix entities", self.prefix_entity_count),
            ("DGP groups", self.dgp_group_count),
            ("missing cells", self.missing_context_cell_count),
            ("fallback count", self.source_regime_fallback_count),
            ("renormalized count", self.source_regime_renormalized_count),
            (
                "expected regime warmup count",
                self.expected_regime_warmup_prefix_count,
            ),
            ("IRLS iterations", self.irls_iterations),
            ("active bounds", self.active_bound_count),
            ("QP sweeps", self.total_qp_coordinate_sweeps),
            ("decision source rows", self.decision_source_row_count),
        ):
            require_exact_int(value, label=f"fit receipt {label}", minimum=0)
        require_exact_bool(self.irls_converged, label="fit receipt convergence")
        require_exact_bool(
            self.dgp_effects_marginalized_for_deploy,
            label="fit receipt DGP marginalization",
        )
        for label, value in (
            ("coefficient delta", self.final_coefficient_delta),
            ("weight delta", self.final_weight_delta),
            ("Huber objective", self.final_huber_objective),
            ("conditional scale", self.final_conditional_huber_scale),
            ("deploy scale", self.deploy_marginalized_scale),
            ("KKT", self.final_kkt_violation),
        ):
            require_exact_float(value, label=f"fit receipt {label}")
        if self.candidate_id != CANDIDATE_ID:
            raise HierarchicalStateV7ContractError("fit receipt candidate drifted")
        if self.design_contract_sha256 != contract_sha256():
            raise HierarchicalStateV7ContractError("fit receipt contract drifted")
        hashes = (
            self.fit_config_sha256,
            self.fit_identity_sha256,
            self.fit_feature_sha256,
            self.fit_state_sha256,
            self.fit_target_sha256,
            self.dgp_partition_sha256,
            self.resource_receipt_sha256,
            self.dgp_mean_nuisance_sha256,
            self.dgp_scale_nuisance_sha256,
            self.decision_source_state_sha256,
            self.decision_block_ordered_membership_sha256,
            self.decision_block_set_membership_sha256,
            self.decision_source_positions_sha256,
            self.prefix_entity_row_counts_sha256,
            self.prefix_entity_causal_invalid_positions_sha256,
            self.expected_regime_warmup_prefix_sha256,
        )
        for value in hashes:
            require_sha256(value, label="fit receipt provenance hash")
        if self.fit_config_sha256 != fit_config_sha256():
            raise HierarchicalStateV7ContractError("fit receipt configuration drifted")
        _validate_decision_custody_receipt(
            ordered_identity_rows=self.decision_ordered_identity_rows,
            source_state_sha256=self.decision_source_state_sha256,
            source_positions=self.decision_source_positions,
            source_row_count=self.decision_source_row_count,
            block_start_date=self.decision_block_start_date,
            block_end_date=self.decision_block_end_date,
            block_first_entity_id=self.decision_block_first_entity_id,
            block_last_entity_id=self.decision_block_last_entity_id,
            ordered_membership_sha256=self.decision_block_ordered_membership_sha256,
            set_membership_sha256=self.decision_block_set_membership_sha256,
            source_positions_sha256=self.decision_source_positions_sha256,
            decision_row_count=self.decision_row_count,
            decision_distinct_date_count=self.decision_distinct_date_count,
            label="fit receipt decision custody",
        )
        fit_start = _canonical_timestamp(self.fit_start_date, label="fit start date")
        fit_end = _canonical_timestamp(self.fit_end_date, label="fit end date")
        block_start = _canonical_timestamp(
            self.decision_block_start_date, label="decision block start date"
        )
        block_end = _canonical_timestamp(
            self.decision_block_end_date, label="decision block end date"
        )
        if fit_start > fit_end or not fit_end < block_start <= block_end:
            raise HierarchicalStateV7ContractError("fit receipt crossed its decision block")
        if self.decision_distinct_date_count < 2:
            raise HierarchicalStateV7ContractError(
                "fit receipt decision block must contain multiple dates"
            )
        if self.within_block_parameter_update_count != 0:
            raise HierarchicalStateV7ContractError(
                "fit receipt forbids within-block parameter updates"
            )
        rows = require_exact_tuple(
            self.prefix_entity_row_counts,
            label="fit receipt prefix entity row counts",
            length=self.prefix_entity_count,
        )
        normalized_rows: list[list[object]] = []
        invalid_position_rows = require_exact_tuple(
            self.prefix_entity_causal_invalid_positions,
            label="fit receipt prefix entity causal invalid positions",
            length=self.prefix_entity_count,
        )
        normalized_invalid_positions: list[list[object]] = []
        seen_entities: set[str] = set()
        totals = [0, 0, 0]
        for position, row in enumerate(rows):
            values = require_exact_tuple(
                row,
                label=f"fit receipt prefix entity row counts[{position}]",
                length=4,
            )
            entity = require_exact_str(
                values[0],
                label=f"fit receipt prefix entity row counts[{position}].entity",
            )
            requested = require_exact_int(
                values[1],
                label=f"fit receipt prefix entity row counts[{position}].requested",
                minimum=0,
            )
            nonwarm = require_exact_int(
                values[2],
                label=f"fit receipt prefix entity row counts[{position}].nonwarm",
                minimum=0,
            )
            warm = require_exact_int(
                values[3],
                label=f"fit receipt prefix entity row counts[{position}].warm",
                minimum=0,
            )
            if entity in seen_entities or (
                requested < MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY
                or nonwarm != MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY
                or warm != requested - nonwarm
                or warm < MIN_WARM_PREFIX_ROWS_PER_ENTITY
            ):
                raise HierarchicalStateV7ContractError(
                    "fit receipt per-entity requested/nonwarm/warm relationship is invalid"
                )
            seen_entities.add(entity)
            totals[0] += requested
            totals[1] += nonwarm
            totals[2] += warm
            normalized_rows.append([entity, requested, nonwarm, warm])
            invalid_row = require_exact_tuple(
                invalid_position_rows[position],
                label=f"fit receipt prefix entity causal invalid positions[{position}]",
                length=2,
            )
            invalid_entity = require_exact_str(
                invalid_row[0],
                label=(
                    f"fit receipt prefix entity causal invalid positions[{position}].entity"
                ),
            )
            invalid_positions = require_exact_tuple(
                invalid_row[1],
                label=(
                    f"fit receipt prefix entity causal invalid positions[{position}].positions"
                ),
                length=MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY,
            )
            normalized_positions = tuple(
                require_exact_int(
                    value,
                    label=(
                        "fit receipt prefix entity causal invalid positions"
                        f"[{position}].positions[{index}]"
                    ),
                    minimum=0,
                )
                for index, value in enumerate(invalid_positions)
            )
            if (
                invalid_entity != entity
                or normalized_positions != ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
                or len(set(normalized_positions)) != len(normalized_positions)
                or tuple(sorted(normalized_positions)) != normalized_positions
                or len(normalized_positions) != nonwarm
            ):
                raise HierarchicalStateV7ContractError(
                    "fit receipt causal invalid-position policy drifted"
                )
            normalized_invalid_positions.append([entity, list(normalized_positions)])
        if tuple(seen_entities) and tuple(sorted(seen_entities)) != tuple(row[0] for row in rows):
            raise HierarchicalStateV7ContractError(
                "fit receipt prefix entity rows are not canonically ordered"
            )
        expected_prefix_hash = hashlib.sha256(canonical_json_bytes(normalized_rows)).hexdigest()
        if self.prefix_entity_row_counts_sha256 != expected_prefix_hash:
            raise HierarchicalStateV7ContractError("fit receipt prefix entity count hash drifted")
        expected_invalid_positions_hash = hashlib.sha256(
            canonical_json_bytes(normalized_invalid_positions)
        ).hexdigest()
        if (
            self.prefix_entity_causal_invalid_positions_sha256
            != expected_invalid_positions_hash
        ):
            raise HierarchicalStateV7ContractError(
                "fit receipt causal invalid-position hash drifted"
            )
        if (
            self.prefix_entity_count < 1
            or totals
            != [
                self.requested_row_count,
                self.causal_prefix_nonwarm_row_count,
                self.fit_row_count,
            ]
            or self.dropped_nonwarm_row_count != self.causal_prefix_nonwarm_row_count
            or self.dropped_nonwarm_row_count != self.requested_row_count - self.fit_row_count
        ):
            raise HierarchicalStateV7ContractError("fit receipt row counts are inconsistent")
        if not 1 <= self.dgp_group_count <= self.fit_row_count:
            raise HierarchicalStateV7ContractError("fit receipt DGP group count is invalid")
        if self.decision_row_count < self.decision_distinct_date_count:
            raise HierarchicalStateV7ContractError("fit receipt decision row count is invalid")
        if (
            not 0
            <= self.missing_context_cell_count
            <= self.fit_row_count * len(STANDARDIZED_COLUMNS)
        ):
            raise HierarchicalStateV7ContractError("fit receipt context count is invalid")
        for label, count in (
            ("expected warmup", self.expected_regime_warmup_prefix_count),
            ("fallback", self.source_regime_fallback_count),
            ("renormalized", self.source_regime_renormalized_count),
        ):
            if not 0 <= count <= self.fit_row_count:
                raise HierarchicalStateV7ContractError(
                    f"fit receipt regime {label} count is invalid"
                )
        if (
            self.source_regime_fallback_count > REGIME_FALLBACK_MAX_COUNT
            or self.source_regime_fallback_count / self.fit_row_count > REGIME_FALLBACK_MAX_FRACTION
        ):
            raise HierarchicalStateV7ContractError(
                "fit receipt fallback gate exceeds exact fit-row denominator"
            )
        if not self.irls_converged or not 2 <= self.irls_iterations <= IRLS_MAX_ITERATIONS:
            raise HierarchicalStateV7ContractError("non-converged IRLS fit cannot be receipted")
        numeric = (
            self.final_coefficient_delta,
            self.final_weight_delta,
            self.final_huber_objective,
            self.final_conditional_huber_scale,
            self.deploy_marginalized_scale,
            self.final_kkt_violation,
        )
        if not np.isfinite(np.asarray(numeric, dtype=np.float64)).all():
            raise HierarchicalStateV7ContractError("fit receipt contains non-finite diagnostics")
        if not 0.0 <= self.final_coefficient_delta <= IRLS_TOLERANCE:
            raise HierarchicalStateV7ContractError("fit receipt coefficient gate failed")
        if not 0.0 <= self.final_weight_delta <= IRLS_TOLERANCE:
            raise HierarchicalStateV7ContractError("fit receipt weight gate failed")
        if not 0.0 <= self.final_kkt_violation <= QP_KKT_TOLERANCE:
            raise HierarchicalStateV7ContractError("fit receipt final-weight KKT gate failed")
        if self.final_huber_objective < 0.0:
            raise HierarchicalStateV7ContractError("fit receipt objective is invalid")
        for label, scale in (
            ("conditional", self.final_conditional_huber_scale),
            ("deploy", self.deploy_marginalized_scale),
        ):
            if not ROBUST_SCALE_FLOOR <= scale <= ROBUST_SCALE_CEILING:
                raise HierarchicalStateV7ContractError(f"fit receipt {label} scale is invalid")
        if not 0 <= self.active_bound_count <= 6:
            raise HierarchicalStateV7ContractError("fit receipt active bound count is invalid")
        if (
            not self.irls_iterations
            <= self.total_qp_coordinate_sweeps
            <= (self.irls_iterations * QP_MAX_SWEEPS)
        ):
            raise HierarchicalStateV7ContractError("fit receipt QP sweep count is invalid")
        if not self.dgp_effects_marginalized_for_deploy:
            raise HierarchicalStateV7ContractError("DGP nuisance must be marginalized")
        if self.fixed_row_order != CANONICAL_DECISION_ORDER:
            raise HierarchicalStateV7ContractError("fit receipt row order drifted")
        if self.fixed_normal_equation_accumulation != "sequential_row_outer_product":
            raise HierarchicalStateV7ContractError("fit receipt accumulation drifted")

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.payload())).hexdigest()


@dataclass(frozen=True)
class FrozenHierarchicalParametersV7:
    """Deployable parameters containing no DGP identity or nuisance effect."""

    candidate_id: str
    design_contract_sha256: str
    fit_start_date: str
    fit_end_date: str
    decision_block_start_date: str
    decision_block_end_date: str
    decision_block_first_entity_id: str
    decision_block_last_entity_id: str
    decision_ordered_identity_rows: tuple[tuple[str, str], ...]
    decision_source_state_sha256: str
    decision_source_positions: tuple[int, ...]
    decision_source_row_count: int
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_source_positions_sha256: str
    decision_row_count: int
    decision_distinct_date_count: int
    within_block_parameter_update_count: int
    fit_row_count: int
    fit_identity_sha256: str
    fit_feature_sha256: str
    fit_state_sha256: str
    fit_target_sha256: str
    fit_config_sha256: str
    convergence_receipt_sha256: str
    resource_receipt_sha256: str
    robust_centers: tuple[float, ...]
    robust_scales: tuple[float, ...]
    global_intercept: float
    global_persistence: float
    global_innovation: float
    context_coefficients: tuple[float, ...]
    regime_intercept_deviations: tuple[float, float, float]
    regime_persistence_deviations: tuple[float, float, float]
    regime_innovation_deviations: tuple[float, float, float]
    global_log_scale: float
    regime_log_scale_deviations: tuple[float, float, float]
    research_dgp_effects_marginalized: bool
    training_target: str

    def __post_init__(self) -> None:
        for label, value in (
            ("candidate", self.candidate_id),
            ("fit start", self.fit_start_date),
            ("fit end", self.fit_end_date),
            ("block start", self.decision_block_start_date),
            ("block end", self.decision_block_end_date),
            ("block first entity", self.decision_block_first_entity_id),
            ("block last entity", self.decision_block_last_entity_id),
            ("training target", self.training_target),
        ):
            require_exact_str(value, label=f"parameter {label}")
        require_exact_int(self.fit_row_count, label="parameter fit row count", minimum=0)
        require_exact_int(
            self.decision_row_count,
            label="parameter decision row count",
            minimum=2,
        )
        require_exact_int(
            self.decision_distinct_date_count,
            label="parameter decision distinct date count",
            minimum=2,
        )
        require_exact_int(
            self.within_block_parameter_update_count,
            label="parameter within-block update count",
            minimum=0,
        )
        require_exact_int(
            self.decision_source_row_count,
            label="parameter decision source row count",
            minimum=1,
        )
        require_exact_bool(
            self.research_dgp_effects_marginalized,
            label="parameter DGP marginalization",
        )
        for label, values, length in (
            ("robust centers", self.robust_centers, len(STANDARDIZED_COLUMNS)),
            ("robust scales", self.robust_scales, len(STANDARDIZED_COLUMNS)),
            ("context coefficients", self.context_coefficients, len(CONTEXT_COLUMNS)),
            ("regime intercept", self.regime_intercept_deviations, 3),
            ("regime persistence", self.regime_persistence_deviations, 3),
            ("regime innovation", self.regime_innovation_deviations, 3),
            ("regime log scale", self.regime_log_scale_deviations, 3),
        ):
            require_float_tuple(values, label=f"parameter {label}", length=length)
        for label, value in (
            ("global intercept", self.global_intercept),
            ("global persistence", self.global_persistence),
            ("global innovation", self.global_innovation),
            ("global log scale", self.global_log_scale),
        ):
            require_exact_float(value, label=f"parameter {label}")
        if self.candidate_id != CANDIDATE_ID:
            raise HierarchicalStateV7ContractError("parameter candidate drifted")
        if self.design_contract_sha256 != contract_sha256():
            raise HierarchicalStateV7ContractError("parameter contract drifted")
        if self.fit_row_count < MIN_WARM_PREFIX_ROWS_PER_ENTITY:
            raise HierarchicalStateV7ContractError("parameter fit row receipt is invalid")
        start = _canonical_timestamp(self.fit_start_date, label="parameter fit start date")
        end = _canonical_timestamp(self.fit_end_date, label="parameter fit end date")
        block_start = _canonical_timestamp(
            self.decision_block_start_date, label="parameter block start date"
        )
        block_end = _canonical_timestamp(
            self.decision_block_end_date, label="parameter block end date"
        )
        if start > end or not end < block_start <= block_end:
            raise HierarchicalStateV7ContractError("parameter chronology receipt is invalid")
        if (
            self.decision_row_count < self.decision_distinct_date_count
            or self.within_block_parameter_update_count != 0
        ):
            raise HierarchicalStateV7ContractError("parameter decision block receipt is invalid")
        if not self.research_dgp_effects_marginalized:
            raise HierarchicalStateV7ContractError("research DGP effects must be marginalized")
        if self.training_target != "log_observed_pe_proxy_minus_prior_offset":
            raise HierarchicalStateV7ContractError("parameter training target drifted")
        hashes = (
            self.fit_identity_sha256,
            self.fit_feature_sha256,
            self.fit_state_sha256,
            self.fit_target_sha256,
            self.fit_config_sha256,
            self.convergence_receipt_sha256,
            self.resource_receipt_sha256,
            self.decision_source_state_sha256,
            self.decision_block_ordered_membership_sha256,
            self.decision_block_set_membership_sha256,
            self.decision_source_positions_sha256,
        )
        for value in hashes:
            require_sha256(value, label="parameter provenance hash")
        if self.fit_config_sha256 != fit_config_sha256():
            raise HierarchicalStateV7ContractError("parameter fit configuration drifted")
        _validate_decision_custody_receipt(
            ordered_identity_rows=self.decision_ordered_identity_rows,
            source_state_sha256=self.decision_source_state_sha256,
            source_positions=self.decision_source_positions,
            source_row_count=self.decision_source_row_count,
            block_start_date=self.decision_block_start_date,
            block_end_date=self.decision_block_end_date,
            block_first_entity_id=self.decision_block_first_entity_id,
            block_last_entity_id=self.decision_block_last_entity_id,
            ordered_membership_sha256=self.decision_block_ordered_membership_sha256,
            set_membership_sha256=self.decision_block_set_membership_sha256,
            source_positions_sha256=self.decision_source_positions_sha256,
            decision_row_count=self.decision_row_count,
            decision_distinct_date_count=self.decision_distinct_date_count,
            label="parameter decision custody",
        )
        if len(self.robust_centers) != len(STANDARDIZED_COLUMNS):
            raise HierarchicalStateV7ContractError("robust center dimension drifted")
        if len(self.robust_scales) != len(STANDARDIZED_COLUMNS):
            raise HierarchicalStateV7ContractError("robust scale dimension drifted")
        if len(self.context_coefficients) != len(CONTEXT_COLUMNS):
            raise HierarchicalStateV7ContractError("context coefficient dimension drifted")
        vectors = (
            self.robust_centers,
            self.robust_scales,
            self.context_coefficients,
            self.regime_intercept_deviations,
            self.regime_persistence_deviations,
            self.regime_innovation_deviations,
            self.regime_log_scale_deviations,
        )
        scalars = (
            self.global_intercept,
            self.global_persistence,
            self.global_innovation,
            self.global_log_scale,
        )
        if any(not np.isfinite(np.asarray(values, dtype=np.float64)).all() for values in vectors):
            raise HierarchicalStateV7ContractError("parameter bundle has non-finite vectors")
        if not np.isfinite(np.asarray(scalars, dtype=np.float64)).all():
            raise HierarchicalStateV7ContractError("parameter bundle has non-finite scalars")
        if any(value < ROBUST_STANDARDIZATION_SCALE_FLOOR for value in self.robust_scales):
            raise HierarchicalStateV7ContractError("robust standardization scales must be positive")
        for label, deviations in (
            ("intercept", self.regime_intercept_deviations),
            ("persistence", self.regime_persistence_deviations),
            ("innovation", self.regime_innovation_deviations),
            ("log scale", self.regime_log_scale_deviations),
        ):
            if abs(math.fsum(deviations)) > _ZERO_SUM_TOLERANCE:
                raise HierarchicalStateV7ContractError(
                    f"regime {label} deviations must sum to zero"
                )
        _validate_effective_bounds(
            self.global_persistence,
            self.regime_persistence_deviations,
            PERSISTENCE_BOUNDS,
            "persistence",
        )
        _validate_effective_bounds(
            self.global_innovation,
            self.regime_innovation_deviations,
            INNOVATION_BOUNDS,
            "innovation",
        )
        _validate_effective_bounds(
            self.global_log_scale,
            self.regime_log_scale_deviations,
            (math.log(ROBUST_SCALE_FLOOR), math.log(ROBUST_SCALE_CEILING)),
            "log scale",
        )

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.payload())).hexdigest()


@dataclass(frozen=True)
class HierarchicalFitResultV7:
    parameters: FrozenHierarchicalParametersV7
    fit_receipt: FitReceiptV7
    resource_receipt: ResourceReceiptV7

    def __post_init__(self) -> None:
        if type(self.parameters) is not FrozenHierarchicalParametersV7:
            raise HierarchicalStateV7ContractError("fit result parameters are invalid")
        if type(self.fit_receipt) is not FitReceiptV7:
            raise HierarchicalStateV7ContractError("fit result receipt is invalid")
        if type(self.resource_receipt) is not ResourceReceiptV7:
            raise HierarchicalStateV7ContractError("fit result resource receipt is invalid")
        if self.resource_receipt.purpose != "FIT":
            raise HierarchicalStateV7ContractError("fit result requires a FIT resource receipt")
        if self.parameters.convergence_receipt_sha256 != self.fit_receipt.sha256():
            raise HierarchicalStateV7ContractError("parameter/fit receipt binding failed")
        if self.parameters.resource_receipt_sha256 != self.resource_receipt.sha256():
            raise HierarchicalStateV7ContractError("parameter/resource receipt binding failed")
        if self.fit_receipt.resource_receipt_sha256 != self.resource_receipt.sha256():
            raise HierarchicalStateV7ContractError("fit/resource receipt binding failed")
        exact_pairs = {
            "candidate": (self.parameters.candidate_id, self.fit_receipt.candidate_id),
            "contract": (
                self.parameters.design_contract_sha256,
                self.fit_receipt.design_contract_sha256,
            ),
            "fit start": (self.parameters.fit_start_date, self.fit_receipt.fit_start_date),
            "fit end": (self.parameters.fit_end_date, self.fit_receipt.fit_end_date),
            "block start": (
                self.parameters.decision_block_start_date,
                self.fit_receipt.decision_block_start_date,
            ),
            "block end": (
                self.parameters.decision_block_end_date,
                self.fit_receipt.decision_block_end_date,
            ),
            "block first entity": (
                self.parameters.decision_block_first_entity_id,
                self.fit_receipt.decision_block_first_entity_id,
            ),
            "block last entity": (
                self.parameters.decision_block_last_entity_id,
                self.fit_receipt.decision_block_last_entity_id,
            ),
            "decision ordered identity rows": (
                self.parameters.decision_ordered_identity_rows,
                self.fit_receipt.decision_ordered_identity_rows,
            ),
            "decision source state": (
                self.parameters.decision_source_state_sha256,
                self.fit_receipt.decision_source_state_sha256,
            ),
            "decision source positions raw": (
                self.parameters.decision_source_positions,
                self.fit_receipt.decision_source_positions,
            ),
            "decision source rows": (
                self.parameters.decision_source_row_count,
                self.fit_receipt.decision_source_row_count,
            ),
            "decision ordered membership": (
                self.parameters.decision_block_ordered_membership_sha256,
                self.fit_receipt.decision_block_ordered_membership_sha256,
            ),
            "decision set membership": (
                self.parameters.decision_block_set_membership_sha256,
                self.fit_receipt.decision_block_set_membership_sha256,
            ),
            "decision source positions": (
                self.parameters.decision_source_positions_sha256,
                self.fit_receipt.decision_source_positions_sha256,
            ),
            "decision rows": (
                self.parameters.decision_row_count,
                self.fit_receipt.decision_row_count,
            ),
            "decision dates": (
                self.parameters.decision_distinct_date_count,
                self.fit_receipt.decision_distinct_date_count,
            ),
            "within-block updates": (
                self.parameters.within_block_parameter_update_count,
                self.fit_receipt.within_block_parameter_update_count,
            ),
            "fit rows": (self.parameters.fit_row_count, self.fit_receipt.fit_row_count),
            "identity": (
                self.parameters.fit_identity_sha256,
                self.fit_receipt.fit_identity_sha256,
            ),
            "features": (
                self.parameters.fit_feature_sha256,
                self.fit_receipt.fit_feature_sha256,
            ),
            "state": (
                self.parameters.fit_state_sha256,
                self.fit_receipt.fit_state_sha256,
            ),
            "target": (
                self.parameters.fit_target_sha256,
                self.fit_receipt.fit_target_sha256,
            ),
            "configuration": (
                self.parameters.fit_config_sha256,
                self.fit_receipt.fit_config_sha256,
            ),
        }
        drifted = [name for name, (left, right) in exact_pairs.items() if left != right]
        if drifted:
            raise HierarchicalStateV7ContractError(
                f"fit result cross-object provenance drift: {sorted(drifted)}"
            )


def _validate_effective_bounds(
    global_value: float,
    deviations: tuple[float, float, float],
    bounds: tuple[float, float],
    label: str,
) -> None:
    values = (global_value, *(global_value + value for value in deviations))
    if any(value < bounds[0] - 1e-12 or value > bounds[1] + 1e-12 for value in values):
        raise HierarchicalStateV7ContractError(f"effective {label} leaves fixed bounds")


def _fit_config_payload() -> dict[str, Any]:
    return {
        "candidate_id": CANDIDATE_ID,
        "design_contract_sha256": contract_sha256(),
        "huber_delta": HUBER_DELTA,
        "global_ridge": GLOBAL_RIDGE,
        "context_ridge": CONTEXT_RIDGE,
        "regime_deviation_ridge": REGIME_DEVIATION_RIDGE,
        "dgp_nuisance_ridge": DGP_NUISANCE_RIDGE,
        "irls_max_iterations": IRLS_MAX_ITERATIONS,
        "irls_tolerance": IRLS_TOLERANCE,
        "box_qp_max_coordinate_sweeps": QP_MAX_SWEEPS,
        "box_qp_kkt_tolerance": QP_KKT_TOLERANCE,
        "minimum_requested_prefix_rows_per_entity": MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY,
        "minimum_warm_prefix_rows_per_entity": MIN_WARM_PREFIX_ROWS_PER_ENTITY,
        "allowed_causal_invalid_positions_per_entity": list(
            ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
        ),
        "maximum_causal_prefix_nonwarm_per_entity": MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY,
        "decision_binding": "exact_multi_date_entity_date_membership",
        "within_block_parameter_update_count": 0,
        "persistence_bounds": list(PERSISTENCE_BOUNDS),
        "innovation_bounds": list(INNOVATION_BOUNDS),
        "fixed_row_order": CANONICAL_DECISION_ORDER,
        "normal_equation_accumulation": "sequential_row_outer_product",
        "objective": "row_sum_huber_plus_one_half_quadratic_penalty",
        "feature_scale": "1p4826_mad_then_iqr_over_1p349_then_population_std_then_1",
        "residual_scale": "1p4826_centered_mad_then_centered_rms_then_fixed_floor",
        "final_kkt": "recomputed_on_final_huber_weights",
        "final_weight_tolerance": IRLS_TOLERANCE,
        "deploy_scale_residual": "DGP_MEAN_NUISANCE_MARGINALIZED_TO_ZERO",
    }


def fit_config_sha256() -> str:
    return hashlib.sha256(canonical_json_bytes(_fit_config_payload())).hexdigest()


def _float_frame_sha256(frame: pd.DataFrame) -> str:
    digest = hashlib.sha256(canonical_json_bytes({"columns": list(frame.columns)}))
    values = frame.to_numpy(dtype=np.float64)
    for value in values.ravel(order="C"):
        digest.update(
            struct.pack("<d", float(value)) if np.isfinite(value) else _CANONICAL_NAN_BYTES
        )
    return digest.hexdigest()


def _float_vector_sha256(values: np.ndarray, label: str) -> str:
    digest = hashlib.sha256(canonical_json_bytes({"label": label, "length": len(values)}))
    for value in np.asarray(values, dtype=np.float64):
        digest.update(
            struct.pack("<d", float(value)) if np.isfinite(value) else _CANONICAL_NAN_BYTES
        )
    return digest.hexdigest()


def _identity_sha256(identities: pd.DataFrame) -> str:
    records = [
        {
            "entity_id": str(entity),
            "decision_date": pd.Timestamp(date).isoformat(),
        }
        for entity, date in identities.loc[:, list(IDENTITY_COLUMNS)].itertuples(
            index=False, name=None
        )
    ]
    return hashlib.sha256(canonical_json_bytes(records)).hexdigest()


def _mask_membership_sha256(
    identities: pd.DataFrame,
    mask: np.ndarray,
    *,
    label: str,
) -> str:
    selected = identities.iloc[np.flatnonzero(mask)]
    rows = sorted(
        (entity, pd.Timestamp(date).isoformat())
        for entity, date in selected.loc[:, list(IDENTITY_COLUMNS)].itertuples(
            index=False,
            name=None,
        )
    )
    return hashlib.sha256(
        canonical_json_bytes({"label": label, "membership": [list(row) for row in rows]})
    ).hexdigest()


def causal_training_valid_mask_v7(
    observed_pe: pd.Series | np.ndarray,
    offset_prior_log_pe: pd.Series | np.ndarray,
) -> np.ndarray:
    """Return the one sealed validity predicate used by public checks and fitting."""

    proxy = pd.to_numeric(pd.Series(observed_pe), errors="coerce").to_numpy(dtype=np.float64)
    offset = pd.to_numeric(pd.Series(offset_prior_log_pe), errors="coerce").to_numpy(
        dtype=np.float64
    )
    if proxy.ndim != 1 or offset.ndim != 1 or proxy.shape != offset.shape:
        raise HierarchicalStateV7ContractError("causal validity inputs are not aligned vectors")
    return np.isfinite(proxy) & (proxy > 0.0) & np.isfinite(offset)


def _prefix_entity_row_receipt(
    identities: pd.DataFrame,
    valid: np.ndarray,
) -> tuple[
    tuple[tuple[str, int, int, int], ...],
    str,
    tuple[tuple[str, tuple[int, ...]], ...],
    str,
]:
    order = identities.loc[:, list(IDENTITY_COLUMNS)].copy()
    order["_position"] = np.arange(len(order), dtype=np.int64)
    order = order.sort_values(list(IDENTITY_COLUMNS), kind="mergesort")
    rows: list[tuple[str, int, int, int]] = []
    invalid_position_rows: list[tuple[str, tuple[int, ...]]] = []
    for entity, group in order.groupby(IDENTITY_COLUMNS[0], sort=False):
        positions = group["_position"].to_numpy(dtype=np.int64)
        entity_valid = valid[positions]
        requested = len(positions)
        nonwarm_positions = np.flatnonzero(~entity_valid)
        normalized_nonwarm_positions = tuple(int(value) for value in nonwarm_positions)
        if (
            requested < MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY
            or normalized_nonwarm_positions
            != ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
        ):
            raise HierarchicalStateV7ContractError(
                "per-entity prefix violates exact causal invalid-position policy"
            )
        nonwarm = len(nonwarm_positions)
        warm = int(entity_valid.sum())
        if warm != requested - nonwarm or warm < MIN_WARM_PREFIX_ROWS_PER_ENTITY:
            raise HierarchicalStateV7ContractError(
                "per-entity prefix requested/nonwarm/warm relationship is invalid"
            )
        rows.append((entity, requested, nonwarm, warm))
        invalid_position_rows.append((entity, normalized_nonwarm_positions))
    rows.sort(key=lambda row: row[0])
    invalid_position_rows.sort(key=lambda row: row[0])
    payload = [list(row) for row in rows]
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    invalid_payload = [[entity, list(positions)] for entity, positions in invalid_position_rows]
    invalid_digest = hashlib.sha256(canonical_json_bytes(invalid_payload)).hexdigest()
    return tuple(rows), digest, tuple(invalid_position_rows), invalid_digest


def _robust_location_scale(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    centers = np.zeros(values.shape[1], dtype=np.float64)
    scales = np.ones(values.shape[1], dtype=np.float64)
    for column in range(values.shape[1]):
        sample = values[:, column]
        sample = sample[np.isfinite(sample)]
        if not len(sample):
            continue
        center = float(np.median(sample))
        scale = 1.4826 * float(np.median(np.abs(sample - center)))
        if not np.isfinite(scale) or scale < ROBUST_STANDARDIZATION_SCALE_FLOOR:
            q25, q75 = np.percentile(sample, (25.0, 75.0))
            scale = float((q75 - q25) / 1.349)
        if not np.isfinite(scale) or scale < ROBUST_STANDARDIZATION_SCALE_FLOOR:
            scale = float(np.std(sample, ddof=0))
        if not np.isfinite(scale) or scale < ROBUST_STANDARDIZATION_SCALE_FLOOR:
            scale = 1.0
        centers[column] = center
        scales[column] = scale
    return centers, scales


def _residual_scale(residual: np.ndarray) -> float:
    center = float(np.median(residual))
    scale = 1.4826 * float(np.median(np.abs(residual - center)))
    if not np.isfinite(scale) or scale <= 0.0:
        scale = float(np.sqrt(np.mean(np.square(residual - center))))
    if not np.isfinite(scale) or scale <= 0.0:
        scale = ROBUST_SCALE_FLOOR
    return float(np.clip(scale, ROBUST_SCALE_FLOOR, ROBUST_SCALE_CEILING))


def _fixed_quadratic_system(
    design: np.ndarray,
    target: np.ndarray,
    weights: np.ndarray,
    penalty_matrix: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Accumulate the weighted normal equation in one declared row order."""

    gram = penalty_matrix.astype(np.float64, copy=True)
    right = np.zeros(design.shape[1], dtype=np.float64)
    for row in range(len(design)):
        weighted = design[row] * float(weights[row])
        gram += np.outer(weighted, design[row])
        right += weighted * float(target[row])
    return gram, right


def _kkt_violation(
    coefficients: np.ndarray,
    gram: np.ndarray,
    right: np.ndarray,
    lower: np.ndarray,
    upper: np.ndarray,
) -> float:
    gradient = gram @ coefficients - right
    violation = 0.0
    for position, value in enumerate(coefficients):
        if value <= lower[position] + 1e-12:
            current = max(0.0, -float(gradient[position]))
        elif value >= upper[position] - 1e-12:
            current = max(0.0, float(gradient[position]))
        else:
            current = abs(float(gradient[position]))
        violation = max(violation, current)
    return violation


def _fixed_box_qp_solve(
    gram: np.ndarray,
    right: np.ndarray,
    lower: np.ndarray,
    upper: np.ndarray,
    start: np.ndarray,
) -> tuple[np.ndarray, int, float]:
    """Solve the strictly-convex box QP by fixed-order coordinate descent."""

    coefficients = np.clip(start.astype(np.float64, copy=True), lower, upper)
    for sweep in range(1, QP_MAX_SWEEPS + 1):
        maximum_delta = 0.0
        for position in range(len(coefficients)):
            partial = math.fsum(
                float(gram[position, other] * coefficients[other])
                for other in range(len(coefficients))
                if other != position
            )
            updated = (float(right[position]) - partial) / float(gram[position, position])
            updated = min(max(updated, float(lower[position])), float(upper[position]))
            maximum_delta = max(maximum_delta, abs(updated - float(coefficients[position])))
            coefficients[position] = updated
        kkt = _kkt_violation(coefficients, gram, right, lower, upper)
        if maximum_delta <= QP_KKT_TOLERANCE and kkt <= QP_KKT_TOLERANCE:
            return coefficients, sweep, kkt
    raise HierarchicalStateV7ContractError("fixed-order box QP failed its KKT gate")


def _endpoint_penalty_block() -> np.ndarray:
    identity = np.eye(3, dtype=np.float64)
    ones = np.ones((3, 3), dtype=np.float64)
    deviation = identity - ones / 3.0
    global_mean = ones / 9.0
    return REGIME_DEVIATION_RIDGE * deviation + GLOBAL_RIDGE * global_mean


def _dgp_contrast(
    group_codes: np.ndarray,
    group_count: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Create membership-ordered contrasts with row-weighted zero-sum effects."""

    counts = np.bincount(group_codes, minlength=group_count).astype(np.float64)
    if group_count == 1:
        return np.zeros((len(group_codes), 0), dtype=np.float64), np.zeros((1, 0))
    transform = np.zeros((group_count, group_count - 1), dtype=np.float64)
    for position in range(group_count - 1):
        transform[position, position] = 1.0
        transform[-1, position] = -counts[position] / counts[-1]
    return transform[group_codes], transform


def _huber_objective(
    residual: np.ndarray,
    scale: float,
    coefficients: np.ndarray,
    penalty_matrix: np.ndarray,
) -> float:
    threshold = HUBER_DELTA * scale
    absolute = np.abs(residual)
    loss = np.where(
        absolute <= threshold,
        0.5 * np.square(residual),
        threshold * (absolute - 0.5 * threshold),
    )
    penalty = 0.5 * float(coefficients @ penalty_matrix @ coefficients)
    return float(math.fsum(float(value) for value in loss) + penalty)


def _weighted_median(values: np.ndarray, weights: np.ndarray) -> float:
    order = np.argsort(values, kind="mergesort")
    ordered_values = values[order]
    ordered_weights = weights[order]
    total = float(math.fsum(float(value) for value in ordered_weights))
    if total <= 0.0:
        return float("nan")
    cutoff = 0.5 * total
    cumulative = 0.0
    for value, weight in zip(ordered_values, ordered_weights, strict=True):
        cumulative += float(weight)
        if cumulative >= cutoff:
            return float(value)
    return float(ordered_values[-1])


def _weighted_robust_scale(values: np.ndarray, weights: np.ndarray, fallback: float) -> float:
    center = _weighted_median(values, weights)
    if not np.isfinite(center):
        return fallback
    mad = _weighted_median(np.abs(values - center), weights)
    scale = 1.4826 * mad
    if not np.isfinite(scale) or scale <= 0.0:
        return fallback
    return float(np.clip(scale, ROBUST_SCALE_FLOOR, ROBUST_SCALE_CEILING))


def _scale_effects(
    residual: np.ndarray,
    regime: np.ndarray,
    group_codes: np.ndarray,
    group_membership_sha256: tuple[str, ...],
    base_scale: float,
) -> tuple[float, tuple[float, float, float], str]:
    base_log = math.log(base_scale)
    regime_deviations = np.zeros(3, dtype=np.float64)
    for position in range(3):
        weights = regime[:, position]
        mass = float(math.fsum(float(value) for value in weights))
        local = _weighted_robust_scale(residual, weights, base_scale)
        shrink = mass / (mass + REGIME_SCALE_PSEUDO_COUNT)
        regime_deviations[position] = shrink * (math.log(local) - base_log)
    regime_deviations -= float(np.mean(regime_deviations))
    effective = np.clip(
        base_log + regime_deviations,
        math.log(ROBUST_SCALE_FLOOR),
        math.log(ROBUST_SCALE_CEILING),
    )
    global_log_scale = float(np.mean(effective))
    regime_deviations = effective - global_log_scale

    dgp_payload: list[dict[str, Any]] = []
    for position, membership_sha256 in enumerate(group_membership_sha256):
        mask = group_codes == position
        count = int(mask.sum())
        local = _weighted_robust_scale(residual[mask], np.ones(count, dtype=np.float64), base_scale)
        shrink = count / (count + DGP_SCALE_PSEUDO_COUNT)
        dgp_payload.append(
            {
                "membership_sha256": membership_sha256,
                "count": count,
                "log_scale_deviation": shrink * (math.log(local) - base_log),
            }
        )
    dgp_sha256 = hashlib.sha256(canonical_json_bytes(dgp_payload)).hexdigest()
    return global_log_scale, tuple(float(value) for value in regime_deviations), dgp_sha256


def _membership_ordered_partition(
    labels: tuple[str, ...],
    identities: pd.DataFrame,
) -> tuple[np.ndarray, tuple[str, ...]]:
    groups: list[tuple[str, np.ndarray]] = []
    label_array = np.asarray(labels, dtype=object)
    for label in set(labels):
        positions = np.flatnonzero(label_array == label)
        membership_sha256 = _identity_sha256(identities.iloc[positions])
        groups.append((membership_sha256, positions))
    groups.sort(key=lambda item: item[0])
    codes = np.empty(len(labels), dtype=np.int64)
    memberships: list[str] = []
    for code, (membership_sha256, positions) in enumerate(groups):
        codes[positions] = code
        memberships.append(membership_sha256)
    return codes, tuple(memberships)


def fit_hierarchical_state_v7(
    state: HierarchicalStateFrameV7,
    *,
    decision_block_identities: pd.DataFrame,
    decision_source_state_sha256: str,
    decision_source_positions: tuple[int, ...],
    decision_source_row_count: int,
    observed_pe: pd.Series,
    research_dgp_memberships: pd.DataFrame,
) -> HierarchicalFitResultV7:
    """Fit one prefix once and bind it to one exact multi-date decision block."""

    if type(state) is not HierarchicalStateFrameV7:
        raise HierarchicalStateV7ContractError("fit requires a bound H-OFS V7 state frame")
    state.assert_live_integrity()
    resource_receipt = capture_runtime_receipt_v7(purpose="FIT")
    if type(decision_block_identities) is not pd.DataFrame:
        raise HierarchicalStateV7ContractError("decision block identities must be a DataFrame")
    decision_identities = require_canonical_decision_identity_order_v7(
        decision_block_identities,
        expected_index=decision_block_identities.index,
    )
    if not decision_identities.equals(decision_block_identities):
        raise HierarchicalStateV7ContractError("decision block identities are not canonical")
    (
        first_decision_entity,
        block_start_date,
        last_decision_entity,
        block_end_date,
        decision_distinct_date_count,
    ) = decision_block_canonical_endpoints_v7(decision_identities)
    block_start = pd.Timestamp(block_start_date)
    block_end = pd.Timestamp(block_end_date)
    decision_block_ordered_membership_sha256 = decision_block_ordered_membership_sha256_v7(
        decision_identities
    )
    decision_block_set_membership_sha256 = decision_block_set_membership_sha256_v7(
        decision_identities
    )
    decision_ordered_identity_rows = tuple(
        (str(entity), pd.Timestamp(date).isoformat())
        for entity, date in decision_identities.loc[:, list(IDENTITY_COLUMNS)].itertuples(
            index=False, name=None
        )
    )
    decision_source_positions_sha256 = decision_source_positions_sha256_v7(
        decision_identities,
        source_state_sha256=decision_source_state_sha256,
        source_positions=decision_source_positions,
        source_row_count=decision_source_row_count,
    )
    fit_dates = pd.to_datetime(state.identities[IDENTITY_COLUMNS[1]], errors="coerce")
    if fit_dates.isna().any() or not bool((fit_dates < block_start).all()):
        raise HierarchicalStateV7ContractError(
            "every fit-prefix identity must be strictly earlier than block start"
        )
    if type(observed_pe) is not pd.Series or not observed_pe.index.equals(state.features.index):
        raise HierarchicalStateV7ContractError("observed proxy is not identity-index-bound")
    labels = validate_research_dgp_nuisance_groups_v7(
        research_dgp_memberships,
        identities=state.identities,
    )
    proxy = pd.to_numeric(observed_pe, errors="coerce").to_numpy(dtype=np.float64)
    offset = pd.to_numeric(state.features[OFFSET_COLUMN], errors="coerce").to_numpy(
        dtype=np.float64
    )
    valid = causal_training_valid_mask_v7(proxy, offset)
    (
        prefix_entity_rows,
        prefix_entity_rows_sha256,
        prefix_entity_invalid_positions,
        prefix_entity_invalid_positions_sha256,
    ) = _prefix_entity_row_receipt(state.identities, valid)

    positions = np.flatnonzero(valid)
    order_frame = state.identities.iloc[positions].copy()
    order_frame["_hofs_v7_position"] = positions
    order_frame = order_frame.sort_values(
        [IDENTITY_COLUMNS[1], IDENTITY_COLUMNS[0]], kind="mergesort"
    )
    positions = order_frame["_hofs_v7_position"].to_numpy(dtype=np.int64)
    ordered_identities = state.identities.iloc[positions].copy()
    ordered_features = state.features.iloc[positions].copy()
    ordered_proxy = proxy[positions]
    ordered_offset = offset[positions]
    ordered_labels = tuple(labels[position] for position in positions)
    fit_expected_regime_warmup_mask = state.expected_regime_warmup_prefix_mask.iloc[
        positions
    ].to_numpy(dtype=bool)
    fit_expected_regime_warmup_count = int(fit_expected_regime_warmup_mask.sum())
    fit_expected_regime_warmup_sha256 = _mask_membership_sha256(
        ordered_identities,
        fit_expected_regime_warmup_mask,
        label="expected_regime_warmup_prefix",
    )
    fit_regime_fallback_count = int(state.regime_fallback_mask.iloc[positions].sum())
    fit_regime_renormalized_count = int(state.regime_renormalized_mask.iloc[positions].sum())
    if (
        fit_regime_fallback_count > REGIME_FALLBACK_MAX_COUNT
        or fit_regime_fallback_count / len(positions) > REGIME_FALLBACK_MAX_FRACTION
    ):
        raise HierarchicalStateV7ContractError(
            "malformed fit regimes exceed the fixed fit-row fallback limit"
        )
    target = np.log(ordered_proxy) - ordered_offset

    raw = ordered_features.loc[:, list(STANDARDIZED_COLUMNS)].to_numpy(dtype=np.float64)
    centers, scales = _robust_location_scale(raw)
    standardized = (raw - centers[None, :]) / scales[None, :]
    missing = ~np.isfinite(standardized)
    missing_context_cell_count = int(missing.sum())
    standardized[missing] = 0.0

    regime = ordered_features.loc[:, list(REGIME_COLUMNS)].to_numpy(dtype=np.float64)
    valid_regime = np.isfinite(regime).all(axis=1) & (regime >= 0.0).all(axis=1)
    totals = regime.sum(axis=1)
    valid_regime &= totals > 0.0
    if not valid_regime.all():
        raise HierarchicalStateV7ContractError("normalized state contains malformed regime rows")
    regime /= totals[:, None]
    group_codes, group_membership_sha256 = _membership_ordered_partition(
        ordered_labels,
        ordered_identities,
    )
    group_count = len(group_membership_sha256)
    dgp_contrast, dgp_transform = _dgp_contrast(group_codes, group_count)

    state_position = STANDARDIZED_COLUMNS.index(STATE_DISPLACEMENT_COLUMN)
    innovation_position = STANDARDIZED_COLUMNS.index(INNOVATION_COLUMN)
    context_positions = [STANDARDIZED_COLUMNS.index(column) for column in CONTEXT_COLUMNS]
    state_values = standardized[:, state_position]
    innovation_values = standardized[:, innovation_position]
    context_values = standardized[:, context_positions]
    design = np.column_stack(
        (
            regime,
            regime * state_values[:, None],
            regime * innovation_values[:, None],
            context_values,
            dgp_contrast,
            dgp_contrast * state_values[:, None],
            dgp_contrast * innovation_values[:, None],
        )
    )
    dgp_start = 9 + len(CONTEXT_COLUMNS)
    contrast_count = max(0, group_count - 1)
    dimension = dgp_start + 3 * contrast_count
    if design.shape[1] != dimension or dgp_start != 20:
        raise HierarchicalStateV7ContractError("fixed design matrix layout drifted")
    penalty_matrix = np.zeros((dimension, dimension), dtype=np.float64)
    endpoint_penalty = _endpoint_penalty_block()
    for block in (slice(0, 3), slice(3, 6), slice(6, 9)):
        penalty_matrix[block, block] = endpoint_penalty
    context_block = slice(9, dgp_start)
    penalty_matrix[context_block, context_block] = np.eye(len(CONTEXT_COLUMNS)) * CONTEXT_RIDGE
    if contrast_count:
        nuisance_penalty = DGP_NUISANCE_RIDGE * (dgp_transform.T @ dgp_transform)
        for start in (
            dgp_start,
            dgp_start + contrast_count,
            dgp_start + 2 * contrast_count,
        ):
            block = slice(start, start + contrast_count)
            penalty_matrix[block, block] = nuisance_penalty
    lower = np.full(dimension, -np.inf, dtype=np.float64)
    upper = np.full(dimension, np.inf, dtype=np.float64)
    lower[3:6], upper[3:6] = PERSISTENCE_BOUNDS
    lower[6:9], upper[6:9] = INNOVATION_BOUNDS

    weights = np.ones(len(target), dtype=np.float64)
    coefficients = np.zeros(design.shape[1], dtype=np.float64)
    converged = False
    final_delta = float("inf")
    final_weight_delta = float("inf")
    final_kkt = float("inf")
    total_qp_sweeps = 0
    scale = ROBUST_SCALE_FLOOR
    iterations = 0
    for iteration in range(1, IRLS_MAX_ITERATIONS + 1):
        gram, right = _fixed_quadratic_system(design, target, weights, penalty_matrix)
        solved, qp_sweeps, final_kkt = _fixed_box_qp_solve(
            gram,
            right,
            lower,
            upper,
            coefficients,
        )
        total_qp_sweeps += qp_sweeps
        denominator = max(1.0, float(np.max(np.abs(coefficients))))
        final_delta = float(np.max(np.abs(solved - coefficients))) / denominator
        coefficients = solved
        residual = target - design @ coefficients
        scale = _residual_scale(residual)
        standardized_residual = np.abs(residual) / scale
        updated_weights = np.ones(len(target), dtype=np.float64)
        tail = standardized_residual > HUBER_DELTA
        updated_weights[tail] = HUBER_DELTA / standardized_residual[tail]
        final_weight_delta = float(np.max(np.abs(updated_weights - weights)))
        # The convergence certificate is deliberately recomputed against the
        # weights implied by the just-solved coefficients.  It is never the KKT
        # value returned for the previous IRLS weights.
        final_gram, final_right = _fixed_quadratic_system(
            design,
            target,
            updated_weights,
            penalty_matrix,
        )
        final_kkt = _kkt_violation(
            coefficients,
            final_gram,
            final_right,
            lower,
            upper,
        )
        weights = updated_weights
        iterations = iteration
        if (
            iteration >= 2
            and final_delta <= IRLS_TOLERANCE
            and final_weight_delta <= IRLS_TOLERANCE
            and final_kkt <= QP_KKT_TOLERANCE
        ):
            converged = True
            break
    if not converged:
        raise HierarchicalStateV7ContractError("box-constrained Huber IRLS did not converge")

    residual = target - design @ coefficients
    objective = _huber_objective(residual, scale, coefficients, penalty_matrix)
    deploy_coefficients = coefficients.copy()
    deploy_coefficients[dgp_start:] = 0.0
    deploy_residual = target - design @ deploy_coefficients
    deploy_scale = _residual_scale(deploy_residual)
    global_log_scale, regime_log_scale, dgp_scale_sha256 = _scale_effects(
        deploy_residual,
        regime,
        group_codes,
        group_membership_sha256,
        deploy_scale,
    )
    dgp_intercept = dgp_transform @ coefficients[dgp_start : dgp_start + contrast_count]
    dgp_persistence = (
        dgp_transform @ coefficients[dgp_start + contrast_count : dgp_start + 2 * contrast_count]
    )
    dgp_innovation = (
        dgp_transform
        @ coefficients[dgp_start + 2 * contrast_count : dgp_start + 3 * contrast_count]
    )
    dgp_mean_payload = {
        "membership_sha256": list(group_membership_sha256),
        "intercept": dgp_intercept.tolist(),
        "persistence": dgp_persistence.tolist(),
        "innovation": dgp_innovation.tolist(),
        "centering": "row_weighted_zero_sum",
    }
    dgp_mean_sha256 = hashlib.sha256(canonical_json_bytes(dgp_mean_payload)).hexdigest()

    start_date = pd.Timestamp(ordered_identities[IDENTITY_COLUMNS[1]].iloc[0]).isoformat()
    end_date = pd.Timestamp(ordered_identities[IDENTITY_COLUMNS[1]].iloc[-1]).isoformat()
    if not pd.Timestamp(end_date) < block_start <= block_end:
        raise HierarchicalStateV7ContractError("fit rows must end before the decision block")
    fit_receipt = FitReceiptV7(
        candidate_id=CANDIDATE_ID,
        design_contract_sha256=contract_sha256(),
        fit_config_sha256=fit_config_sha256(),
        fit_identity_sha256=_identity_sha256(ordered_identities),
        fit_feature_sha256=_float_frame_sha256(ordered_features),
        fit_state_sha256=state.state_binding_sha256,
        fit_target_sha256=_float_vector_sha256(target, "log_proxy_minus_prior_offset"),
        dgp_partition_sha256=hashlib.sha256(
            canonical_json_bytes(list(group_membership_sha256))
        ).hexdigest(),
        resource_receipt_sha256=resource_receipt.sha256(),
        fit_start_date=start_date,
        fit_end_date=end_date,
        decision_block_start_date=block_start_date,
        decision_block_end_date=block_end_date,
        decision_block_first_entity_id=first_decision_entity,
        decision_block_last_entity_id=last_decision_entity,
        decision_ordered_identity_rows=decision_ordered_identity_rows,
        decision_source_state_sha256=decision_source_state_sha256,
        decision_source_positions=decision_source_positions,
        decision_source_row_count=decision_source_row_count,
        decision_block_ordered_membership_sha256=(decision_block_ordered_membership_sha256),
        decision_block_set_membership_sha256=decision_block_set_membership_sha256,
        decision_source_positions_sha256=decision_source_positions_sha256,
        decision_row_count=len(decision_identities),
        decision_distinct_date_count=decision_distinct_date_count,
        within_block_parameter_update_count=0,
        prefix_entity_count=len(prefix_entity_rows),
        prefix_entity_row_counts=prefix_entity_rows,
        prefix_entity_row_counts_sha256=prefix_entity_rows_sha256,
        prefix_entity_causal_invalid_positions=prefix_entity_invalid_positions,
        prefix_entity_causal_invalid_positions_sha256=(
            prefix_entity_invalid_positions_sha256
        ),
        requested_row_count=len(state.features),
        fit_row_count=len(target),
        dropped_nonwarm_row_count=int((~valid).sum()),
        causal_prefix_nonwarm_row_count=sum(row[2] for row in prefix_entity_rows),
        dgp_group_count=group_count,
        missing_context_cell_count=missing_context_cell_count,
        source_regime_fallback_count=fit_regime_fallback_count,
        source_regime_renormalized_count=fit_regime_renormalized_count,
        expected_regime_warmup_prefix_count=fit_expected_regime_warmup_count,
        expected_regime_warmup_prefix_sha256=fit_expected_regime_warmup_sha256,
        irls_iterations=iterations,
        irls_converged=converged,
        final_coefficient_delta=final_delta,
        final_weight_delta=final_weight_delta,
        final_huber_objective=objective,
        final_conditional_huber_scale=scale,
        deploy_marginalized_scale=deploy_scale,
        active_bound_count=int(
            np.count_nonzero(np.isclose(coefficients[3:6], lower[3:6], atol=1e-12, rtol=0.0))
            + np.count_nonzero(np.isclose(coefficients[3:6], upper[3:6], atol=1e-12, rtol=0.0))
            + np.count_nonzero(np.isclose(coefficients[6:9], lower[6:9], atol=1e-12, rtol=0.0))
            + np.count_nonzero(np.isclose(coefficients[6:9], upper[6:9], atol=1e-12, rtol=0.0))
        ),
        final_kkt_violation=final_kkt,
        total_qp_coordinate_sweeps=total_qp_sweeps,
        dgp_mean_nuisance_sha256=dgp_mean_sha256,
        dgp_scale_nuisance_sha256=dgp_scale_sha256,
        dgp_effects_marginalized_for_deploy=True,
        fixed_row_order=CANONICAL_DECISION_ORDER,
        fixed_normal_equation_accumulation="sequential_row_outer_product",
    )
    parameters = FrozenHierarchicalParametersV7(
        candidate_id=CANDIDATE_ID,
        design_contract_sha256=contract_sha256(),
        fit_start_date=start_date,
        fit_end_date=end_date,
        decision_block_start_date=block_start_date,
        decision_block_end_date=block_end_date,
        decision_block_first_entity_id=first_decision_entity,
        decision_block_last_entity_id=last_decision_entity,
        decision_ordered_identity_rows=decision_ordered_identity_rows,
        decision_source_state_sha256=decision_source_state_sha256,
        decision_source_positions=decision_source_positions,
        decision_source_row_count=decision_source_row_count,
        decision_block_ordered_membership_sha256=(decision_block_ordered_membership_sha256),
        decision_block_set_membership_sha256=decision_block_set_membership_sha256,
        decision_source_positions_sha256=decision_source_positions_sha256,
        decision_row_count=len(decision_identities),
        decision_distinct_date_count=decision_distinct_date_count,
        within_block_parameter_update_count=0,
        fit_row_count=len(target),
        fit_identity_sha256=fit_receipt.fit_identity_sha256,
        fit_feature_sha256=fit_receipt.fit_feature_sha256,
        fit_state_sha256=fit_receipt.fit_state_sha256,
        fit_target_sha256=fit_receipt.fit_target_sha256,
        fit_config_sha256=fit_receipt.fit_config_sha256,
        convergence_receipt_sha256=fit_receipt.sha256(),
        resource_receipt_sha256=resource_receipt.sha256(),
        robust_centers=tuple(float(value) for value in centers),
        robust_scales=tuple(float(value) for value in scales),
        global_intercept=float(np.mean(coefficients[0:3])),
        global_persistence=float(np.mean(coefficients[3:6])),
        global_innovation=float(np.mean(coefficients[6:9])),
        context_coefficients=tuple(
            float(value) for value in coefficients[9 : 9 + len(CONTEXT_COLUMNS)]
        ),
        regime_intercept_deviations=tuple(
            float(value - np.mean(coefficients[0:3])) for value in coefficients[0:3]
        ),
        regime_persistence_deviations=tuple(
            float(value - np.mean(coefficients[3:6])) for value in coefficients[3:6]
        ),
        regime_innovation_deviations=tuple(
            float(value - np.mean(coefficients[6:9])) for value in coefficients[6:9]
        ),
        global_log_scale=global_log_scale,
        regime_log_scale_deviations=regime_log_scale,
        research_dgp_effects_marginalized=True,
        training_target="log_observed_pe_proxy_minus_prior_offset",
    )
    return HierarchicalFitResultV7(
        parameters=parameters,
        fit_receipt=fit_receipt,
        resource_receipt=resource_receipt,
    )


__all__ = [
    "FitReceiptV7",
    "FrozenHierarchicalParametersV7",
    "HierarchicalFitResultV7",
    "ResourceReceiptV7",
    "causal_training_valid_mask_v7",
    "fit_config_sha256",
    "fit_hierarchical_state_v7",
]
