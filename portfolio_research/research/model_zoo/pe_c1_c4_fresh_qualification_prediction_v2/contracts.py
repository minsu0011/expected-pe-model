"""Immutable, score-free contracts for the clean PE-C1--C4 binding revision."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


class PredictionContractError(RuntimeError):
    """Raised before a prediction can escape its frozen truth-free contract."""


CHAMPION_ID: Final = "v04_expected_pe"
C1_ID: Final = "bce_v1_b_causal_rolling_dispersion_budget"
C2_ID: Final = "bce_v1_d_observable_state_confidence_shrinkage"
C3_ID: Final = "bce_tournament_v1_fixed_alpha_040_directional_consensus"
C4_ID: Final = "hofs_v4_expected_pe"
CANDIDATE_IDS: Final = (C1_ID, C2_ID, C3_ID, C4_ID)
MODEL_IDS: Final = (CHAMPION_ID, *CANDIDATE_IDS)
MODEL_ORDINALS: Final = dict(zip(MODEL_IDS, range(len(MODEL_IDS)), strict=True))

DGP_IDS: Final = tuple("ABCDEFGHIJ")
SEED_ALIASES: Final = tuple(f"qualification_seed_{index:02d}" for index in range(1, 6))
DIRECTION_EPSILON: Final = 1e-12
FIXED_DIRECTIONAL_ALPHA: Final = 0.40
ROLLING_DISPERSION_WINDOW: Final = 63
ROLLING_DISPERSION_MIN_PERIODS: Final = 10
GLOBAL_HOFS_LOG_SHRINK: Final = 0.50


@dataclass(frozen=True)
class FoldGeometry:
    source_rows_per_task: int = 1_800
    first_prediction_position: int = 504
    final_prediction_position: int = 1_799
    first_fold_number: int = 12
    final_fold_number: int = 73
    regular_test_rows: int = 21
    terminal_test_rows: int = 15
    step_rows: int = 21

    @property
    def test_starts(self) -> tuple[int, ...]:
        return tuple(
            range(
                self.first_prediction_position,
                self.final_prediction_position + 1,
                self.step_rows,
            )
        )

    @property
    def prediction_rows_per_task(self) -> int:
        return self.final_prediction_position - self.first_prediction_position + 1

    def fold_id(self, test_start: int) -> str:
        if test_start not in self.test_starts:
            raise PredictionContractError("test start escaped the frozen schedule")
        ordinal = (test_start - self.first_prediction_position) // self.step_rows
        return f"fold_{self.first_fold_number + ordinal:03d}"

    def test_end_exclusive(self, test_start: int) -> int:
        if test_start not in self.test_starts:
            raise PredictionContractError("test start escaped the frozen schedule")
        return min(self.source_rows_per_task, test_start + self.regular_test_rows)

    def __post_init__(self) -> None:
        sizes = [self.test_end_exclusive(start) - start for start in self.test_starts]
        if len(sizes) != 62 or sizes != [21] * 61 + [15] or sum(sizes) != 1_296:
            raise PredictionContractError("fold geometry changed")


FOLD_GEOMETRY: Final = FoldGeometry()
EXPECTED_TASKS: Final = len(SEED_ALIASES) * len(DGP_IDS)
EXPECTED_IDENTITIES: Final = EXPECTED_TASKS * FOLD_GEOMETRY.prediction_rows_per_task
EXPECTED_MODEL_IDENTITY_ROWS: Final = EXPECTED_IDENTITIES * len(MODEL_IDS)

IDENTITY_COLUMNS: Final = (
    "seed_alias",
    "dgp_id",
    "session_position",
    "date",
    "symbol",
    "fold_id",
    "train_end_position",
    "test_start_position",
)
BCE_VALUE_COLUMNS: Final = (
    "v04_expected_pe",
    "lgbm_full_state_expected_pe",
    "histgb_full_state_expected_pe",
    "ofs_v1_eps_confidence_01",
    "ofs_v1_eps_staleness_log1p",
    "ofs_v1_regime_entropy",
    "ofs_v1_regime_confidence",
    "ofs_v1_state_abs_innovation_lag1",
)
OBSERVABLE_STATE_CONFIDENCE_COLUMNS: Final = BCE_VALUE_COLUMNS[3:]
HOFS_VALUE_COLUMNS: Final = (
    "hofs_r2_expected_log_pe",
    "hofs_v7_tail_guard_weight",
    "hofs_v7_log_scale",
)
BCE_TASK_SURFACE_COLUMNS: Final = (*IDENTITY_COLUMNS, *BCE_VALUE_COLUMNS)
HOFS_TASK_SURFACE_COLUMNS: Final = (*IDENTITY_COLUMNS, *HOFS_VALUE_COLUMNS)
MERGED_TASK_SURFACE_COLUMNS: Final = (*IDENTITY_COLUMNS, *BCE_VALUE_COLUMNS, *HOFS_VALUE_COLUMNS)

PREDICTION_COLUMNS: Final = (
    *IDENTITY_COLUMNS,
    "pe_model_id",
    "model_ordinal",
    "expected_pe",
    "expected_log_pe",
    "uncertainty",
    "confidence",
    "regime_state",
    "specialist_tags",
    "prediction_valid",
    "pit_valid",
    "source_model_version",
    "valuation_state_confidence",
    "out_of_distribution_score",
    "model_disagreement",
    "state_uncertainty",
    "applied_alpha",
    "raw_log_correction",
)

FORBIDDEN_TOKENS: Final = (
    "true_",
    "target",
    "label",
    "score",
    "metric",
    "error",
    "heldout",
    "latent",
)

SOURCE_MODEL_VERSION: Final = {
    CHAMPION_ID: "v04_expected_pe__actual_common_surface",
    C1_ID: "pe_c1_definition_lock_v1__common_binding_pending",
    C2_ID: "pe_c2_definition_lock_v1__common_binding_pending",
    C3_ID: "pe_c3_alpha040_definition_lock_v1__common_binding_pending",
    C4_ID: "hofs_v12_service_pending__frozen_v7_r2_numeric_lineage",
}
SPECIALIST_TAGS: Final = {
    CHAMPION_ID: "champion_comparator",
    C1_ID: "bounded_consensus|causal_rolling_dispersion_budget",
    C2_ID: "bounded_consensus|observable_state_confidence_shrinkage",
    C3_ID: "bounded_consensus|fixed_directional_consensus_alpha040",
    C4_ID: "hierarchical_observable_state|global_log_shrink_w0500",
}

RESOURCE_POLICY: Final = {
    "outer_workers": 16,
    "logical_cpu_affinity_per_worker": 2,
    "inner_threads": 1,
    "cuda_visible": False,
    "prediction_formula_is_vectorized": True,
}
