"""Frozen score-free contract for one bounded C2-R2 sparse-router study."""

from __future__ import annotations

import math
from typing import Final


EVIDENCE_CLASS: Final = "RESEARCH_ONLY_SPENT_PUBLIC_SYNTHETIC"
BASE_MODEL_ID: Final = "c2_r2_b_robust_cap_040"
FIRST_TEST_POSITION: Final = 504
FINAL_TEST_EXCLUSIVE: Final = 1800
ROWS_PER_TASK: Final = FINAL_TEST_EXCLUSIVE - FIRST_TEST_POSITION
SEED_VALUES: Final = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
SEED_ALIASES: Final = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
DGP_IDS: Final = tuple("ABCDEFGHIJ")
TASK_COUNT: Final = len(SEED_VALUES) * len(DGP_IDS)
PREDICTION_ROWS: Final = TASK_COUNT * ROWS_PER_TASK
WORKER_COUNT: Final = 8

IDENTITY_COLUMNS: Final = (
    "seed_alias",
    "dgp_id",
    "date",
    "symbol",
    "session_position",
    "fold_id",
)
BASE_COLUMNS: Final = (
    *IDENTITY_COLUMNS,
    "test_start_position",
    "incumbent__v04_expected_pe",
    "challenger__lgbm_full_state",
    "challenger__histgb_full_state",
    "alpha__bce_d",
    "raw_log_consensus_correction",
)
ROUTER_BASE_COLUMNS: Final = (
    "session_position",
    "test_start_position",
    "incumbent__v04_expected_pe",
    "challenger__lgbm_full_state",
    "challenger__histgb_full_state",
    "alpha__bce_d",
    "raw_log_consensus_correction",
)
ROUTER_FEATURE_COLUMNS: Final = (
    "regime_entropy",
    "regime_confidence",
    "regime_conditional_pe_percentile",
    "benchmark_realized_vol_20",
    "eps_staleness_days",
)
PUBLIC_LOAD_COLUMNS: Final = ("date", "symbol", *ROUTER_FEATURE_COLUMNS)
FORBIDDEN_FEATURE_TOKENS: Final = (
    "dgp",
    "true_",
    "future_",
    "heldout",
    "qualification",
    "target",
    "label",
    "observed_pe",
    "earnings_yield",
    "pe_gap",
    "error",
)

LOG_1P0125: Final = math.log(1.0125)
LOG_1P015: Final = math.log(1.015)
LOG_1P020: Final = math.log(1.020)
LOG_1P030: Final = math.log(1.030)
LOG_1P040: Final = math.log(1.040)

VARIANT_SPECS: Final = {
    "c2_r2_sr_a_magnitude_taper": {
        "features": ["correction_magnitude"],
        "formula": (
            "scale=1; abs(c)>=log(1.02)->0.5; abs(c)>=log(1.03)->0; "
            "c=clip(alpha_d*raw,+/-log(1.04))"
        ),
        "purpose": "sparse taper and reject only the largest robust-cap corrections",
    },
    "c2_r2_sr_b_disagreement_uncertainty": {
        "features": [
            "correction_magnitude",
            "challenger_disagreement",
            "regime_entropy",
            "regime_confidence",
        ],
        "formula": (
            "high=abs(c)>=log(1.015)&disagreement>=prefix_q75&state_uncertain; "
            "scale=0.35; extreme additionally abs(c)>=log(1.02)&disagreement>=prefix_q90; "
            "scale=0"
        ),
        "purpose": "shrink corrections supported by unstable challengers in uncertain states",
    },
    "c2_r2_sr_c_valuation_ood_reject": {
        "features": [
            "correction_magnitude",
            "valuation_percentile",
            "volatility",
            "eps_staleness",
        ],
        "formula": (
            "ood_count=sum(prefix_q95 valuation-tail,volatility,staleness); "
            "abs(c)>=log(1.015)&ood_count>=1->scale=0.5; "
            "abs(c)>=log(1.02)&ood_count>=2->scale=0"
        ),
        "purpose": "reject corrections only when multiple observable OOD alarms coincide",
    },
    "c2_r2_sr_d_persistence_reversal": {
        "features": [
            "correction_magnitude",
            "challenger_disagreement",
            "direction_persistence",
        ],
        "formula": (
            "reversal=current_sign*mean(prior_21_signs)<-0.25; "
            "reversal&abs(c)>=log(1.0125)->scale=0.25; "
            "disagreement>=prefix_q90->scale=0"
        ),
        "purpose": "shrink abrupt correction-direction reversals using only prior decisions",
    },
    "c2_r2_sr_e_two_feature_sparse_score": {
        "features": [
            "correction_magnitude",
            "challenger_disagreement",
            "state_uncertainty",
            "training_distribution_distance",
            "direction_persistence",
        ],
        "formula": (
            "risk=sum(magnitude>=max(log(1.0125),prefix_q85),disagreement>=prefix_q75,"
            "state_uncertain,ood,reversal); magnitude_signal&risk>=3->scale=0.5; "
            "risk>=4->scale=0"
        ),
        "purpose": "bounded five-indicator score with only two actions and no fitted black box",
    },
}
VARIANT_IDS: Final = tuple(VARIANT_SPECS)

RESEARCH_TARGET: Final = {
    "mae_relative_gain_min": 0.04,
    "systematic_joint_tail_failure_count_max": 0,
    "worst_dgp_mean_harm_max": 0.01,
    "worst_seed_dgp_cell_harm_max": 0.03,
    "pooled_p95_non_worse": True,
    "pooled_p99_non_worse": True,
    "pooled_extreme_frequency_non_worse": True,
}


def validate_contract() -> None:
    """Fail if the bounded study silently expands or admits a forbidden feature."""

    if len(VARIANT_IDS) != 5 or len(set(VARIANT_IDS)) != len(VARIANT_IDS):
        raise RuntimeError("sparse-router variant universe differs")
    allowed = {
        "correction_magnitude",
        "challenger_disagreement",
        "direction_persistence",
        "valuation_percentile",
        "volatility",
        "eps_staleness",
        "regime_entropy",
        "regime_confidence",
        "state_uncertainty",
        "training_distribution_distance",
    }
    used = {feature for spec in VARIANT_SPECS.values() for feature in spec["features"]}
    if not used <= allowed:
        raise RuntimeError("sparse-router feature universe expanded")
    if any(
        token in feature.casefold()
        for feature in (*ROUTER_BASE_COLUMNS, *ROUTER_FEATURE_COLUMNS, *used)
        for token in FORBIDDEN_FEATURE_TOKENS
    ):
        raise RuntimeError("sparse-router contract contains a forbidden feature")
    if set(ROUTER_BASE_COLUMNS) & set(IDENTITY_COLUMNS) != {"session_position"}:
        raise RuntimeError("sparse-router received an unnecessary identity column")
    if RESEARCH_TARGET != {
        "mae_relative_gain_min": 0.04,
        "systematic_joint_tail_failure_count_max": 0,
        "worst_dgp_mean_harm_max": 0.01,
        "worst_seed_dgp_cell_harm_max": 0.03,
        "pooled_p95_non_worse": True,
        "pooled_p99_non_worse": True,
        "pooled_extreme_frequency_non_worse": True,
    }:
        raise RuntimeError("sparse-router research target differs")


validate_contract()


__all__ = [name for name in globals() if name.isupper()] + ["validate_contract"]
