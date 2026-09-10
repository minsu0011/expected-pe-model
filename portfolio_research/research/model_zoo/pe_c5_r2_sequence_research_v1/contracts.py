"""Frozen scientific and execution contracts for C5-R2 sequence research."""

from __future__ import annotations

import hashlib
import json
from typing import Final, Mapping


class SequenceResearchContractError(ValueError):
    """Raised when the research lane crosses a causal or governance boundary."""


LOOKBACK: Final = 63
TRAIN_LABEL_START: Final = 252
EVALUATION_START: Final = 504
EVALUATION_END_EXCLUSIVE: Final = 1800
TEST_BLOCK: Final = 21
TEST_STARTS: Final = tuple(range(EVALUATION_START, EVALUATION_END_EXCLUSIVE, TEST_BLOCK))
EVALUATION_POSITIONS: Final = tuple(range(EVALUATION_START, EVALUATION_END_EXCLUSIVE))
SEED_VALUES: Final = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
SEED_ALIASES: Final = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
DGP_IDS: Final = tuple("ABCDEFGHIJ")
FEATURE_NAMES: Final = (
    "lagged_v04_expected_log_pe",
    "lagged_observed_log_pe",
    "lagged_eps_ttm_growth_252",
    "lagged_eps_confidence",
    "lagged_eps_staleness_days",
    "lagged_regime_entropy",
    "lagged_regime_confidence",
    "lagged_valuation_log_z",
    "lagged_benchmark_realized_vol_20",
    "lagged_rate_state",
)
PROHIBITED_INPUT_TOKENS: Final = (
    "future_",
    "label",
    "target",
    "true_fair_pe",
    "true_log_fair_pe",
    "true_expected_pe_eligible",
)
CANDIDATE_ORDER: Final = ("lagged_v04_persistence", "dlinear_residual", "compact_gru")


def canonical_json_bytes(value: object) -> bytes:
    """Return the project research-lane canonical JSON representation."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def semantic_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return raw_sha256(raw)


def validate_sample_boundary(
    *,
    label_position: int,
    source_position_min: int,
    source_position_max: int,
    input_names: tuple[str, ...] = FEATURE_NAMES,
) -> None:
    """Enforce that every tensor source is in ``[t-63, t-1]``."""

    if (
        type(label_position) is not int
        or type(source_position_min) is not int
        or type(source_position_max) is not int
        or source_position_min != label_position - LOOKBACK
        or source_position_max != label_position - 1
        or source_position_max >= label_position
    ):
        raise SequenceResearchContractError("sample source/label chronology differs")
    if input_names != FEATURE_NAMES or len(set(input_names)) != len(input_names):
        raise SequenceResearchContractError("input feature order differs")
    lowered = tuple(name.casefold() for name in input_names)
    if any(token in name for name in lowered for token in PROHIBITED_INPUT_TOKENS):
        raise SequenceResearchContractError("same-row, target, or future feature detected")


def candidate_configuration() -> dict[str, object]:
    """Return the complete score-blind configuration for this compact wave."""

    return {
        "schema_version": "expected_pe.c5_r2.sequence_research.candidate_config.v1",
        "candidate_order": list(CANDIDATE_ORDER),
        "panel_training": {
            "pooled_across_tasks": True,
            "seed_or_dgp_identity_feature": False,
            "train_label_start": TRAIN_LABEL_START,
            "evaluation_start": EVALUATION_START,
            "evaluation_end_exclusive": EVALUATION_END_EXCLUSIVE,
            "test_starts": list(TEST_STARTS),
            "test_block_sessions": TEST_BLOCK,
            "tuning_prefix_sessions": 63,
            "fit_labels_max": "test_start-64",
            "tuning_labels_max": "test_start-1",
            "within_test_block_parameter_updates": 0,
        },
        "features": {
            "lookback_sessions": LOOKBACK,
            "ordered_names": list(FEATURE_NAMES),
            "source_mapping": {
                "lagged_v04_expected_log_pe": "log(canonical.expected_pe[source_position])",
                "lagged_observed_log_pe": "log(canonical.observed_pe[source_position])",
                "lagged_eps_ttm_growth_252": "canonical.eps_ttm_growth_252",
                "lagged_eps_confidence": "canonical.eps_confidence",
                "lagged_eps_staleness_days": "canonical.eps_staleness_days",
                "lagged_regime_entropy": "canonical.regime_entropy",
                "lagged_regime_confidence": "canonical.regime_confidence",
                "lagged_valuation_log_z": "canonical.regime_conditional_pe_log_z",
                "lagged_benchmark_realized_vol_20": ("canonical.benchmark_realized_vol_20"),
                "lagged_rate_state": (
                    "public factor real_rate_z, else short_rate_z, else missing; never DGP identity"
                ),
            },
            "missing_value_policy": "training-prefix raw-feature median",
            "standardization": "training-prefix mean/std after median fill",
            "same_row_or_future_input_allowed": False,
        },
        "tracks": {
            "S": {
                "role": "SIMULATOR_SPECIALIST",
                "deployable": False,
                "promotion_eligible": False,
                "label": "true_log_fair_pe[t]",
                "target": "true_log_fair_pe[t]-v04_expected_log_pe[t-1]",
                "evidence": "RESEARCH_ONLY_SPENT_SYNTHETIC_TRUTH",
            },
            "P": {
                "role": "PIT_OBSERVABLE_SEQUENCE_RESEARCH",
                "deployable": "RESEARCH_PROTOTYPE_ONLY",
                "promotion_eligible": False,
                "label": "observed_log_pe[t]",
                "target": "observed_log_pe[t]-v04_expected_log_pe[t-1]",
                "evidence": "RESEARCH_ONLY_PUBLIC_SYNTHETIC",
            },
        },
        "models": {
            "lagged_v04_persistence": {
                "predicted_residual": 0.0,
                "fit_count_per_fold": 0,
            },
            "dlinear_residual": {
                "architecture": (
                    "moving_average_25 trend/seasonal decomposition; flattened 2x63x10; "
                    "single linear residual head"
                ),
                "moving_average_kernel": 25,
                "parameter_count": 1261,
                "optimizer": "AdamW",
                "learning_rate": 0.006,
                "weight_decay": 0.0001,
                "loss": "SmoothL1(beta=1.0) on training-prefix standardized residual",
                "max_epochs": 12,
                "patience": 3,
                "minimum_epochs": 4,
                "batch_size": 32768,
                "initialization": "all-zero linear weight and bias",
            },
            "compact_gru": {
                "architecture": "one-layer GRU(10,32) plus linear residual head",
                "hidden_size": 32,
                "num_layers": 1,
                "dropout": 0.0,
                "parameter_count": 4257,
                "parameter_cap": 250000,
                "optimizer": "AdamW",
                "learning_rate": 0.0015,
                "weight_decay": 0.0001,
                "loss": "SmoothL1(beta=1.0) on training-prefix standardized residual",
                "max_epochs": 10,
                "patience": 3,
                "minimum_epochs": 4,
                "batch_size": 8192,
                "initialization": "PyTorch default under fixed per-fold config seed",
                "precision": "float32",
            },
        },
        "conditional_execution": {
            "one_compact_gru_family_only": True,
            "gru_runs_only_for_each_track_with_dlinear_signal": True,
            "dlinear_signal": {
                "mae_gain_min": 0.005,
                "rmse_gain_min": 0.0,
                "p95_harm_max": 0.01,
                "alternative_oracle_pair_gain_min": 0.02,
                "alternative_max_abs_signed_error_corr": 0.90,
            },
        },
        "survivor_rule": {
            "standalone_mae_gain_min": 0.005,
            "alternative_oracle_pair_gain_min": 0.02,
            "p95_harm_max": 0.03,
            "systematic_joint_tail_failures_max": 0,
            "max_abs_signed_error_corr_with_each_core": 0.90,
            "formal_authority": False,
        },
        "runtime": {
            "device": "cuda:0",
            "required_gpu_name": "NVIDIA GeForce RTX 5080",
            "precision": "float32",
            "amp": False,
            "tf32": False,
            "torch_deterministic_algorithms": True,
            "cublas_workspace_config": ":4096:8",
            "prediction_parity_process_count": 2,
            "prediction_digest_equality_required": True,
            "fold_seed_schedule": (
                "55100 + track_offset(P=0,S=1000) + "
                "model_offset(DLinear=0,GRU=10000) + fold_ordinal"
            ),
            "cpu_data_workers": 16,
            "inner_blas_threads": 1,
        },
    }


def validate_candidate_configuration(value: Mapping[str, object]) -> None:
    expected = candidate_configuration()
    if dict(value) != expected:
        raise SequenceResearchContractError("candidate configuration differs from source lock")


__all__ = [
    "CANDIDATE_ORDER",
    "DGP_IDS",
    "EVALUATION_END_EXCLUSIVE",
    "EVALUATION_POSITIONS",
    "EVALUATION_START",
    "FEATURE_NAMES",
    "LOOKBACK",
    "PROHIBITED_INPUT_TOKENS",
    "SEED_ALIASES",
    "SEED_VALUES",
    "TEST_BLOCK",
    "TEST_STARTS",
    "TRAIN_LABEL_START",
    "SequenceResearchContractError",
    "candidate_configuration",
    "canonical_json_bytes",
    "raw_sha256",
    "semantic_sha256",
    "validate_candidate_configuration",
    "validate_sample_boundary",
]
