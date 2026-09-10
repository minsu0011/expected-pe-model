from __future__ import annotations

import numpy as np
import pytest

from research.model_zoo.pe_c5_r2_sequence_research_v1.contracts import (
    CANDIDATE_ORDER,
    FEATURE_NAMES,
    LOOKBACK,
    SequenceResearchContractError,
    candidate_configuration,
    validate_candidate_configuration,
    validate_sample_boundary,
)
from research.model_zoo.pe_c5_r2_sequence_research_v1.evaluation import (
    dlinear_signal,
    score_track,
)
from research.model_zoo.pe_c5_r2_sequence_research_v1.worker import (
    build_window_view,
    prediction_semantic_digest,
)


def test_track_roles_and_candidate_configuration_are_explicitly_separate() -> None:
    config = candidate_configuration()
    validate_candidate_configuration(config)
    assert tuple(config["candidate_order"]) == CANDIDATE_ORDER
    assert config["tracks"]["S"] == {
        "role": "SIMULATOR_SPECIALIST",
        "deployable": False,
        "promotion_eligible": False,
        "label": "true_log_fair_pe[t]",
        "target": "true_log_fair_pe[t]-v04_expected_log_pe[t-1]",
        "evidence": "RESEARCH_ONLY_SPENT_SYNTHETIC_TRUTH",
    }
    assert config["tracks"]["P"]["role"] == "PIT_OBSERVABLE_SEQUENCE_RESEARCH"
    assert config["tracks"]["P"]["label"] == "observed_log_pe[t]"
    assert config["tracks"]["P"]["promotion_eligible"] is False
    assert config["panel_training"]["within_test_block_parameter_updates"] == 0
    assert config["models"]["dlinear_residual"]["parameter_count"] == 1261
    assert config["models"]["compact_gru"]["parameter_count"] == 4257
    assert config["models"]["compact_gru"]["parameter_count"] < 250_000


def test_every_sequence_window_is_strictly_before_its_label() -> None:
    for label in range(504, 1800):
        validate_sample_boundary(
            label_position=label,
            source_position_min=label - LOOKBACK,
            source_position_max=label - 1,
        )
    with pytest.raises(SequenceResearchContractError):
        validate_sample_boundary(
            label_position=504,
            source_position_min=441,
            source_position_max=504,
        )
    with pytest.raises(SequenceResearchContractError):
        validate_sample_boundary(
            label_position=504,
            source_position_min=441,
            source_position_max=503,
            input_names=(*FEATURE_NAMES[:-1], "true_log_fair_pe"),
        )


def test_window_view_maps_label_t_to_exact_t_minus_63_through_t_minus_1() -> None:
    features = np.arange(2 * 80 * len(FEATURE_NAMES), dtype=np.float32).reshape(
        2, 80, len(FEATURE_NAMES)
    )
    windows = build_window_view(features)
    label = 70
    observed = windows[1, label - LOOKBACK]
    assert observed.shape == (LOOKBACK, len(FEATURE_NAMES))
    assert np.array_equal(observed, features[1, label - LOOKBACK : label])
    assert not np.any(observed == features[1, label, 0])


def test_prediction_digest_is_exact_across_process_equivalent_arrays() -> None:
    values = {
        "P": {"lagged_v04_persistence": np.arange(12, dtype=np.float64).reshape(3, 4)},
        "S": {"dlinear_residual": np.ones((3, 4), dtype=np.float64)},
    }
    copied = {
        track: {model: prediction.copy() for model, prediction in models.items()}
        for track, models in values.items()
    }
    assert prediction_semantic_digest(values) == prediction_semantic_digest(copied)
    copied["S"]["dlinear_residual"][0, 0] = np.nextafter(1.0, 2.0)
    assert prediction_semantic_digest(values) != prediction_semantic_digest(copied)


def test_score_and_conditional_gru_trigger_use_only_predeclared_metrics() -> None:
    rng = np.random.default_rng(17)
    target = rng.normal(3.0, 0.05, size=(50, 80))
    baseline_error = rng.normal(0.0, 0.04, size=target.shape)
    baseline = target + baseline_error
    dlinear = target + 0.5 * baseline_error
    cores = {
        "C4": target + rng.normal(0.0, 0.03, size=target.shape),
        "C2": target + rng.normal(0.0, 0.035, size=target.shape),
    }
    config = candidate_configuration()
    metrics = score_track(
        predictions={
            "lagged_v04_persistence": baseline,
            "dlinear_residual": dlinear,
        },
        target=target,
        dgp_ids=tuple("ABCDEFGHIJ"),
        core_predictions=cores,
        survivor_rule=config["survivor_rule"],
    )
    assert metrics["dlinear_residual"]["mae_gain_vs_persistence"] > 0.45
    assert metrics["dlinear_residual"]["systematic_joint_tail_failure_count"] == 0
    run_gru, decisions = dlinear_signal(
        {"S": metrics}, config["conditional_execution"]["dlinear_signal"]
    )
    assert run_gru is True
    assert decisions == {"S": True}


def test_candidate_configuration_drift_is_rejected() -> None:
    drifted = candidate_configuration()
    drifted["models"]["compact_gru"]["hidden_size"] = 64
    with pytest.raises(SequenceResearchContractError):
        validate_candidate_configuration(drifted)
