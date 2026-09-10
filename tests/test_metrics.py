from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.ablation import build_ablation_report
from pe_regime_v04.metrics import (
    candidate_metrics,
    paired_candidate_metrics,
    regime_metrics,
    valuation_direction_metrics,
    valuation_state_metrics,
)


def test_valuation_state_metrics_reports_precision_and_recall() -> None:
    observed = pd.Series([8.0, 8.5, 10.0, 12.0, 13.0])
    fair = pd.Series([10.0, 10.0, 10.0, 10.0, 10.0])
    state = pd.Series(
        [
            "CHEAP_TAIL_FOR_CONDITIONS",
            "NORMAL_FOR_CONDITIONS",
            "NORMAL_FOR_CONDITIONS",
            "EXPENSIVE_TAIL_FOR_CONDITIONS",
            "EXPENSIVE_TAIL_FOR_CONDITIONS",
        ]
    )
    metrics = valuation_state_metrics(state, observed, fair, threshold=0.10)
    assert metrics["cheap"]["support"] == 2
    assert metrics["cheap"]["predicted_rows"] == 1
    assert metrics["cheap"]["precision"] == 1.0
    assert metrics["cheap"]["recall"] == 0.5
    assert metrics["expensive"]["support"] == 2
    assert metrics["expensive"]["precision"] == 1.0
    assert metrics["expensive"]["recall"] == 1.0


def test_valuation_state_metrics_excludes_non_signal_states() -> None:
    metrics = valuation_state_metrics(
        pd.Series(["INSUFFICIENT_DATA", "NO_MEANINGFUL_PE", "CHEAP_FOR_CONDITIONS"]),
        pd.Series([10.0, 10.0, 8.0]),
        pd.Series([10.0, 10.0, 10.0]),
    )
    assert metrics["evaluated_rows"] == 1
    assert metrics["excluded_non_signal_rows"] == 2


def test_paired_metrics_cannot_compare_disjoint_coverage() -> None:
    baseline = pd.Series([10.0, 10.0, float("nan"), float("nan")])
    challenger = pd.Series([float("nan"), float("nan"), 10.0, 10.0])
    target = pd.Series([10.0, 10.0, 10.0, 10.0])
    metrics = paired_candidate_metrics(baseline, challenger, target)
    assert metrics["paired_observed_rows"] == 0
    assert metrics["challenger_observed_log_mae_gain"] is None


def test_paired_metrics_use_identical_rows_for_both_candidates() -> None:
    target = pd.Series([10.0, 10.0, 10.0])
    metrics = paired_candidate_metrics(
        pd.Series([10.0, 10.0, float("nan")]),
        pd.Series([11.0, 9.0, 10.0]),
        target,
    )
    assert metrics["paired_observed_rows"] == 2
    assert metrics["baseline_observed_log_mae"] == 0.0
    assert metrics["challenger_observed_log_mae"] == pytest.approx(
        (abs(math.log(1.1)) + abs(math.log(0.9))) / 2
    )


def test_ablation_truth_alignment_preserves_custom_working_index() -> None:
    index = pd.Index([10, 20, 30], name="source_row")
    dates = pd.date_range("2020-01-02", periods=3, freq="B")
    frame = pd.DataFrame(
        {
            "date": dates,
            "benchmark_close": [100.0, 101.0, 102.0],
            "observed_pe": [10.0, 11.0, 12.0],
        },
        index=index,
    )
    truth = pd.DataFrame(
        {
            "date": dates,
            "true_fair_pe": [10.0, 10.0, 10.0],
            "true_observed_pe": [10.0, 11.0, 12.0],
            "true_regime": ["BEAR", "SIDEWAYS", "BULL"],
            "demo_generator_version": ["test-v1"] * 3,
        }
    )
    report = build_ablation_report(frame, truth, forecast_horizon=1)
    identity = report["candidate_ablation"]["B0_observed_pe_identity"]
    assert report["truth_alignment"]["matched_rows"] == 3
    assert identity["fair_coverage_rows"] == 3
    assert identity["fair_log_mae"] == pytest.approx(
        (0.0 + abs(math.log(1.1)) + abs(math.log(1.2))) / 3
    )


def test_metrics_coerce_nullable_float64_and_pd_na() -> None:
    candidate = pd.Series([10.0, pd.NA, np.inf, -1.0], dtype="Float64")
    observed = pd.Series([10.0, 11.0, pd.NA, 12.0], dtype="Float64")
    fair = pd.Series([10.0, pd.NA, 10.0, 10.0], dtype="Float64")

    single = candidate_metrics(candidate, observed, fair)
    assert single["coverage_rows"] == 1
    assert single["fair_coverage_rows"] == 1
    assert single["observed_target_log_mae"] == 0.0

    paired = paired_candidate_metrics(
        candidate,
        pd.Series([10.0, 12.0, pd.NA, 9.0], dtype="Float64"),
        observed,
        fair,
    )
    assert paired["paired_observed_rows"] == 1
    assert paired["paired_fair_rows"] == 1

    direction = valuation_direction_metrics(observed, candidate, fair)
    assert direction["evaluated_rows"] == 1


def test_regime_metrics_coerces_nullable_probability_columns() -> None:
    probabilities = pd.DataFrame(
        {
            "p_bear": pd.Series([0.8, pd.NA, 0.1], dtype="Float64"),
            "p_sideways": pd.Series([0.1, pd.NA, 0.2], dtype="Float64"),
            "p_bull": pd.Series([0.1, pd.NA, 0.7], dtype="Float64"),
        }
    )
    truth = pd.Series(["BEAR", "SIDEWAYS", "BULL"])
    metrics = regime_metrics(probabilities, truth)
    assert metrics["evaluated_rows"] == 2
    assert metrics["invalid_probability_rows"] == 1
    assert metrics["accuracy"] == 1.0
