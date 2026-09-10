from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import (
    ContractError,
    build_leaderboard,
    evaluate_fair_predictions,
    oracle_complementarity,
    pareto_frontier,
)


def test_evaluator_computes_full_metric_set_and_worst_seed(
    prediction_frame: pd.DataFrame,
) -> None:
    result = evaluate_fair_predictions(
        prediction_frame,
        runtime_seconds_by_model={"model_a": 1.25, "model_b": 2.5},
        evaluation_start="2015-01-02",
    )
    assert result.summary["model_id"].tolist() == ["model_a", "model_b"]
    a = result.summary.set_index("model_id").loc["model_a"]
    expected_mae = math.log(2.0) / 2.0
    assert a["fair_log_mae"] == pytest.approx(expected_mae)
    assert a["fair_log_rmse"] == pytest.approx(math.log(2.0) / math.sqrt(2.0))
    assert a["fair_abs_log_error_median"] == pytest.approx(expected_mae)
    assert a["fair_abs_log_error_p90"] == pytest.approx(math.log(2.0))
    assert a["fair_abs_log_error_p95"] == pytest.approx(math.log(2.0))
    assert a["fair_log_bias"] == pytest.approx(0.0)
    assert a["coverage"] == 1.0
    assert a["runtime_seconds"] == 1.25
    assert a["worst_seed_fair_log_mae"] == pytest.approx(expected_mae)
    assert len(result.per_seed) == 4
    assert result.row_errors["valid_prediction"].all()


def test_evaluator_enforces_formal_start_and_reports_natural_coverage(
    prediction_frame: pd.DataFrame,
) -> None:
    before = prediction_frame.iloc[[0]].copy()
    before["date"] = pd.Timestamp("2014-12-31")
    before["seed"] = 99
    frame = pd.concat([prediction_frame, before], ignore_index=True)
    frame.loc[
        (frame["model_id"] == "model_a") & (frame["date"] == pd.Timestamp("2015-01-02")),
        "prediction",
    ] = np.nan
    result = evaluate_fair_predictions(
        frame,
        common_mask_model_ids=["model_a", "model_b"],
    )
    summary = result.summary.set_index("model_id")
    assert summary.loc["model_a", "natural_coverage"] == pytest.approx(0.75)
    assert summary.loc["model_b", "natural_coverage"] == 1.0
    assert (summary["coverage"] == 1.0).all()
    assert (summary["evaluated_rows"] == 3).all()
    assert summary["identical_common_mask"].all()
    assert summary["identity_sha256"].nunique() == 1
    assert (summary["identity_row_count"] == 3).all()
    assert not summary["full_coverage"].all()
    assert result.row_errors.groupby("model_id")["date"].apply(tuple).nunique() == 1


def test_evaluator_rejects_duplicate_missing_seed_and_bad_runtime(
    prediction_frame: pd.DataFrame,
) -> None:
    duplicate = pd.concat([prediction_frame, prediction_frame.iloc[[0]]], ignore_index=True)
    with pytest.raises(ContractError, match="unique"):
        evaluate_fair_predictions(duplicate)
    with pytest.raises(ContractError, match="seed"):
        evaluate_fair_predictions(prediction_frame.drop(columns="seed"), identity_columns=("date",))
    with pytest.raises(ContractError, match="runtime"):
        evaluate_fair_predictions(prediction_frame, runtime_seconds_by_model={"model_a": -1.0})
    with pytest.raises(ContractError, match="unknown models"):
        evaluate_fair_predictions(prediction_frame, runtime_seconds_by_model={"typo": 1.0})


def test_leaderboard_has_stable_tie_breaks_and_pareto_frontier(
    prediction_frame: pd.DataFrame,
) -> None:
    summary = evaluate_fair_predictions(
        prediction_frame,
        runtime_seconds_by_model={"model_a": 2.0, "model_b": 1.0},
        common_mask_model_ids=["model_a", "model_b"],
    ).summary
    board = build_leaderboard(
        summary,
        comparator_model_ids=["model_a", "model_b"],
    )
    assert board["rank"].tolist() == [1, 2]
    assert board["model_id"].tolist() == ["model_b", "model_a"]
    frontier = pareto_frontier(summary)
    assert frontier["model_id"].tolist() == ["model_b"]


def test_pareto_retains_models_with_real_tradeoffs() -> None:
    summary = pd.DataFrame(
        {
            "model_id": ["accurate", "fast", "dominated"],
            "fair_log_mae": [0.1, 0.2, 0.3],
            "fair_log_rmse": [0.1, 0.2, 0.3],
            "fair_abs_log_error_p95": [0.1, 0.2, 0.3],
            "runtime_seconds": [10.0, 1.0, 20.0],
            "worst_seed_fair_log_mae": [0.1, 0.2, 0.4],
            "coverage": [1.0, 1.0, 0.9],
        }
    )
    assert set(pareto_frontier(summary)["model_id"]) == {"accurate", "fast"}


def test_oracle_complementarity_is_evaluation_only_and_exact(
    prediction_frame: pd.DataFrame,
) -> None:
    result = oracle_complementarity(prediction_frame)
    assert len(result) == 1
    row = result.iloc[0]
    assert row["common_rows"] == 4
    assert row["oracle_fair_log_mae"] == 0.0
    assert row["oracle_gain_vs_best_single"] == pytest.approx(math.log(2.0) / 2.0)
    assert row["model_a_win_fraction"] == 0.5
    assert row["model_b_win_fraction"] == 0.5
    assert row["signed_log_residual_correlation"] == pytest.approx(0.0, abs=1.0e-12)
    assert row["absolute_error_correlation"] == pytest.approx(-1.0)
    assert row["prediction_disagreement_frequency"] == 1.0
    assert row["mean_absolute_log_prediction_disagreement"] == pytest.approx(math.log(2.0))
    assert bool(row["evaluation_only"]) is True


def test_analysis_rejects_nonfinite_or_duplicate_inputs(
    prediction_frame: pd.DataFrame,
) -> None:
    summary = evaluate_fair_predictions(
        prediction_frame,
        common_mask_model_ids=["model_a", "model_b"],
    ).summary
    summary.loc[0, "fair_log_mae"] = np.nan
    with pytest.raises(ContractError, match="finite"):
        build_leaderboard(
            summary,
            comparator_model_ids=["model_a", "model_b"],
        )
    duplicate = pd.concat([prediction_frame, prediction_frame.iloc[[0]]], ignore_index=True)
    with pytest.raises(ContractError, match="unique"):
        oracle_complementarity(duplicate)


def test_comparative_leaderboard_requires_exact_common_mask_binding(
    prediction_frame: pd.DataFrame,
) -> None:
    summary = evaluate_fair_predictions(
        prediction_frame,
        common_mask_model_ids=["model_a", "model_b"],
    ).summary
    with pytest.raises(ContractError, match="explicit unique comparator"):
        build_leaderboard(summary)
    unequal = summary.copy()
    unequal.loc[0, "identity_sha256"] = "0" * 64
    with pytest.raises(ContractError, match="binding mismatch"):
        build_leaderboard(
            unequal,
            comparator_model_ids=["model_a", "model_b"],
        )
    incomplete = summary.copy()
    incomplete.loc[0, "natural_coverage"] = 0.75
    incomplete.loc[0, "full_coverage"] = False
    with pytest.raises(ContractError, match="full coverage"):
        build_leaderboard(
            incomplete,
            comparator_model_ids=["model_a", "model_b"],
        )


def test_evaluation_and_oracle_reject_truth_mismatch_for_shared_identity(
    prediction_frame: pd.DataFrame,
) -> None:
    mismatch = prediction_frame.copy()
    mask = (mismatch["model_id"] == "model_b") & (mismatch["date"] == mismatch["date"].min())
    mismatch.loc[mask, "true_fair_pe"] *= 1.01
    with pytest.raises(ContractError, match="truth must be identical"):
        evaluate_fair_predictions(
            mismatch,
            common_mask_model_ids=["model_a", "model_b"],
        )
    with pytest.raises(ContractError, match="truth must be identical"):
        oracle_complementarity(mismatch)
