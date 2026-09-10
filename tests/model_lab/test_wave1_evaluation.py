from __future__ import annotations

import math

import numpy as np
import pandas as pd

from pe_regime_v04.model_lab.models.wave1.artifacts import PREDICTION_COLUMNS
from pe_regime_v04.model_lab.models.wave1.evaluation import evaluate_wave1_predictions
from pe_regime_v04.model_lab.models.wave1.spec import BASELINE_MODEL_IDS


def _evaluation_fixture() -> tuple[pd.DataFrame, dict[int, pd.DataFrame], dict[str, float]]:
    candidates = ("ridge_svd_common", "huber_common")
    dates = pd.date_range("2015-01-02", periods=4, freq="B")
    truth_values = np.asarray([10.0, 11.0, 12.0, 13.0])
    multipliers = {
        "ridge_svd_common": 1.0,
        "huber_common": 1.20,
        "v04_expected_pe": 1.10,
        "ml_expected_pe": 1.08,
        "v04_ml_expected_pe_no_regime": 1.09,
        "v04_ml_expected_pe_with_regime": 1.05,
    }
    rows: list[dict[str, object]] = []
    truth_by_seed: dict[int, pd.DataFrame] = {}
    for seed in (1, 2):
        truth_by_seed[seed] = pd.DataFrame(
            {"date": dates, "true_fair_pe": truth_values * (1.0 + 0.001 * seed)}
        )
        seed_truth = truth_by_seed[seed]["true_fair_pe"].to_numpy(float)
        for model_id in (*candidates, *BASELINE_MODEL_IDS):
            for position, date in enumerate(dates):
                rows.append(
                    {
                        "seed": seed,
                        "date": date,
                        "symbol": "SYNTH",
                        "fold_id": "fold_000",
                        "test_start_position": 252,
                        "model_id": model_id,
                        "prediction": seed_truth[position] * multipliers[model_id],
                    }
                )
    predictions = pd.DataFrame(rows).loc[:, list(PREDICTION_COLUMNS)]
    runtime = {model_id: 0.0 for model_id in (*candidates, *BASELINE_MODEL_IDS)}
    return predictions, truth_by_seed, runtime


def test_primary_gate_uses_lower_independent_baseline_and_deterministic_advancement() -> None:
    predictions, truth, runtime = _evaluation_fixture()
    result = evaluate_wave1_predictions(
        predictions,
        truth,
        runtime_seconds_by_model=runtime,
        candidate_model_ids=("ridge_svd_common", "huber_common"),
        strict_expected_rows_per_seed=4,
    )
    ridge = result.gates.loc[result.gates["model_id"] == "ridge_svd_common"].iloc[0]
    huber = result.gates.loc[result.gates["model_id"] == "huber_common"].iloc[0]
    summary = result.metrics.summary.set_index("model_id")
    assert ridge["mae_primary_comparator"] == min(
        summary.loc["v04_expected_pe", "fair_log_mae"],
        summary.loc["ml_expected_pe", "fair_log_mae"],
    )
    assert ridge["primary_path_pass"]
    assert ridge["stage1_gate_pass"]
    assert ridge["advanced"]
    assert huber["stage1_gate_pass"] is False or not bool(huber["stage1_gate_pass"])
    assert result.common_identity_rows == result.expected_identity_rows == 8
    assert result.complementarity_baseline == "ml_expected_pe"


def test_missing_candidate_prediction_fails_strict_common_coverage() -> None:
    predictions, truth, runtime = _evaluation_fixture()
    index = predictions.index[predictions["model_id"] == "ridge_svd_common"][0]
    predictions.loc[index, "prediction"] = np.nan
    result = evaluate_wave1_predictions(
        predictions,
        truth,
        runtime_seconds_by_model=runtime,
        candidate_model_ids=("ridge_svd_common", "huber_common"),
        strict_expected_rows_per_seed=4,
    )
    ridge = result.gates.loc[result.gates["model_id"] == "ridge_svd_common"].iloc[0]
    assert not bool(ridge["coverage_pass"])
    assert not bool(ridge["stage1_gate_pass"])
    assert result.common_identity_rows == 7
    assert math.isfinite(float(ridge["fair_log_mae"]))
