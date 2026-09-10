from __future__ import annotations

import hashlib
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.classical_exploration_v1.adapters import fit_predict_candidate
from research.model_zoo.classical_exploration_v1.spec import (
    CANDIDATE_IDS,
    DESIGN_LOCK_RAW_SHA256,
    load_design_lock,
)


def _frames(rows: int = 540) -> tuple[pd.DataFrame, pd.DataFrame]:
    position = np.arange(rows, dtype=np.float64)
    observed = 20.0 + 0.01 * position + np.sin(position / 20.0)
    feature = pd.DataFrame(
        {
            "date": pd.date_range("2010-01-04", periods=rows, freq="B"),
            "symbol": "DEMO",
            "observed_pe": observed,
            "eps_ttm_growth_126": np.sin(position / 30.0),
            "eps_ttm_growth_252": np.sin(position / 60.0),
            "eps_staleness_days": position % 90.0,
            "eps_confidence": 80.0 + np.cos(position / 10.0),
            "benchmark_return_63": np.sin(position / 17.0) * 0.1,
            "benchmark_return_252": np.sin(position / 41.0) * 0.2,
            "benchmark_realized_vol_63": 0.2 + np.cos(position / 25.0) * 0.02,
            "benchmark_drawdown_252": -np.abs(np.sin(position / 44.0)) * 0.1,
            "stock_return_63": np.sin(position / 13.0) * 0.1,
            "stock_return_126": np.sin(position / 29.0) * 0.15,
            "pe_median_252_lag": 19.0 + np.sin(position / 50.0),
            "pe_median_756_lag": 18.0 + np.sin(position / 80.0),
        }
    )
    baseline = pd.DataFrame(
        {
            "date": feature["date"],
            "symbol": "DEMO",
            "v04_expected_pe": observed * np.exp(0.03),
        }
    )
    return feature, baseline


def test_design_lock_is_pre_score_and_exact() -> None:
    payload = load_design_lock()
    raw = Path("outputs/model_zoo_classical_exploration_v1_20260820/DESIGN_LOCK.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DESIGN_LOCK_RAW_SHA256
    assert tuple(row["model_id"] for row in payload["candidates"]) == CANDIDATE_IDS
    assert payload["promotion_authority"] == "NOT_PROMOTION_EVIDENCE"


@pytest.mark.parametrize("model_id", CANDIDATE_IDS)
def test_all_candidates_emit_positive_finite_predictions(model_id: str) -> None:
    feature, baseline = _frames()
    prediction = fit_predict_candidate(
        model_id,
        feature.iloc[:504],
        feature.iloc[504:525],
        baseline.iloc[:504],
        baseline.iloc[504:525],
        fold_seed=1,
    )
    assert prediction.shape == (21,)
    assert np.isfinite(prediction).all()
    assert (prediction > 0.0).all()


@pytest.mark.parametrize("model_id", CANDIDATE_IDS)
def test_test_target_intervention_is_invisible(model_id: str) -> None:
    feature, baseline = _frames()
    test = feature.iloc[504:525].copy()
    changed = test.copy()
    changed["observed_pe"] = np.linspace(1.0e6, 2.0e6, len(changed))
    first = fit_predict_candidate(
        model_id,
        feature.iloc[:504],
        test,
        baseline.iloc[:504],
        baseline.iloc[504:525],
        fold_seed=11,
    )
    second = fit_predict_candidate(
        model_id,
        feature.iloc[:504],
        changed,
        baseline.iloc[:504],
        baseline.iloc[504:525],
        fold_seed=11,
    )
    assert np.array_equal(first, second)


def test_training_target_is_log_positive_finite() -> None:
    feature, baseline = _frames()
    feature.loc[0:1, "observed_pe"] = math.nan
    for model_id in CANDIDATE_IDS:
        prediction = fit_predict_candidate(
            model_id,
            feature.iloc[:504],
            feature.iloc[504:525],
            baseline.iloc[:504],
            baseline.iloc[504:525],
            fold_seed=99,
        )
        assert np.isfinite(prediction).all()
