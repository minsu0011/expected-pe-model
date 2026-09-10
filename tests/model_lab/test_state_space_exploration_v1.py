"""Score-free tests for state-space Exploration V1."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.aggressive_lab.contracts import AggressiveLabContractError
from research.model_zoo.state_space_exploration_v1.adapters import fit_predict_candidate
from research.model_zoo.state_space_exploration_v1.runner import (
    _runtime_snapshot,
    _verify_runtime,
)
from research.model_zoo.state_space_exploration_v1.spec import (
    CANDIDATE_IDS,
    CHEAP_FOLD_IDS,
    ECONOMETRIC_FEATURES,
    design_payload,
)


def _frames(n_train: int = 230, n_test: int = 5):
    rng = np.random.default_rng(123)
    total = n_train + n_test
    time = np.arange(total, dtype=float)
    frame = pd.DataFrame(
        {
            column: np.sin(time / (11.0 + index)) + rng.normal(0.0, 0.02, total)
            for index, column in enumerate(ECONOMETRIC_FEATURES)
        }
    )
    frame["observed_pe"] = np.exp(3.0 + 0.0005 * time + rng.normal(0.0, 0.02, total))
    baseline = pd.DataFrame({"v04_expected_pe": np.exp(3.0 + 0.0004 * time)})
    return (
        frame.iloc[:n_train],
        frame.iloc[n_train:],
        baseline.iloc[:n_train],
        baseline.iloc[n_train:],
    )


def test_design_is_distinct_family_not_micro_tuning() -> None:
    payload = design_payload()
    assert len(CANDIDATE_IDS) == 5
    assert len({item["family"] for item in payload["candidates"]}) == 5
    assert payload["same_row_test_target_updates"] is False
    assert len(CHEAP_FOLD_IDS) == 12
    assert payload["expected_rows_per_model"] == 1230


def test_recursive_dynamic_regression_is_truth_blind_on_test_rows() -> None:
    train, test, train_base, test_base = _frames()
    first = fit_predict_candidate(
        "discounted_rls_dynamic_regression_v1", train, test, train_base, test_base
    )
    changed = test.copy()
    changed["observed_pe"] *= 1000.0
    second = fit_predict_candidate(
        "discounted_rls_dynamic_regression_v1", train, changed, train_base, test_base
    )
    np.testing.assert_array_equal(first, second)
    assert np.isfinite(first).all() and (first > 0.0).all()


def test_local_linear_trend_smoke_and_test_target_intervention() -> None:
    train, test, train_base, test_base = _frames()
    first = fit_predict_candidate("uc_local_linear_trend_v1", train, test, train_base, test_base)
    changed = test.copy()
    changed["observed_pe"] = np.nan
    second = fit_predict_candidate(
        "uc_local_linear_trend_v1", train, changed, train_base, test_base
    )
    np.testing.assert_array_equal(first, second)
    assert len(first) == len(test)


def test_every_locked_adapter_emits_positive_fixed_origin_forecasts() -> None:
    train, test, train_base, test_base = _frames()
    for model_id in CANDIDATE_IDS:
        first = fit_predict_candidate(model_id, train, test, train_base, test_base)
        changed = test.copy()
        changed["observed_pe"] = np.inf
        second = fit_predict_candidate(model_id, train, changed, train_base, test_base)
        np.testing.assert_array_equal(first, second)
        assert len(first) == len(test)
        assert np.isfinite(first).all() and (first > 0.0).all()


def test_runner_source_does_not_import_truth_or_evaluator() -> None:
    source = Path("research/model_zoo/state_space_exploration_v1/runner.py").read_text(
        encoding="utf-8"
    )
    assert "EVALUATE_INPUTS" not in source
    assert "true_fair_pe" not in source
    assert "evaluation_target" not in source


def test_runtime_closure_rejects_version_drift() -> None:
    runtime = _runtime_snapshot()
    assert _verify_runtime({"runtime": runtime}) == runtime
    changed = {**runtime, "python_version": "0.0.0"}
    with pytest.raises(AggressiveLabContractError, match="runtime closure differs"):
        _verify_runtime({"runtime": changed})
