"""Leakage-boundary tests for the non-deployable simulator specialists."""

from __future__ import annotations

import inspect

import numpy as np
import pandas as pd

from research.model_zoo.simulator_specialist_v1.adapters import fit_predict_candidate
from research.model_zoo.simulator_specialist_v1.evaluation import classify_candidate_outputs
from research.model_zoo.simulator_specialist_v1.spec import CANDIDATE_IDS, FEATURES


def _fixture(rows: int = 260, test_rows: int = 7):
    rng = np.random.default_rng(20260820)
    total = rows + test_rows
    position = np.arange(total, dtype=float)
    frame = pd.DataFrame(
        {
            name: np.sin(position / (13.0 + index)) + rng.normal(0.0, 0.02, total)
            for index, name in enumerate(FEATURES)
        }
    )
    frame["true_fair_pe"] = np.exp(3.0 + 0.002 * np.sin(position / 20.0))
    base = np.exp(3.0 + 0.001 * np.cos(position / 17.0))
    return (
        frame.iloc[:rows].copy(),
        frame.iloc[rows:].copy(),
        base[:rows],
        base[rows:],
        frame.iloc[:rows]["true_fair_pe"].to_numpy(float),
    )


def test_adapter_signature_has_no_test_truth_argument() -> None:
    assert "test_truth" not in inspect.signature(fit_predict_candidate).parameters


def test_all_specialists_are_invariant_to_test_truth_column() -> None:
    train, test, train_base, test_base, train_truth = _fixture()
    for model_id in CANDIDATE_IDS:
        first = fit_predict_candidate(model_id, train, test, train_base, test_base, train_truth)
        changed = test.copy()
        changed["true_fair_pe"] *= 1_000.0
        second = fit_predict_candidate(model_id, train, changed, train_base, test_base, train_truth)
        np.testing.assert_array_equal(first, second)
        assert len(first) == len(test)
        assert np.isfinite(first).all() and (first > 0.0).all()


def test_training_truth_is_a_real_specialist_input() -> None:
    train, test, train_base, test_base, train_truth = _fixture()
    first = fit_predict_candidate(
        "sim_true_residual_ar1_v1", train, test, train_base, test_base, train_truth
    )
    changed = fit_predict_candidate(
        "sim_true_residual_ar1_v1",
        train,
        test,
        train_base,
        test_base,
        train_truth * 1.05,
    )
    assert not np.array_equal(first, changed)


def test_broken_candidate_does_not_shrink_complete_candidate_mask() -> None:
    rows = []
    for model_id in CANDIDATE_IDS:
        for position in range(3):
            rows.append(
                {
                    "model_id": model_id,
                    "prediction": (
                        np.nan
                        if model_id == "sim_true_residual_uc_local_level_ar1_v1"
                        else 20.0 + position
                    ),
                }
            )
    complete, status = classify_candidate_outputs(pd.DataFrame(rows), expected_rows=3)
    assert "sim_true_residual_uc_local_level_ar1_v1" not in complete
    assert status["sim_true_residual_uc_local_level_ar1_v1"]["status"] == "BROKEN"
    assert status["sim_true_residual_ar1_v1"]["status"] == "COMPLETE"
