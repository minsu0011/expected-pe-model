from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.structural_v7.folds import build_outer_folds, schedule_sha256
from research.model_zoo.structural_v8.contracts import (
    CANDIDATES,
    COMMON_FEATURE_COLUMNS,
    CURRENT_REGIME_PROBABILITY_COLUMNS,
    REGIME_PROBABILITY_COLUMNS,
    SPENT_SEEDS,
    StructuralV8ContractError,
)
from research.model_zoo.structural_v8.evaluation_identity import (
    EXPECTED_MODEL_IDS,
    validate_exact_evaluation_identity,
)
from research.model_zoo.structural_v8.models import (
    fit_predict_hierarchical_regime_ridge,
    fit_predict_local_linear_analogue,
    fit_predict_rbf_nystroem_residual,
    fixed_causal_regime_gated_residual_blend,
)


def _synthetic_frames(train_rows: int = 260, test_rows: int = 7):
    total = train_rows + test_rows
    index = np.arange(total, dtype=float)
    columns = sorted(
        set(COMMON_FEATURE_COLUMNS)
        | set(REGIME_PROBABILITY_COLUMNS)
        | set(CURRENT_REGIME_PROBABILITY_COLUMNS)
    )
    frame = pd.DataFrame(
        {
            column: np.sin(index / (5.0 + column_index % 13))
            + 0.001 * column_index * index
            for column_index, column in enumerate(columns)
        }
    )
    regime = (index.astype(int) // 35) % 3
    probabilities = np.full((total, 3), 0.1)
    probabilities[np.arange(total), regime] = 0.8
    for column_index, column in enumerate(REGIME_PROBABILITY_COLUMNS):
        frame[column] = probabilities[:, column_index]
    for column_index, column in enumerate(CURRENT_REGIME_PROBABILITY_COLUMNS):
        frame[column] = probabilities[:, column_index]
    incumbent = 18.0 + 0.2 * np.sin(index / 17.0)
    observed = incumbent[:train_rows] * np.exp(
        0.02 * np.sin(index[:train_rows] / 9.0)
        + 0.01 * (regime[:train_rows] - 1)
    )
    return (
        frame.iloc[:train_rows].reset_index(drop=True),
        frame.iloc[train_rows:].reset_index(drop=True),
        observed,
        incumbent[:train_rows],
        incumbent[train_rows:],
    )


def test_four_precommitted_distinct_families() -> None:
    assert len(CANDIDATES) == 4
    assert len({row.candidate_id for row in CANDIDATES}) == 4
    assert len({row.family for row in CANDIDATES}) == 4
    assert sum(row.fit_required for row in CANDIDATES) == 3


def test_all_family_paths_are_finite_positive() -> None:
    train, test, observed, incumbent, outer_incumbent = _synthetic_frames()
    analogue, analogue_receipt = fit_predict_local_linear_analogue(
        train,
        observed,
        incumbent,
        test,
        outer_incumbent,
        feature_columns=COMMON_FEATURE_COLUMNS,
    )
    hierarchy, hierarchy_receipt = fit_predict_hierarchical_regime_ridge(
        train,
        observed,
        test,
        outer_incumbent,
        feature_columns=COMMON_FEATURE_COLUMNS,
    )
    rbf, rbf_receipt = fit_predict_rbf_nystroem_residual(
        train,
        observed,
        incumbent,
        test,
        outer_incumbent,
        feature_columns=COMMON_FEATURE_COLUMNS,
        random_state=42,
    )
    gate, gate_receipt = fixed_causal_regime_gated_residual_blend(
        test,
        outer_incumbent,
        outer_incumbent * np.exp(0.03),
        outer_incumbent * np.exp(-0.02),
    )
    for values in (analogue, hierarchy, rbf, gate):
        assert len(values) == len(test)
        assert np.isfinite(values).all()
        assert (values > 0.0).all()
    assert analogue_receipt.detail["k"] == 32
    assert hierarchy_receipt.detail["regime_alpha"] == 100.0
    assert rbf_receipt.detail["components"] == 64
    assert gate_receipt.row_count == 0


def test_hard_min_is_enforced() -> None:
    train, test, observed, incumbent, outer_incumbent = _synthetic_frames(
        train_rows=199
    )
    with pytest.raises(StructuralV8ContractError, match="hard minimum"):
        fit_predict_local_linear_analogue(
            train,
            observed,
            incumbent,
            test,
            outer_incumbent,
            feature_columns=COMMON_FEATURE_COLUMNS,
        )


def test_prediction_source_has_no_evaluation_truth_reference() -> None:
    root = Path(__file__).resolve().parents[2]
    prediction_sources = (
        "research/model_zoo/structural_v8/data.py",
        "research/model_zoo/structural_v8/models.py",
        "research/model_zoo/structural_v8/runner.py",
        "research/model_zoo/structural_v8/artifacts.py",
        "scripts/model_lab/structural_v8/run_predictions.py",
    )
    for relative in prediction_sources:
        assert "true_fair_pe" not in (root / relative).read_text(encoding="utf-8")


def test_exact_identity_is_five_by_1296_by_five(monkeypatch: pytest.MonkeyPatch) -> None:
    dates = pd.Series(pd.date_range("2019-01-01", periods=1800, freq="B"))
    monkeypatch.setattr(
        "research.model_zoo.structural_v8.evaluation_identity."
        "EXPECTED_OUTER_SCHEDULE_SHA256",
        schedule_sha256(build_outer_folds(dates)),
    )
    spent = {
        seed: SimpleNamespace(dates=dates, symbol="SYNTH") for seed in SPENT_SEEDS
    }
    rows = []
    for seed in SPENT_SEEDS:
        for fold in build_outer_folds(dates):
            for model_id in EXPECTED_MODEL_IDS:
                rows.extend(
                    {
                        "seed": seed,
                        "date": dates.iloc[position],
                        "symbol": "SYNTH",
                        "fold_id": fold.fold_id,
                        "test_start_position": fold.test_start_position,
                        "model_id": model_id,
                        "prediction": 20.0,
                    }
                    for position in fold.test_positions
                )
    frame = pd.DataFrame(rows)
    receipt = validate_exact_evaluation_identity(frame, spent)
    assert receipt.total_rows == 32_400
    assert receipt.model_count == 5
    with pytest.raises(StructuralV8ContractError, match="row count"):
        validate_exact_evaluation_identity(frame.iloc[:-1], spent)
