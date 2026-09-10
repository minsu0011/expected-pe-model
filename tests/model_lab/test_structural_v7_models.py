"""Lightweight synthetic tests for the new V7 mathematical structures."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.structural_v7.models import (
    apply_geometric_weights,
    fit_decomposition_ar,
    fit_geometric_pair_weight,
    fit_nonnegative_simplex_weights,
    fit_residual_feature_model,
)


def test_fixed_and_learned_geometric_blends() -> None:
    rng = np.random.default_rng(17)
    base0 = np.exp(rng.normal(3.0, 0.08, 240))
    base1 = np.exp(rng.normal(3.0, 0.08, 240))
    target = apply_geometric_weights(np.column_stack([base0, base1]), (0.7, 0.3))
    fixed = apply_geometric_weights(np.column_stack([base0[:5], base1[:5]]), (0.5, 0.5))
    assert np.allclose(fixed, np.sqrt(base0[:5] * base1[:5]))
    learned = fit_geometric_pair_weight(target, base0, base1)
    assert learned.weights[0] == pytest.approx(0.7, abs=1e-10)
    assert learned.weights[1] == pytest.approx(0.3, abs=1e-10)
    assert learned.row_count == 240
    assert learned.preferred_min_pass is False


def test_three_base_nonnegative_simplex_recovers_convex_weights() -> None:
    rng = np.random.default_rng(23)
    matrix = np.exp(rng.normal(3.0, 0.12, size=(260, 3)))
    target = apply_geometric_weights(matrix, (0.2, 0.5, 0.3))
    fit = fit_nonnegative_simplex_weights(target, matrix)
    assert np.asarray(fit.weights) == pytest.approx([0.2, 0.5, 0.3], abs=2e-6)
    assert min(fit.weights) >= 0.0
    assert sum(fit.weights) == pytest.approx(1.0)
    assert fit.preferred_min_pass is True


@pytest.mark.parametrize("kind", ["spline", "extra_trees"])
def test_feature_residual_models_use_oof_base_and_bound_corrections(kind: str) -> None:
    rng = np.random.default_rng(31)
    rows = 220
    columns = ("growth", "rate", "vol")
    frame = pd.DataFrame(rng.normal(size=(rows, 3)), columns=columns)
    frame.loc[::17, "rate"] = np.nan
    base = np.exp(3.0 + 0.02 * rng.normal(size=rows))
    correction = 0.04 * frame["growth"].to_numpy() - 0.02 * frame["vol"].to_numpy()
    observed = base * np.exp(correction)
    fit = fit_residual_feature_model(
        kind, frame, observed, base, feature_columns=columns, random_state=9
    )
    predicted = fit.predict(frame.iloc[:11], base[:11])
    assert len(predicted) == 11
    assert np.isfinite(predicted).all()
    assert (predicted > 0.0).all()
    assert np.max(np.abs(np.log(predicted / base[:11]))) <= fit.correction_bound_log + 1e-12


def test_structural_plus_ar_decomposition_is_fixed_origin_and_positive() -> None:
    rng = np.random.default_rng(47)
    rows = 230
    columns = ("growth", "rate", "vol")
    frame = pd.DataFrame(rng.normal(size=(rows, 3)), columns=columns)
    residual = np.zeros(rows)
    for index in range(1, rows):
        residual[index] = 0.6 * residual[index - 1] + rng.normal(0.0, 0.005)
    observed = np.exp(3.0 + 0.08 * frame["growth"] - 0.04 * frame["rate"] + residual)
    fit = fit_decomposition_ar(frame, observed, feature_columns=columns)
    future = pd.DataFrame(rng.normal(size=(21, 3)), columns=columns)
    first = fit.predict(future)
    second = fit.predict(future)
    assert np.array_equal(first, second)
    assert np.isfinite(first).all() and (first > 0.0).all()
    assert -0.95 <= fit.rho <= 0.95
