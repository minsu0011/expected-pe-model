from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.dgp_exploration_iteration2.contracts import (
    CANDIDATE_IDS,
    DGPS,
    POOL_MODELS,
    candidate_design,
    resource_design,
)
from research.model_zoo.dgp_exploration_iteration2.ensemble import (
    _simplex_least_squares,
    build_iteration2_predictions,
)


def _surface() -> tuple[pd.DataFrame, pd.Series]:
    identities: list[tuple[int, str, str, str]] = []
    for dgp_index, dgp in enumerate(DGPS):
        for row in range(3):
            identities.append(
                (1, dgp, f"2020-01-{dgp_index * 3 + row + 1:02d}", "fold_0")
            )
    index = pd.MultiIndex.from_tuples(
        identities, names=["seed", "dgp", "date", "fold_id"]
    )
    base = np.arange(len(index), dtype=float) / 1000.0 + 3.0
    pool = pd.DataFrame(
        {
            POOL_MODELS[0]: np.exp(base + 0.03),
            POOL_MODELS[1]: np.exp(base - 0.02),
            POOL_MODELS[2]: np.exp(base + 0.01),
            POOL_MODELS[3]: np.exp(base - 0.01),
        },
        index=index,
    )
    truth = pd.Series(base, index=index, name="log_truth")
    return pool, truth


def test_design_is_exact_and_resource_limited() -> None:
    assert [item["model_id"] for item in candidate_design()] == list(CANDIDATE_IDS)
    resource = resource_design()
    assert resource["cpu_count_limit"] == 4
    assert resource["inner_threads"] == 1
    assert resource["gpu_selected"] is False


def test_simplex_solver_is_nonnegative_and_sum_one() -> None:
    pool, truth = _surface()
    weights, loss = _simplex_least_squares(
        np.log(pool.to_numpy(float)), truth.to_numpy(float)
    )
    assert np.all(weights >= 0.0)
    assert weights.sum() == pytest.approx(1.0, abs=1e-12)
    assert np.isfinite(loss)


def test_static_transforms_are_exact() -> None:
    pool, truth = _surface()
    predictions, _ = build_iteration2_predictions(pool, truth)
    first = predictions.loc[
        predictions[list(pool.index.names)].eq(list(pool.index[0])).all(axis=1)
    ].set_index("model_id")["prediction"]
    values = pool.iloc[0]
    assert first[CANDIDATE_IDS[0]] == pytest.approx(
        np.median(values.loc[list(POOL_MODELS[:3])].to_numpy(float))
    )
    assert first[CANDIDATE_IDS[1]] == pytest.approx(
        np.exp(np.log(values.loc[list(POOL_MODELS[:2])].to_numpy(float)).mean())
    )
    assert first[CANDIDATE_IDS[2]] == pytest.approx(
        np.exp(np.log(values.loc[list(POOL_MODELS[:3])].to_numpy(float)).mean())
    )


def test_logo_heldout_truth_intervention_cannot_change_heldout_prediction() -> None:
    pool, truth = _surface()
    base_predictions, base_weights = build_iteration2_predictions(pool, truth)
    intervened = truth.copy()
    intervened.loc[intervened.index.get_level_values("dgp") == "A"] += 100.0
    changed_predictions, changed_weights = build_iteration2_predictions(pool, intervened)
    def selector(frame: pd.DataFrame) -> np.ndarray:
        return frame.loc[
            (frame["dgp"] == "A") & (frame["model_id"] == CANDIDATE_IDS[3]),
            "prediction",
        ].to_numpy(float)

    np.testing.assert_array_equal(selector(base_predictions), selector(changed_predictions))
    base_a = base_weights.loc[base_weights["heldout_dgp"] == "A", "weight"].to_numpy()
    changed_a = changed_weights.loc[
        changed_weights["heldout_dgp"] == "A", "weight"
    ].to_numpy()
    np.testing.assert_array_equal(base_a, changed_a)
