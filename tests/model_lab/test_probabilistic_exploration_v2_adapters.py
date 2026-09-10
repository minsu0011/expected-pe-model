from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.probabilistic_exploration_v2.adapters import (
    CANDIDATE_IDS,
    make_adapter,
)
from research.model_zoo.probabilistic_exploration_v2.contracts import (
    ExplorationContractError,
)
from research.model_zoo.probabilistic_exploration_v2.design import (
    FEATURE_COLUMNS,
    LOCKED_CANDIDATES,
    QUANTILE_COLUMNS,
)


def _training_data(rows: int = 320) -> tuple[pd.DataFrame, pd.Series]:
    rng = np.random.default_rng(20260820)
    matrix = rng.normal(size=(rows, len(FEATURE_COLUMNS)))
    matrix[::17, 3] = np.nan
    frame = pd.DataFrame(matrix, columns=FEATURE_COLUMNS)
    signal = np.nan_to_num(matrix[:, 0]) * 0.08 - np.nan_to_num(matrix[:, 4]) * 0.03
    target = pd.Series(np.exp(3.0 + signal + rng.normal(scale=0.05, size=rows)), name="observed_pe")
    return frame, target


def test_candidate_table_is_structurally_diverse_and_score_blind() -> None:
    assert tuple(LOCKED_CANDIDATES) == CANDIDATE_IDS
    assert len({item["family"] for item in LOCKED_CANDIDATES.values()}) == len(CANDIDATE_IDS)
    assert all(item["target"] == "log(observed_pe)" for item in LOCKED_CANDIDATES.values())


@pytest.mark.parametrize("model_id", CANDIDATE_IDS)
def test_locked_adapter_synthetic_fit_predict(model_id: str) -> None:
    x, y = _training_data()
    adapter = make_adapter(model_id)
    adapter.fit(x, y, seed=6301, fold_id="fold_synthetic")
    prediction = adapter.predict(
        x.iloc[-11:].reset_index(drop=True), seed=6301, fold_id="fold_synthetic"
    )
    assert len(prediction) == 11
    quantiles = prediction.loc[:, list(QUANTILE_COLUMNS)].to_numpy(float)
    assert np.isfinite(quantiles).all()
    assert (quantiles > 0.0).all()
    assert (np.diff(quantiles, axis=1) >= 0.0).all()
    np.testing.assert_array_equal(prediction["expected_pe"], prediction["predicted_pe_p50"])
    assert adapter.crossing_diagnostics is not None
    assert adapter.crossing_diagnostics["post_repair_crossing_rows"] == 0
    with pytest.raises(ExplorationContractError, match="retry"):
        adapter.fit(x, y, seed=6301, fold_id="fold_synthetic")


def test_adapter_rejects_same_row_target_feature() -> None:
    x, y = _training_data()
    x["observed_pe"] = y
    adapter = make_adapter(CANDIDATE_IDS[0])
    with pytest.raises(ExplorationContractError, match="forbidden target|columns/order"):
        adapter.fit(x, y, seed=6301, fold_id="fold_synthetic")


def test_conformal_adapter_requires_chronological_calibration_mass() -> None:
    x, y = _training_data(rows=250)
    adapter = make_adapter("conformal_lgbm_residual_with_regime_exploration_v1")
    with pytest.raises(ExplorationContractError, match="calibration rows insufficient"):
        adapter.fit(x, y, seed=6301, fold_id="fold_synthetic")
