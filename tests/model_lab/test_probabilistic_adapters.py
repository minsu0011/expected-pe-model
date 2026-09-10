from __future__ import annotations

import importlib.util

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.contracts import FitContext, PredictContext
from pe_regime_v04.model_lab.probabilistic.adapters import (
    AdapterExecutionError,
    AdapterUnavailable,
    NGBoostNormalAdapter,
    QuantileHistGBAdapter,
    QuantileLinearAdapter,
    adapter_binding_payload,
    adapter_binding_sha256_by_id,
    create_adapter,
)
from pe_regime_v04.model_lab.probabilistic.contracts import ProbabilisticContractError
from pe_regime_v04.model_lab.probabilistic.spec import FEATURE_COLUMNS, feature_metadata


def _data(rows: int = 72) -> tuple[pd.DataFrame, pd.Series]:
    rng = np.random.default_rng(314159)
    values = rng.normal(size=(rows, len(FEATURE_COLUMNS)))
    values[3, 5] = np.nan
    frame = pd.DataFrame(values, columns=FEATURE_COLUMNS)
    log_target = 2.5 + 0.35 * np.nan_to_num(values[:, 0]) + rng.normal(0.0, 0.08, rows)
    return frame, pd.Series(np.exp(log_target), name="observed_pe")


def _contexts(seed: int = 11):
    features = feature_metadata()
    fit = FitContext(
        experiment_id="synthetic-score-free",
        fold_id="fold_000",
        seed=seed,
        train_end=pd.Timestamp("2020-03-31"),
        target_name="observed_pe",
        feature_metadata=features,
    )
    predict = PredictContext(
        experiment_id="synthetic-score-free",
        fold_id="fold_000",
        seed=seed,
        prediction_start=pd.Timestamp("2020-04-01"),
        prediction_end=pd.Timestamp("2020-04-21"),
        feature_metadata=features,
    )
    return fit, predict


@pytest.mark.parametrize("adapter_type", [QuantileLinearAdapter, QuantileHistGBAdapter])
def test_three_candidate_contract_quantile_adapters_fit_predict(adapter_type) -> None:
    x, y = _data()
    fit, predict = _contexts()
    adapter = adapter_type().fit(x.iloc[:60], y.iloc[:60], context=fit)
    batch = adapter.predict(x.iloc[60:], context=predict)
    assert batch.pe_quantiles.shape == (12, 5)
    assert np.all(np.diff(batch.pe_quantiles, axis=1) >= 0.0)
    assert np.array_equal(batch.output_frame()["expected_pe"], batch.pe_quantiles[:, 2])


def test_ngboost_candidate_real_or_controlled_unavailable() -> None:
    x, y = _data(52)
    fit, predict = _contexts()
    adapter = NGBoostNormalAdapter()
    if importlib.util.find_spec("ngboost") is None:
        with pytest.raises(AdapterUnavailable):
            adapter.fit(x.iloc[:40], y.iloc[:40], context=fit)
        return
    adapter.fit(x.iloc[:40], y.iloc[:40], context=fit)
    batch = adapter.predict(x.iloc[40:], context=predict)
    assert batch.density_parameters is not None
    assert np.all(batch.density_parameters["scale"] > 0.0)


def test_no_retry_and_failure_contract() -> None:
    x, y = _data()
    fit, _ = _contexts()
    adapter = QuantileLinearAdapter().fit(x, y, context=fit)
    with pytest.raises(AdapterExecutionError, match="retries are forbidden"):
        adapter.fit(x, y, context=fit)


def test_same_row_target_and_evaluation_truth_are_forbidden() -> None:
    x, y = _data()
    fit, _ = _contexts()
    with pytest.raises(ProbabilisticContractError, match="observed_pe"):
        QuantileLinearAdapter().fit(x.assign(observed_pe=y), y, context=fit)
    with pytest.raises(ProbabilisticContractError, match="true_fair_pe"):
        QuantileLinearAdapter().fit(x.assign(true_fair_pe=20.0), y, context=fit)


def test_chronological_predict_boundary_and_fold_identity() -> None:
    x, y = _data()
    fit, predict = _contexts()
    adapter = QuantileLinearAdapter().fit(x.iloc[:60], y.iloc[:60], context=fit)
    invalid = PredictContext(
        experiment_id=predict.experiment_id,
        fold_id=predict.fold_id,
        seed=predict.seed,
        prediction_start=fit.train_end,
        prediction_end=fit.train_end,
        feature_metadata=predict.feature_metadata,
    )
    with pytest.raises(ProbabilisticContractError, match="after training"):
        adapter.predict(x.iloc[60:], context=invalid)


def test_same_row_market_feature_perturbation_is_permitted() -> None:
    x, y = _data()
    fit, predict = _contexts()
    adapter = QuantileLinearAdapter().fit(x.iloc[:60], y.iloc[:60], context=fit)
    base = adapter.predict(x.iloc[[60]].copy(), context=predict).pe_quantiles
    changed = x.iloc[[60]].copy()
    changed.iloc[0, 0] += 10.0
    perturbed = adapter.predict(changed, context=predict).pe_quantiles
    assert not np.array_equal(base, perturbed)


def test_candidate_factory_is_closed() -> None:
    assert create_adapter("qlinear_l1_with_regime_v1").metadata().full_density is False
    with pytest.raises(ProbabilisticContractError):
        create_adapter("post_score_substitute")


def test_adapter_binding_closes_class_source_config_and_environment() -> None:
    digests = adapter_binding_sha256_by_id()
    assert set(digests) == {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }
    payload = adapter_binding_payload("qlinear_l1_with_regime_v1")
    assert payload["adapter_class"].endswith("QuantileLinearAdapter")
    assert len(payload["adapter_source_sha256"]) == 64
    assert payload["definition"]["parameters"]["solver"] == "highs"
    assert payload["required_runtime"]["distributions"]["scikit-learn"] == "1.7.2"
