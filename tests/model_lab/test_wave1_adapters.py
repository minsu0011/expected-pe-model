from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import FitContext, PredictContext
from pe_regime_v04.model_lab.models.wave1.adapters import (
    Wave1StateSpaceAdapter,
    build_wave1_model,
    training_sample_weight,
)
from pe_regime_v04.model_lab.models.wave1.spec import MODEL_BY_ID, feature_metadata

from test_wave1_support import synthetic_model_and_baselines


def _contexts(model_id: str, seed: int, rows: int) -> tuple[FitContext, PredictContext]:
    definition = MODEL_BY_ID[model_id]
    metadata = feature_metadata(tuple(definition.feature_columns))
    dates = pd.date_range("2000-01-03", periods=rows + 2, freq="B")
    return (
        FitContext(
            experiment_id="wave1-test",
            fold_id="fold_000",
            seed=seed,
            train_end=dates[rows - 1],
            target_name="observed_pe",
            feature_metadata=metadata,
        ),
        PredictContext(
            experiment_id="wave1-test",
            fold_id="fold_000",
            seed=seed,
            prediction_start=dates[rows],
            prediction_end=dates[rows + 1],
            feature_metadata=metadata,
        ),
    )


def test_locked_training_sample_weight_handles_nonfinite_without_imputation() -> None:
    frame = pd.DataFrame({"eps_confidence": [np.nan, np.inf, -np.inf, 0.0, 75.0, 200.0]})
    assert training_sample_weight(frame).tolist() == [0.5, 0.5, 0.5, 0.05, 0.75, 1.0]


def test_supervised_adapter_keeps_all_feature_missing_rows_for_fold_imputation() -> None:
    model_frame, _ = synthetic_model_and_baselines(260)
    model_id = "ridge_svd_common"
    definition = MODEL_BY_ID[model_id]
    x = model_frame.loc[:, list(definition.feature_columns)].copy()
    x.loc[0, :] = np.nan
    x["eps_disagreement"] = np.nan
    target = model_frame["observed_pe"].copy()
    fit_context, predict_context = _contexts(model_id, 6553, len(x))
    model = build_wave1_model(model_id, fold_seed=6553)
    model.fit(x, target, context=fit_context)
    prediction = model.predict(x.iloc[:2], context=predict_context)
    diagnostics = model.diagnostics()
    assert np.isfinite(prediction).all()
    assert "eps_disagreement" in diagnostics.dropped_all_missing_features
    assert len(diagnostics.active_features) == len(definition.feature_columns) - 1


def test_state_space_exact_constructor_lbfgs_and_fixed_origin_forecast() -> None:
    model_frame, _ = synthetic_model_and_baselines(260)
    model_id = "state_space_local_linear_trend_target_history_only"
    fit_context, predict_context = _contexts(model_id, 6553, 258)
    model = build_wave1_model(model_id, fold_seed=6553)
    assert isinstance(model, Wave1StateSpaceAdapter)
    with pytest.warns(
        Warning,
        match="Value of `irregular` may be overridden",
    ):
        model.fit(
            pd.DataFrame(index=model_frame.index[:258]),
            model_frame["observed_pe"].iloc[:258],
            context=fit_context,
        )
    prediction = model.predict(pd.DataFrame(index=range(2)), context=predict_context)
    assert len(prediction) == 2
    assert np.isfinite(prediction).all()
    resolved = model.diagnostics().resolved_parameters
    assert resolved["fit"] == {"method": "lbfgs", "maxiter": 100, "disp": False}
    assert resolved["model_flags"] == {
        "irregular": True,
        "level": True,
        "trend": True,
        "stochastic_level": True,
        "stochastic_trend": True,
    }


def test_every_locked_model_factory_is_cpu_and_has_exact_feature_order() -> None:
    for model_id, definition in MODEL_BY_ID.items():
        model = build_wave1_model(model_id, fold_seed=6553)
        assert model.metadata().model_id == model_id
        assert model.metadata().feature_ids == definition.feature_columns
        assert model.metadata().training_target == "observed_pe"
        assert model.metadata().deterministic is True
