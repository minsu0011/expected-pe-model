from __future__ import annotations

from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import (
    ContractError,
    FeatureMetadata,
    FitContext,
    HistoricalGeometricMeanPE,
    ModelMetadata,
    PEModel,
    PredictContext,
    validate_feature_frame,
)


def _fit_context(features: tuple[FeatureMetadata, ...] = ()) -> FitContext:
    return FitContext(
        experiment_id="unit",
        fold_id="fold_000",
        seed=7,
        train_end=pd.Timestamp("2014-12-31"),
        target_name="observed_pe",
        feature_metadata=features,
    )


def _predict_context(features: tuple[FeatureMetadata, ...] = ()) -> PredictContext:
    return PredictContext(
        experiment_id="unit",
        fold_id="fold_000",
        seed=7,
        prediction_start=pd.Timestamp("2015-01-02"),
        prediction_end=pd.Timestamp("2015-01-05"),
        feature_metadata=features,
    )


def test_baseline_satisfies_typed_protocol_and_is_deterministic() -> None:
    model = HistoricalGeometricMeanPE()
    assert isinstance(model, PEModel)
    x = pd.DataFrame(index=pd.RangeIndex(3))
    fitted = model.fit(x, pd.Series([10.0, 40.0, np.nan]), context=_fit_context())
    assert fitted is model
    prediction = model.predict(x, context=_predict_context())
    assert prediction.tolist() == pytest.approx([20.0, 20.0, 20.0])
    assert model.metadata().deterministic is True
    assert model.metadata().training_target == "observed_pe"


def test_baseline_requires_fit_and_positive_finite_target() -> None:
    model = HistoricalGeometricMeanPE()
    x = pd.DataFrame(index=pd.RangeIndex(2))
    with pytest.raises(RuntimeError, match="fitted"):
        model.predict(x, context=_predict_context())
    with pytest.raises(ContractError, match="positive finite"):
        model.fit(x, pd.Series([0.0, np.nan]), context=_fit_context())
    with pytest.raises(ContractError, match="index"):
        model.fit(
            x,
            pd.Series([10.0, 11.0], index=pd.RangeIndex(1, 3)),
            context=_fit_context(),
        )


def test_true_fair_cannot_be_training_target_or_model_input() -> None:
    with pytest.raises(ContractError, match="evaluation-only"):
        ModelMetadata(
            model_id="bad",
            model_version="1",
            family="test",
            feature_ids=(),
            training_target="true_fair_pe",
            prediction_name="expected_pe",
            output_semantics="bad",
            deterministic=True,
        )
    with pytest.raises(ContractError, match="true_fair_pe"):
        validate_feature_frame(pd.DataFrame({"true_fair_pe": [10.0]}), (), phase="fit")
    with pytest.raises(ContractError, match="FitContext"):
        _fit_context().__class__(
            experiment_id="unit",
            fold_id="fold_000",
            seed=7,
            train_end=pd.Timestamp("2014-12-31"),
            target_name="true_fair_pe",
            feature_metadata=(),
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"lookahead_sessions": 1, "allowed_for_fit": True}, "unsafe feature"),
        ({"uses_revised_data": True, "allowed_for_predict": True}, "unsafe feature"),
        ({"point_in_time_safe": False, "allowed_for_fit": True}, "unsafe feature"),
        ({"evaluation_only": True}, "unsafe feature"),
    ],
)
def test_feature_metadata_fails_closed(
    observed_feature: FeatureMetadata,
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        replace(observed_feature, **changes)


@pytest.mark.parametrize("control_column", ["seed", "fold_id", "model_id"])
def test_feature_metadata_rejects_experiment_control_columns(
    observed_feature: FeatureMetadata,
    control_column: str,
) -> None:
    with pytest.raises(ContractError, match="experiment control"):
        replace(
            observed_feature,
            feature_id=f"bad_{control_column}",
            column_name=control_column,
        )


def test_true_fair_feature_requires_explicit_evaluation_contract(
    observed_feature: FeatureMetadata,
) -> None:
    truth = replace(
        observed_feature,
        feature_id="true_fair_pe",
        column_name="true_fair_pe",
        availability="evaluation_only",
        evaluation_only=True,
        allowed_for_fit=False,
        allowed_for_predict=False,
        point_in_time_safe=False,
    )
    assert truth.evaluation_only is True
    with pytest.raises(ContractError, match="explicitly evaluation-only"):
        replace(truth, availability="point_in_time", evaluation_only=False)


def test_feature_frame_requires_exact_declared_columns(
    observed_feature: FeatureMetadata,
) -> None:
    validate_feature_frame(pd.DataFrame({"observed_pe": [10.0]}), [observed_feature], phase="fit")
    with pytest.raises(ContractError, match="missing"):
        validate_feature_frame(pd.DataFrame(index=[0]), [observed_feature], phase="fit")
    with pytest.raises(ContractError, match="undeclared"):
        validate_feature_frame(
            pd.DataFrame({"observed_pe": [10.0], "extra": [1.0]}),
            [observed_feature],
            phase="predict",
        )


@pytest.mark.parametrize("identity_column", ["date", "symbol", "entity_id"])
def test_numeric_feature_frame_rejects_default_identity_columns(
    observed_feature: FeatureMetadata,
    identity_column: str,
) -> None:
    identity_feature = replace(
        observed_feature,
        feature_id=f"identity_{identity_column}",
        column_name=identity_column,
    )
    with pytest.raises(ContractError, match="identity columns"):
        validate_feature_frame(
            pd.DataFrame({identity_column: [1.0]}),
            [identity_feature],
            phase="predict",
        )


def test_runtime_types_are_validated(observed_feature: FeatureMetadata) -> None:
    with pytest.raises(ContractError, match="integer"):
        replace(observed_feature, availability_lag_sessions=0.5)
    with pytest.raises(ContractError, match="booleans"):
        replace(observed_feature, point_in_time_safe="true")
    with pytest.raises(ContractError, match="boolean"):
        replace(HistoricalGeometricMeanPE().metadata(), deterministic=1)
