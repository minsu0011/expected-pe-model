from __future__ import annotations

import inspect
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.structural.contracts import (
    KernelBinding,
    StructuralContractError,
)
from pe_regime_v04.model_lab.structural.authorization import (
    StructuralExecutionAuthorization,
)
from pe_regime_v04.model_lab.structural.authorization_v6 import (
    load_structural_execution_authorization_v6,
)
from pe_regime_v04.model_lab.structural.decomposition import (
    DecompositionFit,
    fit_decomposition_kernel,
    predict_decomposition_kernel,
)
from pe_regime_v04.model_lab.structural.derived_registry import (
    track_a_derived_feature_definitions,
)
from pe_regime_v04.model_lab.structural.features import (
    MARKET_CURRENT,
    REGIME_CURRENT,
    REQUIRED_UPSTREAM_AUDITS,
    TRACK_A_LAGGED_COLUMNS,
    TRACK_C_FEATURE_COLUMNS,
    TrackASourceAuditBinding,
    audit_track_a_lag_transform,
    build_track_a_lag1_artifact,
    lag1_feature_name,
    verify_track_a_lag1_artifact,
)


ROOT = Path(__file__).resolve().parents[2]
V6_REVOKED_AUTHORITY_POLICY_SHA256 = (
    "63e82420c08249261f3c9d635b7f74d35f382c59ec561cdb0750aecd84a9baea"
)


def _audit_binding() -> TrackASourceAuditBinding:
    return TrackASourceAuditBinding(
        audit_sha256="a" * 64,
        passed_audits=REQUIRED_UPSTREAM_AUDITS,
    )


def _lag_source() -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for seed, entity, offset in ((1, "A", 0.0), (2, "B", 1000.0)):
        for position, date in enumerate(pd.date_range("2020-01-01", periods=5, freq="B")):
            row: dict[str, object] = {
                "seed": seed,
                "entity_id": entity,
                "date": date,
                "observed_pe": 10.0 + position,
            }
            for column_index, column in enumerate((*MARKET_CURRENT, *REGIME_CURRENT)):
                row[column] = offset + position * 10.0 + column_index
            rows.append(row)
    return pd.DataFrame(rows).sample(frac=1.0, random_state=7).reset_index(drop=True)


def test_track_a_groupwise_lag_never_crosses_seed_entity_and_passes_interventions() -> None:
    source = _lag_source()
    artifact = build_track_a_lag1_artifact(source, source_audit=_audit_binding())
    verify_track_a_lag1_artifact(source, artifact, source_audit=_audit_binding())
    frame = artifact.to_frame()
    assert tuple(frame.columns) == ("seed", "entity_id", "date", *TRACK_A_LAGGED_COLUMNS)
    for _, group in frame.groupby(["seed", "entity_id"], sort=False):
        assert group.iloc[0][list(TRACK_A_LAGGED_COLUMNS)].isna().all()
    source_sorted = source.sort_values(["seed", "entity_id", "date"], kind="mergesort")
    first_source = source_sorted.query("seed == 2").iloc[0][MARKET_CURRENT[0]]
    second_lag = frame.query("seed == 2").iloc[1][lag1_feature_name(MARKET_CURRENT[0])]
    assert second_lag == first_source
    audit = audit_track_a_lag_transform(source, source_audit=_audit_binding())
    assert audit.passed
    definitions = track_a_derived_feature_definitions()
    assert len(definitions) == 27
    assert {item.column_name for item in definitions} == set(TRACK_A_LAGGED_COLUMNS)
    assert all(item.availability_lag_sessions == 1 for item in definitions)
    assert all(item.uses_same_row_price is False for item in definitions)


def test_track_a_rejects_evaluation_truth_and_bad_upstream_audit() -> None:
    source = _lag_source()
    source["true_fair_pe"] = 10.0
    with pytest.raises(StructuralContractError, match="true_fair_pe"):
        build_track_a_lag1_artifact(source, source_audit=_audit_binding())
    with pytest.raises(StructuralContractError, match="six frozen"):
        TrackASourceAuditBinding(audit_sha256="a" * 64, passed_audits=("prefix_invariance",))


def _track_c_frame(rows: int) -> pd.DataFrame:
    position = np.arange(rows, dtype=np.float64)
    data: dict[str, np.ndarray] = {}
    for index, column in enumerate(TRACK_C_FEATURE_COLUMNS):
        data[column] = np.sin(position / (7.0 + index)) + index / 20.0
    data["eps_confidence"] = 50.0 + 40.0 * np.sin(position / 11.0)
    return pd.DataFrame(data).loc[:, list(TRACK_C_FEATURE_COLUMNS)]


def _authorization() -> StructuralExecutionAuthorization:
    return load_structural_execution_authorization_v6(
        ROOT,
        external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
        scope="SYNTHETIC_NO_SCORE",
    )


def _binding(
    authorization: StructuralExecutionAuthorization,
    candidate_id: str,
) -> KernelBinding:
    return KernelBinding.from_authorization(
        authorization,
        candidate_id=candidate_id,
        fold_sha256="4" * 64,
    )


def test_decomposition_locked_ridge_components_and_fixed_origin_ar1() -> None:
    authorization = _authorization()
    candidate_id = "decomp_block_ridge_ar1_current"
    rows = 90
    train = _track_c_frame(rows)
    dates = pd.date_range("2021-01-01", periods=rows, freq="B")
    latent = 2.5 + 0.08 * train[TRACK_C_FEATURE_COLUMNS[0]].to_numpy()
    residual = np.zeros(rows, dtype=np.float64)
    residual[0] = 0.02
    for index in range(1, rows):
        residual[index] = 0.7 * residual[index - 1] + 0.001 * np.sin(index)
    observed = np.exp(latent + residual)
    fit = fit_decomposition_kernel(
        train,
        observed,
        dates,
        candidate_id=candidate_id,
        track="C",
        binding=_binding(authorization, candidate_id),
        authorization=authorization,
    )
    assert fit.ridge_alpha == 10.0
    assert fit.ridge_solver == "svd"
    assert fit.ridge_fit_intercept is True
    assert fit.ar1.consecutive_pair_count == rows - 1
    assert -0.95 <= fit.ar1.rho <= 0.95
    restored = DecompositionFit.from_process_payload(
        fit.to_process_payload(), authorization=authorization
    )
    assert restored == fit
    assert restored.fit_sha256 == fit.fit_sha256

    test = _track_c_frame(5)
    test_dates = pd.date_range(dates[-1] + pd.offsets.BDay(1), periods=5, freq="B")
    prediction = predict_decomposition_kernel(fit, test, test_dates, authorization=authorization)
    np.testing.assert_allclose(
        prediction["expected_log_pe"],
        prediction[
            ["intercept", "fundamental_component", "market_component", "dynamic_residual_component"]
        ].sum(axis=1),
        rtol=0.0,
        atol=1e-14,
    )
    np.testing.assert_allclose(
        prediction["dynamic_residual_component"], fit.ar1.forecast(5), rtol=0.0, atol=0.0
    )
    assert np.isfinite(prediction["expected_pe"]).all()
    assert (prediction["expected_pe"] > 0.0).all()
    assert "observed_pe" not in inspect.signature(predict_decomposition_kernel).parameters


def test_decomposition_fails_closed_on_schema_or_time_leakage() -> None:
    authorization = _authorization()
    candidate_id = "decomp_block_ridge_ar1_current"
    train = _track_c_frame(70)
    dates = pd.date_range("2022-01-03", periods=70, freq="B")
    fit = fit_decomposition_kernel(
        train,
        np.exp(np.full(70, 2.4)),
        dates,
        candidate_id=candidate_id,
        track="C",
        binding=_binding(authorization, candidate_id),
        authorization=authorization,
    )
    bad = train.iloc[:2].copy()
    bad["true_fair_pe"] = 12.0
    with pytest.raises(StructuralContractError):
        predict_decomposition_kernel(fit, bad, dates[-2:], authorization=authorization)
    with pytest.raises(StructuralContractError, match="strictly follow"):
        predict_decomposition_kernel(
            fit, train.iloc[:2].copy(), dates[-2:], authorization=authorization
        )


def test_decomposition_binding_is_factory_only_and_candidate_track_bound() -> None:
    authorization = _authorization()
    train = _track_c_frame(70)
    dates = pd.date_range("2022-01-03", periods=70, freq="B")
    with pytest.raises(StructuralContractError, match="factory-only"):
        KernelBinding()  # type: ignore[call-arg]
    binding = _binding(authorization, "decomp_block_ridge_ar1_current")
    with pytest.raises(StructuralContractError, match="binding"):
        fit_decomposition_kernel(
            train,
            np.exp(np.full(70, 2.4)),
            dates,
            candidate_id="decomp_block_ridge_ar1_lag1",
            track="A",
            binding=binding,
            authorization=authorization,
        )
    with pytest.raises(TypeError):
        fit_decomposition_kernel(  # type: ignore[call-arg]
            train,
            np.exp(np.full(70, 2.4)),
            dates,
            candidate_id="decomp_block_ridge_ar1_current",
            track="C",
            binding=binding,
        )


def test_track_c_declares_and_uses_same_row_market_information_only_on_that_row() -> None:
    authorization = _authorization()
    candidate_id = "decomp_block_ridge_ar1_current"
    train = _track_c_frame(100)
    dates = pd.date_range("2022-01-03", periods=100, freq="B")
    market_column = "benchmark_return_21"
    observed = np.exp(2.5 + 0.4 * train[market_column].to_numpy())
    fit = fit_decomposition_kernel(
        train,
        observed,
        dates,
        candidate_id=candidate_id,
        track="C",
        binding=_binding(authorization, candidate_id),
        authorization=authorization,
    )
    test = _track_c_frame(3)
    test_dates = pd.date_range(dates[-1] + pd.offsets.BDay(1), periods=3, freq="B")
    before = predict_decomposition_kernel(fit, test, test_dates, authorization=authorization)
    intervened = test.copy()
    intervened.loc[1, market_column] += 10.0
    after = predict_decomposition_kernel(fit, intervened, test_dates, authorization=authorization)
    assert before.loc[1, "expected_pe"] != after.loc[1, "expected_pe"]
    np.testing.assert_allclose(
        before.loc[[0, 2], "expected_pe"],
        after.loc[[0, 2], "expected_pe"],
        rtol=0.0,
        atol=0.0,
    )
