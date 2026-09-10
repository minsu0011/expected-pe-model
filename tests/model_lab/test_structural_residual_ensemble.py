from __future__ import annotations

import copy
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.structural.authorization import (
    EXPECTED_PAIR,
    StructuralExecutionAuthorization,
)
from pe_regime_v04.model_lab.structural.authorization_v6 import (
    load_structural_execution_authorization_v6,
)
from pe_regime_v04.model_lab.structural.contracts import (
    FULL_META_IDENTITY_COLUMNS,
    StructuralContractError,
)
from pe_regime_v04.model_lab.structural.ensemble import (
    PAIR_IDENTITY_COLUMNS,
    BoundEnsembleBase,
    SimplexLogWeightFit,
    apply_two_base_simplex_log_weights,
    equal_geometric_blend,
    fit_two_base_simplex_log_weights,
)
from pe_regime_v04.model_lab.structural.meta import execute_nested_oof_plan_score_free
from pe_regime_v04.model_lab.structural.nested import build_nested_oof_plan
from pe_regime_v04.model_lab.structural.residuals import (
    BoundBaseFeatureContract,
    fit_residual_ar1_kernel,
    fit_residual_huber_kernel,
    predict_residual_ar1_kernel,
    predict_residual_huber_kernel,
)


ROOT = Path(__file__).resolve().parents[2]
V6_REVOKED_AUTHORITY_POLICY_SHA256 = (
    "63e82420c08249261f3c9d635b7f74d35f382c59ec561cdb0750aecd84a9baea"
)


def _authorization() -> StructuralExecutionAuthorization:
    return load_structural_execution_authorization_v6(
        ROOT,
        external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
        scope="SYNTHETIC_NO_SCORE",
    )


def _identity() -> tuple[pd.DataFrame, pd.DataFrame, pd.Timestamp]:
    dates = pd.date_range("2018-01-01", periods=525, freq="B")
    train = pd.DataFrame({"date": dates[:504], "session_position": np.arange(504)})
    test = pd.DataFrame({"date": dates[504:], "session_position": np.arange(504, 525)})
    return train, test, dates[503]


def _artifacts(
    authorization: StructuralExecutionAuthorization, candidate_id: str, base_model_id: str
):
    train, test, cutoff = _identity()
    plan = build_nested_oof_plan(
        train,
        test,
        seed=6301,
        outer_fold_id="outer_012",
        outer_cutoff=cutoff,
        candidate_id=candidate_id,
        base_model_id=base_model_id,
        authorization=authorization,
    )
    return (
        execute_nested_oof_plan_score_free(plan, authorization, role="INNER_OOS_FIT"),
        execute_nested_oof_plan_score_free(plan, authorization, role="OUTER_TEST_PREDICT"),
    )


def test_residual_ar1_accepts_only_exact_authorized_v04_nested_oof() -> None:
    authorization = _authorization()
    inner, outer = _artifacts(authorization, "residual_ar1_nested_oof", "v04_expected_pe")
    meta = inner.to_frame()
    base_prediction = meta["base_prediction"].to_numpy(dtype=np.float64)
    residual = np.empty(len(meta), dtype=np.float64)
    residual[0] = 0.1
    for index in range(1, len(residual)):
        residual[index] = 0.8 * residual[index - 1] + 0.001
    labels = meta.loc[:, list(FULL_META_IDENTITY_COLUMNS)].copy()
    labels["observed_pe"] = base_prediction * np.exp(residual)
    fit = fit_residual_ar1_kernel(inner, labels, authorization=authorization)
    assert fit.base_model_id == "v04_expected_pe"
    assert fit.ar1.consecutive_pair_count == 251
    output = predict_residual_ar1_kernel(fit, outer, authorization=authorization)
    np.testing.assert_allclose(
        output["correction"],
        np.clip(fit.ar1.forecast(21), -np.log(1.5), np.log(1.5)),
        rtol=0.0,
        atol=0.0,
    )
    with pytest.raises(StructuralContractError, match="generic residual"):
        BoundBaseFeatureContract(base_model_id="substituted")
    train, test, cutoff = _identity()
    with pytest.raises(StructuralContractError, match="exactly v04"):
        build_nested_oof_plan(
            train,
            test,
            seed=6301,
            outer_fold_id="outer_012",
            outer_cutoff=cutoff,
            candidate_id="residual_ar1_nested_oof",
            base_model_id="substituted_base",
            authorization=authorization,
        )
    with pytest.raises(TypeError):
        fit_residual_ar1_kernel(inner, labels)  # type: ignore[call-arg]


def test_disabled_huber_is_uncallable_for_fit_and_predict() -> None:
    authorization = _authorization()
    with pytest.raises(StructuralContractError, match="disabled Huber"):
        fit_residual_huber_kernel(authorization=authorization)
    with pytest.raises(StructuralContractError, match="disabled Huber"):
        predict_residual_huber_kernel(authorization=authorization)


def test_equal_and_simplex_use_only_exact_ordered_authorized_pair() -> None:
    authorization = _authorization()
    equal_inner0, equal_outer0 = _artifacts(
        authorization, "stack_geometric_equal_pair", EXPECTED_PAIR[0]
    )
    equal_inner1, equal_outer1 = _artifacts(
        authorization, "stack_geometric_equal_pair", EXPECTED_PAIR[1]
    )
    equal = equal_geometric_blend(equal_outer0, equal_outer1, authorization=authorization)
    p0 = equal_outer0.to_frame()["base_prediction"].to_numpy()
    p1 = equal_outer1.to_frame()["base_prediction"].to_numpy()
    np.testing.assert_allclose(equal["expected_pe"], np.sqrt(p0 * p1))
    with pytest.raises(StructuralContractError, match="generic ensemble"):
        BoundEnsembleBase(model_id="not_xgboost")
    with pytest.raises(StructuralContractError):
        equal_geometric_blend(equal_outer1, equal_outer0, authorization=authorization)

    inner0, outer0 = _artifacts(authorization, "stack_simplex_pair_frozen", EXPECTED_PAIR[0])
    inner1, outer1 = _artifacts(authorization, "stack_simplex_pair_frozen", EXPECTED_PAIR[1])
    train0 = inner0.to_frame()
    train1 = inner1.to_frame()
    labels = train0.loc[:, list(PAIR_IDENTITY_COLUMNS)].copy()
    labels["observed_pe"] = np.exp(
        0.3 * np.log(train0["base_prediction"].to_numpy())
        + 0.7 * np.log(train1["base_prediction"].to_numpy())
    )
    fit = fit_two_base_simplex_log_weights(inner0, inner1, labels, authorization=authorization)
    assert fit.weight0 == pytest.approx(0.3, abs=1e-13)
    assert fit.weight1 == pytest.approx(0.7, abs=1e-13)
    restored = SimplexLogWeightFit.from_sealed_payload(
        fit.to_sealed_payload(), authorization=authorization
    )
    assert restored.weight_sha256 == fit.weight_sha256
    output = apply_two_base_simplex_log_weights(fit, outer0, outer1, authorization=authorization)
    outer_p0 = outer0.to_frame()["base_prediction"].to_numpy()
    outer_p1 = outer1.to_frame()["base_prediction"].to_numpy()
    np.testing.assert_allclose(
        output["expected_pe"],
        np.exp(0.3 * np.log(outer_p0) + 0.7 * np.log(outer_p1)),
    )
    tampered = copy.deepcopy(fit.to_sealed_payload())
    tampered["weight0"] = 0.9
    with pytest.raises(StructuralContractError):
        SimplexLogWeightFit.from_sealed_payload(tampered, authorization=authorization)


def test_candidate_role_substitution_is_rejected_even_for_same_selected_pair() -> None:
    authorization = _authorization()
    _, equal0 = _artifacts(authorization, "stack_geometric_equal_pair", EXPECTED_PAIR[0])
    _, equal1 = _artifacts(authorization, "stack_geometric_equal_pair", EXPECTED_PAIR[1])
    with pytest.raises(StructuralContractError, match="role/candidate"):
        fit_two_base_simplex_log_weights(
            equal0,
            equal1,
            pd.DataFrame(),
            authorization=authorization,
        )
