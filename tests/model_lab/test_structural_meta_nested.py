from __future__ import annotations

import copy
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.structural.authorization import (
    StructuralExecutionAuthorization,
)
from pe_regime_v04.model_lab.structural.authorization_v6 import (
    load_structural_execution_authorization_v6,
)
from pe_regime_v04.model_lab.structural.contracts import (
    StructuralContractError,
    canonical_json_bytes,
    sha256_bytes,
)
from pe_regime_v04.model_lab.folds import generate_pit_folds
from pe_regime_v04.model_lab.structural.meta import (
    GeneratedMetaFeatureArtifact,
    NestedOOFArtifactCache,
    NestedOOFCacheKey,
    create_generated_meta_artifact,
    execute_nested_oof_plan_formal_spent,
    execute_nested_oof_plan_score_free,
)
from pe_regime_v04.model_lab.structural.nested import (
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_FOLD_COUNT,
    FORMAL_OUTER_FOLD_SPEC,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
    FORMAL_OUTER_STARTS,
    NestedOOFPlan,
    NestedOOFTaskPayload,
    build_nested_oof_plan,
    formal_fold_id_for_test_start,
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


def test_formal_outer_schedule_is_code_owned_complete_and_off_grid_601_rejects() -> None:
    assert len(FORMAL_OUTER_STARTS) == FORMAL_OUTER_FOLD_COUNT == 74
    assert FORMAL_OUTER_STARTS == tuple(range(252, 1800, 21))
    assert formal_fold_id_for_test_start(252) == "fold_000"
    assert formal_fold_id_for_test_start(1785) == "fold_073"
    identity = pd.DataFrame({"date": pd.date_range("2000-01-03", periods=1800, freq="B")})
    folds = generate_pit_folds(identity, FORMAL_OUTER_FOLD_SPEC, date_column="date")
    schedule = [
        {
            "fold_id": fold.fold_id,
            "train_positions": list(fold.train_positions),
            "test_positions": list(fold.test_positions),
        }
        for fold in folds
    ]
    coverage = [position for fold in folds for position in fold.test_positions]
    assert len(folds[-1].test_positions) == 15
    assert coverage == list(range(252, 1800))
    assert sha256_bytes(canonical_json_bytes(schedule)) == (FORMAL_OUTER_POSITION_SCHEDULE_SHA256)
    assert sha256_bytes(canonical_json_bytes(coverage)) == FORMAL_OUTER_COVERAGE_SHA256
    with pytest.raises(StructuralContractError, match="off the code-owned grid"):
        formal_fold_id_for_test_start(601)


def _identities() -> tuple[pd.DataFrame, pd.DataFrame, pd.Timestamp]:
    dates = pd.date_range("2018-01-01", periods=525, freq="B")
    train = pd.DataFrame({"date": dates[:504], "session_position": np.arange(504)})
    test = pd.DataFrame({"date": dates[504:], "session_position": np.arange(504, 525)})
    return train, test, dates[503]


def _plan(authorization: StructuralExecutionAuthorization) -> NestedOOFPlan:
    train, test, cutoff = _identities()
    return build_nested_oof_plan(
        train,
        test,
        seed=6301,
        outer_fold_id="outer_012",
        outer_cutoff=cutoff,
        candidate_id="residual_ar1_nested_oof",
        base_model_id="v04_expected_pe",
        authorization=authorization,
    )


def test_plan_is_factory_only_and_binds_both_outer_surfaces_and_every_task() -> None:
    authorization = _authorization()
    with pytest.raises(StructuralContractError, match="factory-only"):
        NestedOOFPlan()  # type: ignore[call-arg]
    with pytest.raises(StructuralContractError, match="factory-only"):
        NestedOOFTaskPayload()  # type: ignore[call-arg]
    plan = _plan(authorization)
    plan.verify(authorization)
    assert plan.meta_row_count == 252
    assert plan.eligible_for_formal_meta_fit
    assert len(plan.tasks) == 12
    assert plan.meta_session_positions == tuple(range(252, 504))
    assert plan.outer_task.test_positions == tuple(range(504, 525))
    assert plan.outer_task.train_end_iso == plan.outer_cutoff_iso
    assert all(max(task.train_positions) < min(task.test_positions) for task in plan.tasks)
    assert len({task.task_sha256 for task in plan.tasks}) == len(plan.tasks)
    assert plan.fold_sha256 != plan.task_manifest_sha256


def test_artifacts_are_plan_executed_role_bound_and_prediction_byte_bound() -> None:
    authorization = _authorization()
    plan = _plan(authorization)
    with pytest.raises(StructuralContractError, match="factory-only"):
        GeneratedMetaFeatureArtifact()  # type: ignore[call-arg]
    inner = execute_nested_oof_plan_score_free(plan, authorization, role="INNER_OOS_FIT")
    outer = execute_nested_oof_plan_score_free(plan, authorization, role="OUTER_TEST_PREDICT")
    assert inner.fold_sha256 == plan.fold_sha256 == outer.fold_sha256
    assert inner.row_count == 252 and outer.row_count == 21
    assert len(inner.task_receipts) == 12 and len(outer.task_receipts) == 1
    assert inner.prediction_bytes_sha256 != outer.prediction_bytes_sha256
    inner.verify(
        authorization,
        expected_role="INNER_OOS_FIT",
        expected_candidate_id="residual_ar1_nested_oof",
    )
    with pytest.raises(StructuralContractError, match="role/candidate"):
        inner.verify(
            authorization,
            expected_role="OUTER_TEST_PREDICT",
            expected_candidate_id="residual_ar1_nested_oof",
        )
    with pytest.raises(StructuralContractError, match="caller-minted"):
        create_generated_meta_artifact(inner.to_frame())


def test_adversarial_fake_fold_in_sample_outer_target_and_prediction_tamper_rejected() -> None:
    authorization = _authorization()
    plan = _plan(authorization)
    artifact = execute_nested_oof_plan_score_free(plan, authorization, role="INNER_OOS_FIT")

    fake_plan = copy.deepcopy(plan)
    object.__setattr__(fake_plan, "outer_cutoff_iso", "2099-01-01T00:00:00")
    with pytest.raises(StructuralContractError):
        fake_plan.verify(authorization)

    fake_task_plan = copy.deepcopy(plan)
    fake_task = copy.deepcopy(fake_task_plan.tasks[0])
    object.__setattr__(fake_task, "train_end_iso", fake_task.test_start_iso)
    object.__setattr__(fake_task_plan, "tasks", (fake_task, *fake_task_plan.tasks[1:]))
    with pytest.raises(StructuralContractError):
        fake_task_plan.verify(authorization)

    fake_artifact = copy.deepcopy(artifact)
    tampered_csv = fake_artifact.csv_text.replace(",8.", ",18.", 1)
    object.__setattr__(fake_artifact, "csv_text", tampered_csv)
    with pytest.raises(StructuralContractError):
        fake_artifact.verify(
            authorization,
            expected_role="INNER_OOS_FIT",
            expected_candidate_id="residual_ar1_nested_oof",
        )

    fake_role = copy.deepcopy(artifact)
    object.__setattr__(fake_role, "role", "OUTER_TEST_PREDICT")
    with pytest.raises(StructuralContractError):
        fake_role.verify(
            authorization,
            expected_role="OUTER_TEST_PREDICT",
            expected_candidate_id="residual_ar1_nested_oof",
        )


def test_cache_requires_original_plan_authorization_and_replays_before_return(tmp_path) -> None:
    authorization = _authorization()
    plan = _plan(authorization)
    inner = execute_nested_oof_plan_score_free(plan, authorization, role="INNER_OOS_FIT")
    key = NestedOOFCacheKey.from_plan(plan, authorization)
    assert len(key.key_sha256) == 64
    cache = NestedOOFArtifactCache(tmp_path / "cache")
    path = cache.put(plan, authorization, inner)
    assert path.is_file()
    assert cache.get(plan, authorization).artifact_sha256 == inner.artifact_sha256
    with pytest.raises(FileExistsError):
        cache.put(plan, authorization, inner)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["artifact"]["csv_text"] = payload["artifact"]["csv_text"].replace(",8.", ",19.", 1)
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(StructuralContractError):
        cache.get(plan, authorization)


def test_formal_executor_and_authority_fail_closed_after_revocation() -> None:
    with pytest.raises(StructuralContractError, match="blocked pending independent audit GO"):
        load_structural_execution_authorization_v6(
            ROOT,
            external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
            scope="FORMAL_SPENT",
        )
    authorization = _authorization()
    plan = _plan(authorization)
    with pytest.raises(StructuralContractError, match="repeat independent audit GO"):
        execute_nested_oof_plan_formal_spent(
            plan,
            authorization,
            role="INNER_OOS_FIT",
        )
