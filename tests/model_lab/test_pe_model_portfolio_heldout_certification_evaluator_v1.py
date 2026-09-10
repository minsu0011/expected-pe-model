from __future__ import annotations

import ast
from datetime import date, timedelta
from dataclasses import replace
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import cast

import numpy as np
import pytest

from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
    semantic_sha256,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.evidence import (
    build_freeze_receipt,
    build_go_audit,
    build_go_seal,
    build_prediction_manifest,
    build_source_manifest,
    go_checks,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
    HeldoutAuthorityError,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.audit import (
    validate_prediction_freeze,
)

from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.canonical import (
    HeldoutEvaluatorError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.constants import (
    BOOTSTRAP_DRAWS,
    BOOTSTRAP_RNG_SEED,
    C1_ID,
    CHAMPION_ID,
    CONSUMPTION_MARKER_LEAF,
    DGP_IDS,
    FORMULA_LOCK_SEMANTIC_SHA256,
    FOLD_IDS,
    GENERATION_PLAN_SEMANTIC_SHA256,
    HELDOUT_GATE,
    HELDOUT_SEEDS,
    IDENTITY_COUNT,
    MODEL_IDS,
    POLICY_RAW_SHA256,
    PREDICTION_AUDIT_CHECK_FIELDS,
    PREDICTION_CHECKSUM_LEDGER_LEAVES,
    QUALIFICATION_RESULT_SCHEMA,
    QUALIFICATION_RESULT_STATUS,
    RESULT_LEAF,
    SEED_ALIASES,
    SOURCE_MODEL_VERSIONS,
    SURVIVOR_IDS,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.contracts import (
    Activation,
    ArtifactRef,
    QualificationFreeze,
    _parse_qualification_result,
    _require_run_scoped_root,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.custody import (
    close_held_artifacts,
    open_held_artifacts,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1 import (
    custody as heldout_custody,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.metrics import (
    _bootstrap_from_fold_aggregates,
    classify_heldout_gate,
    evaluate_heldout,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.evaluator import (
    type7_quantile,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.prediction import (
    DecodedPredictions,
    fold_geometry,
    validate_identity,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.runner import (
    _hold_source_closure,
    _validate_activation_root_relative,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.source_lock import (
    EXPECTED_RUNTIME_VERSIONS,
    EXPECTED_SOURCE_RECORD_GROUPS,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.truth import (
    DecodedTruth,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.vault import (
    VAULT_MANIFEST_SCHEMA,
    VAULT_MANIFEST_STATUS,
    validate_vault_manifest,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.publication import (
    HeldWritableDirectory,
    claim_output_root,
    publish_atomic_create_new,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.custody import (
    _snapshot_artifact_ref_untrusted,
)


def _version(model_id: str) -> str:
    return "sha256:" + hashlib.sha256(model_id.encode("ascii")).hexdigest()


def _qualification_payload() -> dict[str, object]:
    roles = {
        C1_ID: "RESEARCH_ONLY",
        SURVIVOR_IDS[1]: "CERTIFIED_SURVIVOR",
        SURVIVOR_IDS[2]: "CERTIFIED_SURVIVOR",
        SURVIVOR_IDS[0]: "CERTIFIED_SURVIVOR",
    }
    formal = [
        {
            "formal_survivor_rank": rank,
            "candidate_id": candidate_id,
            "worst_dgp_mean_harm": 0.0,
            "dgp_mean_wins": 10,
            "pooled_mae_relative_gain": 0.01,
            "ranking_rule": [
                "worst_dgp_mean_harm_ascending",
                "dgp_mean_wins_descending",
                "pooled_mae_relative_gain_descending",
                "candidate_id_ascending",
            ],
            "rank_universe": "CERTIFIED_SURVIVOR_ONLY",
        }
        for rank, candidate_id in enumerate(SURVIVOR_IDS, start=1)
    ]
    freeze = {
        "status": "FROZEN_AFTER_QUALIFICATION_NO_POST_RESULT_TUNING",
        "certified_survivor_ids_in_rank_order": list(SURVIVOR_IDS),
        "candidate_roles": roles,
        "diagnostic_ranking": [],
        "formal_survivor_ranking": formal,
        "ranking_rule": [
            "worst_dgp_mean_harm_ascending",
            "dgp_mean_wins_descending",
            "pooled_mae_relative_gain_descending",
            "candidate_id_ascending",
        ],
        "qualification_results_mutable": False,
        "candidate_definition_mutable": False,
        "role_assignment_mutable": False,
        "heldout_authority": False,
        "heldout_open_count": 0,
    }
    scorecard = [
        {"candidate_id": candidate_id, "version": _version(candidate_id)}
        for candidate_id in (C1_ID, *SURVIVOR_IDS)
    ]
    return {
        "schema_version": QUALIFICATION_RESULT_SCHEMA,
        "status": QUALIFICATION_RESULT_STATUS,
        "run_id": "synthetic_qualification",
        "activation_raw_sha256": "1" * 64,
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "prediction_binding": {},
        "truth_custody": {
            "exact_pass_1_truth_leaf_count": 50,
            "logical_truth_row_count": 64_800,
            "truth_ref_inventory_semantic_sha256": "2" * 64,
            "latent_open_count": 0,
            "pass_2_open_count": 0,
            "heldout_open_count": 0,
        },
        "score": {
            "champion": {"candidate_id": CHAMPION_ID, "version": _version(CHAMPION_ID)},
            "scorecard": scorecard,
            "survivor_role_ranking_freeze": freeze,
        },
        "heldout_authority": False,
        "heldout_open_count": 0,
        "qualification_result_mutable": False,
        "retry_allowed": False,
        "post_result_candidate_tuning_allowed": False,
    }


def _exact_synthetic_inputs() -> tuple[DecodedPredictions, DecodedTruth, dict[str, str]]:
    identities = []
    base = date(2001, 1, 1)
    for seed_alias in SEED_ALIASES:
        for dgp_id in DGP_IDS:
            for row_index in range(1_296):
                position = 504 + row_index
                fold_id, train_end, test_start = fold_geometry(position)
                identities.append(
                    (
                        seed_alias,
                        dgp_id,
                        position,
                        (base + timedelta(days=row_index)).isoformat(),
                        "DGP_ISSUER",
                        fold_id,
                        train_end,
                        test_start,
                    )
                )
    assert len(identities) == IDENTITY_COUNT
    truth = tuple(3.0 for _ in identities)
    logs = (
        (CHAMPION_ID, tuple(3.1 for _ in identities)),
        (SURVIVOR_IDS[0], tuple(3.098 for _ in identities)),
        (SURVIVOR_IDS[1], tuple(3.097 for _ in identities)),
        (SURVIVOR_IDS[2], tuple(3.096 for _ in identities)),
    )
    versions = {model_id: _version(model_id) for model_id in MODEL_IDS}
    predictions = DecodedPredictions(tuple(identities), logs, "3" * 64)
    return predictions, DecodedTruth(truth, tuple(True for _ in truth)), versions


def _artifact(relative: str, raw: bytes, ordinal: int) -> ArtifactRef:
    return ArtifactRef(
        relative_path=relative,
        raw_sha256=sha256_bytes(raw),
        size_bytes=len(raw),
        volume_serial_number=1,
        file_id_128=f"{ordinal:032x}",
    )


def _prediction_freeze_fixture(
    *,
    omit_estimator_mapping: bool = False,
    plan_semantic: str = GENERATION_PLAN_SEMANTIC_SHA256,
    alternate_source: bool = False,
) -> tuple[dict[str, bytes], dict[str, ArtifactRef], Activation, QualificationFreeze]:
    root = "outputs/synthetic_four_model_prediction"
    freeze_semantic = "a" * 64
    common_semantic = "b" * 64
    prediction_raw = b"synthetic canonical prediction bytes\n"
    prediction_ref = _artifact(f"{root}/PREDICTIONS.csv", prediction_raw, 1)
    source_groups = [
        [
            {
                "relative_path": relative,
                "raw_sha256": digest,
                "size_bytes": size,
            }
            for relative, digest, size in group
        ]
        for group in EXPECTED_SOURCE_RECORD_GROUPS
    ]
    if alternate_source:
        source_groups[0][0] = {**source_groups[0][0], "raw_sha256": "c" * 64}
    runtime = dict(EXPECTED_RUNTIME_VERSIONS)
    source = build_source_manifest(
        adapter_source_records=source_groups[0],
        c2_c3_frozen_numeric_source_records=source_groups[1],
        c4_source_tree_records=source_groups[2],
        c4_source_file_records=source_groups[3],
        runtime_versions=runtime,
        runtime_semantic_sha256=semantic_sha256(runtime),
    )
    source_raw = canonical_json_bytes(source)
    source_ref = _artifact(f"{root}/SOURCE_MANIFEST.json", source_raw, 2)
    manifest = build_prediction_manifest(
        qualification_survivor_freeze_semantic_sha256=freeze_semantic,
        generation_plan_semantic_sha256=plan_semantic,
        common_identity_semantic_sha256=common_semantic,
        prediction_raw_sha256=prediction_ref.raw_sha256,
        prediction_semantic_sha256=prediction_ref.raw_sha256,
        source_manifest_raw_sha256=source_ref.raw_sha256,
        source_manifest_semantic_sha256=source["source_manifest_semantic_sha256"],
        source_records_semantic_sha256=source["source_records_semantic_sha256"],
    )
    if omit_estimator_mapping:
        manifest.pop("estimator_rng_seed_by_alias")
        manifest.pop("manifest_semantic_sha256")
        manifest["manifest_semantic_sha256"] = semantic_sha256(manifest)
    manifest_raw = canonical_json_bytes(manifest)
    manifest_ref = _artifact(f"{root}/PREDICTION_MANIFEST.json", manifest_raw, 3)
    receipt = build_freeze_receipt(
        qualification_survivor_freeze_semantic_sha256=freeze_semantic,
        generation_plan_semantic_sha256=plan_semantic,
        common_identity_semantic_sha256=common_semantic,
        prediction_ref=prediction_ref.as_mapping(),
        prediction_manifest_ref=manifest_ref.as_mapping(),
        source_manifest_ref=source_ref.as_mapping(),
        prediction_semantic_sha256=prediction_ref.raw_sha256,
        prediction_manifest_semantic_sha256=manifest["manifest_semantic_sha256"],
        source_manifest_semantic_sha256=source["source_manifest_semantic_sha256"],
        source_records_semantic_sha256=source["source_records_semantic_sha256"],
    )
    receipt_raw = canonical_json_bytes(receipt)
    receipt_ref = _artifact(
        f"{root}/HELDOUT_PREDICTION_FREEZE_RECEIPT.json", receipt_raw, 4
    )
    root_identity = {"volume_serial_number": 1, "file_id_128": "f" * 32}
    independent_core = {
        "schema_version": "expected_pe.four_model.heldout_independent_audit_evidence.v1",
        "status": "PASS_INDEPENDENT_FORMULA_AND_SOURCE_RECOMPUTATION",
        "checks": {field: True for field in PREDICTION_AUDIT_CHECK_FIELDS},
        "access": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_protected_open_count": 0,
        },
        "independence": {
            "auditor_did_not_import_prediction_producer": True,
            "auditor_recomputed_formulas": True,
            "auditor_recomputed_geometry": True,
        },
        "prediction_recomputed_raw_sha256": prediction_ref.raw_sha256,
        "common_identity_semantic_sha256": common_semantic,
        "source_records_semantic_sha256": source[
            "source_records_semantic_sha256"
        ],
        "task_count": 50,
        "identity_count": 64_800,
        "prediction_row_count": 259_200,
    }
    independent_evidence = {
        **independent_core,
        "evidence_semantic_sha256": semantic_sha256(independent_core),
    }
    audit = build_go_audit(
        qualification_survivor_freeze_semantic_sha256=freeze_semantic,
        generation_plan_semantic_sha256=plan_semantic,
        common_identity_semantic_sha256=common_semantic,
        prediction_ref=prediction_ref.as_mapping(),
        prediction_manifest_ref=manifest_ref.as_mapping(),
        prediction_freeze_receipt_ref=receipt_ref.as_mapping(),
        source_manifest_ref=source_ref.as_mapping(),
        prediction_semantic_sha256=prediction_ref.raw_sha256,
        prediction_manifest_semantic_sha256=manifest["manifest_semantic_sha256"],
        prediction_freeze_receipt_semantic_sha256=receipt["receipt_semantic_sha256"],
        source_manifest_semantic_sha256=source["source_manifest_semantic_sha256"],
        source_records_semantic_sha256=source["source_records_semantic_sha256"],
        output_root_name="synthetic_four_model_prediction",
        output_root_identity=root_identity,
        independent_evidence=independent_evidence,
    )
    audit_raw = canonical_json_bytes(audit)
    audit_ref = _artifact(f"{root}/HELDOUT_PREDICTION_FREEZE_AUDIT.json", audit_raw, 5)
    five = {
        "HELDOUT_PREDICTION_FREEZE_AUDIT.json": audit_raw,
        "HELDOUT_PREDICTION_FREEZE_RECEIPT.json": receipt_raw,
        "PREDICTIONS.csv": prediction_raw,
        "PREDICTION_MANIFEST.json": manifest_raw,
        "SOURCE_MANIFEST.json": source_raw,
    }
    checksums_raw = "".join(
        f"{sha256_bytes(five[leaf])}  {leaf}\n" for leaf in PREDICTION_CHECKSUM_LEDGER_LEAVES
    ).encode("ascii")
    checksums_ref = _artifact(f"{root}/CHECKSUMS.sha256", checksums_raw, 6)
    seal = build_go_seal(
        qualification_survivor_freeze_semantic_sha256=freeze_semantic,
        common_identity_semantic_sha256=common_semantic,
        prediction_ref=prediction_ref.as_mapping(),
        prediction_semantic_sha256=prediction_ref.raw_sha256,
        prediction_freeze_receipt_ref=receipt_ref.as_mapping(),
        prediction_freeze_receipt_semantic_sha256=receipt["receipt_semantic_sha256"],
        prediction_audit_ref=audit_ref.as_mapping(),
        prediction_audit_semantic_sha256=audit["audit_semantic_sha256"],
        checksums_ref=checksums_ref.as_mapping(),
        output_root_name="synthetic_four_model_prediction",
        output_root_identity=root_identity,
    )
    seal_raw = canonical_json_bytes(seal)
    seal_ref = _artifact(f"{root}/AUDIT_SEAL.json", seal_raw, 7)
    raws = {
        "AUDIT_SEAL.json": seal_raw,
        "CHECKSUMS.sha256": checksums_raw,
        **five,
    }
    refs = {
        "AUDIT_SEAL.json": seal_ref,
        "CHECKSUMS.sha256": checksums_ref,
        "HELDOUT_PREDICTION_FREEZE_AUDIT.json": audit_ref,
        "HELDOUT_PREDICTION_FREEZE_RECEIPT.json": receipt_ref,
        "PREDICTIONS.csv": prediction_ref,
        "PREDICTION_MANIFEST.json": manifest_ref,
        "SOURCE_MANIFEST.json": source_ref,
    }
    activation = Activation(
        raw_sha256="d" * 64,
        run_id="synthetic_heldout",
        output_relative_path=(
            "outputs/model_zoo_pe_model_portfolio_heldout_certification_result_"
            "synthetic_heldout"
        ),
        r2_protocol_lock_raw_sha256="9" * 64,
        r2_protocol_binding_semantic_sha256="a" * 64,
        qualification_result_ref=ArtifactRef(
            "outputs/synthetic_qualification/QUALIFICATION_RESULT.json",
            "e" * 64,
            1,
            1,
            "e" * 32,
        ),
        qualification_survivor_freeze_semantic_sha256=freeze_semantic,
        prediction_ref=prediction_ref,
        prediction_freeze_receipt_ref=receipt_ref,
        prediction_audit_ref=audit_ref,
        prediction_audit_seal_ref=seal_ref,
        prediction_checksums_ref=checksums_ref,
        prediction_semantic_sha256=prediction_ref.raw_sha256,
        common_identity_semantic_sha256=common_semantic,
        generation_plan_semantic_sha256=plan_semantic,
        formula_lock_semantic_sha256=FORMULA_LOCK_SEMANTIC_SHA256,
        source_model_versions=tuple(SOURCE_MODEL_VERSIONS.items()),
        vault_manifest_ref=ArtifactRef(
            "outputs/.model_zoo_synthetic_heldout/VAULT_MANIFEST.json",
            "8" * 64,
            1,
            1,
            "8" * 32,
        ),
        vault_manifest_semantic_sha256="8" * 64,
        truth_refs=(),
    )
    freeze = QualificationFreeze(
        raw_sha256="e" * 64,
        survivor_freeze_semantic_sha256=freeze_semantic,
        source_model_versions=tuple(SOURCE_MODEL_VERSIONS.items()),
        payload={},
    )
    return raws, refs, activation, freeze


def test_frozen_identity_and_gate_contract() -> None:
    assert HELDOUT_SEEDS == (7789, 7793, 7817, 7823, 7829)
    assert MODEL_IDS == (CHAMPION_ID, *SURVIVOR_IDS)
    assert C1_ID not in MODEL_IDS
    assert BOOTSTRAP_DRAWS == 10_000
    assert BOOTSTRAP_RNG_SEED == 2_026_082_205
    assert HELDOUT_GATE == {
        "pooled_mae_relative_gain_min": 0.005,
        "pooled_rmse_relative_gain_min": 0.005,
        "seed_wins_min": 4,
        "seed_total": 5,
        "worst_seed_dgp_harm_max": 0.03,
        "worst_dgp_mean_harm_max": 0.01,
        "pooled_p95_abs_log_error_non_worse": True,
        "pooled_extreme_error_frequency_non_worse": True,
        "systematic_dgp_joint_tail_failure_count_max": 0,
        "bootstrap_mae_gain_lower_5pct_strictly_greater_than": 0.0,
    }


def test_qualification_result_freeze_is_exact_and_no_tuning() -> None:
    raw = canonical_json_bytes(_qualification_payload())
    freeze = _parse_qualification_result(raw, expected_raw_sha256=sha256_bytes(raw))
    assert tuple(dict(freeze.source_model_versions)) == MODEL_IDS
    assert len(freeze.survivor_freeze_semantic_sha256) == 64
    changed = _qualification_payload()
    changed["score"]["survivor_role_ranking_freeze"][
        "certified_survivor_ids_in_rank_order"
    ] = list(reversed(SURVIVOR_IDS))
    changed_raw = canonical_json_bytes(changed)
    with pytest.raises(HeldoutEvaluatorError, match="survivor role/rank freeze"):
        _parse_qualification_result(changed_raw, expected_raw_sha256=sha256_bytes(changed_raw))


def test_gate_boundaries_are_inclusive_except_bootstrap() -> None:
    passed = classify_heldout_gate(
        pooled_mae_gain=0.005,
        pooled_rmse_gain=0.005,
        seed_wins=4,
        seed_total=5,
        worst_seed_dgp_harm=0.03,
        worst_dgp_mean_harm=0.01,
        pooled_p95_non_worse=True,
        pooled_extreme_frequency_non_worse=True,
        systematic_dgp_joint_tail_failure_count=0,
        bootstrap_mae_gain_lower_5pct=np.nextafter(0.0, 1.0),
    )
    assert passed["all_heldout_gates_pass"] is True
    failed = classify_heldout_gate(
        pooled_mae_gain=0.005,
        pooled_rmse_gain=0.005,
        seed_wins=4,
        seed_total=5,
        worst_seed_dgp_harm=0.03,
        worst_dgp_mean_harm=0.01,
        pooled_p95_non_worse=True,
        pooled_extreme_frequency_non_worse=True,
        systematic_dgp_joint_tail_failure_count=0,
        bootstrap_mae_gain_lower_5pct=0.0,
    )
    assert failed["gate_bootstrap_lower_5pct_strictly_positive"] is False
    assert failed["all_heldout_gates_pass"] is False


def test_prediction_identity_geometry_rejects_qualification_alias() -> None:
    fold_id, train_end, test_start = fold_geometry(504)
    valid = (
        "heldout_seed_01",
        "A",
        504,
        "2026-01-01",
        "DGP_ISSUER",
        fold_id,
        train_end,
        test_start,
    )
    validate_identity(valid, 0)
    invalid = ("qualification_seed_01", *valid[1:])
    with pytest.raises(HeldoutEvaluatorError, match="identity geometry"):
        validate_identity(invalid, 0)


def test_cross_package_prediction_freeze_seal_and_acyclic_ledger_are_exact() -> None:
    raws, refs, activation, freeze = _prediction_freeze_fixture()
    receipt = validate_prediction_freeze(
        raws=raws,
        refs=refs,
        root_identity={"volume_serial_number": 1, "file_id_128": "f" * 32},
        activation=activation,
        qualification_freeze=freeze,
    )
    assert receipt["prediction_audit_raw_sha256"] == refs[
        "HELDOUT_PREDICTION_FREEZE_AUDIT.json"
    ].raw_sha256
    assert receipt["source_records"][0]["relative_path"].endswith("__init__.py")
    assert "CHECKSUMS.sha256" not in raws["CHECKSUMS.sha256"].decode("ascii")
    assert "AUDIT_SEAL.json" not in raws["CHECKSUMS.sha256"].decode("ascii")


def test_prediction_audit_check_contract_is_exact_18_key_cross_package_parity() -> None:
    expected_fields = (
        "qualification_result_exact",
        "survivor_freeze_exact",
        "source_model_versions_exact",
        "formula_lock_exact",
        "heldout_task_geometry_exact",
        "model_order_exact",
        "c1_absent",
        "estimator_rng_mapping_exact",
        "prediction_recomputed_exact",
        "prediction_before_truth",
        "source_closure_exact",
        "public_only_inputs",
        "root_identity_exact",
        "file_universe_exact",
        "artifact_refs_live",
        "bce_nine_variable_runtime_contract_exact",
        "c4_seven_variable_runtime_contract_exact",
        "python_and_package_runtime_hash_exact",
    )
    checks = {field: True for field in expected_fields}

    assert len(expected_fields) == 18
    assert PREDICTION_AUDIT_CHECK_FIELDS == expected_fields
    assert tuple(go_checks(checks)) == expected_fields
    assert go_checks(checks) == checks


@pytest.mark.parametrize("drift", ("missing", "extra", "false"))
def test_prediction_audit_check_contract_rejects_any_drift(drift: str) -> None:
    checks = {field: True for field in PREDICTION_AUDIT_CHECK_FIELDS}
    if drift == "missing":
        checks.pop("bce_nine_variable_runtime_contract_exact")
    elif drift == "extra":
        checks["unexpected_runtime_contract"] = True
    else:
        checks["c4_seven_variable_runtime_contract_exact"] = False

    with pytest.raises(
        HeldoutAuthorityError, match="independent audit check evidence differs"
    ):
        go_checks(checks)


def test_prediction_freeze_rejects_missing_seed_mapping_and_alternate_plan() -> None:
    raws, refs, activation, freeze = _prediction_freeze_fixture(
        omit_estimator_mapping=True
    )
    with pytest.raises(HeldoutEvaluatorError, match="manifest key universe"):
        validate_prediction_freeze(
            raws=raws,
            refs=refs,
            root_identity={"volume_serial_number": 1, "file_id_128": "f" * 32},
            activation=activation,
            qualification_freeze=freeze,
        )
    raws, refs, activation, freeze = _prediction_freeze_fixture(plan_semantic="9" * 64)
    with pytest.raises(HeldoutEvaluatorError, match="receipt/audit binding"):
        validate_prediction_freeze(
            raws=raws,
            refs=refs,
            root_identity={"volume_serial_number": 1, "file_id_128": "f" * 32},
            activation=activation,
            qualification_freeze=freeze,
        )


def test_prediction_freeze_rejects_self_consistent_alternate_source_closure() -> None:
    raws, refs, activation, freeze = _prediction_freeze_fixture(alternate_source=True)
    with pytest.raises(HeldoutEvaluatorError, match="exact source-record universe"):
        validate_prediction_freeze(
            raws=raws,
            refs=refs,
            root_identity={"volume_serial_number": 1, "file_id_128": "f" * 32},
            activation=activation,
            qualification_freeze=freeze,
        )


def test_vault_manifest_binds_two_pass_parity_before_truth_without_truth_bytes() -> None:
    _, _, template, _ = _prediction_freeze_fixture()
    vault = "outputs/.model_zoo_synthetic_heldout"
    truth_refs = tuple(
        ArtifactRef(
            f"{vault}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv",
            hashlib.sha256(f"{seed}:{dgp}".encode()).hexdigest(),
            123,
            1,
            f"{ordinal + 100:032x}",
        )
        for ordinal, (seed, dgp) in enumerate(
            (seed, dgp) for seed in HELDOUT_SEEDS for dgp in DGP_IDS
        )
    )
    core = {
        "schema_version": VAULT_MANIFEST_SCHEMA,
        "status": VAULT_MANIFEST_STATUS,
        "vault_relative_path": vault,
        "qualification_result_raw_sha256": (
            "4fbf83c18bbd6f339d4cc3f9ce94b4140349c601d01a9790581adae2d4a8f3a1"
        ),
        "generation_plan_semantic_sha256": GENERATION_PLAN_SEMANTIC_SHA256,
        "truth_refs": [ref.as_mapping() for ref in truth_refs],
        "truth_ref_count": 50,
        "protected_task_metadata_count": 100,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "metadata_read_count": 100,
        "pass_1_pass_2_protected_hashes_equal": True,
        "pass_1_pass_2_public_hashes_equal": True,
        "truth_content_open_count": 0,
        "truth_attribute_open_count_by_manifest_builder": 0,
        "truth_attribute_open_count_at_protected_write_time": 100,
        "pass_2_truth_ref_export_count": 0,
        "latent_ref_export_count": 0,
        "truth_refs_origin": "protected_write_time_FILE_READ_ATTRIBUTES_only",
        "outer_truth_content_open_count": 0,
        "evaluator_pre_marker_truth_content_open_count": 0,
    }
    semantic = semantic_sha256(core)
    raw = canonical_json_bytes({**core, "vault_manifest_semantic_sha256": semantic})
    ref = _artifact(f"{vault}/VAULT_MANIFEST.json", raw, 99)
    activation = replace(
        template,
        vault_manifest_ref=ref,
        vault_manifest_semantic_sha256=semantic,
        truth_refs=truth_refs,
    )
    receipt = validate_vault_manifest(raw, ref=ref, activation=activation)
    assert receipt["truth_ref_count"] == 50
    assert receipt["truth_content_open_count"] == 0
    attacked_core = {**core, "pass_1_pass_2_protected_hashes_equal": False}
    attacked_semantic = semantic_sha256(attacked_core)
    attacked_raw = canonical_json_bytes(
        {**attacked_core, "vault_manifest_semantic_sha256": attacked_semantic}
    )
    attacked_ref = _artifact(f"{vault}/VAULT_MANIFEST.json", attacked_raw, 99)
    attacked_activation = replace(
        activation,
        vault_manifest_ref=attacked_ref,
        vault_manifest_semantic_sha256=attacked_semantic,
    )
    with pytest.raises(HeldoutEvaluatorError, match="authority/parity"):
        validate_vault_manifest(
            attacked_raw, ref=attacked_ref, activation=attacked_activation
        )


def test_outputs_descendant_reuses_restrictive_parent_without_reopen(tmp_path) -> None:
    outputs = tmp_path / "outputs"
    leaf = outputs / "synthetic_public" / "PREDICTIONS.csv"
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(b"synthetic-public-only\n")
    observed = _snapshot_artifact_ref_untrusted(
        project_root=tmp_path,
        relative_path="outputs/synthetic_public/PREDICTIONS.csv",
    )
    ref = ArtifactRef(**observed.as_mapping())
    outputs_parent = HeldWritableDirectory.open(outputs)
    held = []
    try:
        held = open_held_artifacts(tmp_path, (ref,), outputs_parent=outputs_parent)
        receipt = held[0].receipt()
        assert receipt["outputs_parent_reused_without_reopen"] is True
        assert (
            receipt["outputs_parent_volume_serial_number"]
            == outputs_parent.volume_serial_number
        )
        assert receipt["outputs_parent_file_id_128"] == outputs_parent.file_id_128
        held[0].assert_live()
        outputs_parent.assert_live()
    finally:
        close_held_artifacts(held)
        outputs_parent.close()


def test_all_heldout_publication_roots_are_derived_from_one_run_id() -> None:
    run_id = "heldout_v1_20260824T000005"
    _require_run_scoped_root(
        PurePosixPath(f"outputs/model_zoo_pe_four_model_heldout_predictions_{run_id}"),
        prefix="model_zoo_pe_four_model_heldout_predictions_",
        run_id=run_id,
        label="prediction publication root",
    )
    _require_run_scoped_root(
        PurePosixPath(f"outputs/.model_zoo_pe_four_model_heldout_vault_{run_id}"),
        prefix=".model_zoo_pe_four_model_heldout_vault_",
        run_id=run_id,
        label="heldout truth vault",
    )
    _validate_activation_root_relative(
        f"outputs/model_zoo_pe_model_portfolio_heldout_activation_{run_id}",
        run_id=run_id,
    )
    with pytest.raises(HeldoutEvaluatorError, match="differs from run_id"):
        _require_run_scoped_root(
            PurePosixPath("outputs/model_zoo_pe_four_model_heldout_predictions_old"),
            prefix="model_zoo_pe_four_model_heldout_predictions_",
            run_id=run_id,
            label="prediction publication root",
        )
    with pytest.raises(HeldoutEvaluatorError, match="differs from run_id"):
        _require_run_scoped_root(
            PurePosixPath("outputs/.model_zoo_pe_four_model_heldout_vault_old"),
            prefix=".model_zoo_pe_four_model_heldout_vault_",
            run_id=run_id,
            label="heldout truth vault",
        )
    with pytest.raises(HeldoutEvaluatorError, match="differs from run_id"):
        _validate_activation_root_relative(
            "outputs/model_zoo_pe_model_portfolio_heldout_activation_old",
            run_id=run_id,
        )


def test_live_source_byte_drift_fails_before_marker(tmp_path: Path) -> None:
    relative = "research/synthetic_numeric.py"
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    frozen = b"frozen numeric source\n"
    path.write_bytes(b"drifted numeric source\n")
    record = {
        "relative_path": relative,
        "raw_sha256": hashlib.sha256(frozen).hexdigest(),
        "size_bytes": len(frozen),
    }
    with pytest.raises(HeldoutEvaluatorError, match="live source bytes differ"):
        _hold_source_closure(tmp_path, (record,))


def test_actual_topology_prediction_marker_fifty_truth_result_reuses_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    prediction_path = outputs / "synthetic_prediction/PREDICTIONS.csv"
    prediction_path.parent.mkdir(parents=True)
    prediction_path.write_bytes(b"synthetic prediction before marker\n")
    prediction_observed = _snapshot_artifact_ref_untrusted(
        project_root=tmp_path,
        relative_path="outputs/synthetic_prediction/PREDICTIONS.csv",
    )
    prediction_ref = ArtifactRef(**prediction_observed.as_mapping())
    truth_refs: list[ArtifactRef] = []
    for seed in HELDOUT_SEEDS:
        for dgp in DGP_IDS:
            relative = f"outputs/.model_zoo_synthetic_heldout/pass_1/seed_{seed}/dgp_{dgp}/truth.csv"
            path = tmp_path / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(f"synthetic truth seed={seed} dgp={dgp}\n".encode("ascii"))
            observed = _snapshot_artifact_ref_untrusted(
                project_root=tmp_path, relative_path=relative
            )
            truth_refs.append(ArtifactRef(**observed.as_mapping()))
    parent = HeldWritableDirectory.open(outputs)
    result_root = None
    prediction_held = []
    truth_held = []
    marker = None
    result = None
    events: list[str] = []
    native_open = heldout_custody._open_native_held

    def reject_outputs_reopen(path: Path, *, directory: bool):  # type: ignore[no-untyped-def]
        if Path(os.path.abspath(path)) == Path(os.path.abspath(outputs)):
            raise AssertionError("restrictive outputs parent was redundantly reopened")
        return native_open(path, directory=directory)

    monkeypatch.setattr(heldout_custody, "_open_native_held", reject_outputs_reopen)
    try:
        result_root = claim_output_root(
            outputs / "synthetic_heldout_result",
            project_root=tmp_path,
            outputs_parent=parent,
        )
        prediction_held = open_held_artifacts(
            tmp_path, (prediction_ref,), outputs_parent=parent
        )
        events.append("prediction")
        marker = publish_atomic_create_new(
            parent=result_root,
            final_leaf=CONSUMPTION_MARKER_LEAF,
            raw=b"synthetic durable marker\n",
        )
        marker.assert_live()
        events.append("marker")
        truth_held = open_held_artifacts(tmp_path, truth_refs, outputs_parent=parent)
        events.append("truth")
        result = publish_atomic_create_new(
            parent=result_root,
            final_leaf=RESULT_LEAF,
            raw=b"synthetic terminal result\n",
        )
        result.assert_live()
        events.append("result")
        assert events == ["prediction", "marker", "truth", "result"]
        assert len(truth_held) == 50
        for artifact in (*prediction_held, *truth_held):
            receipt = artifact.receipt()
            assert receipt["outputs_parent_reused_without_reopen"] is True
            assert receipt["outputs_parent_volume_serial_number"] == parent.volume_serial_number
            assert receipt["outputs_parent_file_id_128"] == parent.file_id_128
            assert cast(int, receipt["ancestor_count"]) >= 1
            artifact.assert_live()
        parent.assert_live()
        result_root.assert_live()
        marker.assert_live()
        result.assert_live()
    finally:
        close_held_artifacts(truth_held)
        close_held_artifacts(prediction_held)
        if result is not None:
            result.close()
        if marker is not None:
            marker.close()
        if result_root is not None:
            result_root.close()
        parent.close()


def test_runner_orders_durable_marker_before_only_truth_open() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/runner.py"
    ).read_text(encoding="utf-8")
    marker = source.index("final_leaf=CONSUMPTION_MARKER_LEAF")
    vault_manifest = source.index("vault_receipt = validate_vault_manifest(")
    truth = source.index("\n        truth_held = open_held_artifacts(", marker)
    result = source.index("final_leaf=RESULT_LEAF", truth)
    assert vault_manifest < marker < truth < result
    signature = source[source.index("def run_once(") : source.index(") -> Path:")]
    assert "truth" not in signature.casefold()
    assert "heldout" not in signature.casefold()
    assert '"latent_open_count": 0' in source
    assert '"pass_2_open_count": 0' in source
    assert '"candidate_tuning_count": 0' in source
    assert '"heldout_reranking_count": 0' in source


def test_direct_cli_is_non_authorizing_and_creates_no_pycache(tmp_path: Path) -> None:
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts/model_lab/pe_model_portfolio_heldout_certification_evaluator_v1/run_once.py"
    )
    prefix = tmp_path / "heldout_eval_pycache_absent_direct"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={prefix}",
            str(script),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "external held-byte launcher trust anchor" in completed.stderr
    assert not prefix.exists()
    source = script.read_text(encoding="utf-8")
    custody = source.index("held = _bootstrap_source_custody()")
    numpy_import = source.index("        import numpy", custody)
    runner_import = source.index("from research.model_zoo", numpy_import)
    assert custody < numpy_import < runner_import
    parser_region = source[source.index("parser = argparse.ArgumentParser") :]
    assert 'add_argument("--truth' not in parser_region
    assert 'add_argument("--vault' not in parser_region


def test_launcher_source_and_numpy_record_pins_match_live_bytes() -> None:
    project = Path(__file__).resolve().parents[2]
    script = (
        project
        / "scripts/model_lab/pe_model_portfolio_heldout_certification_evaluator_v1/run_once.py"
    )
    source = script.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {
        "PINNED_SOURCE_SHA256",
        "PINNED_NUMPY_RECORD_RAW_SHA256",
        "PINNED_NUMPY_RECORD_SIZE_BYTES",
        "PINNED_NUMPY_RECORD_ROW_COUNT",
        "PINNED_NUMPY_RECORD_HASHED_MEMBER_COUNT",
    }
    assignments: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
            value = node.value
        else:
            continue
        for name in names:
            if name in wanted and value is not None:
                assignments[name] = ast.literal_eval(value)
    source_pins = cast(dict[str, str], assignments["PINNED_SOURCE_SHA256"])
    assert len(source_pins) == 37
    assert all("\\" not in relative for relative in source_pins)
    for relative, digest in source_pins.items():
        raw = (project / relative).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
    record = (
        Path(sys.executable).resolve().parents[1]
        / "Lib/site-packages/numpy-1.26.4.dist-info/RECORD"
    )
    record_raw = record.read_bytes()
    assert hashlib.sha256(record_raw).hexdigest() == assignments[
        "PINNED_NUMPY_RECORD_RAW_SHA256"
    ]
    assert len(record_raw) == assignments["PINNED_NUMPY_RECORD_SIZE_BYTES"]
    assert len(record_raw.splitlines()) == assignments["PINNED_NUMPY_RECORD_ROW_COUNT"]
    assert assignments["PINNED_NUMPY_RECORD_HASHED_MEMBER_COUNT"] == 935
    custody = source.index("handles.extend(_hold_numpy_distribution())")
    numpy_import = source.index("        import numpy", custody)
    assert custody < numpy_import


def test_bootstrap_rng_call_order_has_fixed_synthetic_digest() -> None:
    shape = (len(SEED_ALIASES), len(DGP_IDS), len(FOLD_IDS), len(MODEL_IDS))
    sums = np.empty(shape, dtype=np.float64)
    counts = np.empty(shape[:-1], dtype=np.int64)
    for seed in range(shape[0]):
        for dgp in range(shape[1]):
            for fold in range(shape[2]):
                count = 1 + ((seed + 2 * dgp + fold) % 3)
                counts[seed, dgp, fold] = count
                sums[seed, dgp, fold] = count * np.asarray(
                    (
                        0.5 + 0.1 * seed + 0.01 * dgp + 0.001 * fold,
                        0.49 + 0.08 * seed + 0.015 * dgp + 0.0005 * fold,
                        0.45 + 0.12 * seed + 0.005 * dgp + 0.0015 * fold,
                        0.55 - 0.03 * seed + 0.02 * dgp + 0.0002 * fold,
                    ),
                    dtype=np.float64,
                )
    gains, benefits, receipt = _bootstrap_from_fold_aggregates(
        fold_absolute_error_sums=sums,
        fold_counts=counts,
        draw_count=7,
        rng_seed=424_242,
        batch_size=3,
    )
    expected_gain_digests = (
        "3b6a86f29a5c01b5995e06ff632b1f9821bfafe976774d1d5c3d339db448123c",
        "28cc4ed8beecb7695fa4f06f0ee9da01c26e3808aa4f03714fdd74cc511e24a7",
        "ffb04a9322a1974a57cf3ef2b5562aff7b205ec124283311099f9aa41c6c5ae9",
    )
    assert tuple(
        hashlib.sha256(np.asarray(gains[:, index], dtype="<f8").tobytes()).hexdigest()
        for index in range(len(SURVIVOR_IDS))
    ) == expected_gain_digests
    assert tuple(type7_quantile(gains[:, index].tolist(), 0.05) for index in range(3)) == (
        0.033145182803518365,
        0.014665663399378293,
        0.08261772159254546,
    )
    assert benefits.shape == gains.shape
    assert (
        receipt["fold_draws_little_endian_i64_sha256"]
        == "bd858e2d709f8bedc231545cadc53ead194db9c684489e2532e3b1a879458ac6"
    )
    assert (
        receipt["rng_final_state_semantic_sha256"]
        == "6f6b3eb7e95919f5abe80d51188055a20d42df8acefee6b0517d168437b2040a"
    )
    assert receipt["dgp_resampling"] is False
    assert receipt["candidate_resamples_shared"] is True


def test_bootstrap_fsum_oracle_differs_from_numpy_float_sum() -> None:
    # The scoring surface contains nonnegative absolute-error aggregates.  This large/small
    # oracle proves that a vectorized NumPy floating reduction is not an acceptable substitute
    # for the Policy V2 math.fsum operation order.
    values = [1.0e16, *([1.0] * 3_098), 1.0e16]
    oracle = math.fsum(values)
    numpy_reduction = float(np.asarray(values, dtype=np.float64).sum(dtype=np.float64))
    assert oracle == 2.0000000000003096e16
    assert numpy_reduction != oracle


def test_exact_geometry_all_three_survivors_pass_without_reranking() -> None:
    predictions, truth, versions = _exact_synthetic_inputs()
    result = evaluate_heldout(
        predictions=predictions,
        truth=truth,
        source_model_versions=versions,
        qualification_result_raw_sha256="4" * 64,
        qualification_survivor_freeze_semantic_sha256="5" * 64,
        prediction_audit_raw_sha256="6" * 64,
    ).payload
    assert result["certified_survivor_ids_in_qualification_rank_order"] == list(
        SURVIVOR_IDS
    )
    assert result["failed_survivor_ids_in_qualification_rank_order"] == []
    assert result["all_three_frozen_survivors_pass"] is True
    assert result["geometry"] == {
        "model_ids_in_order": list(MODEL_IDS),
        "identity_rows": 64_800,
        "prediction_long_rows": 259_200,
        "common_mask_rows": 64_800,
        "seed_count": 5,
        "dgp_count": 10,
        "seed_dgp_cells": 50,
        "fold_blocks": 3_100,
        "model_specific_row_drops": 0,
        "sort_pivot_join_imputation_or_reorder": False,
    }
    for expected_rank, row in enumerate(
        result["candidate_results_in_qualification_rank_order"], start=1
    ):
        assert row["qualification_rank"] == expected_rank
        assert row["heldout_reranked"] is False
        assert row["candidate_tuned"] is False
        assert row["gate"]["all_heldout_gates_pass"] is True
        complementarity = row["complementarity_vs_champion"]
        assert complementarity["diagnostic_only"] is True
        assert complementarity["affects_gate_or_rank"] is False
        assert set(complementarity) == {
            "candidate_id",
            "rows",
            "signed_error_correlation_vs_v04",
            "signed_error_correlation_status",
            "absolute_error_correlation_vs_v04",
            "absolute_error_correlation_status",
            "log_prediction_correlation_vs_v04",
            "log_prediction_correlation_status",
            "median_absolute_log_prediction_disagreement",
            "q90_absolute_log_prediction_disagreement",
            "q95_absolute_log_prediction_disagreement",
            "frequency_gt_2pct",
            "frequency_gt_5pct",
            "frequency_gt_10pct",
            "oracle_pair_mae",
            "oracle_pair_rmse",
            "oracle_marginal_mae_gain_vs_better_standalone",
            "oracle_marginal_gain_status",
            "oracle_is_achievable_model_or_gate",
            "diagnostic_only",
            "affects_gate_or_rank",
        }
