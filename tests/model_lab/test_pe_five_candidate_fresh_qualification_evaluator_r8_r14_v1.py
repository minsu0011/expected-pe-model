from __future__ import annotations

from pathlib import Path
from typing import cast
import importlib._bootstrap_external as bootstrap_external
import importlib.util
import json
import os
import shutil
import subprocess
import sys

import pytest

from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1 import (
    publication as publication_module,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1 import (
    runner as runner_module,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.audit import (
    validate_pre_score_audit,
    validate_prediction_audit,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.canonical import (
    QualificationScorerError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.constants import (
    ACTIVATION_SCHEMA,
    ACTIVATION_STATUS,
    ACTIVATION_CLAIM_SCHEMA,
    ACTIVATION_CLAIM_STATUS,
    ACTIVATION_OUTPUT_FILES,
    ACTIVATION_OUTPUT_ROOT_NAME,
    ACTIVATION_PUBLICATION_PROTOCOL,
    ACTIVATION_PUBLICATION_SEAL_SCHEMA,
    ACTIVATION_PUBLICATION_SEAL_STATUS,
    CANDIDATE_IDS,
    CONSUMPTION_MARKER_LEAF,
    DGP_IDS,
    MODEL_IDS,
    POLICY_RAW_SHA256,
    PREDICTION_AUDIT_CLAIM_SCHEMA,
    PREDICTION_AUDIT_CLAIM_STATUS,
    PREDICTION_AUDIT_CHECK_FIELDS,
    PREDICTION_AUDIT_FAMILY_ID,
    PREDICTION_AUDIT_INDEPENDENCE_FIELDS,
    PREDICTION_AUDIT_OUTPUT_FILES,
    PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
    PREDICTION_AUDIT_ROOT_NAME,
    PRESCORE_ACCESS_FIELDS,
    PRESCORE_AUDIT_CLAIM_SCHEMA,
    PRESCORE_AUDIT_CLAIM_STATUS,
    PRESCORE_AUDIT_INTEGRATED,
    PRESCORE_AUDIT_OUTPUT_FILES,
    PRESCORE_AUDIT_ROOT_NAME,
    PRESCORE_AUDIT_SCHEMA,
    PRESCORE_AUDIT_SEAL_SCHEMA,
    PRESCORE_AUDIT_SEAL_STATUS,
    PRESCORE_AUDIT_STATUS,
    PRESCORE_CHECK_FIELDS,
    PRESCORE_INDEPENDENCE_FIELDS,
    PRESCORE_STATIC_CHECK_FIELDS,
    PRESCORE_PUBLICATION_PROTOCOL,
    PRESCORE_TARGET_CLAIM_SCHEMA,
    PRESCORE_TARGET_CLAIM_STATUS,
    PRESCORE_TARGET_OUTPUT_FILES,
    PRESCORE_TARGET_PUBLICATION_SEAL_SCHEMA,
    PRESCORE_TARGET_PUBLICATION_SEAL_STATUS,
    PRESCORE_TARGET_ROOT_NAME,
    PRESCORE_TARGET_SCHEMA,
    PRESCORE_TARGET_STATUS,
    PREDICTION_AUDIT_SCHEMA,
    PREDICTION_AUDIT_SEAL_SCHEMA,
    PREDICTION_AUDIT_SEAL_STATUS,
    PREDICTION_AUDIT_SOURCE_RECORD_COUNT,
    PREDICTION_AUDIT_STATUS,
    PREDICTION_SEMANTIC_CONTRACT,
    QUALIFICATION_SEEDS,
    RESULT_LEAF,
    SCORER_SOURCE_RELATIVES,
    SCORER_OUTPUT_ROOT_NAME,
    VENDORED_RUNTIME_DEPENDENCY_SHA256,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.contracts import (
    ACTIVATION_CORE_FIELDS,
    Activation,
    ArtifactRef,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.metrics import (
    classify_policy_v2,
    score_qualification,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.prediction import (
    DecodedPredictions,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.publication import (
    HeldWritableDirectory,
    PublicationCommittedError,
    claim_output_root,
    publish_atomic_create_new,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.truth import (
    DecodedTruth,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.custody import (
    HeldArtifact,
    _close_handle as _close_native_handle,
    _open_held as _open_native_held,
)


def _ref(path: str, ordinal: int) -> dict[str, object]:
    return {
        "relative_path": path,
        "raw_sha256": f"{ordinal + 1:064x}",
        "size_bytes": ordinal + 1,
        "volume_serial_number": 7,
        "file_id_128": f"{ordinal + 1:032x}",
    }


def _compact(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _ref_for_raw(path: str, raw: bytes, ordinal: int) -> dict[str, object]:
    ref = _ref(path, ordinal)
    ref["raw_sha256"] = sha256_bytes(raw)
    ref["size_bytes"] = len(raw)
    return ref


def _native_ref(path: Path, *, relative_path: str) -> dict[str, object]:
    handle, receipt, raw = _open_native_held(path, directory=False)
    try:
        assert raw is not None
        return {
            "relative_path": relative_path,
            "raw_sha256": sha256_bytes(raw),
            "size_bytes": len(raw),
            "volume_serial_number": receipt["volume_serial_number"],
            "file_id_128": receipt["file_id_128"],
        }
    finally:
        _close_native_handle(handle)


def _native_identity(path: Path) -> dict[str, object]:
    handle, receipt, _ = _open_native_held(path, directory=True)
    try:
        return {
            "volume_serial_number": receipt["volume_serial_number"],
            "file_id_128": receipt["file_id_128"],
        }
    finally:
        _close_native_handle(handle)


def _activation_value() -> dict[str, object]:
    vault = "outputs/.model_zoo_synthetic_qualification_vault_spent"
    truth_refs = [
        _ref(f"{vault}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv", 10 + index)
        for index, (seed, dgp) in enumerate(
            (seed, dgp) for seed in QUALIFICATION_SEEDS for dgp in DGP_IDS
        )
    ]
    core = {
        "schema_version": ACTIVATION_SCHEMA,
        "status": ACTIVATION_STATUS,
        "run_id": "synthetic_spent_no_truth",
        "output_relative_path": f"outputs/{SCORER_OUTPUT_ROOT_NAME}",
        "vault_relative_path": vault,
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "heldout_authority": False,
        "prediction_ref": _ref("outputs/model_zoo_synthetic_combined/PREDICTIONS.csv", 1),
        "prediction_audit_ref": _ref(
            f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/PREDICTION_FREEZE_AUDIT.json",
            2,
        ),
        "prediction_audit_seal_ref": _ref(
            f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/AUDIT_SEAL.json", 3
        ),
        "prediction_semantic_sha256": "a" * 64,
        "common_full_identities_semantic_sha256": "b" * 64,
        "source_model_versions": {
            model_id: f"sha256:{index + 100:064x}" for index, model_id in enumerate(MODEL_IDS)
        },
        "truth_refs": truth_refs,
    }
    return {
        **core,
        "activation_core_semantic_sha256": sha256_bytes(_compact(core)[:-1]),
        "pre_score_target_ref": _ref(
            f"outputs/{PRESCORE_TARGET_ROOT_NAME}/PRE_SCORE_TARGET_BINDING.json",
            4,
        ),
        "pre_score_audit_ref": _ref(f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/PRE_SCORE_AUDIT.json", 5),
        "pre_score_audit_seal_ref": _ref(f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/AUDIT_SEAL.json", 6),
    }


def _activation() -> Activation:
    raw = canonical_json_bytes(_activation_value())
    return Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))


def _reseal_activation_core(value: dict[str, object]) -> None:
    core = {key: value[key] for key in ACTIVATION_CORE_FIELDS}
    value["activation_core_semantic_sha256"] = sha256_bytes(_compact(core)[:-1])


def test_activation_accepts_only_exact_fifty_pass1_truth_leaves() -> None:
    activation = _activation()
    assert len(activation.truth_refs) == 50
    assert all("/pass_1/" in ref.relative_path for ref in activation.truth_refs)
    assert all("latent" not in ref.relative_path for ref in activation.truth_refs)
    assert (
        Path(activation.pre_score_target_ref.relative_path).parent
        != Path(activation.pre_score_audit_ref.relative_path).parent
    )

    malformed = _activation_value()
    malformed["truth_refs"][0]["relative_path"] = str(
        malformed["truth_refs"][0]["relative_path"]
    ).replace("pass_1", "pass_2")
    raw = canonical_json_bytes(malformed)
    with pytest.raises(QualificationScorerError):
        Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))


def test_activation_rejects_heldout_authority_and_fileid_alias() -> None:
    malformed = _activation_value()
    malformed["heldout_authority"] = True
    raw = canonical_json_bytes(malformed)
    with pytest.raises(QualificationScorerError):
        Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))


def test_activation_rejects_protected_pretruth_refs_and_heldout_vault_token() -> None:
    malformed = _activation_value()
    malformed["prediction_ref"]["relative_path"] = "outputs/.model_zoo_private/PREDICTIONS.csv"
    _reseal_activation_core(malformed)
    raw = canonical_json_bytes(malformed)
    with pytest.raises(QualificationScorerError):
        Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))

    malformed = _activation_value()
    prior = str(malformed["vault_relative_path"])
    heldout = "outputs/.model_zoo_heldout_synthetic"
    malformed["vault_relative_path"] = heldout
    for ref in malformed["truth_refs"]:
        ref["relative_path"] = str(ref["relative_path"]).replace(prior, heldout)
    _reseal_activation_core(malformed)
    raw = canonical_json_bytes(malformed)
    with pytest.raises(QualificationScorerError):
        Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))

    malformed = _activation_value()
    malformed["truth_refs"][1]["file_id_128"] = malformed["truth_refs"][0]["file_id_128"]
    raw = canonical_json_bytes(malformed)
    with pytest.raises(QualificationScorerError):
        Activation.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))


def test_prediction_audit_and_seal_are_target_bound_go_zero() -> None:
    activation = _activation()
    combined_root_identity = {
        "volume_serial_number": "0000000000000009",
        "file_id_128": "c" * 32,
    }
    publication_root_identity = {
        "volume_serial_number": 23,
        "file_id_128": "f" * 32,
    }
    publication_root_identity_hex = {
        "volume_serial_number": f"{publication_root_identity['volume_serial_number']:016x}",
        "file_id_128": publication_root_identity["file_id_128"],
    }
    identity_material = {
        "combined_root_name": "model_zoo_synthetic_combined",
        "combined_root_identity": combined_root_identity,
        "combined_checksums_raw_sha256": "1" * 64,
        "prediction_raw_sha256": activation.prediction_ref.raw_sha256,
        "prediction_semantic_sha256": activation.prediction_semantic_sha256,
        "prediction_semantic_contract": PREDICTION_SEMANTIC_CONTRACT,
        "identity_csv_raw_sha256": "4" * 64,
        "input_binding_raw_sha256": "e" * 64,
        "input_binding_semantic_sha256": "f" * 64,
        "common_root_name": "synthetic_common",
        "common_root_identity": {
            "volume_serial_number": "000000000000000a",
            "file_id_128": "d" * 32,
        },
        "common_checksums_raw_sha256": "5" * 64,
        "postgen_audit_raw_sha256": "6" * 64,
        "postgen_audit_semantic_sha256": "7" * 64,
        "postgen_target_binding_sha256": "8" * 64,
        "postgen_seal_raw_sha256": "9" * 64,
        "c1_c3_binding_root_name": "synthetic_binding",
        "c1_c3_binding_root_identity": {
            "volume_serial_number": "000000000000000b",
            "file_id_128": "a" * 32,
        },
        "c1_c3_prediction_root_name": "synthetic_prefix",
        "c1_c3_prediction_root_identity": {
            "volume_serial_number": "000000000000000c",
            "file_id_128": "b" * 32,
        },
        "c4_surface_root_name": "synthetic_c4",
        "c4_surface_root_identity": {
            "volume_serial_number": "000000000000000d",
            "file_id_128": "c" * 32,
        },
    }
    target_semantic = sha256_bytes(_compact(identity_material)[:-1])
    target_authority = {
        "combined_root_name": identity_material["combined_root_name"],
        "combined_checksums_raw_sha256": identity_material["combined_checksums_raw_sha256"],
        "common_checksums_raw_sha256": identity_material["common_checksums_raw_sha256"],
    }
    claim = {
        "schema_version": PREDICTION_AUDIT_CLAIM_SCHEMA,
        "status": PREDICTION_AUDIT_CLAIM_STATUS,
        "family_id": PREDICTION_AUDIT_FAMILY_ID,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": publication_root_identity_hex,
        "target_authority": target_authority,
        "target_authority_semantic_sha256": sha256_bytes(_compact(target_authority)[:-1]),
        "expected_authorized_output_file_universe": list(PREDICTION_AUDIT_OUTPUT_FILES),
        "authorization_commit_leaf": "AUDIT_SEAL.json",
        "authorization_rule": "EXACT_GO_SEAL_PRESENT_AND_EXACT_FILE_UNIVERSE",
        "publication_protocol": PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
        "root_claimed_create_new": True,
        "root_identity_consumed_even_on_failure": True,
        "retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    claim["claim_semantic_sha256"] = sha256_bytes(_compact(claim)[:-1])
    claim_raw = _compact(claim)
    claim_ref_value = _ref(f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/ATTEMPT_CLAIM.json", 700)
    claim_ref_value["raw_sha256"] = sha256_bytes(claim_raw)
    claim_ref_value["size_bytes"] = len(claim_raw)
    claim_ref = ArtifactRef.from_mapping(claim_ref_value, label="synthetic prediction claim")
    source_ref_value = _ref(
        f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json", 701
    )
    source_ref_value["raw_sha256"] = "3" * 64
    source_ref = ArtifactRef.from_mapping(
        source_ref_value, label="synthetic prediction auditor source"
    )
    audit = {
        "schema_version": PREDICTION_AUDIT_SCHEMA,
        "status": PREDICTION_AUDIT_STATUS,
        "verdict": PREDICTION_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "qualification_task_count": 50,
        "identity_count": 64_800,
        "prediction_row_count": 324_000,
        "model_ids_in_order": list(MODEL_IDS),
        **identity_material,
        "prediction_before_truth": True,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "protected_namespace_open_count": 0,
        "prefix_byte_fields_exact": True,
        "c4_formula_recomputed": True,
        "task_geometry_exact": True,
        "source_model_versions": [
            {"model_id": model_id, "source_model_version": version}
            for model_id, version in activation.source_model_versions
        ],
        "target_binding_semantic_sha256": target_semantic,
        "combination_receipt_raw_sha256": "a" * 64,
        "prediction_manifest_raw_sha256": "b" * 64,
        "runtime_receipt_raw_sha256": "c" * 64,
        "source_manifest_raw_sha256": "2" * 64,
        "prefix_prediction_raw_sha256": "d" * 64,
        "c4_surface_raw_sha256": "e" * 64,
        "source_record_count": PREDICTION_AUDIT_SOURCE_RECORD_COUNT,
        "auditor_source_manifest_raw_sha256": "3" * 64,
        "auditor_source_manifest_semantic_sha256": "4" * 64,
        "auditor_source_manifest_size_bytes": source_ref.size_bytes,
        "auditor_source_manifest_volume_serial_number": (f"{source_ref.volume_serial_number:016x}"),
        "auditor_source_manifest_file_id_128": source_ref.file_id_128,
        "attempt_claim_raw_sha256": claim_ref.raw_sha256,
        "attempt_claim_semantic_sha256": claim["claim_semantic_sha256"],
        "attempt_claim_size_bytes": claim_ref.size_bytes,
        "attempt_claim_volume_serial_number": f"{claim_ref.volume_serial_number:016x}",
        "attempt_claim_file_id_128": claim_ref.file_id_128,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": publication_root_identity_hex,
        "publication_protocol": PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
        "root_claimed_create_new": True,
        "leaf_claims_handle_relative_create_new": True,
        "authorization_commit_leaf": "AUDIT_SEAL.json",
        "authorization_commit_published_last": True,
        "atomic_directory_publish": False,
        "retry_allowed": False,
        "terminal": False,
        "checks": {key: True for key in PREDICTION_AUDIT_CHECK_FIELDS},
        "access": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
            "protected_namespace_open_count": 0,
        },
        "independence": {key: False for key in PREDICTION_AUDIT_INDEPENDENCE_FIELDS},
    }
    audit_raw = _compact(audit)
    object.__setattr__(
        activation.prediction_audit_ref,
        "raw_sha256",
        sha256_bytes(audit_raw),
    )
    object.__setattr__(activation.prediction_audit_ref, "size_bytes", len(audit_raw))
    seal = {
        "schema_version": PREDICTION_AUDIT_SEAL_SCHEMA,
        "status": PREDICTION_AUDIT_SEAL_STATUS,
        "verdict": PREDICTION_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "audit_raw_sha256": sha256_bytes(audit_raw),
        "audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "audit_size_bytes": activation.prediction_audit_ref.size_bytes,
        "audit_volume_serial_number": (
            f"{activation.prediction_audit_ref.volume_serial_number:016x}"
        ),
        "audit_file_id_128": activation.prediction_audit_ref.file_id_128,
        "prediction_freeze_audit_raw_sha256": sha256_bytes(audit_raw),
        "prediction_freeze_audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "prediction_freeze_audit_size_bytes": activation.prediction_audit_ref.size_bytes,
        "prediction_freeze_audit_volume_serial_number": (
            f"{activation.prediction_audit_ref.volume_serial_number:016x}"
        ),
        "prediction_freeze_audit_file_id_128": activation.prediction_audit_ref.file_id_128,
        "prediction_raw_sha256": activation.prediction_ref.raw_sha256,
        "prediction_semantic_sha256": activation.prediction_semantic_sha256,
        "target_binding_semantic_sha256": target_semantic,
        "input_binding_raw_sha256": "e" * 64,
        "input_binding_semantic_sha256": "f" * 64,
        "combined_root_identity": combined_root_identity,
        "combined_checksums_raw_sha256": "1" * 64,
        "auditor_source_manifest_raw_sha256": "3" * 64,
        "combined_root_name": "model_zoo_synthetic_combined",
        "attempt_claim_raw_sha256": claim_ref.raw_sha256,
        "attempt_claim_semantic_sha256": claim["claim_semantic_sha256"],
        "attempt_claim_size_bytes": claim_ref.size_bytes,
        "attempt_claim_volume_serial_number": f"{claim_ref.volume_serial_number:016x}",
        "attempt_claim_file_id_128": claim_ref.file_id_128,
        "auditor_source_manifest_size_bytes": source_ref.size_bytes,
        "auditor_source_manifest_volume_serial_number": (f"{source_ref.volume_serial_number:016x}"),
        "auditor_source_manifest_file_id_128": source_ref.file_id_128,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": publication_root_identity_hex,
        "publication_protocol": PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
        "root_claimed_create_new": True,
        "leaf_claims_handle_relative_create_new": True,
        "all_final_handles_held_no_share_write_delete": True,
        "precommit_tree_reconciled": True,
        "authorization_commit_leaf": "AUDIT_SEAL.json",
        "authorization_commit_published_last": True,
        "authorization_requires_exact_go_seal_and_file_universe": True,
        "atomic_directory_publish": False,
        "retry_allowed": False,
        "terminal": False,
        "audit_output_file_universe": list(PREDICTION_AUDIT_OUTPUT_FILES),
    }
    seal_raw = _compact(seal)
    object.__setattr__(activation.prediction_audit_seal_ref, "raw_sha256", sha256_bytes(seal_raw))
    object.__setattr__(activation.prediction_audit_seal_ref, "size_bytes", len(seal_raw))
    checksums_raw = "".join(
        f"{digest}  {leaf}\n"
        for leaf, digest in sorted(
            {
                "ATTEMPT_CLAIM.json": claim_ref.raw_sha256,
                "AUDIT_SEAL.json": sha256_bytes(seal_raw),
                "AUDITOR_SOURCE_MANIFEST.json": source_ref.raw_sha256,
                "PREDICTION_FREEZE_AUDIT.json": sha256_bytes(audit_raw),
            }.items()
        )
    ).encode("ascii")
    checksums_ref_value = _ref(f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/CHECKSUMS.sha256", 702)
    checksums_ref_value["raw_sha256"] = sha256_bytes(checksums_raw)
    checksums_ref_value["size_bytes"] = len(checksums_raw)
    checksums_ref = ArtifactRef.from_mapping(
        checksums_ref_value, label="synthetic prediction checksum ledger"
    )
    receipt = validate_prediction_audit(
        claim_raw=claim_raw,
        claim_ref=claim_ref,
        audit_raw=audit_raw,
        seal_raw=seal_raw,
        auditor_source_ref=source_ref,
        checksums_raw=checksums_raw,
        checksums_ref=checksums_ref,
        publication_root_identity=publication_root_identity,
        observed_output_file_universe=tuple(PREDICTION_AUDIT_OUTPUT_FILES),
        activation=activation,
    )
    assert receipt["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0}

    audit["truth_open_count"] = 1
    with pytest.raises(QualificationScorerError):
        validate_prediction_audit(
            claim_raw=claim_raw,
            claim_ref=claim_ref,
            audit_raw=_compact(audit),
            seal_raw=seal_raw,
            auditor_source_ref=source_ref,
            checksums_raw=checksums_raw,
            checksums_ref=checksums_ref,
            publication_root_identity=publication_root_identity,
            observed_output_file_universe=tuple(PREDICTION_AUDIT_OUTPUT_FILES),
            activation=activation,
        )


def _synthetic_pre_score_chain(
    *, pre_score_auditor_source_value: str = "spent-source-only"
) -> tuple[Activation, bytes, bytes, bytes, dict[str, object], dict[str, object]]:
    activation = _activation()
    source_refs = [
        _ref(relative, 100 + index) for index, relative in enumerate(SCORER_SOURCE_RELATIVES)
    ]
    for source_ref in source_refs:
        expected = VENDORED_RUNTIME_DEPENDENCY_SHA256.get(str(source_ref["relative_path"]))
        if expected is not None:
            source_ref["raw_sha256"] = expected
    source_refs[-1]["raw_sha256"] = POLICY_RAW_SHA256
    runtime = {
        "implementation": "cpython",
        "version_info": [
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
            sys.version_info.releaselevel,
            sys.version_info.serial,
        ],
        "cache_tag": sys.implementation.cache_tag,
        "executable_final_path": os.path.abspath(sys.executable),
        "executable_raw_sha256": "7" * 64,
        "executable_size_bytes": 123,
        "executable_volume_serial_number": 19,
        "executable_file_id_128": "8" * 32,
        "required_flags_in_order": ["-I", "-S", "-B", "-E"],
    }
    combined = "model_zoo_synthetic_combined"
    common = "model_zoo_synthetic_common"
    chain = {
        "common_run_id": "synthetic_r8_r14",
        "common_root_name": common,
        "common_checksums_ref": _ref(f"outputs/{common}/CHECKSUMS.sha256", 300),
        "common_manifest_ref": _ref(f"outputs/{common}/MANIFEST.json", 301),
        "common_full_identities_ref": _ref(f"outputs/{common}/FULL_IDENTITIES.csv", 302),
        "postgen_audit_ref": _ref("outputs/model_zoo_synthetic_postgen/POSTGEN_AUDIT.json", 303),
        "postgen_audit_seal_ref": _ref("outputs/model_zoo_synthetic_postgen/AUDIT_SEAL.json", 304),
        "postgen_checksums_ref": _ref("outputs/model_zoo_synthetic_postgen/CHECKSUMS.sha256", 305),
        "combined_root_name": combined,
        "combined_checksums_ref": _ref(f"outputs/{combined}/CHECKSUMS.sha256", 306),
        "combined_combination_receipt_ref": _ref(
            f"outputs/{combined}/COMBINATION_RECEIPT.json", 307
        ),
        "combined_input_binding_ref": _ref(f"outputs/{combined}/INPUT_BINDING.json", 308),
        "combined_input_custody_ref": _ref(f"outputs/{combined}/INPUT_CUSTODY_RECEIPT.json", 309),
        "combined_manifest_ref": _ref(f"outputs/{combined}/PREDICTION_MANIFEST.json", 310),
        "combined_runtime_ref": _ref(f"outputs/{combined}/RUNTIME_RECEIPT.json", 311),
        "combined_source_manifest_ref": _ref(f"outputs/{combined}/SOURCE_MANIFEST.json", 312),
        "prediction_ref": activation.prediction_ref.as_mapping(),
        "prediction_audit_ref": activation.prediction_audit_ref.as_mapping(),
        "prediction_audit_seal_ref": activation.prediction_audit_seal_ref.as_mapping(),
        "prediction_auditor_source_manifest_ref": _ref(
            f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json",
            313,
        ),
        "prediction_audit_checksums_ref": _ref(
            f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/CHECKSUMS.sha256", 314
        ),
    }
    target = {
        "schema_version": PRESCORE_TARGET_SCHEMA,
        "status": PRESCORE_TARGET_STATUS,
        "activation_core": dict(activation.activation_core),
        "activation_core_semantic_sha256": activation.activation_core_semantic_sha256,
        "scorer_source_refs": source_refs,
        "python_runtime": runtime,
        "prediction_chain": chain,
        "pre_score_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    target["target_binding_semantic_sha256"] = sha256_bytes(_compact(target)[:-1])
    target_raw = _compact(target)
    object.__setattr__(activation.pre_score_target_ref, "raw_sha256", sha256_bytes(target_raw))
    object.__setattr__(activation.pre_score_target_ref, "size_bytes", len(target_raw))
    target_root_identity = {"volume_serial_number": 41, "file_id_128": "e" * 32}
    target_claim = {
        "schema_version": PRESCORE_TARGET_CLAIM_SCHEMA,
        "status": PRESCORE_TARGET_CLAIM_STATUS,
        "run_id": activation.run_id,
        "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
        "payload_leaf": "PRE_SCORE_TARGET_BINDING.json",
        "target_binding_raw_sha256": sha256_bytes(target_raw),
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_raw_sha256": sha256_bytes(_compact(target["activation_core"])),
        "activation_core_semantic_sha256": activation.activation_core_semantic_sha256,
        "pre_score_audit_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "same_target_retry_allowed": False,
    }
    target_claim["claim_semantic_sha256"] = sha256_bytes(_compact(target_claim)[:-1])
    target_claim_raw = _compact(target_claim)
    target_claim_ref = _ref_for_raw(
        f"outputs/{PRESCORE_TARGET_ROOT_NAME}/ATTEMPT_CLAIM.json", target_claim_raw, 400
    )
    target_publication_seal = {
        "schema_version": PRESCORE_TARGET_PUBLICATION_SEAL_SCHEMA,
        "status": PRESCORE_TARGET_PUBLICATION_SEAL_STATUS,
        "verdict": PRESCORE_TARGET_PUBLICATION_SEAL_STATUS,
        "run_id": activation.run_id,
        "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
        "output_root_volume_serial_number": target_root_identity["volume_serial_number"],
        "output_root_file_id_128": target_root_identity["file_id_128"],
        "attempt_claim_ref": target_claim_ref,
        "target_binding_ref": activation.pre_score_target_ref.as_mapping(),
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_raw_sha256": target_claim["activation_core_raw_sha256"],
        "activation_core_semantic_sha256": activation.activation_core_semantic_sha256,
        "output_file_universe": list(PRESCORE_TARGET_OUTPUT_FILES),
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    target_publication_seal_raw = _compact(target_publication_seal)
    target_publication_seal_ref = _ref_for_raw(
        f"outputs/{PRESCORE_TARGET_ROOT_NAME}/TARGET_PUBLICATION_SEAL.json",
        target_publication_seal_raw,
        401,
    )
    prediction_receipt = {
        "audit_raw_sha256": activation.prediction_audit_ref.raw_sha256,
        "audit_semantic_sha256": "9" * 64,
        "audit_seal_raw_sha256": activation.prediction_audit_seal_ref.raw_sha256,
        "target_binding_semantic_sha256": "a" * 64,
        "combined_root_name": combined,
        "combined_checksums_raw_sha256": chain["combined_checksums_ref"]["raw_sha256"],
        "combination_receipt_raw_sha256": chain["combined_combination_receipt_ref"]["raw_sha256"],
        "input_binding_raw_sha256": chain["combined_input_binding_ref"]["raw_sha256"],
        "prediction_manifest_raw_sha256": chain["combined_manifest_ref"]["raw_sha256"],
        "runtime_receipt_raw_sha256": chain["combined_runtime_ref"]["raw_sha256"],
        "source_manifest_raw_sha256": chain["combined_source_manifest_ref"]["raw_sha256"],
        "common_root_name": common,
        "common_checksums_raw_sha256": chain["common_checksums_ref"]["raw_sha256"],
        "postgen_audit_raw_sha256": chain["postgen_audit_ref"]["raw_sha256"],
        "postgen_audit_semantic_sha256": "b" * 64,
        "postgen_audit_seal_raw_sha256": chain["postgen_audit_seal_ref"]["raw_sha256"],
        "auditor_source_manifest_raw_sha256": chain["prediction_auditor_source_manifest_ref"][
            "raw_sha256"
        ],
        "auditor_source_manifest_semantic_sha256": "d" * 64,
    }
    auditor_source_raw = _compact({"synthetic": pre_score_auditor_source_value})
    auditor_source_ref = _ref_for_raw(
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json",
        auditor_source_raw,
        402,
    )
    auditor_source_semantic = sha256_bytes(auditor_source_raw[:-1])
    source_semantic = sha256_bytes(_compact(source_refs)[:-1])
    runtime_semantic = sha256_bytes(_compact(runtime)[:-1])
    truth_semantic = sha256_bytes(
        _compact([ref.as_mapping() for ref in activation.truth_refs])[:-1]
    )
    audit = {
        "schema_version": PRESCORE_AUDIT_SCHEMA,
        "status": PRESCORE_AUDIT_STATUS,
        "verdict": PRESCORE_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "target_binding_raw_sha256": sha256_bytes(target_raw),
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "target_binding_size_bytes": len(target_raw),
        "target_binding_volume_serial_number": activation.pre_score_target_ref.volume_serial_number,
        "target_binding_file_id_128": activation.pre_score_target_ref.file_id_128,
        "activation_core_semantic_sha256": activation.activation_core_semantic_sha256,
        "scorer_run_id": activation.run_id,
        "scorer_output_relative_path": activation.output_relative_path,
        "vault_relative_path": activation.vault_relative_path,
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "scorer_source_manifest_semantic_sha256": source_semantic,
        "scorer_source_file_count": len(SCORER_SOURCE_RELATIVES),
        "scorer_source_static_checks": {key: True for key in PRESCORE_STATIC_CHECK_FIELDS},
        "python_runtime_binding_semantic_sha256": runtime_semantic,
        "python_executable_raw_sha256": runtime["executable_raw_sha256"],
        "python_executable_volume_serial_number": runtime["executable_volume_serial_number"],
        "python_executable_file_id_128": runtime["executable_file_id_128"],
        "prediction_raw_sha256": activation.prediction_ref.raw_sha256,
        "prediction_semantic_sha256": activation.prediction_semantic_sha256,
        "prediction_audit_raw_sha256": prediction_receipt["audit_raw_sha256"],
        "prediction_audit_semantic_sha256": prediction_receipt["audit_semantic_sha256"],
        "prediction_audit_seal_raw_sha256": prediction_receipt["audit_seal_raw_sha256"],
        "prediction_audit_target_binding_semantic_sha256": prediction_receipt[
            "target_binding_semantic_sha256"
        ],
        "common_run_id": chain["common_run_id"],
        "common_root_name": common,
        "common_checksums_raw_sha256": chain["common_checksums_ref"]["raw_sha256"],
        "common_manifest_raw_sha256": chain["common_manifest_ref"]["raw_sha256"],
        "common_full_identities_raw_sha256": chain["common_full_identities_ref"]["raw_sha256"],
        "common_full_identities_semantic_sha256": activation.common_identity_semantic_sha256,
        "postgen_audit_raw_sha256": chain["postgen_audit_ref"]["raw_sha256"],
        "postgen_audit_semantic_sha256": "b" * 64,
        "postgen_audit_seal_raw_sha256": chain["postgen_audit_seal_ref"]["raw_sha256"],
        "combined_root_name": combined,
        "combined_checksums_raw_sha256": chain["combined_checksums_ref"]["raw_sha256"],
        "combined_input_binding_raw_sha256": chain["combined_input_binding_ref"]["raw_sha256"],
        "combined_manifest_raw_sha256": chain["combined_manifest_ref"]["raw_sha256"],
        "combined_runtime_raw_sha256": chain["combined_runtime_ref"]["raw_sha256"],
        "combined_source_manifest_raw_sha256": chain["combined_source_manifest_ref"]["raw_sha256"],
        "source_model_versions": [
            {"model_id": model_id, "source_model_version": version}
            for model_id, version in activation.source_model_versions
        ],
        "truth_ref_count": 50,
        "truth_ref_inventory_semantic_sha256": truth_semantic,
        "qualification_task_count": 50,
        "identity_count": 64_800,
        "prediction_row_count": 324_000,
        "prediction_before_truth": True,
        "checks": {key: True for key in PRESCORE_CHECK_FIELDS},
        "access": {key: 0 for key in PRESCORE_ACCESS_FIELDS},
        "independence": {key: False for key in PRESCORE_INDEPENDENCE_FIELDS},
        "auditor_source_manifest_raw_sha256": auditor_source_ref["raw_sha256"],
        "auditor_source_manifest_semantic_sha256": auditor_source_semantic,
    }
    audit_raw = _compact(audit)
    object.__setattr__(activation.pre_score_audit_ref, "raw_sha256", sha256_bytes(audit_raw))
    object.__setattr__(activation.pre_score_audit_ref, "size_bytes", len(audit_raw))
    audit_claim = {
        "schema_version": PRESCORE_AUDIT_CLAIM_SCHEMA,
        "status": PRESCORE_AUDIT_CLAIM_STATUS,
        "run_id": activation.run_id,
        "output_root_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "payload_leaf": "PRE_SCORE_AUDIT.json",
        "audit_raw_sha256": sha256_bytes(audit_raw),
        "audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "audit_verdict": PRESCORE_AUDIT_STATUS,
        "target_binding_raw_sha256": sha256_bytes(target_raw),
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "auditor_source_manifest_raw_sha256": auditor_source_ref["raw_sha256"],
        "auditor_source_manifest_semantic_sha256": audit["auditor_source_manifest_semantic_sha256"],
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "same_target_retry_allowed": False,
    }
    audit_claim["claim_semantic_sha256"] = sha256_bytes(_compact(audit_claim)[:-1])
    audit_claim_raw = _compact(audit_claim)
    audit_claim_ref = _ref_for_raw(
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/ATTEMPT_CLAIM.json", audit_claim_raw, 403
    )
    audit_root_identity = {"volume_serial_number": 43, "file_id_128": "f" * 32}
    seal = {
        "schema_version": PRESCORE_AUDIT_SEAL_SCHEMA,
        "status": PRESCORE_AUDIT_SEAL_STATUS,
        "verdict": PRESCORE_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "pre_score_audit_raw_sha256": sha256_bytes(audit_raw),
        "pre_score_audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "pre_score_audit_size_bytes": len(audit_raw),
        "pre_score_audit_volume_serial_number": activation.pre_score_audit_ref.volume_serial_number,
        "pre_score_audit_file_id_128": activation.pre_score_audit_ref.file_id_128,
        "target_binding_raw_sha256": audit["target_binding_raw_sha256"],
        "target_binding_semantic_sha256": audit["target_binding_semantic_sha256"],
        "activation_core_semantic_sha256": audit["activation_core_semantic_sha256"],
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "scorer_source_manifest_semantic_sha256": source_semantic,
        "python_runtime_binding_semantic_sha256": runtime_semantic,
        "prediction_raw_sha256": audit["prediction_raw_sha256"],
        "prediction_semantic_sha256": audit["prediction_semantic_sha256"],
        "prediction_audit_raw_sha256": audit["prediction_audit_raw_sha256"],
        "prediction_audit_seal_raw_sha256": audit["prediction_audit_seal_raw_sha256"],
        "common_root_name": common,
        "common_checksums_raw_sha256": audit["common_checksums_raw_sha256"],
        "postgen_audit_raw_sha256": audit["postgen_audit_raw_sha256"],
        "postgen_audit_seal_raw_sha256": audit["postgen_audit_seal_raw_sha256"],
        "combined_root_name": combined,
        "combined_checksums_raw_sha256": audit["combined_checksums_raw_sha256"],
        "auditor_source_manifest_raw_sha256": audit["auditor_source_manifest_raw_sha256"],
        "audit_output_file_universe": list(PRESCORE_AUDIT_OUTPUT_FILES),
        "attempt_claim_ref": audit_claim_ref,
        "output_root_volume_serial_number": audit_root_identity["volume_serial_number"],
        "output_root_file_id_128": audit_root_identity["file_id_128"],
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    seal_raw = _compact(seal)
    object.__setattr__(activation.pre_score_audit_seal_ref, "raw_sha256", sha256_bytes(seal_raw))
    object.__setattr__(activation.pre_score_audit_seal_ref, "size_bytes", len(seal_raw))
    checksums_raw = "".join(
        f"{digest}  {leaf}\n"
        for leaf, digest in sorted(
            {
                "ATTEMPT_CLAIM.json": audit_claim_ref["raw_sha256"],
                "AUDIT_SEAL.json": sha256_bytes(seal_raw),
                "AUDITOR_SOURCE_MANIFEST.json": auditor_source_ref["raw_sha256"],
                "PRE_SCORE_AUDIT.json": sha256_bytes(audit_raw),
            }.items()
        )
    ).encode("ascii")
    checksums_ref = _ref_for_raw(
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/CHECKSUMS.sha256", checksums_raw, 404
    )
    publication_args: dict[str, object] = {
        "target_claim_raw": target_claim_raw,
        "target_claim_ref": ArtifactRef.from_mapping(target_claim_ref, label="target claim"),
        "target_publication_seal_raw": target_publication_seal_raw,
        "target_publication_seal_ref": ArtifactRef.from_mapping(
            target_publication_seal_ref, label="target publication seal"
        ),
        "target_root_identity": target_root_identity,
        "target_output_file_universe": PRESCORE_TARGET_OUTPUT_FILES,
        "audit_claim_raw": audit_claim_raw,
        "audit_claim_ref": ArtifactRef.from_mapping(audit_claim_ref, label="audit claim"),
        "auditor_source_raw": auditor_source_raw,
        "auditor_source_ref": ArtifactRef.from_mapping(auditor_source_ref, label="auditor source"),
        "checksums_raw": checksums_raw,
        "checksums_ref": ArtifactRef.from_mapping(checksums_ref, label="checksums"),
        "audit_root_identity": audit_root_identity,
        "audit_output_file_universe": PRESCORE_AUDIT_OUTPUT_FILES,
    }
    return activation, target_raw, audit_raw, seal_raw, prediction_receipt, publication_args


def test_pre_score_target_audit_seal_are_exact_source_bound_go_zero() -> None:
    activation, target_raw, audit_raw, seal_raw, prediction_receipt, publication_args = (
        _synthetic_pre_score_chain()
    )
    receipt = validate_pre_score_audit(
        target_raw=target_raw,
        audit_raw=audit_raw,
        seal_raw=seal_raw,
        activation=activation,
        prediction_audit_receipt=prediction_receipt,
        **publication_args,
    )
    assert tuple(ref.relative_path for ref in receipt["source_refs"]) == (SCORER_SOURCE_RELATIVES)
    assert receipt["truth_ref_inventory_semantic_sha256"]

    bad_audit = json.loads(audit_raw)
    bad_audit["access"]["truth_open_count"] = 1
    with pytest.raises(QualificationScorerError):
        validate_pre_score_audit(
            target_raw=target_raw,
            audit_raw=_compact(bad_audit),
            seal_raw=seal_raw,
            activation=activation,
            prediction_audit_receipt=prediction_receipt,
            **publication_args,
        )


def test_distinct_prediction_and_pre_score_auditor_source_semantics_are_valid() -> None:
    activation, target_raw, audit_raw, seal_raw, prediction_receipt, publication_args = (
        _synthetic_pre_score_chain(pre_score_auditor_source_value="distinct-pre-score-component")
    )
    pre_score_audit = json.loads(audit_raw)
    auditor_source_raw = cast(bytes, publication_args["auditor_source_raw"])
    auditor_source_ref = cast(ArtifactRef, publication_args["auditor_source_ref"])
    assert pre_score_audit["auditor_source_manifest_raw_sha256"] == auditor_source_ref.raw_sha256
    assert pre_score_audit["auditor_source_manifest_semantic_sha256"] == sha256_bytes(
        auditor_source_raw[:-1]
    )
    assert (
        pre_score_audit["auditor_source_manifest_raw_sha256"]
        != prediction_receipt["auditor_source_manifest_raw_sha256"]
    )
    assert (
        pre_score_audit["auditor_source_manifest_semantic_sha256"]
        != prediction_receipt["auditor_source_manifest_semantic_sha256"]
    )

    receipt = validate_pre_score_audit(
        target_raw=target_raw,
        audit_raw=audit_raw,
        seal_raw=seal_raw,
        activation=activation,
        prediction_audit_receipt=prediction_receipt,
        **publication_args,
    )
    assert receipt["audit_raw_sha256"] == activation.pre_score_audit_ref.raw_sha256


def _classification(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "pooled_mae_gain": 0.01,
        "pooled_rmse_gain": 0.01,
        "seed_dgp_wins": 35,
        "dgp_mean_wins": 7,
        "worst_dgp_mean_harm": 0.02,
        "worst_seed_dgp_harm": 0.04,
        "p95_non_worse": True,
        "extreme_non_worse": True,
        "joint_tail_failures": 0,
        "specialist_dgp_count": 2,
        "oracle_marginal_gain": 0.01,
        "signed_error_correlation": 0.90,
        "absolute_error_correlation": 0.99,
    }
    values.update(overrides)
    return classify_policy_v2(**values)


def test_policy_v2_precedence_survivor_specialist_diversity_reject() -> None:
    assert _classification()["classification"] == "CERTIFIED_SURVIVOR"
    assert (
        _classification(pooled_mae_gain=0.004, specialist_dgp_count=2)["classification"]
        == "PORTFOLIO_SPECIALIST_CANDIDATE"
    )
    assert (
        _classification(
            pooled_mae_gain=0.004,
            seed_dgp_wins=29,
            specialist_dgp_count=1,
            joint_tail_failures=0,
        )["classification"]
        == "DIVERSITY_CANDIDATE"
    )
    assert _classification(pooled_mae_gain=0.0)["classification"] == "REJECTED"


def test_policy_v2_full_synthetic_score_freezes_ranks_and_c5_null_row() -> None:
    identities = []
    champion_errors = []
    for seed_alias in (f"qualification_seed_{index:02d}" for index in range(1, 6)):
        for dgp in DGP_IDS:
            for position in range(504, 1800):
                fold_number = 12 + (position - 504) // 21
                test_start = 504 + (fold_number - 12) * 21
                identities.append(
                    (
                        seed_alias,
                        dgp,
                        position,
                        "2020-01-01",
                        "DGP_ISSUER",
                        f"fold_{fold_number:03d}",
                        test_start - 1,
                        test_start,
                    )
                )
                champion_errors.append(0.10 + ((position - 504) % 7) * 0.001)
    factors = dict(zip(MODEL_IDS, (1.0, 0.90, 0.95, 1.05, 0.80), strict=True))
    predictions = DecodedPredictions(
        identities=tuple(identities),
        expected_log_pe=tuple(
            (
                model_id,
                tuple(value * factors[model_id] for value in champion_errors),
            )
            for model_id in MODEL_IDS
        ),
        common_identity_semantic_sha256="e" * 64,
    )
    truth = DecodedTruth(
        true_log_fair_pe=(0.0,) * len(identities),
        eligible=(True,) * len(identities),
    )
    score = score_qualification(
        predictions=predictions,
        truth=truth,
        source_model_versions={
            model_id: f"sha256:{index + 1:064x}" for index, model_id in enumerate(MODEL_IDS)
        },
        prediction_audit_raw_sha256="f" * 64,
    ).payload
    decisions = {row["candidate_id"]: row for row in score["decisions"]}
    assert decisions[MODEL_IDS[1]]["classification"] == "CERTIFIED_SURVIVOR"
    assert decisions[MODEL_IDS[2]]["classification"] == "CERTIFIED_SURVIVOR"
    assert decisions[MODEL_IDS[3]]["classification"] == "REJECTED"
    assert decisions[MODEL_IDS[4]]["classification"] == "CERTIFIED_SURVIVOR"
    freeze = score["survivor_role_ranking_freeze"]
    assert freeze["certified_survivor_ids_in_rank_order"] == [
        MODEL_IDS[4],
        MODEL_IDS[1],
        MODEL_IDS[2],
    ]
    assert freeze["heldout_authority"] is False
    assert freeze["qualification_results_mutable"] is False
    c5 = score["scorecard"][-1]
    assert c5["candidate_id"] == "cvtcn_v8_private_process_tcn_residual"
    assert c5["fresh_qualification_status"] == "NOT_RUN_TERMINAL_CUSTODY_NO_GO"
    numeric_or_safety = tuple(c5)[6:29]
    assert all(c5[key] is None for key in numeric_or_safety if key != "deployable")
    assert c5["deployable"] is False


def test_atomic_create_new_is_no_replace_and_byte_stable(tmp_path: Path) -> None:
    raw = canonical_json_bytes({"heldout_authority": False, "status": "SYNTHETIC"})
    parent = HeldWritableDirectory.open(tmp_path)
    try:
        published = publish_atomic_create_new(
            parent=parent,
            final_leaf="SYNTHETIC_RESULT.json",
            raw=raw,
        )
        published.assert_live()
        with pytest.raises(PermissionError):
            os.replace(
                tmp_path / "SYNTHETIC_RESULT.json",
                tmp_path / "ATTACKER_RENAMED.json",
            )
        with pytest.raises(PermissionError):
            (tmp_path / "SYNTHETIC_RESULT.json").write_bytes(b"attacker")
        published.close()
        assert (tmp_path / "SYNTHETIC_RESULT.json").read_bytes() == raw
        with pytest.raises(QualificationScorerError):
            publish_atomic_create_new(
                parent=parent,
                final_leaf="SYNTHETIC_RESULT.json",
                raw=raw,
            )
    finally:
        parent.close()


def test_direct_final_inode_cannot_be_swapped_during_handle_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = publication_module._write_flush_and_verify

    def adversarial_write(*, handle: int, raw: bytes, raw_sha256: str) -> None:
        final = tmp_path / "SYNTHETIC_RESULT.json"
        assert final.is_file()
        with pytest.raises(PermissionError):
            os.replace(final, tmp_path / "ATTACKER_STOLEN_FINAL.json")
        with pytest.raises(PermissionError):
            final.write_bytes(b"attacker")
        original(handle=handle, raw=raw, raw_sha256=raw_sha256)

    monkeypatch.setattr(publication_module, "_write_flush_and_verify", adversarial_write)
    parent = HeldWritableDirectory.open(tmp_path)
    published = None
    try:
        published = publish_atomic_create_new(
            parent=parent,
            final_leaf="SYNTHETIC_RESULT.json",
            raw=b"held exact bytes",
        )
        published.assert_live()
    finally:
        if published is not None:
            published.close()
        parent.close()
    assert (tmp_path / "SYNTHETIC_RESULT.json").read_bytes() == b"held exact bytes"


def test_direct_final_post_create_failure_consumes_identity_without_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def injected_failure(*, handle: int, raw: bytes, raw_sha256: str) -> None:
        del handle, raw, raw_sha256
        raise QualificationScorerError("synthetic post-create write failure")

    monkeypatch.setattr(
        publication_module,
        "_write_flush_and_verify",
        injected_failure,
    )
    parent = HeldWritableDirectory.open(tmp_path)
    published = None
    try:
        with pytest.raises(PublicationCommittedError) as caught:
            publish_atomic_create_new(
                parent=parent,
                final_leaf="SYNTHETIC_PARTIAL.json",
                raw=b"must not be retried",
            )
        published = caught.value.published
        assert published.committed is True
        assert published.verified is False
        assert (tmp_path / "SYNTHETIC_PARTIAL.json").exists()
        with pytest.raises(QualificationScorerError):
            publish_atomic_create_new(
                parent=parent,
                final_leaf="SYNTHETIC_PARTIAL.json",
                raw=b"retry forbidden",
            )
    finally:
        if published is not None:
            published.close()
        parent.close()


def test_held_outputs_parent_allows_only_one_direct_root_claim(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    parent = HeldWritableDirectory.open(outputs)
    claimed: HeldWritableDirectory | None = None
    published = None
    try:
        claimed = claim_output_root(
            outputs / "model_zoo_synthetic_claim",
            project_root=tmp_path,
            outputs_parent=parent,
        )
        assert claimed.path.is_dir()
        claimed.assert_live()
        with pytest.raises(PermissionError):
            os.replace(claimed.path, outputs / "model_zoo_attacker_swapped")
        published = publish_atomic_create_new(
            parent=claimed,
            final_leaf="HANDLE_RELATIVE_ONLY.json",
            raw=b"held parent write",
        )
        published.assert_live()
        with pytest.raises(QualificationScorerError):
            claim_output_root(
                claimed.path,
                project_root=tmp_path,
                outputs_parent=parent,
            )
    finally:
        if published is not None:
            published.close()
        if claimed is not None:
            claimed.close()
        parent.close()


def test_r4_actual_outputs_topology_reuses_parent_prediction_fifty_truth_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    public_root = outputs / "synthetic_frozen_publication"
    public_root.mkdir(parents=True)
    (public_root / "GO.json").write_bytes(b"synthetic public GO\n")
    prediction_path = outputs / "synthetic_combined/PREDICTIONS.csv"
    prediction_path.parent.mkdir()
    prediction_path.write_bytes(b"synthetic prediction before marker\n")
    prediction_ref = ArtifactRef.from_mapping(
        _native_ref(
            prediction_path,
            relative_path="outputs/synthetic_combined/PREDICTIONS.csv",
        ),
        label="synthetic prediction",
    )
    vault_relative = "outputs/.model_zoo_synthetic_qualification_vault_spent"
    truth_refs: list[ArtifactRef] = []
    for index, (seed, dgp) in enumerate(
        (seed, dgp) for seed in QUALIFICATION_SEEDS for dgp in DGP_IDS
    ):
        relative = f"{vault_relative}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv"
        path = tmp_path / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(f"synthetic truth {index:02d} after marker\n".encode("ascii"))
        truth_refs.append(
            ArtifactRef.from_mapping(
                _native_ref(path, relative_path=relative),
                label=f"synthetic truth/{index}",
            )
        )
    outputs_parent = HeldWritableDirectory.open(outputs)
    result_root: HeldWritableDirectory | None = None
    marker = None
    result = None
    public_handles: list[int] = []
    prediction_held: list[HeldArtifact] = []
    truth_held: list[HeldArtifact] = []
    events: list[str] = []
    native_open = runner_module._open_native_held

    def reject_outputs_parent_reopen(path: Path, *, directory: bool):  # type: ignore[no-untyped-def]
        if Path(os.path.abspath(path)) == Path(os.path.abspath(outputs)):
            raise AssertionError("restrictive outputs parent was redundantly reopened")
        return native_open(path, directory=directory)

    monkeypatch.setattr(runner_module, "_open_native_held", reject_outputs_parent_reopen)
    try:
        result_root = claim_output_root(
            outputs / SCORER_OUTPUT_ROOT_NAME,
            project_root=tmp_path,
            outputs_parent=outputs_parent,
        )
        public_handles, raws, _, _ = runner_module._hold_fixed_public_root(
            project_root=tmp_path,
            root_relative_path="outputs/synthetic_frozen_publication",
            expected_leaves=("GO.json",),
            held_outputs_parent=outputs_parent,
        )
        assert raws == {"GO.json": b"synthetic public GO\n"}
        prediction_held = runner_module._open_held(
            tmp_path, (prediction_ref,), outputs_parent=outputs_parent
        )
        assert prediction_held[0].raw_bytes() == b"synthetic prediction before marker\n"
        events.append("prediction")
        marker = publish_atomic_create_new(
            parent=result_root,
            final_leaf=CONSUMPTION_MARKER_LEAF,
            raw=b"synthetic durable marker\n",
        )
        marker.assert_live()
        events.append("marker")
        truth_held = runner_module._open_held(tmp_path, truth_refs, outputs_parent=outputs_parent)
        assert len(truth_held) == 50
        assert all(row.raw_bytes().startswith(b"synthetic truth ") for row in truth_held)
        for row in [*prediction_held, *truth_held]:
            receipt = row.receipt()
            assert receipt["outputs_parent_reused_without_reopen"] is True
            assert (
                receipt["outputs_parent_volume_serial_number"]
                == outputs_parent.volume_serial_number
            )
            assert receipt["outputs_parent_file_id_128"] == outputs_parent.file_id_128
            assert cast(int, receipt["ancestor_count"]) >= 1
            row.assert_live()
        events.append("truth")
        result = publish_atomic_create_new(
            parent=result_root,
            final_leaf=RESULT_LEAF,
            raw=b"synthetic frozen result\n",
        )
        result.assert_live()
        events.append("result")
        outputs_parent.assert_live()
        result_root.assert_live()
        for row in [*prediction_held, *truth_held]:
            row.assert_live()
        assert events == ["prediction", "marker", "truth", "result"]
        assert tuple(sorted(path.name for path in result_root.path.iterdir())) == (
            CONSUMPTION_MARKER_LEAF,
            RESULT_LEAF,
        )
    finally:
        runner_module._close_held(truth_held)
        runner_module._close_held(prediction_held)
        for handle in reversed(public_handles):
            _close_native_handle(handle)
        if result is not None:
            result.close()
        if marker is not None:
            marker.close()
        if result_root is not None:
            result_root.close()
        outputs_parent.close()


def test_output_claim_rolls_back_exact_created_inode_when_binding_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    target = outputs / "model_zoo_synthetic_failed_claim"
    parent = HeldWritableDirectory.open(outputs)
    original = HeldWritableDirectory._from_handle.__func__

    def injected_failure(
        cls: type[HeldWritableDirectory], path: Path, handle: int
    ) -> HeldWritableDirectory:
        if path == target:
            with pytest.raises((FileNotFoundError, PermissionError)):
                (target / "ATTACKER.json").write_bytes(b"attacker")
            raise QualificationScorerError("synthetic post-create binding failure")
        return original(cls, path, handle)

    monkeypatch.setattr(
        HeldWritableDirectory,
        "_from_handle",
        classmethod(injected_failure),
    )
    try:
        with pytest.raises(
            QualificationScorerError,
            match="synthetic post-create binding failure",
        ):
            claim_output_root(
                target,
                project_root=tmp_path,
                outputs_parent=parent,
            )
        assert not target.exists()
    finally:
        parent.close()


def test_runner_orders_marker_before_only_fixed_truth_open() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/runner.py"
    ).read_text(encoding="utf-8")
    marker = source.index("final_leaf=CONSUMPTION_MARKER_LEAF")
    truth = source.index("\n        truth_held = _open_held(")
    assert marker < truth
    assert 'latent_open_count": 0' in source
    assert 'pass_2_open_count": 0' in source
    assert 'heldout_authority": False' in source
    assert "heldout" not in source[source.index("def run_once(") : source.index(") -> Path:")]
    prescore = source.index("pre_score_receipt = validate_pre_score_audit(")
    source_hold = source.index("source_held = _open_held(")
    assert prescore < source_hold < marker < truth
    result_guard = source.index("if result_committed:", truth)
    terminal_failure = source.index("failure = _publish_failure(", result_guard)
    assert result_guard < terminal_failure
    assert "terminal failure leaf is forbidden" in source[result_guard:terminal_failure]
    assert PRESCORE_AUDIT_INTEGRATED is True


def test_launcher_holds_frozen_sources_and_uses_only_held_byte_loader() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "scripts/model_lab/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/run_once.py"
    ).read_text(encoding="utf-8")
    bootstrap = source.index("held, _ = _bootstrap_source_custody(")
    scorer_import = source.index("importlib.import_module(", bootstrap)
    assert bootstrap < scorer_import
    assert "class _HeldSourceLoader:" in source
    assert "compile(raw," in source
    assert "sys.meta_path.insert(" in source
    bootstrap_function = source[
        source.index("def _bootstrap_source_custody(") : source.index("def main()")
    ]
    assert "_hold_file_with_ancestors(" in bootstrap_function
    assert "_assert_held(held)" in bootstrap_function
    assert ".read_bytes()" not in bootstrap_function
    assert "custody.HeldArtifact" not in source
    assert "from research." not in source
    first_import = source.index("import sys")
    isolation_gate = source.index("sys.flags.isolated", first_import)
    argparse_import = source.index("import argparse")
    assert first_import < isolation_gate < argparse_import


def test_direct_launcher_invocation_is_not_an_authority_path(tmp_path: Path) -> None:
    launcher = (
        Path(__file__).resolve().parents[2]
        / "scripts/model_lab/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/run_once.py"
    )
    absent_prefix = tmp_path / "must_remain_absent"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={absent_prefix}",
            str(launcher),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "external held-byte launcher trust anchor" in completed.stderr
    assert not absent_prefix.exists()


def test_launcher_valid_go_bootstrap_holds_exact_sources_before_import(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    synthetic = tmp_path / "synthetic_repository"
    for relative in SCORER_SOURCE_RELATIVES:
        source = repository / relative
        destination = synthetic / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    source_refs = [
        _native_ref(synthetic / relative, relative_path=relative)
        for relative in SCORER_SOURCE_RELATIVES
    ]

    activation_value = _activation_value()
    _, template_target_raw, template_audit_raw, template_seal_raw, _, _ = (
        _synthetic_pre_score_chain()
    )
    target = json.loads(template_target_raw.decode("ascii"))
    target["activation_core"] = {field: activation_value[field] for field in ACTIVATION_CORE_FIELDS}
    target["activation_core_semantic_sha256"] = activation_value["activation_core_semantic_sha256"]
    target["scorer_source_refs"] = source_refs
    executable = Path(sys.executable)
    executable_ref = _native_ref(executable, relative_path="bootstrap-runtime-only")
    runtime = {
        "implementation": "cpython",
        "version_info": list(sys.version_info),
        "cache_tag": sys.implementation.cache_tag,
        "executable_final_path": os.path.abspath(sys.executable),
        "executable_raw_sha256": executable_ref["raw_sha256"],
        "executable_size_bytes": executable_ref["size_bytes"],
        "executable_volume_serial_number": executable_ref["volume_serial_number"],
        "executable_file_id_128": executable_ref["file_id_128"],
        "required_flags_in_order": ["-I", "-S", "-B", "-E"],
    }
    target["python_runtime"] = runtime
    target["pre_score_output_relative_path"] = f"outputs/{PRESCORE_AUDIT_ROOT_NAME}"
    target.pop("target_binding_semantic_sha256")
    target["target_binding_semantic_sha256"] = sha256_bytes(_compact(target)[:-1])
    target_root = synthetic / f"outputs/{PRESCORE_TARGET_ROOT_NAME}"
    audit_root = synthetic / f"outputs/{PRESCORE_AUDIT_ROOT_NAME}"
    activation_root = synthetic / f"outputs/{ACTIVATION_OUTPUT_ROOT_NAME}"
    for root in (target_root, audit_root, activation_root):
        root.mkdir(parents=True)
    target_path = target_root / "PRE_SCORE_TARGET_BINDING.json"
    target_path.write_bytes(_compact(target))
    target_ref = _native_ref(
        target_path,
        relative_path=f"outputs/{PRESCORE_TARGET_ROOT_NAME}/PRE_SCORE_TARGET_BINDING.json",
    )
    target_claim = {
        "schema_version": PRESCORE_TARGET_CLAIM_SCHEMA,
        "status": PRESCORE_TARGET_CLAIM_STATUS,
        "run_id": activation_value["run_id"],
        "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
        "payload_leaf": "PRE_SCORE_TARGET_BINDING.json",
        "target_binding_raw_sha256": target_ref["raw_sha256"],
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_raw_sha256": sha256_bytes(_compact(target["activation_core"])),
        "activation_core_semantic_sha256": activation_value["activation_core_semantic_sha256"],
        "pre_score_audit_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "same_target_retry_allowed": False,
    }
    target_claim["claim_semantic_sha256"] = sha256_bytes(_compact(target_claim)[:-1])
    target_claim_path = target_root / "ATTEMPT_CLAIM.json"
    target_claim_path.write_bytes(_compact(target_claim))
    target_claim_ref = _native_ref(
        target_claim_path,
        relative_path=f"outputs/{PRESCORE_TARGET_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    target_root_identity = _native_identity(target_root)
    target_publication_seal = {
        "schema_version": PRESCORE_TARGET_PUBLICATION_SEAL_SCHEMA,
        "status": PRESCORE_TARGET_PUBLICATION_SEAL_STATUS,
        "verdict": PRESCORE_TARGET_PUBLICATION_SEAL_STATUS,
        "run_id": activation_value["run_id"],
        "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
        "output_root_volume_serial_number": target_root_identity["volume_serial_number"],
        "output_root_file_id_128": target_root_identity["file_id_128"],
        "attempt_claim_ref": target_claim_ref,
        "target_binding_ref": target_ref,
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_raw_sha256": target_claim["activation_core_raw_sha256"],
        "activation_core_semantic_sha256": activation_value["activation_core_semantic_sha256"],
        "output_file_universe": list(PRESCORE_TARGET_OUTPUT_FILES),
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    (target_root / "TARGET_PUBLICATION_SEAL.json").write_bytes(_compact(target_publication_seal))

    chain = target["prediction_chain"]
    source_semantic = sha256_bytes(_compact(source_refs)[:-1])
    runtime_semantic = sha256_bytes(_compact(runtime)[:-1])
    truth_semantic = sha256_bytes(_compact(activation_value["truth_refs"])[:-1])
    audit = json.loads(template_audit_raw.decode("ascii"))
    audit.update(
        {
            "target_binding_raw_sha256": target_ref["raw_sha256"],
            "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
            "target_binding_size_bytes": target_ref["size_bytes"],
            "target_binding_volume_serial_number": target_ref["volume_serial_number"],
            "target_binding_file_id_128": target_ref["file_id_128"],
            "activation_core_semantic_sha256": activation_value["activation_core_semantic_sha256"],
            "scorer_run_id": activation_value["run_id"],
            "scorer_output_relative_path": activation_value["output_relative_path"],
            "vault_relative_path": activation_value["vault_relative_path"],
            "scorer_source_manifest_semantic_sha256": source_semantic,
            "scorer_source_file_count": len(SCORER_SOURCE_RELATIVES),
            "python_runtime_binding_semantic_sha256": runtime_semantic,
            "python_executable_raw_sha256": executable_ref["raw_sha256"],
            "python_executable_volume_serial_number": executable_ref["volume_serial_number"],
            "python_executable_file_id_128": executable_ref["file_id_128"],
            "prediction_raw_sha256": activation_value["prediction_ref"]["raw_sha256"],
            "prediction_semantic_sha256": activation_value["prediction_semantic_sha256"],
            "prediction_audit_raw_sha256": activation_value["prediction_audit_ref"]["raw_sha256"],
            "prediction_audit_seal_raw_sha256": activation_value["prediction_audit_seal_ref"][
                "raw_sha256"
            ],
            "common_run_id": chain["common_run_id"],
            "common_root_name": chain["common_root_name"],
            "common_checksums_raw_sha256": chain["common_checksums_ref"]["raw_sha256"],
            "common_manifest_raw_sha256": chain["common_manifest_ref"]["raw_sha256"],
            "common_full_identities_raw_sha256": chain["common_full_identities_ref"]["raw_sha256"],
            "common_full_identities_semantic_sha256": activation_value[
                "common_full_identities_semantic_sha256"
            ],
            "postgen_audit_raw_sha256": chain["postgen_audit_ref"]["raw_sha256"],
            "postgen_audit_seal_raw_sha256": chain["postgen_audit_seal_ref"]["raw_sha256"],
            "combined_root_name": chain["combined_root_name"],
            "combined_checksums_raw_sha256": chain["combined_checksums_ref"]["raw_sha256"],
            "combined_input_binding_raw_sha256": chain["combined_input_binding_ref"]["raw_sha256"],
            "combined_manifest_raw_sha256": chain["combined_manifest_ref"]["raw_sha256"],
            "combined_runtime_raw_sha256": chain["combined_runtime_ref"]["raw_sha256"],
            "combined_source_manifest_raw_sha256": chain["combined_source_manifest_ref"][
                "raw_sha256"
            ],
            "source_model_versions": [
                {
                    "model_id": model_id,
                    "source_model_version": activation_value["source_model_versions"][model_id],
                }
                for model_id in MODEL_IDS
            ],
            "truth_ref_inventory_semantic_sha256": truth_semantic,
        }
    )
    audit_path = audit_root / "PRE_SCORE_AUDIT.json"
    audit_path.write_bytes(_compact(audit))
    audit_ref = _native_ref(
        audit_path, relative_path=f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/PRE_SCORE_AUDIT.json"
    )
    auditor_source_path = audit_root / "AUDITOR_SOURCE_MANIFEST.json"
    auditor_source_path.write_bytes(_compact({"synthetic": "spent-source-only"}))
    auditor_source_ref = _native_ref(
        auditor_source_path,
        relative_path=f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json",
    )
    audit["auditor_source_manifest_raw_sha256"] = auditor_source_ref["raw_sha256"]
    audit_path.write_bytes(_compact(audit))
    audit_ref = _native_ref(
        audit_path, relative_path=f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/PRE_SCORE_AUDIT.json"
    )
    audit_claim = {
        "schema_version": PRESCORE_AUDIT_CLAIM_SCHEMA,
        "status": PRESCORE_AUDIT_CLAIM_STATUS,
        "run_id": activation_value["run_id"],
        "output_root_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "payload_leaf": "PRE_SCORE_AUDIT.json",
        "audit_raw_sha256": audit_ref["raw_sha256"],
        "audit_semantic_sha256": sha256_bytes(_compact(audit)[:-1]),
        "audit_verdict": PRESCORE_AUDIT_STATUS,
        "target_binding_raw_sha256": target_ref["raw_sha256"],
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "auditor_source_manifest_raw_sha256": auditor_source_ref["raw_sha256"],
        "auditor_source_manifest_semantic_sha256": audit["auditor_source_manifest_semantic_sha256"],
        "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "same_target_retry_allowed": False,
    }
    audit_claim["claim_semantic_sha256"] = sha256_bytes(_compact(audit_claim)[:-1])
    audit_claim_path = audit_root / "ATTEMPT_CLAIM.json"
    audit_claim_path.write_bytes(_compact(audit_claim))
    audit_claim_ref = _native_ref(
        audit_claim_path,
        relative_path=f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    audit_root_identity = _native_identity(audit_root)

    seal = json.loads(template_seal_raw.decode("ascii"))
    seal.update(
        {
            "pre_score_audit_raw_sha256": audit_ref["raw_sha256"],
            "pre_score_audit_semantic_sha256": sha256_bytes(_compact(audit)[:-1]),
            "pre_score_audit_size_bytes": audit_ref["size_bytes"],
            "pre_score_audit_volume_serial_number": audit_ref["volume_serial_number"],
            "pre_score_audit_file_id_128": audit_ref["file_id_128"],
            "audit_output_file_universe": list(PRESCORE_AUDIT_OUTPUT_FILES),
            "attempt_claim_ref": audit_claim_ref,
            "output_root_volume_serial_number": audit_root_identity["volume_serial_number"],
            "output_root_file_id_128": audit_root_identity["file_id_128"],
            "publication_protocol": PRESCORE_PUBLICATION_PROTOCOL,
            "attempt_claim_published_first": True,
            "seal_published_last": True,
            "same_target_retry_allowed": False,
        }
    )
    for field in (
        "target_binding_raw_sha256",
        "target_binding_semantic_sha256",
        "activation_core_semantic_sha256",
        "policy_raw_sha256",
        "scorer_source_manifest_semantic_sha256",
        "python_runtime_binding_semantic_sha256",
        "prediction_raw_sha256",
        "prediction_semantic_sha256",
        "prediction_audit_raw_sha256",
        "prediction_audit_seal_raw_sha256",
        "common_root_name",
        "common_checksums_raw_sha256",
        "postgen_audit_raw_sha256",
        "postgen_audit_seal_raw_sha256",
        "combined_root_name",
        "combined_checksums_raw_sha256",
        "auditor_source_manifest_raw_sha256",
    ):
        seal[field] = audit[field]
    seal_path = audit_root / "AUDIT_SEAL.json"
    seal_path.write_bytes(_compact(seal))
    seal_ref = _native_ref(
        seal_path, relative_path=f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/AUDIT_SEAL.json"
    )
    checksums_raw = "".join(
        f"{digest}  {leaf}\n"
        for leaf, digest in sorted(
            {
                "ATTEMPT_CLAIM.json": audit_claim_ref["raw_sha256"],
                "AUDIT_SEAL.json": seal_ref["raw_sha256"],
                "AUDITOR_SOURCE_MANIFEST.json": auditor_source_ref["raw_sha256"],
                "PRE_SCORE_AUDIT.json": audit_ref["raw_sha256"],
            }.items()
        )
    ).encode("ascii")
    (audit_root / "CHECKSUMS.sha256").write_bytes(checksums_raw)

    activation_value["pre_score_target_ref"] = target_ref
    activation_value["pre_score_audit_ref"] = audit_ref
    activation_value["pre_score_audit_seal_ref"] = seal_ref
    activation_path = activation_root / "QUALIFICATION_ACTIVATION.json"
    activation_raw = canonical_json_bytes(activation_value)
    activation_path.write_bytes(activation_raw)
    activation_ref = _native_ref(
        activation_path,
        relative_path=f"outputs/{ACTIVATION_OUTPUT_ROOT_NAME}/QUALIFICATION_ACTIVATION.json",
    )
    activation_claim = {
        "schema_version": ACTIVATION_CLAIM_SCHEMA,
        "status": ACTIVATION_CLAIM_STATUS,
        "run_id": activation_value["run_id"],
        "output_root_relative_path": f"outputs/{ACTIVATION_OUTPUT_ROOT_NAME}",
        "payload_leaf": "QUALIFICATION_ACTIVATION.json",
        "activation_raw_sha256": activation_ref["raw_sha256"],
        "activation_semantic_sha256": sha256_bytes(_compact(activation_value)[:-1]),
        "activation_core_semantic_sha256": activation_value["activation_core_semantic_sha256"],
        "pre_score_target_raw_sha256": target_ref["raw_sha256"],
        "pre_score_audit_raw_sha256": audit_ref["raw_sha256"],
        "pre_score_audit_seal_raw_sha256": seal_ref["raw_sha256"],
        "publication_protocol": ACTIVATION_PUBLICATION_PROTOCOL,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "same_target_retry_allowed": False,
    }
    activation_claim["claim_semantic_sha256"] = sha256_bytes(_compact(activation_claim)[:-1])
    activation_claim_path = activation_root / "ATTEMPT_CLAIM.json"
    activation_claim_path.write_bytes(_compact(activation_claim))
    activation_claim_ref = _native_ref(
        activation_claim_path,
        relative_path=f"outputs/{ACTIVATION_OUTPUT_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    activation_root_identity = _native_identity(activation_root)
    activation_publication_seal = {
        "schema_version": ACTIVATION_PUBLICATION_SEAL_SCHEMA,
        "status": ACTIVATION_PUBLICATION_SEAL_STATUS,
        "verdict": ACTIVATION_PUBLICATION_SEAL_STATUS,
        "run_id": activation_value["run_id"],
        "output_root_relative_path": f"outputs/{ACTIVATION_OUTPUT_ROOT_NAME}",
        "output_root_volume_serial_number": activation_root_identity["volume_serial_number"],
        "output_root_file_id_128": activation_root_identity["file_id_128"],
        "attempt_claim_ref": activation_claim_ref,
        "activation_ref": activation_ref,
        "activation_raw_sha256": activation_ref["raw_sha256"],
        "activation_semantic_sha256": activation_claim["activation_semantic_sha256"],
        "activation_core_semantic_sha256": activation_value["activation_core_semantic_sha256"],
        "pre_score_target_raw_sha256": target_ref["raw_sha256"],
        "pre_score_audit_raw_sha256": audit_ref["raw_sha256"],
        "pre_score_audit_seal_raw_sha256": seal_ref["raw_sha256"],
        "output_file_universe": list(ACTIVATION_OUTPUT_FILES),
        "publication_protocol": ACTIVATION_PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    (activation_root / "ACTIVATION_SEAL.json").write_bytes(_compact(activation_publication_seal))

    launcher = (
        synthetic
        / "scripts/model_lab/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/run_once.py"
    )
    runner_source = (
        synthetic
        / "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/runner.py"
    )
    malicious = compile(
        "raise RuntimeError('MALICIOUS_PYC_EXECUTED')\n",
        str(runner_source),
        "exec",
    )
    malicious_pyc = bootstrap_external._code_to_hash_pyc(
        malicious,
        importlib.util.source_hash(runner_source.read_bytes()),
        checked=False,
    )
    repository_cache = Path(importlib.util.cache_from_source(str(runner_source)))
    repository_cache.parent.mkdir(parents=True, exist_ok=True)
    repository_cache.write_bytes(malicious_pyc)
    # Keep the prefix itself short: CPython mirrors the source's absolute path
    # below pycache_prefix and legacy Win32 APIs still reject overlong names.
    hostile_prefix = Path(tmp_path.anchor) / (f"qpyc-{os.getpid()}-{os.urandom(8).hex()}")
    prior_prefix = sys.pycache_prefix
    try:
        sys.pycache_prefix = str(hostile_prefix)
        hostile_cache = Path(importlib.util.cache_from_source(str(runner_source)))
    finally:
        sys.pycache_prefix = prior_prefix
    hostile_cache.parent.mkdir(parents=True, exist_ok=True)
    hostile_cache.write_bytes(malicious_pyc)
    code = """
import ctypes
import importlib
from ctypes import wintypes
import hashlib
import ntpath
import os
from pathlib import Path
import sys
import types
if (sys.flags.isolated, sys.flags.no_site, sys.flags.ignore_environment, sys.dont_write_bytecode) != (1, 1, 1, True):
    raise SystemExit("bad flags")
path = os.path.abspath(sys.argv[1])
expected = sys.argv[2]
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.argtypes = (wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE)
k.CreateFileW.restype = wintypes.HANDLE
k.GetFileSizeEx.argtypes = (wintypes.HANDLE,ctypes.POINTER(ctypes.c_longlong))
k.GetFileSizeEx.restype = wintypes.BOOL
k.ReadFile.argtypes = (wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID)
k.ReadFile.restype = wintypes.BOOL
k.GetFileInformationByHandleEx.argtypes = (wintypes.HANDLE,ctypes.c_int,wintypes.LPVOID,wintypes.DWORD)
k.GetFileInformationByHandleEx.restype = wintypes.BOOL
k.GetFinalPathNameByHandleW.argtypes = (wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD)
k.GetFinalPathNameByHandleW.restype = wintypes.DWORD
k.CloseHandle.argtypes = (wintypes.HANDLE,)
k.CloseHandle.restype = wintypes.BOOL
class Tag(ctypes.Structure):
    _fields_ = (("attributes",wintypes.DWORD),("tag",wintypes.DWORD))
def path_key(value):
    normalized = ntpath.normcase(ntpath.normpath(value))
    slash = chr(92)
    device_prefix = slash * 2 + "?" + slash
    unc_prefix = device_prefix + "unc" + slash
    if normalized.startswith(unc_prefix):
        return slash * 2 + normalized[len(unc_prefix):]
    if normalized.startswith(device_prefix):
        return normalized[len(device_prefix):]
    return normalized
handle = k.CreateFileW(path,0x80000000|0x80|0x100000,1,None,3,0x00200000,None)
numeric = int(handle or 0)
if numeric in (0,ctypes.c_void_p(-1).value):
    raise SystemExit("launcher hold failed")
try:
    tag = Tag()
    if not k.GetFileInformationByHandleEx(wintypes.HANDLE(numeric),9,ctypes.byref(tag),ctypes.sizeof(tag)) or tag.attributes & 0x410:
        raise SystemExit("launcher kind/reparse differs")
    final_buffer = ctypes.create_unicode_buffer(32768)
    final_length = k.GetFinalPathNameByHandleW(wintypes.HANDLE(numeric),final_buffer,len(final_buffer),0)
    if final_length == 0 or final_length >= len(final_buffer) or path_key(final_buffer.value) != path_key(path):
        raise SystemExit("launcher final path differs")
    size = ctypes.c_longlong()
    if not k.GetFileSizeEx(wintypes.HANDLE(numeric),ctypes.byref(size)) or size.value <= 0:
        raise SystemExit("launcher size differs")
    remaining = int(size.value)
    chunks = []
    while remaining:
        requested = min(remaining,1024*1024)
        buffer = ctypes.create_string_buffer(requested)
        read = wintypes.DWORD()
        if not k.ReadFile(wintypes.HANDLE(numeric),buffer,requested,ctypes.byref(read),None) or read.value == 0:
            raise SystemExit("launcher held read failed")
        chunks.append(buffer.raw[:read.value])
        remaining -= int(read.value)
    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit("launcher hash differs")
    module = types.ModuleType("qualification_verified_launcher")
    module.__file__ = path
    module.__package__ = None
    module._QUALIFICATION_VERIFIED_LAUNCHER_RAW_SHA256 = expected
    module._QUALIFICATION_VERIFIED_LAUNCHER_HANDLE = numeric
    sys.modules[module.__name__] = module
    namespace = module.__dict__
    exec(compile(raw,path,"exec",dont_inherit=True,optimize=0),namespace,namespace)
    namespace["PROJECT_ROOT"] = Path(sys.argv[3])
    held, _ = namespace["_bootstrap_source_custody"](
    activation_path=Path(sys.argv[4]), activation_hash=sys.argv[5]
    )
    try:
        importlib.import_module(
            "research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.runner"
        )
        namespace["_assert_held"](held)
    finally:
        namespace["_close_held"](held)
finally:
    k.CloseHandle(wintypes.HANDLE(numeric))
print("BOOTSTRAP_GO_BEFORE_SCORER_IMPORT")
"""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-E",
                "-X",
                f"pycache_prefix={hostile_prefix}",
                "-c",
                code,
                str(launcher),
                sha256_bytes(launcher.read_bytes()),
                str(synthetic),
                str(activation_path),
                sha256_bytes(activation_raw),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "BOOTSTRAP_GO_BEFORE_SCORER_IMPORT"
    finally:
        shutil.rmtree(hostile_prefix, ignore_errors=True)


def test_publication_uses_root_handle_direct_final_create_and_commit_recovery() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/publication.py"
    ).read_text(encoding="utf-8")
    function = source[source.index("def publish_atomic_create_new(") :]
    create = function.index("_create_file_handle(parent._handle, final_name)")
    write = function.index("_write_flush_and_verify(", create)
    assert function.rfind("parent.assert_live()", 0, create) >= 0
    assert "committed=True" in function[create:write]
    assert "published.reconcile_commit()" in function[write:]
    assert "os.link(" not in function
    assert "MoveFileExW" not in function
    assert "SetFileInformationByHandle" not in function
    assert "_FILE_SHARE_DELETE" not in function


def test_c5_remains_terminal_null_policy_in_source() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/metrics.py"
    ).read_text(encoding="utf-8")
    assert "NOT_RUN_TERMINAL_CUSTODY_NO_GO" in source
    assert "V8_TERMINAL_CUSTODY_NO_GO" in source
    assert tuple(CANDIDATE_IDS) == tuple(MODEL_IDS[1:])


def test_v1_arithmetic_and_v2_custody_dependencies_are_byte_pinned() -> None:
    root = Path(__file__).resolve().parents[2]
    assert len(VENDORED_RUNTIME_DEPENDENCY_SHA256) == 6
    for relative, expected in VENDORED_RUNTIME_DEPENDENCY_SHA256.items():
        assert sha256_bytes((root / relative).read_bytes()) == expected
