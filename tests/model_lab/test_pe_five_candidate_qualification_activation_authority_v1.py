from __future__ import annotations

import csv
from datetime import date, timedelta
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.authority import (
    mint_activation_core_once,
    mint_final_activation_once,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.canonical import (
    ActivationAuthorityError,
    checksum_bytes,
    compact_ascii_json_bytes,
    parse_checksums,
    pretty_utf8_json_bytes,
    read_compact_ascii_json,
    semantic_sha256,
    sha256_bytes,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.contracts import (
    ACTIVATION_CORE_FIELDS,
    ACTIVATION_ATTEMPT_CLAIM_LEAF,
    ACTIVATION_CLAIM_SCHEMA,
    ACTIVATION_CLAIM_STATUS,
    ACTIVATION_FIELDS,
    ACTIVATION_OUTPUT_ROOT_NAME,
    ACTIVATION_OUTPUT_FILES,
    ACTIVATION_SEAL_LEAF,
    ACTIVATION_SEAL_SCHEMA,
    ACTIVATION_SEAL_STATUS,
    COMBINED_FILES,
    COMBINED_ROOT_NAME,
    COMMON_ROOT_NAME,
    CORE_RELATIVE,
    DGP_IDS,
    FROZEN_RUNTIME_DEPENDENCY_SHA256,
    IDENTITY_COUNT,
    MODEL_IDS,
    POLICY_RAW_SHA256,
    POLICY_RELATIVE,
    POSTGEN_AUDIT_ROOT_NAME,
    PREDICTION_AUDIT_ACCESS_FIELDS,
    PREDICTION_AUDIT_CHECK_FIELDS,
    PREDICTION_AUDIT_CLAIM_FIELDS,
    PREDICTION_AUDIT_CLAIM_SCHEMA,
    PREDICTION_AUDIT_CLAIM_STATUS,
    PREDICTION_AUDIT_FAMILY_ID,
    PREDICTION_AUDIT_FIELDS,
    PREDICTION_AUDIT_FILES,
    PREDICTION_AUDIT_INDEPENDENCE_FIELDS,
    PREDICTION_AUDIT_ROOT_NAME,
    PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
    PREDICTION_AUDIT_SCHEMA,
    PREDICTION_AUDIT_SOURCE_RECORD_COUNT,
    PREDICTION_AUDIT_STATUS,
    PREDICTION_AUDITOR_SOURCE_RELATIVES,
    PREDICTION_AUDITOR_SOURCE_SHA256,
    PREDICTION_ROW_COUNT,
    PREDICTION_SEAL_SCHEMA,
    PREDICTION_SEAL_FIELDS,
    PREDICTION_SEAL_STATUS,
    PREDICTION_SEMANTIC_CONTRACT,
    PRESCORE_ACCESS_FIELDS,
    PRESCORE_AUDIT_CLAIM_SCHEMA,
    PRESCORE_AUDIT_CLAIM_STATUS,
    PRESCORE_AUDIT_FILES,
    PRESCORE_AUDIT_ROOT_NAME,
    PRESCORE_AUDIT_SCHEMA,
    PRESCORE_AUDIT_STATUS,
    PRESCORE_AUDITOR_SOURCE_RELATIVES,
    PRESCORE_AUDITOR_SOURCE_SHA256,
    PRESCORE_CHECK_FIELDS,
    PRESCORE_INDEPENDENCE_FIELDS,
    PRESCORE_SEAL_SCHEMA,
    PRESCORE_SEAL_STATUS,
    PRESCORE_STATIC_CHECK_FIELDS,
    PRESCORE_TARGET_ROOT_NAME,
    PRESCORE_TARGET_CLAIM_SCHEMA,
    PRESCORE_TARGET_CLAIM_STATUS,
    PRESCORE_TARGET_FILES,
    PRESCORE_TARGET_SCHEMA,
    PRESCORE_TARGET_STATUS,
    PRESCORE_TARGET_SEAL_SCHEMA,
    PRESCORE_TARGET_SEAL_STATUS,
    PUBLICATION_PROTOCOL,
    QUALIFICATION_SEEDS,
    RAW_ROWS_PER_TASK,
    RUN_ID,
    SCORER_SOURCE_RELATIVES,
    SCORER_OUTPUT_ROOT_NAME,
    TASK_COUNT,
    TRUTH_HEADER_RAW_SHA256,
    VAULT_ROOT_NAME,
    ArtifactRef,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.custody import (
    AccessLedger,
    FILE_READ_ATTRIBUTES,
    HeldDirectory,
    HeldReadFile,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.public_chain import (
    _identity_contract,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.publication import (
    _HeldWritableDirectory,
    _publish_atomic_create_new,
)


PROJECT = Path(__file__).resolve().parents[2]
PYTHON = PROJECT.parent / ".venv_pe_model_lab_py310" / "Scripts" / "python.exe"
PACKAGE = "research/model_zoo/pe_five_candidate_qualification_activation_authority_v1"


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def test_checksum_modes_match_distinct_common_and_combiner_producers() -> None:
    records = {"BETA.json": "2" * 64, "alpha.csv": "1" * 64, "Gamma.json": "3" * 64}
    expected = (f"{'1' * 64}  alpha.csv\n{'2' * 64}  BETA.json\n{'3' * 64}  Gamma.json\n").encode(
        "ascii"
    )
    assert checksum_bytes(records, ordering="windows_path_casefold") == expected
    assert (
        parse_checksums(
            expected,
            label="mixed-case common ledger",
            ordering="windows_path_casefold",
        )
        == records
    )
    ascii_ordered = (
        f"{'2' * 64}  BETA.json\n{'3' * 64}  Gamma.json\n{'1' * 64}  alpha.csv\n"
    ).encode("ascii")
    assert checksum_bytes(records, ordering="ascii") == ascii_ordered
    assert (
        parse_checksums(
            ascii_ordered,
            label="mixed-case combined ledger",
            ordering="ascii",
        )
        == records
    )
    with pytest.raises(ActivationAuthorityError, match="ordering/canonical"):
        parse_checksums(
            ascii_ordered,
            label="wrong common-ledger mode",
            ordering="windows_path_casefold",
        )
    with pytest.raises(ActivationAuthorityError, match="ordering/canonical"):
        parse_checksums(expected, label="wrong combined-ledger mode", ordering="ascii")


def test_r4_authority_chain_identities_are_exact() -> None:
    assert CORE_RELATIVE == (
        "build/pe_five_model_qualification_activation_core_r4_r8_r14_20260824T000005.json"
    )
    assert PRESCORE_TARGET_ROOT_NAME == (
        "pe_five_model_qualification_prescore_target_r4_r8_r14_20260824T000005"
    )
    assert PRESCORE_AUDIT_ROOT_NAME == (
        "pe_five_model_qualification_prescore_audit_r4_r8_r14_20260824T000005"
    )
    assert ACTIVATION_OUTPUT_ROOT_NAME == (
        "model_zoo_pe_five_candidate_qualification_activation_r4_r8_r14_20260824T000005"
    )
    assert SCORER_OUTPUT_ROOT_NAME == (
        "model_zoo_pe_five_candidate_fresh_qualification_result_r4_r8_r14_20260824T000005"
    )


def _json(value: object) -> bytes:
    return compact_ascii_json_bytes(value, terminal_lf=True)


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = semantic_sha256(output)
    return output


def _ref(path: Path, relative: str) -> ArtifactRef:
    ledger = AccessLedger()
    with HeldReadFile(path=path, ledger=ledger) as held:
        return held.artifact_ref(relative_path=relative)


def _root_identity(path: Path) -> dict[str, str]:
    ledger = AccessLedger()
    with HeldDirectory(path=path, ledger=ledger) as held:
        return held.root_identity()


def _fake_ref(relative: str, ordinal: int) -> dict[str, object]:
    digest = f"{ordinal + 1:064x}"
    file_id = f"{ordinal + 1:032x}"
    return {
        "relative_path": relative,
        "raw_sha256": digest,
        "size_bytes": ordinal + 1,
        "volume_serial_number": 0xABC000 + ordinal,
        "file_id_128": file_id,
    }


def _source_versions() -> list[dict[str, str]]:
    return [
        {"model_id": model_id, "source_model_version": f"sha256:{index + 21:064x}"}
        for index, model_id in enumerate(MODEL_IDS)
    ]


def _common_identities_raw() -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("seed", "dgp", "row_position", "date"))
    start = date(2015, 1, 1)
    for seed in QUALIFICATION_SEEDS:
        for dgp in DGP_IDS:
            for position in range(RAW_ROWS_PER_TASK):
                writer.writerow(
                    (seed, dgp, position, (start + timedelta(days=position)).isoformat())
                )
    return stream.getvalue().encode("utf-8")


def _build_common(project: Path) -> tuple[str, str]:
    root = project / "outputs" / COMMON_ROOT_NAME
    root.mkdir(parents=True)
    identity_raw = _common_identities_raw()
    manifest = {
        "schema_version": "expected_pe.r7.qualification.public_manifest.v1",
        "status": "PASS_PUBLIC_STAGING_EXACT_PENDING_ATOMIC_PUBLISH",
        "root_file_universe": [],
        "task_file_universe": [],
        "task_count_per_pass": TASK_COUNT,
        "public_replay_passes": 2,
        "full_identity_count": TASK_COUNT * RAW_ROWS_PER_TASK,
        "public_artifact_byte_parity": True,
        "protected_payload_present": False,
    }
    manifest_raw = _json(manifest)
    _write(root / "FULL_IDENTITIES.csv", identity_raw)
    _write(root / "MANIFEST.json", manifest_raw)
    _write(
        root / "CHECKSUMS.sha256",
        checksum_bytes(
            {
                "FULL_IDENTITIES.csv": sha256_bytes(identity_raw),
                "MANIFEST.json": sha256_bytes(manifest_raw),
            },
            ordering="windows_path_casefold",
        ),
    )
    return _identity_contract(identity_raw)


def _build_combined(project: Path) -> str:
    root = project / "outputs" / COMBINED_ROOT_NAME
    root.mkdir(parents=True)
    versions = _source_versions()
    binding = _seal(
        {
            "schema_version": "expected_pe.five_model.qualification_input_binding.v1",
            "status": "FROZEN_EXACT_PRETRUTH_INPUT_ARTIFACTS",
            "source_model_versions": versions,
        },
        "binding_semantic_sha256",
    )
    binding_semantic = binding["binding_semantic_sha256"]
    prediction_raw = b"synthetic frozen five-model predictions\n"
    manifest = _seal(
        {
            "schema_version": "expected_pe.five_model.qualification_predictions.v1",
            "status": "PREDICTIONS_FROZEN_ATOMIC_PUBLICATION_NO_TRUTH_OR_SCORE",
            "binding_semantic_sha256": binding_semantic,
            "source_model_versions": versions,
            "model_ids_in_fixed_order": list(MODEL_IDS),
            "task_count": TASK_COUNT,
            "identity_count": IDENTITY_COUNT,
            "prediction_row_count": PREDICTION_ROW_COUNT,
            "prediction_raw_sha256": sha256_bytes(prediction_raw),
            "prediction_before_truth": True,
            "truth_received": False,
            "score_computed": False,
            "heldout_received": False,
        },
        "manifest_semantic_sha256",
    )
    objects = {
        "COMBINATION_RECEIPT.json": {
            "status": "PASS_EXACT_PREFIX_PRESERVATION_AND_FROZEN_C4_FORMULA",
            "binding_semantic_sha256": binding_semantic,
            "truth_received": False,
            "score_computed": False,
            "heldout_received": False,
        },
        "INPUT_BINDING.json": binding,
        "INPUT_CUSTODY_RECEIPT.json": {
            "status": "PASS_THREE_ROOTS_ALL_FILES_AND_SOURCE_CLOSURE_HELD_BY_FILE_ID",
            "binding_semantic_sha256": binding_semantic,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
        },
        "PREDICTION_MANIFEST.json": manifest,
        "RUNTIME_RECEIPT.json": {
            "status": "PASS_VECTORIZED_NO_FIT_PRETRUTH_COMPOSITION",
            "binding_semantic_sha256": binding_semantic,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
        },
        "SOURCE_MANIFEST.json": {
            "status": "PASS_EXACT_COMBINER_AND_UPSTREAM_FORMULA_SOURCE_CLOSURE"
        },
    }
    raw_by_leaf = {leaf: _json(value) for leaf, value in objects.items()}
    raw_by_leaf["PREDICTIONS.csv"] = prediction_raw
    for leaf, raw in raw_by_leaf.items():
        _write(root / leaf, raw)
    checksums = checksum_bytes(
        {leaf: sha256_bytes(raw) for leaf, raw in raw_by_leaf.items()},
        ordering="ascii",
    )
    _write(root / "CHECKSUMS.sha256", checksums)
    assert tuple(sorted(path.name for path in root.iterdir())) == COMBINED_FILES
    return sha256_bytes(checksums)


def _build_prediction_audit(project: Path, identity_csv_sha: str) -> None:
    combined_root = project / "outputs" / COMBINED_ROOT_NAME
    common_root = project / "outputs" / COMMON_ROOT_NAME
    root = project / "outputs" / PREDICTION_AUDIT_ROOT_NAME
    root.mkdir(parents=True)
    combined_refs = {
        leaf: _ref(combined_root / leaf, f"outputs/{COMBINED_ROOT_NAME}/{leaf}")
        for leaf in COMBINED_FILES
    }
    common_checksums = _ref(
        common_root / "CHECKSUMS.sha256",
        f"outputs/{COMMON_ROOT_NAME}/CHECKSUMS.sha256",
    )
    binding = read_compact_ascii_json(
        (combined_root / "INPUT_BINDING.json").read_bytes(), label="fixture binding"
    )
    source_records = [
        {
            "relative_path": relative,
            "raw_sha256": PREDICTION_AUDITOR_SOURCE_SHA256[relative],
            "size_bytes": index + 1,
            "volume_serial_number": f"{index + 1:016x}",
            "file_id_128": f"{index + 1000:032x}",
        }
        for index, relative in enumerate(PREDICTION_AUDITOR_SOURCE_RELATIVES)
    ]
    source_manifest = {
        "schema_version": "expected_pe.five_model.qualification_prediction_auditor_source.v2",
        "status": "PASS_INDEPENDENT_AUDITOR_SOURCE_CLOSURE_CAPTURED",
        "files": source_records,
        "source_record_count": len(source_records),
        "source_records_semantic_sha256": semantic_sha256(source_records),
        "publication_protocol": PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
        "producer_package_imported": False,
        "scorer_imported": False,
    }
    source_manifest["source_manifest_semantic_sha256"] = semantic_sha256(source_manifest)
    source_raw = _json(source_manifest)
    _write(root / "AUDITOR_SOURCE_MANIFEST.json", source_raw)
    source_ref = _ref(
        root / "AUDITOR_SOURCE_MANIFEST.json",
        f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json",
    )
    target_authority = {
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_checksums_raw_sha256": combined_refs["CHECKSUMS.sha256"].raw_sha256,
        "common_checksums_raw_sha256": common_checksums.raw_sha256,
    }
    claim_base = {
        "schema_version": PREDICTION_AUDIT_CLAIM_SCHEMA,
        "status": PREDICTION_AUDIT_CLAIM_STATUS,
        "family_id": PREDICTION_AUDIT_FAMILY_ID,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": _root_identity(root),
        "target_authority": target_authority,
        "target_authority_semantic_sha256": semantic_sha256(target_authority),
        "expected_authorized_output_file_universe": list(PREDICTION_AUDIT_FILES),
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
    claim = {**claim_base, "claim_semantic_sha256": semantic_sha256(claim_base)}
    assert set(claim) == set(PREDICTION_AUDIT_CLAIM_FIELDS)
    claim_raw = _json(claim)
    _write(root / "ATTEMPT_CLAIM.json", claim_raw)
    claim_ref = _ref(
        root / "ATTEMPT_CLAIM.json",
        f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    identity_material = {
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_root_identity": _root_identity(combined_root),
        "combined_checksums_raw_sha256": combined_refs["CHECKSUMS.sha256"].raw_sha256,
        "prediction_raw_sha256": combined_refs["PREDICTIONS.csv"].raw_sha256,
        "prediction_semantic_sha256": "a" * 64,
        "prediction_semantic_contract": PREDICTION_SEMANTIC_CONTRACT,
        "identity_csv_raw_sha256": identity_csv_sha,
        "input_binding_raw_sha256": combined_refs["INPUT_BINDING.json"].raw_sha256,
        "input_binding_semantic_sha256": binding["binding_semantic_sha256"],
        "common_root_name": COMMON_ROOT_NAME,
        "common_root_identity": _root_identity(common_root),
        "common_checksums_raw_sha256": common_checksums.raw_sha256,
        "postgen_audit_raw_sha256": "b" * 64,
        "postgen_audit_semantic_sha256": "c" * 64,
        "postgen_target_binding_sha256": "d" * 64,
        "postgen_seal_raw_sha256": "e" * 64,
        "c1_c3_binding_root_name": "synthetic_c1_binding",
        "c1_c3_binding_root_identity": {
            "volume_serial_number": "0000000000000001",
            "file_id_128": "1" * 32,
        },
        "c1_c3_prediction_root_name": "synthetic_c1_prediction",
        "c1_c3_prediction_root_identity": {
            "volume_serial_number": "0000000000000002",
            "file_id_128": "2" * 32,
        },
        "c4_surface_root_name": "synthetic_c4_surface",
        "c4_surface_root_identity": {
            "volume_serial_number": "0000000000000003",
            "file_id_128": "3" * 32,
        },
    }
    audit = {
        "schema_version": PREDICTION_AUDIT_SCHEMA,
        "status": PREDICTION_AUDIT_STATUS,
        "verdict": PREDICTION_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        **identity_material,
        "target_binding_semantic_sha256": semantic_sha256(identity_material),
        "combination_receipt_raw_sha256": combined_refs["COMBINATION_RECEIPT.json"].raw_sha256,
        "prediction_manifest_raw_sha256": combined_refs["PREDICTION_MANIFEST.json"].raw_sha256,
        "runtime_receipt_raw_sha256": combined_refs["RUNTIME_RECEIPT.json"].raw_sha256,
        "source_manifest_raw_sha256": combined_refs["SOURCE_MANIFEST.json"].raw_sha256,
        "prefix_prediction_raw_sha256": "f" * 64,
        "c4_surface_raw_sha256": "1" * 64,
        "qualification_task_count": TASK_COUNT,
        "identity_count": IDENTITY_COUNT,
        "prediction_row_count": PREDICTION_ROW_COUNT,
        "model_ids_in_order": list(MODEL_IDS),
        "source_model_versions": _source_versions(),
        "source_record_count": PREDICTION_AUDIT_SOURCE_RECORD_COUNT,
        "prefix_byte_fields_exact": True,
        "c4_formula_recomputed": True,
        "task_geometry_exact": True,
        "prediction_before_truth": True,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "protected_namespace_open_count": 0,
        "checks": {key: True for key in PREDICTION_AUDIT_CHECK_FIELDS},
        "access": {key: 0 for key in PREDICTION_AUDIT_ACCESS_FIELDS},
        "independence": {key: False for key in PREDICTION_AUDIT_INDEPENDENCE_FIELDS},
        "auditor_source_manifest_raw_sha256": source_ref.raw_sha256,
        "auditor_source_manifest_semantic_sha256": semantic_sha256(
            read_compact_ascii_json(source_raw, label="source")
        ),
        "auditor_source_manifest_size_bytes": source_ref.size_bytes,
        "auditor_source_manifest_volume_serial_number": (f"{source_ref.volume_serial_number:016x}"),
        "auditor_source_manifest_file_id_128": source_ref.file_id_128,
        "attempt_claim_raw_sha256": claim_ref.raw_sha256,
        "attempt_claim_semantic_sha256": claim["claim_semantic_sha256"],
        "attempt_claim_size_bytes": claim_ref.size_bytes,
        "attempt_claim_volume_serial_number": f"{claim_ref.volume_serial_number:016x}",
        "attempt_claim_file_id_128": claim_ref.file_id_128,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": _root_identity(root),
        "publication_protocol": PREDICTION_AUDIT_PUBLICATION_PROTOCOL,
        "root_claimed_create_new": True,
        "leaf_claims_handle_relative_create_new": True,
        "authorization_commit_leaf": "AUDIT_SEAL.json",
        "authorization_commit_published_last": True,
        "atomic_directory_publish": False,
        "retry_allowed": False,
        "terminal": False,
    }
    assert set(audit) == set(PREDICTION_AUDIT_FIELDS)
    audit_raw = _json(audit)
    _write(root / "PREDICTION_FREEZE_AUDIT.json", audit_raw)
    audit_ref = _ref(
        root / "PREDICTION_FREEZE_AUDIT.json",
        f"outputs/{PREDICTION_AUDIT_ROOT_NAME}/PREDICTION_FREEZE_AUDIT.json",
    )
    seal = {
        "schema_version": PREDICTION_SEAL_SCHEMA,
        "status": PREDICTION_SEAL_STATUS,
        "verdict": PREDICTION_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "audit_raw_sha256": audit_ref.raw_sha256,
        "audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "audit_size_bytes": audit_ref.size_bytes,
        "audit_volume_serial_number": f"{audit_ref.volume_serial_number:016x}",
        "audit_file_id_128": audit_ref.file_id_128,
        "prediction_freeze_audit_raw_sha256": audit_ref.raw_sha256,
        "prediction_freeze_audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "prediction_freeze_audit_size_bytes": audit_ref.size_bytes,
        "prediction_freeze_audit_volume_serial_number": (f"{audit_ref.volume_serial_number:016x}"),
        "prediction_freeze_audit_file_id_128": audit_ref.file_id_128,
        "target_binding_semantic_sha256": audit["target_binding_semantic_sha256"],
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_root_identity": audit["combined_root_identity"],
        "combined_checksums_raw_sha256": audit["combined_checksums_raw_sha256"],
        "prediction_raw_sha256": audit["prediction_raw_sha256"],
        "prediction_semantic_sha256": audit["prediction_semantic_sha256"],
        "input_binding_raw_sha256": audit["input_binding_raw_sha256"],
        "input_binding_semantic_sha256": audit["input_binding_semantic_sha256"],
        "auditor_source_manifest_raw_sha256": source_ref.raw_sha256,
        "attempt_claim_raw_sha256": claim_ref.raw_sha256,
        "attempt_claim_semantic_sha256": claim["claim_semantic_sha256"],
        "attempt_claim_size_bytes": claim_ref.size_bytes,
        "attempt_claim_volume_serial_number": f"{claim_ref.volume_serial_number:016x}",
        "attempt_claim_file_id_128": claim_ref.file_id_128,
        "auditor_source_manifest_size_bytes": source_ref.size_bytes,
        "auditor_source_manifest_volume_serial_number": (f"{source_ref.volume_serial_number:016x}"),
        "auditor_source_manifest_file_id_128": source_ref.file_id_128,
        "output_root_name": PREDICTION_AUDIT_ROOT_NAME,
        "output_root_identity": _root_identity(root),
        "audit_output_file_universe": list(PREDICTION_AUDIT_FILES),
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
    }
    assert set(seal) == set(PREDICTION_SEAL_FIELDS)
    seal_raw = _json(seal)
    _write(root / "AUDIT_SEAL.json", seal_raw)
    _write(
        root / "CHECKSUMS.sha256",
        checksum_bytes(
            {
                "ATTEMPT_CLAIM.json": claim_ref.raw_sha256,
                "AUDIT_SEAL.json": sha256_bytes(seal_raw),
                "AUDITOR_SOURCE_MANIFEST.json": source_ref.raw_sha256,
                "PREDICTION_FREEZE_AUDIT.json": audit_ref.raw_sha256,
            },
            ordering="ascii",
        ),
    )
    assert tuple(sorted(path.name for path in root.iterdir())) == tuple(
        sorted(PREDICTION_AUDIT_FILES)
    )


def _build_truth_metadata(project: Path) -> None:
    for seed in QUALIFICATION_SEEDS:
        for dgp in DGP_IDS:
            root = project / "outputs" / VAULT_ROOT_NAME / "pass_1" / f"seed_{seed}" / f"dgp_{dgp}"
            truth_raw = f"synthetic truth {seed} {dgp}\n".encode("ascii")
            _write(root / "truth.csv", truth_raw)
            metadata = {
                "schema_version": "expected_pe.r8.r14.qualification.private_task_metadata.v1",
                "status": "PASS_PROTECTED_BYTES_FROZEN",
                "stage": "QUALIFICATION",
                "seed": seed,
                "dgp": dgp,
                "replay_pass": 1,
                "rows": RAW_ROWS_PER_TASK,
                "truth_header_raw_sha256": TRUTH_HEADER_RAW_SHA256,
                "protected_raw_sha256": {
                    "truth": sha256_bytes(truth_raw),
                    "latent_events": "2" * 64,
                },
                "protected_logical_sha256": {"truth": "3" * 64, "latent_events": "4" * 64},
                "public_logical_sha256": {"canonical150.csv": "5" * 64},
                "public_logical_contract": "synthetic",
                "public_path_received": False,
                "score_fit_prediction_evaluation": False,
            }
            _write(root / "METADATA.json", _json(metadata))


@pytest.fixture()
def phase1_project(tmp_path: Path) -> tuple[Path, str]:
    (tmp_path / "build").mkdir()
    (tmp_path / "outputs").mkdir()
    identity_csv_sha, _ = _build_common(tmp_path)
    combined_hash = _build_combined(tmp_path)
    _build_prediction_audit(tmp_path, identity_csv_sha)
    _build_truth_metadata(tmp_path)
    return tmp_path, combined_hash


def _runtime_binding() -> dict[str, object]:
    ref = _ref(Path(sys.executable), "runtime/python.exe")
    ledger = AccessLedger()
    with HeldReadFile(path=Path(sys.executable), ledger=ledger) as held:
        final_path = held.identity()["final_path"]
    return {
        "implementation": sys.implementation.name,
        "version_info": [
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
            sys.version_info.releaselevel,
            sys.version_info.serial,
        ],
        "cache_tag": sys.implementation.cache_tag,
        "executable_final_path": final_path,
        "executable_raw_sha256": ref.raw_sha256,
        "executable_size_bytes": ref.size_bytes,
        "executable_volume_serial_number": ref.volume_serial_number,
        "executable_file_id_128": ref.file_id_128,
        "required_flags_in_order": ["-I", "-S", "-B", "-E"],
    }


def _public_ref(project: Path, root: str, leaf: str) -> dict[str, object]:
    return _ref(project / "outputs" / root / leaf, f"outputs/{root}/{leaf}").as_mapping()


def _build_prescore(project: Path, core: dict[str, Any]) -> tuple[str, str, str]:
    chain: dict[str, object] = {
        "common_run_id": RUN_ID,
        "common_root_name": COMMON_ROOT_NAME,
        "common_checksums_ref": _public_ref(project, COMMON_ROOT_NAME, "CHECKSUMS.sha256"),
        "common_manifest_ref": _public_ref(project, COMMON_ROOT_NAME, "MANIFEST.json"),
        "common_full_identities_ref": _public_ref(project, COMMON_ROOT_NAME, "FULL_IDENTITIES.csv"),
        "postgen_audit_ref": _fake_ref(
            f"outputs/{POSTGEN_AUDIT_ROOT_NAME}/POSTGEN_AUDIT.json", 500
        ),
        "postgen_audit_seal_ref": _fake_ref(
            f"outputs/{POSTGEN_AUDIT_ROOT_NAME}/AUDIT_SEAL.json", 501
        ),
        "postgen_checksums_ref": _fake_ref(
            f"outputs/{POSTGEN_AUDIT_ROOT_NAME}/CHECKSUMS.sha256", 502
        ),
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_checksums_ref": _public_ref(project, COMBINED_ROOT_NAME, "CHECKSUMS.sha256"),
        "combined_combination_receipt_ref": _public_ref(
            project, COMBINED_ROOT_NAME, "COMBINATION_RECEIPT.json"
        ),
        "combined_input_binding_ref": _public_ref(
            project, COMBINED_ROOT_NAME, "INPUT_BINDING.json"
        ),
        "combined_input_custody_ref": _public_ref(
            project, COMBINED_ROOT_NAME, "INPUT_CUSTODY_RECEIPT.json"
        ),
        "combined_manifest_ref": _public_ref(
            project, COMBINED_ROOT_NAME, "PREDICTION_MANIFEST.json"
        ),
        "combined_runtime_ref": _public_ref(project, COMBINED_ROOT_NAME, "RUNTIME_RECEIPT.json"),
        "combined_source_manifest_ref": _public_ref(
            project, COMBINED_ROOT_NAME, "SOURCE_MANIFEST.json"
        ),
        "prediction_ref": core["prediction_ref"],
        "prediction_audit_ref": core["prediction_audit_ref"],
        "prediction_audit_seal_ref": core["prediction_audit_seal_ref"],
        "prediction_auditor_source_manifest_ref": _public_ref(
            project, PREDICTION_AUDIT_ROOT_NAME, "AUDITOR_SOURCE_MANIFEST.json"
        ),
        "prediction_audit_checksums_ref": _public_ref(
            project, PREDICTION_AUDIT_ROOT_NAME, "CHECKSUMS.sha256"
        ),
    }
    source_refs = [
        _fake_ref(relative, 600 + index) for index, relative in enumerate(SCORER_SOURCE_RELATIVES)
    ]
    for row in source_refs:
        relative = row["relative_path"]
        if relative in FROZEN_RUNTIME_DEPENDENCY_SHA256:
            row["raw_sha256"] = FROZEN_RUNTIME_DEPENDENCY_SHA256[relative]
        elif relative == POLICY_RELATIVE:
            row["raw_sha256"] = POLICY_RAW_SHA256
    runtime = _runtime_binding()
    target = {
        "schema_version": PRESCORE_TARGET_SCHEMA,
        "status": PRESCORE_TARGET_STATUS,
        "activation_core": core,
        "activation_core_semantic_sha256": semantic_sha256(core),
        "scorer_source_refs": source_refs,
        "python_runtime": runtime,
        "prediction_chain": chain,
        "pre_score_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    target["target_binding_semantic_sha256"] = semantic_sha256(target)
    target_raw = _json(target)
    target_root = project / "outputs" / PRESCORE_TARGET_ROOT_NAME
    target_root.mkdir(parents=True)
    target_claim = _seal(
        {
            "schema_version": PRESCORE_TARGET_CLAIM_SCHEMA,
            "status": PRESCORE_TARGET_CLAIM_STATUS,
            "run_id": RUN_ID,
            "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
            "payload_leaf": "PRE_SCORE_TARGET_BINDING.json",
            "target_binding_raw_sha256": sha256_bytes(target_raw),
            "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
            "activation_core_raw_sha256": sha256_bytes(_json(core)),
            "activation_core_semantic_sha256": semantic_sha256(core),
            "pre_score_audit_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
            "publication_protocol": PUBLICATION_PROTOCOL,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
            "same_target_retry_allowed": False,
        },
        "claim_semantic_sha256",
    )
    target_claim_raw = _json(target_claim)
    _write(target_root / "ATTEMPT_CLAIM.json", target_claim_raw)
    _write(target_root / "PRE_SCORE_TARGET_BINDING.json", target_raw)
    target_claim_ref = _ref(
        target_root / "ATTEMPT_CLAIM.json",
        f"outputs/{PRESCORE_TARGET_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    target_ref = _ref(
        target_root / "PRE_SCORE_TARGET_BINDING.json",
        f"outputs/{PRESCORE_TARGET_ROOT_NAME}/PRE_SCORE_TARGET_BINDING.json",
    )
    target_root_identity = _root_identity(target_root)
    target_seal = {
        "schema_version": PRESCORE_TARGET_SEAL_SCHEMA,
        "status": PRESCORE_TARGET_SEAL_STATUS,
        "verdict": PRESCORE_TARGET_SEAL_STATUS,
        "run_id": RUN_ID,
        "output_root_relative_path": f"outputs/{PRESCORE_TARGET_ROOT_NAME}",
        "output_root_volume_serial_number": int(target_root_identity["volume_serial_number"], 16),
        "output_root_file_id_128": target_root_identity["file_id_128"],
        "attempt_claim_ref": target_claim_ref.as_mapping(),
        "target_binding_ref": target_ref.as_mapping(),
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_raw_sha256": sha256_bytes(_json(core)),
        "activation_core_semantic_sha256": semantic_sha256(core),
        "output_file_universe": list(PRESCORE_TARGET_FILES),
        "publication_protocol": PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    _write(target_root / "TARGET_PUBLICATION_SEAL.json", _json(target_seal))
    prescore_source_records = [
        _fake_ref(relative, 800 + index)
        for index, relative in enumerate(PRESCORE_AUDITOR_SOURCE_RELATIVES)
    ]
    for row in prescore_source_records:
        row["raw_sha256"] = PRESCORE_AUDITOR_SOURCE_SHA256[row["relative_path"]]
    source_manifest = {
        "schema_version": "expected_pe.qualification.pre_score_auditor_source.r8.r14.v2",
        "status": "PASS_EXACT_SOURCE_CLOSURE_HELD_BY_HASH_SIZE_VOLUME_FILE_ID",
        "family_id": "pe_five_candidate_qualification_pre_score_auditor_v1",
        "source_record_count": len(prescore_source_records),
        "source_records": prescore_source_records,
        "source_records_semantic_sha256": semantic_sha256(prescore_source_records),
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    source_raw = _json(source_manifest)
    audit_root = project / "outputs" / PRESCORE_AUDIT_ROOT_NAME
    _write(audit_root / "AUDITOR_SOURCE_MANIFEST.json", source_raw)
    source_ref = _ref(
        audit_root / "AUDITOR_SOURCE_MANIFEST.json",
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/AUDITOR_SOURCE_MANIFEST.json",
    )
    prediction_audit_raw = (
        project / "outputs" / PREDICTION_AUDIT_ROOT_NAME / "PREDICTION_FREEZE_AUDIT.json"
    ).read_bytes()
    prediction_audit = read_compact_ascii_json(
        prediction_audit_raw, label="synthetic prediction audit"
    )
    versions = [
        {"model_id": model_id, "source_model_version": core["source_model_versions"][model_id]}
        for model_id in MODEL_IDS
    ]
    source_semantic = semantic_sha256(source_refs)
    audit: dict[str, object] = {
        "schema_version": PRESCORE_AUDIT_SCHEMA,
        "status": PRESCORE_AUDIT_STATUS,
        "verdict": PRESCORE_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "target_binding_raw_sha256": target_ref.raw_sha256,
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "target_binding_size_bytes": target_ref.size_bytes,
        "target_binding_volume_serial_number": target_ref.volume_serial_number,
        "target_binding_file_id_128": target_ref.file_id_128,
        "activation_core_semantic_sha256": semantic_sha256(core),
        "scorer_run_id": RUN_ID,
        "scorer_output_relative_path": f"outputs/{SCORER_OUTPUT_ROOT_NAME}",
        "vault_relative_path": f"outputs/{VAULT_ROOT_NAME}",
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "scorer_source_manifest_semantic_sha256": source_semantic,
        "scorer_source_file_count": len(source_refs),
        "scorer_source_static_checks": {key: True for key in PRESCORE_STATIC_CHECK_FIELDS},
        "python_runtime_binding_semantic_sha256": semantic_sha256(runtime),
        "python_executable_raw_sha256": runtime["executable_raw_sha256"],
        "python_executable_volume_serial_number": runtime["executable_volume_serial_number"],
        "python_executable_file_id_128": runtime["executable_file_id_128"],
        "prediction_raw_sha256": core["prediction_ref"]["raw_sha256"],
        "prediction_semantic_sha256": core["prediction_semantic_sha256"],
        "prediction_audit_raw_sha256": core["prediction_audit_ref"]["raw_sha256"],
        "prediction_audit_semantic_sha256": sha256_bytes(prediction_audit_raw[:-1]),
        "prediction_audit_seal_raw_sha256": core["prediction_audit_seal_ref"]["raw_sha256"],
        "prediction_audit_target_binding_semantic_sha256": prediction_audit[
            "target_binding_semantic_sha256"
        ],
        "common_run_id": RUN_ID,
        "common_root_name": COMMON_ROOT_NAME,
        "common_checksums_raw_sha256": chain["common_checksums_ref"]["raw_sha256"],
        "common_manifest_raw_sha256": chain["common_manifest_ref"]["raw_sha256"],
        "common_full_identities_raw_sha256": chain["common_full_identities_ref"]["raw_sha256"],
        "common_full_identities_semantic_sha256": core["common_full_identities_semantic_sha256"],
        "postgen_audit_raw_sha256": chain["postgen_audit_ref"]["raw_sha256"],
        "postgen_audit_semantic_sha256": "6" * 64,
        "postgen_audit_seal_raw_sha256": chain["postgen_audit_seal_ref"]["raw_sha256"],
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_checksums_raw_sha256": chain["combined_checksums_ref"]["raw_sha256"],
        "combined_input_binding_raw_sha256": chain["combined_input_binding_ref"]["raw_sha256"],
        "combined_manifest_raw_sha256": chain["combined_manifest_ref"]["raw_sha256"],
        "combined_runtime_raw_sha256": chain["combined_runtime_ref"]["raw_sha256"],
        "combined_source_manifest_raw_sha256": chain["combined_source_manifest_ref"]["raw_sha256"],
        "source_model_versions": versions,
        "truth_ref_count": TASK_COUNT,
        "truth_ref_inventory_semantic_sha256": semantic_sha256(core["truth_refs"]),
        "qualification_task_count": TASK_COUNT,
        "identity_count": IDENTITY_COUNT,
        "prediction_row_count": PREDICTION_ROW_COUNT,
        "prediction_before_truth": True,
        "checks": {key: True for key in PRESCORE_CHECK_FIELDS},
        "access": {key: 0 for key in PRESCORE_ACCESS_FIELDS},
        "independence": {key: False for key in PRESCORE_INDEPENDENCE_FIELDS},
        "auditor_source_manifest_raw_sha256": source_ref.raw_sha256,
        "auditor_source_manifest_semantic_sha256": semantic_sha256(source_manifest),
    }
    audit_raw = _json(audit)
    audit_claim = _seal(
        {
            "schema_version": PRESCORE_AUDIT_CLAIM_SCHEMA,
            "status": PRESCORE_AUDIT_CLAIM_STATUS,
            "run_id": RUN_ID,
            "output_root_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
            "payload_leaf": "PRE_SCORE_AUDIT.json",
            "audit_raw_sha256": sha256_bytes(audit_raw),
            "audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
            "audit_verdict": PRESCORE_AUDIT_STATUS,
            "target_binding_raw_sha256": target_ref.raw_sha256,
            "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
            "auditor_source_manifest_raw_sha256": source_ref.raw_sha256,
            "auditor_source_manifest_semantic_sha256": semantic_sha256(source_manifest),
            "publication_protocol": PUBLICATION_PROTOCOL,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
            "same_target_retry_allowed": False,
        },
        "claim_semantic_sha256",
    )
    audit_claim_raw = _json(audit_claim)
    _write(audit_root / "ATTEMPT_CLAIM.json", audit_claim_raw)
    _write(audit_root / "PRE_SCORE_AUDIT.json", audit_raw)
    audit_claim_ref = _ref(
        audit_root / "ATTEMPT_CLAIM.json",
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/ATTEMPT_CLAIM.json",
    )
    audit_ref = _ref(
        audit_root / "PRE_SCORE_AUDIT.json",
        f"outputs/{PRESCORE_AUDIT_ROOT_NAME}/PRE_SCORE_AUDIT.json",
    )
    audit_root_identity = _root_identity(audit_root)
    seal = {
        "schema_version": PRESCORE_SEAL_SCHEMA,
        "status": PRESCORE_SEAL_STATUS,
        "verdict": PRESCORE_AUDIT_STATUS,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "pre_score_audit_raw_sha256": audit_ref.raw_sha256,
        "pre_score_audit_semantic_sha256": sha256_bytes(audit_raw[:-1]),
        "pre_score_audit_size_bytes": audit_ref.size_bytes,
        "pre_score_audit_volume_serial_number": audit_ref.volume_serial_number,
        "pre_score_audit_file_id_128": audit_ref.file_id_128,
        "target_binding_raw_sha256": target_ref.raw_sha256,
        "target_binding_semantic_sha256": target["target_binding_semantic_sha256"],
        "activation_core_semantic_sha256": semantic_sha256(core),
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "scorer_source_manifest_semantic_sha256": source_semantic,
        "python_runtime_binding_semantic_sha256": semantic_sha256(runtime),
        "prediction_raw_sha256": core["prediction_ref"]["raw_sha256"],
        "prediction_semantic_sha256": core["prediction_semantic_sha256"],
        "prediction_audit_raw_sha256": core["prediction_audit_ref"]["raw_sha256"],
        "prediction_audit_seal_raw_sha256": core["prediction_audit_seal_ref"]["raw_sha256"],
        "common_root_name": COMMON_ROOT_NAME,
        "common_checksums_raw_sha256": chain["common_checksums_ref"]["raw_sha256"],
        "postgen_audit_raw_sha256": chain["postgen_audit_ref"]["raw_sha256"],
        "postgen_audit_seal_raw_sha256": chain["postgen_audit_seal_ref"]["raw_sha256"],
        "combined_root_name": COMBINED_ROOT_NAME,
        "combined_checksums_raw_sha256": chain["combined_checksums_ref"]["raw_sha256"],
        "auditor_source_manifest_raw_sha256": source_ref.raw_sha256,
        "audit_output_file_universe": list(PRESCORE_AUDIT_FILES),
        "attempt_claim_ref": audit_claim_ref.as_mapping(),
        "output_root_volume_serial_number": int(audit_root_identity["volume_serial_number"], 16),
        "output_root_file_id_128": audit_root_identity["file_id_128"],
        "publication_protocol": PUBLICATION_PROTOCOL,
        "attempt_claim_published_first": True,
        "seal_published_last": True,
        "same_target_retry_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "terminal": False,
    }
    seal_raw = _json(seal)
    _write(audit_root / "AUDIT_SEAL.json", seal_raw)
    _write(
        audit_root / "CHECKSUMS.sha256",
        checksum_bytes(
            {
                "ATTEMPT_CLAIM.json": audit_claim_ref.raw_sha256,
                "AUDIT_SEAL.json": sha256_bytes(seal_raw),
                "AUDITOR_SOURCE_MANIFEST.json": source_ref.raw_sha256,
                "PRE_SCORE_AUDIT.json": audit_ref.raw_sha256,
            },
            ordering="ascii",
        ),
    )
    assert tuple(sorted(path.name for path in audit_root.iterdir())) == tuple(
        sorted(PRESCORE_AUDIT_FILES)
    )
    return target_ref.raw_sha256, audit_ref.raw_sha256, sha256_bytes(seal_raw)


def test_phase1_mints_exact_core_without_truth_content_read(
    phase1_project: tuple[Path, str],
) -> None:
    project, combined_hash = phase1_project
    ledger = AccessLedger()
    receipt = mint_activation_core_once(
        project_root=project,
        ledger=ledger,
        expected_combined_checksums_raw_sha256=combined_hash,
        enforce_runtime=False,
    )
    raw = (project / CORE_RELATIVE).read_bytes()
    core = read_compact_ascii_json(raw, label="minted core")
    assert set(core) == set(ACTIVATION_CORE_FIELDS)
    assert len(core["truth_refs"]) == TASK_COUNT
    assert receipt["truth_content_open_count"] == 0
    assert receipt["truth_read_file_call_count"] == 0
    truth_events = [
        row for row in ledger.create_file_events if Path(row.path).name.casefold() == "truth.csv"
    ]
    assert len(truth_events) == TASK_COUNT
    assert all(
        row.desired_access == FILE_READ_ATTRIBUTES and not row.content_read for row in truth_events
    )
    assert not any(Path(path).name.casefold() == "truth.csv" for path in ledger.read_file_paths)
    assert raw == compact_ascii_json_bytes(core, terminal_lf=True)


def test_phase1_metadata_tamper_fails_closed(phase1_project: tuple[Path, str]) -> None:
    project, combined_hash = phase1_project
    metadata = (
        project
        / "outputs"
        / VAULT_ROOT_NAME
        / "pass_1"
        / f"seed_{QUALIFICATION_SEEDS[0]}"
        / "dgp_A"
        / "METADATA.json"
    )
    value = read_compact_ascii_json(metadata.read_bytes(), label="metadata")
    value["protected_raw_sha256"]["truth"] = "0" * 64
    metadata.write_bytes(_json(value))
    with pytest.raises(ActivationAuthorityError):
        mint_activation_core_once(
            project_root=project,
            expected_combined_checksums_raw_sha256=combined_hash,
            enforce_runtime=False,
        )
    assert not (project / CORE_RELATIVE).exists()


def test_phase1_prediction_audit_tamper_fails_closed(
    phase1_project: tuple[Path, str],
) -> None:
    project, combined_hash = phase1_project
    audit_path = project / "outputs" / PREDICTION_AUDIT_ROOT_NAME / "PREDICTION_FREEZE_AUDIT.json"
    value = read_compact_ascii_json(audit_path.read_bytes(), label="audit")
    value["truth_open_count"] = 1
    audit_path.write_bytes(_json(value))
    with pytest.raises(ActivationAuthorityError):
        mint_activation_core_once(
            project_root=project,
            expected_combined_checksums_raw_sha256=combined_hash,
            enforce_runtime=False,
        )
    assert not (project / CORE_RELATIVE).exists()


def test_phase1_is_create_new(phase1_project: tuple[Path, str]) -> None:
    project, combined_hash = phase1_project
    mint_activation_core_once(
        project_root=project,
        expected_combined_checksums_raw_sha256=combined_hash,
        enforce_runtime=False,
    )
    with pytest.raises(ActivationAuthorityError):
        mint_activation_core_once(
            project_root=project,
            expected_combined_checksums_raw_sha256=combined_hash,
            enforce_runtime=False,
        )


def test_phase1_truth_fileid_alias_fails_closed(phase1_project: tuple[Path, str]) -> None:
    project, combined_hash = phase1_project
    first = (
        project
        / "outputs"
        / VAULT_ROOT_NAME
        / "pass_1"
        / f"seed_{QUALIFICATION_SEEDS[0]}"
        / "dgp_A"
        / "truth.csv"
    )
    second = first.parent.parent / "dgp_B" / "truth.csv"
    second.unlink()
    os.link(first, second)
    with pytest.raises(ActivationAuthorityError, match="alias"):
        mint_activation_core_once(
            project_root=project,
            expected_combined_checksums_raw_sha256=combined_hash,
            enforce_runtime=False,
        )
    assert not (project / CORE_RELATIVE).exists()


def test_phase2_mints_scorer_canonical_public_activation(
    phase1_project: tuple[Path, str],
) -> None:
    project, combined_hash = phase1_project
    core_receipt = mint_activation_core_once(
        project_root=project,
        expected_combined_checksums_raw_sha256=combined_hash,
        enforce_runtime=False,
    )
    core_raw = (project / CORE_RELATIVE).read_bytes()
    core = read_compact_ascii_json(core_raw, label="core")
    target_hash, audit_hash, seal_hash = _build_prescore(project, core)
    ledger = AccessLedger()
    receipt = mint_final_activation_once(
        project_root=project,
        expected_activation_core_raw_sha256=core_receipt["activation_core_ref"]["raw_sha256"],
        expected_pre_score_target_raw_sha256=target_hash,
        expected_pre_score_audit_raw_sha256=audit_hash,
        expected_pre_score_audit_seal_raw_sha256=seal_hash,
        ledger=ledger,
        enforce_runtime=False,
    )
    activation_path = (
        project / "outputs" / ACTIVATION_OUTPUT_ROOT_NAME / "QUALIFICATION_ACTIVATION.json"
    )
    raw = activation_path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    output_root = project / "outputs" / ACTIVATION_OUTPUT_ROOT_NAME
    assert tuple(sorted(path.name for path in output_root.iterdir())) == ACTIVATION_OUTPUT_FILES
    claim = read_compact_ascii_json(
        (output_root / ACTIVATION_ATTEMPT_CLAIM_LEAF).read_bytes(), label="activation claim"
    )
    seal = read_compact_ascii_json(
        (output_root / ACTIVATION_SEAL_LEAF).read_bytes(), label="activation seal"
    )
    assert set(value) == set(ACTIVATION_FIELDS)
    assert raw == pretty_utf8_json_bytes(value)
    assert claim["schema_version"] == ACTIVATION_CLAIM_SCHEMA
    assert claim["status"] == ACTIVATION_CLAIM_STATUS
    assert claim["claim_semantic_sha256"] == semantic_sha256(
        {key: item for key, item in claim.items() if key != "claim_semantic_sha256"}
    )
    assert seal["schema_version"] == ACTIVATION_SEAL_SCHEMA
    assert seal["status"] == ACTIVATION_SEAL_STATUS
    assert seal["verdict"] == ACTIVATION_SEAL_STATUS
    assert seal["output_file_universe"] == list(ACTIVATION_OUTPUT_FILES)
    assert seal["attempt_claim_published_first"] is True
    assert seal["seal_published_last"] is True
    assert seal["terminal"] is False
    assert receipt["activation_ref"]["raw_sha256"] == sha256_bytes(raw)
    assert receipt["truth_content_open_count"] == 0
    assert not any(Path(path).name.casefold() == "truth.csv" for path in ledger.read_file_paths)

    from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.contracts import (  # noqa: PLC0415
        Activation,
    )
    from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.runner import (  # noqa: PLC0415
        _read_public_activation,
    )

    held_raw = _read_public_activation(
        project_root=project,
        activation_path=activation_path,
        expected_raw_sha256=sha256_bytes(raw),
    )
    parsed = Activation.from_json_bytes(held_raw, expected_raw_sha256=sha256_bytes(raw))
    assert parsed.activation_core_semantic_sha256 == semantic_sha256(core)


def test_phase2_tampered_seal_fails_without_publication(
    phase1_project: tuple[Path, str],
) -> None:
    project, combined_hash = phase1_project
    receipt = mint_activation_core_once(
        project_root=project,
        expected_combined_checksums_raw_sha256=combined_hash,
        enforce_runtime=False,
    )
    core = read_compact_ascii_json((project / CORE_RELATIVE).read_bytes(), label="core")
    target_hash, audit_hash, seal_hash = _build_prescore(project, core)
    seal_path = project / "outputs" / PRESCORE_AUDIT_ROOT_NAME / "AUDIT_SEAL.json"
    seal = read_compact_ascii_json(seal_path.read_bytes(), label="seal")
    seal["terminal"] = True
    seal_path.write_bytes(_json(seal))
    with pytest.raises(ActivationAuthorityError):
        mint_final_activation_once(
            project_root=project,
            expected_activation_core_raw_sha256=receipt["activation_core_ref"]["raw_sha256"],
            expected_pre_score_target_raw_sha256=target_hash,
            expected_pre_score_audit_raw_sha256=audit_hash,
            expected_pre_score_audit_seal_raw_sha256=seal_hash,
            enforce_runtime=False,
        )
    assert not (project / "outputs" / ACTIVATION_OUTPUT_ROOT_NAME).exists()


def test_authority_source_is_external_and_truth_read_is_structurally_blocked() -> None:
    sources = [path.read_text(encoding="utf-8") for path in (PROJECT / PACKAGE).glob("*.py")]
    joined = "\n".join(sources)
    assert "from research.model_zoo.pe_five_candidate_fresh_qualification" not in joined
    assert "from research.model_zoo.pe_five_model_qualification_prediction_auditor" not in joined
    assert "from research.model_zoo.observable_state_bce" not in joined
    custody = (PROJECT / PACKAGE / "custody.py").read_text(encoding="utf-8")
    assert "FILE_READ_ATTRIBUTES" in custody
    assert 'path.name.casefold() == "truth.csv"' in custody
    assert 'raise ActivationAuthorityError("ReadFile on truth.csv is forbidden")' in custody


def test_direct_final_leaf_cannot_be_swapped_or_written_while_held(tmp_path: Path) -> None:
    ledger = AccessLedger()
    parent = _HeldWritableDirectory.open(path=tmp_path, ledger=ledger)
    published = None
    try:
        published = _publish_atomic_create_new(
            parent=parent,
            final_leaf="CORE.json",
            relative_path="build/CORE.json",
            raw=b"held exact authority bytes\n",
            ledger=ledger,
        )
        with pytest.raises(PermissionError):
            (tmp_path / "CORE.json").write_bytes(b"attacker")
        attacker = tmp_path / "ATTACKER.json"
        attacker.write_bytes(b"attacker")
        with pytest.raises(PermissionError):
            os.replace(attacker, tmp_path / "CORE.json")
        ref = published.artifact_ref()
        assert ref.raw_sha256 == sha256_bytes(b"held exact authority bytes\n")
    finally:
        if published is not None:
            published.close()
        parent.close()
    assert (tmp_path / "CORE.json").read_bytes() == b"held exact authority bytes\n"


def test_publication_has_no_path_move_or_mkdir_reopen_window() -> None:
    source = (PROJECT / PACKAGE / "publication.py").read_text(encoding="utf-8")
    publish = source[source.index("def _publish_atomic_create_new(") :]
    create_root = source[source.index("def create_new_child(") : source.index("def assert_live(")]
    assert "NtCreateFile" in create_root
    assert "NtCreateFile" in source
    assert "parent.create_new_file" in publish
    assert "SetFileInformationByHandle" not in source
    assert "MoveFileExW" not in source
    assert "os.mkdir(" not in source
    assert ".unlink(" not in publish
    assert "_FILE_SHARE_DELETE" not in publish
    assert "_FILE_SHARE_WRITE" not in source
    assert ".staging" not in source


@pytest.mark.parametrize("leaf", ("mint_core.py", "mint_activation.py"))
def test_isolated_cli_help(leaf: str) -> None:
    script = (
        PROJECT / "scripts/model_lab/pe_five_candidate_qualification_activation_authority_v1" / leaf
    )
    completed = subprocess.run(
        [str(PYTHON), "-I", "-S", "-B", "-E", str(script), "--help"],
        cwd=PROJECT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout
