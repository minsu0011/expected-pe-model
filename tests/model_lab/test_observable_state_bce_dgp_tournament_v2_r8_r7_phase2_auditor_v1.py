from __future__ import annotations

from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import zipfile

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_auditor_v1 import (  # noqa: E501
    archive_entry,
    command_lock,
    constants,
    contracts,
    ed25519,
    endpoint,
    generation_closure,
    publication,
    readiness,
    runtime,
    source_identity,
    win32_live,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_auditor_v1.archive_identity import (  # noqa: E501
    verify_archive_bytes,
    verify_external_archive_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_auditor_v1.canonical import (  # noqa: E501
    Phase2AuditError,
    canonical_json_bytes,
    parse_canonical_mapping,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_auditor_v1.filesystem_identity import (  # noqa: E501
    HeldFile,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1 import (  # noqa: E501
    binding as execution_binding,
    contracts as execution_contracts,
    generation_closure as execution_generation_closure,
    import_closure as execution_import_closure,
    readiness as execution_readiness,
    telemetry as execution_telemetry,
)


UTC = timezone.utc
LOCK_RAW_SHA256 = sha256_bytes(b"third binding lock")
LOCK_VOLUME = 71
LOCK_FILE_ID = "71" * 16
LOCK_SIZE = 4096


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("ascii"))


def _process(
    role: str,
    pid: int,
    *,
    archive_hash: str,
    source_hash: str,
) -> dict[str, Any]:
    return {
        "role": role,
        "pid": pid,
        "creation_time_100ns": 10_000_000 + pid,
        "image_path": rf"C:\Python\{role.lower()}-python.exe",
        "image_raw_sha256": _digest(f"{role}-image"),
        "image_volume_serial_number": 9,
        "image_file_id_128": f"{pid:032x}",
        "image_size_bytes": 100_000 + pid,
        "command_line_sha256": _digest(f"{role}-command-line-utf16le"),
        "archive_raw_sha256": archive_hash,
        "source_identity_raw_sha256": source_hash,
        "handle_held": True,
    }


def _lock() -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.r8.r7.phase2.execution_binding_lock.v1",
        "status": "BOTH_ARCHIVES_FROZEN_INDEPENDENT_PRELAUNCH_GO",
        "architecture_lock_raw_sha256": constants.ARCHITECTURE_LOCK_RAW_SHA256,
        "static_a3_checksums_raw_sha256": constants.STATIC_A3_CHECKSUMS_RAW_SHA256,
        "static_a3_closure_schema_raw_sha256": (
            constants.STATIC_A3_CLOSURE_SCHEMA_RAW_SHA256
        ),
        "execution_archive_relative": constants.EXECUTION_ARCHIVE_RELATIVE,
        "execution_archive_raw_sha256": _digest("execution archive"),
        "execution_source_identity_raw_sha256": _digest("execution source identity"),
        "execution_source_records_semantic_sha256": _digest("execution semantic"),
        "execution_command_lock_raw_sha256": _digest("execution command"),
        "execution_checksums_raw_sha256": _digest("execution checksums"),
        "execution_archive_volume_serial_number": 10,
        "execution_archive_file_id_128": "10" * 16,
        "execution_archive_size_bytes": 1001,
        "auditor_archive_relative": constants.AUDITOR_ARCHIVE_RELATIVE,
        "auditor_archive_raw_sha256": _digest("auditor archive"),
        "auditor_source_identity_raw_sha256": _digest("auditor source identity"),
        "auditor_source_records_semantic_sha256": _digest("auditor semantic"),
        "auditor_command_lock_raw_sha256": _digest("auditor command"),
        "auditor_checksums_raw_sha256": _digest("auditor checksums"),
        "auditor_archive_volume_serial_number": 11,
        "auditor_archive_file_id_128": "11" * 16,
        "auditor_archive_size_bytes": 1002,
        "qualification_policy_v2_raw_sha256": (
            constants.QUALIFICATION_POLICY_V2_RAW_SHA256
        ),
        "generation_external_input_closure_relative": (
            constants.GENERATION_EXTERNAL_INPUT_CLOSURE_RELATIVE
        ),
        "generation_external_input_closure_raw_sha256": _digest(
            "generation external input closure"
        ),
        "generation_external_input_closure_volume_serial_number": 12,
        "generation_external_input_closure_file_id_128": "12" * 16,
        "generation_external_input_closure_size_bytes": 1003,
        "generation_import_closure_receipt_relative": (
            constants.GENERATION_IMPORT_CLOSURE_RECEIPT_RELATIVE
        ),
        "generation_import_closure_receipt_raw_sha256": _digest(
            "generation import closure receipt"
        ),
        "generation_import_closure_receipt_semantic_sha256": _digest(
            "generation import closure receipt semantic"
        ),
        "generation_import_closure_receipt_volume_serial_number": 13,
        "generation_import_closure_receipt_file_id_128": "13" * 16,
        "generation_import_closure_receipt_size_bytes": 1004,
        "independent_prelaunch_audit_checksums_raw_sha256": _digest(
            "independent prelaunch"
        ),
        "prelaunch_verdict": "GO",
        "P0": 0,
        "P1": 0,
        "P2": 0,
        "freeze_completed_before_launch": True,
        "caller_supplied": False,
    }


def _prebinding() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    lock = _lock()
    supervisor = _process(
        "SUPERVISOR",
        4101,
        archive_hash=lock["execution_archive_raw_sha256"],
        source_hash=lock["execution_source_identity_raw_sha256"],
    )
    signer = _process(
        "SIGNER",
        4102,
        archive_hash=lock["execution_archive_raw_sha256"],
        source_hash=lock["execution_source_identity_raw_sha256"],
    )
    auditor = _process(
        "AUDITOR",
        4103,
        archive_hash=lock["auditor_archive_raw_sha256"],
        source_hash=lock["auditor_source_identity_raw_sha256"],
    )
    nonce_hex = "a7" * 32
    nonce_sha = sha256_bytes(bytes.fromhex(nonce_hex))
    lifetime_handle = 812
    query_handle = 816
    job_identity = contracts.derive_job_identity(
        job_nonce_sha256=nonce_sha,
        supervisor=supervisor,
        auditor=auditor,
        supervisor_lifetime_handle_value=lifetime_handle,
        auditor_query_handle_value=query_handle,
    )
    job_evidence = {
        "job_identity_sha256": job_identity,
        "job_nonce_sha256": nonce_sha,
        "supervisor_lifetime_handle_value": lifetime_handle,
        "auditor_query_handle_value": query_handle,
        "assignment_handle_access_mask": 5,
        "query_handle_access_mask": 4,
        "query_handle_inherited_from_supervisor": True,
        "query_handle_recipient": "AUDITOR_CHILD_ONLY",
        "query_handle_open_during_snapshot": True,
        "supervisor_retains_lifetime_handle": True,
        "kill_on_job_close": True,
        "limit_flags": constants.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        "active_process_ids": [signer["pid"], auditor["pid"]],
        "handle_inventory_complete": True,
        "unexpected_job_handle_count": 0,
        "named_job_lookup_used": False,
        "null_job_query_used": False,
    }
    prebinding = {
        "schema_version": "expected_pe.r8.r7.phase2.prebinding.v1",
        "status": "FROZEN_GATE_CLOSED_CHILDREN_SUSPENDED",
        "architecture_lock_raw_sha256": constants.ARCHITECTURE_LOCK_RAW_SHA256,
        "static_a3_checksums_raw_sha256": constants.STATIC_A3_CHECKSUMS_RAW_SHA256,
        "static_a3_closure_schema_raw_sha256": (
            constants.STATIC_A3_CLOSURE_SCHEMA_RAW_SHA256
        ),
        "execution_binding_lock_relative": constants.BINDING_LOCK_RELATIVE,
        "execution_binding_lock_raw_sha256": LOCK_RAW_SHA256,
        "execution_binding_lock_volume_serial_number": LOCK_VOLUME,
        "execution_binding_lock_file_id_128": LOCK_FILE_ID,
        "execution_binding_lock_size_bytes": LOCK_SIZE,
        "execution_archive_raw_sha256": lock["execution_archive_raw_sha256"],
        "execution_source_identity_raw_sha256": lock[
            "execution_source_identity_raw_sha256"
        ],
        "auditor_archive_raw_sha256": lock["auditor_archive_raw_sha256"],
        "auditor_source_identity_raw_sha256": lock[
            "auditor_source_identity_raw_sha256"
        ],
        "qualification_policy_v2_raw_sha256": lock[
            "qualification_policy_v2_raw_sha256"
        ],
        "generation_external_input_closure_raw_sha256": lock[
            "generation_external_input_closure_raw_sha256"
        ],
        "supervisor_process": supervisor,
        "signer_process": signer,
        "auditor_process": auditor,
        "job_identity_sha256": job_identity,
        "job_nonce_hex": nonce_hex,
        "job_nonce_sha256": nonce_sha,
        "job_evidence": job_evidence,
        "job_open_handle_count": 2,
        "job_direct_duplication_lineage": True,
        "job_query_inherited_handle_list_count": 1,
        "telemetry_initial_template_raw_sha256": _digest("telemetry template"),
        "gate_state": "CLOSED_INITIALIZATION_ONLY",
        "request_count": 0,
        "signature_count": 0,
        "error_count": 0,
        "children_suspended": True,
        "production_authority_enabled": False,
    }
    return lock, prebinding, canonical_json_bytes(prebinding)


def _sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    public = ed25519._encode(ed25519._scalar_mult(ed25519.BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little")
    nonce %= ed25519.L
    encoded_r = ed25519._encode(ed25519._scalar_mult(ed25519.BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little"
    ) % ed25519.L
    signature = encoded_r + ((nonce + challenge * scalar) % ed25519.L).to_bytes(
        32, "little"
    )
    return public, signature


def _readiness(
    prebinding: dict[str, Any], prebinding_raw: bytes
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    prebinding_hash = sha256_bytes(prebinding_raw)
    challenge = bytes.fromhex("5c" * 32)
    seed = bytes.fromhex("13" * 32)
    provisional_public, _unused = _sign(seed, b"provisional")
    key_id = sha256_bytes(provisional_public)
    endpoint_name = (
        rf"\\.\pipe\expected_pe_r8_r7_{key_id[:32]}_{prebinding_hash[:16]}"
    )
    message = readiness.readiness_message(
        challenge_hex=challenge.hex(),
        prebinding_raw_sha256=prebinding_hash,
        signer_pid=prebinding["signer_process"]["pid"],
        signer_creation_time_100ns=prebinding["signer_process"][
            "creation_time_100ns"
        ],
        public_key_hex=provisional_public.hex(),
        key_id=key_id,
        endpoint=endpoint_name,
    )
    public_key, signature = _sign(seed, message)
    assert public_key == provisional_public
    now = datetime.now(UTC)
    row = {
        "schema_version": "expected_pe.r8.r7.initialization_readiness_schema.v1",
        "status": "READY_INITIALIZATION_ONLY_GATE_CLOSED",
        "launch_prebinding_raw_sha256": prebinding_hash,
        "signer_pid": prebinding["signer_process"]["pid"],
        "signer_creation_time_100ns": prebinding["signer_process"][
            "creation_time_100ns"
        ],
        "public_key_algorithm": "Ed25519",
        "public_key_hex": public_key.hex(),
        "public_key_raw_sha256": key_id,
        "key_id": key_id,
        "readiness_challenge_hex": challenge.hex(),
        "readiness_challenge_raw_sha256": sha256_bytes(challenge),
        "readiness_proof_domain": readiness.READINESS_DOMAIN,
        "readiness_proof_signature_ed25519_hex": signature.hex(),
        "endpoint_family": "AF_PIPE",
        "endpoint": endpoint_name,
        "started_at_utc": (now - timedelta(seconds=2)).isoformat(),
        "last_heartbeat_utc": (now - timedelta(seconds=1)).isoformat(),
        "heartbeat_sequence": 3,
        "authority_gate_state": "CLOSED_INITIALIZATION_ONLY",
        "private_key_persisted": False,
        "parent_supervised": True,
        "foreground_supervised": True,
        "counters": {
            "readiness_proof_signature_count": 1,
            "authority_gate_open_count": 0,
            "authority_request_count": 0,
            "authority_signature_count": 0,
            "heldout_access_count": 0,
            "qualification_generation_count": 0,
            "read_only_probe_count": 0,
        },
    }
    raw = canonical_json_bytes(row)
    receipt = readiness.validate_readiness_artifact(
        row,
        prebinding=prebinding,
        prebinding_raw_sha256=prebinding_hash,
    )
    return row, raw, receipt


def _witness(prebinding: dict[str, Any]) -> dict[str, Any]:
    job = prebinding["job_evidence"]
    return {
        "schema_version": "expected_pe.r8.r7.phase2.auditor_job_witness.v1",
        "status": "QUERY_CLOSED_SUPERVISOR_POST_CLOSE_RECHECK_REQUIRED",
        "job_identity_sha256": prebinding["job_identity_sha256"],
        "job_nonce_sha256": prebinding["job_nonce_sha256"],
        "job_is_unnamed": True,
        "job_limit_flags": constants.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        "active_process_ids": list(job["active_process_ids"]),
        "signer_pid_listed": True,
        "auditor_pid_listed": True,
        "query_handle_value": job["auditor_query_handle_value"],
        "query_handle_access_mask": 4,
        "query_handle_inherited_from_supervisor": True,
        "query_handle_recipient": "AUDITOR_CHILD_ONLY",
        "query_handle_open_during_snapshot": True,
        "query_handle_closed": True,
        "query_handle_close_succeeded": True,
        "final_query_completed": True,
        "closed_handle_probe_failed": True,
        "supervisor_pid": prebinding["supervisor_process"]["pid"],
        "supervisor_lifetime_handle_value": job[
            "supervisor_lifetime_handle_value"
        ],
        "assignment_handle_access_mask": 5,
        "supervisor_retains_lifetime_handle": True,
        "kill_on_job_close": True,
        "handle_count_before_close": 2,
        "handle_inventory_complete_before_close": True,
        "unexpected_job_handle_count_before_close": 0,
        "named_job_lookup_used": False,
        "null_job_query_used": False,
        "witnessed_at_utc": datetime.now(UTC).isoformat(),
    }


def _final_binding(
    lock: dict[str, Any],
    prebinding: dict[str, Any],
    prebinding_raw: bytes,
    witness: dict[str, Any],
    readiness_row: dict[str, Any],
    readiness_raw: bytes,
    readiness_receipt: dict[str, Any],
) -> dict[str, Any]:
    counters = readiness_row["counters"]
    return {
        "schema_version": "expected_pe.r8.r7.phase2.final_binding.v1",
        "status": "FROZEN_GATE_CLOSED_READY_FOR_LIVE_AUDIT",
        "prebinding_raw_sha256": sha256_bytes(prebinding_raw),
        "execution_binding_lock_raw_sha256": LOCK_RAW_SHA256,
        "execution_binding_lock_file_id_128": LOCK_FILE_ID,
        "process_evidence_semantic_sha256": (
            contracts.process_evidence_semantic_sha256(prebinding)
        ),
        "job_identity_sha256": prebinding["job_identity_sha256"],
        "ed25519_public_key_hex": readiness_row["public_key_hex"],
        "public_key_raw_sha256": readiness_row["public_key_raw_sha256"],
        "key_id": readiness_row["key_id"],
        "readiness_challenge_hex": readiness_row["readiness_challenge_hex"],
        "readiness_challenge_raw_sha256": readiness_row[
            "readiness_challenge_raw_sha256"
        ],
        "readiness_proof_domain": readiness_row["readiness_proof_domain"],
        "readiness_proof_signature_ed25519_hex": readiness_row[
            "readiness_proof_signature_ed25519_hex"
        ],
        "readiness_proof_raw_sha256": readiness_receipt[
            "readiness_proof_raw_sha256"
        ],
        "readiness_raw_sha256": sha256_bytes(readiness_raw),
        "readiness_public_signature_verified": True,
        "readiness_public_verification_receipt_raw_sha256": readiness_receipt[
            "public_verification_receipt_raw_sha256"
        ],
        "qualification_policy_v2_raw_sha256": lock[
            "qualification_policy_v2_raw_sha256"
        ],
        "generation_external_input_closure_raw_sha256": lock[
            "generation_external_input_closure_raw_sha256"
        ],
        "endpoint_family": "AF_PIPE",
        "endpoint": readiness_row["endpoint"],
        "telemetry_initial_template_raw_sha256": prebinding[
            "telemetry_initial_template_raw_sha256"
        ],
        "auditor_job_witness_raw_sha256": sha256_bytes(
            canonical_json_bytes(witness)
        ),
        "expires_at_utc": (datetime.now(UTC) + timedelta(seconds=90)).isoformat(),
        "auditor_query_handle_closed": True,
        "supervisor_is_sole_lifetime_job_owner": True,
        "job_handle_count_after_auditor_close": 1,
        "job_handle_inventory_complete_after_close": True,
        "unexpected_job_handle_count_after_close": 0,
        "supervisor_lifetime_handle_still_open": True,
        "remaining_known_handle_roles": ["SUPERVISOR_LIFETIME"],
        "gate_state": "CLOSED_AWAITING_SUPPLEMENTAL_GO_AND_RECHECK",
        "request_count": 0,
        "signature_count": 0,
        "error_count": 0,
        "heldout_authority": False,
        "production_authority_enabled": False,
        **counters,
    }


def _telemetry(
    *,
    prebinding_raw_sha256: str,
    final_raw_sha256: str,
    final_binding: dict[str, Any],
    sequence: int,
    probe_count: int,
    observed_at: datetime,
) -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.r8.r7.phase2.telemetry.v1",
        "status": "STRICT_LIVE_GATE_CLOSED",
        "sequence": sequence,
        "heartbeat_counter": sequence + 10,
        "error_count": 0,
        "request_count": 0,
        "signature_count": 0,
        "signer_alive": True,
        "auditor_alive": True,
        "gate_state": "CLOSED_AWAITING_SUPPLEMENTAL_GO_AND_RECHECK",
        "observed_at_utc": observed_at.isoformat(),
        "monotonic_ns": sequence * 1_000_000,
        "prebinding_raw_sha256": prebinding_raw_sha256,
        "final_binding_raw_sha256": final_raw_sha256,
        "public_key_hex": final_binding["ed25519_public_key_hex"],
        "key_id": final_binding["key_id"],
        "readiness_proof_signature_count": 1,
        "authority_gate_open_count": 0,
        "authority_request_count": 0,
        "authority_signature_count": 0,
        "heldout_access_count": 0,
        "qualification_generation_count": 0,
        "read_only_probe_count": probe_count,
    }


def _validated_bundle() -> dict[str, Any]:
    lock, prebinding, prebinding_raw = _prebinding()
    contracts.validate_execution_binding_lock(lock)
    contracts.validate_prebinding(
        prebinding,
        lock=lock,
        lock_raw_sha256=LOCK_RAW_SHA256,
        lock_volume_serial_number=LOCK_VOLUME,
        lock_file_id_128=LOCK_FILE_ID,
        lock_size_bytes=LOCK_SIZE,
    )
    witness = _witness(prebinding)
    contracts.validate_job_witness(
        witness,
        prebinding=prebinding,
        query_handle_value=prebinding["job_evidence"]["auditor_query_handle_value"],
    )
    readiness_row, readiness_raw, readiness_receipt = _readiness(
        prebinding, prebinding_raw
    )
    final = _final_binding(
        lock,
        prebinding,
        prebinding_raw,
        witness,
        readiness_row,
        readiness_raw,
        readiness_receipt,
    )
    final_raw = canonical_json_bytes(final)
    contracts.validate_final_binding(
        final,
        raw_sha256=sha256_bytes(final_raw),
        prebinding=prebinding,
        prebinding_raw_sha256=sha256_bytes(prebinding_raw),
        lock=lock,
        lock_raw_sha256=LOCK_RAW_SHA256,
        lock_file_id_128=LOCK_FILE_ID,
        job_witness_raw_sha256=sha256_bytes(canonical_json_bytes(witness)),
        job_witness=witness,
        readiness=readiness_row,
        readiness_raw_sha256=sha256_bytes(readiness_raw),
    )
    return {
        "lock": lock,
        "prebinding": prebinding,
        "prebinding_raw": prebinding_raw,
        "witness": witness,
        "readiness": readiness_row,
        "readiness_raw": readiness_raw,
        "readiness_receipt": readiness_receipt,
        "final": final,
        "final_raw": final_raw,
    }


def test_shared_exact_key_sets_match_execution_package() -> None:
    assert constants.LOCK_KEYS == execution_contracts.EXECUTION_BINDING_LOCK_KEYS
    assert constants.PROCESS_KEYS == execution_binding.PROCESS_KEYS
    assert constants.PREBINDING_KEYS == execution_binding.PREBINDING_KEYS
    assert constants.FINAL_BINDING_KEYS == execution_binding.FINAL_BINDING_KEYS
    assert constants.JOB_EVIDENCE_KEYS == execution_binding.JOB_EVIDENCE_KEYS
    assert constants.JOB_WITNESS_KEYS == execution_binding.AUDITOR_JOB_WITNESS_KEYS
    assert constants.READINESS_KEYS == execution_readiness.READINESS_KEYS
    assert constants.TELEMETRY_KEYS == execution_telemetry.TELEMETRY_KEYS


def test_static_job_identity_has_no_object_pointer_and_is_exact() -> None:
    _lock_row, prebinding, _raw = _prebinding()
    job = prebinding["job_evidence"]
    assert "job_object_pointer" not in job
    payload = {
        "schema_version": "expected_pe.r8.r7.exact_job_identity.v1",
        "job_nonce_sha256": prebinding["job_nonce_sha256"],
        "supervisor_pid": prebinding["supervisor_process"]["pid"],
        "supervisor_creation_time_100ns": prebinding["supervisor_process"][
            "creation_time_100ns"
        ],
        "auditor_pid": prebinding["auditor_process"]["pid"],
        "auditor_creation_time_100ns": prebinding["auditor_process"][
            "creation_time_100ns"
        ],
        "supervisor_lifetime_handle_value": job["supervisor_lifetime_handle_value"],
        "auditor_query_handle_value": job["auditor_query_handle_value"],
        "assignment_handle_access_mask": 5,
        "query_handle_access_mask": 4,
        "limit_flags": constants.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        "job_is_unnamed": True,
    }
    assert sha256_bytes(canonical_json_bytes(payload)) == prebinding[
        "job_identity_sha256"
    ]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("prelaunch_verdict", "NO_GO"),
        ("P0", 1),
        ("caller_supplied", True),
        ("freeze_completed_before_launch", False),
        ("independent_prelaunch_audit_checksums_raw_sha256", "A" * 64),
    ],
)
def test_execution_binding_lock_negative_matrix(key: str, value: object) -> None:
    row = _lock()
    row[key] = value
    with pytest.raises(Phase2AuditError):
        contracts.validate_execution_binding_lock(row)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("job_open_handle_count",), 3),
        (("job_direct_duplication_lineage",), False),
        (("job_query_inherited_handle_list_count",), 2),
        (("job_evidence", "query_handle_recipient"), "AUDITOR"),
        (("job_evidence", "unexpected_job_handle_count"), 1),
        (("job_evidence", "handle_inventory_complete"), False),
        (("auditor_process", "role"), "LIVE_SUPPLEMENTAL_AUDITOR"),
        (("gate_state",), "CLOSED"),
    ],
)
def test_prebinding_negative_matrix(path: tuple[str, ...], value: object) -> None:
    lock, row, _raw = _prebinding()
    target: dict[str, Any] = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(Phase2AuditError):
        contracts.validate_prebinding(
            row,
            lock=lock,
            lock_raw_sha256=LOCK_RAW_SHA256,
            lock_volume_serial_number=LOCK_VOLUME,
            lock_file_id_128=LOCK_FILE_ID,
            lock_size_bytes=LOCK_SIZE,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("handle_count_before_close", 1),
        ("unexpected_job_handle_count_before_close", 1),
        ("handle_inventory_complete_before_close", False),
        ("query_handle_inherited_from_supervisor", False),
        ("query_handle_close_succeeded", False),
        ("closed_handle_probe_failed", False),
        ("query_handle_recipient", "AUDITOR"),
    ],
)
def test_job_witness_negative_matrix(key: str, value: object) -> None:
    _lock_row, prebinding, _raw = _prebinding()
    witness = _witness(prebinding)
    witness[key] = value
    with pytest.raises(Phase2AuditError):
        contracts.validate_job_witness(
            witness,
            prebinding=prebinding,
            query_handle_value=prebinding["job_evidence"][
                "auditor_query_handle_value"
            ],
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("readiness_proof_signature_ed25519_hex",), "00" * 64),
        (("authority_gate_state",), "OPEN"),
        (("private_key_persisted",), True),
        (("parent_supervised",), False),
        (("counters", "qualification_generation_count"), 1),
        (("counters", "read_only_probe_count"), 1),
    ],
)
def test_readiness_negative_matrix(path: tuple[str, ...], value: object) -> None:
    _lock_row, prebinding, prebinding_raw = _prebinding()
    row, _raw, _receipt = _readiness(prebinding, prebinding_raw)
    target: dict[str, Any] = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(Phase2AuditError):
        readiness.validate_readiness_artifact(
            row,
            prebinding=prebinding,
            prebinding_raw_sha256=sha256_bytes(prebinding_raw),
        )


def test_readiness_public_verification_receipt_is_exact() -> None:
    bundle = _validated_bundle()
    receipt = bundle["readiness_receipt"]["public_verification_receipt"]
    assert set(receipt) == {
        "schema_version",
        "status",
        "readiness_raw_sha256",
        "readiness_message_raw_sha256",
        "public_key_raw_sha256",
        "signature_raw_sha256",
        "ed25519_public_verification_succeeded",
    }
    assert receipt["ed25519_public_verification_succeeded"] is True
    assert bundle["final"][
        "readiness_public_verification_receipt_raw_sha256"
    ] == sha256_bytes(canonical_json_bytes(receipt))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("job_handle_count_after_auditor_close", 2),
        ("job_handle_inventory_complete_after_close", False),
        ("unexpected_job_handle_count_after_close", 1),
        ("supervisor_lifetime_handle_still_open", False),
        ("remaining_known_handle_roles", []),
        ("readiness_public_signature_verified", False),
        ("gate_state", "CLOSED_AWAITING_SUPPLEMENTAL_GO"),
    ],
)
def test_final_binding_negative_matrix(key: str, value: object) -> None:
    bundle = _validated_bundle()
    row = deepcopy(bundle["final"])
    row[key] = value
    with pytest.raises(Phase2AuditError):
        contracts.validate_final_binding(
            row,
            raw_sha256=_digest("mutated final"),
            prebinding=bundle["prebinding"],
            prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
            lock=bundle["lock"],
            lock_raw_sha256=LOCK_RAW_SHA256,
            lock_file_id_128=LOCK_FILE_ID,
            job_witness_raw_sha256=sha256_bytes(
                canonical_json_bytes(bundle["witness"])
            ),
            job_witness=bundle["witness"],
            readiness=bundle["readiness"],
            readiness_raw_sha256=sha256_bytes(bundle["readiness_raw"]),
        )


def test_strict_telemetry_causal_zero_to_one_pair() -> None:
    bundle = _validated_bundle()
    publication_at = datetime.now(UTC)
    pre_hash = sha256_bytes(bundle["prebinding_raw"])
    final_hash = sha256_bytes(bundle["final_raw"])
    initial = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=1,
        probe_count=0,
        observed_at=publication_at - timedelta(milliseconds=500),
    )
    final = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=2,
        probe_count=1,
        observed_at=publication_at - timedelta(milliseconds=100),
    )
    receipt = contracts.validate_telemetry_pair(
        initial=initial,
        initial_raw=canonical_json_bytes(initial),
        final=final,
        final_raw=canonical_json_bytes(final),
        prebinding_raw_sha256=pre_hash,
        final_binding=bundle["final"],
        final_binding_raw_sha256=final_hash,
        publication_at=publication_at,
    )
    assert receipt["status"] == "PASS_STRICT_PROGRESS_DOUBLE_SNAPSHOT_ZERO_COUNTERS"


@pytest.mark.parametrize(
    ("target", "key", "value"),
    [
        ("initial", "read_only_probe_count", 1),
        ("final", "read_only_probe_count", 0),
        ("final", "read_only_probe_count", 2),
        ("final", "heartbeat_counter", 11),
        ("final", "authority_request_count", 1),
        ("final", "gate_state", "CLOSED"),
    ],
)
def test_strict_telemetry_negative_matrix(
    target: str, key: str, value: object
) -> None:
    bundle = _validated_bundle()
    publication_at = datetime.now(UTC)
    pre_hash = sha256_bytes(bundle["prebinding_raw"])
    final_hash = sha256_bytes(bundle["final_raw"])
    initial = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=1,
        probe_count=0,
        observed_at=publication_at - timedelta(milliseconds=400),
    )
    final = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=2,
        probe_count=1,
        observed_at=publication_at - timedelta(milliseconds=100),
    )
    (initial if target == "initial" else final)[key] = value
    with pytest.raises(Phase2AuditError):
        contracts.validate_telemetry_pair(
            initial=initial,
            initial_raw=canonical_json_bytes(initial),
            final=final,
            final_raw=canonical_json_bytes(final),
            prebinding_raw_sha256=pre_hash,
            final_binding=bundle["final"],
            final_binding_raw_sha256=final_hash,
            publication_at=publication_at,
        )


def test_probe_request_response_binds_one_contact_and_zero_authority() -> None:
    bundle = _validated_bundle()
    final_hash = sha256_bytes(bundle["final_raw"])
    request = endpoint.build_probe_request(
        final_binding_raw_sha256=final_hash,
        key_id=bundle["final"]["key_id"],
    )
    assert set(request) == constants.READINESS_PROBE_REQUEST_KEYS
    response = {
        "schema_version": "expected_pe.r8.r7.phase2.readiness_probe_response.v1",
        "status": "READY_GATE_CLOSED",
        "prebinding_raw_sha256": sha256_bytes(bundle["prebinding_raw"]),
        "final_binding_raw_sha256": final_hash,
        "signer_pid": bundle["prebinding"]["signer_process"]["pid"],
        "signer_creation_time_100ns": bundle["prebinding"]["signer_process"][
            "creation_time_100ns"
        ],
        "public_key_hex": bundle["final"]["ed25519_public_key_hex"],
        "key_id": bundle["final"]["key_id"],
        "endpoint": bundle["final"]["endpoint"],
        "gate_state": "CLOSED_AWAITING_SUPPLEMENTAL_GO_AND_RECHECK",
        "counters": {
            "readiness_proof_signature_count": 1,
            "read_only_probe_count": 1,
            "authority_gate_open_count": 0,
            "authority_request_count": 0,
            "authority_signature_count": 0,
            "heldout_access_count": 0,
            "qualification_generation_count": 0,
        },
    }
    assert endpoint.validate_probe_response(
        response,
        prebinding=bundle["prebinding"],
        prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
        final_binding=bundle["final"],
        final_binding_raw_sha256=final_hash,
    ) == response
    response["counters"]["authority_request_count"] = 1
    with pytest.raises(Phase2AuditError):
        endpoint.validate_probe_response(
            response,
            prebinding=bundle["prebinding"],
            prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
            final_binding=bundle["final"],
            final_binding_raw_sha256=final_hash,
        )


def test_release_ack_exact_recheck_and_negative_matrix() -> None:
    bundle = _validated_bundle()
    publication_at = datetime.now(UTC)
    ack = {
        "schema_version": "expected_pe.r8.r7.phase2.auditor_release_ack.v1",
        "status": "SUPERVISOR_POST_AUDIT_RECHECK_PASS_GATE_STILL_CLOSED",
        "prebinding_raw_sha256": sha256_bytes(bundle["prebinding_raw"]),
        "final_binding_raw_sha256": sha256_bytes(bundle["final_raw"]),
        "supplemental_checksums_raw_sha256": _digest("supplemental ledger"),
        "job_identity_sha256": bundle["prebinding"]["job_identity_sha256"],
        "auditor_pid": bundle["prebinding"]["auditor_process"]["pid"],
        "auditor_creation_time_100ns": bundle["prebinding"]["auditor_process"][
            "creation_time_100ns"
        ],
        "signer_pid": bundle["prebinding"]["signer_process"]["pid"],
        "signer_creation_time_100ns": bundle["prebinding"]["signer_process"][
            "creation_time_100ns"
        ],
        "public_key_hex": bundle["final"]["ed25519_public_key_hex"],
        "key_id": bundle["final"]["key_id"],
        "gate_state": "CLOSED_AWAITING_SUPPLEMENTAL_GO_AND_RECHECK",
        "request_count": 0,
        "signature_count": 0,
        "auditor_alive": True,
        "signer_alive": True,
        "supervisor_sole_lifetime_job_owner": True,
        "authority_issuance_count": 0,
        "ack_at_utc": (publication_at + timedelta(milliseconds=50)).isoformat(),
    }
    runtime.validate_release_ack(
        ack,
        prebinding=bundle["prebinding"],
        prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
        final_binding=bundle["final"],
        final_binding_raw_sha256=sha256_bytes(bundle["final_raw"]),
        supplemental_checksums_raw_sha256=ack[
            "supplemental_checksums_raw_sha256"
        ],
        publication_at=publication_at,
        observed_at=publication_at + timedelta(milliseconds=100),
    )
    for key, value in (
        ("auditor_alive", False),
        ("request_count", 1),
        ("authority_issuance_count", 1),
        ("gate_state", "OPEN"),
    ):
        mutated = dict(ack)
        mutated[key] = value
        with pytest.raises(Phase2AuditError):
            runtime.validate_release_ack(
                mutated,
                prebinding=bundle["prebinding"],
                prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
                final_binding=bundle["final"],
                final_binding_raw_sha256=sha256_bytes(bundle["final_raw"]),
                supplemental_checksums_raw_sha256=ack[
                    "supplemental_checksums_raw_sha256"
                ],
                publication_at=publication_at,
                observed_at=publication_at + timedelta(milliseconds=100),
            )


def test_command_lock_has_only_one_decimal_handle_placeholder() -> None:
    lock = command_lock.build_auditor_command_lock(
        archive_raw_sha256=_digest("archive"),
        source_identity_raw_sha256=_digest("source"),
        source_records_semantic_sha256=_digest("semantic"),
        python_volume_serial_number=1,
        python_file_id_128="12" * 16,
        python_size_bytes=123,
    )
    assert command_lock.validate_auditor_command_lock(
        lock,
        archive_raw_sha256=_digest("archive"),
        source_identity_raw_sha256=_digest("source"),
        source_records_semantic_sha256=_digest("semantic"),
    ) == lock
    argv = command_lock.instantiate_live_argv(lock, 812)
    assert argv[-1] == "812"
    assert "{decimal_query_handle}" not in argv
    assert lock["readiness_relative"] == constants.READINESS_RELATIVE
    assert lock["auditor_release_ack_relative"] == constants.AUDITOR_RELEASE_ACK_RELATIVE


def test_source_identity_rejects_duplicate_member_and_noncanonical_json() -> None:
    record = source_identity.SourceRecord(
        source_relative="a.py",
        archive_member="pkg/a.py",
        raw_sha256=_digest("a"),
        size_bytes=1,
    )
    identity = source_identity.build_source_identity([record])
    assert source_identity.parse_source_identity(identity) == identity
    with pytest.raises(Phase2AuditError):
        source_identity.build_source_identity(
            [record, source_identity.SourceRecord("b.py", "pkg/a.py", _digest("b"), 1)]
        )
    with pytest.raises(Phase2AuditError):
        parse_canonical_mapping(b'{"b":1, "a":2}', label="noncanonical")


def _load_freeze_builder() -> Any:
    path = (
        constants.PROJECT_ROOT
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
        "r8_r7_phase2_auditor_v1/freeze_auditor.py"
    )
    spec = importlib.util.spec_from_file_location("phase2_auditor_freeze_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_in_memory_archive_is_deterministic_and_vendors_static_custody() -> None:
    builder = _load_freeze_builder()
    sources, identity = builder.collect_sources()
    identity_raw = builder.canonical(identity)
    first = builder.build_archive(sources, identity_raw)
    second = builder.build_archive(sources, identity_raw)
    assert first == second
    receipt = verify_archive_bytes(first)
    assert receipt["source_record_count"] == len(sources)
    members = {row["archive_member"] for row in identity["records"]}
    static_prefix = (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
        "r8_r7_static_design_v1/"
    )
    assert f"{static_prefix}filesystem_identity.py" in members
    assert f"{static_prefix}canonical.py" in members
    assert f"{static_prefix}__init__.py" in members
    with zipfile.ZipFile(Path(os.devnull), "w") if False else zipfile.ZipFile(
        __import__("io").BytesIO(first), "r"
    ) as archive:
        assert archive.read(f"{static_prefix}filesystem_identity.py") == (
            constants.PROJECT_ROOT / f"{static_prefix}filesystem_identity.py"
        ).read_bytes()


def test_no_live_archive_verifier_runs_isolated_with_mutable_import_zero(
    tmp_path: Path,
) -> None:
    builder = _load_freeze_builder()
    sources, identity = builder.collect_sources()
    archive_raw = builder.build_archive(sources, builder.canonical(identity))
    archive_path = tmp_path / "AUDITOR.pyz"
    archive_path.write_bytes(archive_raw)
    completed = subprocess.run(
        [
            str(constants.PINNED_PYTHON),
            "-I",
            "-B",
            str(archive_path),
            constants.VERIFY_FLAG,
        ],
        cwd=tmp_path,
        env={
            "SYSTEMROOT": os.environ["SYSTEMROOT"],
            "WINDIR": os.environ["WINDIR"],
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
            "PYTHONHASHSEED": "0",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    assert completed.returncode == constants.TERMINAL_NO_GO_EXIT_CODE
    assert completed.stderr == b""
    result = json.loads(completed.stdout)
    assert result["status"] == "VERIFIED_FROZEN_AUDITOR_ARCHIVE_NO_LIVE_INPUT"
    assert result["live_audit_executed"] is False
    assert result["qualification_generation_count"] == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ABI smoke")
def test_win32_64bit_handle_abi_and_object_basic_native_smoke() -> None:
    kernel32 = win32_live._kernel32()
    handle = kernel32.OpenProcess(
        win32_live.PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        os.getpid(),
    )
    assert handle
    try:
        basic = win32_live._object_basic(__import__("ctypes").wintypes.HANDLE(handle))
        assert int(basic.handle_count) >= 1
        assert win32_live._object_type_name(
            __import__("ctypes").wintypes.HANDLE(handle)
        ) == "Process"
        assert kernel32.OpenProcess.restype is __import__("ctypes").wintypes.HANDLE
        assert kernel32.QueryInformationJobObject.argtypes is not None
        assert kernel32.GetProcessTimes.argtypes is not None
        assert kernel32.GetExitCodeProcess.argtypes is not None
        assert kernel32.QueryFullProcessImageNameW.argtypes is not None
        assert kernel32.CreateToolhelp32Snapshot.argtypes is not None
    finally:
        win32_live._close_handle_checked(kernel32, handle, label="native smoke process")


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 held ancestry custody")
def test_fixed_held_file_retains_reparse_free_ancestry_and_denies_swap(
    tmp_path: Path,
) -> None:
    target = tmp_path / "held.bin"
    target.write_bytes(b"held immutable bytes")
    with HeldFile(target) as held:
        assert held._archive_custody is not None
        receipt = held._archive_custody.receipt()
        assert receipt["all_ancestry_handles_held"] is True
        assert receipt["write_share_allowed"] is False
        assert receipt["delete_share_allowed"] is False
        with pytest.raises(PermissionError):
            target.write_bytes(b"same size drifted!!")
        held.assert_reopen_exact()


def test_close_handle_failure_is_terminal_and_process_window_unwinds_all() -> None:
    class Kernel:
        def __init__(self) -> None:
            self.closed: list[int] = []

        def CloseHandle(self, handle: Any) -> bool:
            self.closed.append(int(handle.value))
            return False

    kernel = Kernel()
    with pytest.raises(Phase2AuditError, match="CloseHandle failed for injected"):
        win32_live._close_handle_checked(kernel, 91, label="injected handle")
    window = win32_live.LiveProcessWindow({})
    window._kernel32 = kernel
    window._handles = {"supervisor": 101, "signer": 102, "auditor": 103}
    with pytest.raises(Phase2AuditError, match="process-window cleanup failed"):
        window.close()
    assert kernel.closed[-3:] == [103, 102, 101]
    assert window._handles == {}


def test_job_membership_process_close_failure_cannot_return_success() -> None:
    class Kernel:
        def OpenProcess(self, *_args: Any) -> int:
            return 818

        def IsProcessInJob(self, *_args: Any) -> bool:
            result = _args[-1]
            result._obj.value = 1
            return True

        def CloseHandle(self, _handle: Any) -> bool:
            return False

    with pytest.raises(Phase2AuditError, match="CloseHandle failed"):
        win32_live.InheritedJobQuery._require_process_in_exact_job(
            Kernel(), pid=12, job=__import__("ctypes").wintypes.HANDLE(77)
        )


def test_live_terminal_reports_inherited_query_close_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Fixed:
        def __enter__(self) -> "Fixed":
            raise Phase2AuditError("injected primary failure")

        def __exit__(self, *_args: object) -> None:
            return None

    class Job:
        def close_if_open(self) -> None:
            raise Phase2AuditError("CloseHandle failed for injected Job")

    class Custody:
        ledger_raw_sha256 = _digest("injected no-go ledger")

        def assert_exact(self) -> None:
            return None

        def close(self) -> None:
            return None

    monkeypatch.setattr(runtime, "FixedInputWindow", Fixed)
    monkeypatch.setattr(runtime, "InheritedJobQuery", lambda _value: Job())
    monkeypatch.setattr(runtime, "publish_supplemental", lambda _raw: Custody())
    result = runtime.run_live_audit(
        query_handle_value=73,
        running_archive=tmp_path / "AUDITOR.pyz",
    )
    assert result["verdict"] == "NO_GO"
    assert "inherited_query_cleanup" in result["finding"]
    assert "CloseHandle failed" in result["finding"]


def test_terminal_custody_close_failure_replaces_go_capability_with_no_go(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Fixed:
        def __enter__(self) -> "Fixed":
            raise Phase2AuditError("injected validation failure")

        def __exit__(self, *_args: object) -> None:
            return None

    class Job:
        def close_if_open(self) -> None:
            return None

    class Custody:
        ledger_raw_sha256 = _digest("injected close ledger")

        def assert_exact(self) -> None:
            return None

        def close(self) -> None:
            raise Phase2AuditError("CloseHandle failed for terminal custody")

    monkeypatch.setattr(runtime, "FixedInputWindow", Fixed)
    monkeypatch.setattr(runtime, "InheritedJobQuery", lambda _value: Job())
    monkeypatch.setattr(runtime, "publish_supplemental", lambda _raw: Custody())
    result = runtime.run_live_audit(
        query_handle_value=74,
        running_archive=tmp_path / "AUDITOR.pyz",
    )
    assert result["verdict"] == "NO_GO"
    assert result["status"] == "IN_MEMORY_ONLY"
    assert "terminal_custody_cleanup" in result["finding"]
    assert "CloseHandle failed" in result["finding"]


def test_planned_paths_stay_within_legacy_budget_and_outputs_unconsumed() -> None:
    leaves = (
        "AUDITOR.pyz",
        "SOURCE_IDENTITY.json",
        "COMMAND_LOCK.json",
        "QUALITY_RECEIPT.json",
        "CHECKSUMS.sha256",
    )
    root = constants.fixed_path(constants.AUDITOR_FREEZE_ROOT_RELATIVE)
    assert max(len(str(root / leaf)) for leaf in leaves) <= 240
    assert not root.exists()
    for suffix in (".staging", ".fail", ".fstg"):
        assert not (constants.OUTPUTS_ROOT / f".{root.name}{suffix}").exists()


def test_archive_entry_accepts_only_positive_canonical_decimal_handle() -> None:
    assert archive_entry._canonical_decimal_handle("812") == 812
    for value in ("", "0", "0812", "+1", " 1", "1.0", "１２"):
        with pytest.raises(Phase2AuditError):
            archive_entry._canonical_decimal_handle(value)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 custody publication")
def test_synthetic_held_publication_and_ack_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    live = outputs / Path(constants.LIVE_ROOT_RELATIVE).name
    live.mkdir(parents=True)
    supplemental = outputs / Path(constants.SUPPLEMENTAL_ROOT_RELATIVE).name
    witness = live / "AUDITOR_JOB_WITNESS.json"
    ack = live / "AUDITOR_RELEASE_ACK.json"

    def synthetic_fixed(relative: str) -> Path:
        if relative == constants.LIVE_ROOT_RELATIVE:
            return live
        if relative == constants.JOB_WITNESS_RELATIVE:
            return witness
        if relative == constants.SUPPLEMENTAL_ROOT_RELATIVE:
            return supplemental
        if relative == constants.AUDITOR_RELEASE_ACK_RELATIVE:
            return ack
        raise AssertionError(relative)

    monkeypatch.setattr(publication, "PROJECT_ROOT", project)
    monkeypatch.setattr(publication, "OUTPUTS_ROOT", outputs)
    monkeypatch.setattr(publication, "fixed_path", synthetic_fixed)
    with publication.publish_job_witness(b'{"synthetic":true}') as witness_custody:
        witness_custody.assert_exact()
        assert witness_custody.raw_sha256 == sha256_bytes(b'{"synthetic":true}')
        ack.write_bytes(b'{"ack":true}')
        artifacts = publication.build_supplemental_artifacts(
            verdict="NO_GO",
            generated_at=datetime.now(UTC),
            evidence=None,
            finding="synthetic terminal finding",
        )
        with publication.publish_supplemental(artifacts) as supplemental_custody:
            supplemental_custody.assert_exact()
            held_ack = supplemental_custody.hold_live_artifact(ack)
            try:
                assert held_ack.raw_bytes() == b'{"ack":true}'
                assert held_ack.receipt()["write_share_allowed"] is False
                assert held_ack.receipt()["delete_share_allowed"] is False
            finally:
                held_ack.close()
            witness_custody.assert_exact()
    assert supplemental.is_dir()
    assert not (outputs / publication.SUPPLEMENTAL_STAGING_NAME).exists()
    assert not (live / publication.JOB_WITNESS_STAGING).exists()
    with pytest.raises(Exception):
        publication.publish_supplemental(artifacts)


def test_synthetic_end_to_end_ping_then_go_then_ack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = _validated_bundle()
    trace: list[str] = []
    initial_now = datetime.now(UTC)
    pre_hash = sha256_bytes(bundle["prebinding_raw"])
    final_hash = sha256_bytes(bundle["final_raw"])
    initial = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=1,
        probe_count=0,
        observed_at=initial_now,
    )
    final = _telemetry(
        prebinding_raw_sha256=pre_hash,
        final_raw_sha256=final_hash,
        final_binding=bundle["final"],
        sequence=2,
        probe_count=1,
        observed_at=initial_now + timedelta(milliseconds=10),
    )

    class Receipt:
        raw_sha256 = LOCK_RAW_SHA256
        file_id_128 = LOCK_FILE_ID

    class Fixed:
        prebinding = bundle["prebinding"]
        prebinding_raw_sha256 = pre_hash
        lock = bundle["lock"]
        files = {"binding_lock": type("Held", (), {"receipt": Receipt()})()}
        generation_vendored_receipt = {
            "status": "PASS_INDEPENDENT_SOURCE_LOCK_TO_PYZ_MEMBER_BYTE_CLOSURE"
        }
        generation_runtime_receipt = {
            "status": "PASS_HELD_DISTRIBUTION_AND_STDLIB_BYTE_UNIVERSE"
        }
        generation_import_receipt = {
            "status": (
                "PASS_FROZEN_ARCHIVE_NARROW_IMPORT_SPENT_DRY_RUN_UNHELD_ZERO"
            ),
            "semantic_sha256": bundle["lock"][
                "generation_import_closure_receipt_semantic_sha256"
            ],
        }

        def __enter__(self) -> "Fixed":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def require_running_archive(self, _path: Path) -> None:
            trace.append("fixed")

        def assert_all_reopen_exact(self) -> None:
            trace.append("fixed_reopen")

    class Processes:
        count = 0

        def __enter__(self) -> "Processes":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def snapshot(self) -> dict[str, int]:
            self.count += 1
            trace.append(f"snapshot{self.count}")
            return {"snapshot": 1}

    class Held:
        def __init__(self, path: Path) -> None:
            self.raw = (
                bundle["readiness_raw"]
                if path.name == "READINESS.json"
                else bundle["final_raw"]
            )
            self.receipt = type(
                "Receipt",
                (),
                {"raw_sha256": sha256_bytes(self.raw), "file_id_128": "44" * 16},
            )()

        def __enter__(self) -> "Held":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def assert_reopen_exact(self) -> None:
            trace.append("held_reopen")

    class Job:
        def collect_and_close(self, **_kwargs: Any) -> dict[str, Any]:
            trace.append("job_close")
            return bundle["witness"]

        def close_if_open(self) -> None:
            trace.append("job_cleanup")

    class WitnessCustody:
        raw_sha256 = sha256_bytes(canonical_json_bytes(bundle["witness"]))

        def require_live_leaf_missing(self, _name: str) -> None:
            trace.append("ack_absent")

        def assert_exact(self) -> None:
            trace.append("witness_reopen")

        def close(self) -> None:
            trace.append("witness_close")

    class SupplementalCustody:
        ledger_raw_sha256 = _digest("synthetic supplemental ledger")

        def assert_exact(self) -> None:
            trace.append("supplemental_reopen")

        def close(self) -> None:
            trace.append("supplemental_close")

    class AckCustody:
        def receipt(self) -> dict[str, str]:
            trace.append("ack_reopen")
            return {"raw_sha256": _digest("ack")}

        def close(self) -> None:
            trace.append("ack_close")

    monkeypatch.setattr(runtime, "FixedInputWindow", Fixed)
    monkeypatch.setattr(runtime, "LiveProcessWindow", lambda _prebinding: Processes())
    monkeypatch.setattr(runtime, "HeldFile", Held)
    monkeypatch.setattr(runtime, "InheritedJobQuery", lambda _value: Job())
    monkeypatch.setattr(runtime, "_wait_for_fixed_file", lambda *_args, **_kw: None)
    monkeypatch.setattr(
        runtime,
        "_wait_initial_telemetry",
        lambda _hash: (
            trace.append("telemetry0") or canonical_json_bytes(initial),
            initial,
        ),
    )

    def synthetic_probe(**_kwargs: Any) -> dict[str, Any]:
        trace.append("ping")
        return {
            "status": "PASS_ONE_READ_ONLY_ENDPOINT_CONTACT_SAME_PUBLIC_IDENTITY",
            "signer_endpoint_contact_count": 1,
            "authority_request_count": 0,
            "authority_signature_count": 0,
            "request_raw_sha256": _digest("request"),
            "response_raw_sha256": _digest("response"),
            "response": {},
        }

    monkeypatch.setattr(runtime, "probe_readiness_endpoint", synthetic_probe)
    monkeypatch.setattr(
        runtime,
        "_wait_progressed_telemetry",
        lambda _row: (
            trace.append("telemetry1") or canonical_json_bytes(final),
            final,
        ),
    )
    monkeypatch.setattr(
        runtime,
        "stable_process_window",
        lambda *_args: {
            "status": "PASS_HELD_PROCESS_CREATION_IMAGE_COMMAND_STABLE",
            "processes": {},
            "semantic_sha256": _digest("process window"),
        },
    )
    monkeypatch.setattr(
        runtime,
        "validate_telemetry_pair",
        lambda **_kwargs: {
            "status": "PASS_STRICT_PROGRESS_DOUBLE_SNAPSHOT_ZERO_COUNTERS",
            "request_count": 0,
            "signature_count": 0,
        },
    )
    monkeypatch.setattr(
        runtime,
        "publish_job_witness",
        lambda _raw: (trace.append("publish_witness") or WitnessCustody()),
    )
    monkeypatch.setattr(
        runtime,
        "publish_supplemental",
        lambda _artifacts: (trace.append("publish_go") or SupplementalCustody()),
    )

    def synthetic_wait_ack(**_kwargs: Any) -> tuple[AckCustody, dict[str, Any]]:
        trace.append("ack")
        return AckCustody(), {}

    monkeypatch.setattr(runtime, "_wait_release_ack", synthetic_wait_ack)
    result = runtime.run_live_audit(
        query_handle_value=bundle["prebinding"]["job_evidence"][
            "auditor_query_handle_value"
        ],
        running_archive=tmp_path / "AUDITOR.pyz",
    )
    assert result["verdict"] == "GO"
    assert result["release_ack_validated"] is True
    assert trace.index("telemetry0") < trace.index("ping") < trace.index("telemetry1")
    assert trace.index("telemetry1") < trace.index("publish_go") < trace.index("ack")
    assert trace.index("ack") < trace.index("snapshot3")


def test_release_ack_wait_is_finite_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _validated_bundle()
    moments = iter((0.0, 31.0))
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(moments))
    with pytest.raises(Phase2AuditError, match="release ACK wait expired"):
        runtime._wait_release_ack(
            prebinding=bundle["prebinding"],
            prebinding_raw_sha256=sha256_bytes(bundle["prebinding_raw"]),
            final_binding=bundle["final"],
            final_binding_raw_sha256=sha256_bytes(bundle["final_raw"]),
            supplemental_checksums_raw_sha256=_digest("supplemental"),
            publication_at=datetime.now(UTC),
            supplemental_custody=object(),
        )


def test_generation_closure_cross_package_exact_14_distribution_contract() -> None:
    assert set(constants.GENERATION_DISTRIBUTION_NAMES) == set(
        execution_generation_closure.EXPECTED_RUNTIME_DISTRIBUTIONS
    )
    assert (
        constants.GENERATION_EXPECTED_DISTRIBUTIONS
        == execution_generation_closure.EXPECTED_RUNTIME_DISTRIBUTIONS
    )
    assert set(constants.GENERATION_CLOSURE_RUNTIME_KEYS) == set(
        execution_generation_closure.RUNTIME_CLOSURE_KEYS
    )
    assert set(constants.GENERATION_CLOSURE_DISTRIBUTION_KEYS) == set(
        execution_generation_closure.DISTRIBUTION_KEYS
    )
    assert set(constants.GENERATION_CLOSURE_LOADED_ORIGIN_POLICY_KEYS) == set(
        execution_generation_closure.LOADED_ORIGIN_POLICY_KEYS
    )
    assert set(constants.GENERATION_CLOSURE_WORKER_RESOURCE_KEYS) == set(
        execution_generation_closure.WORKER_RESOURCE_CONTRACT_KEYS
    )
    assert generation_closure.IMPORT_ENTRYPOINTS == execution_import_closure.ENTRYPOINTS
    assert (
        generation_closure.IMPORT_CLOSURE_RECEIPT_KEYS
        == execution_import_closure.IMPORT_CLOSURE_KEYS
    )
    assert (
        generation_closure.IMPORT_CONCRETE_ORIGIN_KEYS
        == execution_import_closure.CONCRETE_ORIGIN_KEYS
    )
    assert (
        generation_closure.IMPORT_NAMESPACE_ORIGIN_KEYS
        == execution_import_closure.NAMESPACE_ORIGIN_KEYS
    )
    assert (
        generation_closure.IMPORT_SNAPSHOT_KEYS
        == execution_import_closure.SNAPSHOT_KEYS
    )


def test_vendored_archive_members_are_rederived_and_byte_rehashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_raw = b"print('held source')\n"
    extra_raw = b'{"held":true}\n'
    source_relative = "src/pkg/a.py"
    extra_relative = "fixed/extra.json"
    lock = {
        "schema_version": "expected_pe.r7.qualification.source_lock.v1",
        "status": "FROZEN_HARD_CODED_EXECUTABLE_AND_HERITAGE_CLOSURE",
        "execution_transitive_local_files": [source_relative],
        "source_sha256": [
            [source_relative, sha256_bytes(source_raw), len(source_raw)],
            [extra_relative, sha256_bytes(extra_raw), len(extra_raw)],
        ],
    }
    lock_raw = json.dumps(lock, separators=(",", ":")).encode("utf-8")
    records = [
        {
            "source_relative": extra_relative,
            "archive_member": extra_relative,
            "raw_sha256": sha256_bytes(extra_raw),
            "size_bytes": len(extra_raw),
        },
        {
            "source_relative": source_relative,
            "archive_member": "pkg/a.py",
            "raw_sha256": sha256_bytes(source_raw),
            "size_bytes": len(source_raw),
        },
    ]
    records.sort(key=lambda row: row["archive_member"])
    monkeypatch.setattr(
        generation_closure,
        "GENERATION_R7_SOURCE_LOCK_RAW_SHA256",
        sha256_bytes(lock_raw),
    )
    monkeypatch.setattr(
        generation_closure,
        "GENERATION_R7_SOURCE_LOCK_SIZE_BYTES",
        len(lock_raw),
    )
    monkeypatch.setattr(
        generation_closure,
        "GENERATION_VENDORED_FIXED_EXTRAS",
        ((extra_relative, sha256_bytes(extra_raw), len(extra_raw)),),
    )
    monkeypatch.setattr(generation_closure, "GENERATION_VENDORED_RECORD_COUNT", 2)
    monkeypatch.setattr(
        generation_closure,
        "GENERATION_VENDORED_RECORDS_SEMANTIC_SHA256",
        sha256_bytes(canonical_json_bytes(records)),
    )

    def archive_bytes(*, bad_source: bool = False) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(extra_relative, extra_raw)
            archive.writestr(
                "pkg/a.py",
                b"print('held sourcf')\n" if bad_source else source_raw,
            )
        return buffer.getvalue()

    closure = {"vendored_sources": {"records": records}}
    receipt = generation_closure.verify_vendored_archive_members(
        execution_archive_raw=archive_bytes(),
        source_lock_raw=lock_raw,
        closure=closure,
    )
    assert receipt["record_count"] == 2
    assert receipt["all_member_hashes_and_sizes_recomputed"] is True
    with pytest.raises(Phase2AuditError, match="member bytes drifted"):
        generation_closure.verify_vendored_archive_members(
            execution_archive_raw=archive_bytes(bad_source=True),
            source_lock_raw=lock_raw,
            closure=closure,
        )


def test_external_archive_rejects_noncanonical_compression() -> None:
    member = "pkg/runtime.py"
    member_raw = b"pass\n"
    identity = {
        "schema_version": "synthetic.execution.source_identity.v1",
        "record_count": 1,
        "records": [
            {
                "source_relative": member,
                "archive_member": member,
                "raw_sha256": sha256_bytes(member_raw),
                "size_bytes": len(member_raw),
            }
        ],
    }
    identity["records_semantic_sha256"] = sha256_bytes(
        canonical_json_bytes(identity["records"])
    )
    identity_raw = canonical_json_bytes(identity)
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("SOURCE_IDENTITY.json", identity_raw)
        archive.writestr(member, member_raw)
    with pytest.raises(Phase2AuditError, match="path/compression"):
        verify_external_archive_bytes(
            buffer.getvalue(),
            external_identity_raw=identity_raw,
            expected_source_schema="synthetic.execution.source_identity.v1",
        )


def test_runtime_file_custody_rehashes_receipts_and_record_universe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    venv = tmp_path / "venv"
    site = venv / "Lib" / "site-packages"
    base = tmp_path / "base"
    payload_relative = "demo/data.bin"
    record_relative = "demo-1.0.dist-info/RECORD"
    stdlib_relative = "Lib/startup.py"
    payload_raw = b"DATA"
    record_raw = (
        f"{payload_relative},,\n{record_relative},,\n".encode("utf-8")
    )
    stdlib_raw = b"pass\n"
    raw_by_path = {
        os.path.normcase(str(site / "demo" / "data.bin")): payload_raw,
        os.path.normcase(str(site / "demo-1.0.dist-info" / "RECORD")): record_raw,
        os.path.normcase(str(base / "Lib" / "startup.py")): stdlib_raw,
    }

    class FakeCustody:
        def __init__(self, *, path: Path, root: Path) -> None:
            del root
            self.path = Path(os.path.abspath(path))
            self.raw = raw_by_path[os.path.normcase(str(self.path))]
            self.closed = False

        def __enter__(self) -> "FakeCustody":
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

        def receipt(self) -> dict[str, Any]:
            return {
                "raw_sha256": sha256_bytes(self.raw),
                "size_bytes": len(self.raw),
                "write_share_allowed": False,
                "delete_share_allowed": False,
            }

        def raw_bytes(self) -> bytes:
            return self.raw

    monkeypatch.setattr(generation_closure, "GENERATION_VENV_ROOT", venv)
    monkeypatch.setattr(generation_closure, "GENERATION_SITE_PACKAGES_ROOT", site)
    monkeypatch.setattr(generation_closure, "GENERATION_PYTHON_BASE_PREFIX", base)
    monkeypatch.setattr(generation_closure, "SupervisorArchiveCustody", FakeCustody)
    records = [
        {
            "relative": payload_relative,
            "raw_sha256": sha256_bytes(payload_raw),
            "size_bytes": len(payload_raw),
        },
        {
            "relative": record_relative,
            "raw_sha256": sha256_bytes(record_raw),
            "size_bytes": len(record_raw),
        },
    ]
    closure = {
        "runtime_closure": {
            "distributions": {
                "demo": {
                    "record_raw_sha256": sha256_bytes(record_raw),
                    "records": records,
                }
            },
            "python_stdlib": {
                "records": [
                    {
                        "relative": stdlib_relative,
                        "raw_sha256": sha256_bytes(stdlib_raw),
                        "size_bytes": len(stdlib_raw),
                    }
                ]
            },
        }
    }
    with ExitStack() as stack:
        held, receipt = generation_closure.hold_runtime_file_universe(
            stack=stack,
            closure=closure,
        )
        assert len(held) == 3
        assert receipt["held_file_count"] == 3
        assert receipt["record_member_universe_recomputed"] is True

    drifted = deepcopy(closure)
    drifted["runtime_closure"]["distributions"]["demo"]["records"][0][
        "raw_sha256"
    ] = sha256_bytes(b"DATO")
    with ExitStack() as stack, pytest.raises(
        Phase2AuditError, match="held distribution runtime bytes drifted"
    ):
        generation_closure.hold_runtime_file_universe(
            stack=stack,
            closure=drifted,
        )

    unlisted = deepcopy(closure)
    unlisted["runtime_closure"]["distributions"]["demo"]["records"].append(
        {
            "relative": "demo/unlisted.bin",
            "raw_sha256": sha256_bytes(payload_raw),
            "size_bytes": len(payload_raw),
        }
    )
    raw_by_path[
        os.path.normcase(str(site / "demo" / "unlisted.bin"))
    ] = payload_raw
    with ExitStack() as stack, pytest.raises(
        Phase2AuditError, match="RECORD/member universe drifted"
    ):
        generation_closure.hold_runtime_file_universe(
            stack=stack,
            closure=unlisted,
        )


def test_import_receipt_binds_held_owners_and_preserves_preexisting_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = _lock()
    archive_hash = lock["execution_archive_raw_sha256"]
    source_identity_raw = b"synthetic source identity"
    source_hash = sha256_bytes(source_identity_raw)
    lock["execution_source_identity_raw_sha256"] = source_hash
    archive_receipt = {
        "raw_sha256": archive_hash,
        "size_bytes": 901,
        "volume_serial_number": 44,
        "file_id_128": "44" * 16,
    }

    def owner(
        *, origin_class: str, origin_identity: str, ordinal: int
    ) -> tuple[tuple[str, str], dict[str, Any]]:
        return (
            (origin_class, origin_identity),
            {
                "content_raw_sha256": _digest(f"content-{ordinal}"),
                "content_size_bytes": 100 + ordinal,
                "held_container_relative": (
                    "EXECUTION.pyz"
                    if origin_class == "FROZEN_EXECUTION_ARCHIVE_MEMBER"
                    else f"Lib/runtime-{ordinal}.py"
                ),
                "held_container_raw_sha256": (
                    archive_hash
                    if origin_class == "FROZEN_EXECUTION_ARCHIVE_MEMBER"
                    else _digest(f"container-{ordinal}")
                ),
                "held_container_size_bytes": (
                    archive_receipt["size_bytes"]
                    if origin_class == "FROZEN_EXECUTION_ARCHIVE_MEMBER"
                    else 100 + ordinal
                ),
                "held_container_volume_serial_number": (
                    archive_receipt["volume_serial_number"]
                    if origin_class == "FROZEN_EXECUTION_ARCHIVE_MEMBER"
                    else 50 + ordinal
                ),
                "held_container_file_id_128": (
                    archive_receipt["file_id_128"]
                    if origin_class == "FROZEN_EXECUTION_ARCHIVE_MEMBER"
                    else f"{50 + ordinal:032x}"
                ),
            },
        )

    existing_key, existing_owner = owner(
        origin_class="HELD_PYTHON_STDLIB_OR_NATIVE_FILE",
        origin_identity="Lib/existing.py",
        ordinal=1,
    )
    alternate_key, alternate_owner = owner(
        origin_class="HELD_PYTHON_STDLIB_OR_NATIVE_FILE",
        origin_identity="Lib/alternate.py",
        ordinal=2,
    )
    module_members = {
        entrypoint.split(":", 1)[0]: (
            entrypoint.split(":", 1)[0].replace(".", "/") + ".py"
        )
        for entrypoint in generation_closure.IMPORT_ENTRYPOINTS
    }
    archive_owner_items = [
        owner(
            origin_class="FROZEN_EXECUTION_ARCHIVE_MEMBER",
            origin_identity=member,
            ordinal=ordinal,
        )
        for ordinal, member in enumerate(module_members.values(), start=10)
    ]
    concrete_owners = {
        existing_key: existing_owner,
        alternate_key: alternate_owner,
        **dict(archive_owner_items),
    }

    def concrete_record(
        *, module: str, key: tuple[str, str]
    ) -> dict[str, Any]:
        return {
            "module": module,
            "origin_class": key[0],
            "origin_identity": key[1],
            **concrete_owners[key],
        }

    def snapshot(stage: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        ordered = sorted(records, key=lambda record: record["module"])
        combined = [{"kind": "CONCRETE", **record} for record in ordered]
        return {
            "schema_version": "expected_pe.r8.r7.phase2.loaded_origin_snapshot.v1",
            "status": "PASS_NO_MUTABLE_WORKSPACE_OR_UNHELD_MODULE_ORIGIN",
            "stage": stage,
            "concrete_records": ordered,
            "namespace_records": [],
            "concrete_record_count": len(ordered),
            "namespace_record_count": 0,
            "records_semantic_sha256": sha256_bytes(
                canonical_json_bytes(combined)
            ),
            "mutable_workspace_origin_count": 0,
            "unheld_origin_count": 0,
            "base_parent_search_count": 0,
        }

    pre_record = concrete_record(module="stdlib_existing", key=existing_key)
    imported = [
        concrete_record(
            module=module,
            key=("FROZEN_EXECUTION_ARCHIVE_MEMBER", member),
        )
        for module, member in module_members.items()
    ]
    pre = snapshot("PRE_GENERATION_IMPORT", [pre_record])
    post = snapshot("POST_GENERATION_IMPORT", [pre_record, *imported])
    newly = sorted(imported, key=lambda record: record["module"])
    newly_combined = [{"kind": "CONCRETE", **record} for record in newly]
    runtime = {
        "distributions": {name: {} for name in constants.GENERATION_DISTRIBUTION_NAMES},
        "python_stdlib": {"records": []},
        "worker_resource_contract": {"fixed": True},
    }
    closure = {"runtime_closure": runtime}
    receipt: dict[str, Any] = {
        "schema_version": (
            "expected_pe.r8.r7.phase2.generation_import_closure_receipt.v1"
        ),
        "status": (
            "PASS_FROZEN_ARCHIVE_NARROW_IMPORT_SPENT_DRY_RUN_UNHELD_ZERO"
        ),
        "execution_archive_raw_sha256": archive_hash,
        "execution_source_identity_raw_sha256": source_hash,
        "generation_external_input_closure_raw_sha256": lock[
            "generation_external_input_closure_raw_sha256"
        ],
        "entrypoints": list(generation_closure.IMPORT_ENTRYPOINTS),
        "pre_import_snapshot": pre,
        "post_import_snapshot": post,
        "newly_loaded_concrete_records": newly,
        "newly_loaded_namespace_records": [],
        "newly_loaded_record_count": len(newly),
        "newly_loaded_records_semantic_sha256": sha256_bytes(
            canonical_json_bytes(newly_combined)
        ),
        "runtime_distribution_names": sorted(
            constants.GENERATION_DISTRIBUTION_NAMES
        ),
        "runtime_distribution_count": len(constants.GENERATION_DISTRIBUTION_NAMES),
        "runtime_distributions_semantic_sha256": sha256_bytes(
            canonical_json_bytes(runtime["distributions"])
        ),
        "python_runtime_records_semantic_sha256": (
            constants.GENERATION_PYTHON_RUNTIME_RECORDS_SEMANTIC_SHA256
        ),
        "expected_worker_resource_contract_semantic_sha256": sha256_bytes(
            canonical_json_bytes(runtime["worker_resource_contract"])
        ),
        "mutable_workspace_import_count": 0,
        "unheld_origin_count": 0,
        "generator_invocation_count": 0,
        "comparator_invocation_count": 0,
        "qualification_generation_count": 0,
        "actual_process_launch_count": 0,
        "fresh_access_count": 0,
        "heldout_access_count": 0,
        "truth_access_count": 0,
        "score_access_count": 0,
    }

    def seal(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        sealed = deepcopy(value)
        semantic = {
            key: sealed[key]
            for key in sorted(
                generation_closure.IMPORT_CLOSURE_RECEIPT_KEYS
                - {"semantic_sha256"}
            )
        }
        sealed["semantic_sha256"] = sha256_bytes(canonical_json_bytes(semantic))
        raw = canonical_json_bytes(sealed)
        receipt_lock = deepcopy(lock)
        receipt_lock[
            "generation_import_closure_receipt_semantic_sha256"
        ] = sealed["semantic_sha256"]
        receipt_lock["generation_import_closure_receipt_raw_sha256"] = (
            sha256_bytes(raw)
        )
        return sealed, receipt_lock

    monkeypatch.setattr(
        generation_closure,
        "_runtime_owner_rows",
        lambda **_kwargs: (
            {existing_key: existing_owner, alternate_key: alternate_owner},
            set(),
        ),
    )
    monkeypatch.setattr(
        generation_closure,
        "_archive_owner_rows",
        lambda **_kwargs: (dict(archive_owner_items), set()),
    )
    sealed, receipt_lock = seal(receipt)
    file_receipt = {
        "raw_sha256": receipt_lock[
            "generation_import_closure_receipt_raw_sha256"
        ],
        "volume_serial_number": receipt_lock[
            "generation_import_closure_receipt_volume_serial_number"
        ],
        "file_id_128": receipt_lock[
            "generation_import_closure_receipt_file_id_128"
        ],
        "size_bytes": receipt_lock["generation_import_closure_receipt_size_bytes"],
    }
    assert generation_closure.validate_import_closure_receipt(
        sealed,
        lock=receipt_lock,
        receipt_file_receipt=file_receipt,
        execution_archive_raw=b"synthetic archive",
        execution_archive_receipt=archive_receipt,
        execution_source_identity_raw=source_identity_raw,
        generation_closure=closure,
        generation_closure_raw_sha256=lock[
            "generation_external_input_closure_raw_sha256"
        ],
        runtime_custodies=(),
    )["newly_loaded_record_count"] == 3

    changed = deepcopy(receipt)
    changed_post = [
        concrete_record(module="stdlib_existing", key=alternate_key),
        *imported,
    ]
    changed["post_import_snapshot"] = snapshot(
        "POST_GENERATION_IMPORT", changed_post
    )
    changed_sealed, changed_lock = seal(changed)
    changed_file_receipt = {
        **file_receipt,
        "raw_sha256": changed_lock[
            "generation_import_closure_receipt_raw_sha256"
        ],
    }
    with pytest.raises(Phase2AuditError, match="changed one preexisting module"):
        generation_closure.validate_import_closure_receipt(
            changed_sealed,
            lock=changed_lock,
            receipt_file_receipt=changed_file_receipt,
            execution_archive_raw=b"synthetic archive",
            execution_archive_receipt=archive_receipt,
            execution_source_identity_raw=source_identity_raw,
            generation_closure=closure,
            generation_closure_raw_sha256=lock[
                "generation_external_input_closure_raw_sha256"
            ],
            runtime_custodies=(),
        )
