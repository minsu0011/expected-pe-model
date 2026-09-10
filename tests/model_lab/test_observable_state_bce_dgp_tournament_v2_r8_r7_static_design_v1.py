from __future__ import annotations

import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
import zipfile

import pytest

from scripts.model_lab.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.freeze_static_design import (
    OUTPUTS_ROOT,
    OUTPUT_ROOT,
    QUALITY_SUBPROCESS_COUNT,
    SCOPED_TEST_CASE_COUNT,
    TEST_RELATIVE,
    _adjacent_bytecode_preflight,
    _freeze_with_outputs_custody,
    _require_no_adjacent_bytecode,
    _require_exact_custody_bytes,
    _quality,
    _require_freeze_launcher_isolation,
)

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1 import (
    filesystem_identity,
    publication,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.artifact_contract import (
    A3_INVOCATION_SOURCE,
    A3_LAUNCHER_RELATIVE,
    A3_ONE_SHOT_PREFIX,
    A3_PINNED_PYTHON,
    A3_QUOTE_FREE_BOOTSTRAP,
    parse_command_lock,
    resolve_frozen_archive_path,
    validate_reopened_artifacts,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.archive_entry import (
    DISABLED_EXIT_CODE,
    EXECUTION_PACKAGE_BLOCKERS,
    REQUIRED_EXTERNAL_GATES,
    build_disabled_verification_result,
    validate_disabled_verification_result,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.canonical import (
    R8R7DesignError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.closure import (
    REOPENED_HASH_FIELDS,
    build_closure,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.consumer_reopen import (
    authority_reopen,
    immediate_issuance_reopen,
    signer_reopen,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.evidence import (
    ExactJobEvidence,
    ImageIdentity,
    JobHandleCloseEvidence,
    ProcessInstanceEvidence,
    bind_job_identity,
    expected_evidence_binding,
    validate_evidence_window,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (
    SupervisorArtifactCustody,
    SupervisorArchiveCustody,
    SupervisorDirectoryCustody,
    snapshot_reparse_free_ancestry,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.preflight import (
    FORBIDDEN_PREFIXES,
    STATIC_FREEZE_PREFIX,
    require_clean_r8_r7_preflight,
    scan_forbidden_r8_r7_identities,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.publication import (
    PERMITTED_STATIC_DESIGN_CHILD_NAME,
    R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
    publish_validated_design_no_go,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.source_identity import (
    SourceRecord,
    build_source_identity,
    parse_source_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.terminal import (
    ZERO_STATE_COUNT_KEYS,
    build_exception_negative_receipt,
    build_negative_receipt,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.traceability import (
    build_blocker_trace,
    validate_blocker_trace,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.win32_supervision import (
    JOB_OBJECT_ASSIGN_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_QUERY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST,
    STARTUPINFOEXW,
    build_win32_supervision_blueprint,
    validate_win32_supervision_blueprint,
)


NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
H = {letter: hashlib.sha256(letter.encode()).hexdigest() for letter in "abcdefghijklmnop"}


def _image() -> ImageIdentity:
    return ImageIdentity(
        path="C:/frozen/python.exe",
        raw_sha256=H["a"],
        volume_serial_number=101,
        file_id_128="1" * 32,
        size_bytes=1000,
        all_ancestors_reparse_free=True,
        stable_before_after=True,
    )


def _process(
    role: str,
    *,
    auditor_archive: str = H["f"],
    auditor_source: str = H["d"],
) -> ProcessInstanceEvidence:
    pids = {"SUPERVISOR": 41001, "SIGNER": 41002, "AUDITOR": 41003}
    creation = {
        "SUPERVISOR": 133_000_000_000_000_001,
        "SIGNER": 133_000_000_000_000_002,
        "AUDITOR": 133_000_000_000_000_003,
    }
    command = {"SUPERVISOR": H["c"], "SIGNER": H["b"], "AUDITOR": H["i"]}
    source = {"SUPERVISOR": H["e"], "SIGNER": H["d"], "AUDITOR": auditor_source}
    archive = {"SUPERVISOR": H["g"], "SIGNER": H["f"], "AUDITOR": auditor_archive}
    return ProcessInstanceEvidence(
        role=role,
        pid=pids[role],
        creation_time_100ns=creation[role],
        parent_pid=41000 if role == "SUPERVISOR" else pids["SUPERVISOR"],
        parent_snapshot_while_handles_open=True,
        process_handle_held_through_publication=True,
        alive=True,
        image=_image(),
        command_line_sha256=command[role],
        source_identity_sha256=source[role],
        archive_raw_sha256=archive[role],
    )


def _job(
    *,
    auditor_archive: str = H["f"],
    auditor_source: str = H["d"],
) -> ExactJobEvidence:
    supervisor = _process(
        "SUPERVISOR", auditor_archive=auditor_archive, auditor_source=auditor_source
    )
    auditor = _process(
        "AUDITOR", auditor_archive=auditor_archive, auditor_source=auditor_source
    )
    unsigned = ExactJobEvidence(
        job_identity_sha256="0" * 64,
        job_nonce_sha256=H["h"],
        supervisor_lifetime_handle_value=0x410,
        auditor_query_handle_value=0x414,
        assignment_handle_access_mask=JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY,
        query_handle_access_mask=JOB_OBJECT_QUERY,
        query_handle_inherited_from_supervisor=True,
        query_handle_recipient="AUDITOR_CHILD_ONLY",
        query_handle_open_during_snapshot=True,
        supervisor_retains_lifetime_handle=True,
        kill_on_job_close=True,
        limit_flags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        active_process_ids=(41002, 41003),
        handle_inventory_complete=True,
        unexpected_job_handle_count=0,
        named_job_lookup_used=False,
        null_job_query_used=False,
    )
    return bind_job_identity(unsigned, supervisor=supervisor, auditor=auditor)


def _job_close(job: ExactJobEvidence) -> JobHandleCloseEvidence:
    return JobHandleCloseEvidence(
        job_identity_sha256=job.job_identity_sha256,
        auditor_query_handle_value=job.auditor_query_handle_value,
        final_query_completed=True,
        query_handle_close_succeeded=True,
        closed_handle_probe_failed=True,
        supervisor_lifetime_handle_still_open=True,
        remaining_known_handle_roles=("SUPERVISOR_LIFETIME",),
        handle_inventory_complete=True,
        unexpected_job_handle_count=0,
        closed_at_utc=(NOW + timedelta(seconds=1, milliseconds=500)).isoformat(),
    )


def _binding(
    *,
    auditor_archive: str = H["f"],
    auditor_source: str = H["d"],
) -> dict[str, Any]:
    return dict(
        expected_evidence_binding(
            signer=_process(
                "SIGNER",
                auditor_archive=auditor_archive,
                auditor_source=auditor_source,
            ),
            supervisor=_process(
                "SUPERVISOR",
                auditor_archive=auditor_archive,
                auditor_source=auditor_source,
            ),
            auditor=_process(
                "AUDITOR",
                auditor_archive=auditor_archive,
                auditor_source=auditor_source,
            ),
            job=_job(auditor_archive=auditor_archive, auditor_source=auditor_source),
            expires_at_utc=(NOW + timedelta(seconds=120)).isoformat(),
        )
    )


def _telemetry(
    sequence: int,
    observed: datetime,
    *,
    auditor_archive: str = H["f"],
    auditor_source: str = H["d"],
) -> dict[str, Any]:
    binding = _binding(
        auditor_archive=auditor_archive, auditor_source=auditor_source
    )
    static_keys = {
        "job_identity_sha256",
        "job_limit_flags",
        "job_active_process_count",
        "job_active_process_ids",
        "signer_pid_listed_by_exact_job",
        "auditor_pid_listed_by_exact_job",
        "auditor_inherited_or_duplicated_job_query_handle_witness",
        *(f"{role}_{field}" for role in ("signer", "supervisor", "auditor") for field in ("pid", "creation_time_100ns", "source_identity_sha256")),
    }
    return {
        "state": "READY",
        "heartbeat_sequence": sequence,
        "request_count": 0,
        "signature_count": 0,
        "exit_status": None,
        "error_code": None,
        "private_key_persisted": False,
        "detached_process": False,
        "parent_supervised": True,
        "foreground_supervised": True,
        "started_at_utc": (NOW - timedelta(seconds=60)).isoformat(),
        "last_heartbeat_utc": (observed - timedelta(seconds=1)).isoformat(),
        "observed_at_utc": observed.isoformat(),
        **{key: binding[key] for key in static_keys},
    }


def _window(
    *,
    auditor_archive: str = H["f"],
    auditor_source: str = H["d"],
    **changes: Any,
) -> dict[str, Any]:
    job = _job(auditor_archive=auditor_archive, auditor_source=auditor_source)
    values: dict[str, Any] = {
        "binding": _binding(
            auditor_archive=auditor_archive, auditor_source=auditor_source
        ),
        "signer_initial": _process(
            "SIGNER", auditor_archive=auditor_archive, auditor_source=auditor_source
        ),
        "signer_final": _process(
            "SIGNER", auditor_archive=auditor_archive, auditor_source=auditor_source
        ),
        "supervisor_initial": _process(
            "SUPERVISOR",
            auditor_archive=auditor_archive,
            auditor_source=auditor_source,
        ),
        "supervisor_final": _process(
            "SUPERVISOR",
            auditor_archive=auditor_archive,
            auditor_source=auditor_source,
        ),
        "auditor_initial": _process(
            "AUDITOR", auditor_archive=auditor_archive, auditor_source=auditor_source
        ),
        "auditor_final": _process(
            "AUDITOR", auditor_archive=auditor_archive, auditor_source=auditor_source
        ),
        "job_initial": job,
        "job_final": job,
        "job_close": _job_close(job),
        "telemetry_initial": _telemetry(
            61,
            NOW,
            auditor_archive=auditor_archive,
            auditor_source=auditor_source,
        ),
        "telemetry_final": _telemetry(
            62,
            NOW + timedelta(seconds=1),
            auditor_archive=auditor_archive,
            auditor_source=auditor_source,
        ),
        "initial_observed_at": NOW,
        "final_observed_at": NOW + timedelta(seconds=1),
        "publication_at": NOW + timedelta(seconds=2),
    }
    values.update(changes)
    return values


def _auditor_archive() -> tuple[bytes, bytes, dict[str, Any]]:
    member_raw = b"frozen-runtime-source"
    launcher_raw = b"synthetic-one-shot-launcher-source"
    identity = dict(
        build_source_identity(
            [
                SourceRecord(
                    source_relative="research/frozen.py",
                    archive_member="auditor_r8_r7/frozen.py",
                    raw_sha256=sha256_bytes(member_raw),
                    size_bytes=len(member_raw),
                ),
                SourceRecord(
                    source_relative=A3_LAUNCHER_RELATIVE,
                    archive_member="ONE_SHOT_LAUNCHER.ps1",
                    raw_sha256=sha256_bytes(launcher_raw),
                    size_bytes=len(launcher_raw),
                ),
            ]
        )
    )
    identity_raw = canonical_json_bytes(identity)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("SOURCE_IDENTITY.json", identity_raw)
        archive.writestr("auditor_r8_r7/frozen.py", member_raw)
        archive.writestr("ONE_SHOT_LAUNCHER.ps1", launcher_raw)
    return buffer.getvalue(), identity_raw, identity


def _closure_fixture() -> tuple[dict[str, Any], dict[str, bytes]]:
    archive_raw, identity_raw, identity = _auditor_archive()
    archive_hash = sha256_bytes(archive_raw)
    source_semantic = identity["records_semantic_sha256"]
    launcher_record = next(
        record
        for record in identity["records"]
        if record["source_relative"] == A3_LAUNCHER_RELATIVE
    )
    invocation_source_base64 = base64.b64encode(
        A3_INVOCATION_SOURCE.encode("utf-8")
    ).decode("ascii")
    command = {
        "schema_version": "expected_pe.r8.r7.static_design.command_lock.v2",
        "status": "FROZEN_DESIGN_ONLY_AWAITING_INDEPENDENT_AUDIT",
        "production_command": None,
        "production_execution_allowed": False,
        "signer_authority": None,
        "signer_launch_allowed": False,
        "binding_freeze_allowed": False,
        "supplemental_go_publication_allowed": False,
        "endpoint_contact_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
        "fresh_truth_heldout_access_allowed": False,
        "self_go_audit_allowed": False,
        "frozen_archive_relative": "outputs/frozen/AUDITOR.pyz",
        "frozen_archive_raw_sha256": archive_hash,
        "source_identity_raw_sha256": sha256_bytes(identity_raw),
        "source_records_semantic_sha256": source_semantic,
        "python_executable": _image().path,
        "python_executable_raw_sha256": _image().raw_sha256,
        "python_executable_volume_serial_number": _image().volume_serial_number,
        "python_executable_file_id_128": _image().file_id_128,
        "python_executable_size_bytes": _image().size_bytes,
        "one_shot_launcher": {
            "schema_version": "expected_pe.r8.r7.a3.one_shot_launcher.v1",
            "source_relative": A3_LAUNCHER_RELATIVE,
            "source_raw_sha256": launcher_record["raw_sha256"],
            "source_size_bytes": launcher_record["size_bytes"],
            "one_shot_prefix": A3_ONE_SHOT_PREFIX,
            "python_argv": [
                A3_PINNED_PYTHON,
                "-I",
                "-B",
                "-X",
                f"pycache_prefix={A3_ONE_SHOT_PREFIX}",
                "-c",
                A3_QUOTE_FREE_BOOTSTRAP,
                invocation_source_base64,
            ],
            "invocation_source_raw_sha256": sha256_bytes(
                A3_INVOCATION_SOURCE.encode("utf-8")
            ),
            "prefix_must_be_absent_before_atomic_create": True,
            "created_prefix_must_be_empty": True,
            "preexisting_prefix_builder_launch_count": 0,
            "authorized_builder_source_launch_count": 1,
            "four_output_identities_rechecked_before_dispatch": True,
        },
        "required_next_gate": "INDEPENDENT_STATIC_ADVERSARIAL_AUDIT",
    }
    command_raw = canonical_json_bytes(command)
    ledger_raw = "".join(
        f"{digest}  {name}\n"
        for name, digest in sorted(
            {
                "AUDITOR.pyz": archive_hash,
                "COMMAND_LOCK.json": sha256_bytes(command_raw),
                "SOURCE_IDENTITY.json": sha256_bytes(identity_raw),
            }.items()
        )
    ).encode("ascii")
    window = _window(auditor_archive=archive_hash, auditor_source=source_semantic)
    binding_raw = canonical_json_bytes(window["binding"])
    process_raw = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r8.r7.process_evidence.v1",
            **{
                key: asdict(window[key])
                for key in (
                    "signer_initial",
                    "signer_final",
                    "supervisor_initial",
                    "supervisor_final",
                    "auditor_initial",
                    "auditor_final",
                )
            },
        }
    )
    job_raw = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r8.r7.exact_job_witness.v1",
            "job_initial": asdict(window["job_initial"]),
            "job_final": asdict(window["job_final"]),
            "job_close": asdict(window["job_close"]),
        }
    )
    telemetry_raw = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r8.r7.telemetry_window.v1",
            "initial": window["telemetry_initial"],
            "final": window["telemetry_final"],
            "initial_observed_at_utc": window["initial_observed_at"].isoformat(),
            "final_observed_at_utc": window["final_observed_at"].isoformat(),
            "publication_at_utc": window["publication_at"].isoformat(),
        }
    )
    audit = {
        "schema_version": "expected_pe.r8.r7.supplemental_audit.v1",
        "status": "DESIGN_ONLY_AWAITING_INDEPENDENT_AUDIT",
        "verdict": "NO_GO",
        "supplemental_auditor_archive_raw_sha256": archive_hash,
        "supplemental_auditor_source_identity_raw_sha256": sha256_bytes(identity_raw),
        "supplemental_auditor_source_records_semantic_sha256": source_semantic,
        "supplemental_auditor_command_lock_raw_sha256": sha256_bytes(command_raw),
        "supplemental_auditor_source_freeze_checksums_raw_sha256": sha256_bytes(ledger_raw),
        "signer_binding_raw_sha256": sha256_bytes(binding_raw),
        "process_evidence_raw_sha256": sha256_bytes(process_raw),
        "telemetry_window_raw_sha256": sha256_bytes(telemetry_raw),
        "exact_job_witness_raw_sha256": sha256_bytes(job_raw),
        "request_count": 0,
        "signature_count": 0,
        "evidence_window_status": "PASS_EXACT_HELD_HANDLE_DOUBLE_SNAPSHOT_CLOSURE",
        "production_authority_enabled": False,
    }
    audit_raw = canonical_json_bytes(audit)
    seal = {
        "schema_version": "expected_pe.r8.r7.supplemental_seal.v1",
        "status": "SEALED_DESIGN_ONLY_NO_GO",
        "verdict": "NO_GO",
        "supplemental_audit_json_raw_sha256": sha256_bytes(audit_raw),
        **{
            key: audit[key]
            for key in (
                "supplemental_auditor_archive_raw_sha256",
                "supplemental_auditor_source_identity_raw_sha256",
                "supplemental_auditor_source_records_semantic_sha256",
                "supplemental_auditor_command_lock_raw_sha256",
                "supplemental_auditor_source_freeze_checksums_raw_sha256",
                "signer_binding_raw_sha256",
                "process_evidence_raw_sha256",
                "telemetry_window_raw_sha256",
                "exact_job_witness_raw_sha256",
            )
        },
        "production_authority_enabled": False,
    }
    reopened = {
        "AUDITOR_ARCHIVE": archive_raw,
        "AUDITOR_SOURCE_IDENTITY": identity_raw,
        "AUDITOR_COMMAND_LOCK": command_raw,
        "AUDITOR_SOURCE_FREEZE_CHECKSUMS": ledger_raw,
        "SIGNER_BINDING": binding_raw,
        "SUPPLEMENTAL_AUDIT": audit_raw,
        "SUPPLEMENTAL_SEAL": canonical_json_bytes(seal),
        "PROCESS_EVIDENCE": process_raw,
        "TELEMETRY_WINDOW": telemetry_raw,
        "EXACT_JOB_WITNESS": job_raw,
    }
    binding = window["binding"]
    fields: dict[str, Any] = {
        "schema_version": "expected_pe.r8.r7.identity_closure.v1",
        "status": "DESIGN_ONLY_AWAITING_INDEPENDENT_AUDIT",
        "supplemental_auditor_archive_relative": command[
            "frozen_archive_relative"
        ],
        "supplemental_auditor_source_records_semantic_sha256": source_semantic,
        "signer_command_line_sha256": binding["signer_command_line_sha256"],
        "signer_source_identity_sha256": binding["signer_source_identity_sha256"],
        "signer_archive_raw_sha256": binding["signer_archive_raw_sha256"],
        "supervisor_command_line_sha256": binding["supervisor_command_line_sha256"],
        "supervisor_source_identity_sha256": binding["supervisor_source_identity_sha256"],
        "supervisor_archive_raw_sha256": binding["supervisor_archive_raw_sha256"],
        "auditor_command_line_sha256": binding["auditor_command_line_sha256"],
        "auditor_source_identity_sha256": binding["auditor_source_identity_sha256"],
        "job_identity_sha256": binding["job_identity_sha256"],
        "python_image_raw_sha256": _image().raw_sha256,
        "python_image_path": _image().path,
        "python_image_volume_serial_number": _image().volume_serial_number,
        "python_image_file_id_128": _image().file_id_128,
        "python_image_size_bytes": _image().size_bytes,
        "signer_pid": binding["signer_pid"],
        "signer_creation_time_100ns": binding["signer_creation_time_100ns"],
        "supervisor_pid": binding["supervisor_pid"],
        "supervisor_creation_time_100ns": binding["supervisor_creation_time_100ns"],
        "auditor_pid": binding["auditor_pid"],
        "auditor_creation_time_100ns": binding["auditor_creation_time_100ns"],
        "job_limit_flags": binding["job_limit_flags"],
        "job_active_process_count": binding["job_active_process_count"],
        "job_active_process_ids": binding["job_active_process_ids"],
        "expires_at_utc": binding["expires_at_utc"],
        "publication_at_utc": window["publication_at"].isoformat(),
        "request_count": 0,
        "signature_count": 0,
        "exact_job_query_handle_witness": True,
        "exact_job_query_handle_closed_before_publication": True,
        "all_paths_reparse_free": True,
        "all_file_ids_stable": True,
        "strict_heartbeat_progress": True,
        "snapshot_to_publication_max_seconds": 1,
        "heartbeat_age_at_publication_max_seconds": 5,
        "minimum_expiry_margin_seconds": 30,
        "independent_audit_complete": False,
        "production_authority_enabled": False,
    }
    for artifact, field in REOPENED_HASH_FIELDS.items():
        fields[field] = sha256_bytes(reopened[artifact])
    return dict(build_closure(fields)), reopened


def _zero_counts(value: int = 0) -> dict[str, int]:
    return {key: value for key in ZERO_STATE_COUNT_KEYS}


def _publication_plan() -> Any:
    return publication._bound_plan(PERMITTED_STATIC_DESIGN_CHILD_NAME)


def _publish_private(
    *,
    trusted_root: Path,
    evidence: dict[str, Any],
    counts: dict[str, int],
    clock: Any = None,
) -> dict[str, Any]:
    with SupervisorDirectoryCustody(
        path=trusted_root,
        ancestry_root=trusted_root,
    ) as custody:
        return dict(
            publication._publish_bound_no_go(
                root_custody=custody,
                plan=_publication_plan(),
                evidence_without_publication_time=evidence,
                zero_state_counts=counts,
                clock=clock,
            )
        )


def _trace_quality_receipt(
    *, test_source_raw: bytes, excluded: frozenset[str] = frozenset()
) -> dict[str, Any]:
    names = (
        ("test_r8r7_001_immediate_issuance_rejects_missing_source_command_pin", 1),
        ("test_r8r7_002_signer_rejects_substituted_auditor_archive", 1),
        ("test_r8r7_003_rejects_pid_reuse_creation_time_change", 1),
        ("test_r8r7_004_rejects_any_job_or_non_query_handle_witness", 5),
        ("test_r8r7_005_rejects_command_source_or_file_id_substitution", 3),
        ("test_r8r7_006_authority_rejects_missing_process_job_closure", 1),
    )
    nodeids = []
    for name, count in names:
        if name in excluded:
            continue
        exact = f"{TEST_RELATIVE}::{name}"
        nodeids.extend(
            [exact] if count == 1 else [f"{exact}[case{index}]" for index in range(count)]
        )
    collection_site = {
        "autoloaded_plugin_distribution_count": 0,
        "collected_nodeids": nodeids,
        "conftest_plugin_count": 0,
        "deselected_nodeids": [],
        "pytest_exit_status": 0,
    }
    execution_site = dict(collection_site)
    return {
        "test_source_raw_sha256": sha256_bytes(test_source_raw),
        "pytest_collection": {"returncode": 0},
        "pytest": {"returncode": 0},
        "collected_nodeids": nodeids,
        "executed_nodeids": nodeids,
        "pytest_collection_on_site_evidence": collection_site,
        "pytest_execution_on_site_evidence": execution_site,
        "collected_nodeids_semantic_sha256": sha256_bytes(
            canonical_json_bytes(nodeids)
        ),
        "selected_test_case_count": len(nodeids),
        "executed_test_case_count": len(nodeids),
    }


def test_win32_blueprint_has_exact_startupinfoex_handle_mechanics_no_launch() -> None:
    import ctypes

    blueprint = build_win32_supervision_blueprint()
    validate_win32_supervision_blueprint(blueprint)
    launches = {item["role"]: item for item in blueprint["launches"]}
    assert launches["AUDITOR"]["startup_info_cb"] == ctypes.sizeof(STARTUPINFOEXW)
    assert launches["AUDITOR"]["attribute_count"] == 2
    assert launches["AUDITOR"]["inherit_handles"] is True
    assert launches["SIGNER"]["inherit_handles"] is False
    assert set(launches["AUDITOR"]["attribute_ids"]) == {
        PROC_THREAD_ATTRIBUTE_JOB_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    }
    assert all(blueprint["failure_unwind"].values())
    assert blueprint["actual_createprocess_call_count"] == 0


def test_win32_blueprint_rejects_hostile_recursive_primitives_without_hooks() -> None:
    calls = {
        "eq": 0,
        "ne": 0,
        "iter": 0,
        "items": 0,
        "len": 0,
        "getitem": 0,
    }

    class HostileInt(int):
        def __eq__(self, _other: object) -> bool:
            calls["eq"] += 1
            return True

        def __ne__(self, _other: object) -> bool:
            calls["ne"] += 1
            return False

    class HostileStr(str):
        def __eq__(self, _other: object) -> bool:
            calls["eq"] += 1
            return True

        def __ne__(self, _other: object) -> bool:
            calls["ne"] += 1
            return False

    class HostileList(list[object]):
        def __iter__(self) -> Any:
            calls["iter"] += 1
            raise AssertionError("hostile list iteration is forbidden")

        def __len__(self) -> int:
            calls["len"] += 1
            raise AssertionError("hostile list length is forbidden")

        def __getitem__(self, key: object) -> Any:
            calls["getitem"] += 1
            raise AssertionError("hostile list indexing is forbidden")

    class HostileDict(dict[str, object]):
        def __iter__(self) -> Any:
            calls["iter"] += 1
            raise AssertionError("hostile dict iteration is forbidden")

        def items(self) -> Any:
            calls["items"] += 1
            raise AssertionError("hostile dict items are forbidden")

        def __len__(self) -> int:
            calls["len"] += 1
            raise AssertionError("hostile dict length is forbidden")

        def __getitem__(self, key: object) -> Any:
            calls["getitem"] += 1
            raise AssertionError("hostile dict indexing is forbidden")

    scalar = build_win32_supervision_blueprint()
    scalar["job"]["limit_flags"] = HostileInt(0)
    scalar["blueprint_semantic_sha256"] = HostileStr("0" * 64)
    hostile_list = build_win32_supervision_blueprint()
    hostile_list["required_api_sequence"] = HostileList()
    hostile_dict = HostileDict(build_win32_supervision_blueprint())
    for candidate in (scalar, hostile_list, hostile_dict):
        with pytest.raises(R8R7DesignError, match="exact dict/list/str/int/bool/null"):
            validate_win32_supervision_blueprint(candidate)
    assert calls == {
        "eq": 0,
        "ne": 0,
        "iter": 0,
        "items": 0,
        "len": 0,
        "getitem": 0,
    }


def test_win32_blueprint_recursive_snapshot_rejects_cycle_and_excess_depth() -> None:
    cyclic = build_win32_supervision_blueprint()
    cycle: list[Any] = []
    cycle.append(cycle)
    cyclic["required_api_sequence"] = cycle
    with pytest.raises(R8R7DesignError, match="container cycle"):
        validate_win32_supervision_blueprint(cyclic)

    too_deep = build_win32_supervision_blueprint()
    root: list[Any] = []
    cursor = root
    for _ in range(40):
        child: list[Any] = []
        cursor.append(child)
        cursor = child
    too_deep["required_api_sequence"] = root
    with pytest.raises(R8R7DesignError, match="snapshot depth"):
        validate_win32_supervision_blueprint(too_deep)


def test_disabled_archive_receipt_is_verify_only_exit_78_with_exact_blockers() -> None:
    receipt = {
        "archive_raw_sha256": H["a"],
        "source_identity_raw_sha256": H["b"],
        "source_records_semantic_sha256": H["c"],
        "source_record_count": 17,
    }
    result = build_disabled_verification_result(receipt)
    validate_disabled_verification_result(result)
    assert result["intentional_exit_code"] == DISABLED_EXIT_CODE == 78
    assert result["verdict"] == "NO_GO"
    assert result["archive_role"] == (
        "DISABLED_STATIC_DESIGN_SOURCE_VERIFIER_NOT_LIVE_AUDITOR"
    )
    assert result["live_inputs_allowed"] is False
    assert result["live_audit_allowed"] is False
    assert result["execution_package_required"] is True
    assert result["execution_package_present_in_archive"] is False
    assert result["execution_package_blockers"] == list(EXECUTION_PACKAGE_BLOCKERS)
    assert result["required_external_gates"] == list(REQUIRED_EXTERNAL_GATES)
    assert result["actual_createprocess_call_count"] == 0
    assert result["signer_launch_authorized"] is False
    assert result["authority_issuance_authorized"] is False
    assert result["generation_authorized"] is False
    assert result["fresh_truth_heldout_access_count"] == 0


def test_disabled_archive_validator_rejects_recursive_hostile_cycle_and_depth() -> None:
    receipt = {
        "archive_raw_sha256": H["a"],
        "source_identity_raw_sha256": H["b"],
        "source_records_semantic_sha256": H["c"],
        "source_record_count": 17,
    }
    calls = {"eq": 0, "iter": 0, "items": 0}

    class HostileInt(int):
        def __eq__(self, _other: object) -> bool:
            calls["eq"] += 1
            return True

        def __ne__(self, _other: object) -> bool:
            calls["eq"] += 1
            return False

    class HostileList(list[object]):
        def __iter__(self) -> Any:
            calls["iter"] += 1
            raise AssertionError("hostile list iteration is forbidden")

    class HostileDict(dict[str, object]):
        def items(self) -> Any:
            calls["items"] += 1
            raise AssertionError("hostile dict items are forbidden")

    hostile_scalar = build_disabled_verification_result(receipt)
    hostile_scalar["actual_createprocess_call_count"] = HostileInt(99)
    hostile_list = build_disabled_verification_result(receipt)
    hostile_list["execution_package_blockers"] = HostileList()
    hostile_dict = HostileDict(build_disabled_verification_result(receipt))
    for candidate in (hostile_scalar, hostile_list, hostile_dict):
        with pytest.raises(R8R7DesignError, match="exact dict/list/str/int/bool/null"):
            validate_disabled_verification_result(candidate)
    assert calls == {"eq": 0, "iter": 0, "items": 0}

    cyclic = build_disabled_verification_result(receipt)
    cycle: list[Any] = []
    cycle.append(cycle)
    cyclic["execution_package_blockers"] = cycle
    with pytest.raises(R8R7DesignError, match="container cycle"):
        validate_disabled_verification_result(cyclic)

    too_deep = build_disabled_verification_result(receipt)
    root: list[Any] = []
    cursor = root
    for _ in range(40):
        child: list[Any] = []
        cursor.append(child)
        cursor = child
    too_deep["execution_package_blockers"] = root
    with pytest.raises(R8R7DesignError, match="snapshot depth"):
        validate_disabled_verification_result(too_deep)


def test_quality_subprocesses_are_not_mislabeled_as_production_processes() -> None:
    assert QUALITY_SUBPROCESS_COUNT == 5
    assert SCOPED_TEST_CASE_COUNT == 85


def test_builder_outputs_custody_matches_exact_fixed_parent() -> None:
    assert OUTPUT_ROOT.parent == OUTPUTS_ROOT
    with SupervisorDirectoryCustody(
        path=OUTPUTS_ROOT,
        ancestry_root=OUTPUTS_ROOT,
    ) as custody:
        assert custody.path == OUTPUTS_ROOT
        assert custody.receipt()["rename_capable"] is False


def test_public_and_builder_boundaries_run_held_preflight_before_candidate_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public_source = inspect.getsource(publish_validated_design_no_go)
    assert public_source.index("_require_trusted_outputs_identity") < (
        public_source.index("require_clean_r8_r7_preflight")
    ) < public_source.index("_publish_bound_no_go")
    builder_source = inspect.getsource(_freeze_with_outputs_custody)
    assert builder_source.index("_require_trusted_outputs_identity") < (
        builder_source.index("require_clean_r8_r7_preflight")
    ) < builder_source.index("_predecessor_chain")
    trusted_root_source = inspect.getsource(publication._trusted_outputs_root)
    assert ".resolve(" not in trusted_root_source
    resolve_calls = 0

    def forbidden_pre_custody_resolve(
        _self: Path, *_args: object, **_kwargs: object
    ) -> Path:
        nonlocal resolve_calls
        resolve_calls += 1
        raise AssertionError("trusted outputs was pre-resolved before custody")

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "resolve", forbidden_pre_custody_resolve)
        assert publication._trusted_outputs_root() == OUTPUTS_ROOT
    assert resolve_calls == 0

    public_outputs = tmp_path / "public_outputs"
    public_outputs.mkdir()
    with SupervisorDirectoryCustody(
        path=public_outputs,
        ancestry_root=public_outputs,
    ) as identity_custody:
        trusted_identity = identity_custody.receipt()
    public_calls = {"preflight": 0, "candidate": 0}

    def stop_public_preflight(_custody: SupervisorDirectoryCustody) -> None:
        public_calls["preflight"] += 1
        raise R8R7DesignError("synthetic held public preflight stop")

    def forbidden_public_candidate(**_kwargs: object) -> dict[str, Any]:
        public_calls["candidate"] += 1
        raise AssertionError("candidate publication ran before held preflight")

    window = _window()
    del window["publication_at"]
    with monkeypatch.context() as scoped:
        scoped.setattr(publication, "_trusted_outputs_root", lambda: public_outputs)
        scoped.setattr(
            publication,
            "_TRUSTED_OUTPUTS_VOLUME_SERIAL_NUMBER",
            trusted_identity["volume_serial_number"],
        )
        scoped.setattr(
            publication,
            "_TRUSTED_OUTPUTS_FILE_ID_128",
            trusted_identity["file_id_128"],
        )
        scoped.setattr(
            publication, "require_clean_r8_r7_preflight", stop_public_preflight
        )
        scoped.setattr(
            publication, "_publish_bound_no_go", forbidden_public_candidate
        )
        public_result = publish_validated_design_no_go(
            policy=R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
            requested_child_name=PERMITTED_STATIC_DESIGN_CHILD_NAME,
            evidence_without_publication_time=window,
            zero_state_counts=_zero_counts(),
        )
    assert public_calls == {"preflight": 1, "candidate": 0}
    assert public_result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert public_result["receipt_root"] is None
    assert public_result["production_authority_granted"] is False
    assert list(public_outputs.iterdir()) == []

    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    builder_outputs = tmp_path / "builder_outputs"
    builder_outputs.mkdir()
    builder_calls = {
        "preflight": 0,
        "predecessor": 0,
        "quality": 0,
        "candidate": 0,
    }

    def stop_builder_preflight(_custody: SupervisorDirectoryCustody) -> None:
        builder_calls["preflight"] += 1
        raise R8R7DesignError("synthetic held builder preflight stop")

    def forbidden_builder_step(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("builder crossed the held preflight boundary")

    def forbidden_predecessor() -> None:
        builder_calls["predecessor"] += 1
        forbidden_builder_step()

    def forbidden_quality(*_args: object, **_kwargs: object) -> None:
        builder_calls["quality"] += 1
        forbidden_builder_step()

    def forbidden_builder_candidate(*_args: object, **_kwargs: object) -> None:
        builder_calls["candidate"] += 1
        forbidden_builder_step()

    builder_final = builder_outputs / PERMITTED_STATIC_DESIGN_CHILD_NAME
    with SupervisorDirectoryCustody(
        path=builder_outputs,
        ancestry_root=builder_outputs,
    ) as builder_custody, monkeypatch.context() as scoped:
        scoped.setattr(builder, "OUTPUTS_ROOT", builder_outputs)
        scoped.setattr(builder, "OUTPUT_ROOT", builder_final)
        scoped.setattr(
            builder,
            "STAGING",
            builder_outputs / f".{PERMITTED_STATIC_DESIGN_CHILD_NAME}.stg",
        )
        scoped.setattr(
            builder,
            "_require_trusted_outputs_identity",
            lambda custody: custody.receipt(),
        )
        scoped.setattr(
            builder, "require_clean_r8_r7_preflight", stop_builder_preflight
        )
        scoped.setattr(builder, "_predecessor_chain", forbidden_predecessor)
        scoped.setattr(builder, "_quality", forbidden_quality)
        scoped.setattr(
            builder, "_publish_bound_artifacts_no_go", forbidden_builder_candidate
        )
        with pytest.raises(R8R7DesignError, match="builder preflight stop"):
            _freeze_with_outputs_custody(
                outputs_custody=builder_custody,
                launcher_isolation_before={},
                adjacent_bytecode_preflight={},
            )
    assert builder_calls == {
        "preflight": 1,
        "predecessor": 0,
        "quality": 0,
        "candidate": 0,
    }
    assert list(builder_outputs.iterdir()) == []


def test_builder_main_and_publication_fallbacks_are_deterministic_terminal_no_go(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    terminal_first = dict(builder._builder_terminal_in_memory_no_go())
    terminal_second = dict(builder._builder_terminal_in_memory_no_go())
    assert terminal_first == terminal_second
    assert terminal_first["status"] == "SEALED_IN_MEMORY_BUILDER_NO_GO"
    assert terminal_first["generated_at_utc"] == "1970-01-01T00:00:00+00:00"
    terminal_payload = dict(terminal_first)
    terminal_hash = terminal_payload.pop("receipt_bundle_raw_sha256")
    assert terminal_hash == sha256_bytes(canonical_json_bytes(terminal_payload))

    monkeypatch.setattr(publication, "_system_utc_now", lambda: NOW)
    failure_first, counts_first = publication._failure_artifacts(
        exception=OSError("controlled persistence failure"),
        zero_state_counts=_zero_counts(),
    )
    monkeypatch.setattr(
        publication,
        "_system_utc_now",
        lambda: NOW + timedelta(days=1),
    )
    failure_second, counts_second = publication._failure_artifacts(
        exception=OSError("controlled persistence failure"),
        zero_state_counts=_zero_counts(),
    )
    assert failure_first == failure_second
    fallback_first = publication._in_memory_fallback(
        bound_receipt_child_name=_publication_plan().failure_name,
        artifacts=failure_first,
        zero_state_counts=counts_first,
        persistence_exception=OSError("controlled persistence failure"),
    )
    fallback_second = publication._in_memory_fallback(
        bound_receipt_child_name=_publication_plan().failure_name,
        artifacts=failure_second,
        zero_state_counts=counts_second,
        persistence_exception=OSError("controlled persistence failure"),
    )
    assert fallback_first == fallback_second
    assert fallback_first["production_authority_granted"] is False

    def failed_freeze() -> None:
        raise KeyboardInterrupt("synthetic builder failure")

    stdout_buffer = io.BytesIO()
    with monkeypatch.context() as scoped:
        scoped.setattr(builder, "freeze", failed_freeze)
        scoped.setattr(
            sys,
            "argv",
            [
                "freeze_static_design.py",
                "--freeze-r8-r7-static-design-source-no-signer-no-phase2-no-fresh",
            ],
        )
        scoped.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))
        exit_code = builder.main()
    assert exit_code == 78
    assert stdout_buffer.getvalue() == canonical_json_bytes(terminal_first) + b"\n"


def test_quality_gate_holds_exact_source_handles_until_archive_bytes_are_built() -> None:
    source = inspect.getsource(_freeze_with_outputs_custody)
    custody = source.index("with ExitStack() as source_window")
    quality = source.index("_quality(")
    archive = source.index("_build_archive(")
    after_gate = source.index("source_lock_after_quality")
    assert custody < quality < after_gate < archive
    assert "all_source_handles_held_no_share_write_delete_during_gate" in source


def test_quality_gate_uses_fresh_cache_no_plugins_no_conftest_and_isolated_ruff() -> None:
    source = inspect.getsource(_quality)
    builder_module = sys.modules[_quality.__module__]
    assert "probe_pycache_empty" in source
    assert "collection_pycache_empty" in source
    assert "execution_pycache_empty" in source
    assert "--noconftest" in inspect.getsource(
        builder_module._pytest_command_prefix
    )
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in inspect.getsource(
        builder_module._run
    )
    assert '"--isolated"' in source


def test_quality_uses_five_custodied_tool_launches_on_one_held_source_mirror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = sys.modules[_quality.__module__]
    held_source_bytes = {
        relative: (builder.PROJECT_ROOT / relative).read_bytes()
        for relative in builder._source_relatives()
    }
    synthetic_names = [
        f"test_quality_synthetic_{index:03d}"
        for index in range(builder.SCOPED_TEST_CASE_COUNT)
    ]
    synthetic_nodeids = [
        f"{builder.TEST_RELATIVE}::{name}" for name in synthetic_names
    ]
    calls: list[dict[str, Any]] = []

    with SupervisorArchiveCustody(
        path=builder.GENERATION_PYTHON,
        root=Path(builder.GENERATION_PYTHON.anchor),
    ) as python_custody, SupervisorArchiveCustody(
        path=builder.RUFF_EXECUTABLE,
        root=Path(builder.RUFF_EXECUTABLE.anchor),
    ) as ruff_custody:
        python_receipt = python_custody.receipt()
        ruff_receipt = ruff_custody.receipt()
        python_dos_path = os.path.normpath(
            filesystem_identity._raw_resolved_path(python_custody.handle)
        )
        ruff_dos_path = os.path.normpath(
            filesystem_identity._raw_resolved_path(ruff_custody.handle)
        )
        python_guid_path = filesystem_identity._raw_resolved_guid_path(
            python_custody.handle
        )
        ruff_guid_path = filesystem_identity._raw_resolved_guid_path(
            ruff_custody.handle
        )

        def fake_run(
            command: list[str],
            *,
            python_pycache_prefix: Path | None = None,
            cwd: Path = builder.PROJECT_ROOT,
        ) -> tuple[dict[str, Any], bytes, bytes]:
            call_index = len(calls)
            assert python_custody.receipt() == python_receipt
            assert ruff_custody.receipt() == ruff_receipt
            assert command[0] == (
                python_dos_path if call_index < 3 else ruff_dos_path
            )
            calls.append(
                {
                    "command": list(command),
                    "cwd": Path(cwd),
                    "python_pycache_prefix": python_pycache_prefix,
                }
            )
            stdout = b""
            if call_index == 0:
                stdout = json.dumps(
                    {
                        "dont_write_bytecode": True,
                        "isolated": 1,
                        "plugin_autoload": "1",
                        "pycache_prefix": str(python_pycache_prefix.resolve()),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            elif call_index in {1, 2}:
                site = {
                    "autoloaded_plugin_distribution_count": 0,
                    "call_outcomes": {
                        "failed": 0,
                        "passed": 0 if call_index == 1 else len(synthetic_nodeids),
                        "skipped": 0,
                    },
                    "collected_nodeids": synthetic_nodeids,
                    "conftest_plugin_count": 0,
                    "deselected_nodeids": [],
                    "dont_write_bytecode": True,
                    "isolated": 1,
                    "plugin_autoload": "1",
                    "pycache_prefix": str(python_pycache_prefix.resolve()),
                    "pytest_exit_status": 0,
                }
                stdout = (
                    builder.PYTEST_RECORDER_PREFIX
                    + json.dumps(site, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("ascii")
                if call_index == 2:
                    junit_argument = next(
                        item for item in command if item.startswith("--junitxml=")
                    )
                    junit_path = Path(junit_argument.split("=", 1)[1])
                    junit_path.write_bytes(
                        (
                            "<testsuite>"
                            + "".join(
                                f'<testcase name="{name}" />'
                                for name in synthetic_names
                            )
                            + "</testsuite>"
                        ).encode("ascii")
                    )
            elif call_index == 4:
                stdout = (builder.RUFF_EXPECTED_VERSION + "\n").encode("ascii")
            receipt = {
                "command": list(command),
                "returncode": 0,
                "stdout_raw_sha256": sha256_bytes(stdout),
                "stderr_raw_sha256": sha256_bytes(b""),
                "stdout_tail": stdout.decode("ascii").strip(),
                "stderr_tail": "",
                "environment_contract": {
                    "pycache_empty_before_and_after": True,
                },
            }
            return receipt, stdout, b""

        monkeypatch.setattr(builder, "_run", fake_run)
        result = _quality(
            python_custody=python_custody,
            ruff_custody=ruff_custody,
            python_receipt=python_receipt,
            ruff_receipt=ruff_receipt,
            full_repository_status={"full_repository_suite_passed": False},
            test_source_raw_sha256=sha256_bytes(
                held_source_bytes[builder.TEST_RELATIVE]
            ),
            held_source_bytes=held_source_bytes,
        )

    assert len(calls) == QUALITY_SUBPROCESS_COUNT == 5
    assert len({str(call["cwd"]) for call in calls}) == 1
    assert all(call["cwd"].name == "held_source_mirror" for call in calls)
    assert [call["command"][0] for call in calls[:3]] == [python_dos_path] * 3
    assert [call["command"][0] for call in calls[3:]] == [ruff_dos_path] * 2
    assert calls[3]["command"][1:] == [
        "check",
        "--isolated",
        "--no-cache",
        builder.PACKAGE_RELATIVE,
        builder.SCRIPT_RELATIVE,
        builder.TEST_RELATIVE,
    ]
    assert result["ruff_operated_only_on_held_source_mirror"] is True
    assert result["ruff_cache_reads_and_writes_disabled"] is True
    assert result["ruff_completed_while_all_mirror_handles_were_held"] is True
    assert result["tool_image_handles_held_across_all_five_subprocesses"] is True
    assert result["tool_image_custody_rechecked_after_all_five_subprocesses"] is True
    assert result["held_source_mirror_exact_custody_stable"] is True
    assert result["python_executable_dos_final_launch_path"] == python_dos_path
    assert result["ruff_executable_dos_final_launch_path"] == ruff_dos_path
    assert result["python_executable_volume_guid_identity_path"] == python_guid_path
    assert result["ruff_executable_volume_guid_identity_path"] == ruff_guid_path
    assert result["all_five_subprocesses_used_held_dos_final_launch_paths"] is True
    assert result["volume_guid_executable_launch_count"] == 0
    assert result["volume_guid_paths_used_for_identity_evidence_only"] is True


def test_quality_custody_rejects_stable_mirror_or_config_substitution(
    tmp_path: Path,
) -> None:
    for name in ("mirror.py", "pytest.ini"):
        path = tmp_path / name
        path.write_bytes(b"substituted-stable-bytes")
        with SupervisorArchiveCustody(path=path, root=tmp_path) as custody:
            with pytest.raises(RuntimeError, match="differ from expected"):
                _require_exact_custody_bytes(
                    custody=custody,
                    expected=b"intended-held-bytes",
                    label=name,
                )


def test_freeze_launcher_requires_fresh_empty_matching_pycache_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "launcher_pycache"
    prefix.mkdir()
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", str(prefix))
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.setattr(sys, "pycache_prefix", str(prefix))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    builder = sys.modules[_require_freeze_launcher_isolation.__module__]
    monkeypatch.setattr(builder, "ONE_SHOT_LAUNCHER_PREFIX", prefix)
    receipt = _require_freeze_launcher_isolation()
    assert receipt["status"] == "PASS_FRESH_EMPTY_FREEZE_LAUNCHER_PYCACHE"
    (prefix / "stale.pyc").write_bytes(b"stale")
    with pytest.raises(RuntimeError, match="isolation"):
        _require_freeze_launcher_isolation()


def test_a3_one_shot_launcher_is_held_archived_and_statically_exact() -> None:
    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    launcher_path = builder.PROJECT_ROOT / builder.LAUNCHER_RELATIVE
    launcher_raw = launcher_path.read_bytes()
    launcher_source = launcher_raw.decode("utf-8")
    source_relatives = builder._source_relatives()
    assert source_relatives.count(builder.LAUNCHER_RELATIVE) == 1

    raw_by_relative = {
        relative: (builder.PROJECT_ROOT / relative).read_bytes()
        for relative in source_relatives
    }
    records, members = builder._runtime_sources_from_bytes(raw_by_relative)
    launcher_records = [
        record
        for record in records
        if record.source_relative == builder.LAUNCHER_RELATIVE
    ]
    assert len(launcher_records) == 1
    assert launcher_records[0].archive_member == "ONE_SHOT_LAUNCHER.ps1"
    assert launcher_records[0].raw_sha256 == sha256_bytes(launcher_raw)
    assert members["ONE_SHOT_LAUNCHER.ps1"] == launcher_raw
    source_identity = build_source_identity(records)
    launcher_contract = builder._one_shot_launcher_contract(source_identity)
    assert launcher_contract["source_raw_sha256"] == sha256_bytes(launcher_raw)
    assert launcher_contract["python_argv"] == [
        str(builder.GENERATION_PYTHON),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={builder.ONE_SHOT_LAUNCHER_PREFIX}",
        "-c",
        builder.LAUNCHER_QUOTE_FREE_BOOTSTRAP,
        builder.LAUNCHER_INVOCATION_SOURCE_BASE64,
    ]
    assert not ({"'", '"'} & set(builder.LAUNCHER_QUOTE_FREE_BOOTSTRAP))

    source_lock = builder._source_lock_from_bytes(
        runtime_records=records,
        raw_by_relative=raw_by_relative,
        custody_by_relative={
            relative: {"synthetic_stable_custody": True}
            for relative in source_relatives
        },
    )
    launcher_lock = next(
        row
        for row in source_lock["records"]
        if row["relative_path"] == builder.LAUNCHER_RELATIVE
    )
    assert launcher_lock["runtime_archive_member"] == "ONE_SHOT_LAUNCHER.ps1"
    assert launcher_lock["raw_sha256"] == sha256_bytes(launcher_raw)

    builder_hash = sha256_bytes(Path(builder.__file__).read_bytes())
    assert f"$BuilderHash = '{builder_hash}'" in launcher_source
    first_output_check = launcher_source.index(
        "\nAssert-A3OutputIdentitiesAbsent\n"
    )
    prefix_guard = launcher_source.index("(Test-Path -LiteralPath $OneShotPrefix)")
    atomic_create = launcher_source.index(
        "New-Item -ItemType Directory -Path $OneShotPrefix -ErrorAction Stop"
    )
    dispatch_output_check = launcher_source.rindex(
        "\nAssert-A3OutputIdentitiesAbsent\n"
    )
    dispatch = launcher_source.index("& $PinnedPython @childArgs")
    assert first_output_check < prefix_guard < atomic_create < dispatch_output_check
    assert dispatch_output_check < dispatch
    assert launcher_source.count("& $PinnedPython @childArgs") == 1
    assert launcher_source.count("$BuilderSourceLaunchCount += 1") == 1
    assert "New-Item -ItemType Directory -Path $OneShotPrefix -Force" not in (
        launcher_source
    )
    assert "Remove-Item" not in launcher_source
    assert "while (" not in launcher_source.casefold()
    assert "Start-Process" not in launcher_source
    for name in (
        "$FinalName",
        "$StagingName",
        "$FailureName",
        "$FailureStagingName",
    ):
        assert (
            f"[StringComparer]::OrdinalIgnoreCase.Equals($_.Name, {name})"
            in launcher_source
        )


def test_a3_one_shot_launcher_synthetic_launch_zero_one_matrix(
    tmp_path: Path,
) -> None:
    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    launcher_source = (
        builder.PROJECT_ROOT / builder.LAUNCHER_RELATIVE
    ).read_text(encoding="utf-8")

    def fixed_launcher_literal(variable: str) -> str:
        prefix = f"${variable} = '"
        rows = [
            line
            for line in launcher_source.splitlines()
            if line.startswith(prefix) and line.endswith("'")
        ]
        assert len(rows) == 1
        return rows[0][len(prefix) : -1]

    fixed_outputs_root = fixed_launcher_literal("OutputsRoot")
    fixed_builder = fixed_launcher_literal("Builder")
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    prefix = tmp_path / "one_shot_prefix"
    launch_record = tmp_path / "synthetic_launch.json"
    synthetic_builder = tmp_path / "synthetic_builder.py"
    synthetic_builder_raw = (
        "import json,os,sys\n"
        "from pathlib import Path\n"
        f"prefix=Path({str(prefix)!r})\n"
        f"record=Path({str(launch_record)!r})\n"
        "payload={\n"
        " 'argv':sys.argv,\n"
        " 'orig_argv':sys.orig_argv,\n"
        " 'isolated':sys.flags.isolated,\n"
        " 'dont_write_bytecode':sys.dont_write_bytecode,\n"
        " 'pycache_prefix':sys.pycache_prefix,\n"
        " 'environment_prefix':os.environ.get('PYTHONPYCACHEPREFIX'),\n"
        " 'plugin_autoload':os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD'),\n"
        " 'prefix_entries':sorted(item.name for item in prefix.iterdir()),\n"
        "}\n"
        "record.write_text(json.dumps(payload,sort_keys=True),encoding='utf-8')\n"
    ).encode("utf-8")
    synthetic_builder.write_bytes(synthetic_builder_raw)
    synthetic_invocation_source = (
        "import runpy,sys\n"
        f"project=r'{tmp_path}'\n"
        f"script=r'{synthetic_builder}'\n"
        "sys.path.insert(0,project)\n"
        "sys.argv=[script,'--freeze-r8-r7-static-design-source-no-signer-no-phase2-"
        "no-fresh']\n"
        "runpy.run_path(script,run_name='__main__')\n"
    )
    synthetic_invocation_base64 = base64.b64encode(
        synthetic_invocation_source.encode("utf-8")
    ).decode("ascii")

    replacements = (
        (str(builder.ONE_SHOT_LAUNCHER_PREFIX), str(prefix)),
        (fixed_outputs_root, str(outputs)),
        (fixed_builder, str(synthetic_builder)),
        (sha256_bytes(Path(builder.__file__).read_bytes()), sha256_bytes(synthetic_builder_raw)),
        (builder.LAUNCHER_INVOCATION_SOURCE_BASE64, synthetic_invocation_base64),
    )
    transformed = launcher_source
    for old, new in replacements:
        assert transformed.count(old) == 1
        transformed = transformed.replace(old, new)
    assert fixed_builder not in transformed
    synthetic_launcher = tmp_path / "synthetic_launcher.ps1"
    synthetic_launcher.write_text(transformed, encoding="utf-8", newline="")
    powershell = Path(
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(synthetic_launcher),
    ]

    first = subprocess.run(command, check=False, capture_output=True, timeout=30)
    assert first.returncode == 0, (first.stdout, first.stderr)
    assert prefix.is_dir()
    assert list(prefix.iterdir()) == []
    payload = json.loads(launch_record.read_bytes())
    assert payload["argv"] == [
        str(synthetic_builder),
        "--freeze-r8-r7-static-design-source-no-signer-no-phase2-no-fresh",
    ]
    assert payload["orig_argv"][1:] == [
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={prefix}",
        "-c",
        builder.LAUNCHER_QUOTE_FREE_BOOTSTRAP,
        synthetic_invocation_base64,
    ]
    assert payload["isolated"] == 1
    assert payload["dont_write_bytecode"] is True
    assert payload["pycache_prefix"] == str(prefix)
    assert payload["environment_prefix"] == str(prefix)
    assert payload["plugin_autoload"] == "1"
    assert payload["prefix_entries"] == []
    first_record_raw = launch_record.read_bytes()

    second = subprocess.run(command, check=False, capture_output=True, timeout=30)
    assert second.returncode != 0
    assert list(prefix.iterdir()) == []
    assert launch_record.read_bytes() == first_record_raw
    create_new_collision = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$ErrorActionPreference='Stop';"
                "New-Item -ItemType Directory -Path $args[0] "
                "-ErrorAction Stop | Out-Null"
            ),
            str(prefix),
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert create_new_collision.returncode != 0
    assert list(prefix.iterdir()) == []

    collision_prefix = tmp_path / "collision_prefix"
    collision_name = builder.OUTPUT_ROOT.name.upper()
    (outputs / collision_name).mkdir()
    collision_source = transformed.replace(str(prefix), str(collision_prefix))
    collision_launcher = tmp_path / "collision_launcher.ps1"
    collision_launcher.write_text(collision_source, encoding="utf-8", newline="")
    collision_command = [*command[:-1], str(collision_launcher)]
    collision = subprocess.run(
        collision_command, check=False, capture_output=True, timeout=30
    )
    assert collision.returncode != 0
    assert not collision_prefix.exists()
    assert launch_record.read_bytes() == first_record_raw


def test_static_freeze_rejects_adjacent_source_pyc_without_cleaning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = sys.modules[_adjacent_bytecode_preflight.__module__]
    source = tmp_path / "research" / "held_source.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"synthetic source")
    cache = source.parent / "__pycache__"
    cache.mkdir()
    (cache / "held_source.cpython-310.pyc").write_bytes(b"synthetic pyc")
    monkeypatch.setattr(builder, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(
        builder,
        "_source_relatives",
        lambda: (source.relative_to(tmp_path).as_posix(),),
    )
    receipt = _adjacent_bytecode_preflight()
    assert receipt["status"] == "FAIL_ADJACENT_PYC"
    assert receipt["adjacent_pyc_count"] == 1
    assert receipt["cleanup_performed_by_builder"] is False
    with pytest.raises(RuntimeError, match="adjacent source bytecode"):
        _require_no_adjacent_bytecode()


def test_r8r7_trace_resolves_real_fields_and_named_negative_tests() -> None:
    source_raw = Path(__file__).read_bytes()
    quality = _trace_quality_receipt(test_source_raw=source_raw)
    trace = build_blocker_trace(
        test_relative=TEST_RELATIVE,
        test_source_raw=source_raw,
        quality_receipt=quality,
    )
    validate_blocker_trace(
        trace,
        test_relative=TEST_RELATIVE,
        test_source_raw=source_raw,
        quality_receipt=quality,
    )
    assert trace["row_count"] == 6
    assert all(row["exact_collected_nodeids"] for row in trace["rows"])


def test_traceability_rejects_missing_named_test_in_actual_source() -> None:
    source_raw = b"def test_unrelated(): pass"
    with pytest.raises(R8R7DesignError, match="do not exist"):
        quality = _trace_quality_receipt(test_source_raw=source_raw)
        trace = build_blocker_trace(
            test_relative=TEST_RELATIVE,
            test_source_raw=source_raw,
            quality_receipt=quality,
        )
        validate_blocker_trace(
            trace,
            test_relative=TEST_RELATIVE,
            test_source_raw=source_raw,
            quality_receipt=quality,
        )


def test_traceability_rejects_nested_uncollectable_named_tests() -> None:
    quality_source = Path(__file__).read_bytes()
    quality = _trace_quality_receipt(test_source_raw=quality_source)
    names = [
        row["negative_test"]
        for row in build_blocker_trace(
            test_relative=TEST_RELATIVE,
            test_source_raw=quality_source,
            quality_receipt=quality,
        )["rows"]
    ]
    nested = "def helper():\n" + "".join(f"    def {name}(): pass\n" for name in names)
    nested_raw = nested.encode("utf-8")
    nested_quality = _trace_quality_receipt(test_source_raw=nested_raw)
    nested_trace = build_blocker_trace(
        test_relative=TEST_RELATIVE,
        test_source_raw=nested_raw,
        quality_receipt=nested_quality,
    )
    with pytest.raises(R8R7DesignError, match="do not exist"):
        validate_blocker_trace(
            nested_trace,
            test_relative=TEST_RELATIVE,
            test_source_raw=nested_raw,
            quality_receipt=nested_quality,
        )


def test_traceability_rejects_test_hidden_from_actual_collection() -> None:
    source_raw = Path(__file__).read_bytes()
    hidden = frozenset(
        {"test_r8r7_006_authority_rejects_missing_process_job_closure"}
    )
    quality = _trace_quality_receipt(test_source_raw=source_raw, excluded=hidden)
    with pytest.raises(R8R7DesignError, match="case coverage drifted"):
        build_blocker_trace(
            test_relative=TEST_RELATIVE,
            test_source_raw=source_raw,
            quality_receipt=quality,
        )


def test_traceability_rejects_exit_source_hash_or_execution_binding_drift() -> None:
    source_raw = Path(__file__).read_bytes()
    baseline = _trace_quality_receipt(test_source_raw=source_raw)
    mutations: list[dict[str, Any]] = []
    for section in ("pytest", "pytest_collection"):
        changed = json.loads(json.dumps(baseline))
        changed[section]["returncode"] = 1
        mutations.append(changed)
    changed = json.loads(json.dumps(baseline))
    changed["test_source_raw_sha256"] = "f" * 64
    mutations.append(changed)
    changed = json.loads(json.dumps(baseline))
    changed["executed_nodeids"] = changed["executed_nodeids"][:-1]
    mutations.append(changed)
    for quality in mutations:
        with pytest.raises(R8R7DesignError, match="binding"):
            build_blocker_trace(
                test_relative=TEST_RELATIVE,
                test_source_raw=source_raw,
                quality_receipt=quality,
            )


def test_all_three_consumers_semantically_reopen_same_exact_closure_no_authority() -> None:
    claim, reopened = _closure_fixture()
    results = [
        immediate_issuance_reopen(claim=claim, reopened=reopened),
        signer_reopen(claim=claim, reopened=reopened),
        authority_reopen(claim=claim, reopened=reopened),
    ]
    assert len({result["closure_semantic_sha256"] for result in results}) == 1
    assert all(result["authority_issuance_allowed"] is False for result in results)


def test_semantic_closure_rejects_self_consistent_arbitrary_artifact_bytes() -> None:
    claim, reopened = _closure_fixture()
    reopened["PROCESS_EVIDENCE"] = b"arbitrary"
    claim["process_evidence_raw_sha256"] = sha256_bytes(b"arbitrary")
    claim = dict(build_closure(claim))
    with pytest.raises(R8R7DesignError, match="PROCESS_EVIDENCE"):
        signer_reopen(claim=claim, reopened=reopened)


def test_command_lock_rejects_null_or_noncanonical_frozen_archive_path() -> None:
    _claim, reopened = _closure_fixture()
    command = json.loads(reopened["AUDITOR_COMMAND_LOCK"])
    command["frozen_archive_relative"] = None
    with pytest.raises(R8R7DesignError, match="archive path"):
        parse_command_lock(canonical_json_bytes(command))


def test_command_lock_rejects_all_windows_absolute_drive_device_and_trim_aliases() -> None:
    _claim, reopened = _closure_fixture()
    original = json.loads(reopened["AUDITOR_COMMAND_LOCK"])
    unsafe = (
        "/absolute/AUDITOR.pyz",
        "C:/absolute/AUDITOR.pyz",
        "C:relative/AUDITOR.pyz",
        "//server/share/AUDITOR.pyz",
        "\\\\server\\share\\AUDITOR.pyz",
        "//?/C:/extended/AUDITOR.pyz",
        "\\\\?\\C:\\extended\\AUDITOR.pyz",
        "//./C:/device/AUDITOR.pyz",
        "\\\\.\\C:\\device\\AUDITOR.pyz",
        "outputs/CON/AUDITOR.pyz",
        "outputs/nul.txt/AUDITOR.pyz",
        "outputs/AUX .json/AUDITOR.pyz",
        "outputs/prn.../AUDITOR.pyz",
        "outputs/COM1.log/AUDITOR.pyz",
        "outputs/lpt9 /AUDITOR.pyz",
    )
    for relative in unsafe:
        command = dict(original)
        command["frozen_archive_relative"] = relative
        with pytest.raises(R8R7DesignError, match="archive path"):
            parse_command_lock(canonical_json_bytes(command))


def test_command_lock_cross_binds_exact_archived_a3_one_shot_launcher() -> None:
    _claim, reopened = _closure_fixture()
    command = json.loads(reopened["AUDITOR_COMMAND_LOCK"])
    parsed = parse_command_lock(reopened["AUDITOR_COMMAND_LOCK"])
    assert parsed["one_shot_launcher"]["one_shot_prefix"] == A3_ONE_SHOT_PREFIX
    assert parsed["one_shot_launcher"]["python_argv"][1:7] == [
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={A3_ONE_SHOT_PREFIX}",
        "-c",
        A3_QUOTE_FREE_BOOTSTRAP,
    ]

    for field, value in (
        ("one_shot_prefix", A3_ONE_SHOT_PREFIX + "_drift"),
        ("authorized_builder_source_launch_count", 2),
        ("preexisting_prefix_builder_launch_count", 1),
    ):
        mutated = json.loads(json.dumps(command))
        mutated["one_shot_launcher"][field] = value
        with pytest.raises(R8R7DesignError, match="one-shot launcher"):
            parse_command_lock(canonical_json_bytes(mutated))

    mutated = json.loads(json.dumps(command))
    mutated["one_shot_launcher"]["python_argv"][1:3] = ["-B", "-I"]
    with pytest.raises(R8R7DesignError, match="one-shot launcher"):
        parse_command_lock(canonical_json_bytes(mutated))

    cross_bind_drift = json.loads(json.dumps(command))
    cross_bind_drift["one_shot_launcher"]["source_raw_sha256"] = "f" * 64
    drifted_reopened = dict(reopened)
    drifted_reopened["AUDITOR_COMMAND_LOCK"] = canonical_json_bytes(
        cross_bind_drift
    )
    with pytest.raises(R8R7DesignError, match="cross-bind"):
        validate_reopened_artifacts(drifted_reopened)


def test_resolved_frozen_archive_path_cannot_escape_trusted_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    outside = tmp_path / "outside" / "AUDITOR.pyz"
    original_resolve = Path.resolve

    def synthetic_resolve(path: Path, *, strict: bool = False) -> Path:
        if path == trusted / "outputs" / "frozen" / "AUDITOR.pyz":
            return outside
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", synthetic_resolve)
    with pytest.raises(R8R7DesignError, match="escaped"):
        resolve_frozen_archive_path(
            trusted_root=trusted,
            archive_relative="outputs/frozen/AUDITOR.pyz",
        )


def test_closure_cross_binds_exact_frozen_archive_relative_path() -> None:
    claim, reopened = _closure_fixture()
    claim["supplemental_auditor_archive_relative"] = "outputs/other/AUDITOR.pyz"
    claim = dict(build_closure(claim))
    with pytest.raises(R8R7DesignError, match="command lock"):
        signer_reopen(claim=claim, reopened=reopened)


def test_r8r7_001_immediate_issuance_rejects_missing_source_command_pin() -> None:
    claim, reopened = _closure_fixture()
    del claim["supplemental_auditor_command_lock_raw_sha256"]
    with pytest.raises(R8R7DesignError, match="exact-key"):
        immediate_issuance_reopen(claim=claim, reopened=reopened)


def test_r8r7_002_signer_rejects_substituted_auditor_archive() -> None:
    claim, reopened = _closure_fixture()
    reopened["AUDITOR_ARCHIVE"] += b"substitution"
    with pytest.raises(R8R7DesignError, match="reopened hash"):
        signer_reopen(claim=claim, reopened=reopened)


def test_r8r7_003_rejects_pid_reuse_creation_time_change() -> None:
    changed = replace(
        _process("SIGNER"),
        creation_time_100ns=_process("SIGNER").creation_time_100ns + 1,
    )
    with pytest.raises(R8R7DesignError, match="instance changed"):
        validate_evidence_window(**_window(signer_final=changed))


@pytest.mark.parametrize(
    "mutation",
    [
        {"query_handle_access_mask": 0x1F001F},
        {"active_process_ids": (41002, 99999)},
        {"limit_flags": JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 0x800},
        {"job_identity_sha256": "f" * 64},
        {"handle_inventory_complete": False},
    ],
)
def test_r8r7_004_rejects_any_job_or_non_query_handle_witness(
    mutation: dict[str, Any],
) -> None:
    weak = replace(_job(), **mutation)
    with pytest.raises(R8R7DesignError, match="Job Object"):
        validate_evidence_window(**_window(job_initial=weak, job_final=weak))


@pytest.mark.parametrize(
    "field,value",
    [
        ("command_line_sha256", "f" * 64),
        ("source_identity_sha256", "e" * 64),
        ("image", replace(_image(), file_id_128="f" * 32)),
    ],
)
def test_r8r7_005_rejects_command_source_or_file_id_substitution(
    field: str, value: Any
) -> None:
    signer = replace(_process("SIGNER"), **{field: value})
    with pytest.raises(R8R7DesignError, match="differs from binding"):
        validate_evidence_window(
            **_window(signer_initial=signer, signer_final=signer)
        )


def test_r8r7_006_authority_rejects_missing_process_job_closure() -> None:
    claim, reopened = _closure_fixture()
    del reopened["EXACT_JOB_WITNESS"]
    with pytest.raises(R8R7DesignError, match="artifact universe"):
        authority_reopen(claim=claim, reopened=reopened)


def test_semantic_closure_rejects_rehashed_but_false_audit_and_seal() -> None:
    claim, reopened = _closure_fixture()
    audit = json.loads(reopened["SUPPLEMENTAL_AUDIT"])
    audit["request_count"] = 1
    reopened["SUPPLEMENTAL_AUDIT"] = canonical_json_bytes(audit)
    claim["supplemental_audit_json_raw_sha256"] = sha256_bytes(
        reopened["SUPPLEMENTAL_AUDIT"]
    )
    seal = json.loads(reopened["SUPPLEMENTAL_SEAL"])
    seal["supplemental_audit_json_raw_sha256"] = claim[
        "supplemental_audit_json_raw_sha256"
    ]
    reopened["SUPPLEMENTAL_SEAL"] = canonical_json_bytes(seal)
    claim["supplemental_audit_seal_raw_sha256"] = sha256_bytes(
        reopened["SUPPLEMENTAL_SEAL"]
    )
    claim = dict(build_closure(claim))
    with pytest.raises(R8R7DesignError, match="audit semantic"):
        signer_reopen(claim=claim, reopened=reopened)


def test_job_query_open_witness_and_post_close_receipt_are_separate() -> None:
    window = _window()
    assert window["job_initial"].query_handle_open_during_snapshot is True
    assert window["job_close"].query_handle_close_succeeded is True
    receipt = validate_evidence_window(**window)
    assert receipt["job_open_witness"]["query_handle_open_during_snapshot"] is True
    assert receipt["job_close_witness"]["remaining_known_handle_roles"] == (
        "SUPERVISOR_LIFETIME",
    )


def test_job_close_choreography_rejects_unclosed_or_unknown_handle() -> None:
    close = replace(
        _job_close(_job()),
        query_handle_close_succeeded=False,
        remaining_known_handle_roles=("SUPERVISOR_LIFETIME", "AUDITOR_QUERY"),
    )
    with pytest.raises(R8R7DesignError, match="close choreography"):
        validate_evidence_window(**_window(job_close=close))


def test_strict_double_snapshot_passes_with_zero_counters_and_expiry_margin() -> None:
    receipt = validate_evidence_window(**_window())
    assert receipt["final_heartbeat_sequence"] == 62
    assert receipt["request_count"] == receipt["signature_count"] == 0
    assert receipt["publication_delay_seconds"] == 0.5


@pytest.mark.parametrize(
    "change,match",
    [
        ({"telemetry_final": _telemetry(61, NOW + timedelta(seconds=1))}, "strictly progress"),
        ({"publication_at": NOW + timedelta(seconds=10)}, "delay exceeds"),
    ],
)
def test_double_snapshot_rejects_equal_heartbeat_or_late_publication(
    change: dict[str, Any], match: str
) -> None:
    with pytest.raises(R8R7DesignError, match=match):
        validate_evidence_window(**_window(**change))


def test_evidence_rejects_extra_binding_or_telemetry_keys() -> None:
    binding = _binding()
    binding["extra"] = 1
    with pytest.raises(R8R7DesignError, match="binding exact-key"):
        validate_evidence_window(**_window(binding=binding))
    telemetry = _telemetry(62, NOW + timedelta(seconds=1))
    telemetry["extra"] = 1
    with pytest.raises(R8R7DesignError, match="telemetry exact-key"):
        validate_evidence_window(**_window(telemetry_final=telemetry))


def test_source_identity_rejects_hash_or_schema_drift() -> None:
    raw = b"source"
    identity = build_source_identity(
        [SourceRecord("a.py", "auditor_r8_r7/a.py", sha256_bytes(raw), len(raw))]
    )
    drift = json.loads(canonical_json_bytes(identity))
    drift["records"][0]["raw_sha256"] = "f" * 64
    with pytest.raises(R8R7DesignError, match="digest"):
        parse_source_identity(drift)


def test_supervisor_archive_custody_holds_ancestry_and_no_share_write_delete(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "AUDITOR.pyz"
    archive.write_bytes(b"frozen-archive")
    with SupervisorArchiveCustody(path=archive, root=tmp_path) as custody:
        receipt = custody.receipt()
        assert receipt["write_share_allowed"] is False
        assert receipt["delete_share_allowed"] is False
        assert receipt["all_ancestry_handles_held"] is True
        assert receipt["file_attribute_tag_info_checked"] is True
        assert receipt["archive_handle_matches_held_target_file_id"] is True
        with pytest.raises(OSError):
            archive.open("r+b")


def test_archive_held_parent_mode_resolves_the_attempt_r1_share_conflict(
    tmp_path: Path,
) -> None:
    outputs = tmp_path / "outputs"
    predecessor = outputs / "immutable_predecessor"
    predecessor.mkdir(parents=True)
    archive = predecessor / "CHECKSUMS.sha256"
    archive.write_bytes(b"frozen-predecessor-ledger")
    with SupervisorDirectoryCustody(
        path=outputs,
        ancestry_root=outputs,
    ) as parent:
        with pytest.raises(R8R7DesignError, match="32"):
            SupervisorArchiveCustody(path=archive, root=Path(archive.anchor))
        with SupervisorArchiveCustody(
            path=archive,
            root=predecessor,
            held_parent=parent,
        ) as custody:
            receipt = custody.receipt()
            assert custody.raw_bytes() == b"frozen-predecessor-ledger"
            assert receipt["custody_mode"] == (
                "BORROWED_HELD_PARENT_RELATIVE_ROOT_AND_FILE"
            )
            assert receipt["archive_root_opened_by_held_parent_relative_ntcreatefile"]
            assert receipt["archive_file_opened_by_held_root_relative_ntcreatefile"]
            assert receipt["root_and_file_write_share_allowed"] is False
            assert receipt["root_and_file_delete_share_allowed"] is False
            assert receipt["projected_prefix_stable"] is True


def test_archive_held_parent_binding_negatives_fail_before_nt_path_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    parent = SupervisorDirectoryCustody(path=outputs, ancestry_root=outputs)
    rename_root = tmp_path / "rename_root"
    rename_root.mkdir()
    rename_parent = SupervisorDirectoryCustody(
        path=rename_root,
        ancestry_root=rename_root,
        rename_capable=True,
    )
    closed_root = tmp_path / "closed_root"
    closed_root.mkdir()
    closed_parent = SupervisorDirectoryCustody(
        path=closed_root,
        ancestry_root=closed_root,
    )
    closed_parent.close()
    calls = {"directory": 0, "relative": 0}

    def forbidden_directory(*_args: object, **_kwargs: object) -> int:
        calls["directory"] += 1
        raise AssertionError("binding rejection performed directory path I/O")

    def forbidden_relative(*_args: object, **_kwargs: object) -> tuple[int, int]:
        calls["relative"] += 1
        raise AssertionError("binding rejection performed relative NT path I/O")

    invalid = (
        {
            "path": outputs / "predecessor" / "CHECKSUMS.sha256",
            "root": outputs / "predecessor",
            "held_parent": object(),
        },
        {
            "path": outputs / "nested" / "predecessor" / "CHECKSUMS.sha256",
            "root": outputs / "nested" / "predecessor",
            "held_parent": parent,
        },
        {
            "path": outputs
            / "predecessor"
            / ".."
            / "predecessor"
            / "CHECKSUMS.sha256",
            "root": outputs / "predecessor" / ".." / "predecessor",
            "held_parent": parent,
        },
        {
            "path": outputs / "predecessor" / "nested" / "CHECKSUMS.sha256",
            "root": outputs / "predecessor",
            "held_parent": parent,
        },
        {
            "path": rename_root / "predecessor" / "CHECKSUMS.sha256",
            "root": rename_root / "predecessor",
            "held_parent": rename_parent,
        },
        {
            "path": closed_root / "predecessor" / "CHECKSUMS.sha256",
            "root": closed_root / "predecessor",
            "held_parent": closed_parent,
        },
    )
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(
                filesystem_identity,
                "_open_directory_custody_handle",
                forbidden_directory,
            )
            scoped.setattr(
                filesystem_identity,
                "_nt_create_relative",
                forbidden_relative,
            )
            for kwargs in invalid:
                with pytest.raises(R8R7DesignError):
                    SupervisorArchiveCustody(**kwargs)  # type: ignore[arg-type]
    finally:
        rename_parent.close()
        parent.close()
    assert calls == {"directory": 0, "relative": 0}


def test_archive_borrowed_parent_lifetime_and_default_full_ancestry_are_distinct(
    tmp_path: Path,
) -> None:
    standalone = tmp_path / "standalone"
    standalone.mkdir()
    standalone_archive = standalone / "AUDITOR.pyz"
    standalone_archive.write_bytes(b"default-full-ancestry")
    with SupervisorArchiveCustody(
        path=standalone_archive,
        root=standalone,
    ) as default_custody:
        default_receipt = default_custody.receipt()
        assert "custody_mode" not in default_receipt
        assert default_receipt["held_ancestry_handle_count"] == (
            default_receipt["ancestor_count"] - 1
        )

    outputs = tmp_path / "borrowed_outputs"
    predecessor = outputs / "predecessor"
    predecessor.mkdir(parents=True)
    archive = predecessor / "CHECKSUMS.sha256"
    archive.write_bytes(b"borrowed-lifetime")
    parent = SupervisorDirectoryCustody(path=outputs, ancestry_root=outputs)
    parent_before = parent.receipt()
    custody = SupervisorArchiveCustody(
        path=archive,
        root=predecessor,
        held_parent=parent,
    )
    custody.close()
    assert parent.receipt() == parent_before
    parent.close()

    second_parent = SupervisorDirectoryCustody(path=outputs, ancestry_root=outputs)
    second_custody = SupervisorArchiveCustody(
        path=archive,
        root=predecessor,
        held_parent=second_parent,
    )
    second_parent.close()
    with pytest.raises(R8R7DesignError, match="closed"):
        second_custody.receipt()
    second_custody.close()


def test_predecessor_chain_holds_every_file_under_one_outputs_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    source = inspect.getsource(builder._predecessor_chain)
    assert "with ExitStack() as predecessor_window" in source
    assert "held_parent=outputs_custody" in source
    assert "all_predecessor_file_custodies_held_simultaneously" in source

    project_root = tmp_path / "synthetic_project"
    outputs = project_root / "outputs"
    r8_r6_root = outputs / "r8_r6_predecessor"
    attempt_r1_root = outputs / "r8_r7_attempt_r1_forensic"
    attempt_a2_root = outputs / "r8_r7_attempt_a2_forensic"
    r8_r6_root.mkdir(parents=True)
    attempt_r1_root.mkdir()
    attempt_a2_root.mkdir()
    full_snapshot = {
        "full_repository_suite_passed": False,
        "snapshot_preserved_instead_of_false_pass": True,
        "collection": {"collected_test_count": 2017},
        "bounded_first_three": {"failures": [{}, {}, {}]},
        "isolated_causality_repeat": {},
        "post_r2_workspace_collection_snapshot": {
            "classification": "CONCURRENT_UNRELATED_WORKSPACE_TEST_NAMING_COLLISION"
        },
    }
    r8_r6_raw = {
        "CHECKSUMS.sha256": b"synthetic-r8-r6-ledger\n",
        "COMMAND_LOCK.json": canonical_json_bytes(
            {
                "production_command": None,
                "production_execution_allowed": False,
                "signer_launch_allowed": False,
                "authority_issuance_allowed": False,
            }
        ),
        "SEAL.json": canonical_json_bytes({}),
        "SOURCE_IDENTITY.json": canonical_json_bytes({}),
        "MINIMUM_R8_R7_DELTA.json": canonical_json_bytes({}),
        "FULL_REPOSITORY_TEST_SNAPSHOT.json": canonical_json_bytes(full_snapshot),
    }
    predecessor_hashes: dict[str, str] = {}
    for name, raw in r8_r6_raw.items():
        (r8_r6_root / name).write_bytes(raw)
        predecessor_hashes[f"r8_r6_r2/{name}"] = sha256_bytes(raw)
    attempt_r1_raw = b"synthetic-attempt-r1-forensic-ledger\n"
    (attempt_r1_root / "CHECKSUMS.sha256").write_bytes(attempt_r1_raw)
    predecessor_hashes[
        "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256"
    ] = sha256_bytes(attempt_r1_raw)
    attempt_a2_raw = b"synthetic-attempt-a2-forensic-ledger\n"
    (attempt_a2_root / "CHECKSUMS.sha256").write_bytes(attempt_a2_raw)
    predecessor_hashes[
        "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256"
    ] = sha256_bytes(attempt_a2_raw)

    assert builder.PREDECESSOR_HASHES[
        "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256"
    ] == "a4bd7300f93a91d87bc8dc380c1a1c5d4389ef06c78448d344205b6774d7ded2"
    assert builder.PREDECESSOR_HASHES[
        "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256"
    ] == "35e7fd3248b04a4f99a199f0279892088bba3d210823dff6bab305833f7bd7aa"
    monkeypatch.setattr(builder, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(builder, "R8_R6_R2_ROOT", r8_r6_root)
    monkeypatch.setattr(builder, "ATTEMPT_R1_FORENSIC_ROOT", attempt_r1_root)
    monkeypatch.setattr(builder, "ATTEMPT_A2_FORENSIC_ROOT", attempt_a2_root)
    monkeypatch.setattr(builder, "PREDECESSOR_HASHES", predecessor_hashes)
    with SupervisorDirectoryCustody(
        path=outputs,
        ancestry_root=outputs,
    ) as outputs_custody:
        result = builder._predecessor_chain(outputs_custody=outputs_custody)
    assert result["record_count"] == result["predecessor_custody_count"] == 8
    assert result["peak_simultaneous_predecessor_file_custody_count"] == 8
    assert result["all_predecessor_file_custodies_held_simultaneously"] is True
    assert result["attempt_r1_forensic_checksums_raw_sha256"] == (
        predecessor_hashes[
            "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256"
        ]
    )
    assert result["attempt_a2_forensic_checksums_raw_sha256"] == (
        predecessor_hashes[
            "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256"
        ]
    )


def test_a3_launcher_directly_addresses_terminal_a2_prefix_causality(
    tmp_path: Path,
) -> None:
    builder = sys.modules[_freeze_with_outputs_custody.__module__]
    assert builder.PREDECESSOR_HASHES[
        "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256"
    ] == (
        "35e7fd3248b04a4f99a199f0279892088bba3d210823dff6bab305833f7bd7aa"
    )
    fixture_root = tmp_path / "held_a2_terminal_forensic"
    fixture_root.mkdir()
    command_raw = canonical_json_bytes(
        {
            "actual_builder_process_launch_count": 1,
            "environment": {
                "PYTHONPYCACHEPREFIX": (
                    "C:\\Users\\minsu\\Documents\\EPS\\build\\"
                    "pc_r8r7_a2_freeze_actual_once_20260822"
                )
            },
            "outer_pycache_prefix_created_before_launch": False,
            "outer_pycache_prefix_exists_after": False,
            "prelaunch_dispatch_failure_source_execution_count": 0,
            "reexecution_authorized": False,
        }
    )
    audit_raw = canonical_json_bytes(
        {
            "failed_before_adjacent_bytecode_preflight": True,
            "failed_before_outputs_custody": True,
            "failed_before_publication": True,
            "failed_before_quality": True,
            "root_cause": {
                "exception": "FileNotFoundError from Path.resolve(strict=True)",
                "failure_stage": (
                    "main -> freeze -> _require_freeze_launcher_isolation -> "
                    "absent outer pycache prefix"
                ),
            },
        }
    )
    command_path = fixture_root / "COMMAND_ENVIRONMENT.json"
    audit_path = fixture_root / "FILESYSTEM_AUDIT.json"
    command_path.write_bytes(command_raw)
    audit_path.write_bytes(audit_raw)
    with SupervisorArchiveCustody(
        path=command_path,
        root=fixture_root,
    ) as command_custody, SupervisorArchiveCustody(
        path=audit_path,
        root=fixture_root,
    ) as audit_custody:
        command_receipt = command_custody.receipt()
        audit_receipt = audit_custody.receipt()
        command = json.loads(command_custody.raw_bytes())
        audit = json.loads(audit_custody.raw_bytes())
        assert command_receipt["raw_sha256"] == sha256_bytes(command_raw)
        assert audit_receipt["raw_sha256"] == sha256_bytes(audit_raw)
        assert command_custody.receipt() == command_receipt
        assert audit_custody.receipt() == audit_receipt
    assert command["actual_builder_process_launch_count"] == 1
    assert command["outer_pycache_prefix_created_before_launch"] is False
    assert command["outer_pycache_prefix_exists_after"] is False
    assert command["prelaunch_dispatch_failure_source_execution_count"] == 0
    assert command["reexecution_authorized"] is False
    assert audit["failed_before_adjacent_bytecode_preflight"] is True
    assert audit["failed_before_outputs_custody"] is True
    assert audit["failed_before_quality"] is True
    assert audit["failed_before_publication"] is True
    assert audit["root_cause"]["exception"] == (
        "FileNotFoundError from Path.resolve(strict=True)"
    )
    launcher_source = (
        builder.PROJECT_ROOT / builder.LAUNCHER_RELATIVE
    ).read_text(encoding="utf-8")
    assert launcher_source.index(
        "New-Item -ItemType Directory -Path $OneShotPrefix -ErrorAction Stop"
    ) < launcher_source.index("& $PinnedPython @childArgs")
    assert "The a3 one-shot prefix was already consumed" in launcher_source
    assert command["environment"]["PYTHONPYCACHEPREFIX"] != str(
        builder.ONE_SHOT_LAUNCHER_PREFIX
    )


def test_builder_threads_the_same_outputs_custody_through_all_chain_checks() -> None:
    source = inspect.getsource(_freeze_with_outputs_custody)
    exact_call = "_predecessor_chain(outputs_custody=outputs_custody)"
    assert source.count(exact_call) == 3
    assert "_predecessor_chain()" not in source
    assert source.index(exact_call) < source.index("with ExitStack() as source_window")
    assert source.rindex(exact_call) > source.index(
        "_publish_bound_artifacts_no_go"
    )
    post_publication = source[source.index("persistence =") :]
    assert 'path=OUTPUT_ROOT / "AUDITOR.pyz",' in post_publication
    assert "root=OUTPUT_ROOT," in post_publication
    assert "held_parent=outputs_custody," in post_publication
    assert 'path=OUTPUT_ROOT / "AUDITOR.pyz", root=OUTPUTS_ROOT' not in source


def test_supervisor_archive_constructor_unwinds_every_handle_on_post_open_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_open_directory = filesystem_identity._open_directory_custody_handle
    original_nt_create_relative = filesystem_identity._nt_create_relative
    original_close = filesystem_identity._close
    seam_names = (
        "_native_identity",
        "_attribute_tag_info",
        "_raw_resolved_guid_path",
        "_read_windows_handle",
    )

    for index, seam_name in enumerate(seam_names):
        case_root = tmp_path / f"fault_{index}"
        case_root.mkdir()
        archive = case_root / "AUDITOR.pyz"
        archive.write_bytes(b"frozen-archive")
        opened: list[int] = []
        closed: list[int] = []
        final_handle: dict[str, int | None] = {"value": None}
        original_seam = getattr(filesystem_identity, seam_name)

        def recorded_open_directory(*args: Any, **kwargs: Any) -> int:
            handle = original_open_directory(*args, **kwargs)
            opened.append(handle)
            return handle

        def recorded_nt_create_relative(
            *args: Any, **kwargs: Any
        ) -> tuple[int, int]:
            handle, information = original_nt_create_relative(*args, **kwargs)
            final_handle["value"] = handle
            opened.append(handle)
            return handle, information

        def fail_for_final_handle(*args: Any, **kwargs: Any) -> Any:
            if args and args[0] == final_handle["value"]:
                raise OSError(f"synthetic {seam_name} failure")
            return original_seam(*args, **kwargs)

        def recorded_close(handle: int) -> None:
            closed.append(handle)
            original_close(handle)

        with monkeypatch.context() as scoped:
            scoped.setattr(
                filesystem_identity,
                "_open_directory_custody_handle",
                recorded_open_directory,
            )
            scoped.setattr(
                filesystem_identity,
                "_nt_create_relative",
                recorded_nt_create_relative,
            )
            scoped.setattr(filesystem_identity, seam_name, fail_for_final_handle)
            scoped.setattr(filesystem_identity, "_close", recorded_close)
            with pytest.raises(OSError, match=f"synthetic {seam_name} failure"):
                SupervisorArchiveCustody(path=archive, root=case_root)
        assert final_handle["value"] is not None
        assert closed == list(reversed(opened))

    close_root = tmp_path / "close_failure"
    close_root.mkdir()
    close_archive = close_root / "AUDITOR.pyz"
    close_archive.write_bytes(b"frozen-archive")
    opened = []
    closed = []
    final_handle = {"value": None}
    original_read = filesystem_identity._read_windows_handle
    injected_close_failure = False

    def recorded_open_directory(*args: Any, **kwargs: Any) -> int:
        handle = original_open_directory(*args, **kwargs)
        opened.append(handle)
        return handle

    def recorded_nt_create_relative(*args: Any, **kwargs: Any) -> tuple[int, int]:
        handle, information = original_nt_create_relative(*args, **kwargs)
        final_handle["value"] = handle
        opened.append(handle)
        return handle, information

    def failed_read(handle: int) -> bytes:
        if handle == final_handle["value"]:
            raise OSError("synthetic read failure before cleanup")
        return original_read(handle)

    def close_then_report_failure(handle: int) -> None:
        nonlocal injected_close_failure
        closed.append(handle)
        original_close(handle)
        if not injected_close_failure:
            injected_close_failure = True
            raise R8R7DesignError("synthetic checked CloseHandle failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(
            filesystem_identity,
            "_open_directory_custody_handle",
            recorded_open_directory,
        )
        scoped.setattr(
            filesystem_identity,
            "_nt_create_relative",
            recorded_nt_create_relative,
        )
        scoped.setattr(filesystem_identity, "_read_windows_handle", failed_read)
        scoped.setattr(filesystem_identity, "_close", close_then_report_failure)
        with pytest.raises(
            R8R7DesignError,
            match="archive construction failed and handle cleanup was incomplete",
        ):
            SupervisorArchiveCustody(path=close_archive, root=close_root)
    assert injected_close_failure is True
    assert closed == list(reversed(opened))


def test_supervisor_artifact_custody_preserves_file_id_across_parent_rename(
    tmp_path: Path,
) -> None:
    create_source = inspect.getsource(
        SupervisorDirectoryCustody.create_held_direct_child_directory
    )
    create_call = create_source.index("_create_direct_child_directory_no_replace")
    adopt_call = create_source.index("_adopt_atomic_relative_child", create_call)
    first_observer_after_create = create_source.index(
        "_observe_direct_child_at", adopt_call
    )
    assert create_call < adopt_call < first_observer_after_create

    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as root:
        child, create = root.create_held_direct_child_directory("synthetic.stg")
        with child:
            artifact = child.create_new_direct_child_artifact(
                "artifact.bin", b"synthetic"
            )
            with artifact:
                written = artifact.receipt()
                pre_rename = artifact.prepare_for_parent_rename()
                root_before_rename = root.receipt()
                rename = root.rename_held_direct_child_no_replace(
                    child,
                    "synthetic.final",
                )
                root_after_rename = root.receipt()
                final = artifact.reopen_after_parent_rename()
                assert artifact.raw_bytes() == b"synthetic"
                identity_chain = {
                    (
                        receipt["volume_serial_number"],
                        receipt["file_id_128"],
                        receipt["size_bytes"],
                        receipt["raw_sha256"],
                    )
                    for receipt in (
                        written,
                        pre_rename["final_writer_receipt"],
                        final,
                    )
                }
                assert len(identity_chain) == 1
                assert written["handle_mode"] == "WRITER_HANDLE_HELD"
                assert final["handle_mode"] == "FINAL_READ_HANDLE_HELD"
                bracket = final["parent_rename_bracket"]
                assert bracket["exactly_one_parent_rename_observed"] is True
                assert bracket["zero_non_rename_namespace_mutations_observed"] is True
                assert bracket["same_exact_parent_inventory_before_after"] is True
                assert bracket["same_file_id_before_after_parent_rename"] is True
                assert bracket["same_hash_before_after_parent_rename"] is True
                assert bracket["does_not_claim_detection_of_zero_net_transient_cycles"] is True
                assert (
                    root_after_rename["held_handle_rename_count"]
                    - root_before_rename["held_handle_rename_count"]
                ) == 0
                assert (
                    root_after_rename["custody_namespace_mutation_count"]
                    - root_before_rename["custody_namespace_mutation_count"]
                ) == 1
            assert create["owned_open_child_custody_returned"] is True
            assert create["no_intervening_path_observation_before_child_custody"] is True
            assert create["atomic_create_receipt"]["creation_syscall_returned_handle"] is True
            assert create["atomic_create_receipt"]["share_mode"] == "FILE_SHARE_READ_ONLY"
            assert rename["root_directory_field"] is None
            assert rename["absolute_target_derived_from_held_parent_raw_path"] is True
            assert rename["dos_drive_mapping_fallback_used"] is False
            assert rename["local_ntfs_required_and_observed"] is True
            assert rename["same_file_id_before_after"] is True
            assert rename["same_parent_post_rename_file_id_verified"] is True
            assert [
                row["win32_error"]
                for row in rename["non_null_root_directory_host_probe_evidence"]
            ] == [87, 87]


def test_supervisor_directory_custody_ignores_pathname_spoof_and_detects_handle_reparse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as custody:
        original_lstat = filesystem_identity.os.lstat
        lstat_calls = 0

        def synthetic_lstat(path: os.PathLike[str] | str) -> Any:
            nonlocal lstat_calls
            lstat_calls += 1
            result = original_lstat(path)
            if Path(path) == tmp_path:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_dev=result.st_dev,
                    st_ino=result.st_ino,
                    st_file_attributes=(
                        int(getattr(result, "st_file_attributes", 0)) | 0x400
                    ),
                )
            return result

        monkeypatch.setattr(filesystem_identity.os, "lstat", synthetic_lstat)
        receipt = custody.receipt()
        assert receipt["ancestry_identity_stable"] is True
        assert lstat_calls == 0

        original_attributes = filesystem_identity._attribute_tag_info

        def synthetic_attributes(handle: int) -> tuple[int, int]:
            attributes, tag = original_attributes(handle)
            return attributes | filesystem_identity.FILE_ATTRIBUTE_REPARSE_POINT, tag

        monkeypatch.setattr(
            filesystem_identity,
            "_attribute_tag_info",
            synthetic_attributes,
        )
        with pytest.raises(R8R7DesignError, match="reparse"):
            custody.receipt()


def test_reparse_ancestor_is_rejected_before_handle_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "ancestor" / "member.json"
    nested.parent.mkdir()
    nested.write_bytes(b"{}")
    original = filesystem_identity.os.lstat

    def synthetic_lstat(path: os.PathLike[str] | str) -> Any:
        result = original(path)
        if Path(path).name == "ancestor":
            return SimpleNamespace(
                st_mode=result.st_mode,
                st_dev=result.st_dev,
                st_ino=result.st_ino,
                st_file_attributes=0x400,
            )
        return result

    monkeypatch.setattr(filesystem_identity.os, "lstat", synthetic_lstat)
    with pytest.raises(R8R7DesignError, match="reparse ancestor"):
        snapshot_reparse_free_ancestry(nested, root=tmp_path)


def test_preflight_is_case_insensitive_and_detects_stale_static_staging(
    tmp_path: Path,
) -> None:
    (tmp_path / f".{FORBIDDEN_PREFIXES[0].upper()}X.staging").mkdir()
    (tmp_path / f".{FORBIDDEN_PREFIXES[0]}hidden_non_staging").mkdir()
    (tmp_path / f".{STATIC_FREEZE_PREFIX}old.999.staging").mkdir()
    (tmp_path / ".MODEL_ZOO_OBSERVABLE_STATE_BCE_DGP_TOURNAMENT_V2_R8_R7_PHASE2_EXECUTION_EXTERNAL_ANCHOR").mkdir()
    (tmp_path / f".{STATIC_FREEZE_PREFIX}old.terminal_failure_no_go").mkdir()
    (tmp_path / f".{STATIC_FREEZE_PREFIX}old.partial").mkdir()
    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as custody:
        receipt = scan_forbidden_r8_r7_identities(custody)
        assert receipt["forbidden_identity_count"] == 6
        assert receipt["case_insensitive_name_matching"] is True
        assert receipt["force_inclusive_nofollow_inventory"] is True
        with pytest.raises(R8R7DesignError, match="pre-existing"):
            require_clean_r8_r7_preflight(custody)


def test_preflight_rejects_r8r7_reparse_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synthetic = {
        "observed_name": (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_unknown_x"
        ),
        "exists": True,
        "kind": "reparse",
        "reparse": True,
    }
    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as custody:
        monkeypatch.setattr(
            SupervisorDirectoryCustody,
            "observe_direct_children_force_inclusive",
            lambda _self: (synthetic,),
        )
        receipt = scan_forbidden_r8_r7_identities(custody)
        assert receipt["r8_r7_reparse_identity_count"] == 1
        assert receipt["forbidden_identity_count"] == 1


def test_negative_receipt_status_derives_from_explicit_measured_counts() -> None:
    counts = _zero_counts()
    counts["endpoint_contact_count"] = 1
    artifacts = build_negative_receipt(
        findings=["synthetic"], zero_state_counts=counts, generated_at=NOW
    )
    zero = json.loads(artifacts["ZERO_STATE.json"])
    assert zero["status"] == "FAIL_ZERO_STATE"
    assert set(artifacts) == {"AUDIT.json", "FINDINGS.json", "ZERO_STATE.json"}


def test_exception_receipt_is_canonical_and_hashes_exception_message() -> None:
    artifacts = build_exception_negative_receipt(
        exception=ValueError("secret-ish detail"),
        zero_state_counts=_zero_counts(),
        generated_at=NOW,
    )
    findings = json.loads(artifacts["FINDINGS.json"])
    assert "secret-ish detail" not in findings["findings"][0]["message"]
    assert findings["finding_counts"]["P0"] == 1


def test_publication_uses_internal_clock_and_cannot_grant_authority(
    tmp_path: Path,
) -> None:
    window = _window()
    del window["publication_at"]
    times = iter(
        [
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=2, milliseconds=100),
            NOW + timedelta(seconds=2, milliseconds=200),
        ]
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: next(times),
    )
    assert result["status"] == "PUBLISHED_BRACKET_VALIDATED_DESIGN_NO_GO"
    assert result["rename_injected_clock_seconds"] == 0.1
    assert result["rename_independent_monotonic_seconds"] <= 1
    assert result["both_rename_clocks_within_bound"] is True
    assert result["production_authority_granted"] is False
    persistence = result["persistence_receipt"]
    plan = _publication_plan()
    four_names = {
        plan.final_name,
        plan.staging_name,
        plan.failure_name,
        plan.failure_staging_name,
    }
    assert persistence["all_four_bound_children_checked_before_and_after"] is True
    assert set(persistence["global_child_observations_before"]) == four_names
    assert set(persistence["global_child_observations_after"]) == four_names
    assert all(
        observation["exists"] is False
        for observation in persistence["global_child_observations_before"].values()
    )
    assert {
        name
        for name, observation in persistence[
            "global_child_observations_after"
        ].items()
        if observation["exists"]
    } == {plan.final_name}
    gap = persistence["aggregate_parent_rename_gap"]
    assert gap["within_maximum"] is True
    assert gap["exactly_one_parent_directory_rename"] is True
    assert gap["publication_root_rename_count_delta"] == 0
    assert gap["publication_root_namespace_mutation_count_delta"] == 1
    assert gap["staging_child_rename_count_delta"] == 1
    assert gap["staging_child_namespace_mutation_count_delta"] == 1
    assert gap["unapproved_intervening_namespace_mutation_count"] == 0
    assert gap["authority_or_consumer_action_count"] == 0
    assert persistence["write_staging_final_artifact_file_ids_identical"] is True
    assert persistence["internal_dual_preflight_before_candidate_io"] is True
    assert persistence["preflight_before_full_root_inventory"][
        "forbidden_identity_count"
    ] == 0
    assert persistence["preflight_after_full_root_inventory"][
        "forbidden_identity_count"
    ] == 0
    assert persistence["full_root_inventory_before"]["direct_child_count"] == 0
    assert persistence["full_root_inventory_after"]["direct_child_names"] == [
        plan.final_name
    ]
    assert persistence["full_root_inventory_delta"] == {
        "status": "PASS_EXACTLY_ONE_BOUND_FINAL_CHILD_ADDED",
        "expected_added_name": plan.final_name,
        "added_names": [plan.final_name],
        "removed_names": [],
        "changed_preexisting_identity_names": [],
        "all_preexisting_direct_child_identities_unchanged": True,
        "staging_child_absent_at_final_snapshot": True,
        "final_child_file_id_matches_held_custody": True,
        "unexpected_persistent_namespace_delta_count": 0,
    }
    artifact_names = set(persistence["write_receipts"])
    assert artifact_names == {"DESIGN_NO_GO.json", "CHECKSUMS.sha256"}
    assert artifact_names == set(
        persistence["staging_verification"]["artifact_custody_receipts"]
    ) == set(persistence["pre_rename_artifact_receipts"]) == set(
        persistence["final_relative_reopen_receipts"]
    ) == set(persistence["final_verification"]["artifact_custody_receipts"])
    for name in artifact_names:
        phase_receipts = (
            persistence["write_receipts"][name],
            persistence["staging_verification"]["artifact_custody_receipts"][name],
            persistence["pre_rename_artifact_receipts"][name][
                "final_writer_receipt"
            ],
            persistence["final_relative_reopen_receipts"][name],
            persistence["final_verification"]["artifact_custody_receipts"][name],
        )
        assert len(
            {
                (
                    receipt["volume_serial_number"],
                    receipt["file_id_128"],
                    receipt["size_bytes"],
                    receipt["raw_sha256"],
                )
                for receipt in phase_receipts
            }
        ) == 1
        assert phase_receipts[0]["handle_mode"] == "WRITER_HANDLE_HELD"
        assert phase_receipts[-1]["handle_mode"] == "FINAL_READ_HANDLE_HELD"
    rejected_root = tmp_path / "rejected"
    rejected_root.mkdir()
    rejected = _publish_private(
        trusted_root=rejected_root,
        evidence={**window, "publication_at": NOW},
        counts=_zero_counts(),
    )
    assert rejected["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    assert Path(rejected["receipt_root"]).name == _publication_plan().failure_name


def test_private_artifact_name_gate_is_pure_and_leaves_no_staging_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_calls = 0
    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as custody:
        original_receipt = SupervisorDirectoryCustody.receipt

        def forbidden_receipt(self: SupervisorDirectoryCustody) -> dict[str, Any]:
            nonlocal receipt_calls
            receipt_calls += 1
            raise AssertionError("invalid artifact crossed the pure lexical gate")

        with monkeypatch.context() as scoped:
            scoped.setattr(
                SupervisorDirectoryCustody,
                "receipt",
                forbidden_receipt,
            )
            results = [
                publication._publish_bound_artifacts_no_go(
                    root_custody=custody,
                    plan=_publication_plan(),
                    artifacts=artifacts,
                )
                for artifacts in (
                    {"checksums.sha256": b"casefold ledger alias"},
                    {"invalid!filesystem-name.json": b"lexical mismatch"},
                )
            ]
        assert original_receipt(custody)[
            "custody_namespace_mutation_count"
        ] == 0
    assert receipt_calls == 0
    assert all(
        result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
        for result in results
    )
    assert list(tmp_path.iterdir()) == []


def test_publication_dual_preflight_rejects_persistent_forbidden_insertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    rogue = tmp_path / f"{FORBIDDEN_PREFIXES[0]}persistent_rogue"
    original_preflight = publication.require_clean_r8_r7_preflight
    preflight_calls = 0

    def insert_after_first_clean_scan(
        custody: SupervisorDirectoryCustody,
    ) -> dict[str, Any]:
        nonlocal preflight_calls
        preflight_calls += 1
        receipt = dict(original_preflight(custody))
        if preflight_calls == 1:
            rogue.mkdir()
        return receipt

    monkeypatch.setattr(
        publication,
        "require_clean_r8_r7_preflight",
        insert_after_first_clean_scan,
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert preflight_calls == 3
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_root"] is None
    assert rogue.is_dir()
    assert {path.name for path in tmp_path.iterdir()} == {rogue.name}


def test_publication_full_root_delta_rejects_late_forbidden_insertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    plan = _publication_plan()
    rogue = tmp_path / f"{FORBIDDEN_PREFIXES[0]}late_rogue"
    original_preflight = publication.require_clean_r8_r7_preflight
    original_seal = publication._seal_exception_bound
    preflight_calls = 0
    candidate_failures: list[BaseException] = []

    def insert_after_second_clean_scan(
        custody: SupervisorDirectoryCustody,
    ) -> dict[str, Any]:
        nonlocal preflight_calls
        preflight_calls += 1
        receipt = dict(original_preflight(custody))
        if preflight_calls == 2:
            rogue.mkdir()
        return receipt

    def capture_candidate_failure(**kwargs: Any) -> dict[str, Any]:
        candidate_failures.append(kwargs["exception"])
        return dict(original_seal(**kwargs))

    monkeypatch.setattr(
        publication,
        "require_clean_r8_r7_preflight",
        insert_after_second_clean_scan,
    )
    monkeypatch.setattr(publication, "_seal_exception_bound", capture_candidate_failure)
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert preflight_calls == 2
    assert len(candidate_failures) == 1
    assert str(candidate_failures[0]) == (
        "full-root inventory differs beyond the one approved final child"
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_root"] is None
    assert rogue.is_dir()
    assert (tmp_path / plan.final_name).is_dir()
    assert not (tmp_path / plan.staging_name).exists()


def test_publication_artifact_io_uses_only_retained_parent_relative_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = inspect.getsource(publication)
    assert "SupervisorArchiveCustody" not in source
    assert ".open(" not in source
    assert ".read_bytes(" not in source
    assert ".write_bytes(" not in source
    assert "create_new_direct_child_artifact" in source
    assert "prepare_for_parent_rename" in source
    assert "reopen_after_parent_rename" in source
    assert 'expected_handle_mode="FINAL_READ_HANDLE_HELD"' in source

    calls: list[str] = []

    def forbidden_path_io(*_args: object, **_kwargs: object) -> Any:
        calls.append("DOS_PATH_IO")
        raise AssertionError("publication re-entered an artifact through a DOS path")

    window = _window()
    del window["publication_at"]
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "open", forbidden_path_io)
        scoped.setattr(Path, "read_bytes", forbidden_path_io)
        scoped.setattr(Path, "write_bytes", forbidden_path_io)
        result = _publish_private(
            trusted_root=tmp_path,
            evidence=window,
            counts=_zero_counts(),
            clock=lambda: NOW + timedelta(seconds=2),
        )
    assert result["status"] == "PUBLISHED_BRACKET_VALIDATED_DESIGN_NO_GO"
    assert calls == []
    final_receipts = result["persistence_receipt"]["final_verification"][
        "artifact_custody_receipts"
    ]
    assert final_receipts
    assert all(
        receipt["handle_mode"] == "FINAL_READ_HANDLE_HELD"
        for receipt in final_receipts.values()
    )


def test_publication_validation_exception_seals_canonical_no_go(
    tmp_path: Path,
) -> None:
    window = _window()
    del window["publication_at"]
    window["binding"] = {**window["binding"], "extra": 1}
    times = iter([NOW + timedelta(seconds=2)])
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: next(times),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    assert Path(result["receipt_root"]).joinpath("FINDINGS.json").is_file()


def test_publication_rejects_nonzero_zero_state_on_success_path(tmp_path: Path) -> None:
    window = _window()
    del window["publication_at"]
    counts = _zero_counts()
    counts["endpoint_contact_count"] = 1
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=counts,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    zero = json.loads(Path(result["receipt_root"]).joinpath("ZERO_STATE.json").read_bytes())
    assert zero["status"] == "FAIL_ZERO_STATE"


def test_publication_clock_failure_still_seals_with_system_clock(tmp_path: Path) -> None:
    window = _window()
    del window["publication_at"]

    def failed_clock() -> datetime:
        raise OSError("synthetic clock failure")

    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=failed_clock,
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    assert Path(result["receipt_root"]).is_dir()


def test_publication_post_validation_artifact_io_failure_returns_terminal_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]

    original_create = SupervisorDirectoryCustody.create_new_direct_child_artifact
    create_count = 0

    def failed_create(
        self: SupervisorDirectoryCustody, name: str, raw: bytes
    ) -> SupervisorArtifactCustody:
        nonlocal create_count
        create_count += 1
        if create_count == 1:
            raise OSError("synthetic fsync failure")
        return original_create(self, name, raw)

    monkeypatch.setattr(
        SupervisorDirectoryCustody,
        "create_new_direct_child_artifact",
        failed_create,
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert create_count == 1
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_root"] is None
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert result["production_authority_granted"] is False


def test_publication_slow_atomic_rename_bracket_seals_terminal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original_seal = publication._seal_exception_bound
    candidate_failures: list[BaseException] = []

    def capture_candidate_failure(**kwargs: Any) -> dict[str, Any]:
        candidate_failures.append(kwargs["exception"])
        return dict(original_seal(**kwargs))

    monkeypatch.setattr(publication, "_seal_exception_bound", capture_candidate_failure)
    times = iter(
        [
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=2, milliseconds=100),
            NOW + timedelta(seconds=4),
        ]
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: next(times),
    )
    assert len(candidate_failures) == 1
    assert str(candidate_failures[0]) == (
        "snapshot-to-publication delay exceeds one second"
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert (tmp_path / _publication_plan().final_name).is_dir()
    assert result["receipt_root"] is None
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert result["production_authority_granted"] is False


def test_publication_constant_injected_clock_cannot_hide_monotonic_overrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original_seal = publication._seal_exception_bound
    candidate_failures: list[BaseException] = []

    def capture_candidate_failure(**kwargs: Any) -> dict[str, Any]:
        candidate_failures.append(kwargs["exception"])
        return dict(original_seal(**kwargs))

    monotonic = iter([10, 20, 30, 1_000_000_011])
    monkeypatch.setattr(publication, "_monotonic_ns", lambda: next(monotonic))
    monkeypatch.setattr(publication, "_seal_exception_bound", capture_candidate_failure)
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert len(candidate_failures) == 1
    assert str(candidate_failures[0]) == (
        "handle rename exceeded injected or monotonic publication bracket"
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert (tmp_path / _publication_plan().final_name / "DESIGN_NO_GO.json").is_file()
    assert result["receipt_root"] is None
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert result["production_authority_granted"] is False


def test_publication_each_of_four_bound_child_collisions_is_no_overwrite_fallback(
    tmp_path: Path,
) -> None:
    window = _window()
    del window["publication_at"]
    plan = _publication_plan()
    bound_names = (
        plan.final_name,
        plan.staging_name,
        plan.failure_name,
        plan.failure_staging_name,
    )
    for index, colliding_name in enumerate(bound_names):
        root = tmp_path / f"collision_{index}"
        root.mkdir()
        collision = root / (
            colliding_name.upper() if index == 0 else colliding_name
        )
        collision.mkdir()
        sentinel = collision / "sentinel.bin"
        sentinel.write_bytes(b"do-not-overwrite")
        result = _publish_private(
            trusted_root=root,
            evidence=window,
            counts=_zero_counts(),
        )
        assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
        assert result["receipt_root"] is None
        assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
        assert result["production_authority_granted"] is False
        assert sentinel.read_bytes() == b"do-not-overwrite"
        assert {item.name for item in root.iterdir()} == {collision.name}


def test_publication_malformed_counts_fail_closed_without_receipt_refailure(
    tmp_path: Path,
) -> None:
    window = _window()
    del window["publication_at"]
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts={"signer_launch_count": "not-an-integer"},  # type: ignore[dict-item]
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    zero = json.loads(Path(result["receipt_root"]).joinpath("ZERO_STATE.json").read_bytes())
    assert zero["status"] == "FAIL_ZERO_STATE"
    assert zero["zero_state_measurement_failure_count"] == 1


def test_publication_occupied_failure_root_returns_hashed_in_memory_no_go(
    tmp_path: Path,
) -> None:
    window = _window()
    del window["publication_at"]
    plan = _publication_plan()
    root = tmp_path / "failure_collision"
    root.mkdir()
    (root / plan.final_name).mkdir()
    failure_root = root / plan.failure_name
    failure_root.mkdir()
    sentinel = failure_root / "sentinel"
    sentinel.write_bytes(b"do-not-overwrite")
    result = _publish_private(
        trusted_root=root,
        evidence=window,
        counts=_zero_counts(),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert len(result["receipt_bundle_raw_sha256"]) == 64
    assert sentinel.read_bytes() == b"do-not-overwrite"

    staging_collision_root = tmp_path / "failure_staging_collision"
    staging_collision_root.mkdir()
    (staging_collision_root / plan.final_name).mkdir()
    receipt_staging = staging_collision_root / plan.failure_staging_name
    receipt_staging.mkdir()
    staging_result = _publish_private(
        trusted_root=staging_collision_root,
        evidence=window,
        counts=_zero_counts(),
    )
    assert staging_result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert receipt_staging.is_dir()


def test_publication_injected_and_system_clock_failures_use_fixed_utc_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]

    def failed_clock() -> datetime:
        raise OSError("synthetic clock failure")

    monkeypatch.setattr(publication, "_system_utc_now", failed_clock)
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=failed_clock,
    )
    audit = json.loads(Path(result["receipt_root"]).joinpath("AUDIT.json").read_bytes())
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO"
    assert audit["generated_at_utc"] == "1970-01-01T00:00:00+00:00"


def test_publication_rejects_created_staging_file_id_substitution_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original = SupervisorDirectoryCustody.create_held_direct_child_directory
    artifact_create_count = 0

    def substituted(
        self: SupervisorDirectoryCustody, name: str
    ) -> tuple[SupervisorDirectoryCustody, dict[str, Any]]:
        child, receipt = original(self, name)
        tampered = dict(receipt)
        held = dict(tampered["held_child_receipt"])
        held["file_id_128"] = "0" * 32
        tampered["held_child_receipt"] = held
        return child, tampered

    def forbidden_artifact_create(
        _self: SupervisorDirectoryCustody, _name: str, _raw: bytes
    ) -> SupervisorArtifactCustody:
        nonlocal artifact_create_count
        artifact_create_count += 1
        raise AssertionError("artifact creation crossed a rejected staging FileId")

    monkeypatch.setattr(
        SupervisorDirectoryCustody,
        "create_held_direct_child_directory",
        substituted,
    )
    monkeypatch.setattr(
        SupervisorDirectoryCustody,
        "create_new_direct_child_artifact",
        forbidden_artifact_create,
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert artifact_create_count == 0
    assert not (tmp_path / _publication_plan().final_name).exists()


def test_publication_root_drift_prevents_terminal_failure_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original_receipt = SupervisorDirectoryCustody.receipt
    original_create = SupervisorDirectoryCustody.create_new_direct_child_artifact
    drifted = False
    artifact_create_count = 0

    def drifting_receipt(self: SupervisorDirectoryCustody) -> dict[str, Any]:
        if drifted:
            raise R8R7DesignError("synthetic held root FileId drift")
        return dict(original_receipt(self))

    def trigger_drift(
        self: SupervisorDirectoryCustody, name: str, raw: bytes
    ) -> SupervisorArtifactCustody:
        nonlocal drifted, artifact_create_count
        artifact = original_create(self, name, raw)
        artifact_create_count += 1
        drifted = True
        return artifact

    monkeypatch.setattr(SupervisorDirectoryCustody, "receipt", drifting_receipt)
    monkeypatch.setattr(
        SupervisorDirectoryCustody,
        "create_new_direct_child_artifact",
        trigger_drift,
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert artifact_create_count == 1
    assert not (tmp_path / _publication_plan().failure_name).exists()


def test_publication_post_rename_file_id_mismatch_seals_no_go(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original = SupervisorArtifactCustody.reopen_after_parent_rename
    final_reopen_count = 0

    def mismatched_once(
        self: SupervisorArtifactCustody,
    ) -> dict[str, Any]:
        nonlocal final_reopen_count
        final_reopen_count += 1
        receipt = dict(original(self))
        if final_reopen_count == 1:
            receipt["file_id_128"] = "0" * 32
        return receipt

    monkeypatch.setattr(
        SupervisorArtifactCustody,
        "reopen_after_parent_rename",
        mismatched_once,
    )
    result = _publish_private(
        trusted_root=tmp_path,
        evidence=window,
        counts=_zero_counts(),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert final_reopen_count >= 1
    assert result["receipt_root"] is None
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert result["production_authority_granted"] is False


def test_publication_rejects_extra_namespace_mutation_in_artifact_rename_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window()
    del window["publication_at"]
    original = SupervisorDirectoryCustody.rename_held_direct_child_no_replace
    plan = _publication_plan()
    rename_count = 0
    with SupervisorDirectoryCustody(
        path=tmp_path,
        ancestry_root=tmp_path,
    ) as root:
        unrelated, _create = root.create_held_direct_child_directory(
            "unrelated.before"
        )
        with unrelated:
            baseline = root.receipt()

            def rename_with_unapproved_mutation(
                self: SupervisorDirectoryCustody,
                child: SupervisorDirectoryCustody,
                target_name: str,
            ) -> dict[str, Any]:
                nonlocal rename_count
                rename_count += 1
                receipt = dict(original(self, child, target_name))
                original(self, unrelated, "unrelated.after")
                return receipt

            monkeypatch.setattr(
                SupervisorDirectoryCustody,
                "rename_held_direct_child_no_replace",
                rename_with_unapproved_mutation,
            )
            result = dict(
                publication._publish_bound_no_go(
                    root_custody=root,
                    plan=plan,
                    evidence_without_publication_time=window,
                    zero_state_counts=_zero_counts(),
                    clock=lambda: NOW + timedelta(seconds=2),
                )
            )
            after = root.receipt()
    assert rename_count == 1
    assert (
        after["custody_namespace_mutation_count"]
        - baseline["custody_namespace_mutation_count"]
    ) == 3  # approved staging create + approved rename + unrelated rename
    assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
    assert result["receipt_root"] is None
    assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
    assert result["production_authority_granted"] is False
    assert (tmp_path / "unrelated.after").is_dir()
    assert not (tmp_path / "unrelated.before").exists()
    assert (tmp_path / plan.final_name).is_dir()


def test_bound_publication_names_fit_longpaths_disabled_budget() -> None:
    mirror_outputs = publication._trusted_outputs_root()
    live_project_root = Path(
        "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
    )
    live_outputs = live_project_root / "outputs"
    plan = _publication_plan()
    artifact_names = tuple(
        sorted(
            {
                "AUDITOR.pyz",
                "AUDIT.json",
                "BLOCKER_TRACE.json",
                "CANONICAL_EXCEPTION_NO_GO.json",
                "CHECKSUMS.sha256",
                "CLOSURE_SCHEMA.json",
                "COMMAND_LOCK.json",
                "FINDINGS.json",
                "FULL_REPOSITORY_STATUS.json",
                "MANIFEST.json",
                "NEGATIVE_TEST_MATRIX.json",
                "PREDECESSOR_CHAIN.json",
                "QUALITY_RECEIPT.json",
                "REPORT.md",
                "SEAL.json",
                "SELF_CHECK.json",
                "SOURCE_IDENTITY.json",
                "SOURCE_LOCK.json",
                "STATIC_DESIGN.json",
                "SUPERVISOR_DIRECTORY_CUSTODY.json",
                "ZERO_STATE.json",
            }
        )
    )
    child_names = (
        plan.final_name,
        plan.staging_name,
        plan.failure_name,
        plan.failure_staging_name,
    )
    relative_lengths = [
        len(str(Path("outputs") / child / artifact))
        for child in child_names
        for artifact in artifact_names
    ]
    live_lengths = [
        len(str(live_outputs / child / artifact))
        for child in child_names
        for artifact in artifact_names
    ]
    mirror_lengths = [
        len(str(mirror_outputs / child / artifact))
        for child in child_names
        for artifact in artifact_names
    ]
    assert len(relative_lengths) == len(live_lengths) == len(mirror_lengths)
    assert len(relative_lengths) == 4 * len(artifact_names)
    relative_suffix_max = max(
        len(str(Path(child) / artifact))
        for child in child_names
        for artifact in artifact_names
    )
    assert max(relative_lengths) == len("outputs") + 1 + relative_suffix_max
    assert max(live_lengths) == len(str(live_outputs)) + 1 + relative_suffix_max
    assert max(live_lengths) == 223
    assert max(mirror_lengths) == (
        len(str(mirror_outputs)) + 1 + relative_suffix_max
    )
    assert max(live_lengths) <= 240
    assert max(mirror_lengths) <= 240
    assert all(
        str(os.getpid()) not in name
        for name in child_names
    )


def test_publication_hostile_child_policy_clock_and_evidence_are_zero_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"coercion": 0, "custody": 0, "filesystem": 0, "clock": 0}

    class Hostile:
        def __str__(self) -> str:
            calls["coercion"] += 1
            raise AssertionError("str forbidden")

        def __repr__(self) -> str:
            calls["coercion"] += 1
            raise AssertionError("repr forbidden")

        def __fspath__(self) -> str:
            calls["coercion"] += 1
            raise AssertionError("fspath forbidden")

    def forbidden_custody(*_args: object, **_kwargs: object) -> None:
        calls["custody"] += 1
        raise AssertionError("custody forbidden")

    def forbidden_filesystem(*_args: object, **_kwargs: object) -> None:
        calls["filesystem"] += 1
        raise AssertionError("filesystem forbidden")

    def forbidden_clock(*_args: object, **_kwargs: object) -> datetime:
        calls["clock"] += 1
        raise AssertionError("clock forbidden")

    prebuilt_path = Path("safe-wrong")
    monkeypatch.setattr(publication, "SupervisorDirectoryCustody", forbidden_custody)
    monkeypatch.setattr(publication, "_trusted_outputs_root", forbidden_filesystem)
    monkeypatch.setattr(publication, "_system_utc_now", forbidden_clock)
    monkeypatch.setattr(publication, "_monotonic_ns", forbidden_clock)
    monkeypatch.setattr(
        publication, "_persist_new_artifact_tree", forbidden_filesystem
    )
    hostile_names: tuple[object, ...] = (
        None,
        Hostile(),
        prebuilt_path,
        "safe-wrong",
        "C:relative",
        "C:\\absolute",
        "C:/forward",
        "/posix/absolute",
        "\\\\server\\share",
        "\\\\?\\C:\\extended",
        "\\\\.\\PhysicalDrive0",
        "nested/child",
        "nested\\child",
        "stream:ads",
        "CON",
        "con.txt",
        "NUL ",
        "AUX.",
        "PRN.log",
        "COM1",
        "com¹.txt",
        "LPT9",
        "lpt².log",
        "CONIN$",
        "CONOUT$",
    )
    results = [
        publish_validated_design_no_go(
            policy=R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
            requested_child_name=name,
            evidence_without_publication_time=Hostile(),  # type: ignore[arg-type]
            zero_state_counts=Hostile(),  # type: ignore[arg-type]
        )
        for name in hostile_names
    ]
    results.extend(
        (
            publish_validated_design_no_go(
                policy=object(),
                requested_child_name=PERMITTED_STATIC_DESIGN_CHILD_NAME,
                evidence_without_publication_time=Hostile(),  # type: ignore[arg-type]
                zero_state_counts=Hostile(),  # type: ignore[arg-type]
            ),
            publish_validated_design_no_go(
                policy=R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
                requested_child_name=PERMITTED_STATIC_DESIGN_CHILD_NAME,
                evidence_without_publication_time=Hostile(),  # type: ignore[arg-type]
                zero_state_counts={},
            ),
            publish_validated_design_no_go(
                policy=R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
                requested_child_name=PERMITTED_STATIC_DESIGN_CHILD_NAME,
                evidence_without_publication_time={},
                zero_state_counts=Hostile(),  # type: ignore[arg-type]
            ),
            publish_validated_design_no_go(
                policy=R8_R7_STATIC_DESIGN_PUBLICATION_POLICY,
                requested_child_name=PERMITTED_STATIC_DESIGN_CHILD_NAME,
                evidence_without_publication_time={},
                zero_state_counts={},
                clock=forbidden_clock,
            ),
        )
    )
    for result in results:
        assert result["status"] == "SEALED_CANONICAL_EXCEPTION_NO_GO_FALLBACK"
        assert result["receipt_root"] is None
        assert result["receipt_persistence_status"] == "NOT_PERSISTED_NO_OVERWRITE"
        assert len(result["receipt_bundle_raw_sha256"]) == 64
        assert result["production_authority_granted"] is False
    assert len({result["receipt_bundle_raw_sha256"] for result in results}) == 1
    assert calls == {"coercion": 0, "custody": 0, "filesystem": 0, "clock": 0}
