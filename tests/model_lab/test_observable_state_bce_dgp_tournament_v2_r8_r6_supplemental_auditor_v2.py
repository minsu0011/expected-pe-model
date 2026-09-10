from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import runpy
from typing import Any
import zipfile

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1 import (
    auditor as v1_auditor,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.supervision import (
    validate_supplemental_audit_go as v1_validate_supplemental_go,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1 import (
    ProcessEvidence as V1ProcessEvidence,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1.auditor import (
    _plain_file as v1_plain_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1.auditor import (
    _validate_process as v1_validate_process,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.canonical import (
    V2AuditError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.command_lock import (
    build_frozen_archive_command,
    validate_disabled_r8_r6_command_lock,
    validate_frozen_archive_command,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.compatibility import (
    analyze_r8_r6_archive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.hardened_fs import (
    assert_reparse_free,
    read_stable_plain_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2 import (
    hardened_fs,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.preflight import (
    BINDING_IDENTITY,
    JOURNAL_PREFIX,
    PUBLIC_PREFIX,
    SUPPLEMENTAL_STAGING_FRAGMENT,
    VAULT_PREFIX,
    require_clean_phase2_preflight,
    scan_forbidden_phase2_identities,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.source_identity import (
    SourceRecord,
    build_source_identity,
    parse_source_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.terminal import (
    build_no_go_artifacts,
    execute_or_seal_no_go,
    publish_terminal_no_go,
)
from scripts.model_lab.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.freeze_auditor import (
    _build_archive,
    _runtime_sources,
    _verify_archive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.validation import (
    JobEvidence,
    ProcessEvidence,
    validate_double_snapshot,
    validate_process_pair,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_static_design_r6_20260822"
)
V1_FREEZE_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v1_20260822"
)
NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
H = {letter: hashlib.sha256(letter.encode("ascii")).hexdigest() for letter in "abcdefghij"}


def _r7_binding(now: datetime = NOW) -> dict[str, Any]:
    return {
        "expires_at_utc": (now + timedelta(seconds=120)).isoformat(),
        "job_identity_sha256": H["a"],
        "signer_command_line_sha256": H["b"],
        "signer_creation_time_100ns": 133_000_000_000_000_001,
        "signer_image_path": "C:/frozen/python.exe",
        "signer_image_file_id_128": "1" * 32,
        "signer_image_raw_sha256": H["c"],
        "signer_image_volume_serial_number": 101,
        "signer_pid": 41002,
        "signer_source_identity_sha256": H["d"],
        "supervisor_command_line_sha256": H["e"],
        "supervisor_creation_time_100ns": 133_000_000_000_000_000,
        "supervisor_image_path": "C:/frozen/python.exe",
        "supervisor_image_file_id_128": "1" * 32,
        "supervisor_image_raw_sha256": H["c"],
        "supervisor_image_volume_serial_number": 101,
        "supervisor_pid": 41001,
        "supervisor_source_identity_sha256": H["f"],
    }


def _job() -> JobEvidence:
    return JobEvidence(
        identity_sha256=H["a"],
        limit_flags=0x00002000,
        active_process_count=1,
        kill_on_job_close=True,
        signer_is_member=True,
        signer_pid_listed_by_exact_job=True,
        supervisor_owns_live_handle=True,
        queried_via_inherited_or_duplicated_supervisor_handle=True,
    )


def _process() -> ProcessEvidence:
    binding = _r7_binding()
    return ProcessEvidence(
        signer_pid=binding["signer_pid"],
        signer_creation_time_100ns=binding["signer_creation_time_100ns"],
        supervisor_pid=binding["supervisor_pid"],
        supervisor_creation_time_100ns=binding["supervisor_creation_time_100ns"],
        signer_parent_pid=binding["supervisor_pid"],
        signer_alive=True,
        supervisor_alive=True,
        parent_observed_while_handles_open=True,
        signer_image_path=binding["signer_image_path"],
        signer_image_file_id_128=binding["signer_image_file_id_128"],
        signer_image_raw_sha256=binding["signer_image_raw_sha256"],
        signer_image_volume_serial_number=binding[
            "signer_image_volume_serial_number"
        ],
        supervisor_image_path=binding["supervisor_image_path"],
        supervisor_image_file_id_128=binding["supervisor_image_file_id_128"],
        supervisor_image_raw_sha256=binding["supervisor_image_raw_sha256"],
        supervisor_image_volume_serial_number=binding[
            "supervisor_image_volume_serial_number"
        ],
        signer_command_line_sha256=binding["signer_command_line_sha256"],
        supervisor_command_line_sha256=binding["supervisor_command_line_sha256"],
        signer_source_identity_sha256=binding["signer_source_identity_sha256"],
        supervisor_source_identity_sha256=binding["supervisor_source_identity_sha256"],
        job=_job(),
    )


def _telemetry(sequence: int, observed: datetime = NOW) -> dict[str, Any]:
    binding = _r7_binding()
    return {
        "state": "READY",
        "exit_status": None,
        "error_code": None,
        "heartbeat_sequence": sequence,
        "request_count": 0,
        "signature_count": 0,
        "private_key_persisted": False,
        "detached_process": False,
        "parent_supervised": True,
        "foreground_supervised": True,
        "started_at_utc": (NOW - timedelta(seconds=60)).isoformat(),
        "last_heartbeat_utc": (observed - timedelta(seconds=1)).isoformat(),
        "observed_at_utc": observed.isoformat(),
        "signer_pid": binding["signer_pid"],
        "signer_creation_time_100ns": binding["signer_creation_time_100ns"],
        "supervisor_pid": binding["supervisor_pid"],
        "supervisor_creation_time_100ns": binding["supervisor_creation_time_100ns"],
        "signer_source_identity_sha256": binding["signer_source_identity_sha256"],
        "supervisor_source_identity_sha256": binding[
            "supervisor_source_identity_sha256"
        ],
        "job_identity_sha256": binding["job_identity_sha256"],
    }


def test_actual_frozen_r8_r6_archive_is_incompatible_and_requires_r7() -> None:
    report = analyze_r8_r6_archive(DESIGN_ROOT / "SOURCE_ARCHIVE.zip")
    assert report.compatible is False
    assert report.archive_raw_sha256 == (
        "14dd38872724fb20cc3513e1f358a39f7dc253faa29b3e1b59ba63fc56109c96"
    )
    assert {item.blocker_id for item in report.blockers} == {
        "R8R7-001",
        "R8R7-002",
        "R8R7-003",
        "R8R7-004",
        "R8R7-005",
        "R8R7-006",
    }


def test_r8_r6_issuance_and_signer_lack_exact_v2_identity_pin_consumers() -> None:
    package = (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
        "r8_r6_qualification_generation"
    )
    with zipfile.ZipFile(DESIGN_ROOT / "SOURCE_ARCHIVE.zip") as archive:
        immediate = archive.read(f"{package}/immediate_issuance.py").decode("utf-8")
        signer = archive.read(f"{package}/signer_service.py").decode("utf-8")
    required = (
        "supplemental_auditor_source_identity_sha256",
        "supplemental_auditor_command_lock_raw_sha256",
        "supplemental_auditor_source_freeze_checksums_raw_sha256",
    )
    assert all(token not in immediate for token in required)
    assert all(token not in signer for token in required)
    assert "supplemental_audit_json_raw_sha256" in immediate
    assert "supplemental_audit_seal_raw_sha256" in signer


def test_v1_downstream_accepts_arbitrary_source_identity_field() -> None:
    payload = {
        "schema_version": (
            "expected_pe.r8.r6.independent_signer_binding_supplemental_audit.v1"
        ),
        "verdict": "GO",
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "audit_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
            "independent_signer_binding_supplemental_audit_r6_20260822"
        ),
        "design_checksums_raw_sha256": H["a"],
        "binding_raw_sha256": H["b"],
        "alive_recheck_authorized": True,
        "qualification_authority_issuance_authorized": True,
        "heldout_generation_authorized": False,
        "model_fit_prediction_score_authorized": False,
        "truth_access_count": 0,
        "generation_count": 0,
        "request_count": 0,
        "signature_count": 0,
        "auditor_source_records_semantic_sha256": "f" * 64,
    }
    v1_validate_supplemental_go(
        payload,
        design_checksums_raw_sha256=H["a"],
        binding_raw_sha256=H["b"],
    )


def test_v1_frozen_command_source_identity_differs_from_runtime_schema() -> None:
    lock = json.loads((V1_FREEZE_ROOT / "COMMAND_LOCK.json").read_bytes())
    runtime = v1_auditor._source_identity(PROJECT_ROOT)
    assert lock["runtime_source_records_semantic_sha256"] == (
        "5ae97b8f6bd12e91f2c17489ba05e8773c337e91a7b81aecaeba41360a5b70d6"
    )
    assert runtime["source_records_semantic_sha256"] == (
        "2596228781c36aad96cccf3b57eb4e54b31656ca8d759911cb38d21aac281552"
    )
    assert (
        lock["runtime_source_records_semantic_sha256"]
        != runtime["source_records_semantic_sha256"]
    )


def test_v2_source_identity_uses_one_exact_schema_and_rejects_drift() -> None:
    raw = b"frozen-source"
    record = SourceRecord(
        source_relative="research/frozen.py",
        archive_member="auditor_v2/frozen.py",
        raw_sha256=sha256_bytes(raw),
        size_bytes=len(raw),
    )
    identity = build_source_identity([record])
    assert parse_source_identity(identity) == identity
    drift = json.loads(canonical_json_bytes(identity))
    drift["records"][0]["raw_sha256"] = "f" * 64
    with pytest.raises(V2AuditError, match="semantic digest"):
        parse_source_identity(drift)
    extra_schema = json.loads(canonical_json_bytes(identity))
    extra_schema["records"][0]["runtime_auditor_member"] = True
    with pytest.raises(V2AuditError, match="exact-key"):
        parse_source_identity(extra_schema)


def test_freeze_and_archive_runtime_use_the_same_source_identity_schema() -> None:
    records, members = _runtime_sources()
    identity = build_source_identity(records)
    archive = _build_archive(
        source_identity_raw=canonical_json_bytes(identity), archive_members=members
    )
    receipt = _verify_archive(archive_raw=archive, expected_identity=identity)
    assert receipt["source_records_semantic_sha256"] == identity[
        "records_semantic_sha256"
    ]
    assert receipt["source_record_count"] == len(records)


def test_v1_positive_fixture_seals_go_without_heartbeat_progress(tmp_path: Path) -> None:
    namespace = runpy.run_path(
        str(
            PROJECT_ROOT
            / "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1.py"
        )
    )
    synthetic_root = tmp_path / "v1"
    synthetic_root.mkdir()
    paths, policy, _binding, _telemetry_value, evidence = namespace["_fixture"](
        synthetic_root
    )
    result = namespace["run_supplemental_audit"](
        paths=paths,
        policy=policy,
        process_probe=namespace["FakeProcessProbe"](evidence),
        clock=lambda: namespace["NOW"],
    )
    matrix = json.loads((result.root / "CHECK_MATRIX.json").read_bytes())
    detail = next(
        row["detail"]
        for row in matrix["checks"]
        if row["name"] == "BINDING_STABILITY_ZERO_ACCESS"
    )
    assert result.verdict == "GO"
    assert detail["heartbeat_sequence_initial"] == 61
    assert detail["heartbeat_sequence_final"] == 61


def test_v1_seals_go_after_binding_expiry_at_publication(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    namespace = runpy.run_path(
        str(
            PROJECT_ROOT
            / "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1.py"
        )
    )
    synthetic_root = tmp_path_factory.mktemp("expiry")
    paths, policy, binding, _telemetry_value, evidence = namespace["_fixture"](
        synthetic_root
    )
    expiry = datetime.fromisoformat(binding["expires_at_utc"])
    moments = iter([NOW, NOW, NOW, expiry + timedelta(seconds=1)])
    result = namespace["run_supplemental_audit"](
        paths=paths,
        policy=policy,
        process_probe=namespace["FakeProcessProbe"](evidence),
        clock=lambda: next(moments),
    )
    audit = json.loads((result.root / "AUDIT.json").read_bytes())
    assert result.verdict == "GO"
    assert datetime.fromisoformat(audit["generated_at_utc"]) > expiry


def test_v2_rejects_equal_heartbeat_sequence() -> None:
    with pytest.raises(V2AuditError, match="strictly increase"):
        validate_double_snapshot(
            binding=_r7_binding(),
            initial=_telemetry(61, NOW),
            final=_telemetry(61, NOW + timedelta(seconds=1)),
            initial_observed_at=NOW,
            final_observed_at=NOW + timedelta(seconds=1),
            publication_at=NOW + timedelta(seconds=2),
        )


def test_v2_accepts_strict_progress_with_zero_counters_and_margin() -> None:
    result = validate_double_snapshot(
        binding=_r7_binding(),
        initial=_telemetry(61, NOW),
        final=_telemetry(62, NOW + timedelta(seconds=1)),
        initial_observed_at=NOW,
        final_observed_at=NOW + timedelta(seconds=1),
        publication_at=NOW + timedelta(seconds=2),
    )
    assert result["final_heartbeat_sequence"] == 62
    assert result["expiry_margin_seconds"] == 118


@pytest.mark.parametrize(
    "mutation",
    [
        {"request_count": 1},
        {"signature_count": 1},
        {"signer_creation_time_100ns": 133_000_000_000_000_999},
    ],
)
def test_v2_rejects_counter_or_process_identity_race(mutation: dict[str, Any]) -> None:
    final = _telemetry(62, NOW + timedelta(seconds=1))
    final.update(mutation)
    with pytest.raises(V2AuditError):
        validate_double_snapshot(
            binding=_r7_binding(),
            initial=_telemetry(61, NOW),
            final=final,
            initial_observed_at=NOW,
            final_observed_at=NOW + timedelta(seconds=1),
            publication_at=NOW + timedelta(seconds=2),
        )


def test_v2_rejects_publication_without_expiry_margin() -> None:
    with pytest.raises(V2AuditError, match="expiry margin"):
        validate_double_snapshot(
            binding=_r7_binding(),
            initial=_telemetry(61, NOW + timedelta(seconds=90)),
            final=_telemetry(62, NOW + timedelta(seconds=91)),
            initial_observed_at=NOW + timedelta(seconds=90),
            final_observed_at=NOW + timedelta(seconds=91),
            publication_at=NOW + timedelta(seconds=92),
        )


def test_v2_rejects_delayed_publication_even_before_expiry() -> None:
    with pytest.raises(V2AuditError, match="immediately bound"):
        validate_double_snapshot(
            binding=_r7_binding(),
            initial=_telemetry(61, NOW),
            final=_telemetry(62, NOW + timedelta(seconds=1)),
            initial_observed_at=NOW,
            final_observed_at=NOW + timedelta(seconds=1),
            publication_at=NOW + timedelta(seconds=10),
        )


def test_v1_process_predicate_accepts_pid_any_job_and_python_image_only() -> None:
    evidence = V1ProcessEvidence(
        signer_pid=41002,
        supervisor_pid=41001,
        signer_alive=True,
        supervisor_alive=True,
        signer_parent_pid=41001,
        signer_in_job=True,
        signer_image_path="C:/frozen/python.exe",
        supervisor_image_path="C:/frozen/python.exe",
        signer_image_raw_sha256=H["a"],
        supervisor_image_raw_sha256=H["a"],
        probe_platform="synthetic",
    )
    result = v1_validate_process(
        evidence,
        binding={
            "signer_pid": 41002,
            "supervisor_pid": 41001,
            "service_executable_raw_sha256": H["a"],
        },
    )
    assert result["signer_in_job"] is True
    assert "signer_creation_time_100ns" not in result


def test_v1_frozen_production_command_imports_mutable_live_package() -> None:
    lock = json.loads((V1_FREEZE_ROOT / "COMMAND_LOCK.json").read_bytes())
    command = lock["production_command"]
    assert command[1:3] == ["-B", "-m"]
    assert command[3].startswith("scripts.model_lab.")
    assert "-I" not in command and "-S" not in command and "-E" not in command


def test_v2_process_pair_requires_creation_source_command_and_exact_job() -> None:
    process = _process()
    result = validate_process_pair(
        binding=_r7_binding(), initial=process, final=process
    )
    assert result["job_identity_sha256"] == H["a"]


def test_v2_process_pair_rejects_pid_reuse_by_creation_time() -> None:
    process = _process()
    reused = replace(
        process,
        signer_creation_time_100ns=process.signer_creation_time_100ns + 1,
    )
    with pytest.raises(V2AuditError, match="changed"):
        validate_process_pair(
            binding=_r7_binding(), initial=process, final=reused
        )


@pytest.mark.parametrize(
    "job_mutation",
    [
        {"queried_via_inherited_or_duplicated_supervisor_handle": False},
        {"signer_pid_listed_by_exact_job": False},
        {"limit_flags": 0, "kill_on_job_close": False},
    ],
)
def test_v2_process_pair_rejects_any_job_without_exact_handle_witness(
    job_mutation: dict[str, Any],
) -> None:
    process = _process()
    weak_job = replace(process.job, **job_mutation)
    with pytest.raises(V2AuditError, match="not exact"):
        validate_process_pair(
            binding=_r7_binding(),
            initial=replace(process, job=weak_job),
            final=replace(process, job=weak_job),
        )


def test_frozen_r8_r6_binding_cannot_satisfy_v2_process_schema() -> None:
    with pytest.raises(V2AuditError, match="lacks v2 process identity fields"):
        validate_process_pair(
            binding={"signer_pid": 41002, "supervisor_pid": 41001},
            initial=_process(),
            final=_process(),
        )


def test_v1_reparse_check_is_applied_only_after_resolve() -> None:
    source = inspect.getsource(v1_plain_file)
    assert "resolved = path.resolve(strict=True)" in source
    assert "_is_reparse(resolved)" in source
    assert "path.parents" not in source


def test_v2_rejects_reparse_on_any_lexical_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "ancestor" / "file.json"
    nested.parent.mkdir()
    nested.write_bytes(b"{}")
    original = hardened_fs._is_reparse_or_link

    def synthetic_reparse(path: Path, metadata: os.stat_result) -> bool:
        return path.name == "ancestor" or original(path, metadata)

    monkeypatch.setattr(hardened_fs, "_is_reparse_or_link", synthetic_reparse)
    with pytest.raises(V2AuditError, match="reparse/link"):
        assert_reparse_free(nested, root=tmp_path)


def test_v2_stable_file_read_binds_file_id_before_and_after(tmp_path: Path) -> None:
    member = tmp_path / "member.json"
    raw = b'{"fixed":true}'
    member.write_bytes(raw)
    reopened, receipt = read_stable_plain_file(member, root=tmp_path)
    assert reopened == raw
    assert receipt["raw_sha256"] == sha256_bytes(raw)
    assert receipt["stable_before_after"] is True
    assert receipt["all_ancestors_to_filesystem_anchor_checked"] is True
    assert receipt["ancestry_file_ids_stable_before_after"] is True
    assert receipt["reparse_component_count"] == 0


def test_v2_treats_mode_and_mtime_as_diagnostics_not_file_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    member = tmp_path / "member.json"
    member.write_bytes(b'{"fixed":true}')
    original = hardened_fs.FileIdentity.from_stat.__func__
    calls = 0

    def diagnostic_drift(
        cls: type[hardened_fs.FileIdentity], item: os.stat_result
    ) -> hardened_fs.FileIdentity:
        nonlocal calls
        calls += 1
        value = original(cls, item)
        return replace(
            value,
            mode=value.mode ^ (calls & 1),
            mtime_ns=value.mtime_ns + calls,
        )

    monkeypatch.setattr(
        hardened_fs.FileIdentity,
        "from_stat",
        classmethod(diagnostic_drift),
    )
    reopened, receipt = read_stable_plain_file(member, root=tmp_path)
    assert reopened == b'{"fixed":true}'
    assert receipt["authoritative_file_identity"]["size_bytes"] == len(reopened)
    assert len(receipt["file_id_128"]) == 32


def test_v2_rejects_native_file_id_change_between_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    member = tmp_path / "member.json"
    member.write_bytes(b"{}")
    original = hardened_fs._native_identity_from_path
    member_calls = 0

    def substitute_file_id(
        path: Path, *, metadata: os.stat_result
    ) -> hardened_fs.NativeFileIdentity:
        nonlocal member_calls
        identity = original(path, metadata=metadata)
        if path == member:
            member_calls += 1
            if member_calls == 2:
                return replace(identity, file_id_128="f" * 32)
        return identity

    monkeypatch.setattr(
        hardened_fs,
        "_native_identity_from_path",
        substitute_file_id,
    )
    with pytest.raises(V2AuditError, match="file identity changed"):
        read_stable_plain_file(member, root=tmp_path)


def test_hidden_vault_journal_public_and_staging_are_all_scanned(tmp_path: Path) -> None:
    (tmp_path / f"{VAULT_PREFIX}x").mkdir()
    (tmp_path / f"{JOURNAL_PREFIX}x.json").write_bytes(b"{}")
    (tmp_path / f"{PUBLIC_PREFIX}x").mkdir()
    (tmp_path / f".{PUBLIC_PREFIX}x.staging").mkdir()
    (tmp_path / f".{SUPPLEMENTAL_STAGING_FRAGMENT}.1.staging").mkdir()
    (tmp_path / f".{BINDING_IDENTITY}.1.staging").mkdir()
    result = scan_forbidden_phase2_identities(tmp_path)
    assert result["forbidden_identity_count"] == 6
    assert result["hidden_entries_included"] is True
    assert result["files_and_directories_scanned"] is True
    with pytest.raises(V2AuditError, match="pre-existing"):
        require_clean_phase2_preflight(tmp_path)


def test_clean_force_inclusive_preflight_passes(tmp_path: Path) -> None:
    assert require_clean_phase2_preflight(tmp_path)["forbidden_identity_count"] == 0


def test_no_go_zero_access_status_tracks_actual_result() -> None:
    artifacts = build_no_go_artifacts(
        finding_messages=["synthetic failure"],
        checks=[{"name": "SYNTHETIC", "status": "FAIL"}],
        zero_access_ok=False,
        generated_at=NOW,
    )
    zero = json.loads(artifacts["ZERO_ACCESS_RECEIPT.json"])
    audit = json.loads(artifacts["AUDIT.json"])
    assert zero["status"] == "FAIL_ZERO_ACCESS_OR_MUTATION_OBSERVED"
    assert audit["zero_access_status"] == zero["status"]
    assert audit["verdict"] == "NO_GO"


def test_v1_no_go_mislabels_mutated_generation_boundary_as_zero_access_pass(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    namespace = runpy.run_path(
        str(
            PROJECT_ROOT
            / "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1.py"
        )
    )
    synthetic_root = tmp_path_factory.mktemp("zero")
    paths, policy, _binding, _telemetry_value, evidence = namespace["_fixture"](
        synthetic_root
    )
    forbidden = paths.outputs_root / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_"
        "r8_r6_qualification_generation_synthetic"
    )
    forbidden.mkdir()
    result = namespace["run_supplemental_audit"](
        paths=paths,
        policy=policy,
        process_probe=namespace["FakeProcessProbe"](evidence),
        clock=lambda: NOW,
    )
    zero = json.loads((result.root / "ZERO_ACCESS_RECEIPT.json").read_bytes())
    assert result.verdict == "NO_GO"
    assert zero["generation_roots_before"] == [forbidden.name]
    assert zero["status"] == "PASS_ZERO_ACCESS_AND_ZERO_MUTATION"


def test_v1_precheck_exception_exits_without_terminal_no_go(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(
        str(
            PROJECT_ROOT
            / "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1.py"
        )
    )
    synthetic_root = tmp_path / "v1_unsealed_exception"
    synthetic_root.mkdir()
    paths, policy, _binding, _telemetry_value, evidence = namespace["_fixture"](
        synthetic_root
    )

    def fail_source_identity(_project_root: Path) -> dict[str, Any]:
        raise RuntimeError("synthetic precheck failure")

    monkeypatch.setattr(v1_auditor, "_source_identity", fail_source_identity)
    with pytest.raises(RuntimeError, match="synthetic precheck failure"):
        v1_auditor.run_supplemental_audit(
            paths=paths,
            policy=policy,
            process_probe=namespace["FakeProcessProbe"](evidence),
            clock=lambda: NOW,
        )
    assert not paths.supplemental_root.exists()


def test_v1_runbook_preflight_omits_force_hidden_vault_and_journal() -> None:
    lines = (V1_FREEZE_ROOT / "OPERATOR_RUNBOOK.md").read_text(
        encoding="utf-8"
    ).splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if "Get-ChildItem -LiteralPath 'outputs' -Directory" in line
    )
    vulnerable_preflight = "\n".join(lines[start : start + 14])
    assert "-Force" not in lines[start]
    assert "qualification_vault" not in vulnerable_preflight
    assert "publication_journal" not in vulnerable_preflight


def test_terminal_no_go_is_canonical_exact_and_never_overwritten(tmp_path: Path) -> None:
    artifacts = build_no_go_artifacts(
        finding_messages=["synthetic exception"],
        checks=[],
        zero_access_ok=True,
        generated_at=NOW,
    )
    root = tmp_path / "terminal"
    digest = publish_terminal_no_go(root, artifacts)
    ledger = (root / "CHECKSUMS.sha256").read_bytes()
    assert sha256_bytes(ledger) == digest
    for name, raw in artifacts.items():
        assert (root / name).read_bytes() == raw
        assert canonical_json_bytes(json.loads(raw)) == raw
    with pytest.raises(V2AuditError, match="already exists"):
        publish_terminal_no_go(root, artifacts)


def test_every_operation_exception_becomes_canonical_sealed_no_go(
    tmp_path: Path,
) -> None:
    def fail() -> None:
        raise RuntimeError("synthetic operation failure")

    root = tmp_path / "exception_terminal"
    result = execute_or_seal_no_go(
        root=root,
        operation=fail,
        zero_access_probe=lambda: True,
    )
    assert isinstance(result, dict)
    assert result["verdict"] == "NO_GO"
    assert result["zero_access_ok"] is True
    audit_raw = (root / "AUDIT.json").read_bytes()
    assert canonical_json_bytes(json.loads(audit_raw)) == audit_raw
    assert json.loads(audit_raw)["verdict"] == "NO_GO"


def test_exact_archive_command_is_isolated_and_has_no_live_package_import(
    tmp_path: Path,
) -> None:
    python = str((tmp_path / "python.exe").resolve())
    archive = str((tmp_path / "auditor.pyz").resolve())
    command = build_frozen_archive_command(
        python_executable=python,
        python_executable_raw_sha256=H["c"],
        archive_path=archive,
        archive_raw_sha256=H["a"],
        source_records_semantic_sha256=H["b"],
    )
    validate_frozen_archive_command(
        command,
        python_executable=python,
        python_executable_raw_sha256=H["c"],
        archive_path=archive,
        archive_raw_sha256=H["a"],
        source_records_semantic_sha256=H["b"],
    )
    assert command[1:5] == ["-I", "-S", "-B", "-E"]
    assert "-m" not in command
    assert "research.model_zoo" not in " ".join(command)


def test_mutable_live_package_command_is_rejected(tmp_path: Path) -> None:
    python = str((tmp_path / "python.exe").resolve())
    archive = str((tmp_path / "auditor.pyz").resolve())
    mutable = [python, "-B", "-m", "research.model_zoo.mutable", "--audit"]
    with pytest.raises(V2AuditError, match="differs"):
        validate_frozen_archive_command(
            mutable,
            python_executable=python,
            python_executable_raw_sha256=H["c"],
            archive_path=archive,
            archive_raw_sha256=H["a"],
            source_records_semantic_sha256=H["b"],
        )


def test_r8_r6_command_lock_must_be_exact_production_disabled() -> None:
    payload = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.command_lock.v2",
        "status": "DISABLED_R8_R7_REQUIRED",
        "production_execution_allowed": False,
        "production_command": None,
        "signer_launch_allowed": False,
        "binding_freeze_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
    }
    validate_disabled_r8_r6_command_lock(payload)
    payload["production_execution_allowed"] = True
    with pytest.raises(V2AuditError, match="not exact disabled"):
        validate_disabled_r8_r6_command_lock(payload)
