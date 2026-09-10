from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.supervision import (
    validate_supplemental_audit_go,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1 import (
    AuditPaths,
    AuditPolicy,
    ProcessEvidence,
    run_supplemental_audit,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1.contracts import (
    BINDING_RELATIVE,
    DESIGN_ROOT_RELATIVE,
    SERVICE_SOURCE_RELATIVE,
    STATIC_AUDIT_ROOT_RELATIVE,
    SUPERVISOR_SOURCE_RELATIVE,
    TELEMETRY_RELATIVE,
    canonical_json_bytes,
    sha256_bytes,
)


NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
SERVICE_HASH = "1" * 64
SUPERVISOR_HASH = "2" * 64
EXECUTABLE_HASH = "3" * 64


class FakeProcessProbe:
    def __init__(self, evidence: ProcessEvidence) -> None:
        self.evidence = evidence
        self.calls = 0

    def probe(self, *, signer_pid: int, supervisor_pid: int) -> ProcessEvidence:
        self.calls += 1
        assert signer_pid == self.evidence.signer_pid
        assert supervisor_pid == self.evidence.supervisor_pid
        return self.evidence


def _write_json(path: Path, payload: Any) -> bytes:
    raw = canonical_json_bytes(payload)
    path.write_bytes(raw)
    return raw


def _write_ledger(root: Path) -> bytes:
    rows = [
        f"{sha256_bytes(member.read_bytes())}  {member.name}\n"
        for member in sorted(root.iterdir(), key=lambda item: item.name)
        if member.name != "CHECKSUMS.sha256"
    ]
    raw = "".join(rows).encode("ascii")
    (root / "CHECKSUMS.sha256").write_bytes(raw)
    return raw


def _fixture(tmp_path: Path) -> tuple[
    AuditPaths,
    AuditPolicy,
    dict[str, Any],
    dict[str, Any],
    ProcessEvidence,
]:
    paths = AuditPaths(project_root=tmp_path)
    paths.outputs_root.mkdir()

    design = paths.design_root
    design.mkdir()
    _write_json(
        design / "SOURCE_LOCK.json",
        {
            "schema_version": "synthetic.source.lock.v1",
            "records": [
                {
                    "relative_path": SERVICE_SOURCE_RELATIVE,
                    "raw_sha256": SERVICE_HASH,
                    "size_bytes": 1,
                },
                {
                    "relative_path": SUPERVISOR_SOURCE_RELATIVE,
                    "raw_sha256": SUPERVISOR_HASH,
                    "size_bytes": 1,
                },
            ],
        },
    )
    _write_json(
        design / "STATIC_SUPERVISION_CONTRACT.json",
        {
            "schema_version": "synthetic.supervision.v1",
            "process_model": {
                "detached_process": False,
                "foreground_supervised": True,
                "parent_supervised": True,
                "private_key_persisted": False,
                "private_seed_transport": "INHERITED_ANONYMOUS_STDIN_ONLY",
                "windows_job_kill_on_parent_close": True,
            },
        },
    )
    _write_json(design / "DESIGN_LOCK.json", {"status": "SYNTHETIC_PHASE1"})
    design_ledger = _write_ledger(design)
    design_hash = sha256_bytes(design_ledger)

    anchor_raw = _write_json(paths.anchor, {"status": "SYNTHETIC_ANCHOR"})
    anchor_hash = sha256_bytes(anchor_raw)

    static_root = paths.static_audit_root
    static_root.mkdir()
    static_audit_raw = _write_json(
        static_root / "AUDIT.json",
        {
            "schema_version": "expected_pe.r8.r6.independent_static_audit.v1",
            "verdict": "GO",
            "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
            "audit_root_relative": STATIC_AUDIT_ROOT_RELATIVE,
            "design_root_relative": DESIGN_ROOT_RELATIVE,
            "design_checksums_raw_sha256": design_hash,
            "external_anchor_raw_sha256": anchor_hash,
            "signer_launch_authorized": True,
            "qualification_generation_authorized": False,
            "heldout_generation_authorized": False,
            "truth_access_count": 0,
            "generation_count": 0,
            "signature_count": 0,
        },
    )
    static_seal_raw = _write_json(
        static_root / "SEAL.json",
        {
            "schema_version": "synthetic.static.seal.v1",
            "audit_json_raw_sha256": sha256_bytes(static_audit_raw),
        },
    )
    static_ledger = _write_ledger(static_root)

    registry_raw = _write_json(
        paths.registry,
        {"format_version": 1, "registry_type": "spent_seed", "entries": []},
    )
    policy = AuditPolicy(
        design_checksums_raw_sha256=design_hash,
        external_anchor_raw_sha256=anchor_hash,
        static_audit_json_raw_sha256=sha256_bytes(static_audit_raw),
        static_audit_seal_raw_sha256=sha256_bytes(static_seal_raw),
        static_audit_checksums_raw_sha256=sha256_bytes(static_ledger),
        registry_raw_sha256=sha256_bytes(registry_raw),
    )

    launched = NOW - timedelta(seconds=60)
    expires = launched + timedelta(seconds=900)
    public_key_hex = "00" * 32
    key_id = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
    binding = {
        "schema_version": "expected_pe.r8.r6.signer.binding.v1",
        "binding_root_relative": str(Path(BINDING_RELATIVE).parent).replace("\\", "/"),
        "binding_relative": BINDING_RELATIVE,
        "telemetry_relative": TELEMETRY_RELATIVE,
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "design_checksums_raw_sha256": design_hash,
        "external_anchor_raw_sha256": anchor_hash,
        "static_audit_root_relative": STATIC_AUDIT_ROOT_RELATIVE,
        "static_audit_json_raw_sha256": sha256_bytes(static_audit_raw),
        "static_audit_seal_raw_sha256": sha256_bytes(static_seal_raw),
        "service_source_relative": SERVICE_SOURCE_RELATIVE,
        "service_source_raw_sha256": SERVICE_HASH,
        "service_executable_raw_sha256": EXECUTABLE_HASH,
        "public_key_hex": public_key_hex,
        "key_id": key_id,
        "readiness_raw_sha256": "4" * 64,
        "endpoint": rf"\\.\pipe\expected_pe_r8_r6_{key_id[:40]}",
        "launch_nonce_sha256": "5" * 64,
        "signer_pid": 41002,
        "supervisor_pid": 41001,
        "launched_at_utc": launched.isoformat(),
        "expires_at_utc": expires.isoformat(),
        "heartbeat_interval_seconds": 1,
        "maximum_heartbeat_age_seconds": 5,
        "maximum_lifetime_seconds": 900,
        "private_key_persisted": False,
        "foreground_supervised": True,
        "parent_supervised": True,
        "detached_process": False,
        "maximum_signature_count": 1,
        "maximum_generation_count": 1,
    }
    paths.binding_root.mkdir()
    _write_json(paths.binding, binding)
    telemetry = {
        "schema_version": "expected_pe.r8.r6.signer.telemetry.v1",
        "state": "READY",
        "supervisor_pid": binding["supervisor_pid"],
        "signer_pid": binding["signer_pid"],
        "started_at_utc": binding["launched_at_utc"],
        "last_heartbeat_utc": (NOW - timedelta(seconds=1)).isoformat(),
        "observed_at_utc": NOW.isoformat(),
        "heartbeat_sequence": 61,
        "exit_status": None,
        "error_code": None,
        "request_count": 0,
        "signature_count": 0,
        "private_key_persisted": False,
        "detached_process": False,
        "parent_supervised": True,
        "foreground_supervised": True,
    }
    _write_json(paths.telemetry, telemetry)
    evidence = ProcessEvidence(
        signer_pid=binding["signer_pid"],
        supervisor_pid=binding["supervisor_pid"],
        signer_alive=True,
        supervisor_alive=True,
        signer_parent_pid=binding["supervisor_pid"],
        signer_in_job=True,
        signer_image_path="C:/synthetic/python.exe",
        supervisor_image_path="C:/synthetic/python.exe",
        signer_image_raw_sha256=EXECUTABLE_HASH,
        supervisor_image_raw_sha256=EXECUTABLE_HASH,
        probe_platform="synthetic_query_only",
    )
    return paths, policy, binding, telemetry, evidence


def _assert_exact_ledger(root: Path) -> None:
    rows = (root / "CHECKSUMS.sha256").read_text(encoding="ascii").splitlines()
    names: list[str] = []
    for row in rows:
        digest, name = row[:64], row[66:]
        assert row[64:66] == "  "
        assert sha256_bytes((root / name).read_bytes()) == digest
        names.append(name)
    assert names == sorted(
        item.name for item in root.iterdir() if item.name != "CHECKSUMS.sha256"
    )


def test_synthetic_live_public_binding_emits_exact_go(tmp_path: Path) -> None:
    paths, policy, _binding, _telemetry, evidence = _fixture(tmp_path)
    probe = FakeProcessProbe(evidence)
    result = run_supplemental_audit(
        paths=paths, policy=policy, process_probe=probe, clock=lambda: NOW
    )
    assert result.verdict == "GO"
    assert result.finding_counts == {"P0": 0, "P1": 0, "P2": 0}
    assert probe.calls == 1
    assert result.root.is_dir()
    assert not list(paths.outputs_root.glob(f".{result.root.name}.*.staging"))
    _assert_exact_ledger(result.root)

    audit_raw = (result.root / "AUDIT.json").read_bytes()
    audit = json.loads(audit_raw)
    assert canonical_json_bytes(audit) == audit_raw
    binding_raw = paths.binding.read_bytes()
    validate_supplemental_audit_go(
        audit,
        design_checksums_raw_sha256=policy.design_checksums_raw_sha256,
        binding_raw_sha256=sha256_bytes(binding_raw),
    )
    assert audit["status"] == "SEALED_INDEPENDENT_GO"
    assert audit["qualification_generation_authorized"] is False
    zero = json.loads((result.root / "ZERO_ACCESS_RECEIPT.json").read_bytes())
    assert zero["status"] == "PASS_ZERO_ACCESS_AND_ZERO_MUTATION"
    assert zero["generation_roots_before"] == zero["generation_roots_after"] == []
    assert all(
        zero[key] == 0
        for key in (
            "authority_issuance_count",
            "generation_count",
            "heldout_access_count",
            "model_fit_count",
            "prediction_count",
            "registry_mutation_count",
            "score_count",
            "signature_count",
            "truth_vault_latent_open_count",
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint", r"\\.\pipe\substituted"),
        ("detached_process", True),
        ("static_audit_json_raw_sha256", "a" * 64),
        ("maximum_signature_count", 2),
    ],
)
def test_binding_mutations_are_terminal_no_go(
    tmp_path: Path, field: str, value: Any
) -> None:
    paths, policy, binding, _telemetry, evidence = _fixture(tmp_path)
    binding[field] = value
    _write_json(paths.binding, binding)
    result = run_supplemental_audit(
        paths=paths,
        policy=policy,
        process_probe=FakeProcessProbe(evidence),
        clock=lambda: NOW,
    )
    assert result.verdict == "NO_GO"
    assert result.finding_counts["P1"] >= 1
    audit = json.loads((result.root / "AUDIT.json").read_bytes())
    assert audit["alive_recheck_authorized"] is False
    assert audit["qualification_authority_issuance_authorized"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        {"request_count": 1},
        {"request_count": 1, "signature_count": 1},
        {"error_code": "SYNTHETIC"},
        {"exit_status": 0},
        {"state": "EXITED"},
        {"parent_supervised": False},
    ],
)
def test_used_error_exit_and_supervision_telemetry_rejected(
    tmp_path: Path, mutation: dict[str, Any]
) -> None:
    paths, policy, _binding, telemetry, evidence = _fixture(tmp_path)
    telemetry.update(mutation)
    _write_json(paths.telemetry, telemetry)
    result = run_supplemental_audit(
        paths=paths,
        policy=policy,
        process_probe=FakeProcessProbe(evidence),
        clock=lambda: NOW,
    )
    assert result.verdict == "NO_GO"
    assert result.finding_counts["P0"] >= 1


def test_dead_signer_is_terminal_no_go(tmp_path: Path) -> None:
    paths, policy, _binding, _telemetry, evidence = _fixture(tmp_path)
    dead = replace(evidence, signer_alive=False)
    result = run_supplemental_audit(
        paths=paths,
        policy=policy,
        process_probe=FakeProcessProbe(dead),
        clock=lambda: NOW,
    )
    assert result.verdict == "NO_GO"
    assert result.finding_counts["P0"] >= 1


@pytest.mark.parametrize(
    "mutation",
    [
        {"signer_parent_pid": 99999},
        {"signer_in_job": False},
        {"supervisor_alive": False},
        {"signer_image_raw_sha256": "6" * 64},
    ],
)
def test_parent_job_image_mutations_are_no_go(
    tmp_path: Path, mutation: dict[str, Any]
) -> None:
    paths, policy, _binding, _telemetry, evidence = _fixture(tmp_path)
    changed = replace(evidence, **mutation)
    result = run_supplemental_audit(
        paths=paths,
        policy=policy,
        process_probe=FakeProcessProbe(changed),
        clock=lambda: NOW,
    )
    assert result.verdict == "NO_GO"
    assert result.finding_counts["P0"] >= 1


def test_expired_heartbeat_is_terminal_no_go(tmp_path: Path) -> None:
    paths, policy, _binding, telemetry, evidence = _fixture(tmp_path)
    telemetry["last_heartbeat_utc"] = (NOW - timedelta(seconds=6)).isoformat()
    _write_json(paths.telemetry, telemetry)
    result = run_supplemental_audit(
        paths=paths,
        policy=policy,
        process_probe=FakeProcessProbe(evidence),
        clock=lambda: NOW,
    )
    assert result.verdict == "NO_GO"
    findings = json.loads((result.root / "FINDINGS.json").read_bytes())
    assert any("heartbeat expired" in item["message"] for item in findings["findings"])


def test_existing_supplemental_identity_is_never_overwritten(tmp_path: Path) -> None:
    paths, policy, _binding, _telemetry, evidence = _fixture(tmp_path)
    paths.supplemental_root.mkdir()
    marker = paths.supplemental_root / "PRESERVE.txt"
    marker.write_text("immutable", encoding="utf-8")
    with pytest.raises(Exception, match="already exists"):
        run_supplemental_audit(
            paths=paths,
            policy=policy,
            process_probe=FakeProcessProbe(evidence),
            clock=lambda: NOW,
        )
    assert marker.read_text(encoding="utf-8") == "immutable"


def test_auditor_source_has_no_signer_or_authority_execution_surface() -> None:
    root = Path(__file__).resolve().parents[2]
    package = root / (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
        "r8_r6_supplemental_auditor_v1"
    )
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(package.glob("*.py"))
    )
    assert "multiprocessing.connection" not in source
    assert "subprocess.Popen" not in source
    assert "secrets.token" not in source
    assert "issue_and_activate" not in source
    assert "ping_service" not in source
