"""Freeze the independent supplemental-auditor source, command, and runbook.

This builder never imports the production auditor entry point and refuses to
run if any real R8-r6 Phase 2 identity exists.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS = PROJECT_ROOT / "outputs"
FREEZE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v1_20260822"
)
FREEZE_ROOT = PROJECT_ROOT / FREEZE_ROOT_RELATIVE
STAGING = OUTPUTS / f".{FREEZE_ROOT.name}.staging"
BINDING_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supervised_signer_binding_20260822"
)
SUPPLEMENTAL_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
    "independent_signer_binding_supplemental_audit_r6_20260822"
)
PUBLIC_GENERATION_PREFIX = (
    "model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_qualification_generation_"
)
BYTECODE_BLACKHOLE_RELATIVE = "outputs/.expected_pe_r8_r6_bytecode_blackhole_DO_NOT_CREATE"
GENERATION_PYTHON = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
QUALITY_PYTHON = "C:/Users/minsu/anaconda3/python.exe"
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1.py"
)
RUNBOOK_RELATIVE = (
    "research/model_zoo/portfolio_governance_v1/PHASE2_R8_R6_OPERATOR_RUNBOOK.md"
)
RUNTIME_SOURCE_RELATIVES = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1/__init__.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1/auditor.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1/contracts.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1/process_probe.py",
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1/run_audit.py",
)
FREEZE_SOURCE_RELATIVES = tuple(
    sorted(
        RUNTIME_SOURCE_RELATIVES
        + (
            "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1/freeze_auditor.py",
            TEST_RELATIVE,
            RUNBOOK_RELATIVE,
        )
    )
)
EXPECTED_HASHES = {
    "design_checksums_raw_sha256": (
        "f01a459d1e9692fc034b3c08a043a177a1217c3320040d4573b72ec80c28d540"
    ),
    "external_anchor_raw_sha256": (
        "b1a320312f386546756e00a30b491c9b4c61068eca0763cc81e424a8e7cf7df2"
    ),
    "static_audit_json_raw_sha256": (
        "3ae75a182fe0e36943202f21dda3059360c3760636509c24bc95069286c3cd9d"
    ),
    "static_audit_seal_raw_sha256": (
        "2cd628400cb41e42edbdaeb2861b1734d544a14242df6b025ff33c7f7d03d9e7"
    ),
    "static_audit_checksums_raw_sha256": (
        "f8bd51db27c9a1f244418809ce8ff605026b5a7dd307754506a1dfdd33a83dc2"
    ),
    "registry_raw_sha256": (
        "36ec508fff6affeb67b343dec522610e3bec914eae3ca2542495fdce8afbb941"
    ),
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return path.is_symlink() or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def plain_source(relative: str) -> tuple[Path, bytes]:
    path = (PROJECT_ROOT / relative).resolve(strict=True)
    if PROJECT_ROOT.resolve(strict=True) not in path.parents or not path.is_file() or is_reparse(path):
        raise RuntimeError(f"source escaped or is non-plain: {relative}")
    if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
        raise RuntimeError(f"bytecode member rejected: {relative}")
    return path, path.read_bytes()


def write_new(path: Path, raw: bytes) -> str:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return sha(raw)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def generation_roots() -> list[str]:
    return sorted(
        path.name
        for path in OUTPUTS.iterdir()
        if path.is_dir() and path.name.startswith(PUBLIC_GENERATION_PREFIX)
    )


def boundary_snapshot() -> Mapping[str, Any]:
    return {
        "design_checksums_raw_sha256": sha(
            (
                PROJECT_ROOT
                / "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
                "r8_qualification_generation_static_design_r6_20260822/CHECKSUMS.sha256"
            ).read_bytes()
        ),
        "external_anchor_raw_sha256": sha(
            (
                PROJECT_ROOT
                / "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
                "r8_qualification_generation_external_anchor_r6_20260822.json"
            ).read_bytes()
        ),
        "static_audit_json_raw_sha256": sha(
            (
                PROJECT_ROOT
                / "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
                "independent_static_pre_generation_audit_r6_20260822/AUDIT.json"
            ).read_bytes()
        ),
        "static_audit_seal_raw_sha256": sha(
            (
                PROJECT_ROOT
                / "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
                "independent_static_pre_generation_audit_r6_20260822/SEAL.json"
            ).read_bytes()
        ),
        "static_audit_checksums_raw_sha256": sha(
            (
                PROJECT_ROOT
                / "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
                "independent_static_pre_generation_audit_r6_20260822/CHECKSUMS.sha256"
            ).read_bytes()
        ),
        "registry_raw_sha256": sha(
            (PROJECT_ROOT / "outputs/v04_spent_seed_registry.json").read_bytes()
        ),
        "binding_root_present": (PROJECT_ROOT / BINDING_ROOT_RELATIVE).exists(),
        "supplemental_root_present": (
            PROJECT_ROOT / SUPPLEMENTAL_ROOT_RELATIVE
        ).exists(),
        "generation_roots": generation_roots(),
        "bytecode_blackhole_present": (
            PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE
        ).exists(),
    }


def run_command(command: list[str]) -> Mapping[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str((PROJECT_ROOT / "src").resolve(strict=True))
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout_raw_sha256": sha(completed.stdout),
        "stderr_raw_sha256": sha(completed.stderr),
        "stdout_tail": completed.stdout.decode("utf-8", errors="replace")[-2_000:],
        "stderr_tail": completed.stderr.decode("utf-8", errors="replace")[-2_000:],
    }


def source_records() -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    records: list[dict[str, Any]] = []
    raw_by_relative: dict[str, bytes] = {}
    for relative in FREEZE_SOURCE_RELATIVES:
        _path, raw = plain_source(relative)
        raw_by_relative[relative] = raw
        records.append(
            {
                "relative_path": relative,
                "raw_sha256": sha(raw),
                "size_bytes": len(raw),
                "runtime_auditor_member": relative in RUNTIME_SOURCE_RELATIVES,
            }
        )
    return records, raw_by_relative


def archive_bytes(raw_by_relative: Mapping[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in sorted(raw_by_relative):
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw_by_relative[relative])
    return buffer.getvalue()


def verify_archive(
    archive_raw: bytes,
    records: list[dict[str, Any]],
) -> Mapping[str, Any]:
    expected = {record["relative_path"]: record for record in records}
    with zipfile.ZipFile(io.BytesIO(archive_raw), "r") as archive:
        names = archive.namelist()
        if names != sorted(expected) or len(names) != len(set(names)):
            raise RuntimeError("source archive universe drifted")
        for name in names:
            raw = archive.read(name)
            if (
                sha(raw) != expected[name]["raw_sha256"]
                or len(raw) != expected[name]["size_bytes"]
            ):
                raise RuntimeError(f"source archive member drifted: {name}")
    return {
        "status": "PASS_SOURCE_ARCHIVE_EXACT_REOPEN",
        "record_count": len(records),
        "member_names": sorted(expected),
        "pycache_member_count": 0,
        "pyc_member_count": 0,
    }


def main() -> int:
    if sys.argv != [sys.argv[0], "--freeze-source-command-runbook-without-phase2"]:
        return 64
    before = boundary_snapshot()
    if any(before[key] != value for key, value in EXPECTED_HASHES.items()):
        raise RuntimeError("frozen Phase 1 or registry identity drifted")
    if (
        before["binding_root_present"]
        or before["supplemental_root_present"]
        or before["generation_roots"]
        or before["bytecode_blackhole_present"]
    ):
        raise RuntimeError("real Phase 2 state exists; source freeze refused")
    if FREEZE_ROOT.exists() or STAGING.exists():
        raise RuntimeError("auditor source-freeze identity already exists")

    tests = run_command(
        [
            QUALITY_PYTHON,
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            TEST_RELATIVE,
        ]
    )
    ruff = run_command(
        [
            QUALITY_PYTHON,
            "-B",
            "-m",
            "ruff",
            "check",
            "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1",
            "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
            "r8_r6_supplemental_auditor_v1",
            TEST_RELATIVE,
        ]
    )
    if tests["returncode"] != 0 or ruff["returncode"] != 0:
        raise RuntimeError("auditor quality gate failed")

    records, raw_by_relative = source_records()
    archive_raw = archive_bytes(raw_by_relative)
    archive_reopen = verify_archive(archive_raw, records)
    runtime_records = [
        record for record in records if record["runtime_auditor_member"]
    ]
    runtime_source = b"\n".join(
        raw_by_relative[record["relative_path"]] for record in runtime_records
    )
    forbidden_runtime_tokens = (
        b"multiprocessing.connection",
        b"subprocess.Popen",
        b"secrets.token",
        b"ping_service",
        b"issue_and_activate",
    )
    if any(token in runtime_source for token in forbidden_runtime_tokens):
        raise RuntimeError("runtime auditor acquired a signer/authority execution surface")
    source_lock = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_source_lock.v1",
        "status": "FROZEN_INDEPENDENT_PUBLIC_ONLY_SOURCE",
        "record_count": len(records),
        "runtime_auditor_record_count": len(runtime_records),
        "records": records,
        "records_semantic_sha256": sha(canonical(records)),
        "source_archive_raw_sha256": sha(archive_raw),
        "source_archive_size_bytes": len(archive_raw),
    }
    production_command = [
        GENERATION_PYTHON,
        "-B",
        "-m",
        "scripts.model_lab.observable_state_bce_dgp_tournament_v2_"
        "r8_r6_supplemental_auditor_v1.run_audit",
        "--audit-live-public-binding-after-phase1-go",
    ]
    command_lock = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_command_lock.v1",
        "status": "FROZEN_NOT_EXECUTED_AWAITING_LIVE_PUBLIC_BINDING",
        "production_command": production_command,
        "working_directory": str(PROJECT_ROOT),
        "path_overrides_allowed": False,
        "signer_endpoint_contact_allowed": False,
        "signer_launch_allowed": False,
        "key_generation_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
        "truth_vault_heldout_access_allowed": False,
        "live_phase2_invocation_count": 0,
        "expected_exit_codes": {"GO": 0, "NO_GO": 2, "USAGE_REJECTED": 64},
        "input_roots": [
            BINDING_ROOT_RELATIVE,
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r8_qualification_generation_static_design_r6_20260822",
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
            "independent_static_pre_generation_audit_r6_20260822",
        ],
        "output_root": SUPPLEMENTAL_ROOT_RELATIVE,
        "phase1_and_registry_raw_pins": EXPECTED_HASHES,
        "runtime_source_records_semantic_sha256": sha(canonical(runtime_records)),
    }
    quality = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_quality.v1",
        "status": "PASS_SYNTHETIC_ONLY_NO_LIVE_PHASE2",
        "expected_test_count": 19,
        "test_scope": [
            "synthetic_positive_go",
            "binding_mutations",
            "used_error_exit_telemetry",
            "dead_signer",
            "expired_heartbeat",
            "parent_job_image_mutations",
            "atomic_no_overwrite",
            "no_execution_surface",
        ],
        "pytest": tests,
        "ruff": ruff,
        "live_signer_test_count": 0,
        "real_binding_test_count": 0,
        "authority_generation_truth_test_count": 0,
    }
    runbook_raw = raw_by_relative[RUNBOOK_RELATIVE]
    handoff = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_runbook_handoff.v1",
        "status": "FROZEN_COMMAND_DOCUMENTATION_ONLY",
        "operator_runbook_relative": RUNBOOK_RELATIVE,
        "operator_runbook_raw_sha256": sha(runbook_raw),
        "operator_runbook_size_bytes": len(runbook_raw),
        "production_command": production_command,
        "source_freeze_root_relative": FREEZE_ROOT_RELATIVE,
        "must_reopen_freeze_checksums_before_future_use": True,
        "must_not_execute_without_live_binding_and_fresh_heartbeat": True,
        "same_identity_retry_after_no_go": False,
    }
    after = boundary_snapshot()
    if before != after:
        raise RuntimeError("Phase 2/registry/Phase 1 boundary changed during source freeze")
    self_check = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_self_check.v1",
        "status": "PASS_INDEPENDENT_SOURCE_BUNDLE_REOPEN_ZERO_PHASE2",
        "archive_reopen": archive_reopen,
        "source_lock_record_count": len(records),
        "runtime_source_record_count": len(runtime_records),
        "forbidden_runtime_token_count": 0,
        "phase2_boundary_before": before,
        "phase2_boundary_after": after,
        "signer_launch_count": 0,
        "key_generation_count": 0,
        "binding_freeze_count": 0,
        "authority_issuance_count": 0,
        "generation_count": 0,
        "truth_vault_heldout_access_count": 0,
    }

    STAGING.mkdir(exist_ok=False)
    fsync_directory(STAGING.parent)
    payloads: dict[str, bytes] = {
        "COMMAND_LOCK.json": canonical(command_lock),
        "OPERATOR_RUNBOOK.md": runbook_raw,
        "QUALITY_RECEIPT.json": canonical(quality),
        "RUNBOOK_HANDOFF.json": canonical(handoff),
        "SELF_CHECK.json": canonical(self_check),
        "SOURCE_ARCHIVE.zip": archive_raw,
        "SOURCE_LOCK.json": canonical(source_lock),
    }
    hashes: dict[str, str] = {}
    for name, raw in sorted(payloads.items()):
        hashes[name] = write_new(STAGING / name, raw)
    report_raw = (
        "# R8-r6 independent supplemental auditor source freeze\n\n"
        "The public-only auditor source, production command, synthetic test receipt, and "
        "operator handoff are frozen here. No real signer, key, binding, authority, "
        "generation, truth, vault, or heldout path was executed.\n"
    ).encode("utf-8")
    hashes["REPORT.md"] = write_new(STAGING / "REPORT.md", report_raw)
    manifest_records = [
        {
            "relative_path": member.name,
            "raw_sha256": sha(member.read_bytes()),
            "size_bytes": member.stat().st_size,
        }
        for member in sorted(STAGING.iterdir(), key=lambda item: item.name)
    ]
    manifest = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_freeze_manifest.v1",
        "status": "FROZEN_INDEPENDENT_SOURCE_COMMAND_RUNBOOK_NO_PHASE2",
        "freeze_root_relative": FREEZE_ROOT_RELATIVE,
        "record_count": len(manifest_records),
        "records": manifest_records,
        "source_archive_raw_sha256": hashes["SOURCE_ARCHIVE.zip"],
        "live_phase2_invocation_count": 0,
    }
    manifest_raw = canonical(manifest)
    hashes["MANIFEST.json"] = write_new(STAGING / "MANIFEST.json", manifest_raw)
    ledger_raw = "".join(
        f"{sha(member.read_bytes())}  {member.name}\n"
        for member in sorted(STAGING.iterdir(), key=lambda item: item.name)
    ).encode("ascii")
    ledger_hash = write_new(STAGING / "CHECKSUMS.sha256", ledger_raw)
    fsync_directory(STAGING)
    os.replace(STAGING, FREEZE_ROOT)
    fsync_directory(FREEZE_ROOT.parent)
    print(
        canonical(
            {
                "status": "FROZEN_NOT_EXECUTED",
                "freeze_root_relative": FREEZE_ROOT_RELATIVE,
                "checksums_raw_sha256": ledger_hash,
                "source_archive_raw_sha256": hashes["SOURCE_ARCHIVE.zip"],
                "source_lock_raw_sha256": hashes["SOURCE_LOCK.json"],
                "command_lock_raw_sha256": hashes["COMMAND_LOCK.json"],
                "runbook_handoff_raw_sha256": hashes["RUNBOOK_HANDOFF.json"],
                "quality_receipt_raw_sha256": hashes["QUALITY_RECEIPT.json"],
                "self_check_raw_sha256": hashes["SELF_CHECK.json"],
                "live_phase2_invocation_count": 0,
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
