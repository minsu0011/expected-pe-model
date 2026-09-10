"""Seal the fail-closed first v2 source-freeze attempt as immutable evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
FAILED_FREEZE_NAME = (
    "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v2_no_go_20260822"
)
RECEIPT_NAME = (
    "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_independent_"
    "supplemental_auditor_source_freeze_v2_attempt_r1_failure_receipt_20260822"
)
RECEIPT_ROOT = OUTPUTS_ROOT / RECEIPT_NAME
EXPECTED_SOURCES = {
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/__init__.py": "7e04a74af3aaa8b1203f52dd1104b9d54367ac52e173735dbf5529ddc4179944",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/archive_entry.py": "dc8e1a0c2e8f96fff1a49c9ecf95f7d32bbdff8f6fe72ee1389f0132225941d4",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/canonical.py": "7dc28061734c99d9c258552058355d6de5d4205193c048d8fad992ae5ada2ac9",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/command_lock.py": "8f3c37e8c7622b9bc164c2f86e92b6ea388705e4618cdd81567693a5966d3d7c",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/compatibility.py": "7635da4c17d3b7f4608fd15981c45b2d88912e627ed57e80f1cc0b1eec85272d",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/hardened_fs.py": "176843c1340a85bd0b971169e846be94ade8048c38d22ee50f91c0592322aff6",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/preflight.py": "2dc64ad03d969680f7782b9910b1b1294ea75a49cd6b503f3f230507a83175b3",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/source_identity.py": "08eacda83fffd3ad533797abb2a926b1c29dcaaead51f8ea39c6dcf610c5e9de",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/terminal.py": "2a3baba9eb90bbbb5e66b6867db11955e70c6503cf046603af55a29e99aaf509",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/validation.py": "e359f83262a7a795cf1e2e78f9d3fd874b1c2c46df42f19856835dc1527df23d",
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/archive_main.py": "abdc585f2ef77354f9e475f4e9fd524c2cf02251be3ae0991ca8652026ab66d5",
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2/freeze_auditor.py": "c9770b43cad40109a0bc5e67ea4dfbc70d41c56cdf631e56dde7cf2d91851a35",
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.py": "4cfbc063f421b036cf476bf85f7912bd091af9d0aa390e10ca8f2bc91b6932c2",
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


def write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    if sys.argv != [sys.argv[0], "--seal-exact-r1-failure-before-r2"]:
        return 64
    if RECEIPT_ROOT.exists():
        raise RuntimeError("r1 failure receipt identity already exists")
    failed_root = OUTPUTS_ROOT / FAILED_FREEZE_NAME
    failed_staging = sorted(
        item.name
        for item in OUTPUTS_ROOT.iterdir()
        if item.name.startswith(f".{FAILED_FREEZE_NAME}.")
        and item.name.endswith(".staging")
    )
    if failed_root.exists() or failed_staging:
        raise RuntimeError("failed r1 unexpectedly left a freeze root or staging identity")

    records: list[dict[str, Any]] = []
    for relative, expected in sorted(EXPECTED_SOURCES.items()):
        raw = (PROJECT_ROOT / relative).read_bytes()
        if sha(raw) != expected:
            raise RuntimeError(f"failed r1 source identity drifted: {relative}")
        records.append(
            {
                "relative_path": relative,
                "raw_sha256": expected,
                "size_bytes": len(raw),
            }
        )
    source_lock = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_failure_source.v2",
        "status": "EXACT_FAILED_R1_SOURCE_IDENTITY",
        "record_count": len(records),
        "records": records,
        "records_semantic_sha256": sha(canonical(records)),
    }
    attempted_command = [
        "C:/Users/minsu/anaconda3/python.exe",
        "-B",
        "-m",
        "scripts.model_lab.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.freeze_auditor",
        "--freeze-production-disabled-v2-source-after-no-go-review",
    ]
    command = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_command.v2",
        "status": "FAILED_R1_COMMAND_CAPTURED",
        "argv": attempted_command,
        "argv_semantic_sha256": sha(canonical(attempted_command)),
        "working_directory": str(PROJECT_ROOT),
        "pythonpath": "src",
        "isolated_source_freeze_attempt": True,
        "production_phase2_command": False,
    }
    failure = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_failure.v2",
        "status": "FAIL_CLOSED_BEFORE_PUBLICATION",
        "attempt_id": "SOURCE_FREEZE_V2_ATTEMPT_R1",
        "exception_class": "V2AuditError",
        "exception_message": "path/file-handle identity differed after read",
        "tracepoint": (
            "freeze_auditor.py:774 read_stable_plain_file; "
            "hardened_fs.py:127 path/file-handle identity comparison"
        ),
        "diagnosis": (
            "Windows lstat mode 33279 and open-handle fstat mode 33206 differ "
            "for the pinned Python executable while volume, file ID, size, and mtime agree."
        ),
        "pathname_snapshot": {
            "volume_serial_or_device": 13325047249941796650,
            "file_id_or_inode": 1688849861577655,
            "mode_diagnostic": 33279,
            "size_bytes": 272712,
            "mtime_ns_diagnostic": 1787081228890646800,
            "reparse_tag": 0,
        },
        "open_handle_snapshot": {
            "volume_serial_or_device": 13325047249941796650,
            "file_id_or_inode": 1688849861577655,
            "mode_diagnostic": 33206,
            "size_bytes": 272712,
            "mtime_ns_diagnostic": 1787081228890646800,
            "reparse_tag": 0,
        },
        "failed_freeze_root_present_after_attempt": False,
        "failed_freeze_staging_identity_count_after_attempt": 0,
        "same_attempt_identity_retry_authorized": False,
        "required_next_attempt": "ISOLATED_SOURCE_FREEZE_ATTEMPT_R2_WITH_NEW_SOURCE_AND_COMMAND_HASHES",
    }
    zero_state = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_zero_state.v2",
        "status": "PASS_ZERO_PHASE2_ACCESS_AND_ZERO_PUBLICATION",
        "source_freeze_publication_count": 0,
        "signer_launch_count": 0,
        "binding_freeze_count": 0,
        "production_supplemental_audit_count": 0,
        "self_go_audit_count": 0,
        "signer_endpoint_contact_count": 0,
        "authority_issuance_count": 0,
        "qualification_generation_count": 0,
        "fresh_truth_heldout_access_count": 0,
        "failed_freeze_root_present": False,
        "failed_freeze_staging_identity_count": 0,
    }
    builder_raw = Path(__file__).read_bytes()
    audit = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_audit.v2",
        "status": "SEALED_SOURCE_FREEZE_ATTEMPT_R1_FAILURE_NO_GO",
        "verdict": "NO_GO",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "attempt_id": "SOURCE_FREEZE_V2_ATTEMPT_R1",
        "finding_counts": {"P0": 1, "P1": 0, "P2": 0},
        "failed_source_records_semantic_sha256": source_lock[
            "records_semantic_sha256"
        ],
        "failed_command_argv_semantic_sha256": command["argv_semantic_sha256"],
        "receipt_builder_relative": Path(__file__).relative_to(PROJECT_ROOT).as_posix(),
        "receipt_builder_raw_sha256": sha(builder_raw),
        "phase2_signer_launch_authorized": False,
        "phase2_authority_issuance_authorized": False,
        "phase2_generation_authorized": False,
        "r1_retry_authorized": False,
    }
    report = (
        "# Supplemental auditor v2 source-freeze attempt r1 failure\n\n"
        "Verdict: **NO_GO**. The first source-freeze attempt failed closed before "
        "creating a staging or final freeze root because Windows pathname and handle "
        "mode diagnostics differed. No signer, binding, production audit, endpoint, "
        "authority, generation, fresh truth, or heldout state was accessed. The r1 "
        "identity is not retried; only a new isolated r2 source identity may proceed.\n"
    ).encode("utf-8")
    artifacts = {
        "AUDIT.json": canonical(audit),
        "COMMAND.json": canonical(command),
        "FAILURE.json": canonical(failure),
        "REPORT.md": report,
        "SOURCE_LOCK.json": canonical(source_lock),
        "ZERO_STATE.json": canonical(zero_state),
    }
    seal = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_attempt_seal.v2",
        "status": "SEALED_IMMUTABLE_R1_FAILURE_NO_GO",
        "verdict": "NO_GO",
        "finding_counts": {"P0": 1, "P1": 0, "P2": 0},
        "file_records": [
            {
                "relative_path": name,
                "raw_sha256": sha(raw),
                "size_bytes": len(raw),
            }
            for name, raw in sorted(artifacts.items())
        ],
    }
    artifacts["SEAL.json"] = canonical(seal)
    staging = OUTPUTS_ROOT / f".{RECEIPT_NAME}.{os.getpid()}.staging"
    if staging.exists():
        raise RuntimeError("r1 failure receipt staging identity already exists")
    staging.mkdir(parents=False, exist_ok=False)
    for name, raw in sorted(artifacts.items()):
        write_new(staging / name, raw)
    ledger = "".join(
        f"{sha(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("ascii")
    write_new(staging / "CHECKSUMS.sha256", ledger)
    os.replace(staging, RECEIPT_ROOT)
    if any((RECEIPT_ROOT / name).read_bytes() != raw for name, raw in artifacts.items()):
        raise RuntimeError("r1 failure receipt reopen drifted")
    result = {
        "status": "SEALED_SOURCE_FREEZE_ATTEMPT_R1_FAILURE_NO_GO",
        "root": str(RECEIPT_ROOT),
        "checksums_raw_sha256": sha(ledger),
        "source_records_semantic_sha256": source_lock["records_semantic_sha256"],
        "command_argv_semantic_sha256": command["argv_semantic_sha256"],
        "signer_launch_count": 0,
        "source_freeze_publication_count": 0,
    }
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
