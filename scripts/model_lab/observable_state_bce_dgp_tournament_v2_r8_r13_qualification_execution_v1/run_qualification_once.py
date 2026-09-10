"""Consume the R8-r13 qualification identity exactly once after prelaunch GO."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
AUDIT_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_r8_r13_qualification_execution_v1_prelaunch_audit_go_20260823"
)
EVIDENCE_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_r8_r13_qualification_execution_v1_actual_once_20260823"
)
PUBLIC_RUN_ID = "20260824T000004"
PUBLIC_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r13_"
    f"qualification_generation_{PUBLIC_RUN_ID}"
)
VAULT_ROOT = PROJECT_ROOT / (
    "outputs/.model_zoo_observable_state_bce_dgp_tournament_v2_r8_r13_"
    f"qualification_vault_{PUBLIC_RUN_ID}"
)
MARKER_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r13_"
    "qualification_activation_20260823"
)
PYCACHE_CHILD = "pc_r8r13_qualification_actual_once_v1_20260823"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_new(name: str, value: object) -> None:
    raw = value if isinstance(value, bytes) else canonical(value)
    path = EVIDENCE_ROOT / name
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def verify_audit() -> tuple[dict[str, Any], str]:
    audit_raw = (AUDIT_ROOT / "PRELAUNCH_AUDIT.json").read_bytes()
    audit = json.loads(audit_raw)
    if (
        audit.get("status") != "GO_PRELAUNCH_QUALIFICATION_ONLY_P0_0_P1_0_P2_0"
        or [audit.get("P0"), audit.get("P1"), audit.get("P2")] != [0, 0, 0]
        or audit.get("heldout_authority") is not False
        or audit.get("required_grant_count") != 202
        or audit.get("source_record_count") != 14
    ):
        raise RuntimeError("prelaunch audit is not exact qualification-only GO")
    manifest_raw = (AUDIT_ROOT / "SOURCE_MANIFEST.json").read_bytes()
    manifest = json.loads(manifest_raw)
    if sha(manifest_raw) != audit["source_manifest_raw_sha256"]:
        raise RuntimeError("prelaunch source-manifest binding drifted")
    for relative, digest, size in manifest["records"]:
        raw = (PROJECT_ROOT / relative).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise RuntimeError(f"execution source changed after prelaunch audit: {relative}")
    return audit, sha(audit_raw)


def write_checksums() -> None:
    rows = []
    for path in sorted(EVIDENCE_ROOT.iterdir(), key=lambda item: item.name):
        if path.name == "CHECKSUMS.sha256" or not path.is_file():
            continue
        rows.append(f"{sha(path.read_bytes())}  {path.name}\n")
    write_new("CHECKSUMS.sha256", "".join(rows).encode("ascii"))


def main() -> int:
    sys.path.insert(0, str(PROJECT_ROOT))
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r13_qualification_execution_v1.authority import (  # noqa: E501
        DESIGN_CHECKSUMS_RAW_SHA256,
        RUNTIME_LOCK_SEMANTIC_SHA256,
        SOURCE_LOCK_RAW_SHA256,
        MemoryQualificationAuthority,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r13_qualification_execution_v1.custodian import (  # noqa: E501
        bind_held_no_bytecode_window,
        run_qualification,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r13_qualification_execution_v1.no_bytecode import (  # noqa: E501
        HeldNoBytecodeWindow,
    )

    for path in (
        EVIDENCE_ROOT,
        PUBLIC_ROOT,
        VAULT_ROOT,
        MARKER_ROOT,
        PROJECT_ROOT / "build" / PYCACHE_CHILD,
    ):
        if path.exists():
            raise RuntimeError(f"one-shot target already exists: {path}")
    audit, audit_sha = verify_audit()
    EVIDENCE_ROOT.mkdir(exist_ok=False)
    authority = MemoryQualificationAuthority(
        independent_audit_seal_raw_sha256=audit_sha
    )
    binding = authority.public_binding()
    write_new("QUALIFICATION_AUTHORITY.json", authority.authority)
    write_new("AUTHORITY_SIGNATURE.json", binding)
    write_new(
        "GENERATION_CLAIM.json",
        {
            "schema_version": "expected_pe.r8.r13.qualification_generation_claim.v1",
            "status": "CLAIMED_EXCLUSIVE_NO_RETRY",
            "public_run_id": PUBLIC_RUN_ID,
            "prelaunch_audit_raw_sha256": audit_sha,
            "prelaunch_status": audit["status"],
            "qualification_only": True,
            "heldout_authority": False,
            "required_grant_count": 202,
            "same_identity_retry_allowed": False,
        },
    )
    try:
        with HeldNoBytecodeWindow(
            parent=PROJECT_ROOT / "build",
            child_name=PYCACHE_CHILD,
            ancestry_root=PROJECT_ROOT,
        ) as window:
            with bind_held_no_bytecode_window(window):
                receipt = run_qualification(
                    authority=authority.authority,
                    activation_token=authority.activation_token,
                    public_run_id=PUBLIC_RUN_ID,
                    design_checksums_raw_sha256=DESIGN_CHECKSUMS_RAW_SHA256,
                    source_lock_raw_sha256=SOURCE_LOCK_RAW_SHA256,
                    runtime_lock_semantic_sha256=RUNTIME_LOCK_SEMANTIC_SHA256,
                    consume_grant=authority.consume,
                )
        grant_receipt = authority.final_receipt()
        write_new("GENERATION_RECEIPT.json", receipt)
        write_new("GRANT_CONSUMPTION.json", grant_receipt)
        write_new(
            "FINAL_STATUS.json",
            {
                "schema_version": "expected_pe.r8.r13.qualification_execution_status.v1",
                "status": "PASS_QUALIFICATION_COMMON_SURFACE_GENERATED_ONCE",
                "public_root_relative": PUBLIC_ROOT.relative_to(PROJECT_ROOT).as_posix(),
                "vault_root_returned": False,
                "grant_count": grant_receipt["consumed_grant_count"],
                "heldout_authority": False,
                "score_access_count": 0,
                "same_identity_retry_allowed": False,
            },
        )
        write_checksums()
        print(
            canonical(
                {
                    "status": "PASS_QUALIFICATION_COMMON_SURFACE_GENERATED_ONCE",
                    "public_root": PUBLIC_ROOT.relative_to(PROJECT_ROOT).as_posix(),
                    "grant_count": 202,
                }
            ).decode("ascii")
        )
        return 0
    except BaseException as exc:
        write_new(
            "TERMINAL_FAILURE.json",
            {
                "schema_version": "expected_pe.r8.r13.qualification_execution_failure.v1",
                "status": "TERMINAL_NO_GO_NO_RETRY",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "same_identity_retry_allowed": False,
                "heldout_authority": False,
            },
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
