"""Independent mechanical prelaunch audit for the R8-r14 execution revision."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r14_"
    "qualification_execution_v1"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r14_"
    "qualification_execution_v1"
)
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r8_r14_"
    "qualification_execution_v1.py"
)
STATIC_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r8_"
    "qualification_generation_design_source_freeze_v1_no_go_20260822"
)
STATIC_AUDIT_RELATIVE = "outputs/r8r8_static_freeze_independent_postaudit_20260823/VERDICT.json"
OUTPUT_RELATIVE = (
    "outputs/model_zoo_r8_r14_qualification_execution_v1_prelaunch_audit_go_20260823"
)
RUFF = Path(r"C:\Users\minsu\anaconda3\Scripts\ruff.exe")
PYCACHE_CHILD = "pc_r8r14_prelaunch_audit_v1_20260823"


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


def _source_records() -> list[list[object]]:
    relatives = [
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in sorted((PROJECT_ROOT / PACKAGE_RELATIVE).glob("*.py"))
    ]
    relatives.extend(
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in sorted((PROJECT_ROOT / SCRIPT_RELATIVE).glob("*.py"))
    )
    relatives.append(TEST_RELATIVE)
    if len(relatives) != len(set(relatives)) or len(relatives) != 14:
        raise RuntimeError(f"source closure drifted: {len(relatives)}")
    rows: list[list[object]] = []
    for relative in sorted(relatives):
        path = (PROJECT_ROOT / relative).resolve(strict=True)
        raw = path.read_bytes()
        rows.append([relative, sha(raw), len(raw)])
    return rows


def _static_bundle() -> dict[str, Any]:
    sys.path.insert(0, str(PROJECT_ROOT))
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (  # noqa: E501
        verify_static_bundle_bytes,
    )

    root = (PROJECT_ROOT / STATIC_ROOT_RELATIVE).resolve(strict=True)
    bundle = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
    if len(bundle) != 19:
        raise RuntimeError("R8-r8 static bundle is not exactly 19 files")
    receipt = verify_static_bundle_bytes(bundle)
    verdict_raw = (PROJECT_ROOT / STATIC_AUDIT_RELATIVE).read_bytes()
    verdict = json.loads(verdict_raw)
    if (
        verdict.get("status") != "GO_STATIC_BUNDLE_AUTHENTIC_SEALED_NO_EXECUTION_AUTHORITY"
        or verdict.get("verification", {}).get("status")
        != "PASS_EXACT_19_FILE_R8_R8_STATIC_NO_AUTHORITY_BUNDLE"
    ):
        raise RuntimeError("static independent post-audit is not GO")
    return {
        "verification": receipt,
        "independent_postaudit_raw_sha256": sha(verdict_raw),
        "independent_postaudit_status": verdict["status"],
    }


def _quality() -> dict[str, Any]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }
    environment.update(
        {
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_NUM_THREADS": "1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "NUMEXPR_NUM_THREADS": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
        }
    )
    bootstrap = (
        "import sys;sys.path.insert(0,r'src');sys.path.insert(0,r'.');"
        "import pytest;raise SystemExit(pytest.main(sys.argv[1:]))"
    )
    pytest_run = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            bootstrap,
            TEST_RELATIVE,
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    ruff_run = subprocess.run(
        [
            str(RUFF),
            "check",
            PACKAGE_RELATIVE,
            SCRIPT_RELATIVE,
            TEST_RELATIVE,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    if pytest_run.returncode or ruff_run.returncode:
        raise RuntimeError(
            f"quality failed: pytest={pytest_run.stdout[-2000:]} {pytest_run.stderr[-2000:]}; "
            f"ruff={ruff_run.stdout[-2000:]} {ruff_run.stderr[-2000:]}"
        )
    return {
        "pytest_returncode": pytest_run.returncode,
        "pytest_summary": pytest_run.stdout.strip(),
        "ruff_returncode": ruff_run.returncode,
        "ruff_summary": ruff_run.stdout.strip(),
    }


def _check_only() -> dict[str, Any]:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.custodian import (  # noqa: E501
        bind_held_no_bytecode_window,
        check_only,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.no_bytecode import (  # noqa: E501
        HeldNoBytecodeWindow,
    )

    with HeldNoBytecodeWindow(
        parent=PROJECT_ROOT / "build",
        child_name=PYCACHE_CHILD,
        ancestry_root=PROJECT_ROOT,
    ) as window:
        with bind_held_no_bytecode_window(window):
            receipt = check_only()
    if (
        receipt["status"]
        != "PASS_ALL_PROCESS_ROLES_IMPORTED_CHANNELS_AND_PATHS_NO_GENERATION"
        or receipt["generator_invocation_count"] != 0
        or receipt["data_payload_open_count"] != 0
        or receipt["vault_truth_latent_open_count"] != 0
        or receipt["heldout_authority"] is not False
    ):
        raise RuntimeError("check-only receipt drifted")
    return {
        "status": receipt["status"],
        "protected_returncode": receipt["pipeline"]["protected_returncode"],
        "public_returncode": receipt["pipeline"]["public_returncode"],
        "public_finalizer_returncode": receipt["pipeline"]["public_finalizer_returncode"],
        "anonymous_one_way_pipe_used": receipt["pipeline"]["anonymous_one_way_pipe_used"],
        "generator_invocation_count": 0,
        "data_payload_open_count": 0,
        "vault_truth_latent_open_count": 0,
        "heldout_authority": False,
        "resource": receipt["resource"],
    }


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    if root.exists():
        raise RuntimeError("prelaunch audit output already exists")
    with tempfile.TemporaryDirectory(prefix="r8r14_prelaunch_audit_", dir=PROJECT_ROOT / "build") as text:
        staging = Path(text) / root.name
        staging.mkdir()
        for name, raw in files.items():
            (staging / name).write_bytes(raw)
        os.replace(staging, root)


def main() -> int:
    output = PROJECT_ROOT / OUTPUT_RELATIVE
    if output.exists() or (PROJECT_ROOT / "build" / PYCACHE_CHILD).exists():
        raise RuntimeError("prelaunch identity or pycache prefix already exists")
    rows = _source_records()
    pycache_before = [
        path.relative_to(PROJECT_ROOT).as_posix()
        for base in (PROJECT_ROOT / PACKAGE_RELATIVE, PROJECT_ROOT / SCRIPT_RELATIVE)
        for path in base.rglob("*.pyc")
    ]
    if pycache_before:
        raise RuntimeError(f"source closure contains bytecode: {pycache_before}")
    static = _static_bundle()
    quality = _quality()
    check = _check_only()
    source_manifest = {
        "schema_version": "expected_pe.r8.r14.prelaunch_source_manifest.v1",
        "status": "FROZEN_EXACT_SOURCE_CLOSURE",
        "record_count": len(rows),
        "records": rows,
        "records_semantic_sha256": sha(canonical(rows)),
    }
    audit = {
        "schema_version": "expected_pe.r8.r14.qualification_prelaunch_audit.v1",
        "status": "GO_PRELAUNCH_QUALIFICATION_ONLY_P0_0_P1_0_P2_0",
        "verdict": "GO",
        "P0": 0,
        "P1": 0,
        "P2": 0,
        "qualification_only": True,
        "heldout_authority": False,
        "production_promotion_authority": False,
        "source_manifest_raw_sha256": sha(canonical(source_manifest)),
        "source_record_count": len(rows),
        "static_bundle": static,
        "quality": quality,
        "check_only": check,
        "required_grant_count": 202,
        "generation_count_at_audit": 0,
        "fresh_truth_access_count_at_audit": 0,
        "heldout_access_count_at_audit": 0,
        "score_access_count_at_audit": 0,
        "same_identity_retry_allowed": False,
        "next_action": "ISSUE_ONCE_AND_RUN_EXACT_QUALIFICATION_AUTHORITY",
    }
    payloads = {
        "SOURCE_MANIFEST.json": canonical(source_manifest),
        "PRELAUNCH_AUDIT.json": canonical(audit),
    }
    ledger = b"".join(
        f"{sha(raw)}  {name}\n".encode("ascii") for name, raw in sorted(payloads.items())
    )
    payloads["CHECKSUMS.sha256"] = ledger
    _write_tree(output, payloads)
    print(canonical({"output": OUTPUT_RELATIVE, "status": audit["status"]}).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
