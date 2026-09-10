"""Run score-free quality checks and atomically freeze the H-OFS V1 design."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.hierarchical_observable_fair_value_state_v1 import (  # noqa: E402
    contract_payload,
    contract_sha256,
    run_source_audit,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v1.contracts import (  # noqa: E402
    PRIOR_FAILURE_BINDINGS,
    RUNTIME_PLAN,
    STATUS,
    canonical_json_bytes,
    sealed_payload,
)


DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "model_zoo_hierarchical_observable_fair_value_state_v1_design_20260821"
)
EXPECTED_PYTHON_VERSION = "3.10.19"
EXPECTED_RUFF_VERSION = "ruff 0.12.0"
QUALITY_PATHS = (
    "research/model_zoo/hierarchical_observable_fair_value_state_v1",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v1/freeze_design.py",
    "tests/model_lab/test_hierarchical_observable_fair_value_state_v1.py",
)
PARENT_SOURCE_PATHS = (
    "research/model_zoo/observable_fair_value_state_v1/contracts.py",
    "research/model_zoo/observable_fair_value_state_v1/features.py",
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_hash(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return _sha256_bytes(raw), len(raw)


def _quality_command(arguments: list[str]) -> dict[str, Any]:
    started = time.perf_counter()
    execution_environment = dict(os.environ)
    existing_pythonpath = execution_environment.get("PYTHONPATH", "")
    source_root = str(PROJECT_ROOT / "src")
    execution_environment["PYTHONPATH"] = (
        source_root
        if not existing_pythonpath
        else source_root + os.pathsep + existing_pythonpath
    )
    completed = subprocess.run(
        arguments,
        cwd=PROJECT_ROOT,
        env=execution_environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    receipt = {
        "command": arguments,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "runtime_seconds": time.perf_counter() - started,
    }
    if completed.returncode != 0:
        raise RuntimeError(json.dumps(receipt, indent=2, ensure_ascii=True))
    return receipt


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("memory_load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def _resource_receipt() -> dict[str, Any]:
    if platform.python_version() != EXPECTED_PYTHON_VERSION:
        raise RuntimeError("design freeze requires the pinned Python 3.10.19 runtime")
    executable_hash, executable_bytes = _read_hash(Path(sys.executable).resolve(strict=True))
    cpu_ids: list[int] | None = None
    affinity_mask_hex: str | None = None
    total_gib: float | None = None
    available_gib: float | None = None
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetProcessAffinityMask.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.GetProcessAffinityMask.restype = ctypes.c_int
        kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MemoryStatus)]
        kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
        process = kernel32.GetCurrentProcess()
        process_mask = ctypes.c_size_t()
        system_mask = ctypes.c_size_t()
        if not kernel32.GetProcessAffinityMask(
            process,
            ctypes.byref(process_mask),
            ctypes.byref(system_mask),
        ):
            raise RuntimeError("GetProcessAffinityMask failed")
        mask = int(process_mask.value)
        affinity_mask_hex = f"0x{mask:X}"
        cpu_ids = [index for index in range(max(1, os.cpu_count() or 1)) if mask & (1 << index)]
        memory = _MemoryStatus()
        memory.length = ctypes.sizeof(_MemoryStatus)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            raise RuntimeError("GlobalMemoryStatusEx failed")
        total_gib = memory.total_physical / (1024**3)
        available_gib = memory.available_physical / (1024**3)
    if cpu_ids is None or len(cpu_ids) < int(RUNTIME_PLAN["max_outer_workers"]):
        raise RuntimeError("CPU affinity cannot satisfy the frozen future runtime plan")
    if total_gib is None or total_gib < 90.0:
        raise RuntimeError("physical memory cannot satisfy the frozen hardware profile")
    return {
        "status": "PASS_SCORE_FREE_RESOURCE_ATTESTATION",
        "python_version": platform.python_version(),
        "python_executable": Path(sys.executable).resolve().as_posix(),
        "python_executable_bytes": executable_bytes,
        "python_executable_sha256": executable_hash,
        "platform": platform.platform(),
        "logical_cpu_count": os.cpu_count(),
        "cpu_ids": cpu_ids,
        "affinity_mask_hex": affinity_mask_hex,
        "total_physical_memory_gib": total_gib,
        "available_physical_memory_gib": available_gib,
        "gpu_queried": False,
        "future_runtime_plan": RUNTIME_PLAN,
        "current_stage_fit_or_prediction_executed": False,
    }


def _write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    raw = canonical_json_bytes(payload) + b"\n"
    path.write_bytes(raw)
    return {"bytes": len(raw), "sha256": _sha256_bytes(raw)}


def freeze(output_dir: Path) -> dict[str, Any]:
    output = output_dir.resolve()
    staging = output.with_name(f"{output.name}.staging_{os.getpid()}")
    if output.exists() or staging.exists():
        raise RuntimeError("unique design output or staging root already exists")

    pytest_receipt = _quality_command(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v1.py",
            "-q",
        ]
    )
    ruff_executable = shutil.which("ruff")
    if ruff_executable is None:
        raise RuntimeError("ruff executable is not available")
    ruff_version_receipt = _quality_command([ruff_executable, "--version"])
    if ruff_version_receipt["stdout"].strip() != EXPECTED_RUFF_VERSION:
        raise RuntimeError("ruff version drifted from the score-free quality contract")
    ruff_receipt = _quality_command([ruff_executable, "check", *QUALITY_PATHS])
    source_audit = run_source_audit(PROJECT_ROOT)
    if not source_audit.passed:
        raise RuntimeError(f"source audit failed closed: {source_audit.payload()}")

    prior_receipts: dict[str, dict[str, Any]] = {}
    public_evidence_bytes = 0
    for key in ("structural_saturation_report", "structural_v8_design"):
        binding = dict(PRIOR_FAILURE_BINDINGS[key])
        path = (PROJECT_ROOT / str(binding["path"])).resolve(strict=True)
        observed_hash, observed_bytes = _read_hash(path)
        public_evidence_bytes += observed_bytes
        if observed_hash != binding["raw_sha256"]:
            raise RuntimeError(f"prior public evidence drifted: {key}")
        prior_receipts[key] = {
            "path": path.as_posix(),
            "bytes": observed_bytes,
            "sha256": observed_hash,
        }
    comparison = dict(PRIOR_FAILURE_BINDINGS["structural_v8_hierarchical_result"])
    comparison_path = (PROJECT_ROOT / str(comparison["comparison_path"])).resolve(strict=True)
    comparison_hash, comparison_bytes = _read_hash(comparison_path)
    public_evidence_bytes += comparison_bytes
    if comparison_hash != comparison["comparison_raw_sha256"]:
        raise RuntimeError("prior hierarchical comparison evidence drifted")
    prior_receipts["structural_v8_hierarchical_comparison"] = {
        "path": comparison_path.as_posix(),
        "bytes": comparison_bytes,
        "sha256": comparison_hash,
    }

    parent_sources: dict[str, dict[str, Any]] = {}
    parent_source_bytes = 0
    for relative in PARENT_SOURCE_PATHS:
        path = (PROJECT_ROOT / relative).resolve(strict=True)
        digest, size = _read_hash(path)
        parent_source_bytes += size
        parent_sources[relative] = {"bytes": size, "sha256": digest}

    resource = _resource_receipt()
    quality = {
        "status": "PASS_TESTS_AND_RUFF",
        "pytest": pytest_receipt,
        "ruff_version": ruff_version_receipt,
        "ruff": ruff_receipt,
        "model_fit_calls_executed": 0,
        "research_or_production_prediction_rows_generated": 0,
        "evaluation_truth_opened": False,
        "scores_computed": 0,
    }
    access = {
        "status": "PASS_SCORE_FREE_ACCESS_BOUNDARY",
        "explicit_source_audit_files_opened": source_audit.source_files_opened,
        "explicit_source_audit_bytes_read": source_audit.source_bytes_read,
        "parent_source_files_opened": len(parent_sources),
        "parent_source_bytes_read": parent_source_bytes,
        "prior_public_evidence_files_opened": len(prior_receipts),
        "prior_public_evidence_bytes_read": public_evidence_bytes,
        "truth_files_opened": 0,
        "truth_bytes_read": 0,
        "vault_files_opened": 0,
        "vault_bytes_read": 0,
        "frozen_prediction_package_files_opened": 0,
        "frozen_prediction_package_bytes_read": 0,
        "latent_auxiliary_files_opened": 0,
        "fit_calls_executed": 0,
        "research_or_production_prediction_rows_generated": 0,
        "truth_joins_executed": 0,
        "scores_computed": 0,
        "registry_or_champion_mutations": 0,
    }
    design = sealed_payload(
        {
            "schema_version": "expected_pe.hierarchical_observable_fair_value_state.v1",
            "status": STATUS,
            "created_date_kst": "2026-08-21",
            "contract_sha256": contract_sha256(),
            "contract": contract_payload(),
            "source_audit_status": source_audit.status,
            "source_sha256": source_audit.source_sha256,
            "parent_source_receipts": parent_sources,
            "prior_failure_receipts": prior_receipts,
            "quality_status": quality["status"],
            "resource_status": resource["status"],
            "access_status": access["status"],
            "next_authority_required": (
                "separate independent design audit, then separate fit/prediction authority only if "
                "fresh DGP V2 tournament terminally fails"
            ),
        }
    )
    source_payload = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v1.source_audit.v1",
            "contract_sha256": contract_sha256(),
            **source_audit.payload(),
        }
    )
    quality_payload = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v1.quality.v1",
            "contract_sha256": contract_sha256(),
            **quality,
        }
    )
    resource_payload = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v1.resource.v1",
            "contract_sha256": contract_sha256(),
            **resource,
        }
    )
    access_payload = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v1.access.v1",
            "contract_sha256": contract_sha256(),
            **access,
        }
    )

    staging.mkdir(parents=False)
    records: dict[str, dict[str, Any]] = {}
    records["DESIGN_LOCK.json"] = _write_json(staging / "DESIGN_LOCK.json", design)
    records["SOURCE_AUDIT.json"] = _write_json(staging / "SOURCE_AUDIT.json", source_payload)
    records["QUALITY_RECEIPT.json"] = _write_json(staging / "QUALITY_RECEIPT.json", quality_payload)
    records["RESOURCE_RECEIPT.json"] = _write_json(
        staging / "RESOURCE_RECEIPT.json", resource_payload
    )
    records["ACCESS_RECEIPT.json"] = _write_json(staging / "ACCESS_RECEIPT.json", access_payload)
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v1.design_manifest.v1",
            "status": STATUS,
            "contract_sha256": contract_sha256(),
            "artifacts": records,
            "fit_prediction_truth_score_registry_counts": {
                "fit": 0,
                "prediction_rows": 0,
                "truth_files": 0,
                "score": 0,
                "registry_or_champion_mutations": 0,
            },
        }
    )
    records["MANIFEST.json"] = _write_json(staging / "MANIFEST.json", manifest)
    checksum_raw = "".join(
        f"{record['sha256']}  {name}\n" for name, record in sorted(records.items())
    ).encode("ascii")
    (staging / "CHECKSUMS.sha256").write_bytes(checksum_raw)
    os.replace(staging, output)
    return {
        "output_root": output.as_posix(),
        "contract_sha256": contract_sha256(),
        "design_manifest_sha256": records["DESIGN_LOCK.json"]["sha256"],
        "manifest_raw_sha256": records["MANIFEST.json"]["sha256"],
        "checksums_raw_sha256": _sha256_bytes(checksum_raw),
        "status": STATUS,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = freeze(args.output_dir)
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
