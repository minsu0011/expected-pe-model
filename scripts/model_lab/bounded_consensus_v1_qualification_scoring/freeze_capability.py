from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_qualification_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)
from research.model_zoo.bounded_consensus_v1_qualification_scoring import (  # noqa: E402
    build_capability_payload,
    seal_capability,
)


DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_detached_scoring_capability_r2_20260820"
)
PINNED_LAUNCHER = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_LAUNCHER_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_BASE = Path(r"C:\Users\minsu\anaconda3\envs\myenv\python.exe")
PINNED_BASE_SHA256 = "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
EXPECTED_AFFINITY = 0xFFFFFFFF
THREAD_VARIABLES = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)
SOURCE_PATHS = (
    "research/model_zoo/bounded_consensus_v1_qualification_scoring/__init__.py",
    "research/model_zoo/bounded_consensus_v1_qualification_scoring/contracts.py",
    "research/model_zoo/bounded_consensus_v1_qualification_scoring/capability.py",
    "research/model_zoo/bounded_consensus_v1_qualification_scoring/evaluator.py",
    "research/model_zoo/bounded_consensus_v1/contracts.py",
    "research/model_zoo/bounded_consensus_v1/tail_evaluator.py",
    "research/model_zoo/bounded_consensus_v1/deterministic.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/contracts.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/custody.py",
    "scripts/model_lab/bounded_consensus_v1_qualification_scoring/freeze_capability.py",
    "scripts/model_lab/bounded_consensus_v1_qualification_scoring/score_detached.py",
)


def _process_affinity() -> int:
    process_mask = ctypes.c_size_t()
    system_mask = ctypes.c_size_t()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessAffinityMask.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.GetProcessAffinityMask.restype = ctypes.c_int
    if not kernel32.GetProcessAffinityMask(
        kernel32.GetCurrentProcess(),
        ctypes.byref(process_mask),
        ctypes.byref(system_mask),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessAffinityMask failed")
    return int(process_mask.value)


def _runtime_receipt() -> dict[str, Any]:
    launcher = Path(sys.executable).resolve(strict=True)
    base = Path(sys._base_executable).resolve(strict=True)
    wrong = {name: os.environ.get(name) for name in THREAD_VARIABLES if os.environ.get(name) != "1"}
    if (
        launcher != PINNED_LAUNCHER.resolve(strict=True)
        or base != PINNED_BASE.resolve(strict=True)
        or sha256_file(launcher) != PINNED_LAUNCHER_SHA256
        or sha256_file(base) != PINNED_BASE_SHA256
        or sys.version_info[:3] != (3, 10, 19)
        or wrong
        or os.environ.get("CUDA_VISIBLE_DEVICES") != "-1"
        or _process_affinity() != EXPECTED_AFFINITY
    ):
        raise RuntimeError("detached capability runtime boundary drifted")
    return {
        "worker_launcher": str(launcher),
        "worker_launcher_raw_sha256": PINNED_LAUNCHER_SHA256,
        "base_python": str(base),
        "base_python_raw_sha256": PINNED_BASE_SHA256,
        "python_version": "3.10.19",
        "process_affinity_hex": "0xffffffff",
        "allowed_logical_cpus": "0-31",
        "environment": {
            name: os.environ.get(name) for name in (*THREAD_VARIABLES, "CUDA_VISIBLE_DEVICES")
        },
    }


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    return {
        **unsigned,
        "manifest_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_source_manifest(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("relative_path", "bytes", "sha256"))
        writer.writeheader()
        for relative in SOURCE_PATHS:
            source = (PROJECT_ROOT / relative).resolve(strict=True)
            writer.writerow(
                {
                    "relative_path": relative,
                    "bytes": source.stat().st_size,
                    "sha256": sha256_file(source),
                }
            )


def freeze(output: Path) -> dict[str, Any]:
    runtime = _runtime_receipt()
    output.mkdir(parents=True, exist_ok=False)
    source_path = output / "SOURCE_MANIFEST.csv"
    _write_source_manifest(source_path)
    payload = build_capability_payload(PROJECT_ROOT)
    payload["source_manifest"] = file_record(source_path).__dict__
    payload["freeze_runtime"] = runtime
    capability = seal_capability(payload)
    capability_path = output / "EVALUATION_CAPABILITY.json"
    _write_json(capability_path, capability)
    preflight = _seal(
        {
            "format_version": 1,
            "status": "AUTHORIZED_DETACHED_SCORING_READY",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": capability["capability_sha256"],
            "source_manifest": file_record(source_path).__dict__,
            "truth_seed_count": capability["truth_seed_count"],
            "truth_csv_values_opened": False,
            "truth_csv_bytes_hashed": False,
            "heldout_opened": False,
            "registry_or_champion_mutated": False,
            "score_computation_executed": False,
            "freeze_runtime": runtime,
        }
    )
    preflight_path = output / "CAPABILITY_PREFLIGHT.json"
    _write_json(preflight_path, preflight)
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(
            f"{sha256_file(path)}  {path.name}\n"
            for path in (source_path, capability_path, preflight_path)
        ),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output.resolve()),
        "capability_sha256": capability["capability_sha256"],
        "capability_raw_sha256": sha256_file(capability_path),
        "preflight_sha256": preflight["manifest_sha256"],
        "source_manifest_raw_sha256": sha256_file(source_path),
        "truth_csv_values_opened": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(freeze(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
