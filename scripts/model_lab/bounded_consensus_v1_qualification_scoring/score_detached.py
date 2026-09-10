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

from research.model_zoo.bounded_consensus_v1 import design_lock_sha256  # noqa: E402
from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_qualification_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)
from research.model_zoo.bounded_consensus_v1_qualification_scoring import (  # noqa: E402
    load_and_verify_capability,
    score_from_capability,
)


DEFAULT_CAPABILITY = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_detached_scoring_capability_r2_20260820"
    / "EVALUATION_CAPABILITY.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_detached_scoring_r2_20260820"
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
TABLES = (
    ("POOLED_METRICS.csv", "pooled_metrics"),
    ("SEED_METRICS.csv", "seed_metrics"),
    ("LANE_METRICS.csv", "lane_metrics"),
    ("SEED_LANE_METRICS.csv", "seed_lane_metrics"),
    ("CORRELATION_DIAGNOSTICS.csv", "correlation_diagnostics"),
    ("ORACLE_DIAGNOSTICS.csv", "oracle_diagnostics"),
    ("DECISIONS.csv", "decisions"),
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
        raise RuntimeError("detached scoring runtime boundary drifted")
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


def _verify_source_manifest(capability: dict[str, Any]) -> None:
    record = capability["source_manifest"]
    path = Path(record["path"]).resolve(strict=True)
    if path.stat().st_size != int(record["bytes"]) or sha256_file(path) != record["sha256"]:
        raise RuntimeError("capability source manifest changed")
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            source = (PROJECT_ROOT / row["relative_path"]).resolve(strict=True)
            if source.stat().st_size != int(row["bytes"]) or sha256_file(source) != row["sha256"]:
                raise RuntimeError(f"scoring source changed after capability freeze: {source}")


def score(capability_path: Path, output: Path) -> dict[str, Any]:
    runtime = _runtime_receipt()
    blocked = {"heldout", "registry", "champion"}
    if blocked.intersection(part.lower() for part in output.resolve().parts):
        raise RuntimeError("scoring output crosses a blocked path boundary")
    capability_path = capability_path.resolve(strict=True)
    capability = load_and_verify_capability(capability_path)
    _verify_source_manifest(capability)
    result = score_from_capability(capability_path)
    output.mkdir(parents=True, exist_ok=False)

    artifact_records: dict[str, dict[str, Any]] = {}
    for filename, attribute in TABLES:
        path = output / filename
        getattr(result, attribute).to_csv(
            path,
            index=False,
            lineterminator="\n",
            na_rep="NaN",
            float_format="%.17g",
        )
        artifact_records[filename] = file_record(path).__dict__
    decisions = {
        str(row["bce_v1_variant_id"]): str(row["research_gate_status"])
        for row in result.decisions.to_dict(orient="records")
    }
    receipt = _seal(
        {
            "format_version": 1,
            "status": "DETACHED_QUALIFICATION_SCORING_COMPLETE",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": result.capability_sha256,
            "bounded_consensus_design_lock_sha256": design_lock_sha256(),
            "prediction_artifact": capability["prediction_artifact"],
            "truth_files_opened": [record.__dict__ for record in result.truth_file_records],
            "truth_file_count": len(result.truth_file_records),
            "heldout_files_opened": False,
            "registry_mutated": False,
            "champion_mutated": False,
            "oracle_diagnostics_used_by_gate": False,
            "decisions": decisions,
            "artifacts": artifact_records,
            "runtime": runtime,
        }
    )
    receipt_path = output / "SCORING_RECEIPT.json"
    _write_json(receipt_path, receipt)
    manifest = _seal(
        {
            "format_version": 1,
            "status": "SEALED_RESEARCH_RESULTS_ONLY",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": result.capability_sha256,
            "scoring_receipt": file_record(receipt_path).__dict__,
            "scoring_receipt_manifest_sha256": receipt["manifest_sha256"],
            "artifacts": artifact_records,
            "decisions": decisions,
            "promotion_authority": False,
            "registry_or_champion_mutation": False,
        }
    )
    manifest_path = output / "SCORING_MANIFEST.json"
    _write_json(manifest_path, manifest)
    checksum_paths = [output / filename for filename, _ in TABLES]
    checksum_paths.extend((receipt_path, manifest_path))
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output.resolve()),
        "capability_sha256": result.capability_sha256,
        "scoring_receipt_sha256": receipt["manifest_sha256"],
        "scoring_manifest_sha256": manifest["manifest_sha256"],
        "checksums_raw_sha256": sha256_file(checksum_path),
        "decisions": decisions,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability", type=Path, default=DEFAULT_CAPABILITY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(score(args.capability, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
