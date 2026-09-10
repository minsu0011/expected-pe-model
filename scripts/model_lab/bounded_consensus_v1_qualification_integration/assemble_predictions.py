from __future__ import annotations

import argparse
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
from research.model_zoo.bounded_consensus_v1_qualification_integration import (  # noqa: E402
    assemble_bound_qualification_predictions,
    bind_qualification_inputs,
    integration_design_sha256,
)
from research.model_zoo.bounded_consensus_v1_qualification_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)


DEFAULT_PREFLIGHT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_integration_score_free_preflight_r3_py310_20260820"
    / "PREFLIGHT.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_prediction_only_r3_py310_20260820"
)
PINNED_LAUNCHER = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_LAUNCHER_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_BASE_PYTHON = Path(r"C:\Users\minsu\anaconda3\envs\myenv\python.exe")
PINNED_BASE_PYTHON_SHA256 = (
    "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
)
EXPECTED_PROCESS_AFFINITY = 0xFFFFFFFF
THREAD_VARIABLES = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    return {
        **unsigned,
        "manifest_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _load_preflight(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("preflight root must be an object")
    seal = str(payload.get("manifest_sha256", ""))
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != seal:
        raise RuntimeError("preflight self-seal changed")
    if payload.get("status") != "READY_PREDICTION_ONLY":
        raise RuntimeError("preflight is not prediction-ready")
    if payload.get("integration_design_sha256") != integration_design_sha256():
        raise RuntimeError("preflight integration hash changed")
    if payload.get("actions", {}).get("truth_files_opened") is not False:
        raise RuntimeError("preflight truth boundary changed")
    return payload, hashlib.sha256(raw).hexdigest()


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
    process = kernel32.GetCurrentProcess()
    if not kernel32.GetProcessAffinityMask(
        process,
        ctypes.byref(process_mask),
        ctypes.byref(system_mask),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessAffinityMask failed")
    return int(process_mask.value)


def _validate_runtime_and_output(output: Path) -> None:
    launcher = Path(sys.executable).resolve(strict=True)
    base = Path(sys._base_executable).resolve(strict=True)
    if launcher != PINNED_LAUNCHER.resolve(strict=True):
        raise RuntimeError(f"launcher requires pinned V5 worker launcher: {PINNED_LAUNCHER}")
    if base != PINNED_BASE_PYTHON.resolve(strict=True):
        raise RuntimeError(f"launcher requires pinned py310 base: {PINNED_BASE_PYTHON}")
    if (
        sys.version_info[:3] != (3, 10, 19)
        or sha256_file(launcher) != PINNED_LAUNCHER_SHA256
        or sha256_file(base) != PINNED_BASE_PYTHON_SHA256
    ):
        raise RuntimeError("pinned V5 launcher/base version or executable hash drifted")
    wrong = {name: os.environ.get(name) for name in THREAD_VARIABLES if os.environ.get(name) != "1"}
    if wrong:
        raise RuntimeError(f"native thread variables must all equal 1: {wrong}")
    if os.environ.get("CUDA_VISIBLE_DEVICES") != "-1":
        raise RuntimeError("CUDA_VISIBLE_DEVICES must equal -1 for prediction-only assembly")
    if _process_affinity() != EXPECTED_PROCESS_AFFINITY:
        raise RuntimeError("process affinity must be the exact CPU0-31 mask")
    blocked = {"heldout", "truth", "evaluation", "score"}
    parts = {part.lower() for part in output.resolve().parts}
    if blocked.intersection(parts):
        raise RuntimeError("prediction output path crosses a blocked custody boundary")


def assemble(preflight_path: Path, output: Path) -> dict[str, Any]:
    _validate_runtime_and_output(output)
    preflight, preflight_raw_sha = _load_preflight(preflight_path.resolve(strict=True))
    output.mkdir(parents=True, exist_ok=False)
    closure = bind_qualification_inputs(PROJECT_ROOT)
    closure_payload = closure.to_payload()
    closure_sha256 = hashlib.sha256(canonical_json_bytes(closure_payload)).hexdigest()
    if closure_sha256 != preflight.get("input_closure_sha256"):
        raise RuntimeError("live input closure differs from approved preflight closure")
    result = assemble_bound_qualification_predictions(closure)

    prediction_path = output / "PREDICTIONS.csv"
    result.predictions.to_csv(
        prediction_path,
        index=False,
        lineterminator="\n",
        na_rep="NaN",
        float_format="%.17g",
    )
    geometry_path = output / "SEED_GEOMETRY.json"
    geometry_payload = _seal(
        {
            "format_version": 1,
            "integration_design_sha256": integration_design_sha256(),
            "seeds": [audit.__dict__ for audit in result.seed_audits],
        }
    )
    geometry_path.write_text(
        json.dumps(geometry_payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    runtime_receipt = _seal(
        {
            "format_version": 1,
            "status": "PINNED_PREDICTION_RUNTIME_VERIFIED",
            "integration_design_sha256": integration_design_sha256(),
            "input_closure_sha256": closure_sha256,
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "preflight_raw_sha256": preflight_raw_sha,
            "worker_launcher": str(Path(sys.executable).resolve(strict=True)),
            "worker_launcher_raw_sha256": sha256_file(Path(sys.executable)),
            "base_python_executable": str(Path(sys._base_executable).resolve(strict=True)),
            "base_python_executable_raw_sha256": sha256_file(Path(sys._base_executable)),
            "python_version": ".".join(str(value) for value in sys.version_info[:3]),
            "python_version_full": sys.version,
            "process_affinity_decimal": _process_affinity(),
            "process_affinity_hex": f"0x{_process_affinity():08x}",
            "allowed_logical_cpus": "0-31",
            "environment": {
                name: os.environ.get(name)
                for name in (*THREAD_VARIABLES, "CUDA_VISIBLE_DEVICES")
            },
            "prediction_artifact": file_record(prediction_path).__dict__,
            "seed_geometry_artifact": file_record(geometry_path).__dict__,
            "truth_files_opened": False,
            "heldout_files_opened": False,
            "evaluation_executed": False,
            "scores_computed": False,
        }
    )
    runtime_path = output / "RUNTIME_RECEIPT.json"
    runtime_path.write_text(
        json.dumps(runtime_receipt, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest = _seal(
        {
            "format_version": 1,
            "status": "PREDICTION_ONLY_COMPLETE",
            "integration_design_sha256": integration_design_sha256(),
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "preflight_raw_sha256": preflight_raw_sha,
            "prediction_artifact": file_record(prediction_path).__dict__,
            "seed_geometry_artifact": file_record(geometry_path).__dict__,
            "runtime_receipt": file_record(runtime_path).__dict__,
            "runtime_receipt_manifest_sha256": runtime_receipt["manifest_sha256"],
            "input_closure_sha256": closure_sha256,
            "rows": len(result.predictions),
            "variant_ids": list(result.variant_ids),
            "truth_files_opened": False,
            "heldout_files_opened": False,
            "scores_computed": False,
            "promotion_authority": False,
        }
    )
    manifest_path = output / "PREDICTION_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(
            f"{sha256_file(path)}  {path.name}\n"
            for path in (prediction_path, geometry_path, runtime_path, manifest_path)
        ),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output.resolve()),
        "prediction_raw_sha256": sha256_file(prediction_path),
        "manifest_sha256": manifest["manifest_sha256"],
        "rows": len(result.predictions),
        "scores_computed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", type=Path, default=DEFAULT_PREFLIGHT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(assemble(args.preflight, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
