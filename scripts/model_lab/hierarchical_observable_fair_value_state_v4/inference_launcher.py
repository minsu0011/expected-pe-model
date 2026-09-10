"""Stdlib-first exact runtime launcher preflight for future H-OFS V4 inference.

This score-free revision exposes only ``--check``.  The guard runs before the
H-OFS package, NumPy, or Pandas is imported.  A later separately authorized
launcher may call the frozen runner only after preserving this exact guard.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys


_PYTHON_VERSION = "3.10.19"
_PYTHON_EXECUTABLE = "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
_PYTHON_EXECUTABLE_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
_AFFINITY_MASK = 0xFFFFFFFF
_THREAD_ENVIRONMENT = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
)
_GPU_ENVIRONMENT = (("CUDA_VISIBLE_DEVICES", "-1"),)


def _current_affinity_mask() -> int:
    if os.name != "nt":
        raise RuntimeError("H-OFS V4 launcher requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessAffinityMask.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.GetProcessAffinityMask.restype = wintypes.BOOL
    process_mask = ctypes.c_size_t()
    system_mask = ctypes.c_size_t()
    if not kernel32.GetProcessAffinityMask(
        kernel32.GetCurrentProcess(),
        ctypes.byref(process_mask),
        ctypes.byref(system_mask),
    ):
        raise RuntimeError(f"GetProcessAffinityMask failed: {ctypes.get_last_error()}")
    return int(process_mask.value)


def _preimport_guard() -> dict[str, object]:
    executable = Path(sys.executable).resolve()
    observed = {
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_executable": executable.as_posix(),
        "python_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "logical_cpu_count": int(os.cpu_count() or 0),
        "affinity_mask_hex": f"0x{_current_affinity_mask():08X}",
        "thread_environment": [
            [name, os.environ.get(name, "")] for name, _ in _THREAD_ENVIRONMENT
        ],
        "gpu_environment": [
            [name, os.environ.get(name, "")] for name, _ in _GPU_ENVIRONMENT
        ],
    }
    expected = {
        "python_version": _PYTHON_VERSION,
        "python_executable": _PYTHON_EXECUTABLE,
        "python_executable_sha256": _PYTHON_EXECUTABLE_SHA256,
        "logical_cpu_count": 32,
        "affinity_mask_hex": f"0x{_AFFINITY_MASK:08X}",
        "thread_environment": [list(item) for item in _THREAD_ENVIRONMENT],
        "gpu_environment": [list(item) for item in _GPU_ENVIRONMENT],
    }
    if observed != expected:
        drifted = sorted(key for key in expected if observed[key] != expected[key])
        raise RuntimeError(f"H-OFS V4 pre-import runtime drift: {drifted}")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args()
    if not args.check:
        return 2
    preimport = _preimport_guard()

    # Import only after the stdlib guard has passed.
    from research.model_zoo.hierarchical_observable_fair_value_state_v4.runtime import (
        capture_runtime_receipt_v4,
    )

    receipt = capture_runtime_receipt_v4(purpose="PREFLIGHT")
    print(
        json.dumps(
            {
                "status": "PASS_EXACT_HOFS_V4_INFERENCE_LAUNCHER_PREFLIGHT_ONLY",
                "preimport": preimport,
                "resource_receipt_sha256": receipt.sha256(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
