"""Score-free pinned worker for measuring safe R8 outer concurrency."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time


EXACT_ENVIRONMENT = {
    "CUDA_VISIBLE_DEVICES": "-1",
    "MKL_NUM_THREADS": "1",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "NUMEXPR_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
}


class ProcessMemoryCountersEx(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def set_affinity(cpu_ids: tuple[int, ...]) -> int:
    mask = sum(1 << cpu for cpu in cpu_ids)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    kernel32.GetProcessAffinityMask.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.GetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(kernel32.GetCurrentProcess(), mask):
        raise RuntimeError("benchmark SetProcessAffinityMask failed")
    process = ctypes.c_size_t()
    system = ctypes.c_size_t()
    if not kernel32.GetProcessAffinityMask(
        kernel32.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(system)
    ) or int(process.value) != mask:
        raise RuntimeError("benchmark affinity readback drifted")
    return mask


def peak_rss_bytes() -> int:
    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCountersEx),
        wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(),
        ctypes.byref(counters),
        counters.cb,
    ):
        raise RuntimeError("benchmark GetProcessMemoryInfo failed")
    return int(counters.PeakWorkingSetSize)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpu-ids", required=True)
    parser.add_argument("--task-index", type=int, required=True)
    arguments = parser.parse_args()
    cpu_ids = tuple(int(value) for value in arguments.cpu_ids.split(","))
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or any(os.environ.get(key) != value for key, value in EXACT_ENVIRONMENT.items())
    ):
        raise RuntimeError("benchmark child isolation/environment drifted")
    blackhole = Path(str(sys.pycache_prefix)).resolve(strict=False)
    if blackhole.exists():
        raise RuntimeError("benchmark bytecode blackhole must remain absent")
    mask = set_affinity(cpu_ids)
    started = time.perf_counter()
    # Fixed, score-free CPU+memory work.  It imports no project/generator/model
    # code and uses no seed, DGP, truth, vault, prediction, or evaluation data.
    memory = bytearray(16 * 1024 * 1024)
    state = b"EXPECTED_PE_R8_SCORE_FREE_RESOURCE_BENCHMARK_V1"
    for index in range(100_000):
        state = hashlib.sha256(state + (index & 255).to_bytes(1, "little")).digest()
    memory[0:32] = state
    elapsed = time.perf_counter() - started
    receipt = {
        "status": "PASS_SCORE_FREE_PINNED_RESOURCE_WORKER",
        "task_index": arguments.task_index,
        "cpu_ids": list(cpu_ids),
        "affinity_mask_hex": f"0x{mask:08X}",
        "inner_blas_threads": 1,
        "wall_seconds": elapsed,
        "peak_rss_bytes": peak_rss_bytes(),
        "determinism_digest": state.hex(),
        "payload_generated": False,
        "generator_imported": False,
        "truth_vault_latent_access": False,
    }
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
