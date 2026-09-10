"""Exact fail-closed fit and inference runtime custody for H-OFS V7."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import sys
from typing import Any

import numpy as np
import pandas as pd
from threadpoolctl import threadpool_info

from .contracts import (
    GPU_DISABLED_ENVIRONMENT,
    PINNED_AFFINITY_MASK,
    PINNED_CPU_IDS,
    PINNED_NUMPY_VERSION,
    PINNED_PANDAS_VERSION,
    PINNED_PYTHON_EXECUTABLE,
    PINNED_PYTHON_EXECUTABLE_SHA256,
    PINNED_PYTHON_VERSION,
    PINNED_THREAD_ENVIRONMENT,
    PINNED_THREADPOOL_BACKENDS,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
)
from .validation import (
    require_exact_bool,
    require_exact_int,
    require_exact_str,
    require_exact_tuple,
    require_sha256,
)


_ALLOWED_PURPOSES = frozenset({"FIT", "INFERENCE", "PREFLIGHT"})


@dataclass(frozen=True)
class ResourceReceiptV7:
    """Complete semantic receipt for one exact H-OFS V7 runtime."""

    purpose: str
    python_version: str
    python_executable: str
    python_executable_sha256: str
    numpy_version: str
    pandas_version: str
    logical_cpu_count: int
    affinity_mask_hex: str
    cpu_ids: tuple[int, ...]
    outer_workers: int
    inner_threads: int
    thread_environment: tuple[tuple[str, str], ...]
    threadpool_backends: tuple[tuple[str, str, str, str, int], ...]
    gpu_environment: tuple[tuple[str, str], ...]
    estimator_device: str = "CPU_ONLY_DETERMINISTIC_PROJECTED_IRLS"
    deterministic_row_accumulation: bool = True
    gpu_used: bool = False

    def __post_init__(self) -> None:
        require_exact_str(self.purpose, label="resource purpose")
        if self.purpose not in _ALLOWED_PURPOSES:
            raise HierarchicalStateV7ContractError("resource receipt purpose drifted")
        for label, value in (
            ("python version", self.python_version),
            ("python executable", self.python_executable),
            ("NumPy version", self.numpy_version),
            ("Pandas version", self.pandas_version),
            ("affinity mask", self.affinity_mask_hex),
            ("estimator device", self.estimator_device),
        ):
            require_exact_str(value, label=label)
        require_sha256(
            self.python_executable_sha256,
            label="python executable SHA-256",
        )
        require_exact_int(
            self.logical_cpu_count,
            label="logical CPU count",
            minimum=1,
        )
        require_exact_int(self.outer_workers, label="outer workers", minimum=1)
        require_exact_int(self.inner_threads, label="inner threads", minimum=1)
        require_exact_bool(
            self.deterministic_row_accumulation,
            label="deterministic row accumulation",
        )
        require_exact_bool(self.gpu_used, label="GPU-used flag")
        cpu_ids = require_exact_tuple(
            self.cpu_ids,
            label="CPU identifiers",
            length=len(PINNED_CPU_IDS),
        )
        for position, cpu_id in enumerate(cpu_ids):
            require_exact_int(cpu_id, label=f"CPU identifiers[{position}]", minimum=0)
        thread_environment = require_exact_tuple(
            self.thread_environment,
            label="thread environment",
            length=len(PINNED_THREAD_ENVIRONMENT),
        )
        for position, item in enumerate(thread_environment):
            pair = require_exact_tuple(
                item,
                label=f"thread environment[{position}]",
                length=2,
            )
            require_exact_str(pair[0], label=f"thread environment[{position}].name")
            require_exact_str(pair[1], label=f"thread environment[{position}].value")
        threadpools = require_exact_tuple(
            self.threadpool_backends,
            label="threadpool backends",
            length=len(PINNED_THREADPOOL_BACKENDS),
        )
        for position, item in enumerate(threadpools):
            backend = require_exact_tuple(
                item,
                label=f"threadpool backends[{position}]",
                length=5,
            )
            for field_position in range(4):
                require_exact_str(
                    backend[field_position],
                    label=f"threadpool backends[{position}][{field_position}]",
                )
            require_exact_int(
                backend[4],
                label=f"threadpool backends[{position}].threads",
                minimum=1,
            )
        gpu_environment = require_exact_tuple(
            self.gpu_environment,
            label="GPU environment",
            length=len(GPU_DISABLED_ENVIRONMENT),
        )
        for position, item in enumerate(gpu_environment):
            pair = require_exact_tuple(
                item,
                label=f"GPU environment[{position}]",
                length=2,
            )
            require_exact_str(pair[0], label=f"GPU environment[{position}].name")
            require_exact_str(pair[1], label=f"GPU environment[{position}].value")
        exact_values = {
            "python_version": (self.python_version, PINNED_PYTHON_VERSION),
            "python_executable": (self.python_executable, PINNED_PYTHON_EXECUTABLE),
            "python_executable_sha256": (
                self.python_executable_sha256,
                PINNED_PYTHON_EXECUTABLE_SHA256,
            ),
            "numpy_version": (self.numpy_version, PINNED_NUMPY_VERSION),
            "pandas_version": (self.pandas_version, PINNED_PANDAS_VERSION),
            "logical_cpu_count": (self.logical_cpu_count, len(PINNED_CPU_IDS)),
            "affinity_mask_hex": (
                self.affinity_mask_hex,
                f"0x{PINNED_AFFINITY_MASK:08X}",
            ),
            "cpu_ids": (self.cpu_ids, PINNED_CPU_IDS),
            "outer_workers": (self.outer_workers, 32),
            "inner_threads": (self.inner_threads, 1),
            "thread_environment": (
                self.thread_environment,
                PINNED_THREAD_ENVIRONMENT,
            ),
            "threadpool_backends": (
                self.threadpool_backends,
                PINNED_THREADPOOL_BACKENDS,
            ),
            "gpu_environment": (self.gpu_environment, GPU_DISABLED_ENVIRONMENT),
            "estimator_device": (
                self.estimator_device,
                "CPU_ONLY_DETERMINISTIC_PROJECTED_IRLS",
            ),
            "deterministic_row_accumulation": (
                self.deterministic_row_accumulation,
                True,
            ),
            "gpu_used": (self.gpu_used, False),
        }
        drifted = [name for name, (actual, expected) in exact_values.items() if actual != expected]
        if drifted:
            raise HierarchicalStateV7ContractError(
                f"resource receipt semantic drift: {sorted(drifted)}"
            )

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.payload())).hexdigest()


def _current_affinity_mask() -> int:
    if os.name != "nt":
        raise HierarchicalStateV7ContractError("H-OFS V7 exact runtime requires Windows")
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
        raise HierarchicalStateV7ContractError(
            f"GetProcessAffinityMask failed: {ctypes.get_last_error()}"
        )
    return int(process_mask.value)


def _captured_threadpools() -> tuple[tuple[str, str, str, str, int], ...]:
    output: list[tuple[str, str, str, str, int]] = []
    for item in threadpool_info():
        output.append(
            (
                str(item.get("user_api", "")),
                str(item.get("internal_api", "")),
                str(item.get("version", "")),
                str(item.get("threading_layer", "")),
                int(item.get("num_threads", -1)),
            )
        )
    return tuple(sorted(output))


def capture_runtime_receipt_v7(*, purpose: str) -> ResourceReceiptV7:
    """Capture and enforce the exact live runtime before fit or inference."""

    executable = Path(sys.executable).resolve()
    executable_text = executable.as_posix()
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    affinity_mask = _current_affinity_mask()
    cpu_ids = tuple(
        position for position in range(affinity_mask.bit_length()) if affinity_mask >> position & 1
    )
    receipt = ResourceReceiptV7(
        purpose=purpose,
        python_version=".".join(str(value) for value in sys.version_info[:3]),
        python_executable=executable_text,
        python_executable_sha256=executable_sha256,
        numpy_version=np.__version__,
        pandas_version=pd.__version__,
        logical_cpu_count=int(os.cpu_count() or 0),
        affinity_mask_hex=f"0x{affinity_mask:08X}",
        cpu_ids=cpu_ids,
        outer_workers=32,
        inner_threads=1,
        thread_environment=tuple(
            (name, os.environ.get(name, "")) for name, _ in PINNED_THREAD_ENVIRONMENT
        ),
        threadpool_backends=_captured_threadpools(),
        gpu_environment=tuple(
            (name, os.environ.get(name, "")) for name, _ in GPU_DISABLED_ENVIRONMENT
        ),
    )
    return receipt


__all__ = ["ResourceReceiptV7", "capture_runtime_receipt_v7"]
