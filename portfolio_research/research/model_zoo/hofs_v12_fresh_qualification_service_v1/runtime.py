"""Exact full-affinity resource gates and runtime receipt validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import multiprocessing as mp
import os
import queue
import time
from typing import Any, Mapping, Sequence

from .contracts import (
    CANDIDATE_ID,
    EXPECTED_CPU_IDS,
    GPU_OFF_ENVIRONMENT,
    INNER_THREADS,
    LOGICAL_CPUS_PER_WORKER,
    OUTER_WORKERS,
    PROCESS_EXIT_FIELDS,
    PROCESS_START_METHOD,
    RUNTIME_PREBINDING_FIELDS,
    RUNTIME_LANE_ID,
    RUNTIME_PREBINDING_SCHEMA_VERSION,
    RUNTIME_PREBINDING_STATUS,
    TASK_COUNT,
    NUMERIC_RESOURCE_GATE_STATUS,
    RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
    WORKER_AFFINITY_MASK,
    WORKER_AFFINITY_POLICY,
    HofsV12QualificationServiceError,
    canonical_json_bytes,
)


@dataclass(frozen=True)
class WorkerSlotPlan:
    """One worker slot sharing the exact frozen full-machine affinity."""

    worker_ordinal: int
    logical_cpu_ids: tuple[int, ...]
    affinity_mask: int
    inner_threads: int = INNER_THREADS

    def __post_init__(self) -> None:
        if type(self.worker_ordinal) is not int or not 0 <= self.worker_ordinal < OUTER_WORKERS:
            raise HofsV12QualificationServiceError("worker ordinal escaped the 16-slot plan")
        expected_ids = EXPECTED_CPU_IDS
        expected_mask = WORKER_AFFINITY_MASK
        if (
            self.logical_cpu_ids != expected_ids
            or self.affinity_mask != expected_mask
            or self.inner_threads != 1
        ):
            raise HofsV12QualificationServiceError("worker slot CPU or thread contract drifted")


@dataclass(frozen=True)
class TaskWorkerAssignment:
    """Deterministic custody-only assignment for one logical task."""

    task_ordinal: int
    worker_ordinal: int

    def __post_init__(self) -> None:
        if type(self.task_ordinal) is not int or not 0 <= self.task_ordinal < TASK_COUNT:
            raise HofsV12QualificationServiceError("assignment task ordinal drifted")
        if self.worker_ordinal != self.task_ordinal % OUTER_WORKERS:
            raise HofsV12QualificationServiceError("assignment is not ordinal round-robin")


@dataclass(frozen=True)
class RuntimePrebindingArtifact:
    """Service-side measurement claim requiring an external final binding."""

    receipt: dict[str, Any]
    raw_bytes: bytes
    raw_sha256: str

    def __post_init__(self) -> None:
        if self.raw_bytes != canonical_json_bytes(self.receipt):
            raise HofsV12QualificationServiceError("runtime prebinding bytes are not canonical")
        if hashlib.sha256(self.raw_bytes).hexdigest() != self.raw_sha256:
            raise HofsV12QualificationServiceError("runtime prebinding raw hash differs")


def build_worker_slot_plan() -> tuple[WorkerSlotPlan, ...]:
    plan = tuple(
        WorkerSlotPlan(
            worker_ordinal=ordinal,
            logical_cpu_ids=EXPECTED_CPU_IDS,
            affinity_mask=WORKER_AFFINITY_MASK,
        )
        for ordinal in range(OUTER_WORKERS)
    )
    if len(plan) != OUTER_WORKERS or any(
        slot.logical_cpu_ids != EXPECTED_CPU_IDS
        or slot.affinity_mask != WORKER_AFFINITY_MASK
        for slot in plan
    ):
        raise HofsV12QualificationServiceError("shared full-affinity worker plan drifted")
    return plan


def build_task_worker_assignments() -> tuple[TaskWorkerAssignment, ...]:
    assignments = tuple(
        TaskWorkerAssignment(task_ordinal=ordinal, worker_ordinal=ordinal % OUTER_WORKERS)
        for ordinal in range(TASK_COUNT)
    )
    if len(assignments) != TASK_COUNT:
        raise HofsV12QualificationServiceError("task assignment count drifted")
    return assignments


def validate_inherited_gpu_off_environment() -> dict[str, str]:
    """Validate inherited values without mutating the parent or child environment."""

    captured = {name: os.environ.get(name) for name in GPU_OFF_ENVIRONMENT}
    if captured != GPU_OFF_ENVIRONMENT:
        raise HofsV12QualificationServiceError("inner-thread or GPU-off environment drifted")
    return dict(GPU_OFF_ENVIRONMENT)


def current_windows_affinity() -> tuple[int, tuple[int, ...]]:
    """Capture the exact current Windows process mask without changing it."""

    if os.name != "nt":
        raise HofsV12QualificationServiceError("exact worker affinity capture requires Windows")
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

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
        raise HofsV12QualificationServiceError(
            f"GetProcessAffinityMask failed: {ctypes.get_last_error()}"
        )
    mask = int(process_mask.value)
    cpu_ids = tuple(cpu_id for cpu_id in range(mask.bit_length()) if mask & (1 << cpu_id))
    return mask, cpu_ids


def current_windows_affinity_cpu_ids() -> tuple[int, ...]:
    """Compatibility view of the exact live process affinity."""

    return current_windows_affinity()[1]


def validate_live_resource_values(
    *,
    logical_cpu_count: int,
    affinity_mask: int,
    cpu_ids: tuple[int, ...],
    environment: Mapping[str, object],
) -> dict[str, Any]:
    """Validate observed values against the immutable full-affinity envelope."""

    if (
        type(logical_cpu_count) is not int
        or logical_cpu_count != LOGICAL_CPUS_PER_WORKER
        or type(affinity_mask) is not int
        or affinity_mask != WORKER_AFFINITY_MASK
        or type(cpu_ids) is not tuple
        or cpu_ids != EXPECTED_CPU_IDS
        or type(environment) is not dict
        or environment != GPU_OFF_ENVIRONMENT
    ):
        raise HofsV12QualificationServiceError(
            "live numeric resource envelope is not exact full32/inner1/CUDA=-1"
        )
    return {
        "logical_cpu_count": logical_cpu_count,
        "logical_cpu_ids": list(cpu_ids),
        "affinity_mask": f"0x{affinity_mask:08X}",
        "affinity_policy": WORKER_AFFINITY_POLICY,
        "inner_threads": INNER_THREADS,
        "environment": dict(GPU_OFF_ENVIRONMENT),
        "process_start_method": PROCESS_START_METHOD,
        "status": NUMERIC_RESOURCE_GATE_STATUS,
    }


def validate_current_worker_envelope(worker_ordinal: int) -> dict[str, Any]:
    """Validate one worker's live full32 affinity and inherited environment."""

    if type(worker_ordinal) is not int or not 0 <= worker_ordinal < OUTER_WORKERS:
        raise HofsV12QualificationServiceError("worker ordinal escaped the frozen plan")
    slot = build_worker_slot_plan()[worker_ordinal]
    environment = validate_inherited_gpu_off_environment()
    affinity_mask, observed_cpu_ids = current_windows_affinity()
    observed = validate_live_resource_values(
        logical_cpu_count=int(os.cpu_count() or 0),
        affinity_mask=affinity_mask,
        cpu_ids=observed_cpu_ids,
        environment=environment,
    )
    if observed_cpu_ids != slot.logical_cpu_ids or affinity_mask != slot.affinity_mask:
        raise HofsV12QualificationServiceError("current process affinity differs from worker slot")
    return {
        **observed,
        "worker_ordinal": worker_ordinal,
        "pid": os.getpid(),
    }


def assert_actual_numeric_launch_allowed(worker_ordinal: int) -> dict[str, Any]:
    """Admit unchanged V7 numeric code only inside the exact live envelope."""

    return validate_current_worker_envelope(worker_ordinal)


def current_windows_process_memory() -> dict[str, int]:
    """Capture current and peak process memory without opening another process."""

    if os.name != "nt":
        raise HofsV12QualificationServiceError("exact process memory capture requires Windows")
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

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

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCountersEx),
        wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        raise HofsV12QualificationServiceError(
            f"GetProcessMemoryInfo failed: {ctypes.get_last_error()}"
        )
    return {
        "rss_bytes": int(counters.WorkingSetSize),
        "peak_rss_bytes": int(counters.PeakWorkingSetSize),
        "private_bytes": int(counters.PrivateUsage),
        "peak_pagefile_bytes": int(counters.PeakPagefileUsage),
    }


def _resource_preflight_worker(
    worker_ordinal: int,
    result_queue: Any,
    release_event: Any,
) -> None:
    """Spawn target: attest, rendezvous, then exit without numeric work."""

    try:
        observation = validate_current_worker_envelope(worker_ordinal)
        observation["memory"] = current_windows_process_memory()
        result_queue.put(
            {"kind": "ready", "worker_ordinal": worker_ordinal, "observation": observation}
        )
        if not release_event.wait(timeout=30.0):
            raise HofsV12QualificationServiceError("resource preflight release timed out")
    except Exception as exc:
        result_queue.put(
            {
                "kind": "error",
                "worker_ordinal": worker_ordinal,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        raise


def run_native_16_worker_resource_preflight() -> dict[str, Any]:
    """Spawn all 16 workers concurrently and attest the exact inherited envelope."""

    started = time.perf_counter_ns()
    controller = validate_current_worker_envelope(0)
    controller["process_role"] = "controller"
    controller["memory"] = current_windows_process_memory()
    context = mp.get_context(PROCESS_START_METHOD)
    result_queue = context.Queue()
    release_event = context.Event()
    processes = [
        context.Process(
            target=_resource_preflight_worker,
            args=(ordinal, result_queue, release_event),
            name=f"hofs-v12-resource-{ordinal:02d}",
        )
        for ordinal in range(OUTER_WORKERS)
    ]
    observations: dict[int, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []
    try:
        for process in processes:
            process.start()
        deadline = time.monotonic() + 45.0
        while len(observations) + len(failures) < OUTER_WORKERS:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                failures.append({"kind": "error", "error": "ready receipt timeout"})
                break
            try:
                message = result_queue.get(timeout=min(1.0, remaining))
            except queue.Empty:
                if any(process.exitcode not in (None, 0) for process in processes):
                    failures.append({"kind": "error", "error": "worker exited before receipt"})
                    break
                continue
            if type(message) is not dict or message.get("kind") not in {"ready", "error"}:
                failures.append({"kind": "error", "error": "invalid worker message"})
                break
            ordinal = message.get("worker_ordinal")
            if type(ordinal) is not int or not 0 <= ordinal < OUTER_WORKERS:
                failures.append({"kind": "error", "error": "invalid worker ordinal"})
                break
            if message["kind"] == "error":
                failures.append(message)
                break
            observation = message.get("observation")
            if type(observation) is not dict or ordinal in observations:
                failures.append({"kind": "error", "error": "duplicate/invalid observation"})
                break
            observations[ordinal] = observation
        release_event.set()
        for process in processes:
            process.join(timeout=30.0)
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=10.0)
                failures.append({"kind": "error", "error": f"stuck worker: {process.name}"})
        exit_codes = tuple(process.exitcode for process in processes)
        if any(code != 0 for code in exit_codes):
            failures.append({"kind": "error", "error": f"worker exit codes: {exit_codes}"})
        if failures or set(observations) != set(range(OUTER_WORKERS)):
            raise HofsV12QualificationServiceError(
                f"native 16-worker resource preflight failed: {failures!r}"
            )
        ordered = [observations[ordinal] for ordinal in range(OUTER_WORKERS)]
        pids = [int(item["pid"]) for item in ordered]
        if len(set(pids)) != OUTER_WORKERS or any(
            item["status"] != NUMERIC_RESOURCE_GATE_STATUS
            or item["logical_cpu_ids"] != list(EXPECTED_CPU_IDS)
            or item["affinity_mask"] != f"0x{WORKER_AFFINITY_MASK:08X}"
            for item in ordered
        ):
            raise HofsV12QualificationServiceError("worker observation universe drifted")
        ended = time.perf_counter_ns()
        peak_rows = [int(item["memory"]["peak_rss_bytes"]) for item in ordered]
        receipt = {
            "schema_version": "expected_pe.hofs_v12.resource_preflight.v1",
            "status": "PASS_NATIVE_16_SPAWNED_FULL_AFFINITY_RESOURCE_PREFLIGHT",
            "resource_resolution_lock_raw_sha256": RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
            "process_start_method": PROCESS_START_METHOD,
            "actual_controller_worker_count": OUTER_WORKERS,
            "simultaneous_ready_worker_count": len(ordered),
            "controller_observation": controller,
            "worker_observations": ordered,
            "process_exit_records": list(expected_process_exit_records()),
            "elapsed_ns": ended - started,
            "worker_peak_rss_max_bytes": max(peak_rows),
            "worker_peak_rss_sum_bytes": sum(peak_rows),
            "qualification_access_count": 0,
            "fresh_access_count": 0,
            "truth_access_count": 0,
            "heldout_access_count": 0,
            "score_access_count": 0,
            "publication_count": 0,
        }
        raw = canonical_json_bytes(receipt)
        return {**receipt, "receipt_raw_sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        release_event.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=10.0)
        result_queue.close()
        result_queue.join_thread()


def expected_process_exit_records() -> tuple[dict[str, Any], ...]:
    """Return the exact successful controller plus 16 spawned-worker exit universe."""

    return (
        {"process_role": "controller", "worker_ordinal": 0, "exit_code": 0},
        *(
            {"process_role": "worker", "worker_ordinal": ordinal, "exit_code": 0}
            for ordinal in range(OUTER_WORKERS)
        ),
    )


def _validate_process_exit_records(
    records: Sequence[Mapping[str, object]],
) -> list[dict[str, Any]]:
    if type(records) not in (list, tuple) or len(records) != OUTER_WORKERS + 1:
        raise HofsV12QualificationServiceError("runtime process exit universe drifted")
    normalized: list[dict[str, Any]] = []
    for value in records:
        if type(value) is not dict or set(value) != set(PROCESS_EXIT_FIELDS):
            raise HofsV12QualificationServiceError("runtime process exit fields drifted")
        if (
            type(value["process_role"]) is not str
            or type(value["worker_ordinal"]) is not int
            or type(value["exit_code"]) is not int
        ):
            raise HofsV12QualificationServiceError("runtime process exit types drifted")
        normalized.append({field: value[field] for field in PROCESS_EXIT_FIELDS})
    if tuple(normalized) != expected_process_exit_records():
        raise HofsV12QualificationServiceError("runtime process exits differ from exact success")
    return normalized


def build_isolated_c4_runtime_prebinding(
    *,
    started_perf_counter_ns: int,
    ended_perf_counter_ns: int,
    sample_count: int,
    sample_interval_max_ms: float,
    peak_process_tree_rss_bytes: int,
    peak_vram_bytes: int,
    gpu_process_observation_count: int,
    process_exit_records: Sequence[Mapping[str, object]],
) -> RuntimePrebindingArtifact:
    """Build a non-final service claim for an external measured/FileId binding."""

    for label, value in (
        ("runtime start", started_perf_counter_ns),
        ("runtime end", ended_perf_counter_ns),
        ("runtime sample count", sample_count),
        ("runtime peak RSS", peak_process_tree_rss_bytes),
        ("runtime peak VRAM", peak_vram_bytes),
        ("runtime GPU process observations", gpu_process_observation_count),
    ):
        if type(value) is not int or value < 0:
            raise HofsV12QualificationServiceError(f"{label} must be an exact nonnegative int")
    if ended_perf_counter_ns < started_perf_counter_ns:
        raise HofsV12QualificationServiceError("runtime monotonic interval is reversed")
    if sample_count < 1:
        raise HofsV12QualificationServiceError("runtime sample count must be positive")
    if (
        type(sample_interval_max_ms) not in (int, float)
        or not math.isfinite(float(sample_interval_max_ms))
        or not 0.0 < float(sample_interval_max_ms) <= 100.0
    ):
        raise HofsV12QualificationServiceError("runtime sample interval escaped (0,100] ms")
    if peak_vram_bytes != 0 or gpu_process_observation_count != 0:
        raise HofsV12QualificationServiceError("isolated C4 runtime observed GPU use")
    exits = _validate_process_exit_records(process_exit_records)
    receipt: dict[str, Any] = {
        "schema_version": RUNTIME_PREBINDING_SCHEMA_VERSION,
        "status": RUNTIME_PREBINDING_STATUS,
        "candidate_ids": [CANDIDATE_ID],
        "ended_perf_counter_ns": ended_perf_counter_ns,
        "gpu_process_observation_count": gpu_process_observation_count,
        "lane_id": RUNTIME_LANE_ID,
        "peak_process_tree_rss_bytes": peak_process_tree_rss_bytes,
        "peak_vram_bytes": peak_vram_bytes,
        "process_exit_records": exits,
        "sample_count": sample_count,
        "sample_interval_max_ms": float(sample_interval_max_ms),
        "started_perf_counter_ns": started_perf_counter_ns,
        "wall_time_ns": ended_perf_counter_ns - started_perf_counter_ns,
    }
    if set(receipt) != set(RUNTIME_PREBINDING_FIELDS):
        raise HofsV12QualificationServiceError("isolated C4 runtime prebinding fields drifted")
    raw = canonical_json_bytes(receipt)
    return RuntimePrebindingArtifact(
        receipt=receipt,
        raw_bytes=raw,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )


__all__ = [
    "RuntimePrebindingArtifact",
    "TaskWorkerAssignment",
    "WorkerSlotPlan",
    "assert_actual_numeric_launch_allowed",
    "build_isolated_c4_runtime_prebinding",
    "build_task_worker_assignments",
    "build_worker_slot_plan",
    "current_windows_affinity",
    "current_windows_affinity_cpu_ids",
    "current_windows_process_memory",
    "expected_process_exit_records",
    "run_native_16_worker_resource_preflight",
    "validate_current_worker_envelope",
    "validate_inherited_gpu_off_environment",
    "validate_live_resource_values",
]
