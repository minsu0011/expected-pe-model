"""Score-free H-OFS V10 authority gate and worker lifecycle benchmark.

The frozen V10 bundle intentionally has no ``--run`` mode and no estimator
callback.  A future independently audited launcher may reuse these gates only
after binding a custodian public-key hash and external one-shot consumption.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


LAUNCHER_PATH = Path(__file__).resolve()
LAUNCHER_RELATIVE_PATH = (
    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/"
    "prediction_launcher.py"
)
PINNED_PYTHON_VERSION = "3.10.19"
PINNED_PYTHON_EXECUTABLE = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PINNED_PYTHON_EXECUTABLE_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
PINNED_AFFINITY_MASK = 0xFFFFFFFF
PINNED_OUTER_WORKERS = 32
PINNED_THREAD_ENVIRONMENT = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
)
PINNED_GPU_ENVIRONMENT = (("CUDA_VISIBLE_DEVICES", "-1"),)
FORBIDDEN_PREIMPORT_MODULES = ("numpy", "pandas", "threadpoolctl")


def _resolve_project_root() -> Path:
    candidates = (LAUNCHER_PATH.parents[3], LAUNCHER_PATH.parents[2])
    sentinel = (
        "research/model_zoo/hierarchical_observable_fair_value_state_v10/"
        "contracts.py"
    )
    matches = [candidate for candidate in candidates if (candidate / sentinel).is_file()]
    if len(matches) != 1:
        raise RuntimeError("H-OFS V10 project-root closure is ambiguous or absent")
    return matches[0]


PROJECT_ROOT = _resolve_project_root()


for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def current_affinity_mask() -> int:
    if os.name != "nt":
        raise RuntimeError("H-OFS V10 preflight requires Windows")
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
        raise RuntimeError("V10 GetProcessAffinityMask failed")
    return int(process_mask.value)


def actual_initializer_absence_guard(session_nonce: str) -> dict[str, Any]:
    """Run exactly once inside each worker initializer; no receipt input exists."""

    imported = sorted(
        name for name in FORBIDDEN_PREIMPORT_MODULES if name in sys.modules
    )
    if imported:
        raise RuntimeError(
            f"V10 forbidden numeric module preloaded before initializer: {imported}"
        )
    if (
        type(session_nonce) is not str
        or len(session_nonce) != 64
        or any(character not in "0123456789abcdef" for character in session_nonce)
    ):
        raise RuntimeError("V10 initializer session nonce drifted")
    executable = Path(sys.executable).resolve()
    observed = {
        "schema_version": "expected_pe.hofs_v10.actual_initializer_guard.v1",
        "status": "PASS_ACTUAL_ABSENCE_GUARD_IN_INITIALIZER",
        "worker_pid": os.getpid(),
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_executable": executable.as_posix(),
        "python_executable_sha256": sha256_bytes(executable.read_bytes()),
        "logical_cpu_count": int(os.cpu_count() or 0),
        "outer_workers": PINNED_OUTER_WORKERS,
        "inner_threads": 1,
        "affinity_mask_hex": f"0x{current_affinity_mask():08X}",
        "thread_environment": [
            [name, os.environ.get(name, "")] for name, _ in PINNED_THREAD_ENVIRONMENT
        ],
        "gpu_environment": [
            [name, os.environ.get(name, "")] for name, _ in PINNED_GPU_ENVIRONMENT
        ],
        "absence_guard_observed_modules": imported,
        "session_nonce": session_nonce,
        "initializer_count_per_pid": 1,
        "absence_guard_count_per_pid": 1,
    }
    expected = {
        **observed,
        "python_version": PINNED_PYTHON_VERSION,
        "python_executable": PINNED_PYTHON_EXECUTABLE,
        "python_executable_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
        "logical_cpu_count": 32,
        "outer_workers": PINNED_OUTER_WORKERS,
        "inner_threads": 1,
        "affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
        "thread_environment": [list(value) for value in PINNED_THREAD_ENVIRONMENT],
        "gpu_environment": [list(value) for value in PINNED_GPU_ENVIRONMENT],
        "absence_guard_observed_modules": [],
    }
    if observed != expected:
        drifted = sorted(name for name in expected if observed[name] != expected[name])
        raise RuntimeError(f"V10 exact initializer runtime drifted: {drifted}")
    return observed


class _SharedTaskLedger:
    """Picklable wrapper over manager proxies for atomic task consumption."""

    def __init__(
        self,
        *,
        lock: Any,
        consumed: Any,
        sequence: Any,
        attestation: Mapping[str, Any],
    ) -> None:
        self._lock = lock
        self._consumed = consumed
        self._sequence = sequence
        self._attestation = copy.deepcopy(dict(attestation))

    def attestation(self) -> dict[str, Any]:
        return copy.deepcopy(self._attestation)

    def consume(
        self,
        *,
        capability_envelope_raw_sha256: str,
        run_id: str,
        session_nonce: str,
        custodian_consumption_id: str,
        task_ordinal: int,
        task_binding_sha256: str,
        consumer_pid: int,
    ) -> dict[str, Any]:
        expected = self._attestation
        if (
            capability_envelope_raw_sha256
            != expected["capability_envelope_raw_sha256"]
            or run_id != expected["run_id"]
            or session_nonce != expected["session_nonce"]
            or custodian_consumption_id
            != expected["custodian_consumption_id"]
            or type(task_ordinal) is not int
            or isinstance(task_ordinal, bool)
            or not 0 <= task_ordinal < expected["task_count"]
            or type(task_binding_sha256) is not str
            or len(task_binding_sha256) != 64
            or type(consumer_pid) is not int
            or consumer_pid <= 0
        ):
            raise RuntimeError("V10 shared ledger consumption binding drifted")
        key = (
            f"{custodian_consumption_id}:{run_id}:{session_nonce}:"
            f"{task_ordinal}"
        )
        with self._lock:
            if key in self._consumed:
                raise RuntimeError("V10 duplicate, replay, or concurrent task consumption")
            next_sequence = int(self._sequence["value"]) + 1
            self._sequence["value"] = next_sequence
            self._consumed[key] = {
                "task_binding_sha256": task_binding_sha256,
                "consumer_pid": consumer_pid,
                "sequence": next_sequence,
            }
        return {
            "schema_version": "expected_pe.hofs_v10.task_consumption.v1",
            "status": "CONSUMED_ONCE_BEFORE_DOWNSTREAM",
            "run_id": run_id,
            "session_nonce": session_nonce,
            "custodian_consumption_id": custodian_consumption_id,
            "task_ordinal": task_ordinal,
            "task_binding_sha256": task_binding_sha256,
            "consumer_pid": consumer_pid,
            "global_consumption_sequence": next_sequence,
        }


def _new_shared_ledger(
    manager: Any,
    *,
    capability_envelope_raw_sha256: str,
    run_id: str,
    session_nonce: str,
    custodian_consumption_id: str,
    task_manifest_sha256: str,
    task_count: int,
) -> _SharedTaskLedger:
    attestation = {
        "schema_version": "expected_pe.hofs_v10.shared_task_ledger.v1",
        "status": "ACTIVE_SIGNED_ONE_SHOT_TASK_LEDGER",
        "capability_envelope_raw_sha256": capability_envelope_raw_sha256,
        "run_id": run_id,
        "session_nonce": session_nonce,
        "custodian_consumption_id": custodian_consumption_id,
        "task_manifest_sha256": task_manifest_sha256,
        "task_count": task_count,
        "one_shot": True,
    }
    return _SharedTaskLedger(
        lock=manager.Lock(),
        consumed=manager.dict(),
        sequence=manager.dict({"value": 0}),
        attestation=attestation,
    )


def _v10_worker_initializer(
    envelope_bytes: bytes,
    public_key: bytes,
    policy: Any,
    task_bindings: Sequence[Mapping[str, Any]],
    now_unix: int,
    shared_ledger: _SharedTaskLedger,
    initializer_barrier: Any,
    first_task_barrier: Any,
    receipt_queue: Any,
) -> None:
    """Internal worker entry: the actual guard is generated here, never supplied."""

    try:
        unsigned_probe = json.loads(envelope_bytes.decode("ascii"))
        session_nonce = unsigned_probe["payload"]["session_nonce"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("V10 initializer cannot extract a session nonce") from error
    guard = actual_initializer_absence_guard(session_nonce)
    from research.model_zoo.hierarchical_observable_fair_value_state_v10.capability import (  # noqa: PLC0415
        verify_capability_envelope,
    )

    verified_before_import = verify_capability_envelope(
        envelope_bytes,
        public_key=public_key,
        policy=policy,
        task_bindings=task_bindings,
        now_unix=now_unix,
    )
    if verified_before_import.session_nonce != session_nonce:
        raise RuntimeError("V10 verified initializer session nonce drifted")
    from research.model_zoo.hierarchical_observable_fair_value_state_v10.lifecycle import (  # noqa: PLC0415
        _INITIALIZER_MARKER,
        _install_worker_state,
    )

    receipt = _install_worker_state(
        initializer_marker=_INITIALIZER_MARKER,
        guard_receipt=guard,
        envelope_bytes=envelope_bytes,
        public_key=public_key,
        policy=policy,
        task_bindings=task_bindings,
        now_unix=now_unix,
        shared_ledger=shared_ledger,
        first_task_barrier=first_task_barrier,
    )
    initializer_barrier.wait(timeout=90.0)
    receipt_queue.put(receipt)


def _score_free_authorized_task(
    run_id: str,
    task: Mapping[str, Any],
    now_unix: int,
) -> dict[str, Any]:
    """Authorize and consume only; there is no public read, fit, or prediction."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v10.lifecycle import (  # noqa: PLC0415
        _authorize_and_consume_task,
    )

    authority = _authorize_and_consume_task(
        run_id=run_id,
        task_ordinal=task["task_ordinal"],
        seed=task["seed"],
        dgp=task["dgp"],
        canonical_relative=task["canonical_relative"],
        expected_raw_sha256=task["expected_raw_sha256"],
        now_unix=now_unix,
    )
    return {
        "task_ordinal": task["task_ordinal"],
        "worker_pid": os.getpid(),
        "authority": authority,
        "downstream_callback_invoked": False,
        "public_input_open_count": 0,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def run_score_free_lifecycle_benchmark(
    *,
    envelope_bytes: bytes,
    public_key: bytes,
    policy: Any,
    task_bindings: Sequence[Mapping[str, Any]],
    now_unix: int,
    worker_count: int,
    task_count: int,
) -> dict[str, Any]:
    """Spawn an exact score-free lifecycle schedule with shared one-shot state."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v10.capability import (  # noqa: PLC0415
        task_manifest_payload,
        verify_capability_envelope,
    )

    normalized = task_manifest_payload(task_bindings)
    if (
        type(worker_count) is not int
        or isinstance(worker_count, bool)
        or not 1 <= worker_count <= PINNED_OUTER_WORKERS
        or type(task_count) is not int
        or isinstance(task_count, bool)
        or not worker_count <= task_count <= len(normalized)
    ):
        raise RuntimeError("V10 score-free benchmark geometry drifted")
    verified = verify_capability_envelope(
        envelope_bytes,
        public_key=public_key,
        policy=policy,
        task_bindings=normalized,
        now_unix=now_unix,
    )
    context = multiprocessing.get_context("spawn")
    with context.Manager() as manager:
        ledger = _new_shared_ledger(
            manager,
            capability_envelope_raw_sha256=verified.envelope_raw_sha256,
            run_id=verified.run_id,
            session_nonce=verified.session_nonce,
            custodian_consumption_id=verified.custodian_consumption_id,
            task_manifest_sha256=verified.task_manifest_sha256,
            task_count=len(normalized),
        )
        initializer_barrier = context.Barrier(worker_count)
        first_task_barrier = context.Barrier(worker_count)
        receipt_queue = context.Queue()
        initializer_receipts: list[dict[str, Any]] = []
        results: dict[int, dict[str, Any]] = {}
        try:
            with ProcessPoolExecutor(
                max_workers=worker_count,
                mp_context=context,
                initializer=_v10_worker_initializer,
                initargs=(
                    envelope_bytes,
                    public_key,
                    policy,
                    normalized,
                    now_unix,
                    ledger,
                    initializer_barrier,
                    first_task_barrier,
                    receipt_queue,
                ),
            ) as executor:
                futures = {
                    executor.submit(
                        _score_free_authorized_task,
                        verified.run_id,
                        normalized[position],
                        now_unix,
                    ): position
                    for position in range(task_count)
                }
                initializer_receipts = [
                    receipt_queue.get(timeout=90.0) for _ in range(worker_count)
                ]
                for future in as_completed(futures):
                    position = futures[future]
                    results[position] = future.result(timeout=120.0)
        finally:
            receipt_queue.close()
            receipt_queue.join_thread()
        consumed = copy.deepcopy(dict(ledger._consumed))
    if (
        tuple(sorted(results)) != tuple(range(task_count))
        or len(initializer_receipts) != worker_count
        or len(consumed) != task_count
    ):
        raise RuntimeError("V10 score-free benchmark coverage drifted")
    pids = [int(receipt["worker_pid"]) for receipt in initializer_receipts]
    if len(set(pids)) != worker_count:
        raise RuntimeError("V10 exact initializer PID fanout drifted")
    ordered = [results[position] for position in range(task_count)]
    first_wave = {row["worker_pid"] for row in ordered[:worker_count]}
    if len(first_wave) != worker_count:
        raise RuntimeError("V10 first task worker fanout drifted")
    counts: dict[int, int] = {pid: 0 for pid in pids}
    for row in ordered:
        pid = int(row["worker_pid"])
        counts[pid] += 1
        if (
            row["downstream_callback_invoked"] is not False
            or row["public_input_open_count"] != 0
            or row["real_fit_count"] != 0
            or row["real_prediction_count"] != 0
        ):
            raise RuntimeError("V10 score-free task execution boundary drifted")
    reused = {pid: count for pid, count in counts.items() if count >= 2}
    if task_count > worker_count and not reused:
        raise RuntimeError("V10 benchmark did not prove worker reuse")
    return {
        "schema_version": "expected_pe.hofs_v10.score_free_lifecycle.v1",
        "status": "PASS_SIGNED_CAPABILITY_ATOMIC_ONE_SHOT_SCORE_FREE_LIFECYCLE",
        "process_start_method": "spawn",
        "worker_count": worker_count,
        "task_count": task_count,
        "worker_pids": sorted(pids),
        "task_counts_by_pid": [[pid, counts[pid]] for pid in sorted(counts)],
        "reused_worker_count": len(reused),
        "maximum_reuse_count": max(counts.values()),
        "initializer_count_per_pid": 1,
        "absence_guard_count_per_pid": 1,
        "signature_reverification_count": task_count,
        "atomic_consumption_count": task_count,
        "public_input_open_count": 0,
        "downstream_callback_invocation_count": 0,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def check_only() -> dict[str, Any]:
    """Validate the frozen score-free surface; no fixture or production key exists here."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (  # noqa: PLC0415
        contract_sha256,
    )

    return {
        "schema_version": "expected_pe.hofs_v10.check_only.v1",
        "status": "PASS_V10_SCORE_FREE_CONTRACT_AWAITS_INDEPENDENT_AUDIT_AND_CUSTODIAN",
        "contract_sha256": contract_sha256(),
        "launcher_raw_sha256": sha256_bytes(LAUNCHER_PATH.read_bytes()),
        "launcher_relative_path": LAUNCHER_RELATIVE_PATH,
        "actual_initializer_guard_invocation_count": 0,
        "actual_initializer_guard_location": "_v10_worker_initializer_only",
        "production_private_key_present": False,
        "production_signing_api_present": False,
        "production_public_key_value_present": False,
        "production_public_key_pin_present": False,
        "execution_authority": False,
        "run_mode_present": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", required=True)
    return parser


def main() -> int:
    _parser().parse_args()
    result = check_only()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
