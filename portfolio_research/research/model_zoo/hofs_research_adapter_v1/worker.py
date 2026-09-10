"""Spawn-safe worker that calls only the exact audited H-OFS V7 numeric API."""

from __future__ import annotations

import hashlib
import io
import os
import time
from typing import Any

from .contracts import (
    FOLDS_PER_TASK,
    NONINFORMATIVE_GROUP_LABEL,
    PREDICTION_COLUMNS,
    ROWS_PER_TASK,
    THREAD_ENVIRONMENT,
    V7_CONTRACT_SHA256,
    V7_FIT_CONFIG_SHA256,
    HofsResearchAdapterError,
    canonical_json_bytes,
)
from .inputs import TaskSpec, read_canonical_bytes, verify_numeric_source_closure


for _environment_name, _environment_value in THREAD_ENVIRONMENT:
    os.environ[_environment_name] = _environment_value


_WORKER_INITIALIZED = False
_WORKER_RECEIPT: dict[str, Any] | None = None
_THREAD_LIMITER: Any = None


def _windows_process_memory() -> dict[str, int]:
    """Return current and peak working set using the Windows process API."""

    if os.name != "nt":
        raise HofsResearchAdapterError("exact H-OFS runtime requires Windows memory receipts")
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
        kernel32.GetCurrentProcess(),
        ctypes.byref(counters),
        counters.cb,
    ):
        raise HofsResearchAdapterError(
            f"GetProcessMemoryInfo failed: {ctypes.get_last_error()}"
        )
    return {
        "rss_bytes": int(counters.WorkingSetSize),
        "peak_rss_bytes": int(counters.PeakWorkingSetSize),
        "private_bytes": int(counters.PrivateUsage),
        "peak_pagefile_bytes": int(counters.PeakPagefileUsage),
    }


def _identity_rows(frame: Any, identity_columns: tuple[str, str]) -> list[list[str]]:
    return [
        [str(entity), date.isoformat()]
        for entity, date in frame.loc[:, list(identity_columns)].itertuples(
            index=False,
            name=None,
        )
    ]


def initialize_worker() -> None:
    """Verify source bytes and establish a persistent one-thread numerical scope."""

    global _THREAD_LIMITER, _WORKER_INITIALIZED, _WORKER_RECEIPT
    if _WORKER_INITIALIZED:
        return
    for name, value in THREAD_ENVIRONMENT:
        os.environ[name] = value
    source_receipt = verify_numeric_source_closure()

    from threadpoolctl import threadpool_info, threadpool_limits  # noqa: PLC0415

    _THREAD_LIMITER = threadpool_limits(limits=1)
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: PLC0415
        capture_runtime_receipt_v7,
        contract_sha256,
        fit_config_sha256,
    )

    if contract_sha256() != V7_CONTRACT_SHA256 or fit_config_sha256() != V7_FIT_CONFIG_SHA256:
        raise HofsResearchAdapterError("live audited V7 semantic contract drifted")
    v7_runtime = capture_runtime_receipt_v7(purpose="PREFLIGHT").payload()
    pools = threadpool_info()
    if not pools or any(int(item.get("num_threads", -1)) != 1 for item in pools):
        raise HofsResearchAdapterError("worker numerical thread limit is not exactly one")
    _WORKER_RECEIPT = {
        "pid": os.getpid(),
        "source_closure_semantic_sha256": source_receipt["semantic_sha256"],
        "v7_contract_sha256": V7_CONTRACT_SHA256,
        "v7_fit_config_sha256": V7_FIT_CONFIG_SHA256,
        "thread_environment": dict(THREAD_ENVIRONMENT),
        "threadpool_backends": pools,
        "inner_threads": 1,
        "gpu_used": False,
        "v7_runtime_receipt": v7_runtime,
        "memory_at_initializer": _windows_process_memory(),
    }
    _WORKER_INITIALIZED = True


def _normalize_fold_indices(fold_indices: tuple[int, ...] | None) -> tuple[int, ...]:
    output = tuple(range(FOLDS_PER_TASK)) if fold_indices is None else fold_indices
    if (
        type(output) is not tuple
        or not output
        or any(type(value) is not int or not 0 <= value < FOLDS_PER_TASK for value in output)
        or tuple(sorted(set(output))) != output
    ):
        raise HofsResearchAdapterError("requested benchmark/full fold set drifted")
    return output


def execute_task(
    task: TaskSpec,
    fold_indices: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    """Fit and predict selected chronological blocks for one fixed public task."""

    if type(task) is not TaskSpec:
        raise HofsResearchAdapterError("worker requires an exact TaskSpec")
    selected_folds = _normalize_fold_indices(fold_indices)
    if not _WORKER_INITIALIZED:
        initialize_worker()
    if _WORKER_RECEIPT is None:
        raise HofsResearchAdapterError("worker initialization receipt is missing")

    import numpy as np  # noqa: PLC0415
    import pandas as pd  # noqa: PLC0415

    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: PLC0415
        adapt_r4_canonical_source_v7,
        build_hierarchical_state_features_v7,
        build_r4_fold_plan_v7,
        fit_chronological_prefix_v7,
        run_frozen_decision_block_v7,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.contracts import (  # noqa: PLC0415
        IDENTITY_COLUMNS,
        OUTPUT_COLUMNS,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4 import (  # noqa: PLC0415
        R4_CANONICAL_COLUMNS,
    )

    task_started = time.perf_counter()
    content = read_canonical_bytes(task)
    source = adapt_r4_canonical_source_v7(pd.read_csv(io.BytesIO(content)))
    if (
        tuple(source.columns) != R4_CANONICAL_COLUMNS
        or len(source) != ROWS_PER_TASK
        or not source.index.equals(pd.RangeIndex(ROWS_PER_TASK))
    ):
        raise HofsResearchAdapterError(f"canonical task schema drifted: {task.ordinal}")
    canonical_probe = source.loc[:, ["symbol", "date"]].sort_values(
        ["date", "symbol"], kind="mergesort"
    )
    actual_identity = [
        [str(symbol), pd.Timestamp(date).isoformat()]
        for symbol, date in source.loc[:, ["symbol", "date"]].itertuples(
            index=False, name=None
        )
    ]
    probe_identity = [
        [str(symbol), pd.Timestamp(date).isoformat()]
        for symbol, date in canonical_probe.itertuples(index=False, name=None)
    ]
    if actual_identity != probe_identity:
        raise HofsResearchAdapterError(f"canonical task order drifted: {task.ordinal}")

    full_state = build_hierarchical_state_features_v7(source)
    full_state.assert_live_integrity()
    if _identity_rows(full_state.identities, IDENTITY_COLUMNS) != actual_identity:
        raise HofsResearchAdapterError(f"source/state identity parity drifted: {task.ordinal}")
    observed = source["observed_pe"].copy()
    research_groups = pd.Series(
        [NONINFORMATIVE_GROUP_LABEL] * ROWS_PER_TASK,
        index=source.index,
        dtype="object",
    )
    plan = tuple(
        item
        for item in build_r4_fold_plan_v7()
        if item.seed == task.seed
        and item.dgp == task.dgp
        and item.fold_index in selected_folds
    )
    if tuple(item.fold_index for item in plan) != selected_folds:
        raise HofsResearchAdapterError(f"V7 fold plan selection drifted: {task.ordinal}")

    prediction_rows: list[dict[str, Any]] = []
    fold_receipts: list[dict[str, Any]] = []
    fit_resource: dict[str, Any] | None = None
    inference_resource: dict[str, Any] | None = None
    for spec in plan:
        fold_started = time.perf_counter()
        start = spec.decision_block_start_inclusive
        end = spec.decision_block_end_exclusive
        requested = full_state.identities.iloc[start:end].copy()
        if requested.index.tolist() != list(range(start, end)):
            raise HofsResearchAdapterError("decision source positions drifted")
        requested_rows = _identity_rows(requested, IDENTITY_COLUMNS)
        if requested_rows != sorted(requested_rows, key=lambda row: (row[1], row[0])):
            raise HofsResearchAdapterError("decision block canonical order drifted")

        capability = fit_chronological_prefix_v7(
            source,
            decision_block_identities=requested,
            observed_pe=observed,
            research_dgp_groups=research_groups,
        )
        fit = capability.fit
        parameters = fit.parameters
        fit_receipt = fit.fit_receipt
        output = run_frozen_decision_block_v7(
            source,
            requested_identities=requested,
            parameters=parameters,
        )
        expected_positions = tuple(range(start, end))
        if (
            parameters.decision_source_positions != expected_positions
            or fit_receipt.decision_source_positions != expected_positions
            or output.input_rows != spec.decision_row_count
            or len(output.values) != spec.decision_row_count
            or tuple(output.values.columns) != OUTPUT_COLUMNS
            or parameters.within_block_parameter_update_count != 0
            or fit_receipt.within_block_parameter_update_count != 0
            or output.within_block_parameter_update_count != 0
        ):
            raise HofsResearchAdapterError("V7 fit/output custody drifted")
        parameter_sha256 = parameters.sha256()
        fit_receipt_sha256 = fit_receipt.sha256()
        if (
            output.parameter_sha256 != parameter_sha256
            or parameters.convergence_receipt_sha256 != fit_receipt_sha256
            or parameters.decision_block_ordered_membership_sha256
            != output.decision_block_ordered_membership_sha256
            or parameters.decision_block_set_membership_sha256
            != output.decision_block_set_membership_sha256
            or parameters.decision_source_positions_sha256
            != output.decision_source_positions_sha256
        ):
            raise HofsResearchAdapterError("V7 parameter/output binding drifted")
        prefix_counts = fit_receipt.prefix_entity_row_counts
        prefix_invalid = fit_receipt.prefix_entity_causal_invalid_positions
        if (
            prefix_counts != (("DGP_ISSUER", start, 3, start - 3),)
            or prefix_invalid != (("DGP_ISSUER", (0, 1, 2)),)
            or fit_receipt.fit_row_count != start - 3
            or fit_receipt.causal_prefix_nonwarm_row_count != 3
            or fit_receipt.source_regime_fallback_count != 0
            or output.regime_fallback_count != 0
        ):
            raise HofsResearchAdapterError("V7 causal-prefix receipt drifted")

        current_fit_resource = fit.resource_receipt.payload()
        current_inference_resource = output.inference_resource_receipt.payload()
        if fit_resource is None:
            fit_resource = current_fit_resource
            inference_resource = current_inference_resource
        elif fit_resource != current_fit_resource or inference_resource != current_inference_resource:
            raise HofsResearchAdapterError("V7 runtime receipt drifted within task")

        output_manifest_sha256 = output.output_manifest_sha256
        identities = _identity_rows(output.identities, IDENTITY_COLUMNS)
        if identities != requested_rows:
            raise HofsResearchAdapterError("V7 output identity order drifted")
        numeric = output.values.to_numpy(dtype=np.float64)
        if (
            not np.isfinite(numeric).all()
            or not (numeric[:, :3] > 0.0).all()
            or not (numeric[:, 1] <= numeric[:, 0]).all()
            or not (numeric[:, 0] <= numeric[:, 2]).all()
        ):
            raise HofsResearchAdapterError("V7 output numeric domain drifted")
        for local_position, ((entity, date), values) in enumerate(
            zip(identities, numeric.tolist(), strict=True)
        ):
            row = {
                "task_ordinal": task.ordinal,
                "task_seed": task.seed,
                "task_dgp": task.dgp,
                "fold_index": spec.fold_index,
                "source_row_position": start + local_position,
                "entity_id": entity,
                "decision_date": date,
                "hofs_v7_expected_pe": float(values[0]),
                "hofs_v7_pe_p10": float(values[1]),
                "hofs_v7_pe_p90": float(values[2]),
                "hofs_v7_log_scale": float(values[3]),
                "hofs_v7_tail_guard_weight": float(values[4]),
                "parameter_sha256": parameter_sha256,
                "decision_block_ordered_membership_sha256": (
                    output.decision_block_ordered_membership_sha256
                ),
                "decision_block_set_membership_sha256": (
                    output.decision_block_set_membership_sha256
                ),
                "decision_source_positions_sha256": output.decision_source_positions_sha256,
                "output_manifest_sha256": output_manifest_sha256,
                "within_block_parameter_update_count": 0,
            }
            if tuple(row) != PREDICTION_COLUMNS:
                raise HofsResearchAdapterError("prediction source schema drifted")
            prediction_rows.append(row)
        fold_receipts.append(
            {
                "fold_index": spec.fold_index,
                "fit_prefix_end_exclusive": spec.fit_prefix_end_exclusive,
                "decision_block_start_inclusive": start,
                "decision_block_end_exclusive": end,
                "decision_rows": spec.decision_row_count,
                "fit_rows": fit_receipt.fit_row_count,
                "irls_iterations": fit_receipt.irls_iterations,
                "irls_converged": fit_receipt.irls_converged,
                "final_kkt_violation": fit_receipt.final_kkt_violation,
                "parameter_sha256": parameter_sha256,
                "fit_receipt_sha256": fit_receipt_sha256,
                "output_manifest_sha256": output_manifest_sha256,
                "elapsed_seconds": time.perf_counter() - fold_started,
            }
        )

    expected_rows = sum(item.decision_row_count for item in plan)
    if len(prediction_rows) != expected_rows or fit_resource is None or inference_resource is None:
        raise HofsResearchAdapterError("task aggregate geometry drifted")
    semantic_rows = canonical_json_bytes(prediction_rows)
    final_memory = _windows_process_memory()
    return {
        "task": task.payload(),
        "selected_fold_indices": list(selected_folds),
        "fit_count": len(plan),
        "prediction_row_count": len(prediction_rows),
        "prediction_rows_sha256": hashlib.sha256(semantic_rows).hexdigest(),
        "prediction_rows": prediction_rows,
        "fold_receipts": fold_receipts,
        "fold_receipts_semantic_sha256": hashlib.sha256(
            canonical_json_bytes(
                [{key: value for key, value in row.items() if key != "elapsed_seconds"} for row in fold_receipts]
            )
        ).hexdigest(),
        "fit_resource_receipt": fit_resource,
        "inference_resource_receipt": inference_resource,
        "worker_receipt": dict(_WORKER_RECEIPT),
        "worker_pid": os.getpid(),
        "worker_final_memory": final_memory,
        "worker_peak_rss_bytes": final_memory["peak_rss_bytes"],
        "elapsed_seconds": time.perf_counter() - task_started,
        "status": "PASS_RESEARCH_ONLY_HOFS_V7_NUMERIC_TASK",
    }


__all__ = ["_windows_process_memory", "execute_task", "initialize_worker"]
