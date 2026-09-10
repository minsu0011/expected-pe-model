"""Deterministic C4-R2 research runner over public/spent inputs."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import io
import math
import multiprocessing as mp
import os
import time
from typing import Any, Sequence

import numpy as np
import pandas as pd

from research.model_zoo.hofs_research_adapter_v1.contracts import (
    NONINFORMATIVE_GROUP_LABEL,
)
from research.model_zoo.hofs_research_adapter_v1.inputs import (
    TaskSpec,
    build_public_task_plan,
    canonical_path,
    read_canonical_bytes,
    verify_numeric_source_closure,
)

from .contracts import (
    GLOBAL_HOFS_LOG_SHRINK,
    NUMERIC_FAILURE_MESSAGES,
    C4R2ContractError,
    canonical_json_bytes,
    variant,
)


THREAD_ENVIRONMENT = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
    ("VECLIB_MAXIMUM_THREADS", "1"),
    ("CUDA_VISIBLE_DEVICES", "-1"),
    ("NVIDIA_VISIBLE_DEVICES", "void"),
)
SEED_ALIASES = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
_THREAD_LIMITER: Any = None


def _configure_variant(variant_id: str) -> None:
    global _THREAD_LIMITER
    selected = variant(variant_id)
    for name, value in THREAD_ENVIRONMENT:
        os.environ[name] = value
    if _THREAD_LIMITER is None:
        from threadpoolctl import threadpool_limits

        _THREAD_LIMITER = threadpool_limits(limits=1)
    verify_numeric_source_closure()
    import research.model_zoo.hierarchical_observable_fair_value_state_v7.estimator as estimator

    estimator.IRLS_MAX_ITERATIONS = selected.irls_max_iterations
    estimator.IRLS_TOLERANCE = selected.irls_tolerance


def _read_overlay_bytes(task: TaskSpec) -> bytes:
    path = canonical_path(task).with_name("v04_overlay.csv")
    if path.is_symlink() or not path.is_file():
        raise C4R2ContractError("spent v04 overlay is absent")
    return path.read_bytes()


def _source_and_overlay(
    canonical_raw: bytes,
    overlay_raw: bytes,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (
        adapt_r4_canonical_source_v7,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4 import (
        R4_CANONICAL_COLUMNS,
    )

    canonical = pd.read_csv(io.BytesIO(canonical_raw))
    source = adapt_r4_canonical_source_v7(canonical)
    if (
        tuple(source.columns) != R4_CANONICAL_COLUMNS
        or len(source) != 1_800
        or not source.index.equals(pd.RangeIndex(1_800))
    ):
        raise C4R2ContractError("C4-R2 canonical source geometry drifted")
    overlay = pd.read_csv(
        io.BytesIO(overlay_raw),
        usecols=["date", "symbol", "v04_expected_pe"],
        float_precision="round_trip",
    )
    if (
        len(overlay) != 1_800
        or not overlay.index.equals(pd.RangeIndex(1_800))
        or not overlay.loc[:, ["date", "symbol"]].equals(canonical.loc[:, ["date", "symbol"]])
    ):
        raise C4R2ContractError("C4-R2 v04 overlay identity drifted")
    v04 = pd.to_numeric(overlay["v04_expected_pe"], errors="coerce").to_numpy(dtype=np.float64)
    if not np.isfinite(v04[504:]).all() or np.any(v04[504:] <= 0.0):
        raise C4R2ContractError("C4-R2 v04 fallback is nonfinite")
    return source, overlay


def _is_numeric_solver_failure(exc: Exception) -> bool:
    return type(exc).__name__ == "HierarchicalStateV7ContractError" and str(exc) in (
        NUMERIC_FAILURE_MESSAGES
    )


def _fold_plan(task: TaskSpec | None) -> tuple[Any, ...]:
    if task is None:
        from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (
            build_qualification_fold_plan,
        )

        return build_qualification_fold_plan()
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (
        build_r4_fold_plan_v7,
    )

    plan = tuple(
        item for item in build_r4_fold_plan_v7() if item.seed == task.seed and item.dgp == task.dgp
    )
    if len(plan) != 62:
        raise C4R2ContractError("spent fold plan differs")
    return plan


def run_source_task(
    canonical_raw: bytes,
    overlay_raw: bytes,
    *,
    variant_id: str,
    task_label: str,
    seed_alias: str,
    dgp_id: str,
    spent_task: TaskSpec | None = None,
    fold_indices: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    """Run one public task and expose every numerical fallback in receipts."""

    selected = variant(variant_id)
    _configure_variant(variant_id)
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (
        build_hierarchical_state_features_v7,
        fit_chronological_prefix_v7,
        run_frozen_decision_block_v7,
    )

    source, overlay = _source_and_overlay(canonical_raw, overlay_raw)
    full_state = build_hierarchical_state_features_v7(source)
    full_state.assert_live_integrity()
    observed = source["observed_pe"].copy()
    groups = pd.Series(
        [NONINFORMATIVE_GROUP_LABEL] * len(source),
        index=source.index,
        dtype="object",
    )
    plan = _fold_plan(spent_task)
    selected_indices = tuple(range(len(plan))) if fold_indices is None else tuple(fold_indices)
    if (
        not selected_indices
        or tuple(sorted(set(selected_indices))) != selected_indices
        or any(index not in range(len(plan)) for index in selected_indices)
    ):
        raise C4R2ContractError("fold selection differs")
    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    terminal_failure: dict[str, Any] | None = None
    for fold_index in selected_indices:
        spec = plan[fold_index]
        fold_started = time.perf_counter()
        start = int(spec.decision_block_start_inclusive)
        end = int(spec.decision_block_end_exclusive)
        requested = full_state.identities.iloc[start:end].copy()
        fallback = False
        failure_reason: str | None = None
        fit_receipt: Any = None
        numeric: np.ndarray | None = None
        try:
            capability = fit_chronological_prefix_v7(
                source,
                decision_block_identities=requested,
                observed_pe=observed,
                research_dgp_groups=groups,
            )
            fit_receipt = capability.fit.fit_receipt
            output = run_frozen_decision_block_v7(
                source,
                requested_identities=requested,
                parameters=capability.fit.parameters,
            )
            numeric = output.values.to_numpy(dtype=np.float64)
        except Exception as exc:
            if not _is_numeric_solver_failure(exc):
                raise
            failure_reason = str(exc)
            if not selected.block_v04_fallback:
                terminal_failure = {
                    "fold_index": fold_index,
                    "decision_start": start,
                    "reason": failure_reason,
                }
                receipts.append(
                    {
                        "fold_index": fold_index,
                        "decision_start": start,
                        "decision_end": end,
                        "solver_converged": False,
                        "fallback": False,
                        "failure_reason": failure_reason,
                        "elapsed_seconds": time.perf_counter() - fold_started,
                    }
                )
                break
            fallback = True
        v04 = pd.to_numeric(
            overlay.loc[start : end - 1, "v04_expected_pe"], errors="coerce"
        ).to_numpy(dtype=np.float64)
        if fallback:
            raw_hofs_log = np.log(v04)
            expected_log = raw_hofs_log.copy()
        else:
            if numeric is None or not np.isfinite(numeric).all():
                raise C4R2ContractError("successful C4-R2 fold output is nonfinite")
            raw_hofs_log = np.log(numeric[:, 0])
            expected_log = np.log(v04) + GLOBAL_HOFS_LOG_SHRINK * (raw_hofs_log - np.log(v04))
        expected = np.exp(expected_log)
        if not np.isfinite(expected).all() or np.any(expected <= 0.0):
            raise C4R2ContractError("C4-R2 final prediction is nonfinite")
        fold_id = f"fold_{fold_index + 12:03d}"
        for local, position in enumerate(range(start, end)):
            rows.append(
                {
                    "seed_alias": seed_alias,
                    "dgp_id": dgp_id,
                    "session_position": position,
                    "date": str(overlay.at[position, "date"]),
                    "symbol": str(overlay.at[position, "symbol"]),
                    "fold_id": fold_id,
                    "variant_id": variant_id,
                    "v04_expected_log_pe": float(math.log(v04[local])),
                    "raw_hofs_expected_log_pe": float(raw_hofs_log[local]),
                    "expected_log_pe": float(expected_log[local]),
                    "expected_pe": float(expected[local]),
                    "hofs_available": not fallback,
                    "hofs_solver": "projected_box_huber_irls",
                    "hofs_converged": not fallback,
                    "hofs_iterations": (
                        None if fit_receipt is None else int(fit_receipt.irls_iterations)
                    ),
                    "hofs_fallback": fallback,
                    "hofs_failure_reason": failure_reason,
                }
            )
        receipts.append(
            {
                "fold_index": fold_index,
                "decision_start": start,
                "decision_end": end,
                "solver_converged": not fallback,
                "irls_iterations": (
                    None if fit_receipt is None else int(fit_receipt.irls_iterations)
                ),
                "final_coefficient_delta": (
                    None if fit_receipt is None else float(fit_receipt.final_coefficient_delta)
                ),
                "final_weight_delta": (
                    None if fit_receipt is None else float(fit_receipt.final_weight_delta)
                ),
                "final_kkt_violation": (
                    None if fit_receipt is None else float(fit_receipt.final_kkt_violation)
                ),
                "objective": (
                    None if fit_receipt is None else float(fit_receipt.final_huber_objective)
                ),
                "active_bound_count": (
                    None if fit_receipt is None else int(fit_receipt.active_bound_count)
                ),
                "fallback": fallback,
                "failure_reason": failure_reason,
                "elapsed_seconds": time.perf_counter() - fold_started,
            }
        )
    expected_rows = sum(
        int(plan[index].decision_block_end_exclusive)
        - int(plan[index].decision_block_start_inclusive)
        for index in selected_indices
    )
    finite_rows = sum(math.isfinite(float(row["expected_log_pe"])) for row in rows)
    payload_rows = [
        {
            key: value
            for key, value in row.items()
            if key not in ("hofs_iterations", "hofs_failure_reason")
        }
        for row in rows
    ]
    return {
        "task_label": task_label,
        "variant": selected.payload(),
        "fold_indices": list(selected_indices),
        "expected_rows": expected_rows,
        "prediction_rows": len(rows),
        "finite_prediction_rows": finite_rows,
        "availability": finite_rows / expected_rows,
        "solver_failure_count": sum(not row["solver_converged"] for row in receipts),
        "fallback_fold_count": sum(bool(row["fallback"]) for row in receipts),
        "fallback_row_count": sum(bool(row["hofs_fallback"]) for row in rows),
        "terminal_failure": terminal_failure,
        "prediction_semantic_sha256": hashlib.sha256(
            canonical_json_bytes(payload_rows)
        ).hexdigest(),
        "elapsed_seconds": time.perf_counter() - started,
        "rows": rows,
        "fold_receipts": receipts,
        "status": (
            "PASS_C4_R2_TASK_AVAILABLE"
            if terminal_failure is None and finite_rows == expected_rows
            else "FAIL_C4_R2_TASK_UNAVAILABLE"
        ),
    }


def _execute_spent_task(
    task: TaskSpec,
    variant_id: str,
    fold_indices: tuple[int, ...] | None,
) -> dict[str, Any]:
    seed_index = task.ordinal // 10
    return run_source_task(
        read_canonical_bytes(task),
        _read_overlay_bytes(task),
        variant_id=variant_id,
        task_label=f"spent_{task.ordinal:02d}",
        seed_alias=SEED_ALIASES[seed_index],
        dgp_id=task.dgp,
        spent_task=task,
        fold_indices=fold_indices,
    )


def _prediction_digest(results: Sequence[dict[str, Any]]) -> str:
    payload = [
        {
            "task_label": result["task_label"],
            "prediction_semantic_sha256": result["prediction_semantic_sha256"],
            "availability": result["availability"],
            "fallback_row_count": result["fallback_row_count"],
        }
        for result in results
    ]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def run_spent_batch(
    *,
    variant_id: str,
    workers: int,
    task_count: int = 50,
    fold_indices: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    tasks = build_public_task_plan()[:task_count]
    if type(workers) is not int or not 1 <= workers <= 32:
        raise C4R2ContractError("worker count is outside 1..32")
    started = time.perf_counter()
    context = mp.get_context("spawn")
    by_ordinal: dict[int, dict[str, Any]] = {}
    with ProcessPoolExecutor(max_workers=workers, mp_context=context) as executor:
        futures = {
            executor.submit(_execute_spent_task, task, variant_id, fold_indices): task.ordinal
            for task in tasks
        }
        for future in as_completed(futures):
            ordinal = futures[future]
            by_ordinal[ordinal] = future.result()
    results = [by_ordinal[task.ordinal] for task in tasks]
    elapsed = time.perf_counter() - started
    rows = [row for result in results for row in result["rows"]]
    receipts = [row for result in results for row in result["fold_receipts"]]
    return {
        "variant_id": variant_id,
        "workers": workers,
        "inner_threads": 1,
        "task_count": len(tasks),
        "fit_attempt_count": len(receipts),
        "prediction_rows": len(rows),
        "fallback_rows": sum(bool(row["hofs_fallback"]) for row in rows),
        "unavailable_tasks": sum(result["availability"] < 1.0 for result in results),
        "elapsed_seconds": elapsed,
        "fits_per_second": len(receipts) / elapsed,
        "tasks_per_second": len(tasks) / elapsed,
        "prediction_semantic_sha256": _prediction_digest(results),
        "rows": rows,
        "fold_receipts": receipts,
        "task_receipts": [
            {key: value for key, value in result.items() if key not in ("rows", "fold_receipts")}
            for result in results
        ],
        "status": (
            "PASS_C4_R2_SPENT_BATCH"
            if all(result["availability"] == 1.0 for result in results)
            else "FAIL_C4_R2_SPENT_BATCH"
        ),
    }


def run_worker_benchmark(variant_id: str) -> dict[str, Any]:
    rows = []
    batches = []
    fold_indices = (0, 20, 40, 61)
    for workers in (12, 16, 24, 32):
        batch = run_spent_batch(
            variant_id=variant_id,
            workers=workers,
            task_count=32,
            fold_indices=fold_indices,
        )
        batches.append(batch)
        rows.append(
            {
                "workers": workers,
                "inner_threads": 1,
                "task_count": batch["task_count"],
                "fit_attempt_count": batch["fit_attempt_count"],
                "elapsed_seconds": batch["elapsed_seconds"],
                "fits_per_second": batch["fits_per_second"],
                "prediction_semantic_sha256": batch["prediction_semantic_sha256"],
            }
        )
    if len({row["prediction_semantic_sha256"] for row in rows}) != 1:
        raise C4R2ContractError("worker benchmark changed deterministic predictions")
    selected = min(rows, key=lambda row: (float(row["elapsed_seconds"]), int(row["workers"])))
    return {
        "status": "PASS_C4_R2_WORKER_SCALING_BENCHMARK",
        "candidate_workers": [12, 16, 24, 32],
        "selected_workers": selected["workers"],
        "deterministic_result_equality": True,
        "rows": rows,
    }


__all__ = ["run_source_task", "run_spent_batch", "run_worker_benchmark"]
