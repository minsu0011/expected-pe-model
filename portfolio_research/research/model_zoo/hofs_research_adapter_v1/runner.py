"""Deterministic spawned orchestration for H-OFS research tasks."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import multiprocessing as mp
import time
from typing import Any, Sequence

from .contracts import (
    BENCHMARK_FOLD_INDICES,
    BENCHMARK_TASK_COUNT,
    BENCHMARK_WORKERS,
    FIT_COUNT,
    FOLDS_PER_TASK,
    FULL_OUTER_WORKERS,
    PREDICTION_ROW_COUNT,
    PROCESS_START_METHOD,
    TASK_COUNT,
    HofsResearchAdapterError,
    canonical_json_bytes,
)
from .inputs import TaskSpec, build_public_task_plan
from .worker import execute_task, initialize_worker


def _validate_task_subset(tasks: Sequence[TaskSpec]) -> tuple[TaskSpec, ...]:
    output = tuple(tasks)
    if not output or any(type(task) is not TaskSpec for task in output):
        raise HofsResearchAdapterError("task runner requires exact TaskSpec rows")
    ordinals = tuple(task.ordinal for task in output)
    if ordinals != tuple(sorted(set(ordinals))):
        raise HofsResearchAdapterError("task subset order/uniqueness drifted")
    return output


def _deterministic_result_digest(results: Sequence[dict[str, Any]]) -> str:
    payload = [
        {
            "task": result["task"],
            "selected_fold_indices": result["selected_fold_indices"],
            "fit_count": result["fit_count"],
            "prediction_row_count": result["prediction_row_count"],
            "prediction_rows_sha256": result["prediction_rows_sha256"],
            "fold_receipts_semantic_sha256": result["fold_receipts_semantic_sha256"],
        }
        for result in results
    ]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def run_task_batch(
    tasks: Sequence[TaskSpec],
    *,
    fold_indices: tuple[int, ...] | None,
    workers: int,
) -> dict[str, Any]:
    """Run a deterministic task batch with spawned, single-thread workers."""

    selected = _validate_task_subset(tasks)
    if type(workers) is not int or not 1 <= workers <= FULL_OUTER_WORKERS:
        raise HofsResearchAdapterError("outer worker count is outside the research contract")
    started = time.perf_counter()
    context = mp.get_context(PROCESS_START_METHOD)
    results_by_ordinal: dict[int, dict[str, Any]] = {}
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=context,
        initializer=initialize_worker,
    ) as executor:
        futures = {
            executor.submit(execute_task, task, fold_indices): task.ordinal for task in selected
        }
        for future in as_completed(futures):
            ordinal = futures[future]
            result = future.result()
            if result["task"]["ordinal"] != ordinal or ordinal in results_by_ordinal:
                raise HofsResearchAdapterError("worker result task custody drifted")
            results_by_ordinal[ordinal] = result
    elapsed = time.perf_counter() - started
    if set(results_by_ordinal) != {task.ordinal for task in selected}:
        raise HofsResearchAdapterError("worker task result universe is incomplete")
    results = [results_by_ordinal[task.ordinal] for task in selected]
    fit_count = sum(int(result["fit_count"]) for result in results)
    prediction_rows = sum(int(result["prediction_row_count"]) for result in results)
    worker_pids = sorted({int(result["worker_pid"]) for result in results})
    peak_by_pid: dict[int, int] = {}
    for result in results:
        pid = int(result["worker_pid"])
        peak = int(result["worker_peak_rss_bytes"])
        peak_by_pid[pid] = max(peak_by_pid.get(pid, 0), peak)
    return {
        "tasks": [task.payload() for task in selected],
        "task_count": len(selected),
        "fold_indices": list(range(FOLDS_PER_TASK)) if fold_indices is None else list(fold_indices),
        "outer_workers": workers,
        "inner_threads": 1,
        "process_start_method": PROCESS_START_METHOD,
        "fit_count": fit_count,
        "prediction_row_count": prediction_rows,
        "elapsed_seconds": elapsed,
        "fits_per_second": fit_count / elapsed,
        "prediction_rows_per_second": prediction_rows / elapsed,
        "worker_pid_count_used": len(worker_pids),
        "worker_pids": worker_pids,
        "worker_peak_rss_max_bytes": max(peak_by_pid.values()),
        "worker_peak_rss_sum_by_pid_bytes": sum(peak_by_pid.values()),
        "worker_peak_rss_by_pid_bytes": {
            str(pid): peak_by_pid[pid] for pid in sorted(peak_by_pid)
        },
        "deterministic_result_sha256": _deterministic_result_digest(results),
        "results": results,
        "status": "PASS_RESEARCH_ONLY_HOFS_TASK_BATCH",
    }


def run_one_task_smoke() -> dict[str, Any]:
    tasks = build_public_task_plan()
    result = run_task_batch(tasks[:1], fold_indices=None, workers=1)
    if result["fit_count"] != FOLDS_PER_TASK or result["prediction_row_count"] != 1_296:
        raise HofsResearchAdapterError("one-task smoke geometry drifted")
    return {**result, "mode": "ONE_TASK_FULL_62_FOLD_SMOKE"}


def run_worker_microbenchmark() -> dict[str, Any]:
    """Run equal 16-task/4-fold work at 4, 8, 12, and 16 workers."""

    tasks = build_public_task_plan()[:BENCHMARK_TASK_COUNT]
    batches: list[dict[str, Any]] = []
    for workers in BENCHMARK_WORKERS:
        batch = run_task_batch(
            tasks,
            fold_indices=BENCHMARK_FOLD_INDICES,
            workers=workers,
        )
        batches.append(batch)
    digests = {batch["deterministic_result_sha256"] for batch in batches}
    if len(digests) != 1:
        raise HofsResearchAdapterError("worker-count benchmark changed numeric predictions")
    baseline = float(batches[0]["elapsed_seconds"])
    rows: list[dict[str, Any]] = []
    for batch in batches:
        workers = int(batch["outer_workers"])
        elapsed = float(batch["elapsed_seconds"])
        speedup_vs_4 = baseline / elapsed
        rows.append(
            {
                "outer_workers": workers,
                "inner_threads": 1,
                "task_count": int(batch["task_count"]),
                "folds_per_task": len(BENCHMARK_FOLD_INDICES),
                "fit_count": int(batch["fit_count"]),
                "prediction_row_count": int(batch["prediction_row_count"]),
                "elapsed_seconds": elapsed,
                "fits_per_second": float(batch["fits_per_second"]),
                "prediction_rows_per_second": float(batch["prediction_rows_per_second"]),
                "speedup_vs_4_workers": speedup_vs_4,
                "parallel_efficiency_vs_4_workers": speedup_vs_4 / (workers / 4.0),
                "worker_pid_count_used": int(batch["worker_pid_count_used"]),
                "deterministic_result_sha256": batch["deterministic_result_sha256"],
            }
        )
    sixteen = next(row for row in rows if row["outer_workers"] == FULL_OUTER_WORKERS)
    estimated_full_seconds = FIT_COUNT / float(sixteen["fits_per_second"])
    return {
        "mode": "FIXED_WORK_4_8_12_16_WORKER_MICROBENCHMARK",
        "task_ordinals": [task.ordinal for task in tasks],
        "fold_indices": list(BENCHMARK_FOLD_INDICES),
        "rows": rows,
        "deterministic_result_sha256": next(iter(digests)),
        "estimated_full_seconds_from_16_worker_fit_throughput": estimated_full_seconds,
        "estimated_full_prediction_rows": PREDICTION_ROW_COUNT,
        "full_run_started": False,
        "batches": batches,
        "status": "PASS_RESEARCH_ONLY_FIXED_WORK_MICROBENCHMARK",
    }


def run_full_prediction() -> dict[str, Any]:
    """Run the exact full lane; callers must coordinate resources before invoking."""

    tasks = build_public_task_plan()
    result = run_task_batch(tasks, fold_indices=None, workers=FULL_OUTER_WORKERS)
    if (
        result["task_count"] != TASK_COUNT
        or result["fit_count"] != FIT_COUNT
        or result["prediction_row_count"] != PREDICTION_ROW_COUNT
    ):
        raise HofsResearchAdapterError("full prediction geometry drifted")
    return {**result, "mode": "FULL_50_TASK_3100_FIT_RESEARCH_PREDICTION"}


__all__ = [
    "run_full_prediction",
    "run_one_task_smoke",
    "run_task_batch",
    "run_worker_microbenchmark",
]
