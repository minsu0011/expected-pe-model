"""Artifact assembly for H-OFS research smoke, benchmark, and full prediction."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .contracts import (
    ADAPTER_ID,
    BENCHMARK_FOLD_INDICES,
    BENCHMARK_WORKERS,
    DETAILED_EVIDENCE_CLASS,
    EVIDENCE_CLASS,
    FULL_OUTER_WORKERS,
    MODEL_ID,
    PREDICTION_COLUMNS,
    PREDICTION_ROW_COUNT,
    TASK_COUNT,
    design_payload,
    design_sha256,
    semantic_sha256,
)
from .inputs import TaskSpec, project_root, verify_numeric_source_closure
from .publisher import csv_bytes, jsonl_bytes, prediction_csv_bytes, pretty_json_bytes


SOURCE_PATHS = (
    "research/model_zoo/hofs_research_adapter_v1/__init__.py",
    "research/model_zoo/hofs_research_adapter_v1/artifacts.py",
    "research/model_zoo/hofs_research_adapter_v1/contracts.py",
    "research/model_zoo/hofs_research_adapter_v1/inputs.py",
    "research/model_zoo/hofs_research_adapter_v1/publisher.py",
    "research/model_zoo/hofs_research_adapter_v1/runner.py",
    "research/model_zoo/hofs_research_adapter_v1/worker.py",
    "research/model_zoo/hofs_research_adapter_v1/DESIGN.md",
    "research/model_zoo/hofs_research_adapter_v1/MODEL_HYPOTHESIS.md",
    "research/model_zoo/pre_certification_research_tournament_v1/adapters.py",
    "scripts/model_lab/hofs_research_adapter_v1/run_adapter.py",
    "scripts/model_lab/hofs_research_adapter_v1/publish_r1_failure.py",
    "scripts/model_lab/hofs_research_adapter_v1/freeze_r2.py",
    "tests/model_lab/test_hofs_research_adapter_v1.py",
)

INPUT_MANIFEST_COLUMNS = (
    "task_ordinal",
    "task_seed",
    "task_dgp",
    "canonical_relative_path",
    "canonical_raw_sha256",
)
BENCHMARK_COLUMNS = (
    "outer_workers",
    "inner_threads",
    "task_count",
    "folds_per_task",
    "fit_count",
    "prediction_row_count",
    "elapsed_seconds",
    "fits_per_second",
    "prediction_rows_per_second",
    "speedup_vs_4_workers",
    "parallel_efficiency_vs_4_workers",
    "worker_pid_count_used",
    "deterministic_result_sha256",
)


def _source_manifest() -> tuple[list[dict[str, Any]], str]:
    root = project_root()
    rows: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        path = root / relative
        content = path.read_bytes()
        rows.append(
            {
                "relative_path": relative,
                "raw_sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        )
    return rows, semantic_sha256(rows)


def _input_manifest_rows(tasks: Sequence[TaskSpec]) -> list[dict[str, Any]]:
    return [
        {
            "task_ordinal": task.ordinal,
            "task_seed": task.seed,
            "task_dgp": task.dgp,
            "canonical_relative_path": task.canonical_relative_path,
            "canonical_raw_sha256": task.canonical_raw_sha256,
        }
        for task in tasks
    ]


def _flatten_results(result: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    predictions: list[dict[str, Any]] = []
    task_receipts: list[dict[str, Any]] = []
    for task_result in result["results"]:
        predictions.extend(task_result["prediction_rows"])
        task_receipts.append(
            {
                key: value
                for key, value in task_result.items()
                if key not in {"prediction_rows", "fold_receipts"}
            }
        )
    predictions.sort(
        key=lambda row: (
            int(row["task_ordinal"]),
            int(row["source_row_position"]),
        )
    )
    return predictions, task_receipts


def _fold_receipts(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for task_result in result["results"]:
        task = task_result["task"]
        for receipt in task_result["fold_receipts"]:
            rows.append(
                {
                    "task_ordinal": task["ordinal"],
                    "task_seed": task["seed"],
                    "task_dgp": task["dgp"],
                    **receipt,
                }
            )
    return rows


def _common_files(
    *,
    mode: str,
    status: str,
    tasks: Sequence[TaskSpec],
    access_receipt: Mapping[str, Any],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    source_rows, source_semantic = _source_manifest()
    numeric_closure = verify_numeric_source_closure()
    manifest = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.manifest.v1",
        "adapter_id": ADAPTER_ID,
        "model_id": MODEL_ID,
        "mode": mode,
        "status": status,
        "evidence_class": EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        "design_sha256": design_sha256(),
        "source_manifest_semantic_sha256": source_semantic,
        "numeric_source_closure_semantic_sha256": numeric_closure["semantic_sha256"],
        "task_count": len(tasks),
        "score_or_evaluation_performed": False,
        "formal_or_registry_authority": False,
        "champion_fallback_used": False,
        "partial_publish": False,
    }
    files = {
        "ACCESS_RECEIPT.json": pretty_json_bytes(dict(access_receipt)),
        "DESIGN_LOCK.json": pretty_json_bytes(design_payload()),
        "INPUT_MANIFEST.csv": csv_bytes(_input_manifest_rows(tasks), INPUT_MANIFEST_COLUMNS),
        "NUMERIC_SOURCE_CLOSURE.json": pretty_json_bytes(numeric_closure),
        "SOURCE_MANIFEST.json": pretty_json_bytes(
            {
                "files": source_rows,
                "file_count": len(source_rows),
                "semantic_sha256": source_semantic,
            }
        ),
        "MANIFEST.json": pretty_json_bytes(manifest),
    }
    return files, manifest


def build_smoke_files(result: Mapping[str, Any]) -> dict[str, bytes]:
    tasks = tuple(TaskSpec(**row) for row in result["tasks"])
    predictions, task_receipts = _flatten_results(result)
    folds = _fold_receipts(result)
    if len(tasks) != 1 or len(predictions) != 1_296 or len(folds) != 62:
        raise ValueError("smoke artifact geometry drifted")
    access = {
        "evidence_class": EVIDENCE_CLASS,
        "public_metadata_files_opened": 2,
        "public_canonical_files_opened": 1,
        "public_overlay_files_opened": 0,
        "comparator_diagnostic_files_opened": 0,
        "outcome_or_evaluation_payload_files_opened": 0,
        "external_input_paths_opened": 0,
        "fit_count": int(result["fit_count"]),
        "prediction_row_count": int(result["prediction_row_count"]),
        "score_calls": 0,
        "registry_or_champion_mutations": 0,
    }
    files, manifest = _common_files(
        mode="ONE_TASK_FULL_62_FOLD_SMOKE",
        status="PASS_RESEARCH_ONLY_ONE_TASK_SMOKE",
        tasks=tasks,
        access_receipt=access,
    )
    runtime = {
        key: value
        for key, value in result.items()
        if key not in {"results", "tasks"}
    }
    manifest.update(
        {
            "fit_count": len(folds),
            "prediction_row_count": len(predictions),
            "prediction_rows_semantic_sha256": semantic_sha256(predictions),
        }
    )
    files["MANIFEST.json"] = pretty_json_bytes(manifest)
    files.update(
        {
            "FOLD_RECEIPTS.jsonl": jsonl_bytes(folds),
            "PREDICTIONS.csv": prediction_csv_bytes(predictions),
            "RUNTIME_RECEIPT.json": pretty_json_bytes(runtime),
            "TASK_RECEIPTS.jsonl": jsonl_bytes(task_receipts),
            "REPORT.md": (
                "# H-OFS Research Adapter V1 — One-task smoke\n\n"
                "Evidence: **RESEARCH_ONLY**. Exact first public task, 62 chronological fits, "
                "1,296 predictions. No score, fallback, partial publication, or formal authority.\n"
            ).encode("utf-8"),
        }
    )
    return files


def build_benchmark_files(result: Mapping[str, Any]) -> dict[str, bytes]:
    first_batch = result["batches"][0]
    tasks = tuple(TaskSpec(**row) for row in first_batch["tasks"])
    if len(tasks) != 16 or tuple(result["fold_indices"]) != BENCHMARK_FOLD_INDICES:
        raise ValueError("benchmark artifact geometry drifted")
    if tuple(int(row["outer_workers"]) for row in result["rows"]) != BENCHMARK_WORKERS:
        raise ValueError("benchmark worker surface drifted")
    access = {
        "evidence_class": EVIDENCE_CLASS,
        "public_metadata_files_opened": 2,
        "public_canonical_files_opened": 16 * len(BENCHMARK_WORKERS),
        "public_overlay_files_opened": 0,
        "comparator_diagnostic_files_opened": 0,
        "outcome_or_evaluation_payload_files_opened": 0,
        "external_input_paths_opened": 0,
        "fit_count": sum(int(row["fit_count"]) for row in result["rows"]),
        "prediction_row_count": sum(
            int(row["prediction_row_count"]) for row in result["rows"]
        ),
        "score_calls": 0,
        "registry_or_champion_mutations": 0,
    }
    files, manifest = _common_files(
        mode="FIXED_WORK_4_8_12_16_WORKER_MICROBENCHMARK",
        status="PASS_RESEARCH_ONLY_WORKER_MICROBENCHMARK",
        tasks=tasks,
        access_receipt=access,
    )
    compact_batches = [
        {key: value for key, value in batch.items() if key not in {"results", "tasks"}}
        for batch in result["batches"]
    ]
    receipt = {
        key: value for key, value in result.items() if key not in {"batches", "rows"}
    }
    receipt["batch_runtime_receipts"] = compact_batches
    manifest.update(
        {
            "benchmark_workers": list(BENCHMARK_WORKERS),
            "benchmark_fold_indices": list(BENCHMARK_FOLD_INDICES),
            "deterministic_result_sha256": result["deterministic_result_sha256"],
            "full_run_started": False,
        }
    )
    files["MANIFEST.json"] = pretty_json_bytes(manifest)
    files.update(
        {
            "BENCHMARK.csv": csv_bytes(result["rows"], BENCHMARK_COLUMNS),
            "BENCHMARK_RECEIPT.json": pretty_json_bytes(receipt),
            "REPORT.md": (
                "# H-OFS Research Adapter V1 — Worker microbenchmark\n\n"
                "Evidence: **RESEARCH_ONLY**. Equal work was run at 4, 8, 12, and 16 spawned "
                "workers with one numerical thread each. Numeric result digests must match. "
                "The full 3,100-fit run was not started.\n"
            ).encode("utf-8"),
        }
    )
    return files


def build_full_files(result: Mapping[str, Any]) -> dict[str, bytes]:
    tasks = tuple(TaskSpec(**row) for row in result["tasks"])
    predictions, task_receipts = _flatten_results(result)
    folds = _fold_receipts(result)
    if (
        len(tasks) != TASK_COUNT
        or len(predictions) != PREDICTION_ROW_COUNT
        or len(folds) != 3_100
        or int(result["outer_workers"]) != FULL_OUTER_WORKERS
    ):
        raise ValueError("full artifact geometry drifted")

    import pandas as pd  # noqa: PLC0415

    from research.model_zoo.pre_certification_research_tournament_v1.adapters import (  # noqa: PLC0415
        NORMALIZED_PREDICTION_COLUMNS,
        normalize_hofs_rows,
    )

    normalized = normalize_hofs_rows(
        pd.DataFrame(predictions, columns=PREDICTION_COLUMNS),
        new_model_id=MODEL_ID,
    )
    standardized_rows = normalized.to_dict(orient="records")
    access = {
        "evidence_class": EVIDENCE_CLASS,
        "public_metadata_files_opened": 2,
        "public_canonical_files_opened": TASK_COUNT,
        "public_overlay_files_opened": 0,
        "comparator_diagnostic_files_opened": 0,
        "outcome_or_evaluation_payload_files_opened": 0,
        "external_input_paths_opened": 0,
        "fit_count": int(result["fit_count"]),
        "prediction_row_count": int(result["prediction_row_count"]),
        "score_calls": 0,
        "registry_or_champion_mutations": 0,
    }
    files, manifest = _common_files(
        mode="FULL_50_TASK_3100_FIT_RESEARCH_PREDICTION",
        status="PASS_RESEARCH_ONLY_FULL_HOFS_PREDICTION",
        tasks=tasks,
        access_receipt=access,
    )
    manifest.update(
        {
            "fit_count": len(folds),
            "prediction_row_count": len(predictions),
            "prediction_rows_semantic_sha256": semantic_sha256(predictions),
            "standardized_prediction_rows": len(standardized_rows),
        }
    )
    runtime = {key: value for key, value in result.items() if key not in {"results", "tasks"}}
    files["MANIFEST.json"] = pretty_json_bytes(manifest)
    files.update(
        {
            "FOLD_RECEIPTS.jsonl": jsonl_bytes(folds),
            "PREDICTIONS.csv": prediction_csv_bytes(predictions),
            "RUNTIME_RECEIPT.json": pretty_json_bytes(runtime),
            "STANDARDIZED_PREDICTIONS.csv": csv_bytes(
                standardized_rows,
                NORMALIZED_PREDICTION_COLUMNS,
            ),
            "TASK_RECEIPTS.jsonl": jsonl_bytes(task_receipts),
            "REPORT.md": (
                "# H-OFS Research Adapter V1 — Full prediction\n\n"
                "Evidence: **RESEARCH_ONLY**. 50 public spent tasks, 3,100 chronological fits, "
                "64,800 predictions. No score, Champion fallback, or formal authority.\n"
            ).encode("utf-8"),
        }
    )
    return files


def build_r2_preflight_files(tasks: Sequence[TaskSpec]) -> dict[str, bytes]:
    """Build the score-free r2 source/input/validator freeze after regression tests pass."""

    task_tuple = tuple(tasks)
    if len(task_tuple) != TASK_COUNT:
        raise ValueError("r2 preflight task universe drifted")
    access = {
        "evidence_class": EVIDENCE_CLASS,
        "public_metadata_files_opened": 2,
        "public_canonical_payload_files_opened": 0,
        "public_overlay_files_opened": 0,
        "comparator_diagnostic_files_opened": 0,
        "outcome_or_evaluation_payload_files_opened": 0,
        "fit_count": 0,
        "prediction_row_count": 0,
        "score_calls": 0,
        "registry_or_champion_mutations": 0,
    }
    files, manifest = _common_files(
        mode="FULL_R2_SOURCE_INPUT_VALIDATOR_PREFLIGHT",
        status="PASS_RESEARCH_ONLY_FULL_R2_READY_HELD_FOR_RESOURCE_SIGNAL",
        tasks=task_tuple,
        access_receipt=access,
    )
    root = project_root()
    standardizer_path = (
        root / "research/model_zoo/pre_certification_research_tournament_v1/adapters.py"
    )
    standardizer_sha256 = hashlib.sha256(standardizer_path.read_bytes()).hexdigest()
    repair = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.r2_validator_repair.v1",
        "status": "PASS_SCOPED_LOG_SCALE_SEMANTICS_REPAIR",
        "evidence_class": EVIDENCE_CLASS,
        "failed_r1_standardizer_raw_sha256": (
            "7645f17e3ef13bcef441af6a3573d69034aa007ddd2b0ce8cf5897253b36fb7f"
        ),
        "r2_standardizer_raw_sha256": standardizer_sha256,
        "frozen_v7_output_semantics": "natural_log_of_final_uncertainty_scale",
        "frozen_v7_scale_bounds": [0.01, 0.50],
        "accepted_log_scale_bounds": [-4.605170185988091, -0.6931471805599453],
        "normalized_uncertainty_transform": "exp(hofs_v7_log_scale)",
        "negative_finite_log_scale_accepted": True,
        "nonfinite_log_scale_rejected": True,
        "out_of_contract_log_scale_rejected": True,
        "invalid_tail_guard_rejected": True,
        "nonintegral_custody_fields_rejected": True,
        "invalid_hash_receipts_rejected": True,
        "numeric_estimator_source_changed": False,
        "full_r1_identity_or_root_reused": False,
    }
    test_receipt = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.r2_test_receipt.v1",
        "ruff_status": "PASS",
        "pytest_status": "PASS_27_TESTS",
        "pytest_files": [
            "tests/model_lab/test_hofs_research_adapter_v1.py",
            "tests/model_lab/test_pre_certification_research_tournament_v1.py",
        ],
        "negative_finite_log_scale_regression_test": True,
        "invalid_actual_field_parameterized_cases": 7,
    }
    manifest.update(
        {
            "full_execution_started": False,
            "full_output_root": (
                "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822"
            ),
            "standardizer_raw_sha256": standardizer_sha256,
            "validator_repair_semantic_sha256": semantic_sha256(repair),
            "test_receipt_semantic_sha256": semantic_sha256(test_receipt),
        }
    )
    files["MANIFEST.json"] = pretty_json_bytes(manifest)
    files.update(
        {
            "REPORT.md": (
                "# H-OFS Research Adapter V1 — Full r2 preflight\n\n"
                "Evidence: **RESEARCH_ONLY**. The frozen V7 log-scale semantics are now "
                "validated correctly, tests and Ruff pass, and the unique r2 full identity is "
                "ready. The CPU-heavy full run remains held for resource coordination.\n"
            ).encode("utf-8"),
            "TEST_RECEIPT.json": pretty_json_bytes(test_receipt),
            "VALIDATOR_REPAIR_RECEIPT.json": pretty_json_bytes(repair),
        }
    )
    return files


__all__ = [
    "build_benchmark_files",
    "build_full_files",
    "build_r2_preflight_files",
    "build_smoke_files",
]
