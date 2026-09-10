"""Freeze, execute twice, and publish the C5-R2 compact research wave."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Mapping

import numpy as np

from .contracts import (
    CANDIDATE_ORDER,
    candidate_configuration,
    canonical_json_bytes,
    raw_sha256,
    semantic_sha256,
)
from .data import build_research_caches


EXPECTED_OUTPUT_NAME = "model_zoo_pe_c5_r2_sequence_research_v1_20260825"
DESIGN_LOCK_RELATIVE = (
    "outputs/model_zoo_pe_c5_r2_sequence_design_freeze_v1_20260824/"
    "C5_R2_SCIENTIFIC_DESIGN_LOCK.json"
)
TORCH_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
SOURCE_FILES = (
    "research/model_zoo/pe_c5_r2_sequence_research_v1/__init__.py",
    "research/model_zoo/pe_c5_r2_sequence_research_v1/contracts.py",
    "research/model_zoo/pe_c5_r2_sequence_research_v1/data.py",
    "research/model_zoo/pe_c5_r2_sequence_research_v1/evaluation.py",
    "research/model_zoo/pe_c5_r2_sequence_research_v1/orchestrator.py",
    "research/model_zoo/pe_c5_r2_sequence_research_v1/worker.py",
    "scripts/model_lab/pe_c5_r2_sequence_research_v1.py",
    "tests/model_lab/test_pe_c5_r2_sequence_research_v1.py",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _source_records(project_root: Path) -> list[dict[str, object]]:
    records = []
    for relative in SOURCE_FILES:
        path = (project_root / relative).resolve(strict=True)
        records.append(
            {
                "relative_path": relative,
                "raw_sha256": _sha(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return records


def _config_lock(project_root: Path) -> dict[str, object]:
    design_path = (project_root / DESIGN_LOCK_RELATIVE).resolve(strict=True)
    design = json.loads(design_path.read_text(encoding="utf-8"))
    if (
        design.get("status") != "FROZEN_SCORE_FREE_LEAKAGE_FREE_SEQUENCE_DESIGN"
        or design.get("target") != "true_log_fair_pe[t]-v04_expected_log_pe[t-1]"
        or design.get("input_source_constraint") != "max(source_position) < label_position"
        or design.get("fold_contract", {}).get("within_test_block_parameter_updates") != 0
        or design.get("fit_count") != 0
        or design.get("score_count") != 0
    ):
        raise RuntimeError("upstream C5-R2 scientific design lock differs")
    configuration = candidate_configuration()
    core = {
        "schema_version": "expected_pe.c5_r2.sequence_research.config_lock.v1",
        "status": "FROZEN_BEFORE_ANY_TRACK_LABEL_OPEN_OR_SCORE",
        "research_identity": "pe_c5_r2_sequence_research_v1_20260825",
        "upstream_design_lock": {
            "relative_path": DESIGN_LOCK_RELATIVE,
            "raw_sha256": _sha(design_path),
            "size_bytes": design_path.stat().st_size,
        },
        "candidate_configuration": configuration,
        "source_records": _source_records(project_root),
        "prelock_access": {
            "track_s_spent_truth_open_count": 0,
            "track_p_public_label_open_count": 0,
            "score_count": 0,
            "fit_count": 0,
            "fresh_or_heldout_open_count": 0,
        },
        "governance": {
            "track_s": "SIMULATOR_SPECIALIST_NOT_DEPLOYABLE_NOT_PROMOTION_ELIGIBLE",
            "track_p": "PIT_OBSERVABLE_RESEARCH_PROTOTYPE_NO_PROMOTION_AUTHORITY",
            "qualification_or_r3_used_for_candidate_selection": False,
            "formal_evidence": False,
            "production_promotion_authority": False,
        },
    }
    return {**core, "config_lock_semantic_sha256": semantic_sha256(core)}


def _nvidia_snapshot() -> dict[str, object]:
    command = [
        "nvidia-smi",
        "--query-gpu=name,driver_version,memory.total,memory.free,utilization.gpu,power.draw",
        "--format=csv,noheader,nounits",
        "--id=0",
    ]
    try:
        line = subprocess.check_output(command, text=True, timeout=10.0).strip()
        parts = [item.strip() for item in line.split(",")]
        return {
            "available": len(parts) == 6,
            "name": parts[0],
            "driver_version": parts[1],
            "memory_total_mib": float(parts[2]),
            "memory_free_mib": float(parts[3]),
            "utilization_percent": float(parts[4]),
            "power_draw_watts": float(parts[5]),
        }
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as exc:
        return {"available": False, "error_class": type(exc).__name__}


def _launch_worker(
    *,
    project_root: Path,
    root: Path,
    process_label: str,
    torch_python: Path,
) -> dict[str, object]:
    worker_path = project_root / ("research/model_zoo/pe_c5_r2_sequence_research_v1/worker.py")
    output_dir = root / f"process_{process_label.lower()}"
    output_dir.mkdir()
    command = [
        str(torch_python.resolve(strict=True)),
        "-I",
        "-B",
        str(worker_path.resolve(strict=True)),
        "--config-lock",
        str((root / "CANDIDATE_CONFIG_LOCK.json").resolve(strict=True)),
        "--data-manifest",
        str((root / "DATA_MANIFEST.json").resolve(strict=True)),
        "--public-cache",
        str((root / "work_cache/TRACK_P_PUBLIC_PANEL.npz").resolve(strict=True)),
        "--simulator-cache",
        str((root / "work_cache/TRACK_S_SIMULATOR_PANEL.npz").resolve(strict=True)),
        "--output-dir",
        str(output_dir.resolve(strict=True)),
        "--process-label",
        process_label,
    ]
    environment = os.environ.copy()
    environment.update(
        {
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
            "CUDA_VISIBLE_DEVICES": "0",
            "PYTHONHASHSEED": "0",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
        }
    )
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=False,
        check=False,
    )
    elapsed = time.perf_counter() - started
    launch = {
        "schema_version": "expected_pe.c5_r2.sequence_research.launch_receipt.v1",
        "process_label": process_label,
        "command_argv": command,
        "environment_contract": {
            key: environment[key]
            for key in (
                "CUBLAS_WORKSPACE_CONFIG",
                "CUDA_VISIBLE_DEVICES",
                "PYTHONHASHSEED",
                "OMP_NUM_THREADS",
                "MKL_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
            )
        },
        "exit_code": completed.returncode,
        "elapsed_seconds": elapsed,
        "stdout_raw_sha256": raw_sha256(completed.stdout),
        "stdout_size_bytes": len(completed.stdout),
        "stderr_raw_sha256": raw_sha256(completed.stderr),
        "stderr_size_bytes": len(completed.stderr),
    }
    _write_new(root / f"PROCESS_{process_label}_LAUNCH.json", canonical_json_bytes(launch))
    if completed.returncode != 0:
        diagnostic = {
            **launch,
            "stdout_tail": completed.stdout.decode("utf-8", errors="replace")[-4000:],
            "stderr_tail": completed.stderr.decode("utf-8", errors="replace")[-8000:],
        }
        _write_new(
            root / f"PROCESS_{process_label}_FAILURE.json",
            canonical_json_bytes(diagnostic),
        )
        raise RuntimeError(f"C5-R2 worker {process_label} failed")
    return launch


def _load_worker_predictions(path: Path) -> dict[str, dict[str, np.ndarray]]:
    result: dict[str, dict[str, np.ndarray]] = {}
    with np.load(path, allow_pickle=False) as archive:
        for key in archive.files:
            track, model = key.split("__", maxsplit=1)
            result.setdefault(track, {})[model] = archive[key].astype(np.float64)
    return result


def _fold_runtime_by_model(root: Path) -> dict[tuple[str, str], float]:
    payload = json.loads((root / "process_a/FOLD_RECEIPTS.json").read_text(encoding="utf-8"))
    result: dict[tuple[str, str], float] = {}
    for receipt in payload["receipts"]:
        key = (str(receipt["track"]), str(receipt["model"]))
        result[key] = result.get(key, 0.0) + float(receipt.get("elapsed_seconds", 0.0))
    return result


def _scorecard_rows(
    metrics_payload: Mapping[str, Any],
    model_runtime: Mapping[tuple[str, str], float],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    metrics_by_track = metrics_payload["metrics"]
    roles = {
        "S": ("SIMULATOR_SPECIALIST", False),
        "P": ("PIT_OBSERVABLE_RESEARCH", "RESEARCH_PROTOTYPE_ONLY"),
    }
    for track in ("S", "P"):
        role, deployable = roles[track]
        for model in CANDIDATE_ORDER:
            if model not in metrics_by_track[track]:
                continue
            metrics = metrics_by_track[track][model]
            core = metrics.get("core_complementarity", {})
            rows.append(
                {
                    "track": track,
                    "track_role": role,
                    "deployable": deployable,
                    "model": model,
                    "log_mae": metrics["mae"],
                    "log_rmse": metrics["rmse"],
                    "mae_gain_vs_persistence": metrics["mae_gain_vs_persistence"],
                    "rmse_gain_vs_persistence": metrics["rmse_gain_vs_persistence"],
                    "dgp_wins": metrics["dgp_wins"],
                    "worst_dgp_harm": metrics["worst_dgp_harm"],
                    "p95_absolute_error": metrics["p95_absolute_error"],
                    "p95_harm_vs_persistence": metrics["p95_harm_vs_persistence"],
                    "joint_tail_failures": metrics["systematic_joint_tail_failure_count"],
                    "jump_response_delay": metrics["jump_response_delay_median_sessions"],
                    "slow_state_log_mae": metrics["slow_state_log_mae"],
                    "shock_recovery_half_life": metrics["shock_recovery_half_life_median_sessions"],
                    "signed_error_corr_with_c4": core.get("C4", {}).get("signed_error_correlation"),
                    "absolute_error_corr_with_c4": core.get("C4", {}).get(
                        "absolute_error_correlation"
                    ),
                    "signed_error_corr_with_c2": core.get("C2", {}).get("signed_error_correlation"),
                    "absolute_error_corr_with_c2": core.get("C2", {}).get(
                        "absolute_error_correlation"
                    ),
                    "oracle_pair_gain_with_c4": core.get("C4", {}).get("oracle_pair_mae_gain"),
                    "oracle_pair_gain_with_c2": core.get("C2", {}).get("oracle_pair_mae_gain"),
                    "process_a_model_fit_seconds": model_runtime.get((track, model), 0.0),
                    "research_survivor": metrics["research_survivor_rule_pass"],
                    "decision": (
                        "RESEARCH_SURVIVOR"
                        if metrics["research_survivor_rule_pass"]
                        else "REJECT_OR_BASELINE_CONTROL"
                    ),
                }
            )
    return rows


def _scorecard_bytes(rows: list[dict[str, object]]) -> bytes:
    stream = __import__("io").StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _survivor_result(
    rows: list[dict[str, object]],
    *,
    parity_pass: bool,
    gru_triggered: bool,
) -> dict[str, object]:
    track_result: dict[str, dict[str, object]] = {}
    for track in ("S", "P"):
        candidates = [
            row
            for row in rows
            if row["track"] == track
            and row["model"] != "lagged_v04_persistence"
            and row["research_survivor"] is True
        ]
        candidates.sort(key=lambda row: float(row["log_mae"]))
        selected = str(candidates[0]["model"]) if candidates and parity_pass else None
        if track == "S":
            status = (
                "RESEARCH_SURVIVOR_SIMULATOR_SPECIALIST_NOT_DEPLOYABLE"
                if selected
                else "SATURATED_CURRENT_COMPACT_SIMULATOR_WAVE"
            )
        else:
            status = (
                "PIT_OBSERVABLE_RESEARCH_SURVIVOR_NO_PROMOTION_AUTHORITY"
                if selected
                else "SATURATED_CURRENT_COMPACT_PIT_OBSERVABLE_WAVE"
            )
        track_result[track] = {
            "status": status,
            "selected_model": selected,
            "deployable": False if track == "S" else "RESEARCH_PROTOTYPE_ONLY",
            "formal_evidence_required": bool(selected),
        }
    return {
        "schema_version": "expected_pe.c5_r2.sequence_research.result.v1",
        "status": (
            "PASS_COMPACT_RESEARCH_SURVIVOR_FOUND"
            if any(value["selected_model"] for value in track_result.values())
            else "SATURATED_CURRENT_COMPACT_SEQUENCE_WAVE"
        ),
        "prediction_digest_parity": parity_pass,
        "compact_gru_triggered": gru_triggered,
        "tracks": track_result,
        "track_s_governance": "SIMULATOR_SPECIALIST_NOT_DEPLOYABLE_NOT_PROMOTION_ELIGIBLE",
        "track_p_governance": "PIT_OBSERVABLE_RESEARCH_PROTOTYPE_NO_PROMOTION_AUTHORITY",
        "past_terminal_c5_identity_executed_or_modified": False,
        "qualification_or_r3_used_for_selection": False,
        "production_promotion_authority": False,
        "registry_mutation": False,
    }


def _report(rows: list[dict[str, object]], result: Mapping[str, Any]) -> bytes:
    lines = [
        "# C5-R2 causal sequence research 결과",
        "",
        "Track S는 spent simulator truth를 사용하는 `SIMULATOR_SPECIALIST`이며 배포 및 "
        "promotion 대상이 아니다. Track P는 다음 세션 observed log-P/E를 예측하는 "
        "PIT-observable 연구 prototype이고 역시 formal 권한이 없다.",
        "",
        "모든 평가 표본은 63개 source position이 label보다 작고, rolling test block 내부 "
        "parameter update는 0이다. Candidate config는 label open과 score 전에 봉인됐다.",
        "",
        "| Track | Model | MAE gain | RMSE gain | p95 harm | Joint-tail | C4 corr | C2 corr | Decision |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        c4 = row["signed_error_corr_with_c4"]
        c2 = row["signed_error_corr_with_c2"]
        lines.append(
            "| {track} | {model} | {mae:+.4%} | {rmse:+.4%} | {p95:.4%} | "
            "{tail} | {c4} | {c2} | {decision} |".format(
                track=row["track"],
                model=row["model"],
                mae=float(row["mae_gain_vs_persistence"]),
                rmse=float(row["rmse_gain_vs_persistence"]),
                p95=float(row["p95_harm_vs_persistence"]),
                tail=row["joint_tail_failures"],
                c4="-" if c4 is None else f"{float(c4):.4f}",
                c2="-" if c2 is None else f"{float(c2):.4f}",
                decision=row["decision"],
            )
        )
    lines.extend(
        [
            "",
            f"두 독립 프로세스 prediction digest parity: `{result['prediction_digest_parity']}`",
            f"Compact GRU conditional execution: `{result['compact_gru_triggered']}`",
            f"Track S: `{result['tracks']['S']['status']}`",
            f"Track P: `{result['tracks']['P']['status']}`",
            "",
            "이 결과는 research-only이며 기존 terminal C5, production champion, registry를 "
            "실행하거나 수정하지 않았다.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _checksums(root: Path) -> bytes:
    records = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "CHECKSUMS.sha256":
            continue
        records.append(f"{_sha(path)}  {relative}\n")
    return "".join(records).encode("ascii")


def run(
    *,
    project_root: Path,
    output_root: Path,
    torch_python: Path = TORCH_PYTHON,
) -> dict[str, object]:
    project = Path(project_root).resolve(strict=True)
    root = Path(output_root).resolve(strict=False)
    if root.exists() or root.parent != (project / "outputs").resolve(strict=True):
        raise RuntimeError("C5-R2 output root exists or escaped outputs")
    if root.name != EXPECTED_OUTPUT_NAME:
        raise RuntimeError("C5-R2 output root name differs")
    root.mkdir()
    started_utc = datetime.now(timezone.utc).isoformat()
    nvidia_before = _nvidia_snapshot()
    lock = _config_lock(project)
    lock_raw = canonical_json_bytes(lock)
    _write_new(root / "CANDIDATE_CONFIG_LOCK.json", lock_raw)
    config_hash = raw_sha256(lock_raw)
    build_research_caches(
        project_root=project,
        output_root=root,
        config_lock_raw_sha256=config_hash,
        workers=int(lock["candidate_configuration"]["runtime"]["cpu_data_workers"]),
    )
    launches = [
        _launch_worker(
            project_root=project,
            root=root,
            process_label=label,
            torch_python=torch_python,
        )
        for label in ("A", "B")
    ]
    receipts = [
        json.loads((root / f"process_{label.lower()}/WORKER_RECEIPT.json").read_text())
        for label in ("A", "B")
    ]
    metrics_raw = [
        (root / f"process_{label.lower()}/METRICS.json").read_bytes() for label in ("A", "B")
    ]
    predictions_a = _load_worker_predictions(root / "process_a/PREDICTIONS.npz")
    predictions_b = _load_worker_predictions(root / "process_b/PREDICTIONS.npz")
    array_parity = set(predictions_a) == set(predictions_b) and all(
        set(predictions_a[track]) == set(predictions_b[track])
        and all(
            np.array_equal(predictions_a[track][model], predictions_b[track][model])
            for model in predictions_a[track]
        )
        for track in predictions_a
    )
    digest_a = receipts[0]["execution"]["prediction_semantic_sha256"]
    digest_b = receipts[1]["execution"]["prediction_semantic_sha256"]
    metrics_parity = metrics_raw[0] == metrics_raw[1]
    parity_pass = bool(array_parity and digest_a == digest_b and metrics_parity)
    parity = {
        "schema_version": "expected_pe.c5_r2.sequence_research.prediction_parity.v1",
        "status": "PASS_TWO_PROCESS_EXACT_PREDICTION_PARITY" if parity_pass else "FAIL",
        "process_a_prediction_semantic_sha256": digest_a,
        "process_b_prediction_semantic_sha256": digest_b,
        "semantic_digest_equal": digest_a == digest_b,
        "all_prediction_arrays_exact_equal": array_parity,
        "deterministic_metrics_bytes_equal": metrics_parity,
        "process_a_predictions_file_raw_sha256": _sha(root / "process_a/PREDICTIONS.npz"),
        "process_b_predictions_file_raw_sha256": _sha(root / "process_b/PREDICTIONS.npz"),
    }
    _write_new(root / "PREDICTION_PARITY.json", canonical_json_bytes(parity))
    if not parity_pass:
        raise RuntimeError("two-process prediction parity failed")
    metrics_payload = json.loads(metrics_raw[0].decode("utf-8"))
    runtime_by_model = _fold_runtime_by_model(root)
    rows = _scorecard_rows(metrics_payload, runtime_by_model)
    scorecard_raw = _scorecard_bytes(rows)
    _write_new(root / "MODEL_SCORECARD.csv", scorecard_raw)
    _write_new(root / "METRICS.json", metrics_raw[0])
    result = _survivor_result(
        rows,
        parity_pass=parity_pass,
        gru_triggered=bool(metrics_payload["gru_triggered"]),
    )
    result["candidate_config_lock_raw_sha256"] = config_hash
    result["data_manifest_raw_sha256"] = _sha(root / "DATA_MANIFEST.json")
    result["scorecard_raw_sha256"] = raw_sha256(scorecard_raw)
    result["prediction_semantic_sha256"] = digest_a
    _write_new(root / "RESULT.json", canonical_json_bytes(result))
    _write_new(root / "REPORT.md", _report(rows, result))
    source_manifest = {
        "schema_version": "expected_pe.c5_r2.sequence_research.source_manifest.v1",
        "source_records": _source_records(project),
        "upstream_design_lock": lock["upstream_design_lock"],
        "source_drift_count_after_execution": sum(
            _sha(project / item["relative_path"]) != item["raw_sha256"]
            for item in lock["source_records"]
        ),
    }
    _write_new(root / "SOURCE_MANIFEST.json", canonical_json_bytes(source_manifest))
    runtime = {
        "schema_version": "expected_pe.c5_r2.sequence_research.runtime_receipt.v1",
        "started_at_utc": started_utc,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "cpu": {
            "declared": "AMD Ryzen 9 7950X3D 16-Core Processor",
            "logical_cpu_count": os.cpu_count(),
            "data_builder_workers": 16,
            "inner_blas_threads": 1,
        },
        "ram": {"total_declared_gib": 96, "memory_map_required": False},
        "gpu_before": nvidia_before,
        "gpu_after": _nvidia_snapshot(),
        "worker_receipts": receipts,
        "worker_launches": launches,
        "actual_gpu_use_all_workers": all(
            item["gpu"]["actual_gpu_use"] is True for item in receipts
        ),
        "total_worker_wall_seconds": sum(float(item["elapsed_seconds"]) for item in launches),
        "total_gpu_worker_hours": sum(float(item["elapsed_seconds"]) for item in launches) / 3600.0,
    }
    _write_new(root / "RUNTIME_RECEIPT.json", canonical_json_bytes(runtime))
    _write_new(root / "CHECKSUMS.sha256", _checksums(root))
    return result


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--torch-python", type=Path, default=TORCH_PYTHON)
    args = parser.parse_args()
    result = run(
        project_root=args.project_root,
        output_root=args.output_root,
        torch_python=args.torch_python,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["EXPECTED_OUTPUT_NAME", "run"]
