"""Bind the scored Structural V7 tournament and one broken candidate."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


PREDICTION = ROOT / "outputs/model_zoo_structural_v7_full_load_prediction_20260820"
EVALUATION = ROOT / "outputs/model_zoo_structural_v7_full_load_evaluation_20260820"
OUTPUT = ROOT / "outputs/model_zoo_structural_v7_full_load_terminal_20260820"
PREDICTION_MANIFEST_RAW_SHA256 = (
    "b623e0e1963b975f610dac20f6a46b9bda30896fd910f48669293449b7c4835e"
)
EVALUATION_MANIFEST_RAW_SHA256 = (
    "239abcffb266725b76a56cf57cca623f79a96611c312e6c81b7ddd6851916cb0"
)
BROKEN_MODEL_ID = "s3_residual_state_space_v04_v7"
METRIC_FIELDS = (
    "mean_mae_relative_gain",
    "mean_rmse_relative_gain",
    "seed_wins",
    "seed_count",
    "seed_win_rate",
    "worst_relative_harm",
    "signed_error_correlation",
    "absolute_error_correlation",
    "oracle_fair_log_mae",
    "oracle_fair_log_rmse",
    "oracle_mae_relative_gain",
    "error_sign_disagreement_rate",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_manifest(directory: Path, expected_hash: str) -> tuple[dict[str, Any], bytes]:
    raw = (directory / "MANIFEST.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise RuntimeError(f"sealed manifest changed: {directory}")
    payload = json.loads(raw.decode("utf-8"))
    for name, expected in payload["artifact_sha256"].items():
        if _sha(directory / name) != expected:
            raise RuntimeError(f"sealed artifact changed: {directory / name}")
    return payload, raw


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _number(value: str, *, integer: bool = False) -> int | float:
    return int(value) if integer else float(value)


def _comparison_registry_row(row: dict[str, str], rank: int) -> dict[str, Any]:
    metrics = {
        field: _number(field_value, integer=field in {"seed_wins", "seed_count"})
        for field in METRIC_FIELDS
        if (field_value := row[field]) != ""
    }
    if set(metrics) != set(METRIC_FIELDS):
        raise RuntimeError("scoreable comparison contains null metrics")
    return {
        "rank": rank,
        "model_id": row["model_id"],
        "prediction_status": "SCOREABLE_EXPLORATION_ONLY",
        "evaluation_status": row["status"],
        "failure_policy": None,
        "metrics": metrics,
        "tournament_gate_pass": row["tournament_gate_pass"] == "True",
        "research_continue": row["research_continue"] == "True",
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
    }


def main() -> int:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        load_design_lock,
        verify_full_dependency_freeze,
    )

    dependency_receipt = verify_full_dependency_freeze(ROOT)
    design = load_design_lock(ROOT)
    prediction_manifest, _ = _load_manifest(
        PREDICTION, PREDICTION_MANIFEST_RAW_SHA256
    )
    evaluation_manifest, _ = _load_manifest(
        EVALUATION, EVALUATION_MANIFEST_RAW_SHA256
    )
    comparisons = _read_csv(EVALUATION / "comparisons.csv")
    summaries = _read_csv(EVALUATION / "summary.csv")
    diagnostics = _read_csv(PREDICTION / "diagnostics.csv")
    if len(comparisons) != 9 or len(evaluation_manifest["model_ids"]) != 10:
        raise RuntimeError("scoreable common-mask model universe changed")
    if BROKEN_MODEL_ID in evaluation_manifest["model_ids"]:
        raise RuntimeError("broken model contaminated the common evaluation mask")
    registry = [
        _comparison_registry_row(row, rank)
        for rank, row in enumerate(comparisons, start=1)
    ]
    candidate_ids = [row["candidate_id"] for row in design["candidates"]]
    if set(candidate_ids) != {row["model_id"] for row in registry} | {BROKEN_MODEL_ID}:
        raise RuntimeError("terminal candidate universe changed")
    broken_calls = [row for row in diagnostics if row["model_id"] == BROKEN_MODEL_ID]
    failure_pairs = {
        (row["exception_type"], row["exception_message"]) for row in broken_calls
    }
    if len(broken_calls) != 310 or len(failure_pairs) != 1 or any(
        row["status"] != "FAILED_NO_RETRY" for row in broken_calls
    ):
        raise RuntimeError("broken state-space failure identity changed")
    exception_type, exception_message = next(iter(failure_pairs))
    registry.append(
        {
            "rank": None,
            "model_id": BROKEN_MODEL_ID,
            "prediction_status": "BROKEN",
            "evaluation_status": "BROKEN/FAILED_NO_RETRY",
            "failure_policy": {
                "failed_call_count": 310,
                "exception_type": exception_type,
                "exception_message": exception_message,
                "common_mask_included": False,
                "metrics_are_null": True,
            },
            "metrics": {field: None for field in METRIC_FIELDS},
            "tournament_gate_pass": False,
            "research_continue": False,
            "evidence_class": "EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        }
    )
    if any(row["tournament_gate_pass"] for row in registry):
        status = "POSITIVE_TOURNAMENT_GATE_NEW_WAVE_HELD"
    else:
        status = "ALL_9_SCOREABLE_REJECTED_ONE_BROKEN_NEXT_WAVE_REVIEW_ALLOWED"
    incumbent = next(row for row in summaries if row["model_id"] == "v04_expected_pe")
    parent_design = json.loads(
        (ROOT / "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json").read_text(
            encoding="utf-8"
        )
    )
    registry_payload = {
        "schema_version": "structural_v7.exploration_terminal_registry.v1",
        "status": status,
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "fresh_or_heldout_used": False,
        "incumbent_model_id": "v04_expected_pe",
        "incumbent_fair_log_mae": float(incumbent["fair_log_mae"]),
        "incumbent_fair_log_rmse": float(incumbent["fair_log_rmse"]),
        "locked_thresholds": parent_design["tournament_thresholds"],
        "common_mask": {
            "scoreable_candidate_count": 9,
            "model_count_including_incumbent": 10,
            "rows_per_model": 6480,
            "row_error_rows": evaluation_manifest["row_counts"]["row_errors.csv"],
            "broken_candidate_excluded": True,
        },
        "candidates": registry,
    }
    registry_raw = json.dumps(
        registry_payload, ensure_ascii=False, indent=2, allow_nan=False
    ).encode("utf-8") + b"\n"
    fieldnames = (
        "rank",
        "model_id",
        "prediction_status",
        "evaluation_status",
        *METRIC_FIELDS,
        "tournament_gate_pass",
        "research_continue",
    )
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in registry:
        writer.writerow(
            {
                "rank": row["rank"],
                "model_id": row["model_id"],
                "prediction_status": row["prediction_status"],
                "evaluation_status": row["evaluation_status"],
                **row["metrics"],
                "tournament_gate_pass": row["tournament_gate_pass"],
                "research_continue": row["research_continue"],
            }
        )
    ranking_raw = buffer.getvalue().encode("utf-8")
    report = (
        "# Structural V7 Full-Load Terminal Tournament\n\n"
        f"Status: `{status}`\n\n"
        "- Nine complete candidates were scored with the central incumbent on one mask.\n"
        "- All nine fail the locked standalone/research-continuation gates.\n"
        "- The state-space residual candidate is BROKEN/FAILED_NO_RETRY; metrics are null.\n"
        "- Broken rows were excluded before the common mask and do not alter other metrics.\n"
        "- Evidence remains exploration-only; production and registry promotion are forbidden.\n"
    ).encode("utf-8")
    payloads = {
        "TOURNAMENT_REGISTRY.json": registry_raw,
        "RANKING.csv": ranking_raw,
        "REPORT.md": report,
    }
    manifest = {
        "schema_version": "structural_v7.exploration_terminal_manifest.v1",
        "mode": "structural_v7_full_load_terminal_tournament",
        "status": status,
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "production_registry_modified": False,
        "fresh_or_heldout_used": False,
        "prediction_manifest_raw_sha256": PREDICTION_MANIFEST_RAW_SHA256,
        "evaluation_manifest_raw_sha256": EVALUATION_MANIFEST_RAW_SHA256,
        "full_load_design_raw_sha256": (
            "89e2c110a2fa2f21f52152e5cc6d944845fc70f4685b082d1e85644315be4d3c"
        ),
        "dependency_receipt": dependency_receipt.as_dict(),
        "source_record": {
            "path": Path(__file__).resolve().relative_to(ROOT).as_posix(),
            "raw_sha256": _sha(Path(__file__).resolve()),
        },
        "artifact_sha256": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(payloads.items())
        },
        "row_counts": {"registry_candidates": 10, "scored": 9, "broken": 1},
        "truth_scope": "already-spent five-seed evaluation truth only",
        "scores_recomputed_in_terminal_step": False,
        "prediction_manifest_mode": prediction_manifest["mode"],
    }
    manifest_raw = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if OUTPUT.exists():
        raise FileExistsError(f"immutable terminal directory exists: {OUTPUT}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="structural_v7_terminal_", dir=OUTPUT.parent) as temp:
        staging = Path(temp) / "payload"
        staging.mkdir()
        for name, raw in payloads.items():
            (staging / name).write_bytes(raw)
        (staging / "MANIFEST.json").write_bytes(manifest_raw)
        os.replace(staging, OUTPUT)
    print(hashlib.sha256(manifest_raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
