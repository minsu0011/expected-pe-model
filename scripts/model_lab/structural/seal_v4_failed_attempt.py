"""Seal the failed V4 spent attempt without opening evaluation truth."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import (  # noqa: E402
    load_predict_inputs,
    load_wave1_seed_frames,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
)


SPENT = ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819"
OUTPUT = SPENT / "V4_FAILED_ATTEMPT.json"
EXPECTED_SEEDS = (6301, 6421, 6521, 6607, 6701)
EXPECTED_FOLDS = tuple(f"fold_{index:03d}" for index in range(12, 74))
EXPECTED_ERROR = "decomposition observed_pe must be non-empty, positive, and finite"


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable failure receipt already exists: {path}")
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _file(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "raw_sha256": sha256_file(path),
    }


def main() -> int:
    stderr = SPENT / "RUNNER_STDERR.log"
    stdout = SPENT / "RUNNER_STDOUT.log"
    text = stderr.read_text(encoding="utf-8")
    if EXPECTED_ERROR not in text:
        raise RuntimeError("V4 failure log does not contain the exact fail-closed exception")
    prediction = SPENT / "prediction"
    published = sorted(path.name for path in prediction.glob("*") if path.is_file())
    if published:
        raise RuntimeError("V4 failure unexpectedly published prediction files")

    manifest = load_predict_inputs(
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
    )
    invalid: list[dict[str, Any]] = []
    for row in manifest["seeds"]:
        frame, _ = load_wave1_seed_frames(row)
        target = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(
            dtype=np.float64, na_value=np.nan
        )
        positions = np.flatnonzero((~np.isfinite(target)) | (target <= 0.0)).tolist()
        invalid.append(
            {
                "seed": int(row["seed"]),
                "invalid_session_positions": positions,
                "invalid_values": [
                    None if not np.isfinite(target[pos]) else target[pos] for pos in positions
                ],
            }
        )
    if tuple(row["seed"] for row in invalid) != EXPECTED_SEEDS or any(
        row["invalid_session_positions"] != [0, 1] for row in invalid
    ):
        raise RuntimeError("spent target invalid-identity audit changed")

    failed_python = Path("C:/Users/minsu/anaconda3/python.exe").resolve(strict=True)
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v4_terminal_failed_spent_attempt",
            "status": "TERMINAL_FAILED_NO_PREDICTION_ARTIFACT",
            "prediction_process": {
                "parent_pid": 27700,
                "started_kst": "2026-08-19T13:17:56+09:00",
                "terminated_kst": "2026-08-19T14:18:29+09:00",
                "exit_success": False,
                "stderr": _file(stderr),
                "stdout": _file(stdout),
                "exact_exception": EXPECTED_ERROR,
            },
            "failed_runtime": {
                "launcher_path": failed_python.as_posix(),
                "launcher_bytes": failed_python.stat().st_size,
                "launcher_raw_sha256": sha256_file(failed_python),
                "observed_python": "3.13.9",
                "stdlib_observed_in_traceback": "C:/Users/minsu/anaconda3/Lib",
                "intended_runtime_used": False,
            },
            "v4_execution_chain": {
                "runner_raw_sha256": (
                    "cc5c3345baf6319a2e1f5612ba9735b0cbd86943810a9219c3c9f87502e398f0"
                ),
                "activation_raw_sha256": (
                    "ed469d17308afbaaec23558ee31230912c9daca9936b765046f335b74b4da467"
                ),
                "authority_policy_raw_sha256": (
                    "2c1c27fbe315746fe21a4c1a4d24734a8c05b8c370fc1fec08059a3f447b1a71"
                ),
                "external_policy_pin_raw_sha256": (
                    "9f5cff33f207cf8d4f7bd7d66a37670c34ab04d1513844d67a09af408694cdd1"
                ),
            },
            "failure_diagnosis": {
                "invalid_target_identities": invalid,
                "affected_candidates": [
                    "decomp_block_ridge_ar1_lag1",
                    "decomp_block_ridge_ar1_current",
                ],
                "affected_required_fold_ids": list(EXPECTED_FOLDS),
                "reason": "every required outer-train window contains warm-up positions 0 and 1",
                "formal_prediction_positions_invalid_count": 0,
                "evaluation_truth_opened": False,
                "scores_computed": False,
            },
            "custody": {
                "published_prediction_files": published,
                "prediction_manifest_exists": (prediction / "PREDICTION_MANIFEST.json").exists(),
                "evaluator_started": False,
                "truth_opened": False,
            },
            "resource_observation": {
                "approximate_wall_seconds": 3633,
                "approximate_aggregate_cpu_seconds": 10600,
                "peak_observed_aggregate_rss_gib": 1.856,
                "minimum_observed_free_ram_gib": 70.67,
                "initial_workers": 8,
                "load_imbalance": (
                    "one full-62-fold candidate-by-seed payload produced an approximately "
                    "one-hour serial tail during fail-path executor shutdown"
                ),
            },
            "supersession": {
                "relaunch_authorized": False,
                "requires_new_runner_activation_policy_and_independent_go": True,
            },
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
