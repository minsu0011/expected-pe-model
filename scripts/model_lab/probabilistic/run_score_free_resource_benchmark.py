from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute score-free 8/16/24/32 spawn parity")
    parser.add_argument("--repo-root", type=Path, default=_root())
    args = parser.parse_args()
    for key, value in {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "",
    }.items():
        os.environ[key] = value
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        sha256_file,
        verify_payload_seal,
    )
    from pe_regime_v04.model_lab.probabilistic.resources import (
        run_score_free_parity_benchmark,
    )

    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    replay_paths = (
        output / "MODEL_LAB_SERIALIZATION_REPLAY.json",
        output / "NGBOOST_SERIALIZATION_REPLAY.json",
    )
    replay_records = []
    candidate_ids: set[str] = set()
    for path in replay_paths:
        if not path.is_file():
            raise RuntimeError(f"serialization replay evidence missing: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        verify_payload_seal(payload)
        if payload.get("status") != "PASS":
            raise RuntimeError(f"serialization replay did not pass: {path}")
        candidate_ids.update(record["model_id"] for record in payload["records"])
        replay_records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "model_ids": [record["model_id"] for record in payload["records"]],
            }
        )
    expected = {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }
    if candidate_ids != expected:
        raise RuntimeError("serialization replay does not cover all three candidates")
    benchmark = run_score_free_parity_benchmark(rows=1296)
    if any(
        len(lane["observed_worker_pids"]) != lane["requested_processes"]
        for lane in benchmark["lanes"]
    ):
        raise RuntimeError("spawn benchmark did not observe every requested worker")
    payload = {
        "schema_version": "expected_pe_model_zoo.probabilistic_resource_runtime.v3",
        "status": "PASS_REAL_OUTER_FIT_SPAWN_PARITY_AND_RUNTIME_PROJECTION",
        "synthetic_only": True,
        "project_predictions_generated": False,
        "project_scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "serialization_replays": replay_records,
        "spawn_parity": benchmark,
        "formal_runtime_projection": benchmark["formal_runtime_projections"],
        "selected_worker_count": benchmark["selected_worker_count"],
        "selected_projection_maximum_candidate_minutes": benchmark[
            "selected_projection_maximum_candidate_minutes"
        ],
        "formal_runtime_projection_within_90_minutes": benchmark["projection_guard_passed"],
        "formal_execution_authorized": False,
        "retry_permitted": False,
    }
    immutable_write_json(output / "RESOURCE_RUNTIME_EVIDENCE_V3.json", payload)
    print(json.dumps({"status": payload["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
