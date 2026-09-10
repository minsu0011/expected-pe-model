"""Truth-blind, no-fit preflight for Structural V7 full-load topology."""

# ruff: noqa: E402 -- dependency verification precedes resource/numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_full_load_preflight_20260820"


def main() -> int:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DESIGN_LOCK_RAW_SHA256,
        load_design_lock,
        verify_full_dependency_freeze,
    )

    dependency_receipt = verify_full_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        MAX_OUTER_WORKERS,
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=MAX_OUTER_WORKERS)
    design = load_design_lock(ROOT)
    from research.model_zoo.structural_v7.contracts import (
        CANDIDATES,
        SPENT_SEEDS,
        seal_payload,
        sha256_file,
    )
    from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import load_preflight_v2
    from research.model_zoo.structural_v7_full_load.contracts import (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        lane_gpu_usage_receipt,
    )
    from research.model_zoo.structural_v7_full_load.topology import (
        build_full_load_topology,
    )

    v2_preflight = load_preflight_v2(ROOT)
    spent_inputs, input_evidence = load_spent_unscored_inputs(ROOT)
    topology = build_full_load_topology(spent_inputs)
    cache_bytes = sum(
        int(data.model_frame.memory_usage(deep=True).sum())
        + int(data.base_predictions.memory_usage(deep=True).sum())
        + int(data.dates.memory_usage(deep=True))
        for data in spent_inputs.values()
    )
    if (
        len(topology.base_tasks) != 740
        or len(topology.candidate_tasks) != 3100
        or len(CANDIDATES) != 10
        or topology.outer_schedule_sha256
        != "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
        or v2_preflight["hard_failure_count"] != 0
    ):
        raise RuntimeError("Structural full-load task topology or V2 preflight changed")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v7_full_load_no_fit_preflight",
            "status": "GO_FULL_LOAD_SOURCE_READY_ROOT_LAUNCH_APPROVAL_REQUIRED",
            "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
            "full_load_design_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "full_load_design_manifest_sha256": design["manifest_sha256"],
            "dependency_receipt": dependency_receipt.as_dict(),
            "v7_v2_preflight_manifest_sha256": v2_preflight["manifest_sha256"],
            "spent_seeds": list(SPENT_SEEDS),
            "candidate_count": len(CANDIDATES),
            "base_task_count": len(topology.base_tasks),
            "candidate_task_count": len(topology.candidate_tasks),
            "topology_sha256": topology.topology_sha256,
            "base_schedule_sha256": topology.base_schedule_sha256,
            "outer_schedule_sha256": topology.outer_schedule_sha256,
            "expected_prediction_rows": 5 * 1296 * 11,
            "v2_base_calls_no_fit_inspected": v2_preflight["base_fit_call_count"],
            "v2_candidate_outer_edges_no_fit_inspected": v2_preflight[
                "candidate_outer_consumer_edge_count"
            ],
            "v2_hard_failures": v2_preflight["hard_failure_count"],
            "truth_blind_worker_cache_mib": cache_bytes / 1024**2,
            "truth_blind_worker_cache_projection_32_mib": (
                cache_bytes * MAX_OUTER_WORKERS / 1024**2
            ),
            "resource_receipt": resource_receipt.as_dict(),
            "lane_gpu_usage": lane_gpu_usage_receipt(),
            "input_evidence": input_evidence,
            "parent_and_worker_dependency_guard_required": True,
            "parent_and_worker_resource_assertion_required": True,
            "stage_boundary_memory_assertion_required": True,
            "heavy_launch_authorized": False,
            "root_launch_approval_required": True,
            "fit_calls_executed": 0,
            "prediction_rows_generated": 0,
            "evaluation_truth_opened": False,
            "scores_computed": False,
        }
    )
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural full-load preflight exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "PREFLIGHT.json"
    path.write_bytes(raw)
    report = (
        "# Structural V7 Full-Load No-Fit Preflight\n\n"
        "- Status: source ready; exact root-session launch approval required.\n"
        "- Task graph: 740 base + 3,100 candidate/outer calls.\n"
        "- Expected output identity: 71,280 rows; outer schedule exact.\n"
        "- Full resource receipt: CPU0-31, outer32, inner1, RAM floor passed.\n"
        "- GPU is visible under the common lock and unused by this lane.\n"
        "- Fit/prediction/truth/score: 0/0/0/0.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
