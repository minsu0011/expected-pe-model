"""Freeze the Structural V7 full-load execution design without fitting."""

# ruff: noqa: E402 -- frozen dependency/resource checks precede numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_full_load_design_20260820"


def main() -> int:
    from research.model_zoo.structural_v7_full_load.contracts import (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        CPU_IDS,
        CPU_INNER_THREADS,
        MAX_OUTER_WORKERS,
        RAM_MIN_FREE_GIB,
        RAM_SOFT_BUDGET_GIB,
        V7_V2_DEPENDENCY_RAW_SHA256,
        V7_V2_DESIGN_RAW_SHA256,
        V7_V2_PREFLIGHT_RAW_SHA256,
        lane_gpu_usage_receipt,
        load_common_full_load_lock,
    )

    common_lock = load_common_full_load_lock(ROOT)
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        load_design_lock_v2,
        load_preflight_v2,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    v2_design = load_design_lock_v2(ROOT)
    v2_preflight = load_preflight_v2(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=MAX_OUTER_WORKERS)
    from research.model_zoo.structural_v7.contracts import (
        CANDIDATES,
        SPENT_SEEDS,
        candidate_design_payload,
        seal_payload,
        sha256_file,
    )
    from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
    from research.model_zoo.structural_v7_full_load.topology import (
        build_full_load_topology,
    )

    spent_inputs, input_evidence = load_spent_unscored_inputs(ROOT)
    topology = build_full_load_topology(spent_inputs)
    cache_bytes = sum(
        int(data.model_frame.memory_usage(deep=True).sum())
        + int(data.base_predictions.memory_usage(deep=True).sum())
        + int(data.dates.memory_usage(deep=True))
        for data in spent_inputs.values()
    )
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural full-load design exists: {OUTPUT}")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v7_full_load_execution_design",
            "status": "FROZEN_ROOT_LAUNCH_APPROVAL_REQUIRED",
            "locked_at_date_kst": "2026-08-20",
            "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
            "common_full_load_lock_schema": common_lock["schema_version"],
            "v7_v2_dependency_raw_sha256": V7_V2_DEPENDENCY_RAW_SHA256,
            "v7_v2_design_raw_sha256": V7_V2_DESIGN_RAW_SHA256,
            "v7_v2_preflight_raw_sha256": V7_V2_PREFLIGHT_RAW_SHA256,
            "v7_v2_design_manifest_sha256": v2_design["manifest_sha256"],
            "v7_v2_preflight_manifest_sha256": v2_preflight["manifest_sha256"],
            "v7_v2_dependency_receipt": dependency_receipt.as_dict(),
            "evidence_class": "EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "production_promotion_allowed": False,
            "fresh_or_heldout_allowed": False,
            "spent_seeds": list(SPENT_SEEDS),
            "candidate_count": len(CANDIDATES),
            "candidates": candidate_design_payload(),
            "candidate_or_minimum_change_from_v2": False,
            "same_target": "true_fair_pe",
            "same_evaluator": (
                "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament"
            ),
            "parallel_execution": {
                "architecture": "two global spawn-process stages",
                "stage_1": "740 independent seed/base/fold refits",
                "stage_2": "3100 independent seed/candidate/outer calls",
                "base_task_count": len(topology.base_tasks),
                "candidate_task_count": len(topology.candidate_tasks),
                "base_schedule_sha256": topology.base_schedule_sha256,
                "outer_schedule_sha256": topology.outer_schedule_sha256,
                "topology_sha256": topology.topology_sha256,
                "worker_cache_loaded_only_after_dependency_guard": True,
                "within_outer_test_target_updates": False,
                "retry_policy": "none; record family/fold failure and continue",
            },
            "expected_prediction_identity": {
                "seed_count": 5,
                "rows_per_seed_model": 1296,
                "model_count": 11,
                "total_rows": 71280,
                "outer_schedule_sha256": (
                    "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
                ),
                "exact_gate_before_artifact_and_before_truth": True,
            },
            "resource_policy": {
                "logical_cpu_ids": list(CPU_IDS),
                "max_outer_workers": MAX_OUTER_WORKERS,
                "cpu_inner_threads": CPU_INNER_THREADS,
                "ram_soft_budget_gib": RAM_SOFT_BUDGET_GIB,
                "ram_min_free_gib": RAM_MIN_FREE_GIB,
                "parent_and_every_worker_re_attested": True,
                "stage_boundary_memory_re_attested": True,
                "truth_blind_cache_mib_per_worker": cache_bytes / 1024**2,
                "truth_blind_cache_projection_32_workers_mib": (
                    cache_bytes * MAX_OUTER_WORKERS / 1024**2
                ),
                "lane_auxiliary_memory_budget_gib": 12.0,
            },
            "lane_gpu_usage": lane_gpu_usage_receipt(),
            "design_freeze_resource_receipt": resource_receipt.as_dict(),
            "input_evidence": input_evidence,
            "user_full_load_authority_received": True,
            "heavy_launch_authorized_by_frozen_design": False,
            "heavy_launch_gate": "exact root-session launch token after independent audit",
            "fit_calls_executed": 0,
            "prediction_rows_generated": 0,
            "evaluation_truth_opened": False,
            "scores_computed": False,
            "out_of_scope": [
                "production or registry mutation",
                "fresh or heldout data",
                "promotion evidence",
                "reuse of earlier structural authority or failure chains",
            ],
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "DESIGN_LOCK.json"
    path.write_bytes(raw)
    report = (
        "# Structural V7 Full-Load Design\n\n"
        "- Parent: common CPU0-31 / outer<=32 / inner1 / RAM80+free12 lock.\n"
        "- GPU: visible under the common lock, unused by all ten Structural candidates.\n"
        "- Plan: 740 base tasks, then 3,100 candidate/outer tasks.\n"
        "- Expected prediction identity: 71,280 rows.\n"
        "- State: frozen; root-session launch approval still required.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
