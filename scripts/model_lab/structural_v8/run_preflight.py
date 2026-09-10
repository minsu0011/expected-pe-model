"""Run exact all-call, no-fit Structural V8 preflight."""

# ruff: noqa: E402 -- dependency verification precedes numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

OUTPUT = ROOT / "outputs/model_zoo_structural_v8_preflight_20260820"


def main() -> int:
    from research.model_zoo.structural_v8.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        load_design_lock,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        MAX_OUTER_WORKERS,
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=MAX_OUTER_WORKERS)
    design = load_design_lock(ROOT)
    from research.model_zoo.structural_v8.contracts import (
        CANDIDATES,
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        SPENT_SEEDS,
        seal_payload,
        sha256_file,
    )
    from research.model_zoo.structural_v8.data import load_v8_truth_blind_inputs
    from research.model_zoo.structural_v8.preflight import inspect_all_outer_calls

    inputs, input_evidence = load_v8_truth_blind_inputs(ROOT)
    receipt = inspect_all_outer_calls(inputs)
    if (
        receipt.edge_count != 1240
        or receipt.planned_fit_call_count != 930
        or receipt.planned_transform_only_count != 310
        or receipt.hard_failure_count != 0
        or receipt.min_meta_usable_rows != 252
        or receipt.min_structural_usable_rows != 502
        or receipt.outer_schedule_sha256
        != "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
    ):
        raise RuntimeError("Structural V8 exact no-fit topology changed")
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V8 preflight exists: {OUTPUT}")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v8_all_call_no_fit_preflight",
            "status": "AUDIT_READY_HEAVY_PREDICTION_APPROVAL_REQUIRED",
            "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
            "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "design_manifest_sha256": design["manifest_sha256"],
            "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
            "dependency_receipt": dependency_receipt.as_dict(),
            "spent_seeds": list(SPENT_SEEDS),
            "candidate_count": len(CANDIDATES),
            "all_call_receipt": receipt.as_dict(),
            "expected_prediction_rows": 5 * 1296 * (1 + len(CANDIDATES)),
            "hard_min_rationale_verified": {
                "hard_min": 200,
                "preferred_min": 252,
                "empirical_earliest_meta_rows": receipt.min_meta_usable_rows,
                "empirical_earliest_structural_rows": receipt.min_structural_usable_rows,
                "preferred_shortfall_edges": receipt.preferred_min_shortfall_count,
                "expanded_hierarchical_dimension_upper_bound": 4 * (24 + 1),
                "statement": (
                    "Regularization makes these expanded systems executable; neither "
                    "hard_min=200 nor the empirical 250/502 counts claim adequacy."
                ),
            },
            "rbf_runtime_bound": {
                "nystroem_components": 64,
                "max_meta_rows": receipt.max_meta_usable_rows,
                "max_basis_elements": receipt.max_rbf_basis_rows,
                "exact_n_by_n_kernel_materialized": False,
            },
            "input_evidence": input_evidence,
            "resource_receipt": resource_receipt.as_dict(),
            "lane_gpu_usage": {
                "gpu_visible_under_common_lock": True,
                "candidate_gpu_usage": False,
                "gpu_candidate_ids": [],
            },
            "parent_and_every_worker_dependency_guard_required": True,
            "parent_and_every_worker_resource_assertion_required": True,
            "fit_calls_executed": 0,
            "prediction_rows_generated": 0,
            "evaluation_truth_opened": False,
            "scores_computed": False,
            "heavy_prediction_authorized": False,
            "separate_evaluation_approval_required": True,
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "PREFLIGHT.json"
    path.write_bytes(raw)
    (OUTPUT / "REPORT.md").write_text(
        "# Structural V8 All-Call No-Fit Preflight\n\n"
        "- Inspected 1,240 exact outer consumer edges: 930 planned fits and 310 "
        "fixed-gate transforms.\n"
        "- Earliest residual-meta/structural usable rows: 252/502; hard floor 200.\n"
        "- Exact prediction identity: 32,400 rows after an approved run.\n"
        "- Fit/prediction/truth/score: 0/0/0/0.\n",
        encoding="utf-8",
        newline="\n",
    )
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
