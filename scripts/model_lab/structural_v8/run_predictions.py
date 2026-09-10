"""Root-approved Structural V8 prediction-only full spent screen."""

# ruff: noqa: E402 -- dependency/resource checks precede numerical imports.

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

APPROVAL_TOKEN = "STRUCTURAL_V8_PREDICTION_ONLY_ROOT_APPROVED_20260820"


def _initialize_worker(project_root: str, outer_workers: int) -> None:
    from research.model_zoo.structural_v8.post_freeze_pins import (
        load_design_lock,
        load_preflight,
        load_smoke,
        verify_dependency_freeze,
    )

    root = Path(project_root)
    verify_dependency_freeze(root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        assert_full_load_process,
    )

    receipt = assert_full_load_process(outer_workers=outer_workers)
    load_design_lock(root)
    load_preflight(root)
    load_smoke(root)
    from research.model_zoo.structural_v8.runner import initialize_worker

    initialize_worker(root, receipt.as_dict())


def _run_task(task: tuple[int, str, int]) -> dict[str, Any]:
    from research.model_zoo.structural_v8.runner import run_candidate_task

    return run_candidate_task(task)


def _worker_receipts(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    receipts = {
        int(receipt["pid"]): receipt
        for result in results
        if (receipt := result.get("worker_receipt")) is not None
    }
    return [receipts[pid] for pid in sorted(receipts)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Structural V8 predictions")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--launch-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.launch_approval != APPROVAL_TOKEN:
        raise SystemExit("Structural V8 prediction requires the exact root-session token")
    from research.model_zoo.structural_v8.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        SMOKE_RAW_SHA256,
        load_design_lock,
        load_preflight,
        load_smoke,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        assert_full_load_process,
        seal_full_load_process,
    )

    parent_receipt = seal_full_load_process(outer_workers=args.workers)
    design = load_design_lock(args.project_root)
    preflight = load_preflight(args.project_root)
    smoke = load_smoke(args.project_root)
    if design.get("heavy_prediction_authorized") is not False:
        raise SystemExit("Structural V8 frozen design launch gate changed")
    from research.model_zoo.structural_v8.data import load_v8_truth_blind_inputs
    from research.model_zoo.structural_v8.evaluation_identity import (
        validate_exact_evaluation_identity,
    )
    from research.model_zoo.structural_v8.preflight import inspect_all_outer_calls
    from research.model_zoo.structural_v8.runner import (
        assemble_prediction_frames,
        candidate_tasks,
    )

    inputs, input_evidence = load_v8_truth_blind_inputs(args.project_root)
    current_preflight = inspect_all_outer_calls(inputs)
    if current_preflight.as_dict() != preflight["all_call_receipt"]:
        raise SystemExit("Structural V8 all-call topology changed after preflight")
    tasks = candidate_tasks()
    if len(tasks) != 1240 or len(set(tasks)) != 1240:
        raise SystemExit("Structural V8 execution task identity changed")
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=args.workers,
        mp_context=context,
        initializer=_initialize_worker,
        initargs=(str(args.project_root.resolve()), args.workers),
    ) as executor:
        results = list(executor.map(_run_task, tasks, chunksize=1))
    boundary_receipt = assert_full_load_process(outer_workers=args.workers)
    predictions, diagnostics, runtime = assemble_prediction_frames(inputs, results)
    spent_inputs = {seed: bundle.spent for seed, bundle in inputs.items()}
    identity_receipt = validate_exact_evaluation_identity(predictions, spent_inputs)
    from research.model_zoo.structural_v8.artifacts import write_prediction_bundle

    manifest = write_prediction_bundle(
        predictions,
        diagnostics,
        args.output_directory,
        metadata={
            "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
            "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "design_manifest_sha256": design["manifest_sha256"],
            "preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "smoke_raw_sha256": SMOKE_RAW_SHA256,
            "smoke_manifest_sha256": smoke["manifest_sha256"],
            "dependency_receipt": dependency_receipt.as_dict(),
            "parent_resource_receipt": parent_receipt.as_dict(),
            "terminal_boundary_receipt": boundary_receipt.as_dict(),
            "worker_receipts": _worker_receipts(results),
            "lane_gpu_usage": {
                "gpu_visible_under_common_lock": True,
                "candidate_gpu_usage": False,
                "gpu_candidate_ids": [],
            },
            "all_call_receipt": current_preflight.as_dict(),
            "evaluation_identity_receipt": identity_receipt.as_dict(),
            "input_evidence": input_evidence,
            "approval_token_class": "ROOT_SESSION_PREDICTION_ONLY_APPROVAL",
        },
        runtime_seconds_by_model=runtime,
    )
    print(manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
