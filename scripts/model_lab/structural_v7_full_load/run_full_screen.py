"""Root-approved 32-process Structural V7 full spent-seed screen."""

# ruff: noqa: E402 -- dependency/resource verification precedes numerical imports.

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from pathlib import Path
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


APPROVAL_TOKEN = "STRUCTURAL_V7_FULL_LOAD_ROOT_APPROVED_20260820"


def _initialize_base_worker(project_root: str, outer_workers: int) -> None:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        load_design_lock,
        load_preflight,
        verify_full_dependency_freeze,
    )

    root = Path(project_root)
    verify_full_dependency_freeze(root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        assert_full_load_process,
    )

    receipt = assert_full_load_process(outer_workers=outer_workers)
    load_design_lock(root)
    load_preflight(root)
    from research.model_zoo.structural_v7_full_load.parallel_runner import (
        initialize_base_worker,
    )

    initialize_base_worker(root, receipt.as_dict())


def _initialize_candidate_worker(
    project_root: str,
    outer_workers: int,
    base_cache_path: str,
) -> None:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        load_design_lock,
        load_preflight,
        verify_full_dependency_freeze,
    )

    root = Path(project_root)
    verify_full_dependency_freeze(root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        assert_full_load_process,
    )

    receipt = assert_full_load_process(outer_workers=outer_workers)
    load_design_lock(root)
    load_preflight(root)
    from research.model_zoo.structural_v7_full_load.parallel_runner import (
        initialize_candidate_worker,
    )

    initialize_candidate_worker(root, Path(base_cache_path), receipt.as_dict())


def _base_task(task: tuple[int, str, int]) -> dict[str, Any]:
    from research.model_zoo.structural_v7_full_load.parallel_runner import run_base_task

    return run_base_task(task)


def _candidate_task(task: tuple[int, str, int]) -> dict[str, Any]:
    from research.model_zoo.structural_v7_full_load.parallel_runner import (
        run_candidate_task,
    )

    return run_candidate_task(task)


def _worker_receipts(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    receipts = {
        int(receipt["pid"]): receipt
        for result in results
        if (receipt := result.get("worker_receipt")) is not None
    }
    return [receipts[pid] for pid in sorted(receipts)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Structural V7 full-load screen")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--launch-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.launch_approval != APPROVAL_TOKEN:
        raise SystemExit("Structural full-load launch requires the exact root-session token")
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        load_design_lock,
        load_preflight,
        verify_full_dependency_freeze,
    )

    dependency_receipt = verify_full_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        assert_full_load_process,
        seal_full_load_process,
    )

    parent_receipt = seal_full_load_process(outer_workers=args.workers)
    design = load_design_lock(args.project_root)
    preflight = load_preflight(args.project_root)
    if design.get("heavy_launch_authorized_by_frozen_design") is not False:
        raise SystemExit("Structural full-load frozen design gate changed")
    from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
    from research.model_zoo.structural_v7.evaluation_identity import (
        validate_exact_evaluation_identity,
    )
    from research.model_zoo.structural_v7_full_load.contracts import (
        lane_gpu_usage_receipt,
    )
    from research.model_zoo.structural_v7_full_load.parallel_runner import (
        assemble_base_surfaces,
        assemble_prediction_frames,
        save_base_surface_cache,
    )
    from research.model_zoo.structural_v7_full_load.topology import (
        build_full_load_topology,
    )

    spent_inputs, input_evidence = load_spent_unscored_inputs(args.project_root)
    topology = build_full_load_topology(spent_inputs)
    if topology.topology_sha256 != preflight["topology_sha256"]:
        raise SystemExit("Structural full-load task topology changed after preflight")
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=args.workers,
        mp_context=context,
        initializer=_initialize_base_worker,
        initargs=(str(args.project_root.resolve()), args.workers),
    ) as executor:
        base_results = list(executor.map(_base_task, topology.base_tasks, chunksize=1))
    stage_1_receipt = assert_full_load_process(outer_workers=args.workers)
    base_surfaces, base_diagnostics, base_runtime = assemble_base_surfaces(
        spent_inputs, base_results
    )

    args.output_directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="structural_v7_full_load_",
        dir=args.output_directory.parent,
    ) as temporary:
        base_cache_path = Path(temporary) / "base_surfaces.npz"
        save_base_surface_cache(base_cache_path, base_surfaces)
        with ProcessPoolExecutor(
            max_workers=args.workers,
            mp_context=context,
            initializer=_initialize_candidate_worker,
            initargs=(
                str(args.project_root.resolve()),
                args.workers,
                str(base_cache_path),
            ),
        ) as executor:
            candidate_results = list(
                executor.map(_candidate_task, topology.candidate_tasks, chunksize=1)
            )
    stage_2_receipt = assert_full_load_process(outer_workers=args.workers)
    predictions, diagnostics, runtime = assemble_prediction_frames(
        spent_inputs,
        base_surfaces,
        candidate_results,
        base_diagnostics,
        base_runtime,
    )
    identity_receipt = validate_exact_evaluation_identity(predictions, spent_inputs)
    from research.model_zoo.structural_v7.artifacts import write_prediction_bundle

    manifest = write_prediction_bundle(
        predictions,
        diagnostics,
        args.output_directory,
        metadata={
            "full_load_dependency_manifest_raw_sha256": (
                DEPENDENCY_MANIFEST_RAW_SHA256
            ),
            "full_load_design_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "full_load_design_manifest_sha256": design["manifest_sha256"],
            "full_load_preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
            "full_load_preflight_manifest_sha256": preflight["manifest_sha256"],
            "dependency_receipt": dependency_receipt.as_dict(),
            "parent_resource_receipt": parent_receipt.as_dict(),
            "stage_1_boundary_receipt": stage_1_receipt.as_dict(),
            "stage_2_boundary_receipt": stage_2_receipt.as_dict(),
            "stage_1_worker_receipts": _worker_receipts(base_results),
            "stage_2_worker_receipts": _worker_receipts(candidate_results),
            "lane_gpu_usage": lane_gpu_usage_receipt(),
            "topology": topology.as_dict(),
            "evaluation_identity_receipt": identity_receipt.as_dict(),
            "input_evidence": input_evidence,
            "approval_token_class": "ROOT_SESSION_FULL_LOAD_APPROVAL",
        },
        runtime_seconds_by_model=runtime,
    )
    print(manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
