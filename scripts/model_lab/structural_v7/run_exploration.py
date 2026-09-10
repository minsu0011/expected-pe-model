"""Explicit-approval Structural V7 spent-seed prediction entrypoint."""

# ruff: noqa: E402 -- resource sealing intentionally precedes numerical imports.

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


APPROVAL_TOKEN = "STRUCTURAL_V7_EXPLORATION_HEAVY_APPROVED_20260820"


def _worker(project_root: str, seed: int, outer_workers: int):
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        load_design_lock_v2,
        load_preflight_v2,
        verify_dependency_freeze,
    )

    root = Path(project_root)
    dependency_receipt = verify_dependency_freeze(root)
    from research.model_zoo.aggressive_lab.resources import assert_battleground_process

    receipt = assert_battleground_process(outer_workers=outer_workers)
    load_design_lock_v2(root)
    load_preflight_v2(root)
    from research.model_zoo.structural_v7.runner import run_seed_predictions

    return (
        run_seed_predictions(root, seed),
        receipt.as_dict(),
        dependency_receipt.as_dict(),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Structural V7 exploration predictions")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--launch-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.launch_approval != APPROVAL_TOKEN:
        raise SystemExit("heavy Structural V7 launch remains blocked without root approval")
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        load_design_lock_v2,
        load_preflight_v2,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    receipt = seal_battleground_process(outer_workers=args.workers)
    from research.model_zoo.aggressive_lab.contracts import load_sealed_design_lock

    load_sealed_design_lock(args.project_root)
    from research.model_zoo.structural_v7.contracts import SPENT_SEEDS

    design = load_design_lock_v2(args.project_root)
    preflight = load_preflight_v2(args.project_root)
    if design.get("heavy_launch_authorized") is not False:
        raise SystemExit("the immutable design lock must remain pre-launch blocked")

    results = []
    worker_receipts = []
    worker_dependency_receipts = []
    with ProcessPoolExecutor(max_workers=min(args.workers, len(SPENT_SEEDS))) as executor:
        futures = {
            executor.submit(_worker, str(args.project_root.resolve()), seed, args.workers): seed
            for seed in SPENT_SEEDS
        }
        for future in as_completed(futures):
            result, worker_receipt, worker_dependency_receipt = future.result()
            results.append(result)
            worker_receipts.append(worker_receipt)
            worker_dependency_receipts.append(worker_dependency_receipt)
    results.sort(key=lambda item: item.seed)

    import pandas as pd

    predictions = pd.concat([item.predictions for item in results], ignore_index=True)
    diagnostics = pd.concat([item.diagnostics for item in results], ignore_index=True)
    runtime: dict[str, float] = {}
    for result in results:
        for model_id, seconds in result.runtime_seconds_by_model.items():
            runtime[model_id] = runtime.get(model_id, 0.0) + float(seconds)
    from research.model_zoo.structural_v7.artifacts import write_prediction_bundle

    manifest = write_prediction_bundle(
        predictions,
        diagnostics,
        args.output_directory,
        metadata={
            "design_lock_manifest_sha256": design["manifest_sha256"],
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "dependency_manifest_raw_sha256": (
                dependency_receipt.manifest_raw_sha256
            ),
            "parent_dependency_receipt": dependency_receipt.as_dict(),
            "parent_resource_receipt": receipt.as_dict(),
            "worker_resource_receipts": worker_receipts,
            "worker_dependency_receipts": worker_dependency_receipts,
            "approval_token_class": "ROOT_SESSION_EXPLORATION_APPROVAL",
        },
        runtime_seconds_by_model=runtime,
    )
    print(manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
