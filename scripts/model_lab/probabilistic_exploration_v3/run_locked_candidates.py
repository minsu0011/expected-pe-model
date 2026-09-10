"""Run the V3 locked candidate screen only after root approval."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v3.resources import (  # noqa: E402
    apply_full_load_resource_policy,
)

apply_full_load_resource_policy(gpu=False)

from research.model_zoo.probabilistic_exploration_v3.runner import (  # noqa: E402
    publish_candidate_predictions,
    run_locked_candidates,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    base = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"
    parser.add_argument("--design", type=Path, default=base / "DESIGN_LOCK.json")
    parser.add_argument("--inventory", type=Path, default=base / "INPUT_INVENTORY.json")
    parser.add_argument("--runtime-closure", type=Path, default=base / "RUNTIME_CLOSURE.json")
    parser.add_argument("--runtime-closure-sha256", required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    predictions, bridge, receipt = run_locked_candidates(
        repo_root=ROOT,
        design_path=args.design,
        inventory_path=args.inventory,
        runtime_closure_path=args.runtime_closure,
        runtime_closure_raw_sha256=args.runtime_closure_sha256,
        approval_path=args.approval,
        workers=args.workers,
    )
    publication = publish_candidate_predictions(predictions, bridge, receipt, args.output)
    print(publication["files"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
