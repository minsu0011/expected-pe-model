"""Run the approved one-fold, score-free V3.2 GPU backend probe."""

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

apply_full_load_resource_policy(gpu=True, outer_workers=1)

from research.model_zoo.probabilistic_exploration_v3.probe import (  # noqa: E402
    GPUProbeCandidateError,
    publish_gpu_probe,
    publish_gpu_probe_failure,
    run_score_free_gpu_probe,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    base = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"
    parser.add_argument("--design", type=Path, default=base / "DESIGN_LOCK.json")
    parser.add_argument("--inventory", type=Path, default=base / "INPUT_INVENTORY.json")
    parser.add_argument("--preprobe-closure", type=Path, required=True)
    parser.add_argument("--preprobe-closure-sha256", required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = run_score_free_gpu_probe(
            repo_root=ROOT,
            design_path=args.design,
            inventory_path=args.inventory,
            preprobe_closure_path=args.preprobe_closure,
            preprobe_closure_raw_sha256=args.preprobe_closure_sha256,
            approval_path=args.approval,
        )
    except GPUProbeCandidateError as exc:
        failure = publish_gpu_probe_failure(
            exc,
            design_path=args.design,
            inventory_path=args.inventory,
            preprobe_closure_raw_sha256=args.preprobe_closure_sha256,
            approval_path=args.approval,
            output_directory=args.failure_output,
        )
        print(failure["manifest_raw_sha256"])
        raise
    publication = publish_gpu_probe(result, args.output)
    print(publication["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
