"""Full-load entry point for a separately root-approved V3 A-J screen."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.aggressive_lab.full_load_resources import seal_full_load_process


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-workers", type=int, default=32)
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    resource = seal_full_load_process(outer_workers=args.max_workers)

    # Import NumPy/pandas/sklearn consumers only after the common seal.
    from research.model_zoo.dgp_exploration_v3.runner import run_prediction_stage

    result = run_prediction_stage(
        output=args.output,
        max_workers=args.max_workers,
        design_lock_raw_sha256=args.design_lock_sha256,
        common_lock_raw_sha256=args.common_full_load_lock_sha256,
        activation_literal=args.activation,
    )
    print(json.dumps({"resource": resource.as_dict(), "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
