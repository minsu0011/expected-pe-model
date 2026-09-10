"""Battleground entry point for the root-approved cheap DGP run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.aggressive_lab.resources import seal_battleground_process


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-workers", type=int, default=16)
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()

    # Must happen before importing runner -> NumPy/pandas/sklearn.
    resource = seal_battleground_process(outer_workers=args.max_workers)
    from research.model_zoo.dgp_exploration_v2.runner import run_cheap_stage

    result = run_cheap_stage(
        output=args.output,
        max_workers=args.max_workers,
        design_lock_raw_sha256=args.design_lock_sha256,
        activation_literal=args.activation,
    )
    print(json.dumps({"resource": resource.__dict__, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
