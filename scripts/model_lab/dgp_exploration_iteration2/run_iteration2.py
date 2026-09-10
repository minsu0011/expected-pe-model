"""Execute hash-bound outcome-aware Iteration 2 on four CPUs or fewer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.dgp_exploration_iteration2.resources import (
    seal_iteration2_process,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    resource = seal_iteration2_process()
    from research.model_zoo.dgp_exploration_iteration2.runner import run_iteration2

    result = run_iteration2(
        output=args.output,
        expected_design_lock_raw_sha256=args.design_lock_sha256,
        activation_literal=args.activation,
        resource_receipt=resource,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

