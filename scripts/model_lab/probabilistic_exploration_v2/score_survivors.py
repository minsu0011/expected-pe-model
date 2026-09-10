"""Score the two existing survivors only after a sealed root approval is supplied."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v2.resources import (  # noqa: E402
    apply_background_resource_policy,
)

apply_background_resource_policy()

from research.model_zoo.probabilistic_exploration_v2.scoring import (  # noqa: E402
    publish_score_result,
    score_inventory,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    base = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v2_design_20260820"
    parser.add_argument("--design", type=Path, default=base / "DESIGN_LOCK.json")
    parser.add_argument("--inventory", type=Path, default=base / "INPUT_INVENTORY.json")
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result, bridge = score_inventory(
        repo_root=ROOT,
        design_path=args.design,
        inventory_path=args.inventory,
        approval_path=args.approval,
    )
    publication = publish_score_result(result, bridge, args.output)
    print(publication["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
