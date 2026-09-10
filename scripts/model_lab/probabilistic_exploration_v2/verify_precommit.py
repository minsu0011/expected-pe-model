"""Verify the exploration precommit without opening spent truth or scoring."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v2.resources import (  # noqa: E402
    apply_background_resource_policy,
)

RESOURCE = apply_background_resource_policy()

from research.model_zoo.aggressive_lab.contracts import load_sealed_design_lock  # noqa: E402
from research.model_zoo.probabilistic_exploration_v2.contracts import (  # noqa: E402
    sha256_bytes,
    verify_file_record,
)
from research.model_zoo.probabilistic_exploration_v2.design import (  # noqa: E402
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v2.scoring import (  # noqa: E402
    load_inventory,
    preflight_survivor_inputs,
    preflight_truth_addresses,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--design",
        type=Path,
        default=ROOT
        / "outputs"
        / "model_zoo_probabilistic_exploration_v2_design_20260820"
        / "DESIGN_LOCK.json",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=ROOT
        / "outputs"
        / "model_zoo_probabilistic_exploration_v2_design_20260820"
        / "INPUT_INVENTORY.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    load_sealed_design_lock(ROOT)
    verify_design_file(args.design)
    inventory_raw, inventory = load_inventory(args.inventory)
    # Only truth-blind inputs and the address-only evaluation manifest are hashed.
    artifacts = inventory["artifacts"]
    for name in (
        "formal_identity",
        "common_mask",
        "pit_features",
        "training_labels",
        "v04_point_comparator",
        "evaluation_manifest",
    ):
        verify_file_record(ROOT, artifacts[name])
    for survivor in artifacts["survivors"]:
        verify_file_record(ROOT, survivor["prediction"])
        verify_file_record(ROOT, survivor["receipt"])
    survivor_preflight = preflight_survivor_inputs(ROOT, inventory)
    truth_address_preflight = preflight_truth_addresses(ROOT, inventory)
    print(
        json.dumps(
            {
                "status": "PRECOMMIT_VERIFIED_SCORE_NOT_OPENED",
                "design_raw_sha256": sha256_bytes(args.design.read_bytes()),
                "inventory_raw_sha256": sha256_bytes(inventory_raw),
                "resource_policy": RESOURCE,
                "survivor_preflight": survivor_preflight,
                "truth_address_preflight": truth_address_preflight,
                "truth_values_opened": False,
                "score_computed": False,
                "production_promotion_authority": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
