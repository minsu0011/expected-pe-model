"""Verify the V3 refreeze and runtime closure without truth or fitting."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v3.resources import (  # noqa: E402
    apply_full_load_resource_policy,
)

RESOURCE = apply_full_load_resource_policy(gpu=False)

from research.model_zoo.aggressive_lab.contracts import load_sealed_design_lock  # noqa: E402
from research.model_zoo.probabilistic_exploration_v2.contracts import (  # noqa: E402
    sha256_bytes,
)
from research.model_zoo.probabilistic_exploration_v2.scoring import (  # noqa: E402
    preflight_truth_addresses,
)
from research.model_zoo.probabilistic_exploration_v3.central import (  # noqa: E402
    preflight_immutable_survivor_bridge,
)
from research.model_zoo.probabilistic_exploration_v3.closure import (  # noqa: E402
    verify_runtime_closure,
)
from research.model_zoo.probabilistic_exploration_v3.design import (  # noqa: E402
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v3.governance import (  # noqa: E402
    load_v3_inventory,
)
from research.model_zoo.probabilistic_exploration_v3.inputs import (  # noqa: E402
    load_prediction_inputs,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    base = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"
    parser.add_argument("--design", type=Path, default=base / "DESIGN_LOCK.json")
    parser.add_argument("--inventory", type=Path, default=base / "INPUT_INVENTORY.json")
    parser.add_argument("--runtime-closure", type=Path, default=base / "RUNTIME_CLOSURE.json")
    parser.add_argument("--runtime-closure-sha256")
    return parser.parse_args()


def _closure_pin(args: argparse.Namespace) -> str:
    if args.runtime_closure_sha256:
        return str(args.runtime_closure_sha256)
    sidecar = args.runtime_closure.with_suffix(".sha256")
    return sidecar.read_text(encoding="utf-8").split()[0]


def main() -> int:
    args = parse_args()
    load_sealed_design_lock(ROOT)
    design = verify_design_file(args.design)
    inventory_raw, inventory, v2_inventory = load_v3_inventory(ROOT, args.inventory)
    closure_pin = _closure_pin(args)
    closure = verify_runtime_closure(
        repo_root=ROOT,
        closure_path=args.runtime_closure,
        expected_raw_sha256=closure_pin,
    )
    _, _, reduced = load_prediction_inputs(ROOT, v2_inventory)
    survivor = preflight_immutable_survivor_bridge(
        repo_root=ROOT,
        v3_inventory=inventory,
        v2_inventory=v2_inventory,
    )[1]
    truth_addresses = preflight_truth_addresses(ROOT, v2_inventory)
    print(
        json.dumps(
            {
                "status": "V3_REFREEZE_VERIFIED_NO_FIT_NO_TRUTH",
                "design_schema": design["schema_version"],
                "design_raw_sha256": sha256_bytes(args.design.read_bytes()),
                "inventory_raw_sha256": sha256_bytes(inventory_raw),
                "runtime_closure": closure,
                "resource_policy": RESOURCE,
                "reduced_identity_rows": int(len(reduced)),
                "survivor_preflight": survivor,
                "truth_address_preflight": truth_addresses,
                "truth_values_opened": False,
                "score_computed": False,
                "heavy_fit_started": False,
                "production_promotion_authority": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
