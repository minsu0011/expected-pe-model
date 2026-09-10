"""Seal the root-authorized, score-free V3.2 GPU backend probe approval."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v2.contracts import (  # noqa: E402
    ExplorationContractError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from research.model_zoo.probabilistic_exploration_v3.design import (  # noqa: E402
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v3.governance import (  # noqa: E402
    load_v3_inventory,
)
from research.model_zoo.probabilistic_exploration_v3.probe import (  # noqa: E402
    gpu_probe_approval_payload,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    base = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"
    parser.add_argument("--design", type=Path, default=base / "DESIGN_LOCK.json")
    parser.add_argument("--inventory", type=Path, default=base / "INPUT_INVENTORY.json")
    parser.add_argument(
        "--preprobe-closure",
        type=Path,
        default=base / "PREPROBE_RUNTIME_CLOSURE.json",
    )
    parser.add_argument(
        "--preprobe-closure-sidecar",
        type=Path,
        default=base / "PREPROBE_RUNTIME_CLOSURE.sha256",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "outputs"
            / "model_zoo_probabilistic_exploration_v3_2_gpu_probe_approval_20260820"
            / "APPROVAL.json"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    verify_design_file(args.design)
    load_v3_inventory(ROOT, args.inventory)
    expected_closure = args.preprobe_closure_sidecar.read_text(encoding="ascii").strip()
    if sha256_file(args.preprobe_closure) != expected_closure:
        raise ExplorationContractError("preprobe runtime closure sidecar differs")
    unsigned = gpu_probe_approval_payload(
        design_raw_sha256=sha256_file(args.design),
        inventory_raw_sha256=sha256_file(args.inventory),
        preprobe_closure_raw_sha256=expected_closure,
    )
    approval = {
        **unsigned,
        "seal_sha256": sha256_bytes(canonical_json_bytes(unsigned)),
    }
    raw = (json.dumps(approval, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    output = args.output.resolve()
    if output.exists():
        raise ExplorationContractError("refusing to overwrite GPU probe approval")
    output.parent.mkdir(parents=True, exist_ok=False)
    output.write_bytes(raw)
    print(sha256_bytes(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
