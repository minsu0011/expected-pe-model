"""Child entry point for the V5 descriptor/handshake probe; no model actions."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.prospective_fresh_ensemble_v5.pid_handshake import (  # noqa: E402
    publish_ready_claim,
    wait_for_capability,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("_child",))
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--invocation-id", required=True)
    args = parser.parse_args()
    publish_ready_claim(
        descriptor_path=args.descriptor,
        invocation_id=args.invocation_id,
    )
    capability = wait_for_capability(
        descriptor_path=args.descriptor,
        invocation_id=args.invocation_id,
    )
    if (
        capability.payload["execution_authority"] is not False
        or capability.payload["model_operations_authorized"] is not False
        or capability.payload["bound_inputs"] != {}
    ):
        raise RuntimeError("probe capability exceeded its no-model authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
