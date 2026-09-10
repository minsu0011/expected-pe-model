"""Append the frozen 5+5 seed reservation; never generate or fit data."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
SOURCE = PROJECT_ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from research.model_zoo.prospective_fresh_ensemble_v1.precommit import DEFAULT_OUTPUT_NAME  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v1.seed_ledger import (  # noqa: E402
    reserve_from_frozen_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME)
    args = parser.parse_args()
    receipt = reserve_from_frozen_precommit(PROJECT_ROOT, args.output_root)
    print(f"RESERVED {receipt['reservation_id']}")
    print(f"QUALIFICATION_SEEDS {','.join(str(seed) for seed in receipt['qualification_seeds'])}")
    print(f"HELDOUT_COMMITMENT {receipt['heldout_seed_commitment_sha256']}")
    print("DATA_GENERATED False")
    print("LAUNCH_AUTHORIZED False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
