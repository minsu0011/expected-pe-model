"""Append the frozen V3 5+5 reservation without revealing heldout IDs."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v3.precommit import (  # noqa: E402
    DEFAULT_OUTPUT_NAME,
)
from research.model_zoo.prospective_fresh_ensemble_v3.seed_reservation import (  # noqa: E402
    reserve_from_frozen_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root", type=Path, default=PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME
    )
    args = parser.parse_args()
    receipt = reserve_from_frozen_precommit(PROJECT_ROOT, args.output_root)
    print(f"V3_RESERVED {receipt['reservation_id']}")
    print(
        "QUALIFICATION_SEEDS "
        + ",".join(str(seed) for seed in receipt["qualification_seeds"])
    )
    print(f"HELDOUT_COMMITMENT {receipt['heldout_seed_commitment_sha256']}")
    print("HELDOUT_IDS_EXPOSED False")
    print("DATA_OR_MODEL_RUN False")
    print("LAUNCH_AUTHORIZED False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
