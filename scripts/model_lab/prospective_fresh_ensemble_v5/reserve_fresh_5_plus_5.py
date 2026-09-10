"""Execute the root-approved V5 reservation only; never launch model/data work."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.prospective_fresh_ensemble_v5.execution.seed_reservation import (  # noqa: E402
    reserve_fresh_5_plus_5,
)


def main() -> int:
    receipt = reserve_fresh_5_plus_5(PROJECT_ROOT)
    print(f"V5_RESERVED {receipt['reservation_id']}")
    print(
        "QUALIFICATION_SEEDS "
        + ",".join(str(seed) for seed in receipt["qualification_seeds"])
    )
    print(f"HELDOUT_COMMITMENT {receipt['heldout_seed_commitment_sha256']}")
    print("HELDOUT_IDENTIFIERS_EXPOSED False")
    print("EXECUTION_AUTHORIZED False")
    print("GENERATION_FIT_PREDICTION_TRUTH_SCORE False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
