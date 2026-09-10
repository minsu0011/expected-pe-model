"""Run the isolated spent-seed V4 generator compatibility smoke exactly once."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v4.generator_contract import (  # noqa: E402
    run_generator_smoke,
)


def main() -> int:
    receipt = run_generator_smoke(PROJECT_ROOT)
    print(f"GENERATOR_SMOKE_SUCCESS {receipt['smoke_receipt_sha256']}")
    print(f"INVOCATION_ID {receipt['invocation_id']}")
    print(f"SMOKE_RECEIPT {Path(receipt['attempt_root']) / 'GENERATOR_SMOKE_RECEIPT.json'}")
    print("EVIDENCE_CLASSIFICATION NON_EVIDENTIARY_SPENT_SEED_GENERATOR_COMPATIBILITY_SMOKE")
    print("QUALIFICATION_OR_HELDOUT_LAUNCHED False")
    print("V4_CANDIDATE_MODEL_RUN False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
