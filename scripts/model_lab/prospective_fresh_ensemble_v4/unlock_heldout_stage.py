"""Heldout-only broker CLI; resolves IDs only after PASS plus two approvals."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v4.contracts import DEFAULT_OUTPUT_NAME  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v4.heldout_authority import (  # noqa: E402
    create_heldout_stage_descriptor,
)


def main() -> int:
    output = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME
    descriptor = create_heldout_stage_descriptor(output)
    print(f"HELDOUT_DESCRIPTOR_UNLOCKED {descriptor['descriptor_sha256']}")
    print("HELDOUT_LAUNCH_AUTHORIZED_BY_DESCRIPTOR True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

