"""Exact one-shot launcher for the bounded spent-only concurrency pilot."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE_OWNED_PREFIX = (str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))
expected_folded = {item.casefold() for item in SOURCE_OWNED_PREFIX}
sys.path[:] = [
    *SOURCE_OWNED_PREFIX,
    *(str(item) for item in sys.path if str(item).casefold() not in expected_folded),
]

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_spent_concurrency_pilot_v1.contracts import (  # noqa: E402, E501
    ACTIVATION_LITERAL,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_spent_concurrency_pilot_v1.pilot import (  # noqa: E402, E501
    run_bounded_pilot,
)


ARGV_SUFFIX = ("--run-bounded-spent-concurrency-pilot-no-authority", ACTIVATION_LITERAL)


def main() -> int:
    if tuple(sys.argv[1:]) != ARGV_SUFFIX:
        raise SystemExit("exact spent-pilot command suffix is required")
    receipt = run_bounded_pilot(activation_literal=ACTIVATION_LITERAL)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"].startswith("PASS_") else 78


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
