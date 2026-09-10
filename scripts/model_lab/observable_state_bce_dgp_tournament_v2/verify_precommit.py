"""Verify the frozen V2 score-free precommit without execution authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC = PROJECT_ROOT / "src"
for entry in (PROJECT_ROOT, SRC):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from research.model_zoo.observable_state_bce_dgp_tournament_v2.precommit import (  # noqa: E402
    verify_frozen_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--precommit-root", type=Path, required=True)
    args = parser.parse_args()
    result = verify_frozen_precommit(PROJECT_ROOT, args.precommit_root)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
