"""Run the V2 non-evidentiary full-generator schema smoke only."""

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

from research.model_zoo.observable_state_bce_dgp_tournament_v2.smoke import (  # noqa: E402
    run_schema_smoke,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_schema_smoke(project_root=PROJECT_ROOT, output=args.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
