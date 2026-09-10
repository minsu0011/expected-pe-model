"""Run and seal only the fixed v4-r2 spent import-discovery evidence."""

from __future__ import annotations

import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2.evidence import (  # noqa: E402
    freeze_spent_discovery_evidence,
)


def main() -> int:
    if sys.argv[1:] != []:
        raise RuntimeError("spent discovery script accepts no arguments")
    result = freeze_spent_discovery_evidence()
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
