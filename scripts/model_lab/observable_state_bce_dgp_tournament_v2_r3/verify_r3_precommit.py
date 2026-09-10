"""Verify the fixed frozen V2 R3 precommit and internally derived context."""

from __future__ import annotations

import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC = PROJECT_ROOT / "src"
for entry in (PROJECT_ROOT, SRC):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.authority import (  # noqa: E402
    build_authority_context,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.precommit import (  # noqa: E402
    verify_frozen_precommit,
)


def main() -> int:
    result = verify_frozen_precommit()
    result["authority_context_semantic_sha256"] = build_authority_context()[
        "authority_context_semantic_sha256"
    ]
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
