"""Verify frozen V2 R2 controls without creating any authority or runtime state."""

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

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.authority import (  # noqa: E402
    build_authority_context,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.precommit import (  # noqa: E402
    verify_frozen_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--precommit-root", type=Path, required=True)
    args = parser.parse_args()
    result = verify_frozen_precommit(PROJECT_ROOT, args.precommit_root)
    context = build_authority_context(PROJECT_ROOT, args.precommit_root)
    result["authority_context_semantic_sha256"] = context[
        "authority_context_semantic_sha256"
    ]
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
