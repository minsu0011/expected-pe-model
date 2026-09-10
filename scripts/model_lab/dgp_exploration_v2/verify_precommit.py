"""Read-only verifier for the phase-two pinned v2 design."""

from __future__ import annotations

import argparse
import json

from research.model_zoo.dgp_exploration_v2.runner import verify_precommit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-lock-sha256", required=True)
    args = parser.parse_args()
    payload = verify_precommit(args.design_lock_sha256)
    print(
        json.dumps(
            {
                "status": "PASS_SCORE_FREE_PRECOMMIT",
                "heavy_execution_status": payload["heavy_execution_status"],
                "labels": payload["labels"],
                "source_count": len(payload["source_sha256"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
