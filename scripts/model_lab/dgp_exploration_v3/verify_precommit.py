"""Read-only verifier for the externally pinned V3 and common locks."""

from __future__ import annotations

import argparse
import json

from research.model_zoo.dgp_exploration_v3.precommit import verify_precommit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    args = parser.parse_args()
    payload = verify_precommit(
        expected_design_lock_raw_sha256=args.design_lock_sha256,
        expected_common_lock_raw_sha256=args.common_full_load_lock_sha256,
    )
    print(
        json.dumps(
            {
                "status": "PASS_SCORE_FREE_V3_PRECOMMIT",
                "heavy_execution_status": payload["heavy_execution_status"],
                "labels": payload["labels"],
                "production_authority": payload["production_authority"],
                "source_count": len(payload["source_sha256"]),
                "dependency_count": len(payload["dependency_sha256"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
