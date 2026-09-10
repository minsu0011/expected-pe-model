"""Verify the exact externally supplied Iteration 2 design hash."""

from __future__ import annotations

import argparse
import json

from research.model_zoo.dgp_exploration_iteration2.resources import (
    seal_iteration2_process,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-lock-sha256", required=True)
    args = parser.parse_args()
    resource = seal_iteration2_process()
    from research.model_zoo.dgp_exploration_iteration2.precommit import verify_precommit

    lock = verify_precommit(args.design_lock_sha256)
    print(
        json.dumps(
            {
                "status": "PASS_ITERATION2_PRECOMMIT_NO_SCORE",
                "design_lock_raw_sha256": args.design_lock_sha256,
                "outcome_aware": lock["outcome_aware"],
                "candidate_count": len(lock["candidate_ids"]),
                "same_dgp_training_truth_for_logo": False,
                "score_computed": False,
                "resource": resource,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

