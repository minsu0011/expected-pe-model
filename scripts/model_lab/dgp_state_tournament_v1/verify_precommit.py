"""Read-only verifier for the new input-freeze and inherited V3 locks."""

from __future__ import annotations

import argparse
import json

from research.model_zoo.dgp_state_tournament_v1.precommit import verify_precommit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--v3-design-lock-sha256", required=True)
    parser.add_argument("--v3-prediction-receipt-sha256", required=True)
    parser.add_argument("--v3-predictions-sha256", required=True)
    parser.add_argument("--v3-common-identities-sha256", required=True)
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    args = parser.parse_args()
    payload = verify_precommit(
        expected_design_lock_raw_sha256=args.design_lock_sha256,
        expected_v3_design_lock_raw_sha256=args.v3_design_lock_sha256,
        expected_v3_prediction_receipt_raw_sha256=args.v3_prediction_receipt_sha256,
        expected_v3_predictions_raw_sha256=args.v3_predictions_sha256,
        expected_v3_common_identities_raw_sha256=args.v3_common_identities_sha256,
        expected_common_full_load_lock_raw_sha256=args.common_full_load_lock_sha256,
    )
    print(
        json.dumps(
            {
                "status": "PASS_SCORE_BLIND_INPUT_FREEZE_PRECOMMIT",
                "production_authority": payload["production_authority"],
                "legacy_formal_status": payload["legacy_formal"]["status"],
                "source_count": len(payload["source_sha256"]),
                "dependency_count": len(payload["dependency_sha256"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
