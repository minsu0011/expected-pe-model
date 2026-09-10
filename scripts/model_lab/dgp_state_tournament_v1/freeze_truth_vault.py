"""Separate inert truth-vault freeze; no prediction or scoring API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ACTIVATION_LITERAL = "FREEZE_DGP_STATE_TOURNAMENT_V1_DETACHED_TRUTH_VAULT_NO_SELECTION"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument("--v3-design-lock-sha256", required=True)
    parser.add_argument("--v3-prediction-receipt-sha256", required=True)
    parser.add_argument("--v3-predictions-sha256", required=True)
    parser.add_argument("--v3-common-identities-sha256", required=True)
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    if args.activation != ACTIVATION_LITERAL:
        raise RuntimeError("exact detached truth-vault activation literal is absent")

    from research.model_zoo.dgp_state_tournament_v1.resources import (
        seal_input_freeze_process,
    )

    launch_resource = seal_input_freeze_process(outer_workers=args.workers)

    from research.model_zoo.dgp_state_tournament_v1.truth_vault import (
        freeze_detached_truth_vault,
    )

    result = freeze_detached_truth_vault(
        output=args.output,
        max_workers=args.workers,
        design_lock_raw_sha256=args.design_lock_sha256,
        v3_design_lock_raw_sha256=args.v3_design_lock_sha256,
        v3_prediction_receipt_raw_sha256=args.v3_prediction_receipt_sha256,
        v3_predictions_raw_sha256=args.v3_predictions_sha256,
        v3_common_identities_raw_sha256=args.v3_common_identities_sha256,
        common_full_load_lock_raw_sha256=args.common_full_load_lock_sha256,
        activation_literal=args.activation,
        launch_resource_receipt=launch_resource.as_dict(),
    )
    print(json.dumps({"resource": launch_resource.as_dict(), "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
