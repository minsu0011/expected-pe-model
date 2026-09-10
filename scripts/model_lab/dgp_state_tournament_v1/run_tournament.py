"""Permanent common-prerequisite entrypoint; it cannot fit a survivor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ACTIVATION_LITERAL = "FREEZE_DGP_STATE_TOURNAMENT_V1_PUBLIC_CANONICAL_OVERLAY_ONLY"


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze-inputs")
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--workers", type=int, default=32)
    freeze.add_argument("--design-lock-sha256", required=True)
    freeze.add_argument("--v3-design-lock-sha256", required=True)
    freeze.add_argument("--v3-prediction-receipt-sha256", required=True)
    freeze.add_argument("--v3-predictions-sha256", required=True)
    freeze.add_argument("--v3-common-identities-sha256", required=True)
    freeze.add_argument("--truth-vault-receipt-sha256", required=True)
    freeze.add_argument("--common-full-load-lock-sha256", required=True)
    freeze.add_argument("--activation", required=True)
    args = parser.parse_args()

    # Fail before resource sealing, imports with numerical runtimes, or path access.
    if args.command != "freeze-inputs" or args.activation != ACTIVATION_LITERAL:
        raise RuntimeError("exact public-input-freeze activation literal is absent")

    from research.model_zoo.dgp_state_tournament_v1.resources import (
        seal_input_freeze_process,
    )

    launch_resource = seal_input_freeze_process(outer_workers=args.workers)

    # Import NumPy/pandas and the runner only after the CPU/GPU/thread/RAM seal.
    from research.model_zoo.dgp_state_tournament_v1.runner import freeze_public_inputs

    result = freeze_public_inputs(
        output=args.output,
        max_workers=args.workers,
        design_lock_raw_sha256=args.design_lock_sha256,
        v3_design_lock_raw_sha256=args.v3_design_lock_sha256,
        v3_prediction_receipt_raw_sha256=args.v3_prediction_receipt_sha256,
        v3_predictions_raw_sha256=args.v3_predictions_sha256,
        v3_common_identities_raw_sha256=args.v3_common_identities_sha256,
        vault_receipt_raw_sha256=args.truth_vault_receipt_sha256,
        common_full_load_lock_raw_sha256=args.common_full_load_lock_sha256,
        activation_literal=args.activation,
        launch_resource_receipt=launch_resource.as_dict(),
    )
    print(json.dumps({"resource": launch_resource.as_dict(), "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
