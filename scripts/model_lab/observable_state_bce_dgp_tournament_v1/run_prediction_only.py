from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.observable_state_bce_dgp_tournament_v1.bindings_r4 import (
    INDEPENDENT_AUDIT_BINDING_R4,
    PUBLIC_INPUT_BINDING_R4,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.runner import (
    EXPECTED_FINAL_DESIGN_ROOT,
    PREDICTION_ACTIVATION_LITERAL,
    FutureFinalDesignBinding,
    run_prediction_only,
)


LAUNCH_ACTIVATION_LITERAL = (
    "LAUNCH_R4_OBSERVABLE_STATE_BCE_DGP_TOURNAMENT_PREDICTIONS_ONLY"
)
DEFAULT_OUTPUT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_20260821"
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--activation", required=True)
    parser.add_argument("--final-design-sha256", required=True)
    parser.add_argument("--output-relative", default=DEFAULT_OUTPUT_RELATIVE)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if args.activation != LAUNCH_ACTIVATION_LITERAL:
        raise RuntimeError("prediction-only launch activation differs")
    root = Path(__file__).resolve().parents[3]
    binding = FutureFinalDesignBinding(
        relative_path=f"{EXPECTED_FINAL_DESIGN_ROOT}/DESIGN_LOCK.json",
        raw_sha256=args.final_design_sha256,
    )
    result = run_prediction_only(
        project_root=root,
        output=root / args.output_relative,
        activation=PREDICTION_ACTIVATION_LITERAL,
        public_binding=PUBLIC_INPUT_BINDING_R4,
        independent_audit_binding=INDEPENDENT_AUDIT_BINDING_R4,
        final_design_binding=binding,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
