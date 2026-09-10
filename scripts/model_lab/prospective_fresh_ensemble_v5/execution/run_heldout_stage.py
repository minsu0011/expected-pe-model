"""Heldout-only generator/predictor CLI; no qualification fallback exists."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[4]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v5.execution.contracts import DEFAULT_OUTPUT_NAME  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v5.execution.generation import run_generation  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v5.execution.heldout_process import (  # noqa: E402
    spawn_heldout_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.prediction import run_predictions  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v5.execution.process_runner import (  # noqa: E402
    initialize_actual_child_worker,
)


OUTPUT_ROOT = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "predict", "_child"))
    parser.add_argument("--descriptor", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--invocation-id", help=argparse.SUPPRESS)
    parser.add_argument("--stage", choices=("heldout",), help=argparse.SUPPRESS)
    parser.add_argument("--worker-kind", choices=("generate", "predict"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.action == "_child":
        if args.descriptor is None or args.invocation_id is None or args.stage != "heldout":
            raise RuntimeError("internal heldout child handshake is incomplete")
        kind = args.worker_kind
        if kind not in {"generate", "predict"}:
            raise RuntimeError("heldout stage child rejects this worker kind")
        capability = initialize_actual_child_worker(
            descriptor_path=args.descriptor,
            invocation_id=args.invocation_id,
            expected_precommit_root=OUTPUT_ROOT,
            expected_stage="heldout",
            expected_kind=kind,
        )
        run_generation(capability) if kind == "generate" else run_predictions(capability)
        return 0
    if any(
        value is not None
        for value in (args.descriptor, args.invocation_id, args.stage, args.worker_kind)
    ):
        raise RuntimeError("caller-provided child handshake arguments are forbidden")
    return spawn_heldout_worker(
        output_root=OUTPUT_ROOT,
        kind=args.action,
    )


if __name__ == "__main__":
    raise SystemExit(main())
