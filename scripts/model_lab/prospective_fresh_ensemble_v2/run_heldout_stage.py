"""Heldout-only generator/predictor CLI; no qualification fallback exists."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v2.contracts import DEFAULT_OUTPUT_NAME  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v2.generation import run_generation  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v2.heldout_process import (  # noqa: E402
    spawn_heldout_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v2.prediction import run_predictions  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v2.process_runner import wait_for_capability  # noqa: E402


OUTPUT_ROOT = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "predict", "_child"))
    parser.add_argument("--capability", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-kind", choices=("generate", "predict"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.action == "_child":
        if args.capability is None:
            raise RuntimeError("internal heldout child capability is required")
        kind = args.worker_kind
        if kind not in {"generate", "predict"}:
            raise RuntimeError("heldout stage child rejects this worker kind")
        capability = wait_for_capability(
            args.capability,
            expected_precommit_root=OUTPUT_ROOT,
            expected_stage="heldout",
            expected_kind=kind,
        )
        run_generation(capability) if kind == "generate" else run_predictions(capability)
        return 0
    if args.capability is not None or args.worker_kind is not None:
        raise RuntimeError("caller-provided capability paths are forbidden")
    return spawn_heldout_worker(
        output_root=OUTPUT_ROOT,
        project_root=PROJECT_ROOT,
        kind=args.action,
        child_script=Path(__file__),
    )


if __name__ == "__main__":
    raise SystemExit(main())
