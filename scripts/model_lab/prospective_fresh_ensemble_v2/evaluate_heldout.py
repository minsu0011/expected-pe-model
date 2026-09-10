"""Heldout-only evaluator CLI with a distinct terminal report writer."""

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
from research.model_zoo.prospective_fresh_ensemble_v2.evaluation import (  # noqa: E402
    write_heldout_report_and_terminal,
)
from research.model_zoo.prospective_fresh_ensemble_v2.heldout_process import (  # noqa: E402
    spawn_heldout_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v2.process_runner import wait_for_capability  # noqa: E402


OUTPUT_ROOT = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("run", "_child"), default="run")
    parser.add_argument("--capability", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-kind", choices=("evaluate",), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mode == "_child":
        if args.capability is None:
            raise RuntimeError("internal heldout evaluator capability is required")
        capability = wait_for_capability(
            args.capability,
            expected_precommit_root=OUTPUT_ROOT,
            expected_stage="heldout",
            expected_kind="evaluate",
        )
        write_heldout_report_and_terminal(capability)
        return 0
    if args.capability is not None or args.worker_kind is not None:
        raise RuntimeError("caller-provided capability paths are forbidden")
    return spawn_heldout_worker(
        output_root=OUTPUT_ROOT,
        project_root=PROJECT_ROOT,
        kind="evaluate",
        child_script=Path(__file__),
    )


if __name__ == "__main__":
    raise SystemExit(main())
