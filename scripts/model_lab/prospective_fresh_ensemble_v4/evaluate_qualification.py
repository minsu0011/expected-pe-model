"""Qualification-only evaluator CLI; manifests and paths are capability-derived."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v4.contracts import DEFAULT_OUTPUT_NAME  # noqa: E402
from research.model_zoo.prospective_fresh_ensemble_v4.evaluation import (  # noqa: E402
    write_qualification_report_and_terminal,
)
from research.model_zoo.prospective_fresh_ensemble_v4.process_runner import (  # noqa: E402
    initialize_actual_child_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v4.qualification_process import (  # noqa: E402
    spawn_qualification_worker,
)


OUTPUT_ROOT = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("run", "_child"), default="run")
    parser.add_argument("--descriptor", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--invocation-id", help=argparse.SUPPRESS)
    parser.add_argument("--stage", choices=("qualification",), help=argparse.SUPPRESS)
    parser.add_argument("--worker-kind", choices=("evaluate",), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mode == "_child":
        if args.descriptor is None or args.invocation_id is None or args.stage != "qualification":
            raise RuntimeError("internal qualification evaluator handshake is incomplete")
        if args.worker_kind != "evaluate":
            raise RuntimeError("qualification evaluator rejects this worker kind")
        capability = initialize_actual_child_worker(
            descriptor_path=args.descriptor,
            invocation_id=args.invocation_id,
            expected_precommit_root=OUTPUT_ROOT,
            expected_stage="qualification",
            expected_kind="evaluate",
        )
        write_qualification_report_and_terminal(capability)
        return 0
    if any(
        value is not None
        for value in (args.descriptor, args.invocation_id, args.stage, args.worker_kind)
    ):
        raise RuntimeError("caller-provided child handshake arguments are forbidden")
    return spawn_qualification_worker(
        output_root=OUTPUT_ROOT,
        project_root=PROJECT_ROOT,
        kind="evaluate",
        child_script=Path(__file__),
    )


if __name__ == "__main__":
    raise SystemExit(main())
