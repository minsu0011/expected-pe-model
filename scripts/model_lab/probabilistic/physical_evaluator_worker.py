from __future__ import annotations

import argparse
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Single-use child-only physical evaluator")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execution-request", type=Path, required=True)
    parser.add_argument("--expected-execution-request-sha256", required=True)
    parser.add_argument("--independent-go", type=Path, required=True)
    parser.add_argument("--expected-independent-go-sha256", required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.physical_evaluator import (
        execute_physical_evaluator,
    )
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        load_formal_launch_authority,
    )

    execution_request_path = (
        args.execution_request.resolve()
        if args.execution_request.is_absolute()
        else (root / args.execution_request).resolve()
    )
    independent_go_path = (
        args.independent_go.resolve()
        if args.independent_go.is_absolute()
        else (root / args.independent_go).resolve()
    )
    launch_authority = load_formal_launch_authority(
        execution_request_path=execution_request_path,
        expected_execution_request_sha256=args.expected_execution_request_sha256,
        independent_go_path=independent_go_path,
        expected_independent_go_sha256=args.expected_independent_go_sha256,
        repo_root=root,
    )
    execute_physical_evaluator(
        args.handoff.resolve(),
        args.output.resolve(),
        repo_root=root,
        launch_authority=launch_authority,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
