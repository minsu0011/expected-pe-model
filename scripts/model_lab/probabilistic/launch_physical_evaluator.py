from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify disk custody, then launch the detached evaluator child"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--bundle-spec", type=Path, required=True)
    parser.add_argument("--execution-request", type=Path, required=True)
    parser.add_argument("--expected-execution-request-sha256", required=True)
    parser.add_argument("--independent-go", type=Path, required=True)
    parser.add_argument("--expected-independent-go-sha256", required=True)
    parser.add_argument("--handoff-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.physical_evaluator import (
        build_physical_evaluator_handoff,
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

    handoff = build_physical_evaluator_handoff(
        args.bundle_spec.resolve(),
        args.handoff_directory.resolve(),
        repo_root=root,
        launch_authority=launch_authority,
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    command = [
        str(args.worker_python.resolve()),
        str(root / "scripts/model_lab/probabilistic/physical_evaluator_worker.py"),
        "--repo-root",
        str(root),
        "--handoff",
        str(handoff),
        "--output",
        str(args.output.resolve()),
        "--execution-request",
        str(execution_request_path),
        "--expected-execution-request-sha256",
        args.expected_execution_request_sha256,
        "--independent-go",
        str(independent_go_path),
        "--expected-independent-go-sha256",
        args.expected_independent_go_sha256,
    ]
    completed = subprocess.run(
        command,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "physical evaluator child failed closed; retry forbidden: "
            f"stdout={completed.stdout!r}, stderr={completed.stderr!r}"
        )
    result = json.loads(args.output.resolve().read_text(encoding="utf-8"))
    if (
        result.get("parent_pid") != os.getpid()
        or result.get("evaluator_pid") == os.getpid()
        or result.get("metric_receipts_only") is not True
        or result.get("external_execution_request_raw_sha256")
        != launch_authority.request.raw_sha256
        or result.get("independent_go_raw_sha256") != launch_authority.independent_go.raw_sha256
    ):
        raise RuntimeError("physical evaluator process/return boundary differs")
    print(
        json.dumps(
            {
                "status": result["status"],
                "parent_pid": os.getpid(),
                "evaluator_pid": result["evaluator_pid"],
                "handoff": str(handoff),
                "output": str(args.output.resolve()),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
