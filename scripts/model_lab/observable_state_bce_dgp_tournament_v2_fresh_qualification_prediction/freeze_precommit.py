from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.precommit import (  # noqa: E402
    PRECOMMIT_OUTPUT_RELATIVE,
    VerificationEvidence,
    freeze_precommit,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.source_audit import (  # noqa: E402
    SOURCE_RELATIVE_PATHS,
    TEST_RELATIVE_PATH,
)


def _summary(completed: subprocess.CompletedProcess[str]) -> str:
    lines = [
        line.strip()
        for line in f"{completed.stdout}\n{completed.stderr}".splitlines()
        if line.strip()
    ]
    return lines[-1] if lines else "NO_COMMAND_OUTPUT"


def _run(command: tuple[str, ...], root: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    source_root = str(root / "src")
    prior_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{source_root}{os.pathsep}{prior_pythonpath}"
        if prior_pythonpath
        else source_root
    )
    return subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path)
    args = parser.parse_args()
    root = (
        args.project_root.resolve(strict=True)
        if args.project_root is not None
        else _REPOSITORY_ROOT
    )
    output = root / PRECOMMIT_OUTPUT_RELATIVE
    if output.exists():
        raise SystemExit("exact immutable precommit destination already exists")

    pytest_command = (
        sys.executable,
        "-m",
        "pytest",
        "-q",
        TEST_RELATIVE_PATH,
    )
    pytest_result = _run(pytest_command, root)
    if pytest_result.returncode != 0:
        sys.stdout.write(pytest_result.stdout)
        sys.stderr.write(pytest_result.stderr)
        return pytest_result.returncode

    ruff_command = (
        sys.executable,
        "-m",
        "ruff",
        "check",
        *SOURCE_RELATIVE_PATHS,
    )
    ruff_result = _run(ruff_command, root)
    if ruff_result.returncode != 0:
        sys.stdout.write(ruff_result.stdout)
        sys.stderr.write(ruff_result.stderr)
        return ruff_result.returncode

    result = freeze_precommit(
        project_root=root,
        output=output,
        evidence=VerificationEvidence(
            pytest_command=pytest_command,
            pytest_returncode=pytest_result.returncode,
            pytest_summary=_summary(pytest_result),
            ruff_command=ruff_command,
            ruff_returncode=ruff_result.returncode,
            ruff_summary=_summary(ruff_result),
        ),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
