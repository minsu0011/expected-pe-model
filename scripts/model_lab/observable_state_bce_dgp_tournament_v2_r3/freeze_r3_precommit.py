"""Test, lint, and freeze the one fixed score-free V2 R3 precommit."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC = PROJECT_ROOT / "src"
for entry in (PROJECT_ROOT, SRC):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.contracts import (  # noqa: E402
    R3_PRECOMMIT_ROOT,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.precommit import (  # noqa: E402
    freeze_score_free_precommit,
)


def _run(arguments: Sequence[str]) -> dict[str, object]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(SRC), str(PROJECT_ROOT)))
    completed = subprocess.run(
        list(arguments),
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "argv": list(arguments),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-8_000:],
        "stderr": completed.stderr[-8_000:],
    }


def main() -> int:
    test = "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r3.py"
    source = "research/model_zoo/observable_state_bce_dgp_tournament_v2_r3"
    scripts = "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r3"
    pytest_receipt = _run((sys.executable, "-m", "pytest", test, "-q"))
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError("ruff executable is unavailable")
    ruff_receipt = _run((ruff, "check", source, scripts, test))
    evidence = {
        "pytest_returncode": pytest_receipt["returncode"],
        "pytest": pytest_receipt,
        "ruff_returncode": ruff_receipt["returncode"],
        "ruff": ruff_receipt,
        "fresh_seed_derived_or_reserved": False,
        "fresh_data_generated": False,
        "model_fit_executed": False,
        "prediction_generated": False,
        "truth_opened": False,
        "score_computed": False,
        "registry_mutated": False,
        "runtime_root_created": False,
        "root_approval_created": False,
    }
    result = freeze_score_free_precommit(
        output=PROJECT_ROOT / R3_PRECOMMIT_ROOT,
        test_evidence=evidence,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
