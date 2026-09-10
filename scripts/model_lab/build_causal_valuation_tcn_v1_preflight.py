"""Build the outputs-only Causal Valuation TCN V1 design freeze."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from research.model_zoo.causal_valuation_tcn_v1.artifacts import build_design_bundle
from research.model_zoo.causal_valuation_tcn_v1.contracts import PINNED_PYTHON
from research.model_zoo.causal_valuation_tcn_v1.smoke import (
    run_cross_device_synthetic_smoke,
)
from research.model_zoo.causal_valuation_tcn_v1.source_audit import run_source_audit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CPU_LAB_PYTHON = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
RUFF_EXECUTABLE = "C:/Users/minsu/anaconda3/Scripts/ruff.exe"
RUFF_EXECUTABLE_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)


def _run_quality_command(command: list[str], environment: dict[str, str]) -> dict[str, Any]:
    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
    )
    combined = (process.stdout + process.stderr).encode("utf-8")
    return {
        "command": command,
        "return_code": process.returncode,
        "output_sha256": hashlib.sha256(combined).hexdigest(),
        "output_tail": (process.stdout + process.stderr)[-2000:],
    }


def main() -> int:
    environment = os.environ.copy()
    environment.update(
        {
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
            "PYTHONHASHSEED": "2026082107",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join((str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))),
        }
    )
    if hashlib.sha256(Path(RUFF_EXECUTABLE).read_bytes()).hexdigest() != (
        RUFF_EXECUTABLE_SHA256
    ):
        raise RuntimeError("pinned Ruff executable drifted")
    source_audit = run_source_audit(PROJECT_ROOT)
    if not source_audit.passed:
        raise RuntimeError(json.dumps(source_audit.payload(), indent=2))

    pytest_receipt = _run_quality_command(
        [
            CPU_LAB_PYTHON,
            "-B",
            "-m",
            "pytest",
            "-q",
            "tests/model_lab/test_causal_valuation_tcn_v1.py",
        ],
        environment,
    )
    ruff_receipt = _run_quality_command(
        [
            RUFF_EXECUTABLE,
            "check",
            "research/model_zoo/causal_valuation_tcn_v1",
            "scripts/model_lab/build_causal_valuation_tcn_v1_preflight.py",
            "tests/model_lab/causal_valuation_tcn_v1_torch_checks.py",
            "tests/model_lab/test_causal_valuation_tcn_v1.py",
        ],
        environment,
    )
    if pytest_receipt["return_code"] != 0 or ruff_receipt["return_code"] != 0:
        raise RuntimeError(
            json.dumps({"pytest": pytest_receipt, "ruff": ruff_receipt}, indent=2)
        )
    quality_payload = {
        "schema_version": "expected_pe.causal_valuation_tcn_v1.quality_receipt.v1",
        "status": "PASS_FIXED_TEST_AND_LINT_SURFACE",
        "pytest": pytest_receipt,
        "ruff": ruff_receipt,
        "torch_interpreter": PINNED_PYTHON,
        "real_fit_or_score_run": False,
    }
    smoke = run_cross_device_synthetic_smoke(PROJECT_ROOT)
    output = build_design_bundle(
        project_root=PROJECT_ROOT,
        smoke_payload=smoke,
        source_audit=source_audit,
        quality_payload=quality_payload,
    )
    checksums_sha256 = hashlib.sha256((output / "CHECKSUMS.sha256").read_bytes()).hexdigest()
    sys.stdout.write(
        json.dumps(
            {
                "status": "FROZEN_SCORE_FREE_DESIGN_AWAITING_INDEPENDENT_AUDIT",
                "output_directory": output.relative_to(PROJECT_ROOT).as_posix(),
                "checksums_raw_sha256": checksums_sha256,
                "source_audit_sha256": source_audit.sha256(),
                "synthetic_smoke_semantic_sha256": smoke["semantic_sha256"],
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
