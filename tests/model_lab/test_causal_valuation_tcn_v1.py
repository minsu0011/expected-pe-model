"""Host-pytest bridge to the isolated torch architecture checks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from research.model_zoo.causal_valuation_tcn_v1.artifacts import verify_design_bundle
from research.model_zoo.causal_valuation_tcn_v1.contracts import (
    ACCESS_BOUNDARY,
    CANDIDATE_IDS,
    ENVIRONMENT_PREFLIGHT_BINDING,
    contract_sha256,
)
from research.model_zoo.causal_valuation_tcn_v1.source_audit import run_source_audit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TORCH_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
DESIGN_ROOT = (
    PROJECT_ROOT / "outputs/model_zoo_causal_valuation_tcn_v1_design_preflight_20260821"
)


def test_fixed_score_free_contract_and_source_isolation() -> None:
    assert len(CANDIDATE_IDS) == 3
    assert len(contract_sha256()) == 64
    assert all(
        value is False
        for key, value in ACCESS_BOUNDARY.items()
        if key != "permitted_data"
    )
    assert ACCESS_BOUNDARY["permitted_data"] == (
        "deterministically_generated_unit_tensors_only"
    )
    receipt = run_source_audit(PROJECT_ROOT)
    assert receipt.passed, receipt.payload()
    assert receipt.environment_preflight_binding_passed
    environment_receipt = (
        PROJECT_ROOT
        / ENVIRONMENT_PREFLIGHT_BINDING["directory"]
        / "ENVIRONMENT_RECEIPT.json"
    )
    payload = json.loads(environment_receipt.read_text(encoding="utf-8"))
    assert payload["verdict"] == "READY_FOR_SCORE_FREE_CAUSAL_SEQUENCE_DESIGN_ONLY"


def test_isolated_torch_unit_suite() -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
            "PYTHONHASHSEED": "2026082107",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join((str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))),
        }
    )
    process = subprocess.run(
        [
            str(TORCH_PYTHON),
            "-B",
            "tests/model_lab/causal_valuation_tcn_v1_torch_checks.py",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    assert "PASS_CAUSAL_VALUATION_TCN_V1_TORCH_CHECKS" in process.stdout


def test_frozen_design_bundle_if_present() -> None:
    if not DESIGN_ROOT.exists():
        return
    checksums = (DESIGN_ROOT / "CHECKSUMS.sha256").read_bytes()
    result = verify_design_bundle(
        DESIGN_ROOT,
        expected_checksums_raw_sha256=hashlib.sha256(checksums).hexdigest(),
    )
    assert result["status"] == "PASS_FROZEN_SCORE_FREE_DESIGN_BUNDLE"
