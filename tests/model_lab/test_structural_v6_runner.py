"""Score-free regressions for the Structural V6 release blockers."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

from pe_regime_v04.model_lab.structural.contracts import (
    StructuralContractError,
    canonical_json_bytes,
    sha256_bytes,
    verify_payload_seal,
)


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v6.py"
PINNED_PYTHON = ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe"
RUNTIME = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/RUNTIME_ENVIRONMENT_V6.json"
)


def _runner():
    spec = importlib.util.spec_from_file_location("_structural_v6_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_inputs(module):
    environment = json.loads(RUNTIME.read_text(encoding="utf-8"))
    clean_environment = dict(os.environ)
    clean_environment.pop("PYTHONHOME", None)
    clean_environment.pop("PYTHONPATH", None)
    freeze = subprocess.run(
        [str(PINNED_PYTHON), "-m", "pip", "freeze", "--all"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        env=clean_environment,
    )
    lines = tuple(
        line.strip()
        for line in freeze.stdout.decode("utf-8", errors="strict").splitlines()
        if line.strip()
    )
    packages = module._freeze_package_map(lines)
    return environment, freeze.stdout, lines, packages


def test_v6_complete_runtime_inventory_accepts_exact_freeze_and_map() -> None:
    module = _runner()
    environment, stdout, lines, packages = _runtime_inputs(module)
    result = module._validate_runtime_inventory(
        environment,
        freeze_stdout=stdout,
        freeze_lines=lines,
        package_versions=packages,
    )
    assert result["package_count"] == len(environment["package_versions_all"]) == 38
    assert result["lightgbm_version"] == "4.6.0"
    assert result["pyyaml_version"] == "6.0.2"
    assert environment["package_versions_all_sha256"] == sha256_bytes(
        canonical_json_bytes(environment["package_versions_all"])
    )


@pytest.mark.parametrize("package", ["lightgbm", "pyyaml"])
def test_v6_missing_or_mutated_branch_package_fails_closed(package: str) -> None:
    module = _runner()
    environment, stdout, lines, packages = _runtime_inputs(module)
    missing = dict(packages)
    missing.pop(package)
    with pytest.raises(StructuralContractError):
        module._validate_runtime_inventory(
            environment,
            freeze_stdout=stdout,
            freeze_lines=lines,
            package_versions=missing,
        )
    mutated = dict(packages)
    mutated[package] = "0.0-adversarial"
    with pytest.raises(StructuralContractError):
        module._validate_runtime_inventory(
            environment,
            freeze_stdout=stdout,
            freeze_lines=lines,
            package_versions=mutated,
        )


def test_v6_mutated_complete_freeze_fails_closed() -> None:
    module = _runner()
    environment, stdout, lines, packages = _runtime_inputs(module)
    with pytest.raises(StructuralContractError):
        module._validate_runtime_inventory(
            environment,
            freeze_stdout=stdout + b" ",
            freeze_lines=lines,
            package_versions=packages,
        )
    changed_lines = tuple(
        "lightgbm==0.0-adversarial" if line.lower().startswith("lightgbm==") else line
        for line in lines
    )
    with pytest.raises(StructuralContractError):
        module._validate_runtime_inventory(
            environment,
            freeze_stdout=stdout,
            freeze_lines=changed_lines,
            package_versions=packages,
        )


def test_v6_payload_binds_exact_fold_membership_and_rejects_mutation() -> None:
    module = _runner()
    payload = module._payloads(
        activation_raw_sha256="a" * 64,
        policy_raw_sha256="b" * 64,
        policy_pin_raw_sha256="c" * 64,
    )[0]
    seed, candidate_id, fold_ids = module._validate_payload(payload)
    assert seed == 6301
    assert candidate_id == "decomp_block_ridge_ar1_lag1"
    assert fold_ids == (
        "fold_012",
        "fold_020",
        "fold_028",
        "fold_036",
        "fold_044",
        "fold_052",
        "fold_060",
        "fold_068",
    )
    membership = module._fold_membership(fold_ids)
    assert membership[0]["train_positions"] == list(range(0, 504))
    assert membership[0]["test_positions"] == list(range(504, 525))
    assert membership[-1]["train_positions"] == list(range(672, 1680))
    assert membership[-1]["test_positions"] == list(range(1680, 1701))
    mutated = dict(payload)
    mutated["fold_positions_sha256"] = "0" * 64
    with pytest.raises(StructuralContractError):
        module._validate_payload(mutated)


def test_v6_live_spawn_failure_has_exact_identity_environment_trace_and_shutdown() -> None:
    completed = subprocess.run(
        [str(PINNED_PYTHON), str(RUNNER), "--failure-attribution-self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout.strip().splitlines()[-1])
    verify_payload_seal(receipt)
    identity = receipt["task_identity"]
    assert identity["payload_sha256"] != "MISSING"
    assert identity["seed"] == 6301
    assert identity["candidate_id"] == "decomp_block_ridge_ar1_lag1"
    assert identity["fold_ids"][0] == "fold_012"
    assert identity["fold_positions"][0]["test_positions"] == list(range(504, 525))
    worker = receipt["worker_first_observation_receipt"]
    verify_payload_seal(worker)
    assert worker["task_identity"] == identity
    assert worker["worker_environment"]["pid"] > 0
    assert worker["worker_environment"]["runtime_verification"]["lightgbm_version"] == "4.6.0"
    assert worker["worker_environment"]["runtime_verification"]["pyyaml_version"] == "6.0.2"
    assert "forced-structural-v6-synthetic-worker-failure" in worker["exception"]["traceback"]
    shutdown = receipt["fail_fast_shutdown_receipt"]
    verify_payload_seal(shutdown)
    assert shutdown["shutdown_wait"] is False
    assert shutdown["cancel_futures"] is True
    assert shutdown["worker_pids_alive_after_poll"] == []


def test_v6_runtime_preflight_accepts_pin_and_rejects_base_python() -> None:
    allowed = subprocess.run(
        [str(PINNED_PYTHON), str(RUNNER), "--runtime-preflight-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.returncode == 0
    assert "STRUCTURAL_V6_RUNTIME_PREFLIGHT_PASS" in allowed.stdout
    rejected = subprocess.run(
        ["C:/Users/minsu/anaconda3/python.exe", str(RUNNER), "--runtime-preflight-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "rejects non-pinned Python launcher" in rejected.stderr
