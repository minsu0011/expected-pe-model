from __future__ import annotations

import csv
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from research.model_zoo.prospective_fresh_ensemble_v1.artifacts import (
    json_bytes,
    write_bytes_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v4.contracts import (
    GENERATOR_CONTRACT,
    GENERATOR_MAX_PATH_CHARS,
    ProspectiveContractError,
    seal_payload,
)
from research.model_zoo.prospective_fresh_ensemble_v4.generator_contract import (
    ATTEMPT_PAYLOAD_KEYS,
    SMOKE_PAYLOAD_KEYS,
    SMOKE_RECEIPT_NAME,
    _attempt_payload,
    build_generator_plan,
    execute_generator_attempt,
    expected_v03_relative_files,
    run_generator_smoke,
    verify_generator_attempt_receipt,
    verify_generator_smoke_receipt,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVOCATION = "0123456789abcdef0123456789abcdef"


def _runtime_boundary() -> dict[str, Any]:
    return {
        "apply": True,
        "required_cpu_ids": list(range(32)),
        "observed_cpu_ids": list(range(32)),
        "affinity_mask_hex": "0xFFFFFFFF",
        "maximum_outer_workers": 32,
        "inner_threads": 1,
        "gpu_policy": "SEALED_OFF",
        "ram": {"total_physical_gib": 96.0, "available_physical_gib": 80.0},
    }


def _legacy_observation() -> dict[str, Any]:
    return {
        "platform": "windows" if os.name == "nt" else os.name,
        "registry_hive": "HKEY_LOCAL_MACHINE",
        "registry_path": r"SYSTEM\CurrentControlSet\Control\FileSystem",
        "registry_value_name": "LongPathsEnabled",
        "value": 0 if os.name == "nt" else None,
        "enabled": False if os.name == "nt" else None,
        "legacy_limit_observed": True if os.name == "nt" else None,
    }


def _plan(
    monkeypatch: pytest.MonkeyPatch,
    *,
    invocation_id: str,
    stage: str = "smoke",
):
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.generator_contract."
        "observe_windows_long_paths",
        _legacy_observation,
    )
    return build_generator_plan(
        PROJECT_ROOT,
        stage=stage,
        invocation_id=invocation_id,
        seed=7307,
        runtime_boundary_record=_runtime_boundary(),
    )


@pytest.fixture
def managed_invocation(tmp_path: Path):
    invocation_id = hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:32]
    yield invocation_id
    managed = (PROJECT_ROOT / "outputs" / "_p4g_v4").resolve()
    for stage in ("smoke", "qualification", "heldout"):
        stage_root = (managed / stage).resolve()
        target = (stage_root / invocation_id).resolve()
        if target.parent != stage_root:
            raise AssertionError("test cleanup escaped the V4 managed stage root")
        if target.exists():
            shutil.rmtree(target)
        if stage_root.is_dir() and not any(stage_root.iterdir()):
            stage_root.rmdir()
    if managed.is_dir() and not any(managed.iterdir()):
        managed.rmdir()


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _emit_exact_fake_v03(plan) -> None:
    dates = [f"session_{index:04d}" for index in range(1800)]
    canonical_header = ["date", "symbol", "observed_pe", "ml_expected_pe"] + [
        f"column_{index:03d}" for index in range(146)
    ]
    canonical_rows = [
        [date, "DEMO", "20", "21", *(["0"] * 146)] for date in dates
    ]
    _write_csv(plan.expected_v03_files["canonical_csv"], canonical_header, canonical_rows)
    truth_header = [
        "date",
        "true_fair_pe",
        "true_observed_pe",
        "true_regime",
        "demo_generator_version",
    ]
    truth_rows = [
        [date, "20", "21", "BULL", str(GENERATOR_CONTRACT["generator_version"])]
        for date in dates
    ]
    _write_csv(plan.expected_v03_files["adjacent_truth_csv"], truth_header, truth_rows)
    plan.expected_v03_files["input_truth_csv"].parent.mkdir(parents=True, exist_ok=True)
    plan.expected_v03_files["input_truth_csv"].write_bytes(
        plan.expected_v03_files["adjacent_truth_csv"].read_bytes()
    )
    for role in (
        "input_price_csv",
        "input_price_split_adjusted_csv",
        "input_benchmark_csv",
    ):
        _write_csv(
            plan.expected_v03_files[role],
            ["date", "close"],
            [[date, "100"] for date in dates],
        )
    _write_csv(plan.expected_v03_files["input_eps_csv"], ["date", "eps"], [[dates[0], "2"]])
    generation = {
        "generator_version": GENERATOR_CONTRACT["generator_version"],
        "seed": plan.seed,
        "rows": 1800,
        "input_dir": str(
            plan.output_root
            / "demo_inputs"
            / (
                f"{GENERATOR_CONTRACT['generator_version']}_seed_{plan.seed}_"
                "rows_1800"
            )
        ),
    }
    plan.expected_v03_files["validation_json"].write_text(
        json.dumps({"demo_generation": generation}),
        encoding="utf-8",
    )
    for role in ("summary_json", "diagnostics_json"):
        plan.expected_v03_files[role].write_text("{}\n", encoding="utf-8")
    for role in (
        "intermediate_eps_csv",
        "intermediate_benchmark_csv",
        "intermediate_regime_csv",
    ):
        path = plan.expected_v03_files[role]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value\n1\n", encoding="utf-8")


def test_v4_generator_static_tree_is_exact_legacy_safe_and_command_owned() -> None:
    plan = build_generator_plan(
        PROJECT_ROOT,
        stage="qualification",
        invocation_id=INVOCATION,
        seed=7417,
        runtime_boundary_record=_runtime_boundary(),
    )
    assert plan.attempt_root == (
        PROJECT_ROOT / "outputs" / "_p4g_v4" / "qualification" / INVOCATION / "7417"
    ).resolve()
    assert len(expected_v03_relative_files(7417)) == 13
    assert plan.path_policy["longest_static_path_chars"] == 234
    assert plan.path_policy["longest_static_path_chars"] <= GENERATOR_MAX_PATH_CHARS
    assert plan.argv == (
        str(plan.v03_python),
        "-m",
        "pe_regime_engine",
        "demo",
        "--config",
        str(plan.v03_config),
        "--output-dir",
        str(plan.attempt_root),
        "--start",
        "2013-01-02",
        "--seed",
        "7417",
        "--rows",
        "1800",
        "--no-chart",
    )
    assert plan.environment["PYTHONPATH"] == str((plan.v03_root / "src").resolve())
    assert os.pathsep not in plan.environment["PYTHONPATH"]
    assert all(plan.environment[name] == "1" for name in (
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ))
    assert plan.environment["CUDA_VISIBLE_DEVICES"] == "-1"
    assert plan.environment_contract["inherited_values_disclosed"] is False
    assert set(_attempt_payload(plan)) == ATTEMPT_PAYLOAD_KEYS


def test_v4_generator_rejects_noncanonical_identity_and_bad_runtime() -> None:
    with pytest.raises(ProspectiveContractError, match="32 lowercase hex"):
        build_generator_plan(
            PROJECT_ROOT,
            stage="qualification",
            invocation_id="A" * 32,
            seed=7417,
            runtime_boundary_record=_runtime_boundary(),
        )
    bad = _runtime_boundary()
    bad["observed_cpu_ids"] = list(range(31))
    with pytest.raises(ProspectiveContractError, match="runtime boundary"):
        build_generator_plan(
            PROJECT_ROOT,
            stage="qualification",
            invocation_id=INVOCATION,
            seed=7417,
            runtime_boundary_record=bad,
        )


def test_v4_generator_rejects_actual_environment_tamper_before_receipt_or_spawn(
    monkeypatch: pytest.MonkeyPatch,
    managed_invocation: str,
) -> None:
    plan = _plan(monkeypatch, invocation_id=managed_invocation)
    plan.environment["PYTHONPATH"] = str(PROJECT_ROOT / "attacker")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("tampered environment reached subprocess"),
    )
    with pytest.raises(ProspectiveContractError, match="environment differs"):
        execute_generator_attempt(plan)
    assert not plan.attempt_root.exists()


def test_v4_attempt_receipt_exists_before_one_exact_spawn(
    monkeypatch: pytest.MonkeyPatch,
    managed_invocation: str,
) -> None:
    plan = _plan(monkeypatch, invocation_id=managed_invocation)
    calls = 0

    def fake_run(argv, *, cwd, env, stdout, stderr, check, shell):
        nonlocal calls
        calls += 1
        assert plan.attempt_receipt_path.is_file()
        assert plan.log_path.is_file()
        assert list(plan.argv) == argv
        assert cwd == plan.v03_root
        assert env == plan.environment
        assert stderr is subprocess.STDOUT
        assert check is False and shell is False
        _emit_exact_fake_v03(plan)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = execute_generator_attempt(plan)
    assert calls == 1
    assert result.returncode == 0
    assert len(result.v03_files) == 13
    receipt = verify_generator_attempt_receipt(
        plan.attempt_receipt_path,
        expected_project_root=plan.project_root,
    )
    assert receipt["subprocess_started_at_receipt_write"] is False
    assert receipt["v4_candidate_fit_calls"] == 0
    assert receipt["v03_demo_pipeline_and_synthetic_validation_expected"] is True


def test_v4_smoke_is_spent_seed_generator_only_and_full_leaf_verified(
    monkeypatch: pytest.MonkeyPatch,
    managed_invocation: str,
) -> None:
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.generator_contract."
        "runtime_boundary",
        lambda *, apply: _runtime_boundary(),
    )
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.generator_contract."
        "observe_windows_long_paths",
        _legacy_observation,
    )
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.generator_contract."
        "secrets.token_hex",
        lambda size: managed_invocation,
    )

    def fake_run(argv, *, cwd, env, stdout, stderr, check, shell):
        del cwd, env, stdout, stderr, check, shell
        output = Path(argv[argv.index("--output-dir") + 1])
        plan = build_generator_plan(
            PROJECT_ROOT,
            stage="smoke",
            invocation_id=managed_invocation,
            seed=7307,
            runtime_boundary_record=_runtime_boundary(),
        )
        assert output == plan.output_root
        assert plan.attempt_receipt_path.is_file()
        _emit_exact_fake_v03(plan)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    receipt = run_generator_smoke(PROJECT_ROOT)
    assert set(receipt) == SMOKE_PAYLOAD_KEYS
    assert receipt["seed"] == 7307
    assert receipt["subprocess_returncode"] == 0
    assert receipt["evidence_classification"].startswith("NON_EVIDENTIARY_SPENT_SEED")
    assert receipt["qualification_or_heldout_launched"] is False
    assert receipt["qualification_or_heldout_truth_opened"] is False
    assert receipt["v4_candidate_fit_calls"] == 0
    assert receipt["v4_candidate_prediction_rows"] == 0
    assert receipt["v4_candidate_scores_computed"] is False
    receipt_path = Path(receipt["attempt_root"]) / SMOKE_RECEIPT_NAME
    assert verify_generator_smoke_receipt(
        receipt_path,
        expected_project_root=PROJECT_ROOT,
    ) == receipt
    (Path(receipt["attempt_root"]) / "attacker.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(ProspectiveContractError, match="inventory changed"):
        verify_generator_smoke_receipt(
            receipt_path,
            expected_project_root=PROJECT_ROOT,
        )


def test_v4_attempt_rejects_resealed_extra_schema_key(
    monkeypatch: pytest.MonkeyPatch,
    managed_invocation: str,
) -> None:
    plan = _plan(monkeypatch, invocation_id=managed_invocation)
    payload = _attempt_payload(plan)
    payload.pop("attempt_receipt_sha256")
    payload["attacker_extra"] = True
    resealed = seal_payload(payload, "attempt_receipt_sha256")
    write_bytes_exclusive(plan.attempt_receipt_path, json_bytes(resealed))
    with pytest.raises(ProspectiveContractError, match="schema changed"):
        verify_generator_attempt_receipt(
            plan.attempt_receipt_path,
            expected_project_root=plan.project_root,
        )


def test_v4_smoke_cli_has_no_caller_seed_path_or_invocation_arguments() -> None:
    script = (
        PROJECT_ROOT
        / "scripts"
        / "model_lab"
        / "prospective_fresh_ensemble_v4"
        / "run_generator_smoke.py"
    )
    source = script.read_text(encoding="utf-8")
    assert "argparse" not in source
    assert "--seed" not in source
    assert "--output" not in source
    assert "--invocation" not in source
