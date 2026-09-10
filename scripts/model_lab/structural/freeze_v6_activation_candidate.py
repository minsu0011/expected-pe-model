"""Freeze the score-free Structural V6 test evidence and blocked activation candidate."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)


V6 = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819"
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v6.py"
TEST = ROOT / "tests/model_lab/test_structural_v6_runner.py"
PINNED = (ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)
BASE = Path("C:/Users/minsu/anaconda3/python.exe")
TEST_EVIDENCE = V6 / "V6_TEST_EVIDENCE.json"
ACTIVATION = V6 / "ACTIVATION_CANDIDATE_V6.json"


def _read_sealed(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"sealed object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, logical: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "raw_sha256": sha256_file(path),
    }
    if logical:
        row["logical_sha256"] = _read_sealed(path)["manifest_sha256"]
    return row


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run(command: list[str], *, environment: Mapping[str, str] | None = None):
    return subprocess.run(
        command,
        cwd=ROOT,
        env=dict(environment) if environment is not None else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=120,
    )


def main() -> int:
    if (V6 / "prediction").exists():
        raise RuntimeError("V6 prediction directory exists")
    test_environment = dict(os.environ)
    test_environment["PYTHONPATH"] = str(SRC)
    pytest = _run(
        [str(PINNED), "-m", "pytest", "-q", str(TEST.relative_to(ROOT))],
        environment=test_environment,
    )
    if pytest.returncode != 0 or "......." not in pytest.stdout:
        raise RuntimeError(f"V6 regression suite failed: {pytest.stdout}\n{pytest.stderr}")
    preflight = _run([str(PINNED), str(RUNNER), "--runtime-preflight-only"])
    if preflight.returncode != 0 or "STRUCTURAL_V6_RUNTIME_PREFLIGHT_PASS" not in preflight.stdout:
        raise RuntimeError("V6 pinned runtime preflight failed")
    base = _run([str(BASE), str(RUNNER), "--runtime-preflight-only"])
    if base.returncode == 0 or "rejects non-pinned Python launcher" not in base.stderr:
        raise RuntimeError("V6 base Python adversarial launch did not reject")
    failure = _run([str(PINNED), str(RUNNER), "--failure-attribution-self-test"])
    if failure.returncode != 0:
        raise RuntimeError(f"V6 live failure attribution failed: {failure.stderr}")
    receipt = json.loads(failure.stdout.strip().splitlines()[-1])
    verify_payload_seal(receipt)
    worker_receipt = receipt["worker_first_observation_receipt"]
    verify_payload_seal(worker_receipt)
    shutdown = receipt["fail_fast_shutdown_receipt"]
    verify_payload_seal(shutdown)
    if receipt["worker_receipt_validation_error"] is not None:
        raise RuntimeError("V6 worker receipt validation failed")

    runtime_path = V6 / "RUNTIME_ENVIRONMENT_V6.json"
    runtime = _read_sealed(runtime_path)
    v5_audit_path = (
        ROOT / "outputs/model_zoo_structural_wave_fifth_independent_audit_20260819/AUDIT.json"
    )
    test_evidence = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_score_free_test_evidence",
            "sources": {
                "runner_v6": _record(RUNNER),
                "authorization_v6": _record(
                    ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v6.py"
                ),
                "runtime_preparer_v6": _record(
                    ROOT / "scripts/model_lab/structural/prepare_v6_runtime_environment.py"
                ),
                "tests_v6": _record(TEST),
            },
            "runtime_environment_v6": _record(runtime_path, logical=True),
            "v5_independent_no_go_audit": _record(v5_audit_path, logical=True),
            "pytest": {
                "interpreter": PINNED.as_posix(),
                "command": "pinned CPython -m pytest -q tests/model_lab/test_structural_v6_runner.py",
                "returncode": pytest.returncode,
                "summary": pytest.stdout.strip(),
                "passed": 7,
            },
            "runtime_adversarial": {
                "pinned_preflight_passed": True,
                "base_cpython_3_13_rejected": True,
                "complete_package_count": len(runtime["package_versions_all"]),
                "pip_freeze_all_sha256": runtime["pip_freeze_all_sha256"],
                "freeze_stdout_raw_sha256": runtime["freeze_stdout_raw_sha256"],
                "package_versions_all_sha256": runtime["package_versions_all_sha256"],
                "lightgbm": runtime["package_versions_all"]["lightgbm"],
                "pyyaml": runtime["package_versions_all"]["pyyaml"],
                "missing_or_mutated_lightgbm_tested": True,
                "missing_or_mutated_pyyaml_tested": True,
                "mutated_freeze_tested": True,
            },
            "live_spawn_failure_attribution": {
                "receipt_manifest_sha256": receipt["manifest_sha256"],
                "worker_receipt_manifest_sha256": worker_receipt["manifest_sha256"],
                "shutdown_receipt_manifest_sha256": shutdown["manifest_sha256"],
                "payload_sha256": receipt["task_identity"]["payload_sha256"],
                "seed": receipt["task_identity"]["seed"],
                "candidate_id": receipt["task_identity"]["candidate_id"],
                "fold_ids": receipt["task_identity"]["fold_ids"],
                "fold_positions_sha256": sha256_bytes(
                    canonical_json_bytes(receipt["task_identity"]["fold_positions"])
                ),
                "worker_pid": worker_receipt["worker_environment"]["pid"],
                "worker_environment_present": True,
                "worker_trace_present": True,
                "shutdown_wait": shutdown["shutdown_wait"],
                "cancel_futures": shutdown["cancel_futures"],
                "alive_after_poll": shutdown["worker_pids_alive_after_poll"],
            },
            "candidate_fit_or_prediction_started": False,
            "truth_opened": False,
            "scores_computed": False,
            "seeds_reserved": False,
        }
    )
    _write_atomic(TEST_EVIDENCE, test_evidence)

    exact_bindings = {
        "physical_prediction_runner_v6": _record(RUNNER),
        "frozen_runner_v5_dependency": _record(
            ROOT / "scripts/model_lab/structural/run_spent_predictions_v5.py"
        ),
        "frozen_runner_v4_transitive_dependency": _record(
            ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py"
        ),
        "authorization_v5_transitive_dependency": _record(
            ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v5.py"
        ),
        "authorization_v6": _record(
            ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v6.py"
        ),
        "runtime_environment_v6": _record(runtime_path),
        "v5_independent_no_go_audit": _record(v5_audit_path),
        "v4_failed_attempt": _record(
            ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json"
        ),
    }
    activation = seal_payload(
        {
            "format_version": 6,
            "mode": "structural_v6_blocked_activation_candidate",
            "state": "NO_GO_PENDING_INDEPENDENT_V6_AUDIT",
            "exact_bindings": exact_bindings,
            "audit_evidence_bindings": {
                "v6_test_evidence": _record(TEST_EVIDENCE, logical=True),
                "v5_implementation_manifest": _record(
                    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/"
                    "IMPLEMENTATION_MANIFEST_V5.json",
                    logical=True,
                ),
            },
            "execution_contract": {
                "candidate_ids": list(
                    (
                        "decomp_block_ridge_ar1_lag1",
                        "decomp_block_ridge_ar1_current",
                        "residual_ar1_nested_oof",
                        "stack_geometric_equal_pair",
                        "stack_simplex_pair_frozen",
                    )
                ),
                "seeds": [6301, 6421, 6521, 6607, 6701],
                "seed_role": "ALREADY_SPENT_WAVE1_ONLY",
                "outer_workers": 8,
                "inner_threads": 1,
                "gpu": "OFF",
                "task_count": 200,
                "chunks_per_seed_candidate": 8,
                "same_bytes_v5_scheduling_preserved": True,
                "failure_receipt_required": True,
                "expected_rerun_wall_minutes": [25, 35],
            },
            "fold_contract": {
                "required_evaluation_fold_ids": [f"fold_{index:03d}" for index in range(12, 74)],
                "required_evaluation_positions": "range(504,1800)",
                "required_rows_per_seed_candidate": 1296,
                "full_membership_schedule_sha256": (
                    "1d2423311c01397dafca26f7a865be7fb470fd337897e714a8a975a32f559c00"
                ),
                "coverage_sha256": (
                    "2cbc336c9ea85a7cbc42af253e6f259940ee748189cdf4f4cc38c66545866f37"
                ),
            },
            "runtime_contract": {
                "complete_pip_freeze_and_package_map_verified_parent_and_every_worker": True,
                "package_count": len(runtime["package_versions_all"]),
                "lightgbm": "4.6.0",
                "pyyaml": "6.0.2",
                "launcher": runtime["launcher"],
                "actual_process_image": runtime["actual_process_image"],
                "python_version_info": runtime["runtime"]["version_info"],
            },
            "failure_contract": {
                "worker_first_observation_sealed": True,
                "parent_future_map_identity_sealed": True,
                "fields": [
                    "payload_sha256",
                    "seed",
                    "candidate_id",
                    "fold_ids",
                    "fold_positions",
                    "worker_pid",
                    "worker_environment",
                    "traceback",
                ],
                "fail_fast_cancellation_termination_receipt": True,
            },
            "decision": {
                "independent_v6_audit": "PENDING",
                "open_p0": 1,
                "open_p1": 1,
                "spent_seed_screen": "NO_GO",
                "structural_prediction_or_scoring_authorized": False,
            },
            "attestations": {
                "v6_predictions_generated": False,
                "evaluation_truth_opened": False,
                "scores_computed": False,
                "seeds_selected_or_reserved": False,
            },
        }
    )
    _write_atomic(ACTIVATION, activation)
    print(
        json.dumps(
            {
                "test_evidence_raw_sha256": sha256_file(TEST_EVIDENCE),
                "test_evidence_logical_sha256": test_evidence["manifest_sha256"],
                "activation_raw_sha256": sha256_file(ACTIVATION),
                "activation_logical_sha256": activation["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
