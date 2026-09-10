"""Seal the non-executable Structural V5 activation candidate for independent audit."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.authorization import (  # noqa: E402
    EXPECTED_ENABLED,
    _verify_snapshot,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.structural.nested import (  # noqa: E402
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
)


V5 = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819"
OUTPUT = V5 / "ACTIVATION_CANDIDATE_V5.json"
SEEDS = (6301, 6421, 6521, 6607, 6701)
UPSTREAM = {
    "design": (
        ROOT / "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json",
        "6a1516dc0b75bfa93ffadbdff253cb634dccf3ce7f579bc713033b70db33c4cf",
        None,
    ),
    "trigger_decision": (
        ROOT / "outputs/model_zoo_structural_wave_screen_20260819/TRIGGER_DECISION.json",
        "45b6dee894ed72809c49902f4f78ff058a465db6ebfe8903a21c659883504765",
        "a3440ae5a3aa81767738d59e4f60ae391e0034d6e223c6f8513089042c1b7023",
    ),
    "base_binding_lock_v4": (
        ROOT / "outputs/model_zoo_structural_wave_screen_20260819/BASE_BINDING_LOCK_V4.json",
        "b60ca510b4cad411c29dded212df934e327b948c24f0a932060e1bdff26a81a4",
        "23f10ffdbbf4f81157997baf54a770d47d764eb7196bed4bee6b945b2293bf47",
    ),
    "execution_snapshot_v4": (
        ROOT / "outputs/model_zoo_structural_wave_screen_20260819/EXECUTION_SNAPSHOT_V4.json",
        "b1996943814339ca3b9b9aa4b1d92c13bfe569783e9a174b9440bff54705dec2",
        "f42c7569fd362fddc843d0b81dc34323a819db99f591662a405f651818befd0c",
    ),
    "predict_inputs": (
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
        "f8f30ab74d812909b644984ba9ee3c4a8f509dfabb2ab566c7048313245d500c",
        "b08dd0a63c9b02ef14f06b3fd48764ac44c954100be5f360d03df7390aa494e8",
    ),
    "v4_terminal_failure_audit": (
        ROOT
        / "outputs/model_zoo_structural_wave_terminal_failure_independent_audit_20260819/AUDIT.json",
        "47acda1109f10d4d8d17c5cc04f4d38b52c7ae71fffad443541aa99de3d3f8f5",
        "7ee395daa6366277b7b9b6371983c8f6b0ab3e7c28591a72887127f401a0524c",
    ),
    "runtime_environment_v5": (
        V5 / "RUNTIME_ENVIRONMENT_V5.json",
        "1c23932a1b4bb25daecd5939c7d58b1e89de160e30d1a4777ce62c43ea164f55",
        "68c2155e71a8952c3edf5f9679f2de1f152a958d7c9aa94bc392f4501c4a2b49",
    ),
    "scheduling_parity_v5": (
        V5 / "NO_SCORE_SCHEDULING_PARITY_V5.json",
        "d5a3678fd6d2d0967fd8021c843e960b544c480b6deb91c2bf6806db111a5a80",
        "5e7548f39aa4489dac90c510883c0ebf188ae805a3d1707cd81a2653b4472991",
    ),
    "test_evidence_v5": (
        V5 / "V5_TEST_EVIDENCE.json",
        "3c11dfceaa7043e11fd8a63fbf8b02131e394478d10dd671a80c326e8a2ca759",
        "b49e0bca09abee9b0d2673834926a5f9ddde30f895fa7189222c4085ab78366e",
    ),
    "v4_failed_attempt": (
        ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json",
        "d8b6723854ce03a897bbef6febcc8e5bae0654896c3f73a1bcaddeabe4544cb8",
        "453e3f4939c15a38dedccc603b839fc57b34eaf43401ffbb6f032e6697e9b8bd",
    ),
    "v4_failure_addendum_v2": (
        V5 / "V4_FAILED_ATTEMPT_ADDENDUM_V2.json",
        "548689b15472b57d0c36f684e94adbf03847a014ca954a0e74f302b9a8f022ec",
        "f5079a0e6c0dd7112df2aa5a7be198da7e37d0e1e1068c525246c93ae5127cd1",
    ),
}
SOURCE_PATHS = {
    "physical_prediction_runner_v5": ROOT
    / "scripts/model_lab/structural/run_spent_predictions_v5.py",
    "authorization_v5": ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v5.py",
    "frozen_runner_v4_dependency": ROOT
    / "scripts/model_lab/structural/run_spent_predictions_v4.py",
    "v5_regression_tests": ROOT / "tests/model_lab/test_structural_v5_runner.py",
    "scheduling_parity_script": ROOT
    / "scripts/model_lab/structural/benchmark_v5_scheduling_no_score.py",
}


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, raw: str | None = None, logical: str | None = None) -> dict[str, Any]:
    path = path.resolve(strict=True)
    current = sha256_file(path)
    if raw is not None and current != raw:
        raise RuntimeError(f"raw dependency drift: {path}")
    row: dict[str, Any] = {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "raw_sha256": current,
    }
    if logical is not None:
        payload = _read(path)
        if payload["manifest_sha256"] != logical:
            raise RuntimeError(f"logical dependency drift: {path}")
        row["logical_sha256"] = logical
    return row


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    snapshot = _read(UPSTREAM["execution_snapshot_v4"][0])
    _verify_snapshot(snapshot, ROOT)
    if (V5 / "prediction").exists():
        raise RuntimeError("V5 prediction directory exists before independent audit")
    exact_bindings = {
        name: _record(path, raw=raw, logical=logical)
        for name, (path, raw, logical) in UPSTREAM.items()
    }
    exact_bindings.update({name: _record(path) for name, path in SOURCE_PATHS.items()})
    payload = seal_payload(
        {
            "format_version": 5,
            "mode": "structural_v5_blocked_activation_candidate",
            "state": "NO_GO_PENDING_INDEPENDENT_V5_AUDIT",
            "exact_bindings": exact_bindings,
            "repair_contract": {
                "target_eligibility": "positive-finite outer-train target; leading warm-up only",
                "invalid_positions_each_seed": [0, 1],
                "affected_fold_ids": [f"fold_{index:03d}" for index in range(12, 37)],
                "first_unaffected_fold_id": "fold_037",
                "fold_012_total_train_rows": 504,
                "fold_012_eligible_train_rows": 502,
                "zero_eligible_action": "FAIL_CLOSED",
                "interior_target_gap_action": "FAIL_CLOSED",
                "feature_nonfinite_handling": (
                    "outer-train-only median imputation; all-missing column drop; frozen transform"
                ),
                "formal_prediction_identity_or_mask_changed": False,
                "candidate_parameters_changed": False,
            },
            "runtime_contract": {
                "launcher_path": (
                    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
                ),
                "launcher_raw_sha256": (
                    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
                ),
                "python": "CPython 3.10.19",
                "actual_process_image_path": "C:/Users/minsu/anaconda3/envs/myenv/python.exe",
                "actual_process_image_raw_sha256": (
                    "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
                ),
                "base_python_3_13_action": "REJECT_BEFORE_NUMERICAL_IMPORT",
                "worker_runtime_and_distribution_reverification": True,
            },
            "fold_contract": {
                "fold_count": 74,
                "required_evaluation_fold_ids": list(
                    f"fold_{index:03d}" for index in range(12, 74)
                ),
                "required_evaluation_positions": "range(504,1800)",
                "required_rows_per_seed_candidate": 1296,
                "full_membership_schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
                "coverage_sha256": FORMAL_OUTER_COVERAGE_SHA256,
            },
            "execution_contract": {
                "candidate_ids": list(EXPECTED_ENABLED),
                "seeds": list(SEEDS),
                "seed_role": "ALREADY_SPENT_WAVE1_ONLY",
                "outer_backend": "ProcessPoolExecutor",
                "start_method": "spawn",
                "outer_workers": 8,
                "inner_threads": 1,
                "gpu": "OFF",
                "chunks_per_seed_candidate": 8,
                "task_count": 200,
                "max_folds_per_task": 8,
                "failure_action": "cancel_pending_terminate_workers_shutdown_wait_false",
                "same_bytes_parity_required": True,
                "expected_rerun_wall_minutes": [25, 35],
            },
            "decision": {
                "implementation_claimed_open_p0": 0,
                "implementation_claimed_open_p1": 0,
                "independent_v5_audit": "PENDING",
                "spent_seed_screen": "NO_GO",
                "structural_prediction_or_scoring_authorized": False,
                "fresh_seed_reservation_authorized": False,
            },
            "attestations": {
                "v5_predictions_generated": False,
                "evaluation_truth_opened": False,
                "scores_computed": False,
                "seeds_selected_or_reserved": False,
                "old_v4_attempt_terminally_failed_and_superseded": True,
            },
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
