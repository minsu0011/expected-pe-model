from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REQUIRED_INTERVENTION_NODEIDS = {
    "future_row_perturbation": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_future_row_perturbation_does_not_change_completed_fold_predictions"
    ),
    "outer_test_target_perturbation": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_outer_test_target_perturbation_does_not_change_predictions"
    ),
    "same_row_target_perturbation": (
        "tests/model_lab/test_probabilistic_adapters.py::"
        "test_same_row_target_and_evaluation_truth_are_forbidden"
    ),
    "same_row_market_feature_perturbation": (
        "tests/model_lab/test_probabilistic_adapters.py::"
        "test_same_row_market_feature_perturbation_is_permitted"
    ),
    "detached_truth_perturbation": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_in_process_truth_and_session_apis_are_tombstoned"
    ),
    "row_reordering": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_prediction_row_reordering_and_quantile_deletion_fail"
    ),
    "prefix_truncation": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_prefix_truncation_shared_completed_predictions_are_identical"
    ),
    "seed_entity_boundary_swap": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_seed_entity_boundary_substitution_fails"
    ),
    "feature_sidecar_tampering": (
        "tests/model_lab/test_probabilistic_contracts.py::"
        "test_feature_sidecar_tampering_fails_closed"
    ),
    "one_quantile_deletion": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_prediction_row_reordering_and_quantile_deletion_fail"
    ),
    "quantile_crossing_injection": (
        "tests/model_lab/test_probabilistic_contracts.py::"
        "test_quantile_crossing_injection_stable_repair_and_screen"
    ),
    "ngboost_scale_or_consistency_tampering": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_ngboost_loc_scale_quantile_inconsistency_is_rejected"
    ),
    "comparator_substitution": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_comparator_artifact_substitution_fails"
    ),
    "candidate_output_batch_substitution": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_candidate_guard_rejects_output_batch_substitution"
    ),
    "evaluator_receipt_custody": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_reference_and_distinct_point_receipts_require_full_custody"
    ),
    "residual_window_off_by_one": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_residual_current_position_injection_fails"
    ),
    "environment_drift": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_environment_drift_fails_exact_pins"
    ),
    "artifact_serialization_replay": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_real_candidate_serialization_replay_evidence_is_complete"
    ),
    "worker_count_parity": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_real_outer_fit_worker_parity_and_projection_evidence"
    ),
    "truth_requires_three_candidate_receipts": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_truth_requires_all_three_sealed_candidate_receipts"
    ),
    "forged_short_training_membership": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_forged_short_training_membership_is_rejected"
    ),
    "old_reference_window": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_reference_rejects_old_noncanonical_252_window"
    ),
    "execution_source_closure_drift": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_execution_source_closure_drift_fails_before_capability_use"
    ),
    "physical_evaluator_process_boundary": (
        "tests/model_lab/test_probabilistic_interventions.py::"
        "test_physical_evaluator_returns_metric_receipts_only"
    ),
}


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(root / "src"),
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "CUDA_VISIBLE_DEVICES": "",
        }
    )
    return environment


def _pytest(interpreter: Path, arguments: list[str], *, root: Path) -> dict[str, object]:
    command = [str(interpreter), "-m", "pytest", *arguments]
    completed = subprocess.run(
        command,
        cwd=root,
        env=_environment(root),
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.replace("\r\n", "\n"),
        "stderr": completed.stderr.replace("\r\n", "\n"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run synthetic-only probabilistic validation")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--model-lab-python",
        type=Path,
        default=_root().parent / ".venv_pe_model_lab_py310/Scripts/python.exe",
    )
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument(
        "--dedicated-python",
        type=Path,
        default=_root().parent / ".venv_pe_probabilistic_py310/Scripts/python.exe",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.binding import (
        LOCKED_FEATURE_SIDECAR_SHA256,
        feature_sidecar,
        verify_implementation_binding,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        sha256_file,
        verify_payload_seal,
    )
    from pe_regime_v04.model_lab.probabilistic.environment import verify_dry_run_report
    from pe_regime_v04.model_lab.probabilistic.governance import (
        run_score_free_governance_evidence,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS

    design = root / "outputs/model_zoo_probabilistic_wave_design_20260819/DESIGN.json"
    verify_implementation_binding(design_path=design, sidecar=feature_sidecar())
    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    verify_dry_run_report(output / "NGBOOST_PIP_DRY_RUN.json")
    test_paths = sorted((root / "tests/model_lab").glob("test_probabilistic_*.py"))
    relative_tests = [path.relative_to(root).as_posix() for path in test_paths]
    collection = _pytest(
        args.model_lab_python,
        ["--collect-only", "-q", *relative_tests],
        root=root,
    )
    if collection["returncode"] != 0:
        raise RuntimeError(f"probabilistic test collection failed: {collection}")
    exact_interventions = _pytest(
        args.model_lab_python,
        ["-q", *sorted(set(REQUIRED_INTERVENTION_NODEIDS.values()))],
        root=root,
    )
    if exact_interventions["returncode"] != 0:
        raise RuntimeError(
            "exact semantic intervention nodeids failed collection/execution: "
            f"{exact_interventions}"
        )
    source = root / "src/pe_regime_v04/model_lab/probabilistic"
    violations: list[str] = []
    metric_tokens = ("def _pinball", "def _interval_score", "def _normal_density_metrics")
    for path in sorted(source.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if path.name != "evaluation.py" and any(token in text for token in metric_tokens):
            violations.append(f"metric implementation outside evaluator: {path.name}")
        if path.name in {"adapters.py", "custody.py", "references.py", "runner.py"} and (
            "from .evaluation import" in text
        ):
            violations.append(f"prediction-side evaluator import: {path.name}")
    if violations:
        raise RuntimeError("; ".join(violations))
    model_lab = _pytest(args.model_lab_python, ["-q", *relative_tests], root=root)
    dedicated = _pytest(
        args.dedicated_python,
        [
            "-q",
            "tests/model_lab/test_probabilistic_adapters.py",
            (
                "tests/model_lab/test_probabilistic_interventions.py::"
                "test_candidate_specific_ngboost_authorization_executes_in_dedicated_environment"
            ),
        ],
        root=root,
    )
    if model_lab["returncode"] != 0 or dedicated["returncode"] != 0:
        raise RuntimeError(f"synthetic validation failed: {model_lab=} {dedicated=}")
    runtime_path = output / "RESOURCE_RUNTIME_EVIDENCE_V3.json"
    if not runtime_path.is_file():
        raise RuntimeError("real 8/16/24/32 resource evidence has not been executed")
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    verify_payload_seal(runtime)
    if runtime.get("status") != "PASS_REAL_OUTER_FIT_SPAWN_PARITY_AND_RUNTIME_PROJECTION":
        raise RuntimeError("resource/runtime evidence did not pass")
    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    if not pointer_path.is_file():
        raise RuntimeError("explicit score-free authorization pointer is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    verify_payload_seal(pointer)
    authorization = load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
    )
    governance_path = output / "GOVERNANCE_EXECUTION_EVIDENCE_V4.json"
    immutable_write_json(governance_path, run_score_free_governance_evidence(authorization))
    validation = {
        "schema_version": "expected_pe_model_zoo.probabilistic_validation.v4",
        "status": "PASS_SCORE_FREE_V4_INDEPENDENT_AUDIT_READY",
        "design_sha256_verified": PROBABILISTIC_DESIGN_SHA256,
        "feature_sidecar_sha256": LOCKED_FEATURE_SIDECAR_SHA256,
        "candidate_count": len(CANDIDATE_IDS),
        "candidate_ids": list(CANDIDATE_IDS),
        "test_files": relative_tests,
        "exact_intervention_node_count": len(set(REQUIRED_INTERVENTION_NODEIDS.values())),
        "exact_intervention_execution": exact_interventions,
        "required_interventions": {
            name: {"nodeid": nodeid, "status": "COLLECTED_AND_PASS_IN_EXACT_SUITE"}
            for name, nodeid in REQUIRED_INTERVENTION_NODEIDS.items()
        },
        "model_lab_environment": model_lab,
        "dedicated_ngboost_environment": dedicated,
        "resource_runtime_evidence": {
            "path": runtime_path.relative_to(root).as_posix(),
            "sha256": sha256_file(runtime_path),
        },
        "governance_execution_evidence": {
            "path": governance_path.relative_to(root).as_posix(),
            "sha256": sha256_file(governance_path),
        },
        "score_free_authorization_pointer": {
            "path": pointer_path.relative_to(root).as_posix(),
            "sha256": sha256_file(pointer_path),
        },
        "physical_evaluator_result": {
            "path": "outputs/model_zoo_probabilistic_wave_screen_20260819/PHYSICAL_EVALUATOR_RESULT_V4.json",
            "sha256": sha256_file(output / "PHYSICAL_EVALUATOR_RESULT_V4.json"),
        },
        "evaluator_only_metric_boundary": "PASS",
        "synthetic_only": True,
        "project_predictions_generated": False,
        "project_scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    immutable_write_json(output / "VALIDATION_V4.json", validation)
    print(
        json.dumps(
            {
                "status": "PASS",
                "nodeids": len(set(REQUIRED_INTERVENTION_NODEIDS.values())),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
