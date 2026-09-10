"""Append sealed Wave-1 cheap-screen result events after evaluation completes."""

# ruff: noqa: E402 -- the resource seal must precede every potentially numerical import.

from __future__ import annotations

import os

for _name in (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    os.environ[_name] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
from pathlib import Path
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    file_record,
    load_sealed_json,
    seal_payload,
    verify_file_record,
    write_immutable_json,
)
from pe_regime_v04.model_lab.models.wave1.authorization import (
    RESULT_APPEND_DRIFT_LABELS,
    authorize_execution,
)
from pe_regime_v04.model_lab.models.wave1.registration import (
    reconcile_wave1_result_records,
    verify_result_resume_state_against_binding,
)
from pe_regime_v04.model_lab.models.wave1.spec import CANDIDATE_MODEL_IDS
from pe_regime_v04.model_lab.registry import (
    ModelRegistration,
    RegistryPaths,
    load_feature_registry,
    load_model_registry,
    validate_registry_cross_references,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Append sealed Wave1 cheap-screen results")
    parser.add_argument("--execution-precommit", type=Path, required=True)
    parser.add_argument("--evaluation-manifest", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output_manifest.exists():
        raise FileExistsError(f"immutable result append manifest exists: {args.output_manifest}")
    evaluation = load_sealed_json(args.evaluation_manifest, expected_mode="evaluation_artifact")
    if (
        evaluation.get("candidate_scores_computed") is not True
        or evaluation.get("fresh_seeds_consumed") is not False
        or evaluation.get("heldout_opened") is not False
    ):
        raise RuntimeError("evaluation artifact is not an authorized spent-seed cheap screen")
    evaluation_inputs = verify_file_record(
        evaluation["evaluation_inputs"], context="evaluation inputs"
    )
    authorization = authorize_execution(
        args.execution_precommit,
        evaluation_inputs,
        mode="evaluate",
        permitted_live_drift_labels=RESULT_APPEND_DRIFT_LABELS,
    )
    decisions_path = verify_file_record(
        evaluation["registry_ready_decisions"], context="registry-ready decisions"
    )
    decisions = load_sealed_json(
        decisions_path, expected_mode="registry_ready_wave1_decisions"
    )
    records = tuple(ModelRegistration.from_record(item) for item in decisions["result_records"])
    if tuple(item.model_id for item in records) != CANDIDATE_MODEL_IDS:
        raise RuntimeError("registry-ready result model order/universe differs")
    screen_decisions = decisions.get("screen_decisions")
    valid_screen_statuses = {
        "SCREEN_ADVANCE_STAGE2_PROPOSED",
        "SCREEN_PASS_NOT_ADVANCED",
        "SCREEN_REJECTED",
    }
    if (
        decisions.get("evidence_stage") != "SPENT_SEED_STAGE1_CHEAP_SCREEN"
        or decisions.get("stage2_tuning_authorized") is not False
        or decisions.get("lock_authorized") is not False
        or not isinstance(screen_decisions, list)
        or not all(isinstance(item, dict) for item in screen_decisions)
        or tuple(item.get("model_id") for item in screen_decisions)
        != CANDIDATE_MODEL_IDS
        or any(item.get("screen_status") not in valid_screen_statuses for item in screen_decisions)
        or any(item.get("stage2_tuning_authorized") is not False for item in screen_decisions)
        or any(item.get("lock_authorized") is not False for item in screen_decisions)
        or any(item.status != "RESEARCH_ONLY" for item in records)
        or any(item.tuning_status != "UNTESTED" for item in records)
        or any(item.locked_status != "UNTESTED" for item in records)
    ):
        raise RuntimeError("registry-ready decisions overstate Stage1 lifecycle authority")
    registry_root = ROOT / "research/model_zoo"
    model_paths = RegistryPaths(
        registry_root / "model_registry.csv",
        registry_root / "model_registry.json",
    )
    feature_paths = RegistryPaths(
        registry_root / "feature_registry.csv",
        registry_root / "feature_registry.json",
    )
    exact_partial_count = verify_result_resume_state_against_binding(
        model_paths=model_paths,
        runtime_verified_files=authorization.binding["runtime_verified_files"],
        records=records,
    )
    with tempfile.TemporaryDirectory(prefix="wave1-registry-preflight-") as temporary:
        temporary_root = Path(temporary)
        temporary_model_paths = RegistryPaths(
            temporary_root / "model_registry.csv",
            temporary_root / "model_registry.json",
        )
        shutil.copy2(model_paths.csv_path, temporary_model_paths.csv_path)
        shutil.copy2(model_paths.json_path, temporary_model_paths.json_path)
        reconcile_wave1_result_records(temporary_model_paths, records)
        validate_registry_cross_references(
            load_model_registry(temporary_model_paths),
            load_feature_registry(feature_paths),
            formal_run=True,
        )
    reconciliation = reconcile_wave1_result_records(model_paths, records)
    models = load_model_registry(model_paths)
    features = load_feature_registry(feature_paths)
    validate_registry_cross_references(models, features, formal_run=True)
    manifest = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_registry_result_append",
            "evaluation_manifest": file_record(args.evaluation_manifest),
            "execution_precommit": file_record(args.execution_precommit),
            "independent_audit_go": authorization.binding[
                "independent_audit_go"
            ],
            "registry_ready_decisions": file_record(decisions_path),
            "transaction_policy": "idempotent_exact_resume_reject_conflict_or_extra_revision",
            "resume_state_verified_against_binding": "PASS",
            "exact_partial_result_count": exact_partial_count,
            "resumed_from_exact_partial_state": bool(
                reconciliation.result_skipped_exact
            ),
            "result_events_appended": len(reconciliation.result_appended),
            "result_events_skipped_exact": len(
                reconciliation.result_skipped_exact
            ),
            "result_appended": list(reconciliation.result_appended),
            "result_skipped_exact": list(reconciliation.result_skipped_exact),
            "fresh_seeds_consumed": False,
            "heldout_opened": False,
            "model_registry_csv": file_record(model_paths.csv_path),
            "model_registry_json": file_record(model_paths.json_path),
            "formal_cross_reference_validation": "PASS",
        }
    )
    write_immutable_json(args.output_manifest, manifest)
    print(args.output_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
