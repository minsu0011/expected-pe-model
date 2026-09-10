"""Append audited Wave-1 definition events; never writes evaluation results."""

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
    seal_payload,
    write_immutable_json,
)
from pe_regime_v04.model_lab.models.wave1.audit import (
    MUTABLE_REGISTRY_RELATIVE_PATHS,
    verify_independent_audit_go,
)
from pe_regime_v04.model_lab.models.wave1.registration import (
    reconcile_planned_wave1_definitions,
    verify_definition_resume_state_against_audit,
)
from pe_regime_v04.model_lab.registry import (
    RegistryPaths,
    load_feature_registry,
    load_model_registry,
    validate_registry_cross_references,
)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Append audited Wave1 definition events")
    parser.add_argument("--independent-audit-go", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    audit = verify_independent_audit_go(
        args.independent_audit_go,
        project_root=ROOT,
        permitted_current_drift=MUTABLE_REGISTRY_RELATIVE_PATHS,
    )
    if args.manifest.exists():
        raise FileExistsError(f"immutable registry append manifest exists: {args.manifest}")
    root = ROOT / "research/model_zoo"
    feature_paths = RegistryPaths(
        root / "feature_registry.csv",
        root / "feature_registry.json",
    )
    model_paths = RegistryPaths(
        root / "model_registry.csv",
        root / "model_registry.json",
    )
    resume_state = verify_definition_resume_state_against_audit(
        feature_paths=feature_paths,
        model_paths=model_paths,
        audit_inventory=audit.candidate["runtime_inventory"],
    )
    def digest_only(path: Path) -> dict:
        record = file_record(path)
        return {"bytes": record["bytes"], "sha256": record["sha256"]}

    before = {
        "feature_csv": digest_only(feature_paths.csv_path),
        "feature_json": digest_only(feature_paths.json_path),
        "model_csv": digest_only(model_paths.csv_path),
        "model_json": digest_only(model_paths.json_path),
    }
    with tempfile.TemporaryDirectory(prefix="wave1-definition-preflight-") as temporary:
        temporary_root = Path(temporary)
        temporary_feature_paths = RegistryPaths(
            temporary_root / "feature_registry.csv",
            temporary_root / "feature_registry.json",
        )
        temporary_model_paths = RegistryPaths(
            temporary_root / "model_registry.csv",
            temporary_root / "model_registry.json",
        )
        shutil.copy2(feature_paths.csv_path, temporary_feature_paths.csv_path)
        shutil.copy2(feature_paths.json_path, temporary_feature_paths.json_path)
        shutil.copy2(model_paths.csv_path, temporary_model_paths.csv_path)
        shutil.copy2(model_paths.json_path, temporary_model_paths.json_path)
        reconcile_planned_wave1_definitions(
            feature_paths=temporary_feature_paths,
            model_paths=temporary_model_paths,
        )
        validate_registry_cross_references(
            load_model_registry(temporary_model_paths),
            load_feature_registry(temporary_feature_paths),
            formal_run=True,
        )
    reconciliation = reconcile_planned_wave1_definitions(
        feature_paths=feature_paths,
        model_paths=model_paths,
    )
    features = load_feature_registry(feature_paths)
    models = load_model_registry(model_paths)
    validate_registry_cross_references(models, features, formal_run=True)
    manifest = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_registry_definition_append",
            "candidate_scores_seen": False,
            "candidate_predictions_run": False,
            "fresh_or_heldout_opened": False,
            "independent_audit_go": file_record(args.independent_audit_go),
            "audit_candidate": file_record(audit.candidate_path),
            "audit_runtime_inventory_sha256": audit.candidate[
                "runtime_inventory_sha256"
            ],
            "resume_state_verified_against_audit": "PASS",
            **resume_state,
            "before": before,
            "after": {
                "feature_csv": file_record(feature_paths.csv_path),
                "feature_json": file_record(feature_paths.json_path),
                "model_csv": file_record(model_paths.csv_path),
                "model_json": file_record(model_paths.json_path),
            },
            "transaction_policy": "idempotent_exact_resume_reject_conflict_or_extra_revision",
            "resumed_from_exact_partial_state": bool(
                reconciliation.feature_skipped_exact
                or reconciliation.model_skipped_exact
            ),
            "feature_appended": list(reconciliation.feature_appended),
            "feature_skipped_exact": list(reconciliation.feature_skipped_exact),
            "model_appended": list(reconciliation.model_appended),
            "model_skipped_exact": list(reconciliation.model_skipped_exact),
            "feature_registry_record_count": reconciliation.feature_snapshot.record_count,
            "model_registry_record_count": reconciliation.model_snapshot.record_count,
            "formal_cross_reference_validation": "PASS",
        }
    )
    write_immutable_json(args.manifest, manifest)
    print(args.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
