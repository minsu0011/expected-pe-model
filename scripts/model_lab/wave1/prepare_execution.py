"""Prepare immutable Wave-1 execution seals after an independent audit GO."""

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
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    file_record,
    load_sealed_json,
    verify_file_record,
)
from pe_regime_v04.model_lab.models.wave1.audit import (
    MUTABLE_REGISTRY_RELATIVE_PATHS,
    verify_independent_audit_go,
)
from pe_regime_v04.model_lab.models.wave1.binding import (
    build_execution_binding_payload,
    collect_mg1_execution_inputs,
    opaque_root_evidence_digests,
    runtime_inventory,
    write_execution_package,
)
from pe_regime_v04.model_lab.models.wave1.registration import (
    planned_feature_registrations,
    planned_model_registrations,
)
from pe_regime_v04.model_lab.models.wave1.spec import EVIDENCE_SEEDS
from pe_regime_v04.model_lab.registry import (
    RegistryPaths,
    load_feature_registry,
    load_model_registry_history,
)


RESULT_RELATIVE = (
    "outputs/mg1/artifacts/tuning/seed_{seed}/v04/"
    "causal_matured_forward_median_regularized_promotion_v1/result.json"
)


def _verify_registry_append(
    path: Path,
    *,
    independent_audit_go: dict,
    audit_candidate: dict,
    audit_candidate_payload: dict,
) -> None:
    payload = load_sealed_json(path, expected_mode="wave1_registry_definition_append")
    if (
        payload.get("candidate_scores_seen") is not False
        or payload.get("candidate_predictions_run") is not False
        or payload.get("fresh_or_heldout_opened") is not False
        or payload.get("formal_cross_reference_validation") != "PASS"
    ):
        raise RuntimeError("registry append manifest does not prove a score-blind definition event")
    if (
        payload.get("independent_audit_go") != independent_audit_go
        or payload.get("audit_candidate") != audit_candidate
        or payload.get("resume_state_verified_against_audit") != "PASS"
    ):
        raise RuntimeError("registry append used a different independent audit snapshot")
    inventory = {
        item["relative_path"]: {
            "bytes": item["bytes"],
            "sha256": item["sha256"],
        }
        for item in audit_candidate_payload["runtime_inventory"]
    }
    expected_before = {
        "feature_csv": inventory["research/model_zoo/feature_registry.csv"],
        "feature_json": inventory["research/model_zoo/feature_registry.json"],
        "model_csv": inventory["research/model_zoo/model_registry.csv"],
        "model_json": inventory["research/model_zoo/model_registry.json"],
    }
    if payload.get("audited_registry_before") != expected_before:
        raise RuntimeError("registry append does not bridge the audited registry baseline")
    planned_features = planned_feature_registrations()
    planned_models = planned_model_registrations()
    if (
        tuple(
            [*payload.get("feature_skipped_exact", []), *payload.get("feature_appended", [])]
        )
        != tuple(item.feature_id for item in planned_features)
        or tuple(
            [*payload.get("model_skipped_exact", []), *payload.get("model_appended", [])]
        )
        != tuple(item.registration_id for item in planned_models)
    ):
        raise RuntimeError("registry append transaction evidence differs from the Wave1 plan")
    expected = {
        "feature_csv": ROOT / "research/model_zoo/feature_registry.csv",
        "feature_json": ROOT / "research/model_zoo/feature_registry.json",
        "model_csv": ROOT / "research/model_zoo/model_registry.csv",
        "model_json": ROOT / "research/model_zoo/model_registry.json",
    }
    for role, expected_path in expected.items():
        actual = verify_file_record(payload["after"][role], context=f"registry append {role}")
        if actual != expected_path.resolve():
            raise RuntimeError(f"registry append {role} points outside the registry")
    feature_paths = RegistryPaths(expected["feature_csv"], expected["feature_json"])
    model_paths = RegistryPaths(expected["model_csv"], expected["model_json"])
    features = {item.feature_id: item for item in load_feature_registry(feature_paths)}
    model_history = load_model_registry_history(model_paths)
    histories = {
        item.definition_id: [
            row for row in model_history if row.definition_id == item.definition_id
        ]
        for item in planned_models
    }
    if any(features.get(item.feature_id) != item for item in planned_features) or any(
        histories[item.definition_id] != [item] for item in planned_models
    ):
        raise RuntimeError("live registries do not contain exact definition-only Wave1 events")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal audited Wave1 execution inputs")
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--independent-audit-go", type=Path, required=True)
    parser.add_argument("--no-score-dry-run", type=Path, required=True)
    parser.add_argument("--resolved-model-parameters", type=Path, required=True)
    parser.add_argument("--resource-probe", type=Path, required=True)
    parser.add_argument("--test-evidence", type=Path, required=True)
    parser.add_argument("--registry-append-manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    audit = verify_independent_audit_go(
        args.independent_audit_go,
        project_root=ROOT,
        permitted_current_drift=MUTABLE_REGISTRY_RELATIVE_PATHS,
    )
    audit_go_record = file_record(args.independent_audit_go)
    audit_candidate_record = file_record(audit.candidate_path)
    if file_record(args.test_evidence) != audit_candidate_record:
        raise RuntimeError("test evidence is not the independently approved audit candidate")
    _verify_registry_append(
        args.registry_append_manifest,
        independent_audit_go=audit_go_record,
        audit_candidate=audit_candidate_record,
        audit_candidate_payload=audit.candidate,
    )
    result_paths = {
        seed: ROOT / RESULT_RELATIVE.format(seed=seed) for seed in EVIDENCE_SEEDS
    }
    predict, evaluate, opaque, fold_bindings = collect_mg1_execution_inputs(result_paths)
    additional = (
        args.independent_audit_go,
        args.no_score_dry_run,
        args.resolved_model_parameters,
        args.resource_probe,
        args.test_evidence,
        args.registry_append_manifest,
    )
    inventory = runtime_inventory(
        ROOT,
        additional,
        snapshot_directory=args.output_directory / "execution_snapshots",
    )
    registry_state = {
        "feature_registry_csv": file_record(ROOT / "research/model_zoo/feature_registry.csv"),
        "feature_registry_json": file_record(ROOT / "research/model_zoo/feature_registry.json"),
        "model_registry_csv": file_record(ROOT / "research/model_zoo/model_registry.csv"),
        "model_registry_json": file_record(ROOT / "research/model_zoo/model_registry.json"),
        "schemas": [
            file_record(ROOT / "research/model_zoo/schemas/feature_registry.schema.json"),
            file_record(ROOT / "research/model_zoo/schemas/model_registry.schema.json"),
        ],
        "mutation_performed_by_preparation": False,
    }
    binding = build_execution_binding_payload(
        runtime_verified_files=inventory,
        opaque_external_artifact_digests=[
            *opaque_root_evidence_digests(ROOT),
            *opaque,
        ],
        fold_bindings=fold_bindings,
        registry_state=registry_state,
        independent_audit_go=audit_go_record,
    )
    paths = write_execution_package(
        args.output_directory,
        binding_payload=binding,
        predict_entries=predict,
        evaluate_entries=evaluate,
    )
    print(json.dumps({key: str(value) for key, value in paths.items()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
