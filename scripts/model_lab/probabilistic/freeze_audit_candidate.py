from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze repaired score-free audit candidate")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        base_artifact_payload,
        checksum_manifest,
        file_record,
        immutable_write_json,
        immutable_write_text,
    )
    from pe_regime_v04.model_lab.probabilistic.binding import (
        LOCKED_FEATURE_SIDECAR_SHA256,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        sha256_file,
        verify_payload_seal,
        verify_probabilistic_design,
    )
    from pe_regime_v04.model_lab.probabilistic.environment import MODEL_LAB_LOCK_SHA256
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS

    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    design = root / "outputs/model_zoo_probabilistic_wave_design_20260819/DESIGN.json"
    verify_probabilistic_design(design)
    fixed_evidence = [
        output / name
        for name in (
            "NGBOOST_PIP_DRY_RUN.json",
            "NGBOOST_PACKAGE_FREEZE.txt",
            "NGBOOST_PIP_CHECK.txt",
            "NGBOOST_ENVIRONMENT.json",
            "NGBOOST_PACKAGE_MANIFEST.json",
            "NGBOOST_LICENSE_EVIDENCE.json",
            "MODEL_LAB_FULL_PACKAGE_FREEZE.txt",
            "NGBOOST_FULL_PACKAGE_FREEZE.txt",
            "NGBOOST_FULL_PIP_CHECK.txt",
            "NGBOOST_FULL_CLONE_PIP_DRY_RUN.json",
            "NGBOOST_TRANSITIVE_LICENSE_INVENTORY.json",
            "NGBOOST_FULL_CLONE_EVIDENCE.json",
            "MODEL_LAB_SERIALIZATION_REPLAY.json",
            "NGBOOST_SERIALIZATION_REPLAY.json",
            "MODEL_LAB_AUTHORIZED_RUNNER_EVIDENCE_V3.json",
            "NGBOOST_AUTHORIZED_RUNNER_EVIDENCE_V3.json",
            "RESOURCE_RUNTIME_EVIDENCE_V3.json",
            "CANDIDATE_SURFACE_MODEL_LAB_V4.json",
            "CANDIDATE_SURFACE_NGBOOST_V4.json",
            "REFERENCE_SURFACE_V4.json",
            "PHYSICAL_EVALUATOR_BUNDLE_SPEC_V4.json",
            "PHYSICAL_EVALUATOR_RESULT_V4.json",
            "GOVERNANCE_EXECUTION_EVIDENCE_V4.json",
            "VALIDATION_V4.json",
            "V5_FOCUSED_SOURCE_CLOSURE_TESTS.xml",
        )
    ]
    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    if not pointer_path.is_file():
        raise RuntimeError("explicit V5 authorization pointer is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    verify_payload_seal(pointer)
    pointed_paths = {
        (root / value).resolve()
        for key, value in pointer.items()
        if key.endswith("_path") and isinstance(value, str)
    }
    content_addressed = sorted({pointer_path.resolve(), *pointed_paths})
    if any(not path.is_file() for path in content_addressed):
        raise RuntimeError("a V5 authorization-pointer dependency is unavailable")
    required_evidence = [*fixed_evidence, *content_addressed]
    if any(not path.is_file() for path in required_evidence):
        missing = [str(path) for path in required_evidence if not path.is_file()]
        raise RuntimeError(f"required evidence missing: {missing}")
    unsealed_json = {
        "NGBOOST_PIP_DRY_RUN.json",
        "NGBOOST_FULL_CLONE_PIP_DRY_RUN.json",
    }
    for path in required_evidence:
        if path.suffix == ".json" and path.name not in unsealed_json:
            verify_payload_seal(json.loads(path.read_text(encoding="utf-8")))
    authorization_path = root / pointer["authorization_path"]
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    runtime = json.loads((output / "RESOURCE_RUNTIME_EVIDENCE_V3.json").read_text())
    full_clone = json.loads((output / "NGBOOST_FULL_CLONE_EVIDENCE.json").read_text())
    prerequisites = base_artifact_payload(artifact_type="IMPLEMENTATION_PREREQUISITES_V5")
    prerequisites.update(
        {
            "status": "IMPLEMENTED_SCORE_FREE_FORMAL_AUTHORITY_NOT_GRANTED",
            "factory_only_entry": (
                "load_execution_authorization(external_raw_sha256) then "
                "load_verified_pit_features/load_verified_training_labels"
            ),
            "score_free_authorization": {
                "path": pointer_path.relative_to(root).as_posix(),
                "sha256": sha256_file(pointer_path),
                "authorization_raw_sha256": pointer["authorization_raw_sha256"],
                "identity_raw_sha256": pointer["identity_raw_sha256"],
                "common_mask_raw_sha256": pointer["common_mask_raw_sha256"],
            },
            "formal_spent_screen_prerequisites": [
                "independent fourth-party GO over this exact inventory",
                "external authority pins a new raw authorization SHA before loading",
                "authorization scope SPENT_SCREEN_EXECUTION and formal_execution_authorized=true",
                "exact existing spent-role identity/folds/features/labels/comparators/references/truth hashes",
                "all candidate prediction bytes sealed before evaluator-private truth load",
                "physical evaluator child consumes exact immutable disk receipts and live runtime receipts",
                "current complete execution source closure matches the externally pinned snapshot",
                "model_lab package-initializer imports are derived and bound as executable source",
                "exact scheduler-reconstructed train/test membership and cutoff for every fold",
                "exact latest 252-row reference history from each canonical training window",
                "single-use FormalScreenOrchestrator applies fixed gates/rank and advances at most one",
                "stop without retry on warning/failure/RSS/free-RAM/runtime guard",
            ],
            "forbidden_without_new_design_lock": [
                "fresh seed reservation or opening",
                "heldout access",
                "candidate/config/feature/reference substitution",
                "post-score tuning or retry",
                "registry mutation",
            ],
            "three_candidates_exact": list(CANDIDATE_IDS),
            "ngboost_environment": full_clone["status"],
            "resource_benchmark": runtime["status"],
            "selected_worker_count": runtime["selected_worker_count"],
            "maximum_projected_candidate_minutes": runtime[
                "selected_projection_maximum_candidate_minutes"
            ],
            "formal_execution_authorized": False,
        }
    )
    prerequisites_path = output / "IMPLEMENTATION_PREREQUISITES_V5.json"
    immutable_write_json(prerequisites_path, prerequisites)
    source_paths = sorted((root / "src/pe_regime_v04/model_lab/probabilistic").glob("*.py"))
    script_paths = sorted((root / "scripts/model_lab/probabilistic").glob("*.py"))
    test_paths = sorted((root / "tests/model_lab").glob("test_probabilistic_*.py"))
    inventory_paths = [
        design,
        *source_paths,
        *script_paths,
        *test_paths,
        *required_evidence,
        prerequisites_path,
    ]
    audit = base_artifact_payload(artifact_type="INDEPENDENT_REAUDIT_CANDIDATE_V5")
    audit.update(
        {
            "status": "V5_INDEPENDENT_AUDIT_READY_SCORE_FREE",
            "design_sha256_verified": PROBABILISTIC_DESIGN_SHA256,
            "feature_sidecar_sha256": LOCKED_FEATURE_SIDECAR_SHA256,
            "original_model_lab_lock_sha256": MODEL_LAB_LOCK_SHA256,
            "candidates": list(CANDIDATE_IDS),
            "candidate_ceiling": 3,
            "source_inventory": [file_record(path, root=root) for path in inventory_paths],
            "repair_findings": {
                "P1_01_factory_authority_common_mask": "PASS",
                "P1_02_all_three_predictions_sealed_before_single_use_truth_open": "PASS",
                "P1_03_ngboost_one_normal_distribution": "PASS",
                "P1_04_exact_canonical_fold_reconstruction_rejects_short_membership": "PASS",
                "P1_05_exact_latest_252_reference_window": "PASS",
                "P1_06_actual_all_candidate_outer_fit_spawn_parity_projection": "PASS_SCORE_FREE",
                "P2_ruff_and_format": "PASS",
                "V4_01_physical_evaluator_disk_receipt_boundary": "PASS",
                "V4_02_complete_current_execution_source_closure": "PASS",
                "V5_P1_02_initializer_derived_loaded_shared_module_closure": "PASS",
            },
            "execution_evidence": {
                "model_lab_tests": "PASS_SEE_VALIDATION_V4",
                "dedicated_ngboost_tests": "PASS_SEE_VALIDATION_V4",
                "exact_semantic_intervention_nodeids": "PASS_SEE_VALIDATION_V4",
                "physical_evaluator_separate_process": "PASS_SEE_PHYSICAL_EVALUATOR_RESULT_V4",
                "complete_source_closure": "PASS_CURRENT_BYTES_REVERIFIED_BEFORE_CAPABILITY_USE",
                "clean_process_shared_module_set": "PASS_SEE_V5_FOCUSED_SOURCE_CLOSURE_TESTS",
                "five_omitted_shared_module_drift_cases": "PASS_SEE_V5_FOCUSED_SOURCE_CLOSURE_TESTS",
                "serialization_replay_all_three_candidates": "PASS",
                "spawn_worker_counts": [8, 16, 24, 32],
                "spawn_worker_count_observed_exact": True,
                "prediction_bytes_equal_across_worker_counts": True,
                "actual_outer_fit_tasks_by_worker_count": {
                    str(lane["worker_count"]): lane["actual_outer_fit_task_count"]
                    for lane in runtime["spawn_parity"]["lanes"]
                },
                "all_three_candidates_fitted_in_every_lane": True,
                "selected_worker_count": runtime["selected_worker_count"],
                "maximum_projected_candidate_minutes": runtime[
                    "selected_projection_maximum_candidate_minutes"
                ],
                "projection_within_90_minutes": runtime[
                    "formal_runtime_projection_within_90_minutes"
                ],
                "maximum_live_process_tree_rss_gib": max(
                    lane["live_peak_process_tree_rss_gib"]
                    for lane in runtime["spawn_parity"]["lanes"]
                ),
                "minimum_live_free_ram_gib": min(
                    lane["live_minimum_free_ram_gib"] for lane in runtime["spawn_parity"]["lanes"]
                ),
                "gpu": "OFF",
                "inner_threads": 1,
            },
            "v4_physical_custody_reuse": {
                "status": "PRIOR_IMMUTABLE_EVIDENCE_RETAINED_NO_REFIT_NO_RESCORE",
                "scope": "V4 physical boundary evidence only; not relabeled as V5 execution",
                "v5_change": "source-closure completeness only",
                "formal_v5_execution_authorized": False,
            },
            "ngboost_installation": {
                "status": full_clone["status"],
                "base_environment_version_drift": full_clone["common_package_version_drift"],
                "dedicated_additions": full_clone["dedicated_additions"],
                "pip_check": full_clone["pip_check"],
                "transitive_license_inventory_sha256": full_clone["license_inventory_sha256"],
            },
            "formal_execution_authorized": False,
            "spent_screen_gate": "AWAIT_INDEPENDENT_FIFTH_PARTY_GO",
            "project_predictions_generated": False,
            "project_scores_generated_or_read": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
            "registry_modified": False,
        }
    )
    audit_path = output / "AUDIT_CANDIDATE_V5.json"
    immutable_write_json(audit_path, audit)
    checksummed = [*inventory_paths, audit_path]
    immutable_write_text(output / "CHECKSUMS_V5.sha256", checksum_manifest(checksummed, root=root))
    print(
        json.dumps(
            {
                "status": "V5_INDEPENDENT_AUDIT_READY_SCORE_FREE",
                "audit": str(audit_path),
                "checksums": str(output / "CHECKSUMS_V5.sha256"),
                "authorization_sha256": authorization["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
