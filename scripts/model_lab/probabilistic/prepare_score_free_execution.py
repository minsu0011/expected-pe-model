from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import sys

import numpy as np
import pandas as pd


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create executable synthetic-only probabilistic authorization artifacts"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))

    from pe_regime_v04.model_lab.probabilistic.adapters import (
        adapter_binding_sha256_by_id,
        candidate_environment_sha256_by_id,
    )
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        SCORE_FREE_SCOPE,
        build_execution_authorization_payload,
        common_mask_manifest,
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import seal_payload, sha256_bytes
    from pe_regime_v04.model_lab.probabilistic.custody import (
        build_feature_provenance,
        load_verified_pit_features,
        load_verified_point_comparator,
        load_verified_training_labels,
        seal_point_comparator_custody_receipt,
        write_content_addressed_csv,
        write_content_addressed_json,
    )
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.references import (
        load_verified_point_prediction_history,
        reference_binding_sha256_by_id,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import FEATURE_COLUMNS
    from pe_regime_v04.model_lab.probabilistic.source_closure import (
        build_source_closure_payload,
    )

    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    rows = 1800
    dates = pd.date_range("2000-01-03", periods=rows, freq="B")
    position = np.arange(rows, dtype=np.int64)
    feature_frame = pd.DataFrame(
        {
            column: np.sin((position + index + 1) / (17.0 + index))
            for index, column in enumerate(FEATURE_COLUMNS)
        }
    )
    feature_frame.insert(0, "ordered_position", position)
    feature_frame.insert(0, "date", dates)
    feature_frame.insert(0, "entity_id", "SYNTHETIC_SCORE_FREE_ONLY")
    feature_frame.insert(0, "seed", 0)
    labels = feature_frame.loc[:, ["seed", "entity_id", "date", "ordered_position"]].copy()
    labels["label_available_at"] = dates
    score_free_rng = np.random.default_rng(20260819)
    labels["observed_pe"] = np.exp(
        2.7 + 0.05 * feature_frame[FEATURE_COLUMNS[0]] + score_free_rng.normal(0.0, 0.12, size=rows)
    )
    folds = build_outer_folds(labels, label_available_at_column="label_available_at")
    identity_records: list[dict[str, object]] = []
    for fold in folds[12:]:
        for row_position in fold.test_positions:
            identity_records.append(
                {
                    "seed": 0,
                    "entity_id": "SYNTHETIC_SCORE_FREE_ONLY",
                    "date": dates[row_position],
                    "ordered_position": row_position,
                    "fold_id": fold.fold_id,
                }
            )
    identity = pd.DataFrame(identity_records)
    truth = identity.copy()
    truth["true_fair_pe"] = np.exp(2.72 + position[504:] / 100000.0)
    point = labels.loc[:, ["seed", "entity_id", "date", "ordered_position"]].copy()
    point["point_expected_pe"] = np.exp(2.69 + position / 100000.0)
    v04_comparator = identity.copy()
    v04_comparator["expected_pe"] = np.exp(2.70 + position[504:] / 100000.0)
    ml_comparator = identity.copy()
    ml_comparator["expected_pe"] = np.exp(2.71 + position[504:] / 100000.0)

    feature_path = write_content_addressed_csv(output, "SCORE_FREE_PIT_FEATURES", feature_frame)
    feature_hash = sha256_bytes(feature_path.read_bytes())
    provenance = build_feature_provenance(feature_artifact_raw_sha256=feature_hash)
    provenance_path = write_content_addressed_json(
        output, "SCORE_FREE_PIT_FEATURE_PROVENANCE", provenance
    )
    label_path = write_content_addressed_csv(output, "SCORE_FREE_TRAINING_LABELS", labels)
    identity_path = write_content_addressed_csv(output, "SCORE_FREE_FORMAL_IDENTITY", identity)
    truth_path = write_content_addressed_csv(output, "SCORE_FREE_EVALUATOR_ARTIFACT", truth)
    point_path = write_content_addressed_csv(output, "SCORE_FREE_POINT_HISTORY", point)
    v04_comparator_path = write_content_addressed_csv(
        output, "SCORE_FREE_V04_COMPARATOR", v04_comparator
    )
    ml_comparator_path = write_content_addressed_csv(
        output, "SCORE_FREE_ML_COMPARATOR", ml_comparator
    )
    mask_path = write_content_addressed_json(
        output, "SCORE_FREE_COMMON_MASK", common_mask_manifest(identity)
    )

    source_snapshot = build_source_closure_payload(root)
    source_path = write_content_addressed_json(
        output, "SCORE_FREE_SOURCE_SNAPSHOT", source_snapshot
    )
    environment = seal_payload(
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_runtime_environment.v2",
            "python": platform.python_version(),
            "executable": str(Path(sys.executable).resolve()),
            "adapter_bindings": adapter_binding_sha256_by_id(),
            "thread_policy": {
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "VECLIB_MAXIMUM_THREADS": "1",
                "NUMEXPR_NUM_THREADS": "1",
                "CUDA_VISIBLE_DEVICES": "",
            },
        }
    )
    environment_path = write_content_addressed_json(output, "SCORE_FREE_ENVIRONMENT", environment)
    role = seal_payload(
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_score_free_role.v2",
            "role": "SYNTHETIC_VALIDATION_ONLY",
            "spent_role_opened": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
            "score_computation_authorized": False,
        }
    )
    role_path = write_content_addressed_json(output, "SCORE_FREE_ROLE", role)
    comparator_placeholders = {
        "v04_expected_pe": sha256_bytes(v04_comparator_path.read_bytes()),
        "ml_expected_pe": sha256_bytes(ml_comparator_path.read_bytes()),
        "point_history": sha256_bytes(point_path.read_bytes()),
    }
    bindings = {
        "adapter_binding_sha256_by_id": adapter_binding_sha256_by_id(),
        "candidate_source_snapshot_sha256": sha256_bytes(source_path.read_bytes()),
        "comparator_prediction_sha256_by_id": comparator_placeholders,
        "detached_truth_manifest_sha256": sha256_bytes(truth_path.read_bytes()),
        "environment_manifest_sha256_by_id": candidate_environment_sha256_by_id(),
        "feature_artifact_raw_sha256": feature_hash,
        "feature_provenance_sha256": sha256_bytes(provenance_path.read_bytes()),
        "probabilistic_reference_sha256_by_id": reference_binding_sha256_by_id(),
        "spent_role_authorization_sha256": sha256_bytes(role_path.read_bytes()),
        "training_label_artifact_raw_sha256": sha256_bytes(label_path.read_bytes()),
    }
    payload = build_execution_authorization_payload(
        identity_raw=identity_path.read_bytes(),
        bindings=bindings,
        authorization_scope=SCORE_FREE_SCOPE,
        formal_execution_authorized=False,
        synthetic_evaluation_authorized=True,
    )
    authorization_path = write_content_addressed_json(
        output, "SCORE_FREE_EXECUTION_AUTHORIZATION", payload
    )
    authorization_hash = sha256_bytes(authorization_path.read_bytes())
    authorization = load_execution_authorization(
        authorization_path,
        identity_path,
        source_path,
        expected_precommit_sha256=authorization_hash,
    )
    load_verified_pit_features(feature_path, provenance_path, authorization=authorization)
    load_verified_training_labels(label_path, authorization=authorization)
    load_verified_point_prediction_history(
        point_path, authorization=authorization, comparator_id="point_history"
    )
    v04_artifact = load_verified_point_comparator(
        v04_comparator_path,
        comparator_id="v04_expected_pe",
        authorization=authorization,
    )
    ml_artifact = load_verified_point_comparator(
        ml_comparator_path,
        comparator_id="ml_expected_pe",
        authorization=authorization,
    )
    v04_receipt_path = seal_point_comparator_custody_receipt(
        v04_artifact, output, authorization=authorization
    )
    ml_receipt_path = seal_point_comparator_custody_receipt(
        ml_artifact, output, authorization=authorization
    )
    pointer = seal_payload(
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_authorization_pointer.v2",
            "authorization_scope": SCORE_FREE_SCOPE,
            "authorization_path": authorization_path.relative_to(root).as_posix(),
            "authorization_raw_sha256": authorization_hash,
            "identity_path": identity_path.relative_to(root).as_posix(),
            "identity_raw_sha256": sha256_bytes(identity_path.read_bytes()),
            "common_mask_path": mask_path.relative_to(root).as_posix(),
            "common_mask_raw_sha256": sha256_bytes(mask_path.read_bytes()),
            "environment_path": environment_path.relative_to(root).as_posix(),
            "environment_raw_sha256": sha256_bytes(environment_path.read_bytes()),
            "feature_path": feature_path.relative_to(root).as_posix(),
            "feature_raw_sha256": feature_hash,
            "feature_provenance_path": provenance_path.relative_to(root).as_posix(),
            "feature_provenance_raw_sha256": sha256_bytes(provenance_path.read_bytes()),
            "score_computation_authorized": False,
            "source_snapshot_path": source_path.relative_to(root).as_posix(),
            "source_snapshot_raw_sha256": sha256_bytes(source_path.read_bytes()),
            "training_label_path": label_path.relative_to(root).as_posix(),
            "training_label_raw_sha256": sha256_bytes(label_path.read_bytes()),
            "truth_path": truth_path.relative_to(root).as_posix(),
            "truth_raw_sha256": sha256_bytes(truth_path.read_bytes()),
            "point_history_path": point_path.relative_to(root).as_posix(),
            "point_history_raw_sha256": sha256_bytes(point_path.read_bytes()),
            "v04_comparator_path": v04_comparator_path.relative_to(root).as_posix(),
            "v04_comparator_raw_sha256": sha256_bytes(v04_comparator_path.read_bytes()),
            "v04_comparator_receipt_path": v04_receipt_path.relative_to(root).as_posix(),
            "v04_comparator_receipt_raw_sha256": sha256_bytes(v04_receipt_path.read_bytes()),
            "ml_comparator_path": ml_comparator_path.relative_to(root).as_posix(),
            "ml_comparator_raw_sha256": sha256_bytes(ml_comparator_path.read_bytes()),
            "ml_comparator_receipt_path": ml_receipt_path.relative_to(root).as_posix(),
            "ml_comparator_receipt_raw_sha256": sha256_bytes(ml_receipt_path.read_bytes()),
            "role_path": role_path.relative_to(root).as_posix(),
            "role_raw_sha256": sha256_bytes(role_path.read_bytes()),
            "project_predictions_generated": False,
            "project_scores_generated_or_read": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
        }
    )
    pointer_path = write_content_addressed_json(output, "SCORE_FREE_AUTHORIZATION_POINTER", pointer)
    print(
        json.dumps(
            {
                "status": "EXECUTABLE_SYNTHETIC_ONLY_AUTHORIZATION_READY",
                "authorization": authorization_path.relative_to(root).as_posix(),
                "authorization_sha256": authorization_hash,
                "pointer": pointer_path.relative_to(root).as_posix(),
                "source_snapshot_sha256": sha256_bytes(source_path.read_bytes()),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
