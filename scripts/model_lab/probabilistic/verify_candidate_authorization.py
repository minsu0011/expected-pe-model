from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _exact_glob(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {pattern}, found {len(matches)}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify candidate-specific score-free authority")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--model-id", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pointer", type=Path, required=True)
    args = parser.parse_args()
    for key, value in {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "",
    }.items():
        os.environ[key] = value
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    import pandas as pd

    from pe_regime_v04.model_lab.probabilistic.adapters import (
        verify_candidate_runtime_environment,
    )
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import logical_frame_sha256
    from pe_regime_v04.model_lab.probabilistic.custody import (
        load_verified_pit_features,
        load_verified_training_labels,
    )
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.resources import (
        create_candidate_resource_guard,
    )
    from pe_regime_v04.model_lab.probabilistic.runner import fit_predict_fold

    directory = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    if not pointer_path.is_file():
        raise RuntimeError("explicit score-free authorization pointer is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    authorization = load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
    )
    feature_path = _exact_glob(directory, "SCORE_FREE_PIT_FEATURES.*.csv")
    provenance_path = _exact_glob(directory, "SCORE_FREE_PIT_FEATURE_PROVENANCE.*.json")
    label_path = _exact_glob(directory, "SCORE_FREE_TRAINING_LABELS.*.csv")
    features = load_verified_pit_features(
        feature_path, provenance_path, authorization=authorization
    )
    labels = load_verified_training_labels(label_path, authorization=authorization)
    label_frame = pd.read_csv(label_path, float_precision="round_trip")
    folds = build_outer_folds(label_frame, label_available_at_column="label_available_at")
    fold = folds[12]
    records = []
    for model_id in args.model_id:
        started = time.monotonic()
        runtime_hash = verify_candidate_runtime_environment(model_id)
        if runtime_hash != authorization.bindings["environment_manifest_sha256_by_id"][model_id]:
            raise RuntimeError(f"candidate-specific environment mismatch: {model_id}")
        result = fit_predict_fold(
            model_id=model_id,
            features=features,
            labels=labels,
            authorization=authorization,
            fold=fold,
            experiment_id="score-free-authorized-runner-evidence",
            seed=0,
            entity_id="SYNTHETIC_SCORE_FREE_ONLY",
            resource_guard=create_candidate_resource_guard(
                authorization=authorization,
                model_id=model_id,
                worker_count=8,
            ),
        )
        records.append(
            {
                "model_id": model_id,
                "candidate_environment_sha256": runtime_hash,
                "adapter_binding_sha256": authorization.bindings["adapter_binding_sha256_by_id"][
                    model_id
                ],
                "fold_id": fold.fold_id,
                "train_rows": len(fold.train_positions),
                "prediction_rows": len(result.output),
                "prediction_logical_sha256": logical_frame_sha256(result.output),
                "fit_attempts": result.adapter.fit_attempts,
                "warnings": [],
                "wall_seconds": time.monotonic() - started,
            }
        )
    payload = {
        "schema_version": "expected_pe_model_zoo.probabilistic_authorized_runner.v2",
        "status": "PASS_CANDIDATE_SPECIFIC_AUTHORIZATION",
        "authorization_raw_sha256": authorization.raw_sha256,
        "synthetic_only": True,
        "project_predictions_generated": False,
        "project_scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "records": records,
    }
    output = args.output if args.output.is_absolute() else root / args.output
    immutable_write_json(output, payload)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
