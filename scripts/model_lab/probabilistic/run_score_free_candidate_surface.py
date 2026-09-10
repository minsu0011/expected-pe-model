from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

import pandas as pd


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {pattern}, found {len(matches)}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate full-mask score-free candidate disk/runtime custody"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--model-id", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_file
    from pe_regime_v04.model_lab.probabilistic.custody import (
        load_verified_pit_features,
        load_verified_prediction_artifact,
        load_verified_training_labels,
        seal_prediction_artifact,
    )
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.resources import (
        create_candidate_resource_guard,
        write_runtime_receipt,
    )
    from pe_regime_v04.model_lab.probabilistic.runner import fit_predict_fold
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS

    output_directory = (
        root / "outputs/model_zoo_probabilistic_wave_screen_20260819/v4_physical_custody"
    )
    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    authorization = load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
    )
    feature_path = Path(root / pointer["feature_path"])
    provenance_path = Path(root / pointer["feature_provenance_path"])
    label_path = Path(root / pointer["training_label_path"])
    features = load_verified_pit_features(
        feature_path, provenance_path, authorization=authorization
    )
    labels = load_verified_training_labels(label_path, authorization=authorization)
    label_frame = pd.read_csv(label_path, float_precision="round_trip")
    folds = build_outer_folds(label_frame, label_available_at_column="label_available_at")[12:]
    records: dict[str, object] = {}
    for model_id in args.model_id:
        if model_id not in CANDIDATE_IDS:
            raise RuntimeError(f"candidate is not locked: {model_id}")
        guard = create_candidate_resource_guard(
            authorization=authorization, model_id=model_id, worker_count=32
        )
        outputs = []
        for fold in folds:
            result = fit_predict_fold(
                model_id=model_id,
                features=features,
                labels=labels,
                authorization=authorization,
                fold=fold,
                experiment_id="score-free-v4-physical-candidate-surface",
                seed=0,
                entity_id="SYNTHETIC_SCORE_FREE_ONLY",
                resource_guard=guard,
            )
            outputs.append(result.output)
        full = pd.concat(outputs, ignore_index=True)
        candidate_directory = output_directory / model_id
        prediction_path, receipt_path = seal_prediction_artifact(
            full, candidate_directory, authorization=authorization
        )
        predictions = load_verified_prediction_artifact(
            prediction_path, receipt_path, authorization=authorization
        )
        runtime_path = write_runtime_receipt(guard.finalize(predictions), candidate_directory)
        records[model_id] = {
            "prediction_path": prediction_path.relative_to(root).as_posix(),
            "prediction_sha256": sha256_file(prediction_path),
            "receipt_path": receipt_path.relative_to(root).as_posix(),
            "receipt_sha256": sha256_file(receipt_path),
            "runtime_receipt_path": runtime_path.relative_to(root).as_posix(),
            "runtime_receipt_sha256": sha256_file(runtime_path),
            "fold_count": len(folds),
            "rows": len(full),
            "fit_attempts_per_fold": 1,
        }
    payload = {
        "schema_version": "expected_pe_model_zoo.score_free_candidate_surface.v4",
        "status": "PASS_FULL_MASK_LIVE_RUNTIME_CUSTODY",
        "authorization_raw_sha256": authorization.raw_sha256,
        "source_closure_sha256": authorization.source_closure_sha256,
        "records": records,
        "synthetic_only": True,
        "project_predictions_generated": False,
        "project_scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "formal_execution_authorized": False,
    }
    output = args.output if args.output.is_absolute() else root / args.output
    immutable_write_json(output, payload)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
