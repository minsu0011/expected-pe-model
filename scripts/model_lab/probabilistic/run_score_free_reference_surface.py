from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import pandas as pd


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate full-mask score-free reference disk custody"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_file
    from pe_regime_v04.model_lab.probabilistic.custody import load_verified_training_labels
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.references import (
        REFERENCE_IDS,
        create_reference_execution_accumulator,
        load_verified_point_prediction_history,
        point_residual_quantiles_252,
        rolling_log_quantiles_252,
        write_reference_execution_receipt,
    )

    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    authorization = load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
    )
    label_path = root / pointer["training_label_path"]
    labels = load_verified_training_labels(label_path, authorization=authorization)
    point_history = load_verified_point_prediction_history(
        root / pointer["point_history_path"],
        authorization=authorization,
        comparator_id="point_history",
    )
    label_frame = pd.read_csv(label_path, float_precision="round_trip")
    folds = build_outer_folds(label_frame, label_available_at_column="label_available_at")[12:]
    output_directory = (
        root / "outputs/model_zoo_probabilistic_wave_screen_20260819/v4_physical_custody"
    )
    records: dict[str, object] = {}
    for reference_id in REFERENCE_IDS:
        accumulator = create_reference_execution_accumulator(
            authorization=authorization, reference_id=reference_id
        )
        for fold in folds:
            if reference_id == "rolling_log_quantiles_252":
                result = rolling_log_quantiles_252(
                    labels=labels,
                    authorization=authorization,
                    fold=fold,
                    seed=0,
                    entity_id="SYNTHETIC_SCORE_FREE_ONLY",
                )
            else:
                result = point_residual_quantiles_252(
                    point_history=point_history,
                    labels=labels,
                    authorization=authorization,
                    fold=fold,
                    seed=0,
                    entity_id="SYNTHETIC_SCORE_FREE_ONLY",
                )
            accumulator.record(result)
        directory = output_directory / reference_id
        predictions, execution_receipt = accumulator.seal(directory)
        execution_path = write_reference_execution_receipt(execution_receipt, directory)
        prediction_paths = sorted(directory.glob(f"reference_predictions_{reference_id}.*.csv"))
        receipt_paths = sorted(
            directory.glob(f"reference_prediction_receipt_{reference_id}.*.json")
        )
        if len(prediction_paths) != 1 or len(receipt_paths) != 1:
            raise RuntimeError("reference custody paths are ambiguous")
        records[reference_id] = {
            "prediction_path": prediction_paths[0].relative_to(root).as_posix(),
            "prediction_sha256": sha256_file(prediction_paths[0]),
            "receipt_path": receipt_paths[0].relative_to(root).as_posix(),
            "receipt_sha256": sha256_file(receipt_paths[0]),
            "execution_receipt_path": execution_path.relative_to(root).as_posix(),
            "execution_receipt_sha256": sha256_file(execution_path),
            "prediction_logical_sha256": predictions.prediction_sha256,
            "fold_count": len(folds),
            "rows": len(predictions.frame),
        }
    payload = {
        "schema_version": "expected_pe_model_zoo.score_free_reference_surface.v4",
        "status": "PASS_FULL_MASK_CAUSAL_REFERENCE_CUSTODY",
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
