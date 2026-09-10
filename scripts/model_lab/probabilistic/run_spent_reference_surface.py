from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute the two fixed causal references on the formal spent mask"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--execution-request", type=Path, required=True)
    parser.add_argument("--expected-execution-request-sha256", required=True)
    parser.add_argument("--independent-go", type=Path, required=True)
    parser.add_argument("--expected-independent-go-sha256", required=True)
    args = parser.parse_args()
    for key in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "NUMEXPR_NUM_THREADS",
    ):
        os.environ[key] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    execution_request_path = (
        args.execution_request
        if args.execution_request.is_absolute()
        else root / args.execution_request
    )
    independent_go_path = (
        args.independent_go if args.independent_go.is_absolute() else root / args.independent_go
    )
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        FORMAL_SCOPE,
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        sha256_file,
    )
    from pe_regime_v04.model_lab.probabilistic.custody import load_verified_training_labels
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        load_formal_launch_authority,
        verify_externally_pinned_pointer,
    )
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.references import (
        REFERENCE_IDS,
        create_reference_execution_accumulator,
        load_verified_point_prediction_history,
        point_residual_quantiles_252,
        rolling_log_quantiles_252,
        write_reference_execution_receipt,
    )
    from pe_regime_v04.model_lab.probabilistic.spent import (
        ENTITY_ID,
        FOLDS_PER_SEED,
        SPENT_SEEDS,
    )
    import pandas as pd

    launch_authority = load_formal_launch_authority(
        execution_request_path=execution_request_path,
        expected_execution_request_sha256=args.expected_execution_request_sha256,
        independent_go_path=independent_go_path,
        expected_independent_go_sha256=args.expected_independent_go_sha256,
        repo_root=root,
    )
    pointer = verify_externally_pinned_pointer(
        pointer_path,
        request=launch_authority.request,
    )
    if pointer.get("authorization_scope") != FORMAL_SCOPE:
        raise RuntimeError("reference process requires formal spent authorization")
    authorization = load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
        require_formal=True,
        formal_activation_path=root / pointer["formal_activation_path"],
        expected_formal_activation_sha256=pointer["formal_activation_raw_sha256"],
    )
    label_path = root / pointer["training_label_path"]
    labels = load_verified_training_labels(label_path, authorization=authorization)
    point_history = load_verified_point_prediction_history(
        root / pointer["point_history_path"],
        authorization=authorization,
        comparator_id="point_history",
    )
    label_frame = pd.read_csv(label_path, float_precision="round_trip")
    folds_by_seed = {}
    for seed in SPENT_SEEDS:
        group = label_frame.loc[
            (label_frame["seed"] == seed) & (label_frame["entity_id"] == ENTITY_ID)
        ].reset_index(drop=True)
        folds = build_outer_folds(
            group,
            label_available_at_column="label_available_at",
            require_formal_shape=True,
        )[12:]
        if len(folds) != FOLDS_PER_SEED:
            raise RuntimeError("formal reference fold count differs")
        folds_by_seed[seed] = folds

    records = {}
    for reference_index, reference_id in enumerate(REFERENCE_IDS):
        accumulator = create_reference_execution_accumulator(
            authorization=authorization, reference_id=reference_id
        )
        for seed in SPENT_SEEDS:
            for fold in folds_by_seed[seed]:
                if reference_id == "rolling_log_quantiles_252":
                    result = rolling_log_quantiles_252(
                        labels=labels,
                        authorization=authorization,
                        fold=fold,
                        seed=seed,
                        entity_id=ENTITY_ID,
                    )
                else:
                    result = point_residual_quantiles_252(
                        point_history=point_history,
                        labels=labels,
                        authorization=authorization,
                        fold=fold,
                        seed=seed,
                        entity_id=ENTITY_ID,
                    )
                accumulator.record(result)
        directory = root / "outputs/p5s/r" / str(reference_index)
        predictions, execution_receipt = accumulator.seal(directory)
        execution_path = write_reference_execution_receipt(execution_receipt, directory)
        prediction_paths = sorted(directory.glob(f"reference_predictions_{reference_id}.*.csv"))
        receipt_paths = sorted(
            directory.glob(f"reference_prediction_receipt_{reference_id}.*.json")
        )
        if len(prediction_paths) != 1 or len(receipt_paths) != 1:
            raise RuntimeError("formal reference custody paths are ambiguous")
        records[reference_id] = {
            "prediction_path": prediction_paths[0].relative_to(root).as_posix(),
            "prediction_raw_sha256": sha256_file(prediction_paths[0]),
            "receipt_path": receipt_paths[0].relative_to(root).as_posix(),
            "receipt_raw_sha256": sha256_file(receipt_paths[0]),
            "execution_receipt_path": execution_path.relative_to(root).as_posix(),
            "execution_receipt_raw_sha256": sha256_file(execution_path),
            "prediction_logical_sha256": predictions.prediction_sha256,
            "fold_count": len(SPENT_SEEDS) * FOLDS_PER_SEED,
            "rows": len(predictions.frame),
        }
    surface = {
        "schema_version": "expected_pe_model_zoo.probabilistic_spent_reference_surface.v1",
        "status": "PASS_FULL_MASK_CAUSAL_REFERENCE_CUSTODY",
        "authorization_raw_sha256": authorization.raw_sha256,
        "activation_raw_sha256": pointer["formal_activation_raw_sha256"],
        "source_closure_sha256": authorization.source_closure_sha256,
        "external_execution_request_raw_sha256": launch_authority.request.raw_sha256,
        "independent_go_raw_sha256": launch_authority.independent_go.raw_sha256,
        "records": records,
        "spent_seeds": list(SPENT_SEEDS),
        "folds_per_seed": FOLDS_PER_SEED,
        "truth_manifest_received": False,
        "truth_bytes_read": False,
        "scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    surface_path = root / "outputs/p5s/r" / "REFERENCE_SURFACE.json"
    immutable_write_json(surface_path, surface)
    print(surface_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
