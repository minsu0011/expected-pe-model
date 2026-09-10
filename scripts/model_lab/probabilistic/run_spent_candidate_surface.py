from __future__ import annotations

import argparse
from concurrent.futures import FIRST_EXCEPTION, ProcessPoolExecutor, wait
import multiprocessing as mp
import os
from pathlib import Path
import sys
from typing import Any


_WORKER_STATE: dict[str, Any] = {}
_THREAD_POLICY = {
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "CUDA_VISIBLE_DEVICES": "",
}


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_formal_authorization(root: Path, pointer_path: Path, launch_authority: object):
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        FORMAL_SCOPE,
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        require_formal_launch_authority,
        verify_externally_pinned_pointer,
    )

    launch_authority = require_formal_launch_authority(launch_authority)
    pointer = verify_externally_pinned_pointer(
        pointer_path,
        request=launch_authority.request,
    )
    if pointer.get("authorization_scope") != FORMAL_SCOPE:
        raise RuntimeError("candidate process requires formal spent authorization")
    return load_execution_authorization(
        root / pointer["authorization_path"],
        root / pointer["identity_path"],
        root / pointer["source_snapshot_path"],
        expected_precommit_sha256=pointer["authorization_raw_sha256"],
        require_formal=True,
        formal_activation_path=root / pointer["formal_activation_path"],
        expected_formal_activation_sha256=pointer["formal_activation_raw_sha256"],
    )


def _worker_initialize(
    root_text: str,
    pointer_text: str,
    model_id: str,
    execution_request_text: str,
    expected_execution_request_sha256: str,
    independent_go_text: str,
    expected_independent_go_sha256: str,
) -> None:
    os.environ.update(_THREAD_POLICY)
    root = Path(root_text)
    if str(root / "src") not in sys.path:
        sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.custody import (
        load_verified_pit_features,
        load_verified_training_labels,
    )
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        load_formal_launch_authority,
        verify_externally_pinned_pointer,
    )

    pointer_path = Path(pointer_text)
    launch_authority = load_formal_launch_authority(
        execution_request_path=Path(execution_request_text),
        expected_execution_request_sha256=expected_execution_request_sha256,
        independent_go_path=Path(independent_go_text),
        expected_independent_go_sha256=expected_independent_go_sha256,
        repo_root=root,
    )
    authorization = _load_formal_authorization(root, pointer_path, launch_authority)
    pointer = verify_externally_pinned_pointer(
        pointer_path,
        request=launch_authority.request,
    )
    features = load_verified_pit_features(
        root / pointer["feature_path"],
        root / pointer["feature_provenance_path"],
        authorization=authorization,
    )
    labels = load_verified_training_labels(
        root / pointer["training_label_path"], authorization=authorization
    )
    _WORKER_STATE.update(
        {
            "root": root,
            "pointer": pointer,
            "authorization": authorization,
            "features": features,
            "labels": labels,
            "model_id": model_id,
        }
    )


def _fit_worker(task: tuple[int, str, object]) -> dict[str, Any]:
    from pe_regime_v04.model_lab.probabilistic.resources import (
        create_candidate_resource_guard,
    )
    from pe_regime_v04.model_lab.probabilistic.runner import fit_predict_fold

    seed, entity_id, fold = task
    authorization = _WORKER_STATE["authorization"]
    model_id = _WORKER_STATE["model_id"]
    # This worker-local guard provides live process/thread/GPU enforcement at
    # the actual fit boundary.  The parent owns the complete 310-fold guard.
    local_guard = create_candidate_resource_guard(
        authorization=authorization, model_id=model_id, worker_count=32
    )
    result = fit_predict_fold(
        model_id=model_id,
        features=_WORKER_STATE["features"],
        labels=_WORKER_STATE["labels"],
        authorization=authorization,
        fold=fold,
        experiment_id="probabilistic-v5-spent-screen-fixed",
        seed=seed,
        entity_id=entity_id,
        resource_guard=local_guard,
    )
    density = None
    if result.batch.density_parameters is not None:
        density = {
            name: values.tolist() for name, values in result.batch.density_parameters.items()
        }
    return {
        "pid": os.getpid(),
        "seed": seed,
        "entity_id": entity_id,
        "fold_id": fold.fold_id,
        "output": result.output,
        "raw_diagnostics": result.raw_diagnostics,
        "raw_log_quantiles": result.batch.raw_log_quantiles.tolist(),
        "density_parameters": density,
        "fit_attempts": result.adapter.fit_attempts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one exact formal candidate across 5 spent seeds x 62 folds"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--execution-request", type=Path, required=True)
    parser.add_argument("--expected-execution-request-sha256", required=True)
    parser.add_argument("--independent-go", type=Path, required=True)
    parser.add_argument("--expected-independent-go-sha256", required=True)
    parser.add_argument("--model-id", required=True)
    args = parser.parse_args()
    for key, value in _THREAD_POLICY.items():
        current = os.environ.get(key)
        if current not in {None, value}:
            raise RuntimeError(f"{key} differs from the fixed one-thread policy")
        os.environ[key] = value
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
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        IDENTITY_COLUMNS,
        sha256_file,
    )
    from pe_regime_v04.model_lab.probabilistic.crossing import make_prediction_batch
    from pe_regime_v04.model_lab.probabilistic.custody import (
        load_verified_pit_features,
        load_verified_prediction_artifact,
        load_verified_training_labels,
        seal_prediction_artifact,
        write_content_addressed_csv,
    )
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        load_formal_launch_authority,
        verify_externally_pinned_pointer,
    )
    from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
    from pe_regime_v04.model_lab.probabilistic.resources import (
        create_candidate_resource_guard,
        install_thread_guards,
        write_runtime_receipt,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS
    from pe_regime_v04.model_lab.probabilistic.spent import (
        ENTITY_ID,
        FOLDS_PER_SEED,
        SPENT_SEEDS,
        WORKER_COUNT,
    )
    import pandas as pd

    if args.model_id not in CANDIDATE_IDS:
        raise RuntimeError("candidate is outside the fixed three-model universe")
    install_thread_guards()
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
    if pointer["formal_activation_raw_sha256"] not in Path(
        pointer["formal_activation_path"]
    ).name.split("."):
        raise RuntimeError("formal activation pointer is not content-addressed")
    authorization = _load_formal_authorization(root, pointer_path, launch_authority)
    load_verified_pit_features(
        root / pointer["feature_path"],
        root / pointer["feature_provenance_path"],
        authorization=authorization,
    )
    load_verified_training_labels(
        root / pointer["training_label_path"], authorization=authorization
    )
    label_frame = pd.read_csv(root / pointer["training_label_path"], float_precision="round_trip")
    tasks: list[tuple[int, str, object]] = []
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
            raise RuntimeError("formal candidate fold count differs")
        tasks.extend((seed, ENTITY_ID, fold) for fold in folds)
    if len(tasks) != len(SPENT_SEEDS) * FOLDS_PER_SEED:
        raise RuntimeError("formal candidate task count differs")

    guard = create_candidate_resource_guard(
        authorization=authorization, model_id=args.model_id, worker_count=WORKER_COUNT
    )
    context = mp.get_context("spawn")
    outputs = []
    diagnostics = []
    worker_pids: set[int] = set()
    futures = {}
    with ProcessPoolExecutor(
        max_workers=WORKER_COUNT,
        mp_context=context,
        initializer=_worker_initialize,
        initargs=(
            str(root),
            str(pointer_path),
            args.model_id,
            str(execution_request_path),
            args.expected_execution_request_sha256,
            str(independent_go_path),
            args.expected_independent_go_sha256,
        ),
    ) as pool:
        for task in tasks:
            seed, entity_id, fold = task
            guard.before_fold(
                authorization=authorization,
                model_id=args.model_id,
                seed=seed,
                entity_id=entity_id,
                fold_id=fold.fold_id,
            )
            futures[pool.submit(_fit_worker, task)] = task
        done, pending = wait(tuple(futures), return_when=FIRST_EXCEPTION)
        failure = next((future.exception() for future in done if future.exception()), None)
        if failure is not None:
            for future in pending:
                future.cancel()
            raise RuntimeError("candidate fold failed; retry/fallback forbidden") from failure
        for future in futures:
            item = future.result()
            if item["fit_attempts"] != 1:
                raise RuntimeError("candidate fold fit attempt count differs")
            batch = make_prediction_batch(
                model_id=args.model_id,
                raw_log_quantiles=item["raw_log_quantiles"],
                density_parameters=item["density_parameters"],
            )
            guard.after_fold(batch=batch, output=item["output"], fold_id=item["fold_id"])
            worker_pids.add(int(item["pid"]))
            outputs.append(item["output"])
            diagnostics.append(item["raw_diagnostics"])
    if len(worker_pids) != WORKER_COUNT:
        raise RuntimeError(
            f"ProcessPool32 did not execute on exactly 32 workers: {sorted(worker_pids)}"
        )

    full = pd.concat(outputs, ignore_index=True)
    identity = authorization.identity_frame()
    indexed = full.set_index(list(IDENTITY_COLUMNS), drop=False)
    expected_index = pd.MultiIndex.from_frame(identity.loc[:, list(IDENTITY_COLUMNS)])
    try:
        full = indexed.loc[expected_index].reset_index(drop=True)
    except KeyError as exc:
        raise RuntimeError("candidate full-mask output identity differs") from exc
    short_id = {model_id: str(index) for index, model_id in enumerate(CANDIDATE_IDS)}[args.model_id]
    candidate_directory = root / "outputs/p5s/c" / short_id
    prediction_path, receipt_path = seal_prediction_artifact(
        full, candidate_directory, authorization=authorization
    )
    predictions = load_verified_prediction_artifact(
        prediction_path, receipt_path, authorization=authorization
    )
    runtime_path = write_runtime_receipt(guard.finalize(predictions), candidate_directory)
    raw_diagnostics = pd.concat(diagnostics, ignore_index=True)
    diagnostics_path = write_content_addressed_csv(
        candidate_directory, "raw_crossing_diagnostics", raw_diagnostics
    )
    surface = {
        "schema_version": "expected_pe_model_zoo.probabilistic_spent_candidate_surface.v1",
        "status": "PASS_FULL_MASK_FORMAL_PREDICTION_CUSTODY",
        "model_id": args.model_id,
        "authorization_raw_sha256": authorization.raw_sha256,
        "activation_raw_sha256": pointer["formal_activation_raw_sha256"],
        "source_closure_sha256": authorization.source_closure_sha256,
        "external_execution_request_raw_sha256": launch_authority.request.raw_sha256,
        "independent_go_raw_sha256": launch_authority.independent_go.raw_sha256,
        "prediction_path": prediction_path.relative_to(root).as_posix(),
        "prediction_raw_sha256": sha256_file(prediction_path),
        "receipt_path": receipt_path.relative_to(root).as_posix(),
        "receipt_raw_sha256": sha256_file(receipt_path),
        "runtime_receipt_path": runtime_path.relative_to(root).as_posix(),
        "runtime_receipt_raw_sha256": sha256_file(runtime_path),
        "raw_diagnostics_path": diagnostics_path.relative_to(root).as_posix(),
        "raw_diagnostics_sha256": sha256_file(diagnostics_path),
        "spent_seeds": list(SPENT_SEEDS),
        "folds_per_seed": FOLDS_PER_SEED,
        "rows": len(full),
        "process_pool_workers": WORKER_COUNT,
        "observed_worker_pids": sorted(worker_pids),
        "inner_threads": 1,
        "gpu": "OFF",
        "fit_attempts_per_fold": 1,
        "retry_permitted": False,
        "truth_manifest_received": False,
        "truth_bytes_read": False,
        "scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    surface_path = candidate_directory / "CANDIDATE_SURFACE.json"
    immutable_write_json(surface_path, surface)
    print(surface_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
