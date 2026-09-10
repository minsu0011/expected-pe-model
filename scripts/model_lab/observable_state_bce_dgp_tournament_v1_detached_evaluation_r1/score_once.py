"""Consume one frozen capability and score the DGP tournament exactly once."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import sys


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resource_guard() -> dict[str, object]:
    for key, value in {
        "CUDA_VISIBLE_DEVICES": "-1",
        "HIP_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "ROCR_VISIBLE_DEVICES": "-1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }.items():
        os.environ[key] = value
    return {
        "mode": "FIXED_ORDER_CPU_0_31_INNER1_GPU_OFF",
        "python": platform.python_version(),
        "sys_executable": sys.executable,
        "pid": os.getpid(),
        "gpu_enabled": False,
        "inner_threads": 1,
        "environment": {
            key: os.environ[key]
            for key in (
                "CUDA_VISIBLE_DEVICES",
                "HIP_VISIBLE_DEVICES",
                "MKL_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
                "NVIDIA_VISIBLE_DEVICES",
                "OMP_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "ROCR_VISIBLE_DEVICES",
                "VECLIB_MAXIMUM_THREADS",
            )
        },
    }


def main() -> int:
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.contract import (  # noqa: E501
        PREDICTION_ROOT,
        PREFLIGHT_ROOT,
        RESULT_ROOT,
        VAULT_ROOT,
        LAUNCHER_SHA256,
        EvaluationContractError,
        sha256_file,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.custody import (  # noqa: E501
        create_consumption_marker,
        designated_truth_records,
        load_and_verify_preflight,
        verify_independent_pre_score_go,
        verify_prediction_and_lineage,
        verify_registries,
        windows_resource_guard,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.evaluator import (  # noqa: E501
        evaluate_joined_rows,
        join_predictions_and_truth,
        load_designated_truth,
        load_predictions,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.reporting import (  # noqa: E501
        publish_result,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=root)
    parser.add_argument("--preflight-root", type=Path, required=True)
    parser.add_argument("--independent-pre-score-go-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--activation-token", required=True)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    if args.preflight_root.resolve() != (repo_root / PREFLIGHT_ROOT).resolve():
        raise EvaluationContractError("launcher preflight root differs from frozen contract")
    if args.destination.resolve() != (repo_root / RESULT_ROOT).resolve():
        raise EvaluationContractError("launcher result root differs from frozen contract")

    if platform.python_version() != "3.10.19":
        raise EvaluationContractError("scoring requires frozen Python 3.10.19")
    if sha256_file(Path(sys.executable)) != LAUNCHER_SHA256:
        raise EvaluationContractError("scoring launcher hash differs from frozen contract")
    resource = {**_resource_guard(), **windows_resource_guard()}
    if resource["resource_guard_error"] is not None:
        raise EvaluationContractError("scoring resource guard could not be applied")
    if resource["cpu_ids"] != list(range(32)):
        raise EvaluationContractError("scoring process affinity must be exactly CPU 0-31")
    if int(os.cpu_count() or 0) != 32:
        raise EvaluationContractError("scoring host must expose exactly 32 logical CPUs")
    if float(resource.get("total_physical_memory_gib", 0.0)) < 90.0:
        raise EvaluationContractError("scoring host does not expose the 96GB RAM contract")
    if float(resource.get("available_physical_memory_gib", 0.0)) < 12.0:
        raise EvaluationContractError("scoring RAM guard requires at least 12GiB free")
    frozen = load_and_verify_preflight(repo_root, args.preflight_root)
    capability = frozen["capability"]
    activation_token = str(capability["activation_token"])
    if args.activation_token != activation_token:
        raise EvaluationContractError("activation token argument differs from frozen capability")
    independent = verify_independent_pre_score_go(
        args.independent_pre_score_go_root,
        capability_raw_sha256=str(frozen["capability_raw_sha256"]),
        preflight_raw_sha256=str(frozen["preflight_raw_sha256"]),
        preflight_checksums_raw_sha256=str(frozen["checksums_raw_sha256"]),
        activation_token=activation_token,
    )
    marker = create_consumption_marker(
        repo_root,
        activation_token=activation_token,
        capability_raw_sha256=str(frozen["capability_raw_sha256"]),
        independent_audit_raw_sha256=str(independent["audit_raw_sha256"]),
    )

    predictions = load_predictions(repo_root / PREDICTION_ROOT / "PREDICTIONS.csv")
    records = designated_truth_records(repo_root)
    targets, truth_access = load_designated_truth(repo_root / VAULT_ROOT, records)
    joined = join_predictions_and_truth(predictions, targets)
    result = evaluate_joined_rows(joined, enforce_full_geometry=True)

    post_lineage = verify_prediction_and_lineage(repo_root)
    post_registries = verify_registries(repo_root)
    post_preflight = load_and_verify_preflight(repo_root, args.preflight_root)
    if post_preflight["capability_raw_sha256"] != frozen["capability_raw_sha256"]:
        raise EvaluationContractError("capability drifted during evaluation")
    access = {
        "status": "ONE_SHOT_TRUTH_ACCESS_COMPLETE",
        "activation_token": activation_token,
        "activation_marker_relative_path": marker.relative_to(repo_root).as_posix(),
        "activation_marker_raw_sha256": sha256_file(marker),
        "prediction_payload_files_opened": 1,
        "prediction_rows_read": len(predictions),
        **truth_access,
        "truth_join_executed": True,
        "truth_join_rows": len(joined),
        "score_computed": True,
        "score_executions": 1,
        "candidate_or_state_models_fit": 0,
        "parameter_or_alpha_sweeps": 0,
        "latent_auxiliary_files_opened": 0,
        "fresh_or_heldout_payload_opened": False,
        "registry_or_champion_mutations": 0,
        "prediction_mutations": 0,
        "frozen_prediction_package_imported": False,
        "frozen_prediction_package_modified": False,
    }
    custody = {
        "status": "PASS_POST_FREEZE_AND_POST_SCORE_DRIFT_CHECKS",
        "preflight": {
            "capability_raw_sha256": frozen["capability_raw_sha256"],
            "preflight_raw_sha256": frozen["preflight_raw_sha256"],
            "checksums_raw_sha256": frozen["checksums_raw_sha256"],
        },
        "independent_pre_score_go": independent,
        "post_score_lineage": post_lineage,
        "post_score_registries": post_registries,
        "post_score_preflight_capability_raw_sha256": post_preflight[
            "capability_raw_sha256"
        ],
        "prediction_rerun": False,
        "promotion_authority": False,
        "registry_or_champion_update_authority": False,
    }
    destination = publish_result(
        repo_root,
        destination=args.destination,
        result=result,
        access_receipt=access,
        custody_receipt=custody,
        resource_receipt=resource,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
