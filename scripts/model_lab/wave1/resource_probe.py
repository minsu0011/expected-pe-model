"""Fresh-process CPU/GPU/thread resource proof; never reads project data."""

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
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import seal_payload, write_immutable_json
from pe_regime_v04.model_lab.models.wave1.resources import (
    assert_cpu_environment,
    assert_memory_budget,
    assert_threadpools_one,
    set_full_process_affinity_0_31,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record a fresh Wave1 CPU-only resource proof")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    assert_cpu_environment()
    affinity = set_full_process_affinity_0_31()
    import numpy as np
    import scipy.linalg
    from sklearn.linear_model import Ridge
    from statsmodels.tsa.statespace.structural import UnobservedComponents
    from threadpoolctl import threadpool_limits

    from catboost import CatBoostRegressor
    from xgboost import XGBRegressor

    with threadpool_limits(limits=1):
        _ = scipy.linalg.solve(np.eye(2), np.ones(2), assume_a="pos")
        _ = Ridge(solver="svd").fit(np.eye(3), np.arange(3.0)).predict(np.eye(3))
        _ = UnobservedComponents(
            np.asarray([1.0, 1.1, 1.2, 1.3]),
            level="local linear trend",
            irregular=True,
        )
        catboost = CatBoostRegressor(task_type="CPU", thread_count=1, verbose=False)
        xgboost = XGBRegressor(device="cpu", n_jobs=1)
        inventory = assert_threadpools_one()
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_fresh_process_resource_probe",
            "project_data_read": False,
            "candidate_scores_computed": False,
            "affinity": list(affinity),
            "environment": {
                name: os.environ[name]
                for name in (
                    "OMP_NUM_THREADS",
                    "MKL_NUM_THREADS",
                    "OPENBLAS_NUM_THREADS",
                    "NUMEXPR_NUM_THREADS",
                    "VECLIB_MAXIMUM_THREADS",
                    "CUDA_VISIBLE_DEVICES",
                    "NVIDIA_VISIBLE_DEVICES",
                )
            },
            "gpu_assertion": {
                "cuda_visible_devices": "-1",
                "nvidia_visible_devices": "void",
                "catboost_task_type": catboost.get_params()["task_type"],
                "xgboost_device": xgboost.get_params()["device"],
            },
            "threadpool_inventory": inventory,
            "memory_snapshot": assert_memory_budget(),
            "claims_not_made": ["performance", "cross-run_determinism", "gpu_speed"],
        }
    )
    write_immutable_json(args.output, payload)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
