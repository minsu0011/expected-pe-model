"""Detached truth evaluator for the sealed classical exploration surface."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


for _name in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    os.environ[_name] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

from research.model_zoo.aggressive_lab.resources import (  # noqa: E402
    seal_battleground_process,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prediction-manifest", type=Path, required=True)
    parser.add_argument("--wave1-joined", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seal_battleground_process(outer_workers=1)
    from research.model_zoo.classical_exploration_v1.evaluation import (
        evaluate_classical_predictions,
    )

    path = evaluate_classical_predictions(
        args.prediction_manifest,
        args.wave1_joined,
        args.output,
    )
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
