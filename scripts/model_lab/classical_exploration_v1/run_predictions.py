"""Launch the classical research wave under battleground resource isolation."""

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
    parser.add_argument("--predict-inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--model", action="append", dest="models")
    args = parser.parse_args()
    seal_battleground_process(outer_workers=args.workers)
    from research.model_zoo.classical_exploration_v1.runner import run_predictions

    kwargs = {"outer_workers": args.workers}
    if args.models:
        kwargs["model_ids"] = tuple(args.models)
    path = run_predictions(args.predict_inputs, args.output, **kwargs)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
