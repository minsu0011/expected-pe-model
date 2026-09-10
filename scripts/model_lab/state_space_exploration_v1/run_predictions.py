"""Launch state-space cheap predictions under the full-load resource policy."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
for item in (ROOT, ROOT / "src"):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))
for name in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    os.environ[name] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "0"

from research.model_zoo.aggressive_lab.full_load_resources import (  # noqa: E402
    seal_full_load_process,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predict-inputs", type=Path, required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--design-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    args = parser.parse_args()
    seal_full_load_process(outer_workers=args.workers)
    from research.model_zoo.state_space_exploration_v1.runner import run_predictions

    result = run_predictions(
        args.predict_inputs,
        args.design,
        args.design_sha256,
        args.output,
        outer_workers=args.workers,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
