"""Launch detached state-space evaluation under the full-load resource policy."""

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
    parser.add_argument("--prediction-manifest", type=Path, required=True)
    parser.add_argument("--prediction-manifest-sha256", required=True)
    parser.add_argument("--prediction-sha256", required=True)
    parser.add_argument("--wave1-joined", type=Path, required=True)
    parser.add_argument("--wave1-joined-sha256", required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--design-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seal_full_load_process(outer_workers=1)
    from research.model_zoo.state_space_exploration_v1.evaluation import (
        evaluate_state_space_predictions,
    )

    result = evaluate_state_space_predictions(
        args.prediction_manifest,
        args.prediction_manifest_sha256,
        args.prediction_sha256,
        args.wave1_joined,
        args.wave1_joined_sha256,
        args.design,
        args.design_sha256,
        args.output,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
