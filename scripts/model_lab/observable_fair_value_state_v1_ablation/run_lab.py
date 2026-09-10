"""CLI for the truth-separated Observable State V1 matched ablation."""

from __future__ import annotations

import argparse
import json
import os


os.environ.update(
    {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "-1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "HIP_VISIBLE_DEVICES": "-1",
        "ROCR_VISIBLE_DEVICES": "-1",
    }
)

from research.model_zoo.observable_fair_value_state_v1_ablation.contracts import (  # noqa: E402
    MAX_OUTER_WORKERS,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.custody import (  # noqa: E402
    freeze_preflight,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.evaluation import (  # noqa: E402
    evaluate_predictions,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.prediction import (  # noqa: E402
    run_predictions,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")
    predict = subparsers.add_parser("predict")
    predict.add_argument("--workers", type=int, default=MAX_OUTER_WORKERS)
    subparsers.add_parser("evaluate")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "preflight":
        payload = freeze_preflight()
    elif arguments.command == "predict":
        payload = run_predictions(workers=arguments.workers)
    else:
        payload = evaluate_predictions()
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
