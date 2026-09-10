"""Wave1 evaluation-only process; it cannot fit or generate predictions."""

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

from pe_regime_v04.model_lab.models.wave1.evaluation_mode import run_evaluation_mode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a sealed Wave1 prediction artifact")
    parser.add_argument("--prediction-manifest", type=Path, required=True)
    parser.add_argument("--evaluation-inputs", type=Path, required=True)
    parser.add_argument("--execution-precommit", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = run_evaluation_mode(
        args.prediction_manifest,
        args.evaluation_inputs,
        args.execution_precommit,
        args.output_directory,
    )
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
