"""Evaluate precomputed research predictions under the common tournament contract."""

from __future__ import annotations

import argparse
import hashlib
import json
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--predictions-sha256", required=True)
    parser.add_argument("--incumbent", required=True)
    parser.add_argument("--candidate", action="append", dest="candidates")
    parser.add_argument("--runtime-json", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=16)
    return parser


def main() -> int:
    args = _parser().parse_args()
    resource = seal_battleground_process(outer_workers=args.workers)
    from research.model_zoo.aggressive_lab.artifacts import write_tournament_evaluation
    from research.model_zoo.aggressive_lab.contracts import (
        TournamentThresholds,
        load_sealed_design_lock,
    )
    from research.model_zoo.aggressive_lab.evaluation import evaluate_tournament
    import pandas as pd

    raw = args.predictions.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.predictions_sha256:
        raise SystemExit("prediction input hash mismatch")
    design = load_sealed_design_lock()
    runtime = None
    if args.runtime_json is not None:
        runtime = json.loads(args.runtime_json.read_text(encoding="utf-8"))
        if not isinstance(runtime, dict):
            raise SystemExit("runtime JSON must be an object")
    frame = pd.read_csv(args.predictions)
    identity = ("seed", "dgp", "date") if "dgp" in frame else ("seed", "date")
    result = evaluate_tournament(
        frame,
        incumbent_model_id=args.incumbent,
        candidate_model_ids=args.candidates,
        runtime_seconds_by_model=runtime,
        identity_columns=identity,
        thresholds=TournamentThresholds.from_design_lock(design),
    )
    manifest = write_tournament_evaluation(
        result,
        args.output,
        metadata={
            "design_lock_raw_sha256": hashlib.sha256(
                (
                    Path.cwd() / "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json"
                ).read_bytes()
            ).hexdigest(),
            "prediction_input_raw_sha256": args.predictions_sha256,
            "resource_receipt": resource.as_dict(),
        },
    )
    print(json.dumps(manifest, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
