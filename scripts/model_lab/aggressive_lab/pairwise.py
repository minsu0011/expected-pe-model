"""Compute all-pairs complementarity from a hash-bound research prediction surface."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile


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
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--predictions-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    resource = seal_battleground_process(outer_workers=1)
    from research.model_zoo.aggressive_lab.contracts import (
        AggressiveLabContractError,
        canonical_json_bytes,
        load_sealed_design_lock,
    )
    from research.model_zoo.aggressive_lab.evaluation import pairwise_complementarity
    import pandas as pd

    load_sealed_design_lock()
    raw = args.predictions.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.predictions_sha256:
        raise AggressiveLabContractError("pairwise prediction input hash mismatch")
    frame = pd.read_csv(args.predictions, low_memory=False, float_precision="round_trip")
    identity = ("seed", "dgp", "date") if "dgp" in frame else ("seed", "date")
    result = pairwise_complementarity(frame, identity_columns=identity)
    csv_raw = result.to_csv(
        index=False,
        lineterminator="\n",
        float_format="%.17g",
    ).encode("utf-8")
    manifest = {
        "evidence_class": "EXPLORATION_ONLY",
        "input_prediction_raw_sha256": args.predictions_sha256,
        "mode": "all_pairs_complementarity",
        "model_count": int(frame["model_id"].nunique()),
        "pair_count": len(result),
        "pairwise_csv_sha256": hashlib.sha256(csv_raw).hexdigest(),
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "resource": resource.as_dict(),
    }
    manifest_raw = canonical_json_bytes(manifest)
    output = args.output.resolve()
    if output.exists():
        raise AggressiveLabContractError("pairwise output directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pairwise_", dir=output.parent) as temp:
        staging = Path(temp) / "payload"
        staging.mkdir()
        (staging / "PAIRWISE_COMPLEMENTARITY.csv").write_bytes(csv_raw)
        (staging / "MANIFEST.json").write_bytes(manifest_raw)
        os.replace(staging, output)
    print(output / "MANIFEST.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
