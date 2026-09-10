"""Generate sealed Exploration-only incumbent residual diagnostics."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile


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

import pandas as pd  # noqa: E402

from pe_regime_v04.model_lab.models.wave1.artifacts import (  # noqa: E402
    load_predict_inputs,
    load_wave1_seed_frames,
)
from research.model_zoo.aggressive_lab.contracts import (  # noqa: E402
    AggressiveLabContractError,
    canonical_json_bytes,
)
from research.model_zoo.aggressive_lab.full_load_resources import (  # noqa: E402
    seal_full_load_process,
)
from research.model_zoo.aggressive_lab.residual_diagnostics import (  # noqa: E402
    compute_residual_diagnostics,
)


PREDICT_INPUTS = ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
PREDICT_INPUTS_SHA256 = "f8f30ab74d812909b644984ba9ee3c4a8f509dfabb2ab566c7048313245d500c"
WAVE1_JOINED = (
    ROOT / "outputs/model_zoo_wave1_screen_20260819/evaluation/wave1_joined_predictions.csv"
)
WAVE1_JOINED_SHA256 = "a134da37f73107087755cf0724d216c776331fe28944a1635018b0f85f88c0f3"
OUTPUT = ROOT / "outputs/model_zoo_incumbent_residual_diagnostics_20260820"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _csv(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False, lineterminator="\n", float_format="%.17g").encode("utf-8")


def main() -> int:
    resource = seal_full_load_process(outer_workers=1)
    if _sha(PREDICT_INPUTS) != PREDICT_INPUTS_SHA256:
        raise AggressiveLabContractError("residual diagnostic predict inputs differ")
    if _sha(WAVE1_JOINED) != WAVE1_JOINED_SHA256:
        raise AggressiveLabContractError("residual diagnostic Wave1 surface differs")
    manifest = load_predict_inputs(PREDICT_INPUTS)
    feature_rows: list[pd.DataFrame] = []
    for entry in manifest["seeds"]:
        seed = int(entry["seed"])
        frame, _ = load_wave1_seed_frames(entry)
        selected = frame.iloc[504:].copy()
        selected.insert(0, "seed", seed)
        feature_rows.append(selected)
    features = pd.concat(feature_rows, ignore_index=True)
    features["date"] = pd.to_datetime(features["date"], errors="raise")
    wave1 = pd.read_csv(WAVE1_JOINED, low_memory=False, float_precision="round_trip")
    wave1["date"] = pd.to_datetime(wave1["date"], errors="raise")
    incumbent = wave1.loc[wave1["model_id"] == "v04_expected_pe"].copy()
    if len(incumbent) != 6480:
        raise AggressiveLabContractError("incumbent residual surface must contain 6480 rows")
    joined = incumbent.merge(
        features,
        on=["seed", "date", "symbol"],
        how="left",
        validate="one_to_one",
    )
    results = compute_residual_diagnostics(joined)
    files = {
        "rows.csv": _csv(results["rows"]),
        "serial.csv": _csv(results["serial"]),
        "subgroups.csv": _csv(results["subgroups"]),
        "correlations.csv": _csv(results["correlations"]),
    }
    metadata = {
        "schema_version": "expected_pe.incumbent_residual_diagnostics.v1",
        "lane_labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "model_id": "v04_expected_pe",
        "residual_definition": "log(true_fair_pe / prediction)",
        "rows": 6480,
        "seeds": [6301, 6421, 6521, 6607, 6701],
        "predict_inputs_raw_sha256": PREDICT_INPUTS_SHA256,
        "wave1_joined_raw_sha256": WAVE1_JOINED_SHA256,
        "files": {
            name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in files.items()
        },
        "resource": resource.as_dict(),
        "model_fit": False,
        "promotion_authority": False,
    }
    manifest_raw = canonical_json_bytes(metadata)
    if OUTPUT.exists():
        raise FileExistsError("residual diagnostic output already exists")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="residual_diag_", dir=OUTPUT.parent) as temp:
        staging = Path(temp) / "payload"
        staging.mkdir()
        for name, raw in files.items():
            (staging / name).write_bytes(raw)
        (staging / "MANIFEST.json").write_bytes(manifest_raw)
        os.replace(staging, OUTPUT)
    print(OUTPUT / "MANIFEST.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
