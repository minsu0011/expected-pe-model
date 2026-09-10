"""Separately approved Structural V8 spent-truth evaluator."""

# ruff: noqa: E402 -- dependency/artifact/identity checks precede truth imports.

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

APPROVAL_TOKEN = "STRUCTURAL_V8_SPENT_SCORE_ROOT_APPROVED_20260820"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Score Structural V8 spent screen")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--prediction-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--score-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.score_approval != APPROVAL_TOKEN:
        raise SystemExit("Structural V8 scoring requires the exact root-session token")
    from research.model_zoo.structural_v8.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        SMOKE_RAW_SHA256,
        load_design_lock,
        load_preflight,
        load_smoke,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    design = load_design_lock(args.project_root)
    preflight = load_preflight(args.project_root)
    smoke = load_smoke(args.project_root)
    import numpy as np
    import pandas as pd

    prediction_directory = args.prediction_directory.resolve(strict=True)
    manifest_raw = (prediction_directory / "MANIFEST.json").read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    if (
        manifest.get("mode") != "structural_v8_unscored_prediction_bundle"
        or manifest.get("evaluation_truth_used") is not False
        or manifest.get("scores_computed") is not False
        or manifest.get("fresh_or_heldout_used") is not False
    ):
        raise SystemExit("prediction bundle is not unscored Structural V8 output")
    metadata = manifest.get("metadata", {})
    expected_metadata = {
        "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
        "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "design_manifest_sha256": design["manifest_sha256"],
        "preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
        "preflight_manifest_sha256": preflight["manifest_sha256"],
        "smoke_raw_sha256": SMOKE_RAW_SHA256,
        "smoke_manifest_sha256": smoke["manifest_sha256"],
    }
    if not isinstance(metadata, dict) or any(
        metadata.get(key) != value for key, value in expected_metadata.items()
    ):
        raise SystemExit("prediction bundle is not bound to this V8 revision")
    if metadata.get("lane_gpu_usage", {}).get("candidate_gpu_usage") is not False:
        raise SystemExit("Structural V8 GPU receipt changed")
    for name, expected in manifest["artifact_sha256"].items():
        if _sha(prediction_directory / name) != expected:
            raise SystemExit(f"Structural V8 prediction artifact drift: {name}")
    predictions = pd.read_csv(
        prediction_directory / "predictions.csv", float_precision="round_trip"
    )
    predictions["date"] = pd.to_datetime(predictions["date"], errors="coerce")
    runtime = json.loads((prediction_directory / "runtime.json").read_text(encoding="utf-8"))
    from research.model_zoo.structural_v8.contracts import (
        CANDIDATES,
        PRIMARY_BASE_ID,
        SPENT_SEEDS,
    )
    from research.model_zoo.structural_v8.data import load_v8_truth_blind_inputs
    from research.model_zoo.structural_v8.evaluation_identity import (
        validate_exact_evaluation_identity,
    )

    inputs, _ = load_v8_truth_blind_inputs(args.project_root)
    spent_inputs = {seed: bundle.spent for seed, bundle in inputs.items()}
    identity_receipt = validate_exact_evaluation_identity(predictions, spent_inputs)
    expected_rows = len(SPENT_SEEDS) * 1296
    complete_candidates = []
    candidate_status = {}
    for candidate in CANDIDATES:
        rows = predictions.loc[predictions["model_id"] == candidate.candidate_id]
        values = pd.to_numeric(rows["prediction"], errors="coerce").to_numpy(
            dtype=np.float64, na_value=np.nan
        )
        complete = (
            len(rows) == expected_rows
            and not rows.duplicated(["seed", "date"]).any()
            and bool((np.isfinite(values) & (values > 0.0)).all())
        )
        candidate_status[candidate.candidate_id] = (
            "SCOREABLE_EXPLORATION_ONLY" if complete else "UNSCORED_INCOMPLETE"
        )
        if complete:
            complete_candidates.append(candidate.candidate_id)
    if not complete_candidates:
        raise SystemExit("no complete Structural V8 candidate is scoreable")

    # Only this separate evaluator opens already-spent simulation truth, and only
    # after immutable artifact verification plus the exact identity gate above.
    from pe_regime_v04.model_lab.models.wave1.artifacts import (
        load_sealed_json,
        verify_file_record,
    )

    evaluation_inputs = load_sealed_json(
        args.project_root / "outputs/model_zoo_wave1_screen_20260819/EVALUATE_INPUTS.json",
        expected_mode="evaluate_inputs",
    )
    truth_frames = []
    for entry in evaluation_inputs["seeds"]:
        seed = int(entry["seed"])
        if seed not in SPENT_SEEDS:
            raise SystemExit("Structural V8 truth seed universe changed")
        path = verify_file_record(entry["truth_csv"], context=f"truth seed {seed}")
        frame = pd.read_csv(
            path, usecols=["date", "true_fair_pe"], float_precision="round_trip"
        )
        frame["date"] = pd.to_datetime(frame["date"], errors="coerce")
        frame.insert(0, "seed", seed)
        truth_frames.append(frame)
    truth = pd.concat(truth_frames, ignore_index=True)
    selected_models = [PRIMARY_BASE_ID, *complete_candidates]
    selected = predictions.loc[predictions["model_id"].isin(selected_models)].copy()
    evaluation_frame = selected.merge(
        truth, how="left", on=["seed", "date"], validate="many_to_one", sort=False
    )
    if evaluation_frame["true_fair_pe"].isna().any():
        raise SystemExit("Structural V8 spent-truth join is incomplete")
    from research.model_zoo.aggressive_lab.contracts import (
        TournamentThresholds,
        load_sealed_design_lock,
    )
    from research.model_zoo.aggressive_lab.evaluation import evaluate_tournament

    parent_design = load_sealed_design_lock(args.project_root)
    result = evaluate_tournament(
        evaluation_frame,
        incumbent_model_id=PRIMARY_BASE_ID,
        candidate_model_ids=complete_candidates,
        runtime_seconds_by_model={
            model_id: float(runtime.get(model_id, 0.0)) for model_id in selected_models
        },
        identity_columns=("seed", "date"),
        thresholds=TournamentThresholds.from_design_lock(parent_design),
    )
    from research.model_zoo.aggressive_lab.artifacts import write_tournament_evaluation

    output_manifest = write_tournament_evaluation(
        result,
        args.output_directory,
        metadata={
            **expected_metadata,
            "prediction_manifest_raw_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "candidate_status": candidate_status,
            "dependency_receipt": dependency_receipt.as_dict(),
            "evaluation_identity_receipt": identity_receipt.as_dict(),
            "resource_receipt": resource_receipt.as_dict(),
            "lane_gpu_usage": metadata["lane_gpu_usage"],
            "same_target": "true_fair_pe",
            "same_evaluator": (
                "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament"
            ),
            "fresh_or_heldout_used": False,
            "production_promotion_allowed": False,
        },
    )
    print(output_manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
