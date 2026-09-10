"""Explicit-approval, research-only Structural V7 evaluator."""

# ruff: noqa: E402 -- resource sealing intentionally precedes numerical imports.

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


APPROVAL_TOKEN = "STRUCTURAL_V7_EXPLORATION_SCORE_APPROVED_20260820"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Score Structural V7 exploration predictions")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--prediction-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--score-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.score_approval != APPROVAL_TOKEN:
        raise SystemExit("Structural V7 truth/scoring remains blocked without root approval")
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        load_design_lock_v2,
        load_preflight_v2,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    receipt = seal_battleground_process(outer_workers=1)
    from research.model_zoo.aggressive_lab.contracts import (
        TournamentThresholds,
        load_sealed_design_lock,
    )

    parent_design = load_sealed_design_lock(args.project_root)
    from research.model_zoo.structural_v7.contracts import (
        CANDIDATES,
        PRIMARY_BASE_ID,
        SPENT_SEEDS,
    )

    design = load_design_lock_v2(args.project_root)
    preflight = load_preflight_v2(args.project_root)

    import numpy as np
    import pandas as pd

    prediction_directory = args.prediction_directory.resolve(strict=True)
    manifest_path = prediction_directory / "MANIFEST.json"
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    if (
        manifest.get("mode") != "structural_v7_unscored_prediction_bundle"
        or manifest.get("evaluation_truth_used") is not False
        or manifest.get("scores_computed") is not False
    ):
        raise SystemExit("prediction bundle is not an unscored Structural V7 artifact")
    for name, expected in manifest["artifact_sha256"].items():
        if _sha(prediction_directory / name) != expected:
            raise SystemExit(f"prediction bundle artifact drift: {name}")
    predictions = pd.read_csv(
        prediction_directory / "predictions.csv", float_precision="round_trip"
    )
    predictions["date"] = pd.to_datetime(predictions["date"], errors="coerce")
    runtime = json.loads((prediction_directory / "runtime.json").read_text(encoding="utf-8"))

    # Truth remains unopened until the exact five-seed, 1,296-row-per-model,
    # code-owned outer identity surface has passed.
    from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
    from research.model_zoo.structural_v7.evaluation_identity import (
        EXPECTED_MODEL_IDS,
        validate_exact_evaluation_identity,
    )

    spent_inputs, _input_evidence = load_spent_unscored_inputs(args.project_root)
    identity_receipt = validate_exact_evaluation_identity(
        predictions,
        spent_inputs,
        expected_model_ids=EXPECTED_MODEL_IDS,
    )

    expected_rows = len(SPENT_SEEDS) * 1296
    complete_candidates: list[str] = []
    candidate_status: dict[str, str] = {}
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
        raise SystemExit("no complete Structural V7 candidate is scoreable")
    incumbent_rows = predictions.loc[predictions["model_id"] == PRIMARY_BASE_ID]
    if len(incumbent_rows) != expected_rows:
        raise SystemExit("incumbent comparison surface is incomplete")

    from pe_regime_v04.model_lab.models.wave1.artifacts import (
        load_sealed_json,
        verify_file_record,
    )

    evaluation_inputs = load_sealed_json(
        args.project_root / "outputs/model_zoo_wave1_screen_20260819/EVALUATE_INPUTS.json",
        expected_mode="evaluate_inputs",
    )
    truths = []
    for entry in evaluation_inputs["seeds"]:
        seed = int(entry["seed"])
        if seed not in SPENT_SEEDS:
            raise SystemExit("evaluation input seed universe changed")
        path = verify_file_record(entry["truth_csv"], context=f"truth seed {seed}")
        frame = pd.read_csv(path, usecols=["date", "true_fair_pe"], float_precision="round_trip")
        frame["date"] = pd.to_datetime(frame["date"], errors="coerce")
        frame.insert(0, "seed", seed)
        truths.append(frame)
    truth = pd.concat(truths, ignore_index=True)
    selected_models = [PRIMARY_BASE_ID, *complete_candidates]
    selected = predictions.loc[predictions["model_id"].isin(selected_models)].copy()
    evaluation_frame = selected.merge(
        truth, how="left", on=["seed", "date"], validate="many_to_one", sort=False
    )
    if evaluation_frame["true_fair_pe"].isna().any():
        raise SystemExit("Structural V7 truth join is incomplete")

    from research.model_zoo.aggressive_lab.evaluation import evaluate_tournament

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
            "structural_design_lock_manifest_sha256": design["manifest_sha256"],
            "structural_preflight_manifest_sha256": preflight["manifest_sha256"],
            "prediction_manifest_raw_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "candidate_status": candidate_status,
            "dependency_receipt": dependency_receipt.as_dict(),
            "evaluation_identity_receipt": identity_receipt.as_dict(),
            "resource_receipt": receipt.as_dict(),
            "same_target": "true_fair_pe",
            "same_evaluator": "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament",
            "production_promotion_allowed": False,
        },
    )
    print(output_manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
