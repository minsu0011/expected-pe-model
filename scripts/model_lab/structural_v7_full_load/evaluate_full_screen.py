"""Root-approved evaluator for the Structural V7 full-load spent screen."""

# ruff: noqa: E402 -- dependency/resource checks precede numerical/truth imports.

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


APPROVAL_TOKEN = "STRUCTURAL_V7_FULL_LOAD_SCORE_ROOT_APPROVED_20260820"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Score Structural V7 full-load screen")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--prediction-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--score-approval", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.score_approval != APPROVAL_TOKEN:
        raise SystemExit("Structural full-load scoring requires the exact root-session token")
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        load_design_lock,
        load_preflight,
        verify_full_dependency_freeze,
    )

    dependency_receipt = verify_full_dependency_freeze(args.project_root)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    design = load_design_lock(args.project_root)
    preflight = load_preflight(args.project_root)
    from research.model_zoo.aggressive_lab.contracts import (
        TournamentThresholds,
        load_sealed_design_lock,
    )
    from research.model_zoo.structural_v7.contracts import (
        CANDIDATES,
        PRIMARY_BASE_ID,
        SPENT_SEEDS,
    )
    from research.model_zoo.structural_v7_full_load.contracts import (
        lane_gpu_usage_receipt,
    )

    parent_design = load_sealed_design_lock(args.project_root)
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
        raise SystemExit("prediction bundle is not unscored Structural V7 output")
    metadata = manifest.get("metadata", {})
    expected_metadata = {
        "full_load_dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
        "full_load_design_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "full_load_design_manifest_sha256": design["manifest_sha256"],
        "full_load_preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
        "full_load_preflight_manifest_sha256": preflight["manifest_sha256"],
    }
    if not isinstance(metadata, dict) or any(
        metadata.get(key) != value for key, value in expected_metadata.items()
    ):
        raise SystemExit("prediction bundle is not bound to this full-load revision")
    if metadata.get("lane_gpu_usage", {}).get("candidate_gpu_usage") is not False:
        raise SystemExit("Structural full-load prediction GPU-usage receipt changed")
    for name, expected in manifest["artifact_sha256"].items():
        if _sha(prediction_directory / name) != expected:
            raise SystemExit(f"prediction bundle artifact drift: {name}")
    predictions = pd.read_csv(
        prediction_directory / "predictions.csv", float_precision="round_trip"
    )
    predictions["date"] = pd.to_datetime(predictions["date"], errors="coerce")
    runtime = json.loads((prediction_directory / "runtime.json").read_text(encoding="utf-8"))

    from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
    from research.model_zoo.structural_v7.evaluation_identity import (
        validate_exact_evaluation_identity,
    )

    spent_inputs, _ = load_spent_unscored_inputs(args.project_root)
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
        raise SystemExit("no complete Structural candidate is scoreable")

    # Evaluation truth is opened only after dependency, artifact, and exact
    # 5 x 1,296 x 11 identity checks have passed.
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
            raise SystemExit("evaluation truth seed universe changed")
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
        raise SystemExit("Structural full-load truth join is incomplete")

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
            **expected_metadata,
            "prediction_manifest_raw_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "candidate_status": candidate_status,
            "dependency_receipt": dependency_receipt.as_dict(),
            "evaluation_identity_receipt": identity_receipt.as_dict(),
            "resource_receipt": resource_receipt.as_dict(),
            "lane_gpu_usage": lane_gpu_usage_receipt(),
            "same_target": "true_fair_pe",
            "same_evaluator": (
                "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament"
            ),
            "production_promotion_allowed": False,
        },
    )
    print(output_manifest["manifest_raw_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
