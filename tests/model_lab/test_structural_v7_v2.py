"""Lightweight regression checks for Structural V7 audit-blocker repair V2."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from research.model_zoo.structural_v7.contracts import StructuralV7ContractError
from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
from research.model_zoo.structural_v7.dependency_guard import (
    EXPECTED_LOCAL_DEPENDENCY_PATHS,
    EXPECTED_SHARED_LANE_PATHS,
    POST_FREEZE_PIN_RELATIVE,
)
from research.model_zoo.structural_v7.evaluation_identity import (
    EXPECTED_MODEL_IDS,
    EXPECTED_OUTER_SCHEDULE_SHA256,
    EXPECTED_ROWS_PER_SEED_MODEL,
    validate_exact_evaluation_identity,
)
from research.model_zoo.structural_v7.folds import build_outer_folds
from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
    DEPENDENCY_MANIFEST_V2_RAW_SHA256,
    load_design_lock_v2,
    load_preflight_v2,
    verify_dependency_freeze,
)


ROOT = Path(__file__).resolve().parents[2]


def test_practical_dependency_freeze_is_exact_and_non_cyclic() -> None:
    receipt = verify_dependency_freeze(ROOT)
    assert receipt.manifest_raw_sha256 == DEPENDENCY_MANIFEST_V2_RAW_SHA256
    assert receipt.local_dependency_count == len(EXPECTED_LOCAL_DEPENDENCY_PATHS) == 16
    assert receipt.shared_lane_dependency_count == len(EXPECTED_SHARED_LANE_PATHS) == 5
    manifest_path = (
        ROOT
        / "outputs/model_zoo_structural_v7_dependency_freeze_v2_20260820/"
        "DEPENDENCY_MANIFEST_V2.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    closure = [row["path"] for row in manifest["v7_source_closure"]]
    assert POST_FREEZE_PIN_RELATIVE.as_posix() not in closure
    assert manifest["post_freeze_pin_exclusion"]["path"] == (
        POST_FREEZE_PIN_RELATIVE.as_posix()
    )


def test_corrected_hard_min_rationale_and_candidates_are_unchanged() -> None:
    design = load_design_lock_v2(ROOT)
    policy = design["minimum_train_policy"]
    assert (policy["preferred_min"], policy["hard_min"]) == (252, 200)
    assert policy["empirical_usable_support"] == {
        "earliest_base_usable_of_raw": [250, 252],
        "earliest_meta_usable": 252,
        "earliest_structural_usable": 502,
        "hard_floor_margin_below_empirical_minimum": 50,
    }
    rationale = policy["rationale"]
    assert "exploration executability floor" in rationale
    assert "SplineTransformer" in rationale and "Ridge alpha=10" in rationale
    assert "parameter/sample sufficiency claim" in rationale
    assert "ten observations" not in rationale
    assert "126-session" not in rationale
    assert len(design["candidates"]) == 10
    assert design["candidate_or_minimum_changes_from_revision_1"] is False
    preflight = load_preflight_v2(ROOT)
    assert preflight["minimum_train_rationale_v2"][
        "empirical_usable_base_meta_structural"
    ] == [250, 252, 502]
    assert preflight["minimum_train_rationale_v2"][
        "parameter_sample_sufficiency_claim"
    ] is False


def _prediction_identity_frame(spent_inputs) -> pd.DataFrame:
    rows = []
    for seed, data in spent_inputs.items():
        for call in build_outer_folds(data.dates):
            for position in call.test_positions:
                for model_id in EXPECTED_MODEL_IDS:
                    rows.append(
                        {
                            "seed": seed,
                            "date": data.dates.iloc[position],
                            "symbol": data.symbol,
                            "fold_id": call.fold_id,
                            "test_start_position": call.test_start_position,
                            "model_id": model_id,
                        }
                    )
    return pd.DataFrame(rows)


def test_evaluator_identity_requires_exact_five_by_1296_and_outer_hash() -> None:
    spent_inputs, _ = load_spent_unscored_inputs(ROOT)
    predictions = _prediction_identity_frame(spent_inputs)
    receipt = validate_exact_evaluation_identity(predictions, spent_inputs)
    assert receipt.seed_count == 5
    assert receipt.model_count == len(EXPECTED_MODEL_IDS) == 11
    assert receipt.rows_per_seed_model == EXPECTED_ROWS_PER_SEED_MODEL == 1296
    assert receipt.total_rows == 5 * 1296 * 11
    assert receipt.outer_schedule_sha256 == EXPECTED_OUTER_SCHEDULE_SHA256
    with pytest.raises(StructuralV7ContractError, match="row count changed"):
        validate_exact_evaluation_identity(predictions.iloc[:-1], spent_inputs)
    changed = predictions.copy()
    changed.loc[0, "fold_id"] = "fold_tampered"
    with pytest.raises(StructuralV7ContractError, match="identity differs"):
        validate_exact_evaluation_identity(changed, spent_inputs)


def test_runtime_entrypoints_verify_dependency_before_import_fit_or_truth() -> None:
    run_source = (
        ROOT / "scripts/model_lab/structural_v7/run_exploration.py"
    ).read_text(encoding="utf-8")
    worker = run_source[
        run_source.index("def _worker") : run_source.index("def build_parser")
    ]
    parent = run_source[run_source.index("def main") :]
    for source in (worker, parent):
        assert source.index("verify_dependency_freeze") < source.index(
            "aggressive_lab.resources"
        )
    assert worker.index("verify_dependency_freeze") < worker.index("runner import")
    assert parent.index("verify_dependency_freeze") < parent.index("import pandas")

    evaluator = (
        ROOT / "scripts/model_lab/structural_v7/evaluate_exploration.py"
    ).read_text(encoding="utf-8")
    evaluator_main = evaluator[evaluator.index("def main") :]
    assert evaluator_main.index("verify_dependency_freeze") < evaluator_main.index(
        "aggressive_lab.resources"
    )
    assert evaluator_main.index("verify_dependency_freeze") < evaluator_main.index(
        "import numpy"
    )
    assert evaluator_main.index("validate_exact_evaluation_identity") < (
        evaluator_main.index("EVALUATE_INPUTS.json")
    )
