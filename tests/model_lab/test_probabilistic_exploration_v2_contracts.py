from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.probabilistic_exploration_v2.contracts import (
    ExplorationContractError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.probabilistic_exploration_v2.design import (
    AGGRESSIVE_LAB_DESIGN_RAW_SHA256,
    LANE_LABELS,
    RESOURCE_POLICY,
    design_payload,
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v2.runner import (
    require_heavy_fit_approval,
)
from research.model_zoo.probabilistic_exploration_v2.scoring import (
    central_point_surface,
    evaluate_survivor_frame,
    load_inventory,
    require_scoring_approval,
)


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v2_design_20260820"


def test_design_lock_and_inventory_are_pre_score_and_parent_bound() -> None:
    design = verify_design_file(OUTPUT / "DESIGN_LOCK.json")
    assert design == design_payload()
    assert design["parent_research_lane"]["design_lock_raw_sha256"] == (
        AGGRESSIVE_LAB_DESIGN_RAW_SHA256
    )
    inventory_raw, inventory = load_inventory(OUTPUT / "INPUT_INVENTORY.json")
    assert len(inventory_raw) > 0
    assert inventory["score_opened"] is False
    assert inventory["truth_values_opened_by_this_lane"] is False
    assert inventory["expected_rows"] == 6480
    assert tuple(item["model_id"] for item in inventory["artifacts"]["survivors"]) == (
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
    )


def test_resource_policy_is_exact_background_mode() -> None:
    assert RESOURCE_POLICY["logical_cpu_ids"] == list(range(16, 32))
    assert RESOURCE_POLICY["maximum_workers"] == 16
    assert RESOURCE_POLICY["estimator_inner_threads"] == 1
    assert RESOURCE_POLICY["gpu"] == "SEALED_OFF"
    assert RESOURCE_POLICY["environment"]["CUDA_VISIBLE_DEVICES"] == ""


def test_unapproved_templates_fail_closed() -> None:
    design_hash = sha256_bytes((OUTPUT / "DESIGN_LOCK.json").read_bytes())
    inventory_hash = sha256_bytes((OUTPUT / "INPUT_INVENTORY.json").read_bytes())
    with pytest.raises(ExplorationContractError, match="approval"):
        require_scoring_approval(
            OUTPUT / "SCORING_APPROVAL_TEMPLATE.json",
            design_raw_sha256=design_hash,
            inventory_raw_sha256=inventory_hash,
        )
    with pytest.raises(ExplorationContractError, match="approval"):
        require_heavy_fit_approval(
            OUTPUT / "HEAVY_FIT_APPROVAL_TEMPLATE.json",
            design_raw_sha256=design_hash,
            inventory_raw_sha256=inventory_hash,
        )


def test_scoring_approval_seal_cannot_expand_scope(tmp_path: Path) -> None:
    expected = {
        "schema_version": "expected_pe_model_lab.probabilistic_exploration_v2.approval.v1",
        "lane_labels": list(LANE_LABELS),
        "scope": "EXISTING_TWO_SURVIVOR_SPENT_EXPLORATION_SCORE",
        "parent_design_lock_raw_sha256": AGGRESSIVE_LAB_DESIGN_RAW_SHA256,
        "probabilistic_design_lock_raw_sha256": "a" * 64,
        "input_inventory_raw_sha256": "b" * 64,
        "allow_spent_truth_scoring": True,
        "allow_heavy_spent_candidate_fit": False,
        "allow_fresh_or_heldout": False,
        "authorized_by": "ROOT_AGENT",
    }
    allowed = {**expected, "seal_sha256": sha256_bytes(canonical_json_bytes(expected))}
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(allowed), encoding="utf-8")
    assert require_scoring_approval(
        path,
        design_raw_sha256="a" * 64,
        inventory_raw_sha256="b" * 64,
    )["allow_fresh_or_heldout"] is False
    expanded = dict(expected)
    expanded["allow_fresh_or_heldout"] = True
    # Reusing the old seal after scope expansion must fail.
    path.write_text(json.dumps({**expanded, "seal_sha256": allowed["seal_sha256"]}), encoding="utf-8")
    with pytest.raises(ExplorationContractError, match="approval"):
        require_scoring_approval(
            path,
            design_raw_sha256="a" * 64,
            inventory_raw_sha256="b" * 64,
        )


def _synthetic_distribution() -> tuple[pd.DataFrame, pd.DataFrame]:
    rows = 8
    identity = pd.DataFrame(
        {
            "seed": [1] * 4 + [2] * 4,
            "entity_id": ["DEMO"] * rows,
            "date": pd.date_range("2020-01-01", periods=rows, freq="D", tz="UTC"),
            "ordered_position": np.arange(rows),
            "fold_id": ["fold_000"] * rows,
        }
    )
    truth_values = np.exp(np.linspace(2.0, 2.7, rows))
    truth = identity.copy()
    truth["true_fair_pe"] = truth_values
    widths = np.linspace(0.1, 0.4, rows)
    median_error = np.linspace(-0.08, 0.12, rows)
    median = np.log(truth_values) + median_error
    quantiles = np.column_stack(
        [
            median - widths,
            median - widths / 2.0,
            median,
            median + widths / 2.0,
            median + widths,
        ]
    )
    prediction = identity.copy()
    prediction["model_id"] = "synthetic_quantile"
    for index, suffix in enumerate(("p10", "p25", "p50", "p75", "p90")):
        prediction[f"predicted_pe_{suffix}"] = np.exp(quantiles[:, index])
    prediction["expected_pe"] = prediction["predicted_pe_p50"]
    return prediction, truth


def test_research_metrics_and_central_bridge_use_exact_p50() -> None:
    prediction, truth = _synthetic_distribution()
    result = evaluate_survivor_frame(prediction, truth)
    expected_error = np.log(prediction["predicted_pe_p50"]) - np.log(truth["true_fair_pe"])
    assert result["pooled"]["fair_log_mae"] == pytest.approx(np.mean(np.abs(expected_error)))
    assert result["pooled"]["fair_log_rmse"] == pytest.approx(
        np.sqrt(np.mean(np.square(expected_error)))
    )
    assert result["pooled"]["p10_p90_coverage"] == pytest.approx(1.0)
    assert set(result["per_seed"]) == {"1", "2"}
    bridge = central_point_surface(prediction)
    assert tuple(bridge.columns) == ("seed", "date", "model_id", "prediction")
    np.testing.assert_array_equal(bridge["prediction"], prediction["predicted_pe_p50"])


def test_metrics_reject_identity_mismatch() -> None:
    prediction, truth = _synthetic_distribution()
    truth.loc[0, "ordered_position"] = 999
    with pytest.raises(ExplorationContractError, match="identity"):
        evaluate_survivor_frame(prediction, truth)
