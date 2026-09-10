"""Structural V7 isolated-lane and design-lock contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path

from research.model_zoo.aggressive_lab import EVIDENCE_CLASS, LANE_ID, PROMOTION_AUTHORITY
from research.model_zoo.aggressive_lab.contracts import DESIGN_LOCK_RAW_SHA256
from research.model_zoo.aggressive_lab.resources import (
    CPU_IDS,
    INNER_THREADS,
    MAX_OUTER_WORKERS,
    assert_battleground_process,
)
from research.model_zoo.structural_v7.contracts import (
    CANDIDATES,
    EVALUATION_TARGET,
    HARD_MIN_TRAIN_ROWS,
    PARENT_DESIGN_LOCK_RAW_SHA256,
    PARENT_LANE_ID,
    PREFERRED_MIN_TRAIN_ROWS,
    PROMOTION_ROLE,
    SPENT_SEEDS,
    TRAINING_TARGET,
    verify_sealed_payload,
)
from research.model_zoo.structural_v7.design import (
    DESIGN_LOCK_RAW_SHA256 as V7_DESIGN_LOCK_RAW_SHA256,
    PREFLIGHT_RAW_SHA256,
    load_design_lock,
    load_preflight,
)


ROOT = Path(__file__).resolve().parents[2]


def test_design_lock_binds_parent_lane_and_precommitted_minimums() -> None:
    design = load_design_lock(ROOT)
    verify_sealed_payload(design)
    assert design["parent_lane_id"] == LANE_ID == PARENT_LANE_ID
    assert design["parent_design_lock_raw_sha256"] == DESIGN_LOCK_RAW_SHA256
    assert PARENT_DESIGN_LOCK_RAW_SHA256 == DESIGN_LOCK_RAW_SHA256
    assert design["evidence_class"] == EVIDENCE_CLASS == "EXPLORATION_ONLY"
    assert design["promotion_authority"] == PROMOTION_AUTHORITY == PROMOTION_ROLE
    assert design["production_promotion_allowed"] is False
    assert design["fresh_or_heldout_allowed"] is False
    assert design["heavy_launch_authorized"] is False
    assert design["minimum_train_policy"]["preferred_min"] == PREFERRED_MIN_TRAIN_ROWS == 252
    assert design["minimum_train_policy"]["hard_min"] == HARD_MIN_TRAIN_ROWS == 200
    assert design["spent_seeds"] == list(SPENT_SEEDS)
    assert design["training_target"] == TRAINING_TARGET == "observed_pe"
    assert design["evaluation_target"] == EVALUATION_TARGET == "true_fair_pe"
    assert design["evaluation_contract"]["identical_global_common_mask"] is True


def test_candidate_zoo_contains_required_structures_and_regime_ablations() -> None:
    ids = {candidate.candidate_id for candidate in CANDIDATES}
    assert len(ids) == 10
    assert "s1_geometric_fixed_050_xgb_spline_v7" in ids
    assert "s1_geometric_learned_oof_xgb_spline_v7" in ids
    assert "s2_nonnegative_simplex_v04_xgb_spline_v7" in ids
    assert "s3_residual_state_space_v04_v7" in ids
    families = {candidate.family for candidate in CANDIDATES}
    assert {
        "S1_STATIC_GEOMETRIC",
        "S1_LEARNED_GEOMETRIC",
        "S2_NONNEGATIVE_SIMPLEX",
        "S3_NESTED_RESIDUAL_SPLINE",
        "S3_NESTED_RESIDUAL_EXTRA_TREES",
        "S3_NESTED_RESIDUAL_STATE_SPACE",
        "S4_STRUCTURAL_AR_DECOMPOSITION",
    }.issubset(families)
    for family in (
        "S3_NESTED_RESIDUAL_SPLINE",
        "S3_NESTED_RESIDUAL_EXTRA_TREES",
        "S4_STRUCTURAL_AR_DECOMPOSITION",
    ):
        variants = {candidate.feature_variant for candidate in CANDIDATES if candidate.family == family}
        assert variants == {"common", "with_regime"}
    for candidate in CANDIDATES:
        assert TRAINING_TARGET not in candidate.feature_columns
        assert EVALUATION_TARGET not in candidate.feature_columns


def test_preflight_pin_and_resource_policy_are_exact() -> None:
    preflight = load_preflight(ROOT)
    verify_sealed_payload(preflight)
    assert len(V7_DESIGN_LOCK_RAW_SHA256) == len(PREFLIGHT_RAW_SHA256) == 64
    assert preflight["v7_design_lock_raw_sha256"] == V7_DESIGN_LOCK_RAW_SHA256
    if os.environ.get("CUDA_VISIBLE_DEVICES") == "0":
        from research.model_zoo.aggressive_lab.full_load_resources import (
            assert_full_load_process,
        )

        receipt = assert_full_load_process(outer_workers=1)
        assert receipt.cpu_ids == tuple(range(32))
        assert receipt.cpu_inner_threads == 1
        assert receipt.gpu_enabled is True
    else:
        receipt = assert_battleground_process(outer_workers=1)
        assert receipt.cpu_ids == CPU_IDS == tuple(range(16, 32))
        assert receipt.outer_workers <= MAX_OUTER_WORKERS == 16
        assert receipt.inner_threads == INNER_THREADS == 1
        assert receipt.gpu_sealed is True


def test_v7_execution_source_has_no_prior_authority_dependency() -> None:
    paths = [
        *sorted((ROOT / "research/model_zoo/structural_v7").glob("*.py")),
        *sorted((ROOT / "scripts/model_lab/structural_v7").glob("*.py")),
    ]
    forbidden = (
        "authority_policy_v6",
        "authorization_v6",
        "ACTIVATION_EXECUTION_V6",
        "EXTERNAL_POLICY_PIN_EXECUTION_V6",
        "ba4dc2df64dc555be3a5b7453b1e62eb6c9da084e38f39aab1d0a8227b3b49c1",
        "63e82420c08249261f3c9d635b7f74d35f382c59ec561cdb0750aecd84a9baea",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not any(token in text for token in forbidden), path
    run_source = (ROOT / "research/model_zoo/structural_v7/runner.py").read_text(
        encoding="utf-8"
    )
    assert "true_fair_pe" not in run_source


def test_design_json_is_strict_and_pins_only_new_lane_inputs() -> None:
    path = ROOT / "outputs/model_zoo_structural_v7_design_20260820/DESIGN_LOCK.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["prohibited_reuse"] == {
        "prior_structural_execution_authority": "NOT_AN_INPUT",
        "prior_structural_policy": "NOT_AN_INPUT",
        "prior_structural_activation_pin": "NOT_AN_INPUT",
        "partial_prior_predictions": "NOT_AN_INPUT",
    }
    assert all("v6" not in row["path"].lower() for row in payload["input_artifacts"])
