"""Lightweight audit tests for isolated DGP exploration V3."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pandas as pd
import pytest

from research.model_zoo.aggressive_lab.full_load_resources import (
    GPU_ENVIRONMENT as PARENT_GPU_ENVIRONMENT,
)
from research.model_zoo.dgp_exploration_v3.contracts import (
    CHILD_ENVIRONMENT,
    COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    CPU_IDS,
    EXPLORATION_LABELS,
    MAX_OUTER_WORKERS,
    PRODUCTION_AUTHORITY,
    candidate_design_payload,
    dgp_design_payload,
)
from research.model_zoo.dgp_exploration_v3.precommit import (
    DESIGN_OUTPUT,
    load_common_full_load_lock,
    repository_root,
    verify_exact_hash_inventory,
    verify_precommit,
)
from research.model_zoo.dgp_exploration_v3.replay_adapter import (
    _validate_public,
    capture_replay_inventory,
    run_research_comparator_replay,
)
from research.model_zoo.dgp_exploration_v3.runner import score_frozen_prediction_stage
from research.model_zoo.dgp_exploration_v3.contracts import ExplorationContractError


def test_v3_is_research_only_and_binds_the_common_full_load_lock() -> None:
    root = repository_root()
    payload = load_common_full_load_lock(
        root=root,
        expected_raw_sha256=COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    )
    assert payload["heavy_execution_authority"] is True
    assert payload["production_promotion_authority"] is False
    assert payload["fresh_or_heldout_authority"] is False
    assert payload["lane_labels"] == list(EXPLORATION_LABELS)
    assert PRODUCTION_AUTHORITY is False


def test_v3_resource_contract_uses_all_cpus_inner_one_and_hides_unsupported_gpu() -> None:
    assert CPU_IDS == tuple(range(32))
    assert MAX_OUTER_WORKERS == 32
    assert PARENT_GPU_ENVIRONMENT == {
        "CUDA_VISIBLE_DEVICES": "0",
        "NVIDIA_VISIBLE_DEVICES": "0",
    }
    assert CHILD_ENVIRONMENT == {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }
    design = candidate_design_payload()["resource_policy"]
    assert design["comparator_backend"] == "CPU"
    assert design["comparator_gpu_selected"] is False
    assert design["inner_threads"] == 1


def test_replay_inventory_pins_current_v03_v04_runtime_and_no_go_policy() -> None:
    first = capture_replay_inventory()
    second = capture_replay_inventory()
    assert first == second
    assert first["production_authority"] is False
    assert first["production_attestation_used"] is False
    assert first["old_production_implementation_status"] == "NO_GO_NOT_RESEALED"
    assert len(first["v03"]["archive_raw_sha256"]) == 64
    assert len(first["v03"]["member_sha256"]) == 3
    assert len(first["v04"]["project_sha256"]) == 20
    assert len(first["runtime"]["distributions"]) == 9
    assert first["child_resource_contract"]["environment"] == CHILD_ENVIRONMENT
    assert first["child_resource_contract"]["gpu_supported"] is False


def test_replay_api_accepts_public_mapping_only_and_rejects_truth_columns() -> None:
    signature = inspect.signature(run_research_comparator_replay)
    assert "truth" not in signature.parameters
    fake = {
        "price": pd.DataFrame(
            {"date": ["2020-01-01"], "close": [1.0], "true_fair_pe": [2.0]}
        ),
        "benchmark": pd.DataFrame({"date": ["2020-01-01"], "close": [1.0]}),
        "eps_events": pd.DataFrame({"date": ["2020-01-01"], "eps_ttm": [1.0]}),
    }
    with pytest.raises(ExplorationContractError, match="forbidden evaluator"):
        _validate_public(fake)


def test_v3_dgp_design_preserves_prompt_a_j_mapping() -> None:
    design = dgp_design_payload()
    assert tuple(item["dgp_id"] for item in design["dgps"]) == tuple("ABCDEFGHIJ")
    assert tuple(item["prompt_name"] for item in design["dgps"]) == (
        "SMOOTH_LATENT_PE",
        "SUDDEN_VALUATION_JUMPS",
        "STRONG_REGIME_SWITCHING",
        "HIGH_OBSERVATION_NOISE",
        "LOW_OBSERVATION_NOISE",
        "EARNINGS_DRIVEN_JUMPS",
        "RATE_COMPRESSION",
        "SECTOR_SHOCK",
        "MEAN_REVERTING_VALUATION",
        "STRUCTURAL_DRIFT",
    )


def test_exact_inventory_verifier_rejects_key_and_byte_changes() -> None:
    live = {"a": "a" * 64, "b": "b" * 64}
    verify_exact_hash_inventory(label="unit", sealed=dict(live), live=live)
    with pytest.raises(ExplorationContractError, match="keyset changed"):
        verify_exact_hash_inventory(label="unit", sealed={"a": "a" * 64}, live=live)
    changed = dict(live)
    changed["b"] = "c" * 64
    with pytest.raises(ExplorationContractError, match="bytes changed"):
        verify_exact_hash_inventory(label="unit", sealed=changed, live=live)


def test_truth_scoring_requires_a_distinct_activation_before_file_access() -> None:
    with pytest.raises(ExplorationContractError, match="scoring activation"):
        score_frozen_prediction_stage(
            prediction_output=Path("outputs/model_zoo_dgp_exploration_v3_missing"),
            output=Path("outputs/model_zoo_dgp_exploration_v3_missing_score"),
            max_workers=1,
            design_lock_raw_sha256="0" * 64,
            common_lock_raw_sha256=COMMON_FULL_LOAD_LOCK_RAW_SHA256,
            activation_literal="NOT_APPROVED",
        )


def test_score_free_dgp_a_smoke_receipt_is_bound() -> None:
    root = repository_root()
    path = root / "outputs/model_zoo_dgp_exploration_v3_comparator_smoke_20260820/SMOKE_RECEIPT.json"
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    assert payload["status"] == "PASS_SCORE_FREE_DGP_A_RESEARCH_COMPARATOR_REPLAY"
    assert payload["truth_frame_accessed_by_smoke"] is False
    assert payload["truth_score_computed"] is False
    assert payload["candidate_fit_executed"] is False
    assert payload["comparator_backend"] == "CPU"
    assert payload["comparator_gpu_selected"] is False
    for stage in ("v03", "v04"):
        probe = payload["comparator_receipt"]["child_attestation"][stage][
            "resource_probe"
        ]
        assert probe["cpu_ids"] == list(range(32))
        assert probe["environment"] == CHILD_ENVIRONMENT
        assert probe["all_five_thread_variables_one"] is True
        assert probe["both_gpu_variables_sealed"] is True


def test_external_v3_design_hash_and_inventories_verify() -> None:
    root = repository_root()
    raw = (root / DESIGN_OUTPUT / "DESIGN_LOCK.json").read_bytes()
    external_hash = hashlib.sha256(raw).hexdigest()
    payload = verify_precommit(
        expected_design_lock_raw_sha256=external_hash,
        expected_common_lock_raw_sha256=COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    )
    assert payload["labels"] == list(EXPLORATION_LABELS)
    assert payload["production_authority"] is False
    assert payload["heavy_execution_status"] == (
        "PREDICTION_STAGE_NOT_LAUNCHED_WAITING_ROOT_APPROVAL_TRUTH_SCORING_LOCKED"
    )
    assert payload["truth_scoring_status"] == (
        "LOCKED_REQUIRES_SEPARATE_ROOT_ACTIVATION"
    )
    with pytest.raises(ExplorationContractError, match="externally passed"):
        verify_precommit(
            expected_design_lock_raw_sha256="0" * 64,
            expected_common_lock_raw_sha256=COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        )
