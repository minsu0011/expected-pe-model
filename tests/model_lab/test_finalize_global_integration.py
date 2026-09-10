from __future__ import annotations

from pathlib import Path

import pytest

from scripts.model_lab.aggressive_lab.finalize_global_integration import (
    EXPECTED_OUTPUT_FILES,
    FINALIZATION_TOKEN,
    FROZEN_SOURCE_TREE_SHA256,
    assert_token,
    replay_in_memory,
    validate_tables,
    verify_frozen_source_tree,
    verify_terminal_bindings,
)


ROOT = Path(__file__).resolve().parents[2]


def test_finalizer_requires_exact_literal_token_before_any_publication(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="exact global leaderboard finalization token"):
        assert_token(f"{FINALIZATION_TOKEN}_WRONG")
    token_hash = assert_token(FINALIZATION_TOKEN)
    assert len(token_hash) == 64
    assert EXPECTED_OUTPUT_FILES == {
        "EXPECTED_PE_GLOBAL_LEADERBOARD.csv",
        "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv",
        "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv",
        "MANIFEST.json",
        "REPORT.md",
        "CHECKSUMS.sha256",
    }
    assert not tuple(tmp_path.iterdir())


def test_v1_finalizer_source_seal_fails_closed_after_v2_supersession() -> None:
    assert FROZEN_SOURCE_TREE_SHA256 == (
        "4407e490e8a77d87c62c51ddbfc223354f7f8c2622f658136b77b2b50f1fb8ae"
    )
    with pytest.raises(ValueError, match="frozen integration source differs"):
        verify_frozen_source_tree(ROOT)


def test_finalizer_verifies_all_terminal_binding_bytes() -> None:
    receipt = verify_terminal_bindings(ROOT)
    assert receipt["all_sources_bound"] is True
    assert receipt["pending_lane_ids"] == []
    assert receipt["receipt_count"] == 10
    assert receipt["verified_artifact_count"] == 50
    assert {row["status"] for row in receipt["source_receipts"]} == {"BOUND"}


def test_finalizer_actual_data_e2e_replay_and_publication_invariants() -> None:
    tables = replay_in_memory(ROOT)
    receipt = validate_tables(tables)
    assert receipt["row_counts"] == {
        "EXPECTED_PE_GLOBAL_LEADERBOARD.csv": 82,
        "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv": 13,
        "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv": 22_100,
    }
    assert receipt["eligible_base_model_count"] == 51
    assert receipt["incomplete_positive_rows"] == {
        "huber_with_regime": 936,
        "state_space_local_linear_trend_target_history_only": 1_146,
    }
    assert receipt["simulator_ensemble_member_count"] == 0
    assert receipt["multi_dgp_robust_gate_pass_count"] == 0
    assert receipt["status_only_numeric_nonnull_count"] == 0
    assert receipt["ensemble_family_counts"] == {
        "equal_geometric_pair": 1_275,
        "pointwise_level_median3": 20_825,
    }
