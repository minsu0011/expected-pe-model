from __future__ import annotations

from dataclasses import asdict
import inspect
from pathlib import Path

import pandas as pd
import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v1.candidates import (
    compute_fixed_alpha_040,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.contracts import (
    RANKING_RULE as V1_RANKING_RULE,
    TOURNAMENT_CANDIDATE_IDS as V1_CANDIDATE_IDS,
    TOURNAMENT_GATE as V1_GATE,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2 import seed_ledger
from research.model_zoo.observable_state_bce_dgp_tournament_v2.artifacts import (
    verify_sealed_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.contracts import (
    BOOTSTRAP_POLICY,
    HELDOUT_GATE,
    HELDOUT_GEOMETRY,
    QUALIFICATION_GATE,
    QUALIFICATION_GEOMETRY,
    QUALIFICATION_RANKING_RULE,
    RESOURCE_POLICY,
    TOURNAMENT_CANDIDATE_IDS,
    TRUTH_COLUMNS,
    TRUTH_HEADER_BYTES,
    TRUTH_HEADER_SHA256,
    TRUTH_PANDAS_DTYPES,
    V2ContractError,
    candidate_contract_payload,
    evaluation_policy_payload,
    geometry_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.custody import (
    SELECTION_LOCK_STATUS,
    build_selection_lock_payload,
    heldout_commitment_descriptor,
    qualification_descriptor,
    seal_selection_lock,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.lineage import (
    HISTORICAL_PREDICTION_REFERENCE,
    METADATA_BINDINGS,
    verify_failure_lineage,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.precommit import (
    source_manifest_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.schema import (
    derive_truth_columns_from_generator_source,
    observe_new_smoke_truth_frame,
    require_all_dgp_schema_parity,
    source_schema_contract,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_truth_schema_is_derived_from_new_generator_without_vault_access() -> None:
    generator = PROJECT_ROOT / "research/model_zoo/dgp_exploration_v2/generator.py"
    assert derive_truth_columns_from_generator_source(generator) == TRUTH_COLUMNS
    contract = source_schema_contract(PROJECT_ROOT)
    assert contract["ordered_columns"] == list(TRUTH_COLUMNS)
    assert contract["header_raw_sha256"] == TRUTH_HEADER_SHA256
    assert contract["old_vault_payload_opened"] is False
    assert TRUTH_HEADER_BYTES.endswith(b"\n")


def test_new_smoke_frame_binds_actual_writer_header_and_dtypes() -> None:
    frame = pd.DataFrame(
        {
            "date": ["2020-01-02", "2020-01-03"],
            "true_fair_pe": [20.0, 21.0],
            "true_log_fair_pe": [2.995732273553991, 3.044522437723423],
            "true_economic_eps_contemporaneous": [3.0, 3.1],
            "true_pit_eps": [2.9, 3.0],
            "true_observed_pe": [20.5, 21.5],
            "true_expected_pe_eligible": [True, False],
        }
    )
    assert tuple(str(dtype) for dtype in frame.dtypes) == TRUTH_PANDAS_DTYPES
    observations = []
    for dgp_id in "ABCDEFGHIJ":
        observations.append(observe_new_smoke_truth_frame(frame, dgp_id=dgp_id))
    require_all_dgp_schema_parity(observations)
    assert all(item["header_raw_sha256"] == TRUTH_HEADER_SHA256 for item in observations)
    assert all(item["full_truth_payload_persisted"] is False for item in observations)


def test_v2_qualification_candidate_gate_and_ranking_are_exact_v1() -> None:
    assert TOURNAMENT_CANDIDATE_IDS == V1_CANDIDATE_IDS
    assert asdict(QUALIFICATION_GATE) == asdict(V1_GATE)
    assert QUALIFICATION_RANKING_RULE == V1_RANKING_RULE
    contract = candidate_contract_payload()
    assert contract["ids_in_fixed_order"] == list(V1_CANDIDATE_IDS)
    assert contract["parameter_or_alpha_sweep"] is False
    assert "alpha" not in inspect.signature(compute_fixed_alpha_040).parameters


def test_exact_two_stage_geometry() -> None:
    qualification = geometry_payload(QUALIFICATION_GEOMETRY)
    heldout = geometry_payload(HELDOUT_GEOMETRY)
    for geometry in (qualification, heldout):
        assert geometry["task_count"] == 50
        assert geometry["full_rows"] == 90_000
        assert geometry["scored_identities"] == 64_800
        assert geometry["fold_blocks"] == 3_100
        assert geometry["state_model_fits"] == 6_200
        assert geometry["score_start_inclusive"] == 504
        assert geometry["score_end_exclusive"] == 1_800


def test_heldout_gate_and_bootstrap_are_stricter_and_exact() -> None:
    assert HELDOUT_GATE.pooled_mae_relative_gain_min == 0.005
    assert HELDOUT_GATE.pooled_rmse_relative_gain_min == 0.005
    assert (HELDOUT_GATE.seed_mean_wins_min, HELDOUT_GATE.seed_total) == (4, 5)
    assert HELDOUT_GATE.worst_seed_dgp_harm_max == 0.03
    assert HELDOUT_GATE.worst_dgp_mean_harm_max == 0.01
    assert HELDOUT_GATE.systematic_dgp_joint_tail_failures_max == 0
    assert BOOTSTRAP_POLICY["replicates"] == 10_000
    assert BOOTSTRAP_POLICY["rng"] == "numpy_PCG64DXSM"
    assert BOOTSTRAP_POLICY["rng_seed"] == 2026082102
    assert BOOTSTRAP_POLICY["pass_rule"] == "lower_bound_strictly_greater_than_zero"
    assert evaluation_policy_payload()["heldout_runs_selected_winner_only"] is True


def test_resource_policy_is_cpu0_31_outer32_inner1_gpu_off() -> None:
    assert RESOURCE_POLICY.cpu_ids == tuple(range(32))
    assert RESOURCE_POLICY.outer_workers == 32
    assert RESOURCE_POLICY.inner_threads == 1
    assert RESOURCE_POLICY.gpu_enabled is False
    assert RESOURCE_POLICY.ram_soft_budget_gib == 80.0
    assert RESOURCE_POLICY.ram_min_free_gib == 12.0
    assert RESOURCE_POLICY.affinity_mask == 0xFFFFFFFF
    assert RESOURCE_POLICY.environment["CUDA_VISIBLE_DEVICES"] == "-1"
    assert RESOURCE_POLICY.environment["OMP_NUM_THREADS"] == "1"


def test_r1_r2_r3_terminal_lineage_is_metadata_only_and_exact() -> None:
    lineage = verify_failure_lineage(PROJECT_ROOT)
    assert lineage["r3_authority_reuse_or_retry"] is False
    assert lineage["old_truth_or_latent_payload_opened"] is False
    assert lineage["historical_prediction_payload_opened"] is False
    assert lineage["historical_scores_opened_or_reused"] is False
    assert len(METADATA_BINDINGS) == 15
    assert HISTORICAL_PREDICTION_REFERENCE["role"].startswith("FORBIDDEN_HISTORICAL")
    assert all("/vault/" not in binding.relative_path for binding in METADATA_BINDINGS)


def test_source_manifest_has_no_old_payload_inventory() -> None:
    manifest = source_manifest_payload(PROJECT_ROOT)
    assert manifest["old_vault_payload_files_in_inventory"] == 0
    assert manifest["historical_prediction_or_score_payload_files_in_inventory"] == 0
    assert all("/vault/" not in path for path in manifest["dependencies"])
    assert all("PREDICTIONS.csv" not in path for path in manifest["dependencies"])


def test_registry_snapshot_and_reservation_plan_do_not_copy_fresh_ids() -> None:
    snapshot = seed_ledger.registry_snapshot(PROJECT_ROOT)
    plan = seed_ledger.reservation_plan_payload(snapshot)
    assert snapshot["entry_count"] >= 9
    assert snapshot["fresh_seed_derivation_performed"] is False
    assert snapshot["seed_identifiers_copied_into_precommit"] is False
    assert plan["qualification_seed_ids"] is None
    assert plan["heldout_seed_ids"] is None
    assert plan["heldout_seed_commitment_sha256"] is None
    assert plan["reservation_performed"] is False
    assert plan["registry_mutated"] is False


def test_reservation_rejects_before_touching_ledger_without_exact_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> tuple[object, ...]:
        raise AssertionError("ledger API must not be touched")

    monkeypatch.setattr(seed_ledger, "_ledger_api", forbidden)
    with pytest.raises(V2ContractError, match="activation literal"):
        seed_ledger.reserve_fresh_5_plus_5(
            project_root=PROJECT_ROOT,
            precommit_root=PROJECT_ROOT / "absent",
            independent_audit_path=PROJECT_ROOT / "absent-audit.json",
            root_approval_path=PROJECT_ROOT / "absent-approval.json",
            activation_literal="WRONG",
        )


def test_qualification_receipt_hides_heldout_and_selection_lock_is_single_winner() -> None:
    reservation = {
        "qualification_seeds": [101, 103, 107, 109, 113],
        "heldout_seed_count": 5,
        "heldout_seed_commitment_sha256": "a" * 64,
        "heldout_seed_ids_exposed_in_receipt": False,
        "qualification_launch_authorized": False,
    }
    qualification = qualification_descriptor(reservation)
    commitment = heldout_commitment_descriptor(reservation)
    assert qualification.candidate_ids == TOURNAMENT_CANDIDATE_IDS
    assert qualification.heldout_ids_available is False
    assert commitment.heldout_ids_available is False
    assert commitment.launch_authorized is False
    lock = seal_selection_lock(
        build_selection_lock_payload(
            qualification_result_raw_sha256="b" * 64,
            qualification_result_semantic_sha256="c" * 64,
            winner_id=TOURNAMENT_CANDIDATE_IDS[0],
            reservation=reservation,
        )
    )
    verify_sealed_payload(lock, "selection_lock_semantic_sha256")
    assert lock["status"] == SELECTION_LOCK_STATUS
    assert lock["winner_count"] == 1
    assert lock["heldout_seed_ids_opened"] is False
    assert lock["runner_up_fallback_or_substitution_allowed"] is False
