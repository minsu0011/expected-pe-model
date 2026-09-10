from __future__ import annotations

import copy
import inspect
from pathlib import Path
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2.artifacts import (
    seal_payload,
    semantic_sha256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2.contracts import (
    TOURNAMENT_CANDIDATE_IDS,
    candidate_contract_payload,
    evaluation_policy_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3 import authority
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3 import seed_ledger
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.contracts import (
    EXPECTED_APPROVAL_AUTHORITY,
    EXPECTED_APPROVAL_RESERVATION_SCOPE,
    AUDIT_KEYS,
    EXPECTED_AUDIT_AUTHORITY,
    EXPECTED_EXECUTION_STATE_ZERO,
    EXPECTED_FORBIDDEN_ACCESS_ZERO,
    EXPECTED_SEVERITY_ZERO,
    PROJECT_ROOT,
    REQUIRED_AUDIT_CHECK_IDS,
    RESERVATION_ACTIVATION_LITERAL,
    R3_AUDIT_SCHEMA_VERSION,
    R3_AUDIT_STATUS,
    R3_AUDIT_VERDICT,
    R3_APPROVAL_ACTION,
    R3_APPROVAL_DECISION,
    R3_APPROVAL_SCHEMA_VERSION,
    R3_APPROVAL_STATUS,
    R3_PRECOMMIT_ROOT,
    STATUS,
    V2R3ContractError,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.lineage import (
    R2_NO_GO_AUDIT_SEMANTIC,
    R2_NO_GO_FILES,
    prior_no_go_bindings,
    verify_r3_lineage,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.precommit import (
    _authority_contract_payload,
    _smoke_binding,
    _supersession_payload,
    source_manifest_payload,
    verify_frozen_precommit,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r3.semantic_contract import (
    expected_design_payload,
    registry_snapshot,
    validate_design_semantics,
)


def _expected_design() -> dict[str, Any]:
    source = source_manifest_payload()
    authority_contract = _authority_contract_payload()
    smoke = _smoke_binding()
    supersession = _supersession_payload()
    lineage = verify_r3_lineage(PROJECT_ROOT)
    registry = registry_snapshot(PROJECT_ROOT)
    return expected_design_payload(
        project_root=PROJECT_ROOT,
        source_manifest_semantic_sha256=source["source_manifest_semantic_sha256"],
        authority_contract_semantic_sha256=authority_contract[
            "authority_contract_semantic_sha256"
        ],
        smoke_binding_semantic_sha256=smoke["smoke_binding_semantic_sha256"],
        prior_no_go_supersession_semantic_sha256=supersession[
            "supersession_semantic_sha256"
        ],
        lineage=lineage,
        smoke=smoke,
        registry=registry,
    )


def _reseal(mutated: dict[str, Any]) -> dict[str, Any]:
    mutated.pop("design_semantic_sha256", None)
    return seal_payload(mutated, "design_semantic_sha256")


def _audit_context() -> dict[str, Any]:
    unsigned = {
        "precommit_root": R3_PRECOMMIT_ROOT,
        "precommit_raw_sha256": {"fixture": "a" * 64},
        "precommit_semantic_sha256": {"fixture": "b" * 64},
        "smoke_root": "outputs/smoke",
        "smoke_raw_sha256": {"fixture": "c" * 64},
        "smoke_semantic_sha256": "d" * 64,
        "registry": {"fixture": "e" * 64},
        "complete_lineage_semantic_sha256": "f" * 64,
        "prior_no_go_audits": {"fixture": "0" * 64},
    }
    return {**unsigned, "authority_context_semantic_sha256": semantic_sha256(unsigned)}


def _valid_audit(context: dict[str, Any]) -> dict[str, Any]:
    return seal_payload(
        {
            "schema_version": R3_AUDIT_SCHEMA_VERSION,
            "audit_revision": "R3",
            "generated_at_utc": "2026-08-21T00:00:00+00:00",
            "status": R3_AUDIT_STATUS,
            "verdict": R3_AUDIT_VERDICT,
            "severity_counts": EXPECTED_SEVERITY_ZERO,
            "bindings": context,
            "access_state": EXPECTED_FORBIDDEN_ACCESS_ZERO,
            "execution_state": EXPECTED_EXECUTION_STATE_ZERO,
            "checks": {key: "PASS" for key in REQUIRED_AUDIT_CHECK_IDS},
            "findings": [],
            "authorization_boundary": EXPECTED_AUDIT_AUTHORITY,
        },
        "audit_semantic_sha256",
    )


def _approval_bindings() -> dict[str, Any]:
    return {
        "precommit_root": R3_PRECOMMIT_ROOT,
        "precommit_raw_sha256": {"fixture": "a" * 64},
        "precommit_semantic_sha256": {"fixture": "b" * 64},
        "audit_root": "outputs/fixed-audit",
        "audit_raw_sha256": "c" * 64,
        "audit_semantic_sha256": "d" * 64,
        "audit_seal_raw_sha256": "e" * 64,
        "audit_checksums_raw_sha256": "f" * 64,
        "registry": {"fixture": "0" * 64},
        "authority_context_semantic_sha256": "1" * 64,
    }


def _valid_approval(bindings: dict[str, Any]) -> dict[str, Any]:
    return seal_payload(
        {
            "schema_version": R3_APPROVAL_SCHEMA_VERSION,
            "created_at_utc": "2026-08-21T00:01:00+00:00",
            "status": R3_APPROVAL_STATUS,
            "action": R3_APPROVAL_ACTION,
            "decision": R3_APPROVAL_DECISION,
            "root_approver_id": "independent-root",
            "bindings": bindings,
            "reservation_scope": EXPECTED_APPROVAL_RESERVATION_SCOPE,
            "authority_boundary": EXPECTED_APPROVAL_AUTHORITY,
        },
        "approval_semantic_sha256",
    )


def test_public_authority_api_has_no_context_or_project_injection() -> None:
    assert tuple(inspect.signature(authority.build_authority_context).parameters) == ()
    assert set(inspect.signature(authority.verify_independent_audit_bundle).parameters) == {
        "precommit_root",
        "audit_root",
    }
    assert set(
        inspect.signature(authority.verify_root_reservation_approval_bundle).parameters
    ) == {"precommit_root", "audit_root", "approval_root"}
    with pytest.raises(TypeError):
        authority.verify_independent_audit_bundle(
            precommit_root=Path("absent"),
            audit_root=Path("absent"),
            expected_context={},  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        authority.verify_root_reservation_approval_bundle(
            precommit_root=Path("absent"),
            audit_root=Path("absent"),
            approval_root=Path("absent"),
            project_root=Path("."),  # type: ignore[call-arg]
        )


def test_empty_or_copied_precommit_path_is_rejected_before_context(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(V2R3ContractError, match="exact frozen R3 precommit"):
        verify_frozen_precommit(empty)
    with pytest.raises(V2R3ContractError, match="one exact fixed root"):
        authority.verify_independent_audit_bundle(
            precommit_root=empty,
            audit_root=empty,
        )


def test_exact_live_design_reconstruction_passes() -> None:
    expected = _expected_design()
    validate_design_semantics(expected, expected)
    assert expected["status"] == STATUS
    assert expected["candidate_contract"] == candidate_contract_payload()
    assert expected["evaluation_policy"] == evaluation_policy_payload()
    assert expected["qualification"]["candidate_ids"] == list(TOURNAMENT_CANDIDATE_IDS)


@pytest.mark.parametrize(
    "attack",
    [
        "candidate_id",
        "candidate_formula",
        "qualification_gate",
        "heldout_gate",
        "ranking",
        "geometry",
        "schema",
        "qualification_seed",
        "heldout_seed",
        "reservation",
        "registry",
        "audit_go",
        "root_approval",
        "runtime",
        "qualification_launch",
        "heldout_launch",
        "promotion",
    ],
)
def test_resealed_semantic_drift_is_rejected(attack: str) -> None:
    expected = _expected_design()
    mutated = copy.deepcopy(expected)
    if attack == "candidate_id":
        mutated["candidate_contract"]["ids_in_fixed_order"] = ["unbound_candidate"]
    elif attack == "candidate_formula":
        mutated["candidate_contract"]["fixed_alpha_040"][
            "alpha_on_directional_agreement"
        ] = 0.9
    elif attack == "qualification_gate":
        mutated["qualification"]["gate"]["pooled_mae_relative_gain_min"] = -1.0
    elif attack == "heldout_gate":
        mutated["heldout"]["gate"]["worst_seed_dgp_harm_max"] = 1.0
    elif attack == "ranking":
        mutated["qualification"]["ranking_rule"] = ["highest_pooled_gain"]
    elif attack == "geometry":
        mutated["heldout"]["geometry"]["seed_count"] = 4
    elif attack == "schema":
        mutated["truth_schema"]["ordered_columns"] = ["date", "wrong_truth"]
    elif attack == "qualification_seed":
        mutated["reservation_plan"]["qualification_seed_ids"] = [1, 2, 3, 4, 5]
    elif attack == "heldout_seed":
        mutated["reservation_plan"]["heldout_seed_ids"] = [7, 11, 13, 17, 19]
    elif attack == "reservation":
        mutated["reservation_plan"]["reservation_performed"] = True
    elif attack == "registry":
        mutated["registry_mutated"] = True
    elif attack == "audit_go":
        mutated["audit_GO_created"] = True
    elif attack == "root_approval":
        mutated["root_approval_created"] = True
    elif attack == "runtime":
        mutated["runtime_root_created"] = True
    elif attack == "qualification_launch":
        mutated["qualification_launch_authorized"] = True
    elif attack == "heldout_launch":
        mutated["heldout_unlock_or_launch_authorized"] = True
    else:
        mutated["production_promotion_authority"] = True
    with pytest.raises(V2R3ContractError):
        validate_design_semantics(_reseal(mutated), expected)


@pytest.mark.parametrize(
    "attack", ["minimal", "unbound", "extra", "missing", "wrong_hash", "P0", "state"]
)
def test_prior_audit_payload_attacks_still_reject(attack: str) -> None:
    context = _audit_context()
    audit = _valid_audit(context)
    if attack == "minimal":
        audit = seal_payload(
            {
                "schema_version": R3_AUDIT_SCHEMA_VERSION,
                "verdict": R3_AUDIT_VERDICT,
                "reservation_authorized_by_audit_alone": False,
            },
            "audit_semantic_sha256",
        )
    else:
        audit.pop("audit_semantic_sha256")
        if attack == "unbound":
            audit["bindings"] = {}
        elif attack == "extra":
            audit["unexpected"] = True
        elif attack == "missing":
            audit.pop("findings")
        elif attack == "wrong_hash":
            audit["bindings"] = copy.deepcopy(audit["bindings"])
            audit["bindings"]["authority_context_semantic_sha256"] = "0" * 64
        elif attack == "P0":
            audit["severity_counts"] = {"P0": 1, "P1": 0, "P2": 0}
        else:
            audit["execution_state"] = copy.deepcopy(audit["execution_state"])
            audit["execution_state"]["fresh_seed_ids_derived"] = True
        audit = seal_payload(audit, "audit_semantic_sha256")
    with pytest.raises(V2R3ContractError):
        authority._validate_audit_payload(audit, context)


@pytest.mark.parametrize(
    "attack", ["minimal", "unbound", "extra", "missing", "wrong_hash", "scope", "state"]
)
def test_prior_root_approval_payload_attacks_still_reject(attack: str) -> None:
    bindings = _approval_bindings()
    approval = _valid_approval(bindings)
    if attack == "minimal":
        approval = seal_payload(
            {
                "schema_version": R3_APPROVAL_SCHEMA_VERSION,
                "action": R3_APPROVAL_ACTION,
                "decision": R3_APPROVAL_DECISION,
                "root_approver_id": "fixture",
            },
            "approval_semantic_sha256",
        )
    else:
        approval.pop("approval_semantic_sha256")
        if attack == "unbound":
            approval["bindings"] = {}
        elif attack == "extra":
            approval["unexpected"] = True
        elif attack == "missing":
            approval.pop("reservation_scope")
        elif attack == "wrong_hash":
            approval["bindings"] = copy.deepcopy(approval["bindings"])
            approval["bindings"]["audit_raw_sha256"] = "2" * 64
        elif attack == "scope":
            approval["reservation_scope"] = copy.deepcopy(
                approval["reservation_scope"]
            )
            approval["reservation_scope"]["qualification_seed_count"] = 6
        else:
            approval["authority_boundary"] = copy.deepcopy(
                approval["authority_boundary"]
            )
            approval["authority_boundary"][
                "generation_prediction_truth_or_score_authorized"
            ] = True
        approval = seal_payload(approval, "approval_semantic_sha256")
    with pytest.raises(V2R3ContractError):
        authority._validate_approval_payload(approval, bindings)


def test_r2_no_go_and_complete_lineage_are_exact_metadata_only() -> None:
    no_go = prior_no_go_bindings(PROJECT_ROOT)
    lineage = verify_r3_lineage(PROJECT_ROOT)
    assert no_go["R2"]["audit_raw_sha256"] == R2_NO_GO_FILES["AUDIT.json"]
    assert no_go["R2"]["audit_semantic_sha256"] == R2_NO_GO_AUDIT_SEMANTIC
    assert no_go["R2"]["severity_counts"] == {"P0": 2, "P1": 0, "P2": 0}
    assert lineage["R1_R2_authority_reuse_or_retry"] is False
    assert lineage["old_truth_or_latent_payload_opened"] is False
    assert lineage["historical_prediction_payload_opened"] is False
    assert lineage["historical_score_payload_opened"] is False


def test_source_smoke_and_registry_contain_no_new_payload_or_seed_ids() -> None:
    source = source_manifest_payload()
    smoke = _smoke_binding()
    registry = registry_snapshot(PROJECT_ROOT)
    assert source["old_vault_payload_files_in_inventory"] == 0
    assert source["historical_prediction_payload_files_in_inventory"] == 0
    assert source["historical_score_payload_files_in_inventory"] == 0
    assert source["fresh_truth_payload_files_in_inventory"] == 0
    assert smoke["truth_payload_persisted"] is False
    assert smoke["truth_values_selected_or_reported"] is False
    assert registry["seed_identifiers_copied_into_precommit"] is False
    assert registry["fresh_seed_derivation_performed"] is False


def test_wrong_activation_rejects_before_ledger_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> tuple[object, ...]:
        raise AssertionError("ledger must not be imported")

    monkeypatch.setattr(seed_ledger, "_ledger_api", forbidden)
    with pytest.raises(V2R3ContractError, match="activation literal"):
        seed_ledger.reserve_fresh_5_plus_5(
            activation_literal=RESERVATION_ACTIVATION_LITERAL + "_WRONG"
        )


def test_audit_schema_is_closed_and_context_hash_is_required() -> None:
    assert "bindings" in AUDIT_KEYS
    assert "audit_semantic_sha256" in AUDIT_KEYS
    assert "authority_context_semantic_sha256" in _audit_context()
