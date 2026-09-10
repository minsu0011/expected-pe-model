from __future__ import annotations

import copy
from pathlib import Path

import pytest

from research.model_zoo.prospective_fresh_ensemble_v1.seed_ledger import (
    heldout_commitment,
    planned_seed_groups,
    read_registry,
)
from research.model_zoo.prospective_fresh_ensemble_v4.contracts import (
    GENERATOR_LONG_PATHS_INDEPENDENT,
    GENERATOR_MAX_PATH_CHARS,
    GENERATOR_STAGING_RELATIVE,
    HELDOUT_SEED_COMMITMENT_SHA256,
    QUALIFICATION_SEEDS,
    V3_FAILURE_AUDIT_ROOT_RAW_SHA256,
    V3_PRELAUNCH_AUDIT_ROOT_RAW_SHA256,
    V3_QUALIFICATION_SEEDS,
    V3_RESERVATION_ENTRY_SHA256,
    V3_RESERVATION_ID,
    V3_ROOT_RAW_SHA256,
    V4_PRE_RESERVATION_REGISTRY_RAW_SHA256,
    V4_PRE_RESERVATION_REGISTRY_SELF_SHA256,
    ProspectiveContractError,
    seal_payload,
    sha256_file,
)
from research.model_zoo.prospective_fresh_ensemble_v4.precommit import (
    _verify_v3_custody,
    build_reservation_binding,
    build_source_dependency_closure,
    build_supersession,
    verify_generator_smoke_evidence,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json"


def _pre_v4_registry() -> dict[str, object]:
    current = read_registry(REGISTRY_PATH)
    prefix = copy.deepcopy(current)
    prefix["entries"] = prefix["entries"][:7]
    prefix["updated_at_utc"] = prefix["entries"][-1]["created_at_utc"]
    prefix.pop("registry_sha256")
    return seal_payload(prefix, "registry_sha256")


def test_v4_fresh_plan_is_deterministic_and_all_v3_ids_are_unavailable() -> None:
    current = read_registry(REGISTRY_PATH)
    registry = _pre_v4_registry()
    qualification, heldout = planned_seed_groups(registry)
    v3_matches = [
        entry
        for entry in registry["entries"]
        if entry.get("reservation_id") == V3_RESERVATION_ID
    ]
    assert len(v3_matches) == 1
    assert v3_matches[0]["entry_sha256"] == V3_RESERVATION_ENTRY_SHA256
    v3_reserved = set(v3_matches[0]["reserved_seeds"])
    assert tuple(qualification) == QUALIFICATION_SEEDS
    if len(current["entries"]) == 7:
        assert sha256_file(REGISTRY_PATH) == V4_PRE_RESERVATION_REGISTRY_RAW_SHA256
    assert registry["registry_sha256"] == V4_PRE_RESERVATION_REGISTRY_SELF_SHA256
    assert len(heldout) == 5
    assert heldout_commitment(heldout) == HELDOUT_SEED_COMMITMENT_SHA256
    assert not (set(qualification) | set(heldout)).intersection(v3_reserved)
    assert set(V3_QUALIFICATION_SEEDS).issubset(v3_reserved)


def test_v3_terminal_lineage_is_exact_recursive_and_sealed() -> None:
    state = _verify_v3_custody(PROJECT_ROOT)
    assert set(state["v3_root_records"]) == set(V3_ROOT_RAW_SHA256)
    assert set(state["prelaunch_records"]) == set(V3_PRELAUNCH_AUDIT_ROOT_RAW_SHA256)
    assert set(state["failure_records"]) == set(V3_FAILURE_AUDIT_ROOT_RAW_SHA256)
    assert state["failure_audit"]["verdict"] == (
        "TERMINAL_QUALIFICATION_GENERATION_FAILURE_NO_RELAUNCH"
    )
    assert state["failure_audit"]["qualification_relaunch_authorized"] is False


def test_v4_binding_and_supersession_are_read_only_and_hide_new_heldout_ids() -> None:
    before = sha256_file(REGISTRY_PATH)
    supersession = build_supersession(PROJECT_ROOT)
    assert sha256_file(REGISTRY_PATH) == before
    if len(read_registry(REGISTRY_PATH)["entries"]) == 7:
        binding = build_reservation_binding(PROJECT_ROOT)
        assert binding["qualification_seeds"] == list(QUALIFICATION_SEEDS)
        assert binding["heldout_seed_count"] == 5
        assert "locked_seeds" not in binding
        assert binding["v3_reserved_group_available_to_v4"] is False
    else:
        with pytest.raises(ProspectiveContractError, match="fresh V4 deterministic"):
            build_reservation_binding(PROJECT_ROOT)
    assert supersession["supersedes_lane"] == "prospective_fresh_ensemble_v3"
    assert supersession["v3_relaunch_allowed"] is False
    assert set(supersession["v3_terminal_root_artifacts"]) == set(V3_ROOT_RAW_SHA256)


def test_source_closure_requires_smoke_before_any_interpreter_or_output_work() -> None:
    with pytest.raises(ProspectiveContractError, match="generator smoke receipt"):
        build_source_dependency_closure(PROJECT_ROOT)


def test_smoke_path_must_use_exact_short_managed_identity() -> None:
    with pytest.raises(ProspectiveContractError, match="short staging root"):
        verify_generator_smoke_evidence(PROJECT_ROOT, REGISTRY_PATH)
    assert GENERATOR_STAGING_RELATIVE == "outputs/_p4g_v4"
    assert GENERATOR_MAX_PATH_CHARS == 239
    assert GENERATOR_LONG_PATHS_INDEPENDENT is True
