from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from pe_regime_v04.model_lab.models.wave1.registration import (
    append_planned_wave1_definitions,
    planned_feature_registrations,
    planned_model_registrations,
    reconcile_planned_wave1_definitions,
    verify_definition_resume_state_against_audit,
)
from pe_regime_v04.model_lab.registry import (
    load_feature_registry,
    load_model_registry,
    validate_registry_cross_references,
)
from registry_test_support import write_pre_wave1_registry_fixture


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_planned_definitions_are_unopened_and_use_append_apis_only_in_temp(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    registry_root = root / "research" / "model_zoo"
    originals = {
        name: _hash(registry_root / name)
        for name in (
            "feature_registry.csv",
            "feature_registry.json",
            "model_registry.csv",
            "model_registry.json",
        )
    }
    feature_paths, model_paths = write_pre_wave1_registry_fixture(tmp_path)
    append_planned_wave1_definitions(feature_paths=feature_paths, model_paths=model_paths)
    features = load_feature_registry(feature_paths)
    models = load_model_registry(model_paths)
    validate_registry_cross_references(models, features, formal_run=True)
    assert len(planned_feature_registrations()) == 36
    assert len(planned_model_registrations()) == 17
    planned_ids = {item.model_id for item in planned_model_registrations()}
    appended = [item for item in models if item.model_id in planned_ids]
    assert len(appended) == 17
    assert all(item.status == "UNTESTED" for item in appended)
    assert all(item.heldout_status == "NOT_OPENED" for item in appended)
    assert {item.target for item in appended} == {"log(observed_pe)"}
    state_space = next(item for item in appended if item.family == "state_space_local_linear_trend")
    supervised = [item for item in appended if item is not state_space]
    assert state_space.track == "B"
    assert state_space.uses_same_row_price is False
    assert {item.track for item in supervised} == {"C"}
    assert all(item.uses_same_row_price is True for item in supervised)
    assert all(
        item.paper and item.repository and item.package and item.license for item in appended
    )
    for name, digest in originals.items():
        assert _hash(registry_root / name) == digest


def test_definition_transaction_resumes_exactly_after_injected_interruption(
    tmp_path: Path,
) -> None:
    feature_paths, model_paths = write_pre_wave1_registry_fixture(tmp_path)
    audit_inventory = [
        {
            "relative_path": f"research/model_zoo/{name}",
            "bytes": (tmp_path / name).stat().st_size,
            "sha256": _hash(tmp_path / name),
        }
        for name in (
            "feature_registry.csv",
            "feature_registry.json",
            "model_registry.csv",
            "model_registry.json",
        )
    ]

    def interrupt(kind: str, _identifier: str, appended: int) -> None:
        if kind == "feature" and appended == 5:
            raise RuntimeError("injected interruption")

    with pytest.raises(RuntimeError, match="injected interruption"):
        reconcile_planned_wave1_definitions(
            feature_paths=feature_paths,
            model_paths=model_paths,
            after_append=interrupt,
        )
    resume_state = verify_definition_resume_state_against_audit(
        feature_paths=feature_paths,
        model_paths=model_paths,
        audit_inventory=audit_inventory,
    )
    assert resume_state["exact_partial_feature_count"] == 5
    assert resume_state["exact_partial_model_count"] == 0
    resumed = reconcile_planned_wave1_definitions(
        feature_paths=feature_paths,
        model_paths=model_paths,
    )
    assert len(resumed.feature_skipped_exact) == 5
    assert len(resumed.feature_appended) == 31
    assert len(resumed.model_appended) == 17
    repeated = reconcile_planned_wave1_definitions(
        feature_paths=feature_paths,
        model_paths=model_paths,
    )
    assert len(repeated.feature_skipped_exact) == 36
    assert len(repeated.model_skipped_exact) == 17
    assert not repeated.feature_appended
    assert not repeated.model_appended
