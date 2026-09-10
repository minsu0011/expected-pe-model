"""Test-only fixtures for the append-only checked-in Model Lab registries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pe_regime_v04.model_lab.models.wave1.registration import (
    planned_feature_registrations,
    planned_model_registrations,
)
from pe_regime_v04.model_lab.registry import (
    FeatureRegistration,
    ModelRegistration,
    RegistryPaths,
    load_feature_registry,
    load_model_registry,
    load_model_registry_history,
    validate_registry_cross_references,
    write_feature_registry,
    write_model_registry,
)


_LIFECYCLE_FIELDS = frozenset(
    {
        "registry_revision",
        "tuning_status",
        "locked_status",
        "heldout_status",
        "fair_log_mae",
        "fair_log_rmse",
        "worst_seed",
        "compute_time",
        "status",
        "notes",
    }
)
_PRE_WAVE1_FEATURE_IDS = frozenset(
    {"observed_pe", "ml_expected_pe", "v04_expected_pe", "true_fair_pe"}
)


@dataclass(frozen=True)
class CheckedInRegistryState:
    root: Path
    feature_paths: RegistryPaths
    model_paths: RegistryPaths
    features: tuple[FeatureRegistration, ...]
    history: tuple[ModelRegistration, ...]
    latest: tuple[ModelRegistration, ...]


def _checked_in_root() -> Path:
    return Path(__file__).resolve().parents[2] / "research" / "model_zoo"


def _definition_payload(record: ModelRegistration) -> dict[str, object]:
    return {
        field: value
        for field, value in record.to_record().items()
        if field not in _LIFECYCLE_FIELDS
    }


def assert_checked_in_registry_history() -> CheckedInRegistryState:
    """Validate every event and prove the public loader is the latest projection."""

    root = _checked_in_root()
    feature_paths = RegistryPaths(root / "feature_registry.csv", root / "feature_registry.json")
    model_paths = RegistryPaths(root / "model_registry.csv", root / "model_registry.json")
    features = load_feature_registry(feature_paths)
    history = load_model_registry_history(model_paths)
    latest = load_model_registry(model_paths)

    histories: dict[str, list[ModelRegistration]] = {}
    definition_order: list[str] = []
    for event in history:
        if event.definition_id not in histories:
            histories[event.definition_id] = []
            definition_order.append(event.definition_id)
        histories[event.definition_id].append(event)

    assert history
    assert len(histories) == len(latest)
    for events in histories.values():
        assert tuple(event.registry_revision for event in events) == tuple(range(len(events)))
        assert all(
            _definition_payload(event) == _definition_payload(events[0]) for event in events[1:]
        )
    assert latest == tuple(histories[definition_id][-1] for definition_id in definition_order)

    planned = {record.definition_id: record for record in planned_model_registrations()}
    assert planned.keys() <= histories.keys()
    for definition_id, definition in planned.items():
        events = histories[definition_id]
        assert events[0] == definition
        assert len(events) >= 2

    baseline_events = [
        event for event in history if event.model_id == "historical_geometric_mean_pe"
    ]
    assert len(baseline_events) == 1
    assert baseline_events[0].registry_revision == 0

    validate_registry_cross_references(history, features)
    validate_registry_cross_references(latest, features)
    return CheckedInRegistryState(
        root=root,
        feature_paths=feature_paths,
        model_paths=model_paths,
        features=features,
        history=history,
        latest=latest,
    )


def write_pre_wave1_registry_fixture(
    destination: Path,
) -> tuple[RegistryPaths, RegistryPaths]:
    """Materialize the exact valid registry prefix before Wave1 definitions/events."""

    state = assert_checked_in_registry_history()
    planned_feature_ids = {
        registration.feature_id for registration in planned_feature_registrations()
    }
    planned_definition_ids = {
        registration.definition_id for registration in planned_model_registrations()
    }
    base_features = tuple(
        feature for feature in state.features if feature.feature_id not in planned_feature_ids
    )
    wave1_positions = tuple(
        index
        for index, event in enumerate(state.history)
        if event.definition_id in planned_definition_ids
    )
    assert wave1_positions
    base_models = state.history[: min(wave1_positions)]
    assert all(event.definition_id not in planned_definition_ids for event in base_models)
    assert {feature.feature_id for feature in base_features} == _PRE_WAVE1_FEATURE_IDS
    assert len(base_models) == 1
    assert base_models[0].model_id == "historical_geometric_mean_pe"
    assert base_models[0].registry_revision == 0

    destination.mkdir(parents=True, exist_ok=True)
    feature_paths = RegistryPaths(
        destination / "feature_registry.csv",
        destination / "feature_registry.json",
    )
    model_paths = RegistryPaths(
        destination / "model_registry.csv",
        destination / "model_registry.json",
    )
    write_feature_registry(feature_paths, base_features)
    write_model_registry(model_paths, base_models)
    validate_registry_cross_references(
        load_model_registry(model_paths), load_feature_registry(feature_paths)
    )
    return feature_paths, model_paths
