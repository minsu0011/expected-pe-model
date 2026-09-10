from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from pe_regime_v04.model_lab import (
    FeatureMetadata,
    FeatureRegistration,
    ModelRegistration,
    RegistryError,
    RegistryPaths,
    append_feature_registration,
    append_model_registration,
    feature_registry_json_schema,
    load_feature_registry,
    load_model_registry,
    load_model_registry_history,
    model_registry_json_schema,
    validate_registry_cross_references,
    write_feature_registry,
    write_immutable_schema,
    write_model_registry,
)
from registry_test_support import assert_checked_in_registry_history


EMPTY_PARAMETERS_SHA256 = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def _model(*, model_id: str = "example", description: str = "Example model") -> ModelRegistration:
    return ModelRegistration(
        model_id=model_id,
        family="test",
        variant="unit",
        version="1",
        registry_revision=0,
        track="B",
        estimand="market-conditioned expected P/E",
        external_reference=False,
        paper=None,
        repository=None,
        package=None,
        license=None,
        target="observed_pe",
        feature_set="observed_pe_only",
        uses_same_row_price=False,
        uses_same_row_observed_pe=True,
        causal=False,
        pit_safe=True,
        train_window="expanding",
        refit_frequency="each_fold",
        hyperparameters={},
        tuning_status="UNTESTED",
        locked_status="UNTESTED",
        heldout_status="NOT_OPENED",
        fair_log_mae=None,
        fair_log_rmse=None,
        worst_seed=None,
        compute_time=None,
        status="UNTESTED",
        notes="Unit-test registration only.",
        entrypoint="example.module:Model",
        feature_ids=("observed_pe",),
        prediction_name="expected_pe",
        output_semantics="positive expected P/E",
        deterministic=True,
        description=description,
        parameters_sha256=EMPTY_PARAMETERS_SHA256,
    )


def _feature(
    *, feature_id: str = "observed_pe", column_name: str = "observed_pe"
) -> FeatureRegistration:
    return FeatureRegistration(
        feature_id=feature_id,
        column_name=column_name,
        description="PIT feature",
        source="test",
        dtype="float64",
        availability="point_in_time",
        availability_lag_sessions=0,
        lookahead_sessions=0,
        evaluation_only=False,
        allowed_for_fit=True,
        allowed_for_predict=True,
        point_in_time_safe=True,
        uses_revised_data=False,
        feature_family="VALUATION",
        provenance_reference="unit-test registry fixture",
        provenance_sha256=None,
        prefix_invariance_status="UNTESTED",
        future_intervention_status="UNTESTED",
        same_row_target_leakage_status="UNTESTED",
        pit_availability_status="UNTESTED",
        publication_date_status="NOT_APPLICABLE",
        restatement_availability_status="NOT_APPLICABLE",
        audit_notes="Synthetic unit-test feature.",
    )


def _paths(root: Path, kind: str) -> RegistryPaths:
    return RegistryPaths(root / f"{kind}.csv", root / f"{kind}.json")


def test_checked_in_registries_and_schemas_are_self_consistent() -> None:
    state = assert_checked_in_registry_history()
    assert len(state.history) > len(state.latest)
    assert any(model.registry_revision > 0 for model in state.latest)
    assert "historical_geometric_mean_pe" in {model.model_id for model in state.latest}
    truth = next(feature for feature in state.features if feature.column_name == "true_fair_pe")
    assert truth.evaluation_only is True
    assert truth.allowed_for_fit is False
    assert truth.allowed_for_predict is False
    assert (
        json.loads(
            (state.root / "schemas" / "model_registry.schema.json").read_text(encoding="utf-8")
        )
        == model_registry_json_schema()
    )
    assert (
        json.loads(
            (state.root / "schemas" / "feature_registry.schema.json").read_text(encoding="utf-8")
        )
        == feature_registry_json_schema()
    )


def test_dual_registry_round_trip_and_idempotent_append(tmp_path: Path) -> None:
    model_paths = _paths(tmp_path, "models")
    feature_paths = _paths(tmp_path, "features")
    model = _model()
    feature = _feature()
    model_snapshot = write_model_registry(model_paths, [model])
    feature_snapshot = write_feature_registry(feature_paths, [feature])
    assert model_snapshot.record_count == feature_snapshot.record_count == 1
    assert load_model_registry(model_paths) == (model,)
    assert load_feature_registry(feature_paths) == (feature,)
    before = (model_paths.csv_path.read_bytes(), model_paths.json_path.read_bytes())
    assert append_model_registration(model_paths, model).record_count == 1
    assert (model_paths.csv_path.read_bytes(), model_paths.json_path.read_bytes()) == before


def test_model_lifecycle_is_revisioned_append_only_and_resolves_latest(tmp_path: Path) -> None:
    paths = _paths(tmp_path, "models")
    initial = _model()
    evaluated = replace(
        initial,
        registry_revision=1,
        tuning_status="PASS",
        locked_status="LOCKED",
        fair_log_mae=0.12,
        fair_log_rmse=0.18,
        worst_seed=17,
        compute_time=4.5,
        status="PASS",
        notes="Formal common-mask evaluation passed.",
    )
    write_model_registry(paths, [initial])
    snapshot = append_model_registration(paths, evaluated)
    assert snapshot.record_count == 2
    assert load_model_registry_history(paths) == (initial, evaluated)
    assert load_model_registry(paths) == (evaluated,)
    assert append_model_registration(paths, evaluated).record_count == 2


def test_model_lifecycle_rejects_gaps_definition_changes_and_terminal_reversal(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path, "models")
    initial = _model()
    write_model_registry(paths, [initial])
    with pytest.raises(RegistryError, match="contiguous"):
        append_model_registration(
            paths,
            replace(initial, registry_revision=2, status="REJECTED", notes="gap"),
        )
    with pytest.raises(RegistryError, match="definition fields are immutable"):
        append_model_registration(
            paths,
            replace(
                initial,
                registry_revision=1,
                description="changed immutable definition",
                status="REJECTED",
                notes="invalid",
            ),
        )
    rejected = replace(
        initial,
        registry_revision=1,
        status="REJECTED",
        notes="Screening rejection.",
    )
    append_model_registration(paths, rejected)
    with pytest.raises(RegistryError, match="illegal status transition"):
        append_model_registration(
            paths,
            replace(
                rejected,
                registry_revision=2,
                tuning_status="PASS",
                locked_status="LOCKED",
                status="PASS",
                fair_log_mae=0.1,
                fair_log_rmse=0.2,
                worst_seed=1,
                compute_time=1.0,
                notes="illegal reversal",
            ),
        )


def test_model_status_schema_contains_required_tournament_outcomes() -> None:
    status_enum = model_registry_json_schema()["properties"]["records"]["items"]["properties"][
        "status"
    ]["enum"]
    assert {
        "PROMOTED",
        "PROMISING",
        "SATURATED",
        "REJECTED",
        "COMPUTE_INEFFICIENT",
        "DATA_INSUFFICIENT",
    }.issubset(status_enum)


def test_required_tournament_outcomes_round_trip_through_csv_and_json(
    tmp_path: Path,
) -> None:
    statuses = (
        "PROMOTED",
        "PROMISING",
        "SATURATED",
        "REJECTED",
        "COMPUTE_INEFFICIENT",
        "DATA_INSUFFICIENT",
    )
    records = []
    for index, status in enumerate(statuses):
        initial = _model(model_id=status.lower())
        records.append(initial)
        if status in {"PROMOTED", "PROMISING"}:
            evaluated = replace(
                initial,
                registry_revision=1,
                tuning_status="PASS",
                locked_status="LOCKED",
                fair_log_mae=0.1 + index / 100.0,
                fair_log_rmse=0.2 + index / 100.0,
                worst_seed=index,
                compute_time=1.0 + index,
                status="PROMISING" if status == "PROMISING" else "PASS",
                notes=f"Evaluated fixture for {status}.",
            )
            records.append(evaluated)
            if status == "PROMOTED":
                spent = replace(
                    evaluated,
                    registry_revision=2,
                    heldout_status="RESERVED_SPENT",
                    notes="Heldout reservation opened and spent.",
                )
                records.extend(
                    [
                        spent,
                        replace(
                            spent,
                            registry_revision=3,
                            heldout_status="PASS",
                            status="PROMOTED",
                            notes="Heldout passed; promoted fixture.",
                        ),
                    ]
                )
        else:
            records.append(
                replace(
                    initial,
                    registry_revision=1,
                    status=status,
                    notes=f"Round-trip fixture for {status}.",
                )
            )
    paths = _paths(tmp_path, "models")
    write_model_registry(paths, records)
    latest = load_model_registry(paths)
    assert {record.status for record in latest} == set(statuses)
    assert load_model_registry_history(paths) == tuple(records)


def test_model_lifecycle_cross_field_invariants_and_heldout_spend_gate(
    tmp_path: Path,
) -> None:
    initial = _model()
    complete_results = {
        "fair_log_mae": 0.1,
        "fair_log_rmse": 0.2,
        "worst_seed": 7,
        "compute_time": 1.0,
    }
    with pytest.raises(RegistryError, match="revision 0"):
        replace(
            initial,
            tuning_status="PASS",
            locked_status="LOCKED",
            heldout_status="PASS",
            status="PROMOTED",
            **complete_results,
        )
    with pytest.raises(RegistryError, match="tuning_status PASS"):
        replace(initial, registry_revision=1, locked_status="LOCKED")
    with pytest.raises(RegistryError, match="locked model"):
        replace(initial, registry_revision=1, heldout_status="RESERVED_SPENT")

    evaluated = replace(
        initial,
        registry_revision=1,
        tuning_status="PASS",
        locked_status="LOCKED",
        status="PASS",
        notes="Locked evaluation passed.",
        **complete_results,
    )
    paths = _paths(tmp_path, "models")
    write_model_registry(paths, [initial, evaluated])
    with pytest.raises(RegistryError, match="illegal heldout_status transition"):
        append_model_registration(
            paths,
            replace(
                evaluated,
                registry_revision=2,
                heldout_status="PASS",
                notes="Invalid direct heldout result.",
            ),
        )
    spent = replace(
        evaluated,
        registry_revision=2,
        heldout_status="RESERVED_SPENT",
        notes="Heldout reservation spent before result publication.",
    )
    append_model_registration(paths, spent)
    promoted = replace(
        spent,
        registry_revision=3,
        heldout_status="PASS",
        status="PROMOTED",
        notes="Heldout passed after reserved-spent event.",
    )
    append_model_registration(paths, promoted)
    assert load_model_registry(paths) == (promoted,)


def test_track_a_and_feature_audit_contracts_fail_closed(
    observed_feature: FeatureMetadata,
) -> None:
    with pytest.raises(RegistryError, match="Track A"):
        replace(_model(), track="A")
    track_a = replace(
        _model(),
        track="A",
        uses_same_row_observed_pe=False,
        feature_ids=(),
        feature_set="fundamental_only",
    )
    assert track_a.track == "A"
    with pytest.raises(ValueError, match="unsafe feature"):
        replace(
            observed_feature,
            prefix_invariance_status="FAIL",
            allowed_for_fit=True,
            allowed_for_predict=True,
        )


def test_append_only_registry_preserves_prefix_and_rejects_conflict(tmp_path: Path) -> None:
    paths = _paths(tmp_path, "models")
    first = _model(model_id="first")
    second = _model(model_id="second")
    write_model_registry(paths, [first])
    prefix_line = paths.csv_path.read_text(encoding="utf-8").splitlines()[1]
    append_model_registration(paths, second)
    assert load_model_registry(paths) == (first, second)
    assert paths.csv_path.read_text(encoding="utf-8").splitlines()[1] == prefix_line
    with pytest.raises(RegistryError, match="conflict"):
        append_model_registration(paths, replace(first, description="changed"))
    with pytest.raises(RegistryError, match="exact existing prefix"):
        write_model_registry(paths, [second, first])
    with pytest.raises(RegistryError, match="exact existing prefix"):
        write_model_registry(paths, [first])


def test_feature_append_and_cross_reference_validation(tmp_path: Path) -> None:
    paths = _paths(tmp_path, "features")
    observed = _feature()
    second = _feature(feature_id="ml_expected_pe", column_name="ml_expected_pe")
    append_feature_registration(paths, observed)
    append_feature_registration(paths, second)
    assert load_feature_registry(paths) == (observed, second)
    validate_registry_cross_references([_model()], [observed, second])
    with pytest.raises(RegistryError, match="unknown features"):
        validate_registry_cross_references(
            [replace(_model(), feature_ids=("missing",))], [observed]
        )


def test_formal_cross_reference_requires_completed_feature_audits() -> None:
    observed = _feature()
    with pytest.raises(RegistryError, match="completed feature audits"):
        validate_registry_cross_references([_model()], [observed], formal_run=True)
    audited = replace(
        observed,
        prefix_invariance_status="PASS",
        future_intervention_status="PASS",
        same_row_target_leakage_status="PASS",
        pit_availability_status="PASS",
        publication_date_status="NOT_APPLICABLE",
        restatement_availability_status="NOT_APPLICABLE",
    )
    validate_registry_cross_references([_model()], [audited], formal_run=True)


def test_evaluation_only_feature_cannot_be_cross_referenced() -> None:
    truth = FeatureRegistration(
        feature_id="truth",
        column_name="true_fair_pe",
        description="evaluation truth",
        source="detached",
        dtype="float64",
        availability="evaluation_only",
        availability_lag_sessions=0,
        lookahead_sessions=0,
        evaluation_only=True,
        allowed_for_fit=False,
        allowed_for_predict=False,
        point_in_time_safe=False,
        uses_revised_data=False,
        feature_family="VALUATION",
        provenance_reference="detached unit-test truth",
        provenance_sha256=None,
        prefix_invariance_status="NOT_APPLICABLE",
        future_intervention_status="NOT_APPLICABLE",
        same_row_target_leakage_status="NOT_APPLICABLE",
        pit_availability_status="NOT_APPLICABLE",
        publication_date_status="NOT_APPLICABLE",
        restatement_availability_status="NOT_APPLICABLE",
        audit_notes="Evaluation-only truth is forbidden from model calls.",
    )
    model = replace(_model(), feature_ids=("truth",))
    with pytest.raises(RegistryError, match="unsafe feature"):
        validate_registry_cross_references([model], [truth])


def test_registry_detects_json_and_csv_tampering(tmp_path: Path) -> None:
    json_paths = _paths(tmp_path / "json", "models")
    write_model_registry(json_paths, [_model()])
    payload = json.loads(json_paths.json_path.read_text(encoding="utf-8"))
    payload["records"][0]["description"] = "tampered"
    json_paths.json_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RegistryError, match="SHA-256"):
        load_model_registry(json_paths)

    csv_paths = _paths(tmp_path / "csv", "models")
    write_model_registry(csv_paths, [_model()])
    text = csv_paths.csv_path.read_text(encoding="utf-8").replace("Example model", "tampered")
    csv_paths.csv_path.write_text(text, encoding="utf-8")
    with pytest.raises(RegistryError, match="projections differ"):
        load_model_registry(csv_paths)


def test_schema_writer_is_create_only_or_byte_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    schema = model_registry_json_schema()
    first = write_immutable_schema(path, schema)
    second = write_immutable_schema(path, schema)
    assert first == second
    with pytest.raises(RegistryError, match="immutable"):
        write_immutable_schema(path, feature_registry_json_schema())
