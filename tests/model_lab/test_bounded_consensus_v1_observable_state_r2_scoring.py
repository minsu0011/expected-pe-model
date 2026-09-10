from __future__ import annotations

import json
from pathlib import Path

import pytest

from research.model_zoo.bounded_consensus_v1 import RESEARCH_GATE, VARIANT_IDS
from research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring import (
    StateR2DetachedScoringError,
    build_capability_payload,
    load_and_verify_capability,
    scoring_design_payload,
    seal_capability,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring.contracts import (
    INPUT_CLOSURE_SHA256,
    INTEGRATION_DESIGN_SHA256,
    PREDICTION_FREEZE_LOGICAL_SHA256,
    PREDICTION_MANIFEST_LOGICAL_SHA256,
    PREDICTION_RAW_SHA256,
    TRUTH_LANE_SPECS,
)


def test_scoring_design_binds_exact_approved_state_r2_scope() -> None:
    design = scoring_design_payload()
    assert design["prediction_raw_sha256"] == PREDICTION_RAW_SHA256
    assert design["prediction_manifest_logical_sha256"] == (PREDICTION_MANIFEST_LOGICAL_SHA256)
    assert design["prediction_freeze_logical_sha256"] == PREDICTION_FREEZE_LOGICAL_SHA256
    assert design["integration_design_sha256"] == INTEGRATION_DESIGN_SHA256
    assert design["input_closure_sha256"] == INPUT_CLOSURE_SHA256
    assert tuple(design["variant_ids"]) == VARIANT_IDS
    assert design["expected_prediction_rows"] == 64800
    assert design["expected_evaluation_rows_per_variant"] == 12960
    assert design["frozen_research_gate"] == RESEARCH_GATE.__dict__
    assert design["tail_diagnostics_required"] is True
    assert design["correlation_diagnostics_required"] is True
    assert design["oracle_diagnostics_required"] is True
    assert design["oracle_diagnostics_used_by_gate"] is False
    assert design["heldout_access_authorized"] is False
    assert design["registry_mutation_authorized"] is False
    assert design["champion_mutation_authorized"] is False


def test_truth_to_prediction_lane_mapping_is_explicit_and_exact() -> None:
    assert tuple(spec.truth_lane_id for spec in TRUTH_LANE_SPECS) == (
        "prospective_fresh_ensemble_v4",
        "prospective_fresh_ensemble_v5",
    )
    assert tuple(spec.prediction_lane_id for spec in TRUTH_LANE_SPECS) == (
        "prospective_fresh_ensemble_v4_qualification_spent",
        "prospective_fresh_ensemble_v5_qualification_spent",
    )
    assert tuple(seed for spec in TRUTH_LANE_SPECS for seed in spec.seeds) == (
        7417,
        7433,
        7451,
        7457,
        7459,
        7507,
        7517,
        7523,
        7529,
        7537,
    )


def test_capability_freeze_binds_truth_records_without_opening_truth_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring.capability as module

    root = Path(__file__).resolve().parents[2]
    original_hash = module.sha256_file
    original_read_text = Path.read_text

    def guarded_hash(path: Path) -> str:
        if path.name.casefold() == "truth.csv":
            raise AssertionError("capability freeze attempted to hash truth CSV bytes")
        return original_hash(path)

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name.casefold() == "truth.csv":
            raise AssertionError("capability freeze attempted to read truth CSV values")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(module, "sha256_file", guarded_hash)
    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    capability = build_capability_payload(root)
    assert capability["truth_seed_count"] == 10
    assert capability["truth_csv_values_opened_while_freezing"] is False
    assert capability["truth_csv_bytes_hashed_while_freezing"] is False
    assert capability["prediction_artifact"]["sha256"] == PREDICTION_RAW_SHA256
    truth_records = [seed for lane in capability["truth_sources"] for seed in lane["seeds"]]
    assert len(truth_records) == 10
    assert all("qualification" in seed["truth_csv"]["path"].casefold() for seed in truth_records)
    assert all("truth_vault" in seed["truth_csv"]["path"].casefold() for seed in truth_records)
    assert not any("heldout" in seed["truth_csv"]["path"].casefold() for seed in truth_records)


def test_capability_self_seal_and_scope_fail_closed(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    capability = seal_capability(build_capability_payload(root))
    path = tmp_path / "EVALUATION_CAPABILITY.json"
    path.write_text(json.dumps(capability), encoding="utf-8")
    loaded = load_and_verify_capability(path)
    assert loaded["capability_sha256"] == capability["capability_sha256"]

    tampered = dict(capability)
    tampered["heldout_access_authorized"] = True
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(StateR2DetachedScoringError, match="self-seal"):
        load_and_verify_capability(path)

    excessive = dict(capability)
    excessive["heldout_access_authorized"] = True
    excessive = seal_capability(excessive)
    path.write_text(json.dumps(excessive), encoding="utf-8")
    with pytest.raises(StateR2DetachedScoringError, match="exceeds approved scope"):
        load_and_verify_capability(path)


def test_prediction_manifest_freeze_and_runtime_are_cross_bound() -> None:
    root = Path(__file__).resolve().parents[2]
    capability = build_capability_payload(root)
    assert capability["prediction_manifest_logical_sha256"] == (PREDICTION_MANIFEST_LOGICAL_SHA256)
    assert capability["prediction_freeze_logical_sha256"] == PREDICTION_FREEZE_LOGICAL_SHA256
    assert capability["prediction_artifact"]["sha256"] == PREDICTION_RAW_SHA256
    assert capability["capability_status"] == ("AUTHORIZED_EXACT_STATE_R2_SPENT_QUALIFICATION_ONLY")
