from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = (
    ROOT
    / "research"
    / "model_zoo"
    / "portfolio_governance_v1"
    / "PE_C1_C4_BINDING_METADATA_DESIGN_LOCK.json"
)
EXPECTED_LOCK_RAW_SHA256 = "8781077b3c12f6e0e647e81889d9e560fdcfd943aa40ff465881b57b8463f380"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_lock() -> dict[str, object]:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _walk(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_lock_is_canonical_and_dependency_raw_hashes_are_current() -> None:
    raw = LOCK_PATH.read_bytes()
    lock = json.loads(raw)
    canonical = (
        json.dumps(lock, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    assert raw == canonical
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_LOCK_RAW_SHA256

    for binding in lock["dependency_bindings"]["raw_sha256"]:
        path = ROOT / binding["path"]
        assert path.is_file(), binding["path"]
        assert _sha256(path) == binding["sha256"], binding["path"]


def test_hofs_embedded_semantic_dependencies_and_identity_are_frozen() -> None:
    lock = _load_lock()
    semantic = lock["dependency_bindings"]["semantic_sha256"]
    final_path = (
        ROOT
        / "outputs"
        / "model_zoo_hofs_robustness_revision_r3_final_research_definition_freeze_r1_20260822"
        / "FINAL_RESEARCH_DEFINITION_LOCK.json"
    )
    final = json.loads(final_path.read_text(encoding="utf-8"))

    assert final["selected_model_id"] == "hofs_r3_global_log_shrink_w0500"
    assert final["selected_global_weight"] == 0.5
    assert (
        final["hofs_operand"]["underlying_r2_design_semantic_sha256"]
        == semantic["hofs_r2_design_lock"]
    )
    assert (
        final["hofs_operand"]["underlying_r2_numeric_source_closure_semantic_sha256"]
        == semantic["hofs_r2_numeric_source_closure"]
    )
    assert (
        final["hofs_operand"]["underlying_r2_prediction_rows_semantic_sha256"]
        == semantic["hofs_r2_prediction_rows"]
    )
    assert (
        final["hofs_operand"]["underlying_r2_source_manifest_semantic_sha256"]
        == semantic["hofs_r2_source_manifest"]
    )
    selected = final["selected_prediction_binding"]
    assert selected["row_count"] == 64_800
    assert (
        selected["selected_expected_log_pe_binary64_little_endian_sha256"]
        == semantic["hofs_selected_expected_log_pe_f64_le"]
    )
    assert (
        selected["selected_projection_csv_raw_sha256"]
        == semantic["hofs_selected_projection_csv_raw"]
    )
    assert (
        final["source_bindings"]["selection_decision_raw_sha256"]
        == semantic["hofs_selection_decision_raw"]
    )
    assert (
        selected["source_prediction_raw_sha256"]
        == semantic["hofs_source_prediction_raw"]
    )
    assert (
        final["v04_operand"]["source_predictions_raw_sha256"]
        == semantic["v04_source_predictions_raw"]
    )


def test_candidate_metadata_semantics_and_non_routing_prediction_contract() -> None:
    lock = _load_lock()
    candidates = lock["candidate_bindings"]
    qualification_lock = json.loads(
        (
            ROOT
            / "research"
            / "model_zoo"
            / "portfolio_governance_v1"
            / "QUALIFICATION_CERTIFICATION_DESIGN_LOCK.json"
        ).read_text(encoding="utf-8")
    )
    qualification_ids = {
        row["line_id"]: row["candidate_id"]
        for row in qualification_lock["candidate_order"]
        if row["line_id"] in {"PE-C1", "PE-C2", "PE-C3", "PE-C4"}
    }
    expected = {
        "PE-C1": (
            "bce_v1_b_causal_rolling_dispersion_budget",
            ["bounded_consensus", "causal_rolling_dispersion_budget"],
        ),
        "PE-C2": (
            "bce_v1_d_observable_state_confidence_shrinkage",
            ["bounded_consensus", "observable_state_confidence_shrinkage"],
        ),
        "PE-C3": (
            "bce_tournament_v1_fixed_alpha_040_directional_consensus",
            ["bounded_consensus", "fixed_directional_consensus_alpha040"],
        ),
    }

    for line, (candidate_id, tags) in expected.items():
        candidate = candidates[line]
        metadata = candidate["metadata_contract"]
        prediction = candidate["prediction_contract"]
        assert candidate["candidate_id"] == candidate_id
        assert candidate["candidate_id"] == qualification_ids[line]
        assert metadata["uncertainty"]["formula"] == "abs(ca-cb)/2"
        assert metadata["model_disagreement"]["formula"] == "abs(ca-cb)/2"
        assert metadata["uncertainty"]["units"] == "natural_log_pe"
        assert metadata["confidence"]["formula"] == "applied_alpha"
        assert metadata["confidence"]["disagreement_or_invalid_value"] == 0.0
        assert metadata["regime_state"] == "NON_ROUTING_ALL_REGIMES"
        assert metadata["specialist_tags"] == tags
        assert metadata["optional_fields"] == {
            "out_of_distribution_score": None,
            "state_uncertainty": None,
            "valuation_state_confidence": None,
        }
        assert prediction["metadata_fields_used_by_prediction"] == []
        assert prediction["routing"] is False
        assert prediction["expected_pe_formula"] == "exp(expected_log_pe)"

    assert "rolling(63,min_periods=10)" in candidates["PE-C1"]["prediction_contract"]["budget_formula"]
    assert candidates["PE-C2"]["prediction_contract"]["alpha_formula"] == (
        "observable_state_confidence on agreement; otherwise 0"
    )
    state_confidence = candidates["PE-C2"]["prediction_contract"][
        "observable_state_confidence_contract"
    ]
    assert state_confidence["component_weight"] == 0.25
    assert state_confidence["combination_formula"] == (
        "(eps_reliability*staleness_reliability*regime_clarity*innovation_stability)^0.25"
    )
    assert state_confidence["source_columns"] == [
        "ofs_v1_eps_confidence_01",
        "ofs_v1_eps_staleness_log1p",
        "ofs_v1_regime_entropy",
        "ofs_v1_regime_confidence",
        "ofs_v1_state_abs_innovation_lag1",
    ]
    assert state_confidence["components"] == {
        "eps_reliability": "ofs_v1_eps_confidence_01 identity when finite in [0,1]; otherwise 0",
        "innovation_stability": (
            "exp(-ofs_v1_state_abs_innovation_lag1) when finite and nonnegative; otherwise 0"
        ),
        "regime_clarity": (
            "0.5*((1-ofs_v1_regime_entropy)+clip((ofs_v1_regime_confidence-1/3)/(2/3),0,1)) "
            "when both inputs are finite in [0,1]; otherwise 0"
        ),
        "staleness_reliability": (
            "1-clip(ofs_v1_eps_staleness_log1p/log1p(252),0,1) when finite and nonnegative; "
            "otherwise 0"
        ),
    }
    assert "exactly 0" in state_confidence["invalid_to_zero"]
    assert candidates["PE-C3"]["prediction_contract"]["alpha_formula"] == (
        "0.40 on agreement; otherwise 0"
    )

    c4 = candidates["PE-C4"]
    metadata = c4["metadata_contract"]
    prediction = c4["prediction_contract"]
    assert c4["candidate_id"] == "hofs_v4_expected_pe"
    assert c4["candidate_id"] == qualification_ids["PE-C4"]
    assert prediction["score_candidate_id"] == "hofs_v4_expected_pe"
    assert (
        prediction["immutable_research_estimator_definition_id"]
        == "hofs_r3_global_log_shrink_w0500"
    )
    assert prediction["global_log_shrink_weight"] == 0.5
    assert c4["source_model_version"] is None
    assert "custody/service lineage" in c4["source_model_version_policy"]
    assert metadata["uncertainty"]["formula"] == "exp(hofs_v7_log_scale)"
    assert metadata["state_uncertainty"]["formula"] == "exp(hofs_v7_log_scale)"
    assert metadata["uncertainty"]["units"] == "natural_log_pe_scale"
    assert metadata["state_uncertainty"]["units"] == "natural_log_pe_scale"
    assert metadata["confidence"]["formula"] == "hofs_v7_tail_guard_weight"
    assert (
        metadata["valuation_state_confidence"]["formula"]
        == "hofs_v7_tail_guard_weight"
    )
    assert metadata["model_disagreement"] is None
    assert metadata["optional_fields"] == {"out_of_distribution_score": None}
    assert metadata["regime_state"] == "NON_ROUTING_ALL_REGIMES"
    assert metadata["specialist_tags"] == [
        "hierarchical_observable_state",
        "global_log_shrink_w0500",
    ]
    assert prediction["metadata_fields_used_by_prediction"] == []
    assert prediction["routing"] is False
    assert "no_refit" not in prediction
    assert "one strict-prefix fit per fold" in prediction["raw_estimator_fit_policy"]
    assert "before that fold's decision block" in prediction["raw_estimator_fit_policy"]
    assert prediction["robustness_wrapper_fit_policy"] == (
        "The fixed 0.5 log-space robustness wrapper performs no refit, calibration, or routing "
        "and cannot modify the raw estimator fit."
    )


def test_numeric_formulas_are_finite_consistent_and_metadata_inert() -> None:
    def bce(base: float, ca: float, cb: float, alpha: float) -> tuple[float, float]:
        agreement = (ca > 1e-12 and cb > 1e-12) or (ca < -1e-12 and cb < -1e-12)
        applied = alpha if agreement and all(map(math.isfinite, (base, ca, cb, alpha))) else 0.0
        raw_correction = 0.5 * (ca + cb) if agreement else 0.0
        expected_log_pe = math.log(base) + applied * raw_correction
        return expected_log_pe, math.exp(expected_log_pe)

    for ca, cb, alpha in ((0.2, 0.4, 0.6), (-0.3, -0.1, 0.4), (0.2, -0.1, 0.4)):
        expected_log_pe, expected_pe = bce(10.0, ca, cb, alpha)
        assert math.isfinite(abs(ca - cb) / 2.0)
        assert math.isclose(expected_pe, math.exp(expected_log_pe), rel_tol=0.0, abs_tol=0.0)
        changed_metadata = {"uncertainty": 999.0, "regime_state": "IGNORED"}
        assert changed_metadata and bce(10.0, ca, cb, alpha) == (expected_log_pe, expected_pe)

    v04_log = math.log(10.0)
    hofs_r2_log = math.log(14.0)
    hofs_v7_log_scale = math.log(0.25)
    tail_guard_weight = 0.75
    expected_log_pe = v04_log + 0.5 * (hofs_r2_log - v04_log)
    expected_pe = math.exp(expected_log_pe)
    assert math.isclose(expected_pe, math.sqrt(140.0), rel_tol=1e-15)
    assert math.exp(hofs_v7_log_scale) == 0.25
    assert 0.0 <= tail_guard_weight <= 1.0
    assert expected_pe == math.exp(expected_log_pe)


def test_scope_has_no_fresh_truth_scoring_or_portfolio_authority() -> None:
    lock = _load_lock()
    assert lock["status"] == "FROZEN_PRE_FRESH_METADATA_POLICY_ONLY"
    assert lock["common_identity_contract"]["exact_core_identity_count"] == 64_800
    row_contract = lock["row_validity_contract"]
    assert "finite" in row_contract["c1_c3"] and "[0,1]" in row_contract["c1_c3"]
    assert "finite" in row_contract["c4"] and "[0,1]" in row_contract["c4"]
    assert row_contract["expected_pe_identity"] == "expected_pe=exp(expected_log_pe)"
    assert row_contract["metadata_effect"].startswith("Metadata must never alter prediction")
    assert all(value is False for value in lock["authority"].values())
    assert all(value is None for key, value in lock["pending_pre_truth_bindings"].items() if key != "requirement")
    for key, value in _walk(lock):
        if key.endswith("authority") and isinstance(value, bool):
            assert value is False

    tracks = lock["implementation_tracks"]
    assert tracks["c1_c3"]["binding_revision"].startswith("PENDING_NEW_COMMON_C1_C3")
    assert tracks["c4"]["binding_revision"].startswith("PENDING_NEW_V12")
    assert tracks["c4"]["v11_disposition"].startswith("NO_GO")

    c5 = lock["c5_disposition"]
    assert c5["status"] == "RESEARCH_ONLY"
    assert c5["wave_status"] == "TERMINAL"
    assert c5["formal_custody_track"] == "SATURATED"
    assert c5["metadata_contract"] is None
    assert c5["qualification_score"] == "NOT_RUN_TERMINAL_CUSTODY_NO_GO"
    assert c5["scope"] == "PRIVATE_PROCESS_V8_CURRENT_IMPLEMENTATION_WAVE_ONLY"
    assert c5["broader_sequence_family_future_research_retained"] is True
