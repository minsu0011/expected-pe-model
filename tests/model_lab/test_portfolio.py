from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.portfolio_governance_v1.contracts import (
    EXPECTED_PE_TRUTH_COLUMNS,
    PE_PREDICTION_REQUIRED_COLUMNS,
    PORTFOLIO_DISPOSITIONS,
    PortfolioAssessment,
    PortfolioContractError,
    PortfolioMetrics,
    append_portfolio_assessment,
    latest_portfolio_assessments,
    load_portfolio_history,
    pe_prediction_artifact_json_schema,
    pe_truth_artifact_json_schema,
    portfolio_registry_json_schema,
    validate_pe_prediction_artifact,
    validate_portfolio_history,
    validate_seven_column_truth_frame,
    write_portfolio_history,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _metrics(**changes: object) -> PortfolioMetrics:
    values: dict[str, object] = {
        "n_rows": 100,
        "n_seeds": 5,
        "n_dgps": 4,
        "worst_seed": 7573,
        "worst_dgp": "jump_recovery",
        "pooled_mae": 0.12,
        "pooled_rmse": 0.18,
        "mae_gain_pct_vs_champion": 0.7,
        "rmse_gain_pct_vs_champion": 0.6,
        "seed_wins": 4,
        "seed_total": 5,
        "worst_seed_dgp_harm_pct": 2.0,
        "worst_dgp_mean_harm_pct": 0.8,
        "p95_absolute_error_harm_pct": -0.1,
        "extreme_absolute_error_harm_pct": -0.2,
        "signed_error_corr_vs_champion": 0.5,
        "absolute_error_corr_vs_champion": 0.4,
        "prediction_corr_vs_champion": 0.8,
        "median_abs_log_prediction_disagreement": 0.03,
        "oracle_pair_mae_gain_pct": 2.2,
        "oracle_pair_rmse_gain_pct": 2.0,
        "jump_peak_harm_pct": -0.3,
        "jump_recovery_sessions": 2.0,
        "bootstrap_mae_gain_lower5_pct": 0.1,
        "runtime_seconds": 10.0,
        "peak_rss_gib": 1.2,
        "peak_gpu_memory_gib": 0.0,
        "slice_metrics": {"dgp_1": {"mae": 0.11, "rows": 25}},
    }
    values.update(changes)
    return PortfolioMetrics(**values)


def _research_assessment(
    *,
    pe_model_id: str = "candidate",
    revision: int = 0,
) -> PortfolioAssessment:
    return PortfolioAssessment(
        pe_model_id=pe_model_id,
        family="unit",
        variant="base",
        version="v1",
        definition_sha256=SHA_A,
        source_sha256=SHA_B,
        estimand="causal expected fair P/E",
        target="log_observed_pe_pit_proxy",
        feature_set="unit_pit_features_v1",
        feature_set_sha256=SHA_C,
        training_contract_sha256=SHA_D,
        prediction_contract_sha256=SHA_E,
        external_data=(),
        uses_same_row_price=False,
        uses_same_row_observed_pe=False,
        pit_safe=True,
        causal=True,
        deployable=True,
        assessment_revision=revision,
        assessed_at_utc="2026-08-21T12:00:00Z",
        champion_model_id="v04_expected_pe",
        disposition="RESEARCH_ONLY",
        portfolio_admission_status="CANDIDATE",
        champion_gate_status="NOT_EVALUATED",
        evidence_scope="DESIGN_ONLY",
        scoreable=False,
        qualification_status="NOT_OPENED",
        heldout_status="NOT_OPENED",
        survivor_frozen=False,
        causal_audit_status="UNTESTED",
        pit_audit_status="UNTESTED",
        deployment_audit_status="UNTESTED",
        source_audit_status="UNTESTED",
        specialist_scope=None,
        specialist_tags=(),
        prediction_artifact_sha256=None,
        evaluator_sha256=None,
        common_mask_sha256=None,
        truth_schema_sha256=None,
        external_reference=False,
        paper=None,
        repository=None,
        package=None,
        license=None,
        external_modifications=None,
        metrics=PortfolioMetrics(),
        rationale="Design-only candidate; no performance claim.",
        next_action="Run fresh qualification after custody audit.",
    )


def _qualified_assessment(
    *,
    pe_model_id: str = "candidate",
    disposition: str = "PE_PORTFOLIO_CORE",
    revision: int = 0,
    **changes: object,
) -> PortfolioAssessment:
    values: dict[str, object] = {
        "disposition": disposition,
        "portfolio_admission_status": "ADMITTED",
        "champion_gate_status": "NOT_ELIGIBLE",
        "evidence_scope": "QUALIFICATION",
        "scoreable": True,
        "qualification_status": "PASS",
        "survivor_frozen": True,
        "causal_audit_status": "PASS",
        "pit_audit_status": "PASS",
        "deployment_audit_status": "PASS",
        "source_audit_status": "PASS",
        "prediction_artifact_sha256": SHA_B,
        "evaluator_sha256": SHA_C,
        "common_mask_sha256": SHA_D,
        "truth_schema_sha256": SHA_E,
        "metrics": _metrics(),
        "rationale": "Fresh qualification supports a deployable portfolio role.",
        "next_action": "Monitor complementary value without champion promotion.",
    }
    values.update(changes)
    return replace(_research_assessment(pe_model_id=pe_model_id, revision=revision), **values)


def _champion(*, pe_model_id: str = "candidate", revision: int = 0) -> PortfolioAssessment:
    return _qualified_assessment(
        pe_model_id=pe_model_id,
        disposition="CHAMPION",
        revision=revision,
        champion_model_id=pe_model_id,
        champion_gate_status="PASS",
        evidence_scope="HELDOUT",
        heldout_status="PASS",
        rationale="All frozen heldout champion gates passed.",
    )


def _prediction_frame() -> pd.DataFrame:
    expected = np.array([10.0, 20.0])
    return pd.DataFrame(
        {
            "date": ["2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z"],
            "ticker": ["AAA", "AAA"],
            "pe_model_id": ["candidate", "candidate"],
            "expected_pe": expected,
            "expected_log_pe": np.log(expected),
            "uncertainty": [0.2, 0.3],
            "confidence": [0.8, 0.7],
            "regime_state": ["bull", "sideways"],
            "specialist_tags": [["global"], ["global"]],
            "prediction_valid": [True, True],
            "pit_valid": [True, True],
            "source_model_version": ["v1", "v1"],
        }
    )


def _truth_frame() -> pd.DataFrame:
    true_pe = np.array([10.0, 20.0])
    return pd.DataFrame(
        {
            "date": ["2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z"],
            "true_fair_pe": true_pe,
            "true_log_fair_pe": np.log(true_pe),
            "true_economic_eps_contemporaneous": [2.0, 2.1],
            "true_pit_eps": [1.9, 2.0],
            "true_observed_pe": [10.5, 19.5],
            "true_expected_pe_eligible": [True, True],
        },
        columns=EXPECTED_PE_TRUTH_COLUMNS,
    )


def test_new_direction_vocabulary_is_closed_and_complete() -> None:
    assert set(PORTFOLIO_DISPOSITIONS) == {
        "CHAMPION",
        "FORMAL_CHALLENGER",
        "PE_PORTFOLIO_CORE",
        "PE_SPECIALIST",
        "ENSEMBLE_COMPONENT",
        "DIVERSITY_COMPONENT",
        "RESEARCH_PROMISING",
        "RESEARCH_ONLY",
        "SATURATED",
        "REJECTED",
        "BROKEN",
    }


def test_champion_and_portfolio_admission_are_independent() -> None:
    core = _qualified_assessment()
    assert core.portfolio_admission_status == "ADMITTED"
    assert core.champion_gate_status == "NOT_ELIGIBLE"
    with pytest.raises(PortfolioContractError, match="only CHAMPION"):
        replace(core, champion_gate_status="PASS")
    with pytest.raises(PortfolioContractError, match="passing heldout champion gate"):
        replace(core, disposition="CHAMPION", champion_model_id=core.pe_model_id)
    with pytest.raises(PortfolioContractError, match="PIT-safe, causal, and deployable"):
        replace(core, deployable=False)


def test_formal_challenger_and_specialist_require_their_distinct_evidence() -> None:
    challenger = _qualified_assessment(
        disposition="FORMAL_CHALLENGER",
        portfolio_admission_status="CANDIDATE",
        champion_gate_status="NOT_OPENED",
    )
    assert challenger.survivor_frozen
    with pytest.raises(PortfolioContractError, match="frozen, audited"):
        replace(challenger, survivor_frozen=False)
    with pytest.raises(PortfolioContractError, match="specialist_scope"):
        _qualified_assessment(disposition="PE_SPECIALIST")
    specialist = _qualified_assessment(
        disposition="PE_SPECIALIST",
        specialist_scope="jump_recovery",
        specialist_tags=("jump_recovery",),
        qualification_status="FAIL",
    )
    assert specialist.specialist_scope == "jump_recovery"
    assert specialist.qualification_status == "FAIL"


def test_core_requires_performance_pass_but_specialist_components_may_fail_it() -> None:
    with pytest.raises(PortfolioContractError, match="passing qualification performance"):
        _qualified_assessment(qualification_status="FAIL")
    diversity = _qualified_assessment(
        disposition="DIVERSITY_COMPONENT",
        qualification_status="FAIL",
    )
    ensemble = _qualified_assessment(
        disposition="ENSEMBLE_COMPONENT",
        qualification_status="FAIL",
    )
    assert diversity.portfolio_admission_status == "ADMITTED"
    assert ensemble.portfolio_admission_status == "ADMITTED"


def test_diversity_component_requires_measured_complementarity() -> None:
    diversity = _qualified_assessment(disposition="DIVERSITY_COMPONENT")
    assert diversity.metrics.oracle_pair_mae_gain_pct == 2.2
    with pytest.raises(PortfolioContractError, match="error-correlation"):
        replace(
            diversity,
            metrics=replace(diversity.metrics, signed_error_corr_vs_champion=None),
        )


def test_scoreable_claims_require_detached_evidence_hashes_and_metrics() -> None:
    with pytest.raises(PortfolioContractError, match="detached-evaluation hashes"):
        replace(
            _research_assessment(),
            scoreable=True,
            evidence_scope="REUSED_SEEDS",
        )
    with pytest.raises(PortfolioContractError, match="cannot claim evaluator"):
        replace(_research_assessment(), evaluator_sha256=SHA_B)
    with pytest.raises(PortfolioContractError, match="completed qualification_status"):
        replace(
            _qualified_assessment(),
            qualification_status="NOT_OPENED",
        )


def test_research_and_external_reference_claims_fail_closed() -> None:
    with pytest.raises(PortfolioContractError, match="cannot claim portfolio admission"):
        replace(_research_assessment(), portfolio_admission_status="ADMITTED")
    with pytest.raises(PortfolioContractError, match="source reference and license"):
        replace(_research_assessment(), external_reference=True)
    external = replace(
        _research_assessment(),
        external_reference=True,
        repository="https://example.invalid/official-repository",
        license="BSD-3-Clause",
        external_modifications="No code reuse; hypothesis reference only.",
    )
    assert external.external_reference is True


def test_portfolio_metrics_reject_impossible_counts_and_correlations() -> None:
    with pytest.raises(PortfolioContractError, match="cannot exceed"):
        _metrics(seed_wins=6)
    with pytest.raises(PortfolioContractError, match=r"\[-1, 1\]"):
        _metrics(absolute_error_corr_vs_champion=1.01)
    with pytest.raises(PortfolioContractError, match="finite"):
        _metrics(pooled_mae=float("nan"))


def test_prediction_artifact_contract_accepts_standard_truth_free_rows() -> None:
    frame = _prediction_frame()
    validate_pe_prediction_artifact(frame)
    assert tuple(pe_prediction_artifact_json_schema()["required"]) == (
        PE_PREDICTION_REQUIRED_COLUMNS
    )


def test_invalid_prediction_rows_must_null_point_predictions() -> None:
    frame = _prediction_frame()
    frame.loc[1, "prediction_valid"] = False
    with pytest.raises(PortfolioContractError, match="invalid predictions must null"):
        validate_pe_prediction_artifact(frame)
    frame.loc[1, ["expected_pe", "expected_log_pe"]] = np.nan
    validate_pe_prediction_artifact(frame)


def test_prediction_numeric_columns_reject_stringly_typed_values() -> None:
    frame = _prediction_frame().astype({"confidence": "string"})
    with pytest.raises(PortfolioContractError, match="numeric dtype"):
        validate_pe_prediction_artifact(frame)


def test_detached_truth_contract_is_exactly_seven_ordered_columns() -> None:
    frame = _truth_frame()
    validate_seven_column_truth_frame(frame)
    assert tuple(frame.columns) == EXPECTED_PE_TRUTH_COLUMNS
    with pytest.raises(PortfolioContractError, match="exact ordered seven-column"):
        validate_seven_column_truth_frame(frame[list(reversed(frame.columns))])
    with pytest.raises(PortfolioContractError, match="exact ordered seven-column"):
        validate_seven_column_truth_frame(frame.assign(obsolete_truth_column=1.0))


def test_detached_truth_contract_rejects_invalid_eligible_log_truth() -> None:
    frame = _truth_frame()
    frame.loc[1, "true_log_fair_pe"] = 0.0
    with pytest.raises(PortfolioContractError, match=r"log\(true_fair_pe\)"):
        validate_seven_column_truth_frame(frame)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda frame: frame.assign(true_fair_pe=10.0), "evaluation truth"),
        (lambda frame: frame.assign(pit_valid=False), "must be PIT-safe"),
        (lambda frame: frame.assign(expected_log_pe=0.0), r"log\(expected_pe\)"),
        (lambda frame: frame.assign(confidence=1.1), r"\[0, 1\]"),
        (lambda frame: frame.assign(date="not-a-date"), "parseable timestamps"),
    ],
)
def test_prediction_artifact_contract_fails_closed(mutation: object, match: str) -> None:
    with pytest.raises(PortfolioContractError, match=match):
        validate_pe_prediction_artifact(mutation(_prediction_frame()))  # type: ignore[operator]


def test_portfolio_history_is_append_only_revisioned_and_terminal(tmp_path: Path) -> None:
    path = tmp_path / "portfolio.json"
    initial = _research_assessment()
    admitted = _qualified_assessment(revision=1)
    first_hash = write_portfolio_history(path, [initial])
    assert first_hash != append_portfolio_assessment(path, admitted)
    assert load_portfolio_history(path) == (initial, admitted)
    assert latest_portfolio_assessments((initial, admitted)) == (admitted,)
    before = path.read_bytes()
    append_portfolio_assessment(path, admitted)
    assert path.read_bytes() == before

    rejected = replace(
        _research_assessment(pe_model_id="terminal"),
        disposition="REJECTED",
        portfolio_admission_status="REJECTED",
    )
    reversal = replace(
        _qualified_assessment(pe_model_id="terminal", revision=1),
        definition_sha256=rejected.definition_sha256,
    )
    with pytest.raises(PortfolioContractError, match="illegal disposition transition"):
        validate_portfolio_history((rejected, reversal))

    with pytest.raises(PortfolioContractError, match="definition fields are immutable"):
        validate_portfolio_history((initial, replace(admitted, feature_set="changed")))


def test_portfolio_history_rejects_multiple_current_champions() -> None:
    with pytest.raises(PortfolioContractError, match="only one current CHAMPION"):
        validate_portfolio_history((_champion(pe_model_id="first"), _champion(pe_model_id="second")))


def test_portfolio_schema_carries_all_decision_and_metric_axes() -> None:
    schema = portfolio_registry_json_schema()
    item = schema["properties"]["records"]["items"]
    assert item["properties"]["disposition"]["enum"] == list(PORTFOLIO_DISPOSITIONS)
    metric_fields = set(item["properties"]["metrics"]["properties"])
    assert {
        "pooled_mae",
        "pooled_rmse",
        "signed_error_corr_vs_champion",
        "absolute_error_corr_vs_champion",
        "oracle_pair_mae_gain_pct",
        "jump_recovery_sessions",
        "peak_gpu_memory_gib",
        "worst_seed",
        "worst_dgp",
    }.issubset(metric_fields)
    required = set(item["required"])
    assert {
        "source_sha256",
        "estimand",
        "target",
        "feature_set",
        "feature_set_sha256",
        "training_contract_sha256",
        "prediction_contract_sha256",
        "external_data",
        "uses_same_row_price",
        "uses_same_row_observed_pe",
        "pit_safe",
        "causal",
        "deployable",
        "specialist_tags",
    }.issubset(required)


def test_checked_in_portfolio_registry_starts_empty_without_rewriting_legacy_registry() -> None:
    project_root = Path(__file__).resolve().parents[2]
    portfolio_path = (
        project_root
        / "research"
        / "model_zoo"
        / "portfolio_governance_v1"
        / "pe_model_portfolio.json"
    )
    legacy_path = project_root / "research" / "model_zoo" / "model_registry.json"
    assert load_portfolio_history(portfolio_path) == ()
    assert legacy_path.exists()


def test_checked_in_portfolio_schemas_match_code_generated_contracts() -> None:
    root = Path(__file__).resolve().parents[2] / "research" / "model_zoo"
    root = root / "portfolio_governance_v1"
    assert json.loads((root / "pe_model_portfolio.schema.json").read_text(encoding="utf-8")) == (
        portfolio_registry_json_schema()
    )
    assert json.loads(
        (root / "pe_prediction_artifact.schema.json").read_text(encoding="utf-8")
    ) == pe_prediction_artifact_json_schema()
    assert json.loads((root / "pe_truth_artifact.schema.json").read_text(encoding="utf-8")) == (
        pe_truth_artifact_json_schema()
    )
