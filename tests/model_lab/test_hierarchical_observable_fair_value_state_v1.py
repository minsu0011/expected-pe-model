from __future__ import annotations

from dataclasses import fields, replace
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v1 import (
    ABLATIONS,
    CANDIDATE,
    CANDIDATE_ID,
    FUTURE_TOURNAMENT_GATES,
    MODEL_FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    PARENT_FEATURE_CONTRACT_SHA256,
    FrozenHierarchicalParameters,
    HierarchicalStateContractError,
    apply_frozen_parameters,
    build_hierarchical_state_features,
    contract_payload,
    contract_sha256,
    run_source_audit,
    validate_research_dgp_nuisance_groups,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v1.contracts import (
    CONTEXT_COLUMNS,
    REGIME_COLUMNS,
    STANDARDIZED_COLUMNS,
    STATE_DISPLACEMENT_COLUMN,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _source(rows: int = 280) -> pd.DataFrame:
    dates = pd.bdate_range("2023-01-02", periods=rows)
    records: list[dict[str, object]] = []
    for entity_number, entity_id in enumerate(("ENTITY_A", "ENTITY_B")):
        position = np.arange(rows, dtype=np.float64)
        probabilities = np.column_stack(
            (
                0.25 + 0.04 * np.sin(position / 17.0),
                0.45 + 0.03 * np.cos(position / 19.0),
                0.30 - 0.02 * np.sin(position / 23.0),
            )
        )
        probabilities /= probabilities.sum(axis=1, keepdims=True)
        for index, date in enumerate(dates):
            records.append(
                {
                    "seed": 2026082001,
                    "research_dgp_id": "DGP_SYNTHETIC_A",
                    "entity_id": entity_id,
                    "date": date,
                    "observed_pe": (
                        17.0
                        + 2.0 * entity_number
                        + 0.008 * index
                        + 0.35 * math.sin(index / 13.0)
                    ),
                    "eps_ttm": 2.0 + 0.2 * entity_number + 0.002 * index,
                    "eps_ttm_growth_126": 0.05 + 0.01 * math.sin(index / 31.0),
                    "eps_ttm_growth_252": 0.04 + 0.008 * math.cos(index / 37.0),
                    "eps_staleness_days": float(index % 90),
                    "eps_period_age_days": float(30 + index % 90),
                    "eps_confidence": 92.0 - float(index % 5),
                    "eps_disagreement": float(index % 7) / 100.0,
                    "eps_approximation_flag": float(index % 29 == 0),
                    "benchmark_return_21": 0.02 * math.sin(index / 11.0),
                    "benchmark_return_63": 0.04 * math.sin(index / 29.0),
                    "benchmark_return_252": 0.08 * math.sin(index / 71.0),
                    "benchmark_realized_vol_20": 0.16 + 0.01 * math.cos(index / 9.0),
                    "benchmark_realized_vol_63": 0.17 + 0.01 * math.cos(index / 21.0),
                    "benchmark_drawdown_252": -0.1 * abs(math.sin(index / 43.0)),
                    "benchmark_sma_50_vs_200": 0.03 * math.sin(index / 51.0),
                    "benchmark_trend_efficiency_63": abs(math.sin(index / 33.0)),
                    "p_bear": probabilities[index, 0],
                    "p_sideways": probabilities[index, 1],
                    "p_bull": probabilities[index, 2],
                }
            )
    return (
        pd.DataFrame.from_records(records)
        .sort_values(["date", "entity_id"], kind="mergesort")
        .reset_index(drop=True)
    )


def _parameters() -> FrozenHierarchicalParameters:
    return FrozenHierarchicalParameters(
        candidate_id=CANDIDATE_ID,
        design_contract_sha256=contract_sha256(),
        fit_end_date="2023-12-31",
        fit_row_count=504,
        robust_centers=(0.0,) * len(STANDARDIZED_COLUMNS),
        robust_scales=(1.0,) * len(STANDARDIZED_COLUMNS),
        global_intercept=0.0,
        global_persistence=0.20,
        global_innovation=0.10,
        context_coefficients=(0.0,) * len(CONTEXT_COLUMNS),
        regime_intercept_deviations=(-0.01, 0.0, 0.01),
        regime_persistence_deviations=(-0.05, 0.0, 0.05),
        regime_innovation_deviations=(-0.03, 0.0, 0.03),
        global_log_scale=math.log(0.08),
        regime_log_scale_deviations=(-0.10, 0.0, 0.10),
        research_dgp_effects_marginalized=True,
        training_target="log_observed_pe_proxy",
    )


def test_contract_has_one_candidate_fixed_ablations_gates_and_zero_authority() -> None:
    payload = contract_payload()
    assert CANDIDATE.candidate_id == CANDIDATE_ID
    assert len(ABLATIONS) == 4
    assert all(item.diagnostic_only and not item.promotion_eligible for item in ABLATIONS)
    assert len(MODEL_FEATURE_COLUMNS) == 17
    assert len(contract_sha256()) == 64
    assert payload["parent_feature_contract"]["sha256"] == PARENT_FEATURE_CONTRACT_SHA256
    assert payload["selection_policy"]["candidate_count"] == 1
    assert payload["selection_policy"]["hyperparameter_sweep"] is False
    assert not any(payload["authority"].values())
    assert FUTURE_TOURNAMENT_GATES["seed_dgp_wins_min"] == 30
    assert FUTURE_TOURNAMENT_GATES["dgp_mean_wins_min"] == 6
    assert FUTURE_TOURNAMENT_GATES["all_required"] is True


def test_feature_adapter_is_same_row_safe_future_safe_and_excludes_ids() -> None:
    source = _source()
    baseline = build_hierarchical_state_features(source).features
    assert tuple(baseline.columns) == MODEL_FEATURE_COLUMNS
    assert not {"seed", "research_dgp_id", "entity_id", "observed_pe"}.intersection(
        baseline.columns
    )

    entity_positions = np.flatnonzero(source["entity_id"].eq("ENTITY_A").to_numpy())
    pivot = int(entity_positions[220])
    next_row = int(entity_positions[221])
    changed = source.copy()
    changed.loc[pivot, "observed_pe"] *= 9.0
    result = build_hierarchical_state_features(changed).features
    pd.testing.assert_frame_equal(baseline.loc[[pivot]], result.loc[[pivot]], check_exact=True)
    assert not baseline.loc[[next_row]].equals(result.loc[[next_row]])

    cutoff = pd.Timestamp(source["date"].sort_values().unique()[180])
    future = source.copy()
    future.loc[future["date"] > cutoff, "observed_pe"] *= 7.0
    future.loc[future["date"] > cutoff, "benchmark_return_63"] = 5.0
    intervened = build_hierarchical_state_features(future).features
    prefix = source["date"] <= cutoff
    pd.testing.assert_frame_equal(baseline.loc[prefix], intervened.loc[prefix], check_exact=True)


def test_feature_adapter_is_order_invariant_and_dgp_label_blind() -> None:
    source = _source()
    baseline = build_hierarchical_state_features(source).features
    shuffled = source.sample(frac=1.0, random_state=1701)
    shuffled_result = build_hierarchical_state_features(shuffled).features
    pd.testing.assert_frame_equal(
        baseline.sort_index(),
        shuffled_result.sort_index(),
        check_exact=True,
    )

    relabeled = source.copy()
    relabeled["research_dgp_id"] = np.where(
        np.arange(len(relabeled)) % 2 == 0,
        "ARBITRARY_X",
        "ARBITRARY_Y",
    )
    relabeled_result = build_hierarchical_state_features(relabeled).features
    pd.testing.assert_frame_equal(baseline, relabeled_result, check_exact=True)


def test_soft_regime_fallback_and_training_only_dgp_groups() -> None:
    source = _source()
    attacked = source.copy()
    attacked.loc[attacked.index[:5], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    result = build_hierarchical_state_features(attacked).features
    probabilities = result.loc[result.index[:5], list(REGIME_COLUMNS)]
    np.testing.assert_allclose(probabilities.to_numpy(), np.full((5, 3), 1.0 / 3.0))

    labels = validate_research_dgp_nuisance_groups(
        source["research_dgp_id"], expected_rows=len(source)
    )
    assert len(labels) == len(source)
    with pytest.raises(HierarchicalStateContractError, match="length"):
        validate_research_dgp_nuisance_groups(labels[:-1], expected_rows=len(source))


def test_fit_free_adapter_emits_fixed_tail_aware_schema_from_manual_parameters() -> None:
    source = _source()
    state = build_hierarchical_state_features(source).features
    final_date = source["date"].max()
    mask = source["date"].eq(final_date)
    features = state.loc[mask].copy()
    features.loc[features.index[0], STATE_DISPLACEMENT_COLUMN] = 100.0
    output = apply_frozen_parameters(
        features,
        _parameters(),
        decision_dates=source.loc[mask, "date"],
    )
    assert tuple(output.values.columns) == OUTPUT_COLUMNS
    assert output.input_rows == 2
    assert output.parameter_sha256 == _parameters().sha256()
    assert output.values["hofs_v1_pe_p10"].le(output.values["hofs_v1_expected_pe"]).all()
    assert output.values["hofs_v1_expected_pe"].le(output.values["hofs_v1_pe_p90"]).all()
    assert output.values["hofs_v1_tail_guard_weight"].between(0.0, 1.0).all()
    assert output.values.loc[features.index[0], "hofs_v1_tail_guard_weight"] < 0.1
    assert not {item.name for item in fields(FrozenHierarchicalParameters)}.intersection(
        {"dgp_id", "research_dgp_id", "dgp_effects", "seed"}
    )

    with pytest.raises(HierarchicalStateContractError, match="strictly before"):
        apply_frozen_parameters(
            features,
            replace(_parameters(), fit_end_date=str(final_date.date())),
            decision_dates=source.loc[mask, "date"],
        )


def test_parameter_bundle_fails_closed_on_domain_or_constraint_drift() -> None:
    parameters = _parameters()
    with pytest.raises(HierarchicalStateContractError, match="marginalized"):
        replace(parameters, research_dgp_effects_marginalized=False)
    with pytest.raises(HierarchicalStateContractError, match="sum to zero"):
        replace(parameters, regime_persistence_deviations=(0.0, 0.0, 0.1))
    with pytest.raises(HierarchicalStateContractError, match="fixed bounds"):
        replace(parameters, global_persistence=0.94)


def test_exact_source_audit_passes_without_fit_io_or_frozen_imports() -> None:
    audit = run_source_audit(PROJECT_ROOT)
    assert audit.passed
    assert audit.status == "PASS_SCORE_FREE_SOURCE_AUDIT"
    assert audit.forbidden_import_hits == ()
    assert audit.frozen_prediction_package_import_hits == ()
    assert audit.runtime_io_hits == ()
    assert audit.estimator_fit_call_hits == ()
    assert audit.truth_files_opened == 0
    assert audit.vault_files_opened == 0
    assert audit.prediction_files_opened == 0
    assert audit.scores_computed == 0
