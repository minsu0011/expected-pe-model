from __future__ import annotations

from dataclasses import fields
import hashlib
import inspect
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v2 import (
    MODEL_FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    PARENT_RUNTIME_SOURCE_SHA256,
    V1_INDEPENDENT_AUDIT_BINDING,
    DecisionBatchV2,
    FrozenHierarchicalParametersV2,
    HierarchicalStateV2ContractError,
    apply_frozen_parameters_v2,
    build_decision_batch_v2,
    build_frozen_parameter_bundle_bytes,
    build_hierarchical_state_features_v2,
    contract_payload,
    contract_sha256,
    fit_chronological_prefix_v2,
    load_frozen_parameter_bundle,
    run_frozen_decision_session_v2,
    run_source_audit_v2,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v2.contracts import (
    INNOVATION_BOUNDS,
    PERSISTENCE_BOUNDS,
    REGIME_COLUMNS,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _source(rows: int = 330) -> pd.DataFrame:
    dates = pd.bdate_range("2022-01-03", periods=rows)
    records: list[dict[str, object]] = []
    for entity_number, entity_id in enumerate(("ENTITY_A", "ENTITY_B")):
        position = np.arange(rows, dtype=np.float64)
        probabilities = np.column_stack(
            (
                0.24 + 0.05 * np.sin(position / 17.0 + entity_number),
                0.44 + 0.04 * np.cos(position / 19.0),
                0.32 - 0.03 * np.sin(position / 23.0),
            )
        )
        probabilities /= probabilities.sum(axis=1, keepdims=True)
        for index, date in enumerate(dates):
            records.append(
                {
                    "seed": 2026082101,
                    "research_dgp_id": "DGP_X" if index % 4 < 2 else "DGP_Y",
                    "entity_id": entity_id,
                    "date": date,
                    "observed_pe": (
                        16.5
                        + 1.6 * entity_number
                        + 0.006 * index
                        + 0.32 * math.sin(index / 13.0)
                        + (0.08 if index % 4 < 2 else -0.08)
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


@pytest.fixture(scope="module")
def fitted_case():
    source = _source()
    decision_date = pd.Timestamp(source["date"].max())
    capability = fit_chronological_prefix_v2(
        source,
        future_decision_date=decision_date,
        observed_pe=source["observed_pe"],
        research_dgp_groups=source["research_dgp_id"],
    )
    return source, decision_date, capability


def test_contract_binds_v1_audit_and_complete_parent_runtime_closure() -> None:
    payload = contract_payload()
    assert len(MODEL_FEATURE_COLUMNS) == 17
    assert len(contract_sha256()) == 64
    assert payload["selection_policy"] == {
        "candidate_count": 1,
        "hyperparameter_sweep": False,
        "ranking": "single_candidate_no_adaptive_selection",
    }
    assert V1_INDEPENDENT_AUDIT_BINDING["raw_sha256"] == (
        "406ede52119db452531ddbef1d77fc0962947c1112f461e77b171798ed541a93"
    )
    assert set(PARENT_RUNTIME_SOURCE_SHA256) == {
        "research/model_zoo/observable_fair_value_state_v1/__init__.py",
        "research/model_zoo/observable_fair_value_state_v1/audit.py",
        "research/model_zoo/observable_fair_value_state_v1/contracts.py",
        "research/model_zoo/observable_fair_value_state_v1/features.py",
    }
    assert payload["authority"]["real_model_fit"] is False
    assert payload["authority"]["research_or_production_prediction"] is False


def test_features_are_group_injection_blind_prefix_safe_and_same_row_safe() -> None:
    source = _source()
    baseline = build_hierarchical_state_features_v2(source)
    assert tuple(baseline.features.columns) == MODEL_FEATURE_COLUMNS
    assert baseline.parent_group_columns == ("entity_id",)
    assert "group_columns" not in inspect.signature(
        build_hierarchical_state_features_v2
    ).parameters

    injected = source.copy()
    injected["research_dgp_id"] = np.where(
        np.arange(len(injected)) % 2,
        "ATTACK_A",
        "ATTACK_B",
    )
    injected["seed"] = np.arange(len(injected), dtype=np.int64)
    result = build_hierarchical_state_features_v2(injected)
    pd.testing.assert_frame_equal(baseline.features, result.features, check_exact=True)

    entity_positions = np.flatnonzero(source["entity_id"].eq("ENTITY_A").to_numpy())
    pivot = int(entity_positions[250])
    next_row = int(entity_positions[251])
    same_row_changed = source.copy()
    same_row_changed.loc[pivot, "observed_pe"] *= 8.0
    changed_state = build_hierarchical_state_features_v2(same_row_changed)
    pd.testing.assert_frame_equal(
        baseline.features.loc[[pivot]],
        changed_state.features.loc[[pivot]],
        check_exact=True,
    )
    assert not baseline.features.loc[[next_row]].equals(changed_state.features.loc[[next_row]])

    cutoff = pd.Timestamp(source["date"].sort_values().unique()[220])
    future = source.copy()
    future.loc[future["date"] > cutoff, "observed_pe"] *= 6.0
    future.loc[future["date"] > cutoff, "benchmark_return_63"] = 7.0
    future.loc[future["date"] > cutoff, "research_dgp_id"] = "FUTURE_ATTACK"
    future_state = build_hierarchical_state_features_v2(future)
    prefix = source["date"] <= cutoff
    pd.testing.assert_frame_equal(
        baseline.features.loc[prefix],
        future_state.features.loc[prefix],
        check_exact=True,
    )


def test_feature_order_invariance_regime_receipts_and_identity_failures() -> None:
    source = _source()
    baseline = build_hierarchical_state_features_v2(source)
    shuffled = source.sample(frac=1.0, random_state=1701)
    shuffled_state = build_hierarchical_state_features_v2(shuffled)
    pd.testing.assert_frame_equal(
        baseline.features.sort_index(),
        shuffled_state.features.sort_index(),
        check_exact=True,
    )

    normalized = source.copy()
    normalized.loc[normalized.index[:5], ["p_bear", "p_sideways", "p_bull"]] *= 2.0
    normalized_state = build_hierarchical_state_features_v2(normalized)
    assert normalized_state.regime_renormalized_count == 5
    assert normalized_state.regime_fallback_count == 0

    fallback = source.copy()
    fallback.loc[fallback.index[:3], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    fallback_state = build_hierarchical_state_features_v2(fallback)
    assert fallback_state.regime_fallback_count == 3
    np.testing.assert_allclose(
        fallback_state.features.loc[fallback.index[:3], list(REGIME_COLUMNS)],
        np.full((3, 3), 1.0 / 3.0),
    )
    overflow = source.copy()
    overflow.loc[overflow.index[:10], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    with pytest.raises(HierarchicalStateV2ContractError, match="fallback limit"):
        build_hierarchical_state_features_v2(overflow)

    duplicate = source.copy()
    entity_rows = duplicate.index[duplicate["entity_id"].eq("ENTITY_A")]
    duplicate.loc[entity_rows[1], "date"] = duplicate.loc[entity_rows[0], "date"]
    with pytest.raises(HierarchicalStateV2ContractError, match="unique"):
        build_hierarchical_state_features_v2(duplicate)


def test_robust_fit_converges_is_constrained_and_seals_provenance(fitted_case) -> None:
    _, decision_date, capability = fitted_case
    fit = capability.fit
    parameters = fit.parameters
    receipt = fit.fit_receipt
    assert fit.resource_receipt.thread_environment == (
        ("OMP_NUM_THREADS", "1"),
        ("OPENBLAS_NUM_THREADS", "1"),
        ("MKL_NUM_THREADS", "1"),
        ("NUMEXPR_NUM_THREADS", "1"),
    )
    assert receipt.irls_converged
    assert receipt.final_kkt_violation <= 1e-10
    assert receipt.fit_row_count >= 504
    assert pd.Timestamp(parameters.fit_end_date) < decision_date
    assert parameters.convergence_receipt_sha256 == receipt.sha256()
    assert parameters.resource_receipt_sha256 == fit.resource_receipt.sha256()
    assert parameters.research_dgp_effects_marginalized
    for value in (
        parameters.global_persistence,
        *(parameters.global_persistence + item for item in parameters.regime_persistence_deviations),
    ):
        assert PERSISTENCE_BOUNDS[0] <= value <= PERSISTENCE_BOUNDS[1]
    for value in (
        parameters.global_innovation,
        *(parameters.global_innovation + item for item in parameters.regime_innovation_deviations),
    ):
        assert INNOVATION_BOUNDS[0] <= value <= INNOVATION_BOUNDS[1]
    deployable_fields = {item.name for item in fields(FrozenHierarchicalParametersV2)}
    assert not deployable_fields.intersection(
        {"dgp_id", "research_dgp_id", "seed", "dgp_effects", "dgp_scale_effects"}
    )


def test_dgp_bijective_relabel_and_row_shuffle_are_bit_reproducible(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    relabeled = source["research_dgp_id"].map({"DGP_X": "ZZZ", "DGP_Y": "AAA"})
    relabeled_fit = fit_chronological_prefix_v2(
        source,
        future_decision_date=decision_date,
        observed_pe=source["observed_pe"],
        research_dgp_groups=relabeled,
    )
    assert relabeled_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert relabeled_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    shuffled = source.sample(frac=1.0, random_state=901)
    shuffled_fit = fit_chronological_prefix_v2(
        shuffled,
        future_decision_date=decision_date,
        observed_pe=shuffled["observed_pe"],
        research_dgp_groups=shuffled["research_dgp_id"],
    )
    assert shuffled_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert shuffled_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()


def test_decision_runner_is_identity_bound_future_and_same_row_safe(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v2(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()
    batch = build_decision_batch_v2(state, requested)
    output = apply_frozen_parameters_v2(batch, capability.fit.parameters)
    assert tuple(output.values.columns) == OUTPUT_COLUMNS
    assert output.identities.equals(requested)
    assert output.values[OUTPUT_COLUMNS[1]].le(output.values[OUTPUT_COLUMNS[0]]).all()
    assert output.values[OUTPUT_COLUMNS[0]].le(output.values[OUTPUT_COLUMNS[2]]).all()
    assert output.values[OUTPUT_COLUMNS[4]].between(0.0, 1.0).all()

    attacked = source.copy()
    attacked.loc[attacked["date"].eq(decision_date), "observed_pe"] *= 50.0
    attacked.loc[attacked["date"].eq(decision_date), "research_dgp_id"] = "ATTACK"
    attacked_output = run_frozen_decision_session_v2(
        attacked,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    pd.testing.assert_frame_equal(output.values, attacked_output.values, check_exact=True)

    misaligned = requested.copy()
    misaligned.index = misaligned.index[::-1]
    with pytest.raises(HierarchicalStateV2ContractError, match="feature index"):
        DecisionBatchV2(features=batch.features, identities=misaligned)


def test_frozen_bundle_round_trip_and_exact_universe_gate(tmp_path: Path, fitted_case) -> None:
    _, _, capability = fitted_case
    payloads = build_frozen_parameter_bundle_bytes(capability.fit)
    assert tuple(sorted(payloads)) == (
        "CHECKSUMS.sha256",
        "FIT_RECEIPT.json",
        "MANIFEST.json",
        "PARAMETERS.json",
        "RESOURCE_RECEIPT.json",
    )
    good = tmp_path / "good_bundle"
    good.mkdir()
    for name, content in payloads.items():
        (good / name).write_bytes(content)
    checksums_sha256 = hashlib.sha256(payloads["CHECKSUMS.sha256"]).hexdigest()
    loaded = load_frozen_parameter_bundle(
        good,
        expected_checksums_raw_sha256=checksums_sha256,
    )
    assert loaded.parameters.sha256() == capability.fit.parameters.sha256()
    assert loaded.fit_receipt.sha256() == capability.fit.fit_receipt.sha256()

    extra = tmp_path / "extra_file_bundle"
    extra.mkdir()
    for name, content in payloads.items():
        (extra / name).write_bytes(content)
    (extra / "UNDECLARED.json").write_bytes(b"{}\n")
    with pytest.raises(HierarchicalStateV2ContractError, match="file universe"):
        load_frozen_parameter_bundle(
            extra,
            expected_checksums_raw_sha256=checksums_sha256,
        )


def test_chronological_prefix_excludes_same_session_target_and_future_rows(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    attacked = source.copy()
    attacked.loc[attacked["date"] >= decision_date, "observed_pe"] *= 100.0
    attacked.loc[attacked["date"] >= decision_date, "research_dgp_id"] = "FUTURE_ONLY"
    attacked_fit = fit_chronological_prefix_v2(
        attacked,
        future_decision_date=decision_date,
        observed_pe=attacked["observed_pe"],
        research_dgp_groups=attacked["research_dgp_id"],
    )
    assert attacked_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert attacked_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    with pytest.raises(HierarchicalStateV2ContractError, match="index-bound"):
        fit_chronological_prefix_v2(
            source,
            future_decision_date=decision_date,
            observed_pe=source["observed_pe"].reset_index(drop=True).rename(index=lambda x: x + 1),
            research_dgp_groups=source["research_dgp_id"],
        )


def test_static_source_isolation_and_bound_public_evidence() -> None:
    audit = run_source_audit_v2(PROJECT_ROOT)
    assert audit.passed
    assert audit.status == "PASS_HOFS_V2_SCORE_FREE_SOURCE_ISOLATION"
    assert audit.forbidden_import_hits == ()
    assert audit.frozen_prediction_import_hits == ()
    assert audit.forbidden_call_hits == ()
    assert audit.unexpected_runtime_io_hits == ()
    assert audit.protected_payload_open_count == 0
    assert audit.frozen_prediction_open_count == 0
    assert audit.score_call_count == 0
    assert audit.registry_mutation_count == 0
    assert audit.v1_audit_raw_sha256 == V1_INDEPENDENT_AUDIT_BINDING["raw_sha256"]
