from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import inspect
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v3 import (
    MODEL_FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    PARENT_RUNTIME_SOURCE_SHA256,
    V2_INDEPENDENT_AUDIT_BINDING,
    DecisionBatchV3,
    FrozenHierarchicalParametersV3,
    HierarchicalFitResultV3,
    HierarchicalStateV3ContractError,
    apply_frozen_parameters_v3,
    bind_research_dgp_nuisance_groups_v3,
    build_decision_batch_v3,
    build_frozen_parameter_bundle_bytes,
    build_hierarchical_state_features_v3,
    contract_payload,
    contract_sha256,
    capture_runtime_receipt_v3,
    fit_chronological_prefix_v3,
    load_frozen_parameter_bundle,
    run_frozen_decision_session_v3,
    run_source_audit_v3,
    validate_research_dgp_nuisance_groups_v3,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v3.contracts import (
    DGP_MEMBERSHIP_COLUMN,
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
    capability = fit_chronological_prefix_v3(
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
    assert V2_INDEPENDENT_AUDIT_BINDING["raw_sha256"] == (
        "82f1d6df2deb1d02c45f394c228340c5f4316ec4c0b480ecaec2a3d293f6e4bb"
    )
    assert V2_INDEPENDENT_AUDIT_BINDING["severity_counts"] == {
        "P0": 0,
        "P1": 6,
        "P2": 3,
    }
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
    baseline = build_hierarchical_state_features_v3(source)
    assert tuple(baseline.features.columns) == MODEL_FEATURE_COLUMNS
    assert baseline.parent_group_columns == ("entity_id",)
    assert "group_columns" not in inspect.signature(
        build_hierarchical_state_features_v3
    ).parameters

    injected = source.copy()
    injected["research_dgp_id"] = np.where(
        np.arange(len(injected)) % 2,
        "ATTACK_A",
        "ATTACK_B",
    )
    injected["seed"] = np.arange(len(injected), dtype=np.int64)
    result = build_hierarchical_state_features_v3(injected)
    pd.testing.assert_frame_equal(baseline.features, result.features, check_exact=True)

    entity_positions = np.flatnonzero(source["entity_id"].eq("ENTITY_A").to_numpy())
    pivot = int(entity_positions[250])
    next_row = int(entity_positions[251])
    same_row_changed = source.copy()
    same_row_changed.loc[pivot, "observed_pe"] *= 8.0
    changed_state = build_hierarchical_state_features_v3(same_row_changed)
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
    future_state = build_hierarchical_state_features_v3(future)
    prefix = source["date"] <= cutoff
    pd.testing.assert_frame_equal(
        baseline.features.loc[prefix],
        future_state.features.loc[prefix],
        check_exact=True,
    )


def test_feature_order_invariance_regime_receipts_and_identity_failures() -> None:
    source = _source()
    baseline = build_hierarchical_state_features_v3(source)
    shuffled = source.sample(frac=1.0, random_state=1701)
    shuffled_state = build_hierarchical_state_features_v3(shuffled)
    pd.testing.assert_frame_equal(
        baseline.features.sort_index(),
        shuffled_state.features.sort_index(),
        check_exact=True,
    )

    normalized = source.copy()
    normalized.loc[normalized.index[:5], ["p_bear", "p_sideways", "p_bull"]] *= 2.0
    normalized_state = build_hierarchical_state_features_v3(normalized)
    assert normalized_state.regime_renormalized_count == 5
    assert normalized_state.regime_fallback_count == 0

    fallback = source.copy()
    fallback.loc[fallback.index[:3], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    fallback_state = build_hierarchical_state_features_v3(fallback)
    assert fallback_state.regime_fallback_count == 3
    np.testing.assert_allclose(
        fallback_state.features.loc[fallback.index[:3], list(REGIME_COLUMNS)],
        np.full((3, 3), 1.0 / 3.0),
    )
    overflow = source.copy()
    overflow.loc[overflow.index[:10], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    overflow_state = build_hierarchical_state_features_v3(overflow)
    assert overflow_state.regime_fallback_count == 10

    duplicate = source.copy()
    entity_rows = duplicate.index[duplicate["entity_id"].eq("ENTITY_A")]
    duplicate.loc[entity_rows[1], "date"] = duplicate.loc[entity_rows[0], "date"]
    with pytest.raises(HierarchicalStateV3ContractError, match="unique"):
        build_hierarchical_state_features_v3(duplicate)


def test_robust_fit_converges_is_constrained_and_seals_provenance(fitted_case) -> None:
    _, decision_date, capability = fitted_case
    fit = capability.fit
    parameters = fit.parameters
    receipt = fit.fit_receipt
    assert fit.resource_receipt.purpose == "FIT"
    assert fit.resource_receipt.python_version == "3.10.19"
    assert fit.resource_receipt.affinity_mask_hex == "0xFFFFFFFF"
    assert fit.resource_receipt.thread_environment == (
        ("OMP_NUM_THREADS", "1"),
        ("OPENBLAS_NUM_THREADS", "1"),
        ("MKL_NUM_THREADS", "1"),
        ("NUMEXPR_NUM_THREADS", "1"),
    )
    assert receipt.irls_converged
    assert receipt.final_kkt_violation <= 1e-10
    assert receipt.final_coefficient_delta <= 1e-8
    assert receipt.final_weight_delta <= 1e-8
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
    deployable_fields = {item.name for item in fields(FrozenHierarchicalParametersV3)}
    assert not deployable_fields.intersection(
        {"dgp_id", "research_dgp_id", "seed", "dgp_effects", "dgp_scale_effects"}
    )


def test_dgp_bijective_relabel_and_row_shuffle_are_bit_reproducible(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    relabeled = source["research_dgp_id"].map({"DGP_X": "ZZZ", "DGP_Y": "AAA"})
    relabeled_fit = fit_chronological_prefix_v3(
        source,
        future_decision_date=decision_date,
        observed_pe=source["observed_pe"],
        research_dgp_groups=relabeled,
    )
    assert relabeled_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert relabeled_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    shuffled = source.sample(frac=1.0, random_state=901)
    shuffled_fit = fit_chronological_prefix_v3(
        shuffled,
        future_decision_date=decision_date,
        observed_pe=shuffled["observed_pe"],
        research_dgp_groups=shuffled["research_dgp_id"],
    )
    assert shuffled_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert shuffled_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()


def test_decision_runner_is_identity_bound_future_and_same_row_safe(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v3(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()
    batch = build_decision_batch_v3(state, requested)
    output = apply_frozen_parameters_v3(batch, capability.fit.parameters)
    assert tuple(output.values.columns) == OUTPUT_COLUMNS
    assert output.identities.equals(requested)
    assert output.values[OUTPUT_COLUMNS[1]].le(output.values[OUTPUT_COLUMNS[0]]).all()
    assert output.values[OUTPUT_COLUMNS[0]].le(output.values[OUTPUT_COLUMNS[2]]).all()
    assert output.values[OUTPUT_COLUMNS[4]].between(0.0, 1.0).all()
    assert output.values[OUTPUT_COLUMNS[3]].between(math.log(0.01), math.log(0.50)).all()
    assert output.inference_resource_receipt.purpose == "INFERENCE"
    assert output.inference_resource_receipt_sha256 == (
        output.inference_resource_receipt.sha256()
    )

    attacked = source.copy()
    attacked.loc[attacked["date"].eq(decision_date), "observed_pe"] *= 50.0
    attacked.loc[attacked["date"].eq(decision_date), "research_dgp_id"] = "ATTACK"
    attacked_output = run_frozen_decision_session_v3(
        attacked,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    pd.testing.assert_frame_equal(output.values, attacked_output.values, check_exact=True)

    with pytest.raises(HierarchicalStateV3ContractError, match="exact identity-join factory"):
        DecisionBatchV3(
            features=batch.features,
            identities=batch.identities,
            source_state_sha256=batch.source_state_sha256,
            decision_batch_sha256=batch.decision_batch_sha256,
            source_positions=batch.source_positions,
            source_row_count=batch.source_row_count,
            decision_regime_fallback_count=batch.decision_regime_fallback_count,
            decision_regime_renormalized_count=batch.decision_regime_renormalized_count,
        )


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
    with pytest.raises(HierarchicalStateV3ContractError, match="file universe"):
        load_frozen_parameter_bundle(
            extra,
            expected_checksums_raw_sha256=checksums_sha256,
        )


def test_chronological_prefix_excludes_same_session_target_and_future_rows(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    attacked = source.copy()
    attacked.loc[attacked["date"] >= decision_date, "observed_pe"] *= 100.0
    attacked.loc[attacked["date"] >= decision_date, "research_dgp_id"] = "FUTURE_ONLY"
    attacked_fit = fit_chronological_prefix_v3(
        attacked,
        future_decision_date=decision_date,
        observed_pe=attacked["observed_pe"],
        research_dgp_groups=attacked["research_dgp_id"],
    )
    assert attacked_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert attacked_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    with pytest.raises(HierarchicalStateV3ContractError, match="index-bound"):
        fit_chronological_prefix_v3(
            source,
            future_decision_date=decision_date,
            observed_pe=source["observed_pe"].reset_index(drop=True).rename(index=lambda x: x + 1),
            research_dgp_groups=source["research_dgp_id"],
        )


def test_static_source_isolation_and_bound_public_evidence() -> None:
    audit = run_source_audit_v3(PROJECT_ROOT)
    assert audit.passed
    assert audit.status == "PASS_HOFS_V3_SCORE_FREE_SOURCE_ISOLATION"
    assert audit.forbidden_import_hits == ()
    assert audit.frozen_prediction_import_hits == ()
    assert audit.forbidden_call_hits == ()
    assert audit.unexpected_runtime_io_hits == ()
    assert audit.protected_payload_open_count == 0
    assert audit.frozen_prediction_open_count == 0
    assert audit.score_call_count == 0
    assert audit.registry_mutation_count == 0
    assert audit.v2_audit_raw_sha256 == V2_INDEPENDENT_AUDIT_BINDING["raw_sha256"]
    assert audit.v2_audit_semantic_sha256 == V2_INDEPENDENT_AUDIT_BINDING[
        "semantic_sha256"
    ]


def test_entity_and_dgp_membership_require_strict_keyed_strings() -> None:
    source = _source()
    coerced = source.copy()
    coerced.loc[coerced.index[0], "entity_id"] = 1
    with pytest.raises(HierarchicalStateV3ContractError, match="without coercion"):
        build_hierarchical_state_features_v3(coerced)

    state = build_hierarchical_state_features_v3(source)
    memberships = bind_research_dgp_nuisance_groups_v3(
        source["research_dgp_id"], identities=state.identities
    )
    shuffled = memberships.sample(frac=1.0, random_state=211)
    labels = validate_research_dgp_nuisance_groups_v3(
        shuffled, identities=state.identities
    )
    assert labels == tuple(source["research_dgp_id"].tolist())

    with pytest.raises(HierarchicalStateV3ContractError, match="keyed DataFrame"):
        validate_research_dgp_nuisance_groups_v3(
            source["research_dgp_id"].tolist(),  # type: ignore[arg-type]
            identities=state.identities,
        )
    attacked = memberships.copy()
    attacked.loc[attacked.index[0], DGP_MEMBERSHIP_COLUMN] = 1
    with pytest.raises(HierarchicalStateV3ContractError, match="without coercion"):
        validate_research_dgp_nuisance_groups_v3(
            attacked, identities=state.identities
        )


def test_decision_fallback_gate_uses_only_selected_decision_rows(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v3(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()

    historical = source.copy()
    historical.loc[historical.index[0], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    accepted = run_frozen_decision_session_v3(
        historical,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    assert accepted.regime_fallback_count == 0

    decision_attack = source.copy()
    attacked_index = decision_attack.index[decision_attack["date"].eq(decision_date)][0]
    decision_attack.loc[
        attacked_index, ["p_bear", "p_sideways", "p_bull"]
    ] = np.nan
    with pytest.raises(HierarchicalStateV3ContractError, match="decision-row fallback limit"):
        run_frozen_decision_session_v3(
            decision_attack,
            requested_identities=requested,
            parameters=capability.fit.parameters,
        )

    renormalized = source.copy()
    renormalized.loc[
        attacked_index, ["p_bear", "p_sideways", "p_bull"]
    ] *= 1.000005
    output = run_frozen_decision_session_v3(
        renormalized,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    assert output.regime_renormalized_count == 1


def test_decision_batch_detects_post_factory_identity_or_feature_mutation(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v3(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()

    identity_batch = build_decision_batch_v3(state, requested)
    identity_batch.identities.iloc[0, 0] = "SWAPPED_ENTITY"
    with pytest.raises(HierarchicalStateV3ContractError, match="binding drifted"):
        apply_frozen_parameters_v3(identity_batch, capability.fit.parameters)

    feature_batch = build_decision_batch_v3(state, requested)
    feature_batch.features.iloc[0, 0] += 0.01
    with pytest.raises(HierarchicalStateV3ContractError, match="binding drifted"):
        apply_frozen_parameters_v3(feature_batch, capability.fit.parameters)


def test_receipt_and_cross_object_semantics_fail_closed(fitted_case) -> None:
    _, _, capability = fitted_case
    fit = capability.fit
    with pytest.raises(HierarchicalStateV3ContractError, match="final-weight KKT"):
        replace(fit.fit_receipt, final_kkt_violation=1.0)
    with pytest.raises(HierarchicalStateV3ContractError, match="coefficient gate"):
        replace(fit.fit_receipt, final_coefficient_delta=1.0)
    with pytest.raises(HierarchicalStateV3ContractError, match="resource receipt semantic"):
        replace(fit.resource_receipt, logical_cpu_count=-7)

    mismatched = replace(fit.parameters, fit_identity_sha256="a" * 64)
    with pytest.raises(HierarchicalStateV3ContractError, match="cross-object provenance"):
        HierarchicalFitResultV3(
            parameters=mismatched,
            fit_receipt=fit.fit_receipt,
            resource_receipt=fit.resource_receipt,
        )


def test_final_kkt_is_recomputed_on_final_huber_weights(monkeypatch) -> None:
    from research.model_zoo.hierarchical_observable_fair_value_state_v3 import estimator

    source = _source()
    observed = source["observed_pe"].copy()
    observed.iloc[::37] *= 3.0
    fixed_system_calls: list[tuple[np.ndarray, np.ndarray, np.ndarray]] = []
    kkt_calls: list[float] = []
    original_system = estimator._fixed_quadratic_system
    original_kkt = estimator._kkt_violation

    def capture_system(design, target, weights, penalty):
        result = original_system(design, target, weights, penalty)
        fixed_system_calls.append((result[0], result[1], weights.copy()))
        return result

    def capture_kkt(coefficients, gram, right, lower, upper):
        value = original_kkt(coefficients, gram, right, lower, upper)
        kkt_calls.append(value)
        return value

    monkeypatch.setattr(estimator, "_fixed_quadratic_system", capture_system)
    monkeypatch.setattr(estimator, "_kkt_violation", capture_kkt)
    decision = pd.Timestamp(source["date"].max())
    fit = fit_chronological_prefix_v3(
        source,
        future_decision_date=decision,
        observed_pe=observed,
        research_dgp_groups=source["research_dgp_id"],
    ).fit
    assert len(fixed_system_calls) == 2 * fit.fit_receipt.irls_iterations
    assert fit.fit_receipt.final_kkt_violation == kkt_calls[-1]
    assert fit.fit_receipt.final_kkt_violation <= 1e-10
    assert fit.fit_receipt.final_weight_delta <= 1e-8


def test_centered_zero_mad_scale_and_forced_nonconvergence(monkeypatch) -> None:
    from research.model_zoo.hierarchical_observable_fair_value_state_v3 import estimator

    assert estimator._residual_scale(np.full(64, 0.2, dtype=np.float64)) == 0.01
    source = _source()
    decision = pd.Timestamp(source["date"].max())
    monkeypatch.setattr(estimator, "IRLS_MAX_ITERATIONS", 1)
    with pytest.raises(HierarchicalStateV3ContractError, match="did not converge"):
        fit_chronological_prefix_v3(
            source,
            future_decision_date=decision,
            observed_pe=source["observed_pe"],
            research_dgp_groups=source["research_dgp_id"],
        )


def test_exact_runtime_guard_rejects_thread_and_gpu_drift(monkeypatch) -> None:
    baseline = capture_runtime_receipt_v3(purpose="PREFLIGHT")
    assert baseline.python_version == "3.10.19"
    assert baseline.affinity_mask_hex == "0xFFFFFFFF"
    monkeypatch.setenv("OMP_NUM_THREADS", "7")
    with pytest.raises(HierarchicalStateV3ContractError, match="resource receipt semantic"):
        capture_runtime_receipt_v3(purpose="INFERENCE")
    monkeypatch.setenv("OMP_NUM_THREADS", "1")
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    with pytest.raises(HierarchicalStateV3ContractError, match="resource receipt semantic"):
        capture_runtime_receipt_v3(purpose="INFERENCE")


def test_bundle_rejects_directory_symlink_and_semantic_tamper(
    tmp_path: Path,
    fitted_case,
    monkeypatch,
) -> None:
    _, _, capability = fitted_case
    payloads = build_frozen_parameter_bundle_bytes(capability.fit)
    checksums_sha256 = hashlib.sha256(payloads["CHECKSUMS.sha256"]).hexdigest()

    directory_attack = tmp_path / "directory_attack"
    directory_attack.mkdir()
    for name, content in payloads.items():
        (directory_attack / name).write_bytes(content)
    (directory_attack / "UNDECLARED_DIRECTORY").mkdir()
    with pytest.raises(HierarchicalStateV3ContractError, match="non-file entry"):
        load_frozen_parameter_bundle(
            directory_attack,
            expected_checksums_raw_sha256=checksums_sha256,
        )

    symlink_attack = tmp_path / "symlink_attack"
    symlink_attack.mkdir()
    for name, content in payloads.items():
        (symlink_attack / name).write_bytes(content)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self.name == "PARAMETERS.json" or original_is_symlink(self),
    )
    with pytest.raises(HierarchicalStateV3ContractError, match="symlink"):
        load_frozen_parameter_bundle(
            symlink_attack,
            expected_checksums_raw_sha256=checksums_sha256,
        )
    monkeypatch.undo()

    semantic_attack = tmp_path / "semantic_attack"
    semantic_attack.mkdir()
    attacked = dict(payloads)
    fit_payload = json.loads(attacked["FIT_RECEIPT.json"].decode("ascii"))
    fit_payload["final_kkt_violation"] = 1.0
    attacked["FIT_RECEIPT.json"] = (
        json.dumps(fit_payload, ensure_ascii=True, sort_keys=True, indent=2).encode("ascii")
        + b"\n"
    )
    manifest = json.loads(attacked["MANIFEST.json"].decode("ascii"))
    manifest["file_raw_sha256"]["FIT_RECEIPT.json"] = hashlib.sha256(
        attacked["FIT_RECEIPT.json"]
    ).hexdigest()
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256")
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    attacked["MANIFEST.json"] = (
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2).encode("ascii")
        + b"\n"
    )
    attacked["CHECKSUMS.sha256"] = "".join(
        f"{hashlib.sha256(attacked[name]).hexdigest()}  {name}\n"
        for name in sorted(attacked)
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    for name, content in attacked.items():
        (semantic_attack / name).write_bytes(content)
    with pytest.raises(HierarchicalStateV3ContractError, match="final-weight KKT"):
        load_frozen_parameter_bundle(
            semantic_attack,
            expected_checksums_raw_sha256=hashlib.sha256(
                attacked["CHECKSUMS.sha256"]
            ).hexdigest(),
        )
