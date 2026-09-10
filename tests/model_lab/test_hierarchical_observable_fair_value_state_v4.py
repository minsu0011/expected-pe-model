from __future__ import annotations

from dataclasses import asdict, fields, replace
import copy
import hashlib
import inspect
import json
import math
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v4 import (
    CANDIDATE,
    MODEL_FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    PARENT_RUNTIME_SOURCE_SHA256,
    V3_INDEPENDENT_AUDIT_BINDING,
    DecisionBatchV4,
    FrozenHierarchicalParametersV4,
    HierarchicalFitResultV4,
    HierarchicalStateV4ContractError,
    apply_frozen_parameters_v4,
    bind_research_dgp_nuisance_groups_v4,
    build_decision_batch_v4,
    build_frozen_parameter_bundle_bytes,
    build_hierarchical_state_features_v4,
    contract_payload,
    contract_sha256,
    capture_runtime_receipt_v4,
    fit_chronological_prefix_v4,
    load_frozen_parameter_bundle,
    run_frozen_decision_session_v4,
    run_source_audit_v4,
    validate_research_dgp_nuisance_groups_v4,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v4.contracts import (
    DGP_MEMBERSHIP_COLUMN,
    INNOVATION_BOUNDS,
    PERSISTENCE_BOUNDS,
    REGIME_COLUMNS,
    canonical_json_bytes,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v4 import (
    freeze_design as freeze_design_v4,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _pretty_json(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _seal_payload(payload: dict[str, object]) -> dict[str, object]:
    sealed = copy.deepcopy(payload)
    sealed.pop("manifest_sha256", None)
    sealed["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(sealed)
    ).hexdigest()
    return sealed


def _fully_reseal_parameter_payloads(
    original: dict[str, bytes],
    *,
    mutate: Callable[[dict[str, dict[str, Any]]], None],
) -> dict[str, bytes]:
    documents = {
        name: json.loads(original[name].decode("ascii"))
        for name in (
            "FIT_RECEIPT.json",
            "PARAMETERS.json",
            "RESOURCE_RECEIPT.json",
            "MANIFEST.json",
        )
    }
    mutate(documents)
    fit = documents["FIT_RECEIPT.json"]
    parameters = documents["PARAMETERS.json"]
    resource = documents["RESOURCE_RECEIPT.json"]
    manifest = documents["MANIFEST.json"]
    resource_sha = hashlib.sha256(canonical_json_bytes(resource)).hexdigest()
    fit["resource_receipt_sha256"] = resource_sha
    fit_sha = hashlib.sha256(canonical_json_bytes(fit)).hexdigest()
    parameters["resource_receipt_sha256"] = resource_sha
    parameters["convergence_receipt_sha256"] = fit_sha
    parameter_sha = hashlib.sha256(canonical_json_bytes(parameters)).hexdigest()
    files = {
        "FIT_RECEIPT.json": _pretty_json(fit),
        "PARAMETERS.json": _pretty_json(parameters),
        "RESOURCE_RECEIPT.json": _pretty_json(resource),
    }
    manifest.update(
        {
            "parameter_sha256": parameter_sha,
            "fit_receipt_sha256": fit_sha,
            "resource_receipt_sha256": resource_sha,
            "file_raw_sha256": {
                name: hashlib.sha256(content).hexdigest()
                for name, content in sorted(files.items())
            },
        }
    )
    manifest = _seal_payload(manifest)
    files["MANIFEST.json"] = _pretty_json(manifest)
    files["CHECKSUMS.sha256"] = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(files.items())
    ).encode("ascii")
    return files


def _write_payloads(root: Path, payloads: dict[str, bytes]) -> str:
    root.mkdir()
    for name, content in payloads.items():
        (root / name).write_bytes(content)
    return hashlib.sha256(payloads["CHECKSUMS.sha256"]).hexdigest()


def _rechecksum(payloads: dict[str, bytes]) -> str:
    payloads["CHECKSUMS.sha256"] = "".join(
        f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
        for name in sorted(payloads)
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    return hashlib.sha256(payloads["CHECKSUMS.sha256"]).hexdigest()


def _mutate_document_path(
    documents: dict[str, dict[str, Any]],
    document: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    cursor: Any = documents[document]
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value


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
    capability = fit_chronological_prefix_v4(
        source,
        future_decision_date=decision_date,
        observed_pe=source["observed_pe"],
        research_dgp_groups=source["research_dgp_id"],
    )
    return source, decision_date, capability


def test_contract_binds_v3_audit_and_complete_parent_runtime_closure() -> None:
    payload = contract_payload()
    assert len(MODEL_FEATURE_COLUMNS) == 17
    assert len(contract_sha256()) == 64
    assert payload["selection_policy"] == {
        "candidate_count": 1,
        "hyperparameter_sweep": False,
        "ranking": "single_candidate_no_adaptive_selection",
    }
    assert V3_INDEPENDENT_AUDIT_BINDING["raw_sha256"] == (
        "6991529ba9c3791c6b5fed0fe548cc450dfb6dce269a782373bfb6a0a84bca91"
    )
    assert V3_INDEPENDENT_AUDIT_BINDING["severity_counts"] == {
        "P0": 0,
        "P1": 3,
        "P2": 1,
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
    baseline = build_hierarchical_state_features_v4(source)
    assert tuple(baseline.features.columns) == MODEL_FEATURE_COLUMNS
    assert baseline.parent_group_columns == ("entity_id",)
    assert "group_columns" not in inspect.signature(
        build_hierarchical_state_features_v4
    ).parameters

    injected = source.copy()
    injected["research_dgp_id"] = np.where(
        np.arange(len(injected)) % 2,
        "ATTACK_A",
        "ATTACK_B",
    )
    injected["seed"] = np.arange(len(injected), dtype=np.int64)
    result = build_hierarchical_state_features_v4(injected)
    pd.testing.assert_frame_equal(baseline.features, result.features, check_exact=True)

    entity_positions = np.flatnonzero(source["entity_id"].eq("ENTITY_A").to_numpy())
    pivot = int(entity_positions[250])
    next_row = int(entity_positions[251])
    same_row_changed = source.copy()
    same_row_changed.loc[pivot, "observed_pe"] *= 8.0
    changed_state = build_hierarchical_state_features_v4(same_row_changed)
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
    future_state = build_hierarchical_state_features_v4(future)
    prefix = source["date"] <= cutoff
    pd.testing.assert_frame_equal(
        baseline.features.loc[prefix],
        future_state.features.loc[prefix],
        check_exact=True,
    )


def test_feature_order_invariance_regime_receipts_and_identity_failures() -> None:
    source = _source()
    baseline = build_hierarchical_state_features_v4(source)
    shuffled = source.sample(frac=1.0, random_state=1701)
    shuffled_state = build_hierarchical_state_features_v4(shuffled)
    pd.testing.assert_frame_equal(
        baseline.features.sort_index(),
        shuffled_state.features.sort_index(),
        check_exact=True,
    )

    normalized = source.copy()
    normalized.loc[normalized.index[:5], ["p_bear", "p_sideways", "p_bull"]] *= 2.0
    normalized_state = build_hierarchical_state_features_v4(normalized)
    assert normalized_state.regime_renormalized_count == 5
    assert normalized_state.regime_fallback_count == 0

    fallback = source.copy()
    fallback.loc[fallback.index[:3], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    fallback_state = build_hierarchical_state_features_v4(fallback)
    assert fallback_state.regime_fallback_count == 3
    np.testing.assert_allclose(
        fallback_state.features.loc[fallback.index[:3], list(REGIME_COLUMNS)],
        np.full((3, 3), 1.0 / 3.0),
    )
    overflow = source.copy()
    overflow.loc[overflow.index[:10], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    overflow_state = build_hierarchical_state_features_v4(overflow)
    assert overflow_state.regime_fallback_count == 10

    duplicate = source.copy()
    entity_rows = duplicate.index[duplicate["entity_id"].eq("ENTITY_A")]
    duplicate.loc[entity_rows[1], "date"] = duplicate.loc[entity_rows[0], "date"]
    with pytest.raises(HierarchicalStateV4ContractError, match="unique"):
        build_hierarchical_state_features_v4(duplicate)


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
    deployable_fields = {item.name for item in fields(FrozenHierarchicalParametersV4)}
    assert not deployable_fields.intersection(
        {"dgp_id", "research_dgp_id", "seed", "dgp_effects", "dgp_scale_effects"}
    )


def test_dgp_bijective_relabel_and_row_shuffle_are_bit_reproducible(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    relabeled = source["research_dgp_id"].map({"DGP_X": "ZZZ", "DGP_Y": "AAA"})
    relabeled_fit = fit_chronological_prefix_v4(
        source,
        future_decision_date=decision_date,
        observed_pe=source["observed_pe"],
        research_dgp_groups=relabeled,
    )
    assert relabeled_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert relabeled_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    shuffled = source.sample(frac=1.0, random_state=901)
    shuffled_fit = fit_chronological_prefix_v4(
        shuffled,
        future_decision_date=decision_date,
        observed_pe=shuffled["observed_pe"],
        research_dgp_groups=shuffled["research_dgp_id"],
    )
    shuffled_parameters = asdict(shuffled_fit.fit.parameters)
    baseline_parameters = asdict(baseline.fit.parameters)
    for payload in (shuffled_parameters, baseline_parameters):
        payload.pop("fit_state_sha256")
        payload.pop("convergence_receipt_sha256")
    assert shuffled_parameters == baseline_parameters
    shuffled_receipt = asdict(shuffled_fit.fit.fit_receipt)
    baseline_receipt = asdict(baseline.fit.fit_receipt)
    shuffled_receipt.pop("fit_state_sha256")
    baseline_receipt.pop("fit_state_sha256")
    assert shuffled_receipt == baseline_receipt
    assert shuffled_fit.fit.parameters.fit_state_sha256 != (
        baseline.fit.parameters.fit_state_sha256
    )


def test_decision_runner_is_identity_bound_future_and_same_row_safe(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v4(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()
    batch = build_decision_batch_v4(state, requested)
    output = apply_frozen_parameters_v4(batch, capability.fit.parameters)
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
    attacked_output = run_frozen_decision_session_v4(
        attacked,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    pd.testing.assert_frame_equal(output.values, attacked_output.values, check_exact=True)

    with pytest.raises(HierarchicalStateV4ContractError, match="exact identity-join factory"):
        DecisionBatchV4(
            features=batch.features,
            identities=batch.identities,
            source_state_sha256=batch.source_state_sha256,
            decision_batch_sha256=batch.decision_batch_sha256,
            source_positions=batch.source_positions,
            source_row_count=batch.source_row_count,
            decision_regime_fallback_mask=batch.decision_regime_fallback_mask,
            decision_regime_renormalized_mask=(
                batch.decision_regime_renormalized_mask
            ),
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
    with pytest.raises(HierarchicalStateV4ContractError, match="file universe"):
        load_frozen_parameter_bundle(
            extra,
            expected_checksums_raw_sha256=checksums_sha256,
        )


def test_chronological_prefix_excludes_same_session_target_and_future_rows(fitted_case) -> None:
    source, decision_date, baseline = fitted_case
    attacked = source.copy()
    attacked.loc[attacked["date"] >= decision_date, "observed_pe"] *= 100.0
    attacked.loc[attacked["date"] >= decision_date, "research_dgp_id"] = "FUTURE_ONLY"
    attacked_fit = fit_chronological_prefix_v4(
        attacked,
        future_decision_date=decision_date,
        observed_pe=attacked["observed_pe"],
        research_dgp_groups=attacked["research_dgp_id"],
    )
    assert attacked_fit.fit.parameters.sha256() == baseline.fit.parameters.sha256()
    assert attacked_fit.fit.fit_receipt.sha256() == baseline.fit.fit_receipt.sha256()

    with pytest.raises(HierarchicalStateV4ContractError, match="index-bound"):
        fit_chronological_prefix_v4(
            source,
            future_decision_date=decision_date,
            observed_pe=source["observed_pe"].reset_index(drop=True).rename(index=lambda x: x + 1),
            research_dgp_groups=source["research_dgp_id"],
        )


def test_static_source_isolation_and_bound_public_evidence() -> None:
    audit = run_source_audit_v4(PROJECT_ROOT)
    assert audit.passed
    assert audit.status == "PASS_HOFS_V4_SCORE_FREE_SOURCE_ISOLATION"
    assert audit.forbidden_import_hits == ()
    assert audit.frozen_prediction_import_hits == ()
    assert audit.forbidden_call_hits == ()
    assert audit.unexpected_runtime_io_hits == ()
    assert audit.protected_payload_open_count == 0
    assert audit.frozen_prediction_open_count == 0
    assert audit.score_call_count == 0
    assert audit.registry_mutation_count == 0
    assert audit.v3_audit_raw_sha256 == V3_INDEPENDENT_AUDIT_BINDING["raw_sha256"]
    assert audit.v3_audit_semantic_sha256 == V3_INDEPENDENT_AUDIT_BINDING[
        "semantic_sha256"
    ]
    assert audit.v3_audit_manifest_raw_sha256 == V3_INDEPENDENT_AUDIT_BINDING[
        "manifest_raw_sha256"
    ]
    assert audit.v3_audit_seal_raw_sha256 == V3_INDEPENDENT_AUDIT_BINDING[
        "seal_raw_sha256"
    ]
    assert audit.v3_audit_checksums_raw_sha256 == V3_INDEPENDENT_AUDIT_BINDING[
        "checksums_raw_sha256"
    ]


def test_entity_and_dgp_membership_require_strict_keyed_strings() -> None:
    source = _source()
    coerced = source.copy()
    coerced.loc[coerced.index[0], "entity_id"] = 1
    with pytest.raises(HierarchicalStateV4ContractError, match="without coercion"):
        build_hierarchical_state_features_v4(coerced)

    state = build_hierarchical_state_features_v4(source)
    memberships = bind_research_dgp_nuisance_groups_v4(
        source["research_dgp_id"], identities=state.identities
    )
    shuffled = memberships.sample(frac=1.0, random_state=211)
    labels = validate_research_dgp_nuisance_groups_v4(
        shuffled, identities=state.identities
    )
    assert labels == tuple(source["research_dgp_id"].tolist())

    with pytest.raises(HierarchicalStateV4ContractError, match="keyed DataFrame"):
        validate_research_dgp_nuisance_groups_v4(
            source["research_dgp_id"].tolist(),  # type: ignore[arg-type]
            identities=state.identities,
        )
    attacked = memberships.copy()
    attacked.loc[attacked.index[0], DGP_MEMBERSHIP_COLUMN] = 1
    with pytest.raises(HierarchicalStateV4ContractError, match="without coercion"):
        validate_research_dgp_nuisance_groups_v4(
            attacked, identities=state.identities
        )


def test_decision_fallback_gate_uses_only_selected_decision_rows(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v4(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()

    historical = source.copy()
    historical.loc[historical.index[0], ["p_bear", "p_sideways", "p_bull"]] = np.nan
    accepted = run_frozen_decision_session_v4(
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
    with pytest.raises(HierarchicalStateV4ContractError, match="decision-row fallback limit"):
        run_frozen_decision_session_v4(
            decision_attack,
            requested_identities=requested,
            parameters=capability.fit.parameters,
        )

    renormalized = source.copy()
    renormalized.loc[
        attacked_index, ["p_bear", "p_sideways", "p_bull"]
    ] *= 1.000005
    output = run_frozen_decision_session_v4(
        renormalized,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    assert output.regime_renormalized_count == 1


def test_decision_batch_detects_post_factory_identity_or_feature_mutation(fitted_case) -> None:
    source, decision_date, capability = fitted_case
    state = build_hierarchical_state_features_v4(source)
    requested = state.identities.loc[source["date"].eq(decision_date)].copy()

    identity_batch = build_decision_batch_v4(state, requested)
    identity_batch.identities.iloc[0, 0] = "SWAPPED_ENTITY"
    with pytest.raises(HierarchicalStateV4ContractError, match="binding drifted"):
        apply_frozen_parameters_v4(identity_batch, capability.fit.parameters)

    feature_batch = build_decision_batch_v4(state, requested)
    feature_batch.features.iloc[0, 0] += 0.01
    with pytest.raises(HierarchicalStateV4ContractError, match="binding drifted"):
        apply_frozen_parameters_v4(feature_batch, capability.fit.parameters)


def test_receipt_and_cross_object_semantics_fail_closed(fitted_case) -> None:
    _, _, capability = fitted_case
    fit = capability.fit
    with pytest.raises(HierarchicalStateV4ContractError, match="final-weight KKT"):
        replace(fit.fit_receipt, final_kkt_violation=1.0)
    with pytest.raises(HierarchicalStateV4ContractError, match="coefficient gate"):
        replace(fit.fit_receipt, final_coefficient_delta=1.0)
    with pytest.raises(HierarchicalStateV4ContractError, match="fixed domain"):
        replace(fit.resource_receipt, logical_cpu_count=-7)

    mismatched = replace(fit.parameters, fit_identity_sha256="a" * 64)
    with pytest.raises(HierarchicalStateV4ContractError, match="cross-object provenance"):
        HierarchicalFitResultV4(
            parameters=mismatched,
            fit_receipt=fit.fit_receipt,
            resource_receipt=fit.resource_receipt,
        )


def test_final_kkt_is_recomputed_on_final_huber_weights(monkeypatch) -> None:
    from research.model_zoo.hierarchical_observable_fair_value_state_v4 import estimator

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
    fit = fit_chronological_prefix_v4(
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
    from research.model_zoo.hierarchical_observable_fair_value_state_v4 import estimator

    assert estimator._residual_scale(np.full(64, 0.2, dtype=np.float64)) == 0.01
    source = _source()
    decision = pd.Timestamp(source["date"].max())
    monkeypatch.setattr(estimator, "IRLS_MAX_ITERATIONS", 1)
    with pytest.raises(HierarchicalStateV4ContractError, match="did not converge"):
        fit_chronological_prefix_v4(
            source,
            future_decision_date=decision,
            observed_pe=source["observed_pe"],
            research_dgp_groups=source["research_dgp_id"],
        )


def test_exact_runtime_guard_rejects_thread_and_gpu_drift(monkeypatch) -> None:
    baseline = capture_runtime_receipt_v4(purpose="PREFLIGHT")
    assert baseline.python_version == "3.10.19"
    assert baseline.affinity_mask_hex == "0xFFFFFFFF"
    monkeypatch.setenv("OMP_NUM_THREADS", "7")
    with pytest.raises(HierarchicalStateV4ContractError, match="resource receipt semantic"):
        capture_runtime_receipt_v4(purpose="INFERENCE")
    monkeypatch.setenv("OMP_NUM_THREADS", "1")
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    with pytest.raises(HierarchicalStateV4ContractError, match="resource receipt semantic"):
        capture_runtime_receipt_v4(purpose="INFERENCE")


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
    with pytest.raises(HierarchicalStateV4ContractError, match="non-file entry"):
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
    with pytest.raises(HierarchicalStateV4ContractError, match="reparse child"):
        load_frozen_parameter_bundle(
            symlink_attack,
            expected_checksums_raw_sha256=checksums_sha256,
        )
    monkeypatch.undo()

    from research.model_zoo.hierarchical_observable_fair_value_state_v4 import artifacts

    monkeypatch.setattr(
        artifacts,
        "_windows_reparse_point",
        lambda path: Path(path).name == "reparse_root",
    )
    reparse_root = tmp_path / "reparse_root"
    reparse_root.mkdir()
    for name, content in payloads.items():
        (reparse_root / name).write_bytes(content)
    with pytest.raises(HierarchicalStateV4ContractError, match="reparse root"):
        load_frozen_parameter_bundle(
            reparse_root,
            expected_checksums_raw_sha256=checksums_sha256,
        )
    monkeypatch.undo()

    duplicate_json = tmp_path / "duplicate_json_bundle"
    duplicate_payloads = dict(payloads)
    duplicate_payloads["PARAMETERS.json"] = duplicate_payloads[
        "PARAMETERS.json"
    ].replace(
        b'  "candidate_id":',
        b'  "candidate_id": "DUPLICATE",\n  "candidate_id":',
        1,
    )
    duplicate_payloads["CHECKSUMS.sha256"] = "".join(
        f"{hashlib.sha256(duplicate_payloads[name]).hexdigest()}  {name}\n"
        for name in sorted(duplicate_payloads)
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    duplicate_checksum = _write_payloads(duplicate_json, duplicate_payloads)
    with pytest.raises(HierarchicalStateV4ContractError, match="duplicate JSON key"):
        load_frozen_parameter_bundle(
            duplicate_json,
            expected_checksums_raw_sha256=duplicate_checksum,
        )

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
    with pytest.raises(HierarchicalStateV4ContractError, match="final-weight KKT"):
        load_frozen_parameter_bundle(
            semantic_attack,
            expected_checksums_raw_sha256=hashlib.sha256(
                attacked["CHECKSUMS.sha256"]
            ).hexdigest(),
        )


@pytest.mark.parametrize(
    ("document", "path", "attacked_value"),
    (
        ("FIT_RECEIPT.json", ("irls_converged",), "false"),
        ("FIT_RECEIPT.json", ("final_weight_delta",), True),
        ("FIT_RECEIPT.json", ("fit_row_count",), 656.0),
        ("FIT_RECEIPT.json", ("requested_row_count",), True),
        ("PARAMETERS.json", ("research_dgp_effects_marginalized",), "false"),
        ("PARAMETERS.json", ("global_intercept",), "0.1"),
        ("PARAMETERS.json", ("global_log_scale",), 0),
        ("PARAMETERS.json", ("robust_centers", 0), "0.1"),
        ("PARAMETERS.json", ("robust_scales", 0), True),
        ("RESOURCE_RECEIPT.json", ("cpu_ids", 0), 0.0),
        ("RESOURCE_RECEIPT.json", ("threadpool_backends", 0, 4), 1.0),
        ("RESOURCE_RECEIPT.json", ("gpu_used",), 0),
        ("RESOURCE_RECEIPT.json", ("thread_environment", 0), ["OMP_NUM_THREADS"]),
        ("MANIFEST.json", ("research_dgp_effects_marginalized",), 1),
        ("MANIFEST.json", ("fit_row_count",), 656.0),
    ),
)
def test_fully_resealed_bundle_rejects_every_wrong_json_type(
    tmp_path: Path,
    fitted_case,
    document: str,
    path: tuple[str | int, ...],
    attacked_value: object,
) -> None:
    _, _, capability = fitted_case
    original = build_frozen_parameter_bundle_bytes(capability.fit)
    attacked = _fully_reseal_parameter_payloads(
        original,
        mutate=lambda documents: _mutate_document_path(
            documents, document, path, attacked_value
        ),
    )
    checksum = _write_payloads(
        tmp_path / f"typed_{document}_{len(path)}_{str(attacked_value)[:8]}",
        attacked,
    )
    with pytest.raises(HierarchicalStateV4ContractError):
        load_frozen_parameter_bundle(
            tmp_path / f"typed_{document}_{len(path)}_{str(attacked_value)[:8]}",
            expected_checksums_raw_sha256=checksum,
        )


def test_direct_dataclass_constructors_reject_cross_numeric_and_truthy_types(
    fitted_case,
) -> None:
    source, decision, capability = fitted_case
    fit = capability.fit
    state = build_hierarchical_state_features_v4(source)
    requested = state.identities.loc[source["date"].eq(decision)].copy()
    output = run_frozen_decision_session_v4(
        source,
        requested_identities=requested,
        parameters=fit.parameters,
    )
    attacks = (
        lambda: replace(CANDIDATE, family=True),
        lambda: replace(fit.fit_receipt, irls_converged="false"),
        lambda: replace(fit.fit_receipt, final_weight_delta=True),
        lambda: replace(fit.fit_receipt, fit_row_count=float(fit.fit_receipt.fit_row_count)),
        lambda: replace(fit.parameters, research_dgp_effects_marginalized="false"),
        lambda: replace(fit.parameters, global_intercept=1),
        lambda: replace(
            fit.parameters,
            robust_centers=("0.1", *fit.parameters.robust_centers[1:]),
        ),
        lambda: replace(
            fit.resource_receipt,
            cpu_ids=(0.0, *fit.resource_receipt.cpu_ids[1:]),
        ),
        lambda: replace(fit.resource_receipt, gpu_used=0),
        lambda: replace(capability, future_decision_date=1),
        lambda: replace(capability.training_state, warm_rows=True),
        lambda: replace(output, input_rows=True),
        lambda: replace(output, parameter_sha256=1),
        lambda: replace(run_source_audit_v4(PROJECT_ROOT), score_call_count=False),
    )
    for attack in attacks:
        with pytest.raises(HierarchicalStateV4ContractError):
            attack()


@pytest.mark.parametrize(
    "mutation",
    (
        "feature",
        "identity",
        "feature_index",
        "consistent_reorder",
        "fallback_mask",
        "renormalized_mask",
        "fallback_count",
        "warm_rows",
        "metadata",
    ),
)
def test_every_live_state_mutation_fails_before_decision_consumption(
    mutation: str,
) -> None:
    source = _source()
    state = build_hierarchical_state_features_v4(source)
    decision = source["date"].max()
    requested = state.identities.loc[source["date"].eq(decision)].copy()
    if mutation == "feature":
        state.features.iloc[-1, 0] += 0.01
    elif mutation == "identity":
        state.identities.iloc[0, 0] = "MUTATED_ENTITY"
    elif mutation == "feature_index":
        state.features.index = pd.Index(range(10_000, 10_000 + len(state.features)))
    elif mutation == "consistent_reorder":
        order = np.arange(len(state.features) - 1, -1, -1)
        object.__setattr__(state, "features", state.features.iloc[order].copy())
        object.__setattr__(state, "identities", state.identities.iloc[order].copy())
        object.__setattr__(
            state,
            "regime_fallback_mask",
            state.regime_fallback_mask.iloc[order].copy(),
        )
        object.__setattr__(
            state,
            "regime_renormalized_mask",
            state.regime_renormalized_mask.iloc[order].copy(),
        )
    elif mutation == "fallback_mask":
        state.regime_fallback_mask.iloc[0] = not state.regime_fallback_mask.iloc[0]
    elif mutation == "renormalized_mask":
        state.regime_renormalized_mask.iloc[0] = not (
            state.regime_renormalized_mask.iloc[0]
        )
    elif mutation == "fallback_count":
        object.__setattr__(state, "regime_fallback_count", state.regime_fallback_count + 1)
    elif mutation == "warm_rows":
        object.__setattr__(state, "warm_rows", state.warm_rows - 1)
    else:
        object.__setattr__(state, "entity_source_column", "symbol")
    with pytest.raises(HierarchicalStateV4ContractError):
        build_decision_batch_v4(state, requested)


def test_exported_direct_fitter_rejects_mutated_state_before_solver() -> None:
    from research.model_zoo.hierarchical_observable_fair_value_state_v4 import (
        fit_hierarchical_state_v4,
    )

    source = _source()
    decision = pd.Timestamp(source["date"].max())
    prefix = source["date"] < decision
    prefix_source = source.loc[prefix].copy()
    state = build_hierarchical_state_features_v4(prefix_source)
    state.identities.iloc[0, 0] = "MUTATED_ENTITY"
    memberships = bind_research_dgp_nuisance_groups_v4(
        source.loc[prefix, "research_dgp_id"], identities=state.identities
    )
    with pytest.raises(HierarchicalStateV4ContractError, match="binding drifted"):
        fit_hierarchical_state_v4(
            state,
            future_decision_date=decision,
            observed_pe=source.loc[prefix, "observed_pe"],
            research_dgp_memberships=memberships,
        )


def test_decision_batch_masks_counts_and_positions_are_live_bound(fitted_case) -> None:
    source, decision, capability = fitted_case
    state = build_hierarchical_state_features_v4(source)
    requested = state.identities.loc[source["date"].eq(decision)].copy()
    for field_name, attacked_value in (
        (
            "decision_regime_fallback_mask",
            (True, *([False] * (len(requested) - 1))),
        ),
        ("decision_regime_fallback_count", 1),
        ("source_positions", tuple(reversed(range(len(requested))))),
    ):
        batch = build_decision_batch_v4(state, requested)
        object.__setattr__(batch, field_name, attacked_value)
        with pytest.raises(HierarchicalStateV4ContractError):
            apply_frozen_parameters_v4(batch, capability.fit.parameters)


def test_design_verifier_rejects_resealed_cross_seal_and_duplicate_ledger_attacks(
    tmp_path: Path,
) -> None:
    bundle = freeze_design_v4.build_design_bundle_bytes(PROJECT_ROOT)
    good = tmp_path / "good_design"
    checksum = _write_payloads(good, bundle)
    receipt = freeze_design_v4.verify_design_bundle(
        good, expected_checksums_raw_sha256=checksum
    )
    assert receipt["status"] == "PASS_EXACT_V4_DESIGN_BUNDLE_CLOSURE"

    design_attack = copy.deepcopy(bundle)
    design_payload = json.loads(design_attack["DESIGN_LOCK.json"].decode("ascii"))
    design_payload["candidate_count"] = 999
    design_attack["DESIGN_LOCK.json"] = _pretty_json(_seal_payload(design_payload))
    design_checksum = _rechecksum(design_attack)
    design_root = tmp_path / "design_attack"
    _write_payloads(design_root, design_attack)
    with pytest.raises(RuntimeError, match="canonical cross-binding"):
        freeze_design_v4.verify_design_bundle(
            design_root, expected_checksums_raw_sha256=design_checksum
        )

    duplicate_attack = copy.deepcopy(bundle)
    lines = duplicate_attack["CHECKSUMS.sha256"].decode("ascii").splitlines()
    access_line = next(line for line in lines if line.endswith("ACCESS_RECEIPT.json"))
    lines = [
        access_line if line.endswith("REPORT.md") else line
        for line in lines
    ]
    duplicate_attack["CHECKSUMS.sha256"] = ("\n".join(lines) + "\n").encode("ascii")
    duplicate_checksum = hashlib.sha256(
        duplicate_attack["CHECKSUMS.sha256"]
    ).hexdigest()
    duplicate_root = tmp_path / "duplicate_attack"
    _write_payloads(duplicate_root, duplicate_attack)
    with pytest.raises(RuntimeError, match="order/universe/uniqueness"):
        freeze_design_v4.verify_design_bundle(
            duplicate_root, expected_checksums_raw_sha256=duplicate_checksum
        )

    manifest_attack = copy.deepcopy(bundle)
    manifest = json.loads(manifest_attack["MANIFEST.json"].decode("ascii"))
    manifest["core_files"]["REPORT.md"]["size_bytes"] += 1
    manifest_attack["MANIFEST.json"] = _pretty_json(_seal_payload(manifest))
    manifest_checksum = _rechecksum(manifest_attack)
    manifest_root = tmp_path / "manifest_attack"
    _write_payloads(manifest_root, manifest_attack)
    with pytest.raises(RuntimeError, match="canonical cross-binding"):
        freeze_design_v4.verify_design_bundle(
            manifest_root, expected_checksums_raw_sha256=manifest_checksum
        )

    seal_attack = copy.deepcopy(bundle)
    seal = json.loads(seal_attack["SEAL_RECEIPT.json"].decode("ascii"))
    seal["authority"]["score"] = "false"
    seal_attack["SEAL_RECEIPT.json"] = _pretty_json(_seal_payload(seal))
    seal_checksum = _rechecksum(seal_attack)
    seal_root = tmp_path / "seal_attack"
    _write_payloads(seal_root, seal_attack)
    with pytest.raises(RuntimeError, match="canonical cross-binding"):
        freeze_design_v4.verify_design_bundle(
            seal_root, expected_checksums_raw_sha256=seal_checksum
        )


def test_design_verifier_rejects_duplicate_json_key_and_reparse_root_or_child(
    tmp_path: Path,
    monkeypatch,
) -> None:
    bundle = freeze_design_v4.build_design_bundle_bytes(PROJECT_ROOT)
    duplicate_json = copy.deepcopy(bundle)
    duplicate_json["ACCESS_RECEIPT.json"] = duplicate_json[
        "ACCESS_RECEIPT.json"
    ].replace(b'  "status":', b'  "status": "DUPLICATE",\n  "status":', 1)
    duplicate_checksum = _rechecksum(duplicate_json)
    duplicate_root = tmp_path / "duplicate_json"
    _write_payloads(duplicate_root, duplicate_json)
    with pytest.raises(RuntimeError, match="duplicate/invalid JSON key"):
        freeze_design_v4.verify_design_bundle(
            duplicate_root, expected_checksums_raw_sha256=duplicate_checksum
        )

    clean_root = tmp_path / "reparse_probe"
    clean_checksum = _write_payloads(clean_root, bundle)
    monkeypatch.setattr(
        freeze_design_v4,
        "_windows_reparse_point",
        lambda path: Path(path).name == clean_root.name,
    )
    with pytest.raises(RuntimeError, match="reparse root"):
        freeze_design_v4.verify_design_bundle(
            clean_root, expected_checksums_raw_sha256=clean_checksum
        )
    monkeypatch.setattr(
        freeze_design_v4,
        "_windows_reparse_point",
        lambda path: Path(path).name == "REPORT.md",
    )
    with pytest.raises(RuntimeError, match="non-regular child"):
        freeze_design_v4.verify_design_bundle(
            clean_root, expected_checksums_raw_sha256=clean_checksum
        )
