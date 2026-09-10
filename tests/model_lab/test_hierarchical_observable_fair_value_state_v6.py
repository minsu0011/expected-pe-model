from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v6 import (
    R4_INPUT_BINDING,
    V5_DESIGN_FREEZE_BINDING,
    V5_INDEPENDENT_AUDIT_BINDING,
    FrozenHierarchicalParametersV6,
    HierarchicalStateV6ContractError,
    adapt_r4_canonical_source_v6,
    build_decision_batch_v6,
    build_frozen_parameter_bundle_bytes,
    build_hierarchical_state_features_v6,
    build_r4_fold_plan_v6,
    build_r4_input_closure_v6,
    capture_runtime_receipt_v6,
    contract_payload,
    contract_sha256,
    decision_block_ordered_membership_sha256_v6,
    decision_block_set_membership_sha256_v6,
    decision_source_positions_sha256_v6,
    fit_chronological_prefix_v6,
    load_frozen_parameter_bundle,
    run_frozen_decision_block_v6,
    run_source_audit_v6,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v6.contracts import (
    IDENTITY_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    R4_FOLDS_PER_TASK,
    R4_TOTAL_DECISION_ROWS,
    R4_TOTAL_FIT_COUNT,
    canonical_json_bytes,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v6.source_audit import (
    DECLARED_SOURCE_PATHS,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v6 import (
    freeze_design as freeze_design_v6,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
R4_ROOT = PROJECT_ROOT / str(R4_INPUT_BINDING["path"])


def _source(rows: int = 525, entities: tuple[str, ...] = ("ENTITY_A",)) -> pd.DataFrame:
    dates = pd.bdate_range("2022-01-03", periods=rows)
    records: list[dict[str, object]] = []
    for entity_number, entity_id in enumerate(entities):
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


def _block_identities(source: pd.DataFrame, start: int = 504) -> pd.DataFrame:
    state = build_hierarchical_state_features_v6(source)
    dates = pd.Index(pd.to_datetime(source["date"]).unique()).sort_values()
    selected_dates = dates[start:]
    mask = state.identities[IDENTITY_COLUMNS[1]].isin(selected_dates)
    return state.identities.loc[mask].copy()


@pytest.fixture(scope="module")
def fitted_case():
    source = _source()
    requested = _block_identities(source)
    capability = fit_chronological_prefix_v6(
        source,
        decision_block_identities=requested,
        observed_pe=source["observed_pe"],
        research_dgp_groups=source["research_dgp_id"],
    )
    return source, requested, capability


@pytest.fixture(scope="module")
def public_closure():
    return build_r4_input_closure_v6(PROJECT_ROOT)


def _write_payloads(root: Path, payloads: dict[str, bytes]) -> str:
    root.mkdir()
    for name, content in payloads.items():
        (root / name).write_bytes(content)
    return hashlib.sha256(payloads["CHECKSUMS.sha256"]).hexdigest()


def _json_bytes(payload: dict[str, object]) -> bytes:
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


def _seal(payload: dict[str, object]) -> dict[str, object]:
    output = dict(payload)
    output.pop("manifest_sha256", None)
    output["manifest_sha256"] = hashlib.sha256(canonical_json_bytes(output)).hexdigest()
    return output


def test_contract_lineage_geometry_runtime_and_new_identity() -> None:
    payload = contract_payload()
    geometry = payload["dgp_r4_execution_geometry"]
    assert len(MODEL_FEATURE_COLUMNS) == 17
    assert len(OUTPUT_COLUMNS) == 5
    assert len(contract_sha256()) == 64
    assert payload["candidate"]["candidate_id"] == ("hofs_v6_huber_soft_pool_state_dgp_r4_blocked")
    assert payload["v5_independent_no_go_audit_binding"] == V5_INDEPENDENT_AUDIT_BINDING
    assert payload["v5_design_freeze_binding"] == V5_DESIGN_FREEZE_BINDING
    assert payload["r4_public_input_binding"] == R4_INPUT_BINDING
    assert V5_INDEPENDENT_AUDIT_BINDING["severity_counts"] == {
        "P0": 0,
        "P1": 1,
        "P2": 0,
    }
    assert payload["decision_block_order_custody"]["incoming_order_policy"] == (
        "REJECT_WITHOUT_SILENT_SORT"
    )
    assert geometry["fit_count"] == 3100
    assert geometry["decision_row_count"] == 64800
    assert geometry["within_block_parameter_update_count"] == 0
    assert payload["runtime_plan"]["max_outer_workers"] == 32
    assert payload["runtime_plan"]["inner_threads"] == 1


def test_exact_r4_fold_plan_has_3100_fits_and_64800_rows() -> None:
    plan = build_r4_fold_plan_v6()
    assert len(plan) == R4_TOTAL_FIT_COUNT
    assert sum(item.decision_row_count for item in plan) == R4_TOTAL_DECISION_ROWS
    first_task = plan[:R4_FOLDS_PER_TASK]
    assert first_task[0].fit_prefix_end_exclusive == 504
    assert first_task[0].decision_row_count == 21
    assert first_task[-1].decision_row_count == 15
    assert all(item.within_block_parameter_update_count == 0 for item in plan)


def test_public_r4_closure_is_exact_and_score_blind(public_closure) -> None:
    assert public_closure["status"].startswith("PASS_EXACT_PUBLIC_R4")
    assert len(public_closure["public_files"]) == 150
    assert public_closure["public_files_sha256"] == R4_INPUT_BINDING["bound_public_files_sha256"]
    assert public_closure["geometry"]["fit_count"] == 3100
    assert public_closure["geometry"]["decision_row_count"] == 64800
    assert all(
        item["expected_row_count"] == 199
        and item["unexpected_malformed_row_count"] == 0
        and item["decision_expected_warmup_row_count"] == 0
        for item in public_closure["task_regime_receipts"]
    )
    assert public_closure["access"]["real_fit_count"] == 0
    assert public_closure["access"]["real_prediction_count"] == 0
    assert public_closure["access"]["score_call_count"] == 0
    assert public_closure["access"]["model_registry_file_read_count"] == 0


def test_public_canonical_adapter_is_schema_restricting() -> None:
    path = R4_ROOT / "replays/pass_1/seed_2026082001/dgp_A/canonical150.csv"
    canonical = pd.read_csv(path)
    adapted = adapt_r4_canonical_source_v6(canonical)
    assert len(adapted) == 1800
    assert len(adapted.columns) == 22
    assert "expected_pe" not in adapted.columns
    assert "ml_expected_pe" not in adapted.columns


def test_expected_regime_warmup_is_separate_hashed_and_uniform() -> None:
    source = _source(rows=220)
    source.loc[:4, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    state = build_hierarchical_state_features_v6(source)
    assert state.expected_regime_warmup_prefix_count == 5
    assert state.regime_fallback_count == 0
    assert len(state.expected_regime_warmup_prefix_sha256) == 64
    assert state.expected_regime_warmup_prefix_mask.iloc[:5].all()
    assert np.allclose(
        state.features.loc[:4, list(MODEL_FEATURE_COLUMNS[-3:])].to_numpy(),
        1.0 / 3.0,
    )


def test_noncontiguous_missing_regime_is_unexpected_not_expected() -> None:
    source = _source(rows=220)
    source.loc[:1, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    source.loc[10, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    state = build_hierarchical_state_features_v6(source)
    assert state.expected_regime_warmup_prefix_count == 2
    assert state.regime_fallback_count == 1
    assert state.regime_fallback_mask.iloc[10]


def test_expected_regime_warmup_above_199_fails_closed() -> None:
    source = _source(rows=220)
    source.loc[:199, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    with pytest.raises(HierarchicalStateV6ContractError, match="sealed maximum"):
        build_hierarchical_state_features_v6(source)


def test_expected_regime_warmup_is_forbidden_in_decision_block() -> None:
    first = _source(rows=525)
    second = _source(rows=21).assign(entity_id="ENTITY_B")
    second["date"] = pd.bdate_range(first["date"].iloc[504], periods=21)
    second.loc[:, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    source = (
        pd.concat([first, second], ignore_index=True)
        .sort_values(["date", "entity_id"], kind="mergesort")
        .reset_index(drop=True)
    )
    state = build_hierarchical_state_features_v6(source)
    dates = pd.to_datetime(state.identities[IDENTITY_COLUMNS[1]])
    requested = state.identities.loc[dates >= pd.Timestamp(first["date"].iloc[504])]
    with pytest.raises(HierarchicalStateV6ContractError, match="forbidden in a decision block"):
        build_decision_batch_v6(state, requested)


def test_unexpected_decision_malformed_gate_uses_exact_block_denominator() -> None:
    source = _source()
    source.loc[504, ["p_bear", "p_sideways", "p_bull"]] = (-1.0, 0.0, 0.0)
    state = build_hierarchical_state_features_v6(source)
    requested = _block_identities(source)
    with pytest.raises(HierarchicalStateV6ContractError, match="fallback limit"):
        build_decision_batch_v6(state, requested)


def test_first_fold_receipts_exact_504_equals_1_plus_503(fitted_case) -> None:
    _, _, capability = fitted_case
    receipt = capability.fit.fit_receipt
    assert receipt.prefix_entity_row_counts == (("ENTITY_A", 504, 1, 503),)
    assert receipt.requested_row_count == 504
    assert receipt.causal_first_row_nonwarm_row_count == 1
    assert receipt.dropped_nonwarm_row_count == 1
    assert receipt.fit_row_count == 503
    assert receipt.final_kkt_violation <= 1e-10
    assert receipt.expected_regime_warmup_prefix_count == 0


def test_prefix_below_504_and_interior_nonwarm_attacks_fail_before_solver() -> None:
    short = _source(rows=524)
    requested = _block_identities(short, start=503)
    with pytest.raises(HierarchicalStateV6ContractError, match="prefix"):
        fit_chronological_prefix_v6(
            short,
            decision_block_identities=requested,
            observed_pe=short["observed_pe"],
            research_dgp_groups=short["research_dgp_id"],
        )
    source = _source()
    requested = _block_identities(source)
    observed = source["observed_pe"].copy()
    observed.iloc[100] = np.nan
    with pytest.raises(HierarchicalStateV6ContractError, match="causal-first-row"):
        fit_chronological_prefix_v6(
            source,
            decision_block_identities=requested,
            observed_pe=observed,
            research_dgp_groups=source["research_dgp_id"],
        )


def test_valid_block_uses_one_parameter_hash_and_zero_updates(fitted_case) -> None:
    source, requested, capability = fitted_case
    output = run_frozen_decision_block_v6(
        source,
        requested_identities=requested,
        parameters=capability.fit.parameters,
    )
    assert len(output.values) == 21
    assert output.decision_distinct_date_count == 21
    assert output.decision_block_ordered_membership_sha256 == (
        decision_block_ordered_membership_sha256_v6(requested)
    )
    assert output.decision_block_set_membership_sha256 == decision_block_set_membership_sha256_v6(
        requested
    )
    assert output.identity_order_sha256 == output.decision_block_ordered_membership_sha256
    assert len(output.decision_source_positions_sha256) == 64
    assert len(output.output_manifest_sha256) == 64
    assert output.parameter_sha256 == capability.fit.parameters.sha256()
    assert output.within_block_parameter_update_count == 0
    assert np.isfinite(output.values.to_numpy()).all()


def test_reverse_order_is_rejected_without_silent_sort_and_set_hash_is_stable() -> None:
    source = _source()
    state = build_hierarchical_state_features_v6(source)
    requested = _block_identities(source)
    reversed_request = requested.iloc[::-1].copy()
    assert decision_block_set_membership_sha256_v6(reversed_request) == (
        decision_block_set_membership_sha256_v6(requested)
    )
    with pytest.raises(HierarchicalStateV6ContractError, match="not already in exact canonical"):
        decision_block_ordered_membership_sha256_v6(reversed_request)
    with pytest.raises(HierarchicalStateV6ContractError, match="not already in exact canonical"):
        build_decision_batch_v6(state, reversed_request)


def test_arbitrary_permutation_and_duplicate_identity_are_rejected() -> None:
    source = _source()
    state = build_hierarchical_state_features_v6(source)
    requested = _block_identities(source)
    permutation = [5, *range(5), *range(6, len(requested))]
    permuted = requested.iloc[permutation].copy()
    with pytest.raises(HierarchicalStateV6ContractError, match="not already in exact canonical"):
        build_decision_batch_v6(state, permuted)

    duplicated = requested.copy()
    duplicated.iloc[6] = duplicated.iloc[5]
    with pytest.raises(HierarchicalStateV6ContractError, match="one-to-one"):
        build_decision_batch_v6(state, duplicated)


def test_canonical_date_cross_block_substitution_is_rejected_by_exact_coverage() -> None:
    source = _source()
    state = build_hierarchical_state_features_v6(source)
    requested = _block_identities(source)
    crossed = requested.copy()
    crossed.iloc[0] = state.identities.iloc[503]
    with pytest.raises(HierarchicalStateV6ContractError, match="does not exactly cover"):
        build_decision_batch_v6(state, crossed)


def test_canonical_endpoint_rows_and_source_positions_are_exactly_bound() -> None:
    source = _source(rows=506, entities=("ENTITY_A", "ENTITY_B"))
    state = build_hierarchical_state_features_v6(source)
    requested = _block_identities(source)
    batch = build_decision_batch_v6(state, requested)
    assert batch.decision_block_first_entity_id == "ENTITY_A"
    assert batch.decision_block_last_entity_id == "ENTITY_B"
    assert (
        batch.decision_block_start_date
        == pd.Timestamp(requested[IDENTITY_COLUMNS[1]].iloc[0]).isoformat()
    )
    assert (
        batch.decision_block_end_date
        == pd.Timestamp(requested[IDENTITY_COLUMNS[1]].iloc[-1]).isoformat()
    )
    assert batch.source_positions == tuple(sorted(batch.source_positions))
    assert batch.decision_source_positions_sha256 == decision_source_positions_sha256_v6(
        requested,
        source_state_sha256=batch.source_state_sha256,
        source_positions=batch.source_positions,
        source_row_count=batch.source_row_count,
    )
    with pytest.raises(HierarchicalStateV6ContractError, match="strictly increasing"):
        decision_source_positions_sha256_v6(
            requested,
            source_state_sha256=batch.source_state_sha256,
            source_positions=tuple(reversed(batch.source_positions)),
            source_row_count=batch.source_row_count,
        )


def test_fit_parameter_batch_and_output_manifest_share_all_order_custody(fitted_case) -> None:
    source, requested, capability = fitted_case
    parameters = capability.fit.parameters
    receipt = capability.fit.fit_receipt
    output = run_frozen_decision_block_v6(
        source,
        requested_identities=requested,
        parameters=parameters,
    )
    ordered = decision_block_ordered_membership_sha256_v6(requested)
    set_membership = decision_block_set_membership_sha256_v6(requested)
    assert parameters.decision_block_ordered_membership_sha256 == ordered
    assert receipt.decision_block_ordered_membership_sha256 == ordered
    assert output.decision_block_ordered_membership_sha256 == ordered
    assert parameters.decision_block_set_membership_sha256 == set_membership
    assert receipt.decision_block_set_membership_sha256 == set_membership
    assert output.decision_block_set_membership_sha256 == set_membership
    assert parameters.decision_source_positions_sha256 == (receipt.decision_source_positions_sha256)
    assert output.decision_source_positions_sha256 == (parameters.decision_source_positions_sha256)
    manifest = output.output_manifest_payload()
    assert manifest["decision_block_ordered_membership_sha256"] == ordered
    assert manifest["decision_block_set_membership_sha256"] == set_membership
    assert manifest["decision_source_positions_sha256"] == (
        parameters.decision_source_positions_sha256
    )
    assert manifest["decision_block_first_entity_id"] == requested.iloc[0][IDENTITY_COLUMNS[0]]
    assert manifest["decision_block_last_entity_id"] == requested.iloc[-1][IDENTITY_COLUMNS[0]]


def test_removed_shifted_and_single_date_block_attacks_fail(fitted_case) -> None:
    source, requested, capability = fitted_case
    with pytest.raises(HierarchicalStateV6ContractError):
        run_frozen_decision_block_v6(
            source,
            requested_identities=requested.iloc[:-1].copy(),
            parameters=capability.fit.parameters,
        )
    shifted = requested.copy()
    shifted[IDENTITY_COLUMNS[1]] = shifted[IDENTITY_COLUMNS[1]] + pd.Timedelta(days=1)
    with pytest.raises(HierarchicalStateV6ContractError):
        run_frozen_decision_block_v6(
            source,
            requested_identities=shifted,
            parameters=capability.fit.parameters,
        )
    single = requested.iloc[:1].copy()
    with pytest.raises(HierarchicalStateV6ContractError, match="multiple"):
        build_decision_batch_v6(build_hierarchical_state_features_v6(source), single)


def test_update_and_membership_parameter_constructor_attacks_fail(fitted_case) -> None:
    _, _, capability = fitted_case
    parameters = capability.fit.parameters
    with pytest.raises(HierarchicalStateV6ContractError, match="block receipt"):
        replace(parameters, within_block_parameter_update_count=1)
    with pytest.raises(HierarchicalStateV6ContractError):
        replace(parameters, decision_block_ordered_membership_sha256="not-a-sha")


def test_live_expected_warmup_mask_mutation_is_custody_bound() -> None:
    source = _source(rows=220)
    source.loc[:4, ["p_bear", "p_sideways", "p_bull"]] = np.nan
    state = build_hierarchical_state_features_v6(source)
    state.expected_regime_warmup_prefix_mask.iloc[3] = False
    with pytest.raises(HierarchicalStateV6ContractError):
        state.assert_live_integrity()


def test_parameter_artifact_round_trip_and_fully_resealed_membership_attack(
    tmp_path: Path,
    fitted_case,
) -> None:
    _, _, capability = fitted_case
    payloads = build_frozen_parameter_bundle_bytes(capability.fit)
    good = tmp_path / "good"
    checksum = _write_payloads(good, payloads)
    loaded = load_frozen_parameter_bundle(
        good,
        expected_checksums_raw_sha256=checksum,
    )
    assert loaded.parameters == capability.fit.parameters

    attacked = dict(payloads)
    parameters = json.loads(attacked["PARAMETERS.json"].decode("ascii"))
    parameters["decision_block_ordered_membership_sha256"] = "a" * 64
    attacked["PARAMETERS.json"] = _json_bytes(parameters)
    manifest = json.loads(attacked["MANIFEST.json"].decode("ascii"))
    manifest["parameter_sha256"] = hashlib.sha256(canonical_json_bytes(parameters)).hexdigest()
    manifest["file_raw_sha256"]["PARAMETERS.json"] = hashlib.sha256(
        attacked["PARAMETERS.json"]
    ).hexdigest()
    attacked["MANIFEST.json"] = _json_bytes(_seal(manifest))
    attacked["CHECKSUMS.sha256"] = "".join(
        f"{hashlib.sha256(attacked[name]).hexdigest()}  {name}\n"
        for name in sorted(attacked)
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    attack_root = tmp_path / "attack"
    attack_checksum = _write_payloads(attack_root, attacked)
    with pytest.raises(HierarchicalStateV6ContractError, match="custody drifted"):
        load_frozen_parameter_bundle(
            attack_root,
            expected_checksums_raw_sha256=attack_checksum,
        )


def test_runtime_receipt_pins_outer32_inner1_cpu_gpu_and_py310() -> None:
    receipt = capture_runtime_receipt_v6(purpose="PREFLIGHT")
    assert receipt.python_version == "3.10.19"
    assert receipt.outer_workers == 32
    assert receipt.inner_threads == 1
    assert receipt.cpu_ids == tuple(range(32))
    assert receipt.gpu_used is False


def test_source_audit_closes_v5_no_go_and_rejects_partial_registry_surfaces() -> None:
    audit = run_source_audit_v6(PROJECT_ROOT)
    assert audit.passed
    assert audit.v5_audit_raw_sha256 == V5_INDEPENDENT_AUDIT_BINDING["raw_sha256"]
    assert audit.v5_design_checksums_raw_sha256 == V5_DESIGN_FREEZE_BINDING["checksums_raw_sha256"]
    assert audit.forbidden_import_hits == ()
    assert audit.score_call_count == 0
    assert audit.registry_mutation_count == 0


def test_no_single_date_parameter_or_receipt_field_survives() -> None:
    names = {field.name for field in fields(FrozenHierarchicalParametersV6)}
    assert "decision_block_start_date" in names
    assert "decision_block_end_date" in names
    assert "decision_block_ordered_membership_sha256" in names
    assert "decision_block_set_membership_sha256" in names
    assert "decision_source_positions_sha256" in names
    assert "within_block_parameter_update_count" in names
    assert "frozen_" + "for_decision_date" not in names
    forbidden = (
        "frozen_" + "for_decision_date",
        "decision_" + "session_v6",
        "decision_" + "membership_sha256",
    )
    for relative_path in DECLARED_SOURCE_PATHS:
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert all(token not in source for token in forbidden)


def test_design_bundle_cross_seals_input_audit_and_contract(public_closure, tmp_path: Path) -> None:
    assert public_closure["geometry"]["fit_count"] == 3100
    bundle = freeze_design_v6.build_design_bundle_bytes(PROJECT_ROOT)
    root = tmp_path / "design"
    checksum = _write_payloads(root, bundle)
    receipt = freeze_design_v6.verify_design_bundle(
        root,
        expected_checksums_raw_sha256=checksum,
    )
    assert receipt["status"] == "PASS_EXACT_V6_DESIGN_BUNDLE_CLOSURE"
    assert set(bundle) == set(freeze_design_v6.FINAL_FILE_UNIVERSE)


@pytest.mark.parametrize(
    "field_name",
    (
        "decision_block_start_date",
        "decision_block_end_date",
        "decision_block_first_entity_id",
        "decision_block_last_entity_id",
        "decision_ordered_identity_rows",
        "decision_source_state_sha256",
        "decision_source_positions",
        "decision_source_row_count",
        "decision_block_ordered_membership_sha256",
        "decision_block_set_membership_sha256",
        "decision_source_positions_sha256",
        "decision_row_count",
        "decision_distinct_date_count",
        "within_block_parameter_update_count",
    ),
)
def test_all_block_fields_are_present_in_parameter_payload(fitted_case, field_name: str) -> None:
    _, _, capability = fitted_case
    assert field_name in capability.fit.parameters.payload()
