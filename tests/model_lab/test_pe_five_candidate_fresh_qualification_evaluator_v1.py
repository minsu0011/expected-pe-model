from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
from typing import Iterator

import pytest

from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.contract import (
    C1_ID,
    C2_ID,
    C3_ID,
    C4_ID,
    C5_ID,
    CANDIDATE_IDS,
    CHAMPION_ID,
    DGP_IDS,
    IDENTITY_COLUMNS,
    IDENTITY_COUNT,
    MODEL_IDS,
    PREDICTION_COLUMNS,
    SCORECARD_COLUMNS,
    SEED_ALIASES,
    FinalPretruthBinding,
    OneShotCustodyVerification,
    QualificationContract,
    QualificationEvaluatorError,
    canonical_json_bytes,
    identity_semantic_sha256,
    validate_research_diagnostics,
    validate_runtime_bindings,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.evaluator import (
    _complementarity,
    _group_indexes,
    _summary,
    decode_prediction_rows,
    decode_truth_rows,
    evaluate_qualification,
    fixed_order_correlation,
    type7_quantile,
)


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = (
    ROOT
    / "research/model_zoo/portfolio_governance_v1/"
    "QUALIFICATION_CERTIFICATION_DESIGN_LOCK_V2.json"
)
HASH = "a" * 64
AUTHORITATIVE_POLICY_SHA256 = (
    "8574fb9a375d4dc93e74201729868ef2e64371544165e2c84d9da1f3c063d112"
)
SOURCE_VERSIONS = {model_id: f"final::{model_id}" for model_id in MODEL_IDS}
ERROR_SCALE = {
    CHAMPION_ID: 1.0,
    C1_ID: 0.8,
    C2_ID: 1.1,
    C3_ID: 0.9,
    C4_ID: 0.95,
}


def _contract() -> QualificationContract:
    raw = LOCK_PATH.read_bytes()
    return QualificationContract.from_json_bytes(
        raw,
        expected_raw_sha256=AUTHORITATIVE_POLICY_SHA256,
    )


def _fold(position: int) -> tuple[str, int, int]:
    fold_number = 12 + (position - 504) // 21
    start = 504 + (fold_number - 12) * 21
    return f"fold_{fold_number:03d}", start - 1, start


def _identity(identity_ordinal: int) -> tuple[str, str, int, str, str, str, int, int]:
    seed_index, remainder = divmod(identity_ordinal, len(DGP_IDS) * 1_296)
    dgp_index, row_index = divmod(remainder, 1_296)
    position = 504 + row_index
    fold_id, train_end, test_start = _fold(position)
    return (
        SEED_ALIASES[seed_index],
        DGP_IDS[dgp_index],
        position,
        f"{20000000 + position:08d}",
        "DGP_ISSUER",
        fold_id,
        train_end,
        test_start,
    )


def _identity_hash() -> str:
    return identity_semantic_sha256(
        _identity(ordinal) for ordinal in range(IDENTITY_COUNT)
    )


def _binding(contract: QualificationContract) -> FinalPretruthBinding:
    payload = {
        "schema_version": "expected_pe.qualification.final_pretruth_binding.v1",
        "qualification_lock_raw_sha256": contract.raw_sha256,
        "prediction_artifact_raw_sha256": HASH,
        "prediction_artifact_semantic_sha256": "b" * 64,
        "post_prediction_audit_raw_sha256": "c" * 64,
        "post_prediction_audit_semantic_sha256": "d" * 64,
        "common_full_identities_semantic_sha256": _identity_hash(),
        "prediction_columns": list(PREDICTION_COLUMNS),
        "source_model_versions": dict(SOURCE_VERSIONS),
    }
    return FinalPretruthBinding.from_mapping(payload, contract=contract)


def _custody(
    contract: QualificationContract,
    binding: FinalPretruthBinding,
) -> OneShotCustodyVerification:
    payload = {
        "schema_version": "expected_pe.qualification.one_shot_custody_verification.v1",
        "qualification_lock_raw_sha256": contract.raw_sha256,
        "prediction_artifact_raw_sha256": binding.payload[
            "prediction_artifact_raw_sha256"
        ],
        "prediction_artifact_semantic_sha256": binding.payload[
            "prediction_artifact_semantic_sha256"
        ],
        "post_prediction_audit_raw_sha256": binding.payload[
            "post_prediction_audit_raw_sha256"
        ],
        "post_prediction_audit_semantic_sha256": binding.payload[
            "post_prediction_audit_semantic_sha256"
        ],
        "common_full_identities_semantic_sha256": binding.payload[
            "common_full_identities_semantic_sha256"
        ],
        "prediction_rows_stream_from_verified_held_artifact": True,
        "post_prediction_audit_links_prediction_artifact": True,
        "verification_completed_before_truth_open": True,
    }
    return OneShotCustodyVerification.from_mapping(
        payload,
        contract=contract,
        final_binding=binding,
    )


def _truth_log(identity_ordinal: int) -> float:
    return 3.0 + (identity_ordinal % 17) * 0.0001


def _champion_error(identity_ordinal: int) -> float:
    sign = -1.0 if identity_ordinal % 2 else 1.0
    return sign * (0.08 + (identity_ordinal % 11) * 0.0002)


def _prediction_row(
    identity_ordinal: int,
    model_ordinal: int,
    *,
    attack: str | None = None,
) -> dict[str, object]:
    identity = list(_identity(identity_ordinal))
    model_id = MODEL_IDS[model_ordinal]
    error = _champion_error(identity_ordinal) * ERROR_SCALE[model_id]
    expected_log = _truth_log(identity_ordinal) + error
    row: dict[str, object] = dict(zip(IDENTITY_COLUMNS, identity, strict=True))
    row.update(
        {
            "pe_model_id": model_id,
            "model_ordinal": model_ordinal,
            "expected_pe": math.exp(expected_log),
            "expected_log_pe": expected_log,
            "uncertainty": 0.01,
            "confidence": 0.5,
            "regime_state": "NON_ROUTING_ALL_REGIMES",
            "specialist_tags": "synthetic",
            "prediction_valid": True,
            "pit_valid": True,
            "source_model_version": SOURCE_VERSIONS[model_id],
            "valuation_state_confidence": 0.5,
            "out_of_distribution_score": "",
            "model_disagreement": 0.01,
            "state_uncertainty": 0.01,
            "applied_alpha": 0.5,
            "raw_log_correction": 0.01,
        }
    )
    if identity_ordinal == 0 and model_ordinal == 0:
        if attack == "model_order":
            row["pe_model_id"] = C1_ID
        elif attack == "invalid":
            row["prediction_valid"] = False
        elif attack == "nonfinite":
            row["expected_log_pe"] = math.inf
        elif attack == "extra_column":
            row["truth_leak"] = 1
    if identity_ordinal == 0 and model_ordinal == 1 and attack == "block_identity":
        row["date"] = "20991231"
    return row


def _prediction_rows(
    *,
    attack: str | None = None,
    identity_limit: int = IDENTITY_COUNT,
) -> Iterator[dict[str, object]]:
    for identity_ordinal in range(identity_limit):
        for model_ordinal in range(len(MODEL_IDS)):
            yield _prediction_row(identity_ordinal, model_ordinal, attack=attack)


def _truth_row(identity_ordinal: int, *, eligible: bool = True) -> dict[str, object]:
    identity = _identity(identity_ordinal)
    log_fair = _truth_log(identity_ordinal)
    row: dict[str, object] = dict(zip(IDENTITY_COLUMNS, identity, strict=True))
    row.update(
        {
            "true_fair_pe": math.exp(log_fair),
            "true_log_fair_pe": log_fair,
            "true_economic_eps_contemporaneous": 1.0,
            "true_pit_eps": 1.0,
            "true_observed_pe": math.exp(log_fair),
            "true_expected_pe_eligible": eligible,
        }
    )
    return row


def _truth_rows() -> Iterator[dict[str, object]]:
    for identity_ordinal in range(IDENTITY_COUNT):
        yield _truth_row(identity_ordinal)


def _research_records(contract: QualificationContract) -> list[dict[str, object]]:
    return [
        {
            "candidate_id": candidate_id,
            "research_candidate_id": record["research_candidate_id"],
            "candidate_summary_raw_sha256": record["candidate_summary_raw_sha256"],
            "checksums_raw_sha256": record["checksums_raw_sha256"],
            "pooled_mae_relative_gain": record["pooled_mae_relative_gain"],
        }
        for candidate_id in CANDIDATE_IDS
        for record in (contract.research_baselines[candidate_id],)
    ]


def _receipt(candidate_ids: tuple[str, ...], lane_id: str) -> dict[str, object]:
    return {
        "schema_version": "expected_pe.qualification.prediction_runtime.v1",
        "status": "PASS_FROZEN_PRETRUTH_RUNTIME",
        "candidate_ids": list(candidate_ids),
        "ended_perf_counter_ns": 2_000,
        "gpu_process_observation_count": 0,
        "lane_id": lane_id,
        "peak_process_tree_rss_bytes": 1_000_000,
        "peak_vram_bytes": 0,
        "process_exit_records": [
            {"process_role": "parent", "worker_ordinal": 0, "exit_code": 0}
        ],
        "sample_count": 2,
        "sample_interval_max_ms": 50.0,
        "started_perf_counter_ns": 1_000,
        "wall_time_ns": 1_000,
    }


def _runtime_bindings() -> list[dict[str, object]]:
    shared = _receipt(CANDIDATE_IDS[:3], "shared_c1_c3")
    isolated = _receipt((C4_ID,), "isolated_c4")
    return [
        {
            "raw_sha256": hashlib.sha256(canonical_json_bytes(shared)).hexdigest(),
            "file_id": {"volume_serial_number": 1, "file_id_128": "1" * 32},
            "receipt": shared,
        },
        {
            "raw_sha256": hashlib.sha256(canonical_json_bytes(isolated)).hexdigest(),
            "file_id": {"volume_serial_number": 1, "file_id_128": "2" * 32},
            "receipt": isolated,
        },
    ]


@pytest.fixture(scope="module")
def full_result():
    contract = _contract()
    binding = _binding(contract)
    return evaluate_qualification(
        contract=contract,
        final_binding=binding,
        custody_verification=_custody(contract, binding),
        prediction_rows=_prediction_rows(),
        truth_rows=_truth_rows(),
        research_diagnostics=_research_records(contract),
        runtime_bindings=_runtime_bindings(),
    )


def test_v2_contract_is_injected_and_tampered_gate_fails_closed() -> None:
    contract = _contract()
    assert contract.payload["status"] == "FROZEN_PRE_TRUTH_SUPERSEDING_POLICY_ONLY"
    attacked = copy.deepcopy(contract.payload)
    attacked["qualification_performance_screen"]["seed_dgp_wins_min"] = 0
    raw = (json.dumps(attacked, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(QualificationEvaluatorError, match="performance gate"):
        QualificationContract.from_json_bytes(
            raw,
            expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_identity_semantic_sha256_policy_and_known_vector() -> None:
    contract = _contract()
    assert (
        contract.payload["prediction_and_truth_geometry"]["identity_semantic_sha256"]
        == "SHA-256 over the byte concatenation, in fixed task/row order, of canonical "
        "JSON lines for each logical eight-field identity encoded as a JSON array in "
        "identity_columns_in_order; each line uses UTF-8, sort_keys=true, "
        "separators=(',',':'), ensure_ascii=false, allow_nan=false, and one terminal LF."
    )
    identity = (
        "qualification_seed_01",
        "A",
        504,
        "20260822",
        "DGP_ISSUER",
        "fold_012",
        503,
        504,
    )
    assert identity_semantic_sha256([identity]) == (
        "d9840a277ea065efc65fc10594bdcb67af41aea66bb5512ae9e1668aabe24d9a"
    )

    attacked = copy.deepcopy(contract.payload)
    attacked["prediction_and_truth_geometry"]["identity_semantic_sha256"] += " drift"
    raw = canonical_json_bytes(attacked)
    with pytest.raises(QualificationEvaluatorError, match="identity semantic"):
        QualificationContract.from_json_bytes(
            raw,
            expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        )


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        (
            "metric_math_contract",
            "seed_win",
            "ties are wins",
            "metric math",
        ),
        (
            "diagnostic_contract",
            "overfit_detector",
            {},
            "overfit detector",
        ),
        (
            "scorecard_contract",
            "columns_in_order",
            ["candidate_id"],
            "scorecard columns",
        ),
    ],
)
def test_new_v2_math_overfit_and_scorecard_contracts_are_exact(
    section: str,
    key: str,
    value: object,
    message: str,
) -> None:
    contract = _contract()
    attacked = copy.deepcopy(contract.payload)
    attacked[section][key] = value
    raw = canonical_json_bytes(attacked)
    with pytest.raises(QualificationEvaluatorError, match=message):
        QualificationContract.from_json_bytes(
            raw,
            expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_final_binding_rejects_pending_source_version_and_schema_drift() -> None:
    contract = _contract()
    binding = dict(_binding(contract).payload)
    binding["source_model_versions"] = dict(binding["source_model_versions"])
    binding["source_model_versions"][C1_ID] = "binding_pending"
    with pytest.raises(QualificationEvaluatorError, match="not final"):
        FinalPretruthBinding.from_mapping(binding, contract=contract)

    binding = dict(_binding(contract).payload)
    binding["prediction_columns"] = list(PREDICTION_COLUMNS[:-1])
    with pytest.raises(QualificationEvaluatorError, match="prediction columns"):
        FinalPretruthBinding.from_mapping(binding, contract=contract)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prediction_artifact_raw_sha256", "9" * 64),
        ("post_prediction_audit_semantic_sha256", "8" * 64),
        ("prediction_rows_stream_from_verified_held_artifact", False),
        ("post_prediction_audit_links_prediction_artifact", False),
        ("verification_completed_before_truth_open", False),
    ],
)
def test_one_shot_custody_verification_links_rows_audit_and_open_order(
    field: str,
    value: object,
) -> None:
    contract = _contract()
    binding = _binding(contract)
    attacked = dict(_custody(contract, binding).payload)
    attacked[field] = value
    with pytest.raises(QualificationEvaluatorError, match="one-shot custody"):
        OneShotCustodyVerification.from_mapping(
            attacked,
            contract=contract,
            final_binding=binding,
        )

@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("model_order", "block order"),
        ("block_identity", "inside a five-model block"),
        ("invalid", "must be true"),
        ("nonfinite", "must be finite"),
        ("extra_column", "columns/order"),
    ],
)
def test_long_decoder_rejects_first_block_attacks(attack: str, message: str) -> None:
    contract = _contract()
    with pytest.raises(QualificationEvaluatorError, match=message):
        decode_prediction_rows(_prediction_rows(attack=attack), binding=_binding(contract))


def test_long_decoder_rejects_truncated_artifact() -> None:
    contract = _contract()
    with pytest.raises(QualificationEvaluatorError, match="ended before 324,000"):
        decode_prediction_rows(
            _prediction_rows(identity_limit=1),
            binding=_binding(contract),
        )


def test_truth_decoder_rejects_identity_and_schema_attacks() -> None:
    identity = _identity(0)
    attacked = _truth_row(0)
    attacked["date"] = "20991231"
    with pytest.raises(QualificationEvaluatorError, match="identity/order"):
        decode_truth_rows([attacked], identities=[identity])

    attacked = _truth_row(0)
    attacked["extra"] = 1
    with pytest.raises(QualificationEvaluatorError, match="columns/order"):
        decode_truth_rows([attacked], identities=[identity])


def test_common_mask_requires_every_frozen_fold() -> None:
    identities = tuple(_identity(task * 1_296) for task in range(50)) + (_identity(21),)
    with pytest.raises(QualificationEvaluatorError, match="required fold"):
        _group_indexes(identities, list(range(50)))


def test_type7_quantile_and_fixed_order_correlation_edge_contracts() -> None:
    assert type7_quantile([0.0, 10.0], 0.95) == 9.5
    perfect = fixed_order_correlation([1.0, 2.0, 3.0], [2.0, 4.0, 6.0])
    assert perfect["status"] == "OK"
    assert perfect["value"] == pytest.approx(1.0)
    assert fixed_order_correlation([1.0], [1.0]) == {
        "value": None,
        "status": "INSUFFICIENT_ROWS",
    }
    assert fixed_order_correlation([1.0, 1.0], [1.0, 2.0]) == {
        "value": None,
        "status": "ZERO_VARIANCE",
    }


def test_oracle_zero_better_standalone_mae_is_null_with_exact_status() -> None:
    pooled = _summary([0.0, 0.0])
    result = _complementarity(
        C1_ID,
        [3.0, 3.0],
        [3.0, 3.0],
        [0.0, 0.0],
        [0.0, 0.0],
        pooled,
        pooled,
    )
    assert result["oracle_marginal_mae_gain_vs_better_standalone"] is None
    assert result["oracle_marginal_gain_status"] == "ZERO_BETTER_STANDALONE_MAE"


def test_research_diagnostic_mismatch_fails_closed() -> None:
    contract = _contract()
    records = _research_records(contract)
    records[0]["pooled_mae_relative_gain"] = 999.0
    with pytest.raises(QualificationEvaluatorError, match="research diagnostic"):
        validate_research_diagnostics(records, contract=contract)


def test_runtime_pretty_canonical_receipt_known_hash() -> None:
    receipt = _receipt(CANDIDATE_IDS[:3], "shared_c1_c3")
    raw = canonical_json_bytes(receipt)
    assert raw.startswith(b'{\n  "candidate_ids": [\n')
    assert raw.endswith(b"\n")
    assert hashlib.sha256(raw).hexdigest() == (
        "9631ebcf2e27e150a3952deb2a345fc4b88c94d3930b8bd1fcab9bfdcd5b03aa"
    )


@pytest.mark.parametrize(
    "attack",
    [
        "hash",
        "compact_hash",
        "schema",
        "status",
        "lane",
        "gpu",
        "exit",
        "order",
        "attribution",
        "interval",
    ],
)
def test_runtime_receipt_attacks_fail_closed(attack: str) -> None:
    bindings = _runtime_bindings()
    if attack == "hash":
        bindings[0]["raw_sha256"] = HASH
    elif attack == "compact_hash":
        compact = (
            json.dumps(
                bindings[0]["receipt"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        bindings[0]["raw_sha256"] = hashlib.sha256(compact).hexdigest()
    elif attack == "schema":
        bindings[0]["receipt"]["schema_version"] = "drift"
    elif attack == "status":
        bindings[0]["receipt"]["status"] = "PASS_BUT_NOT_FROZEN"
    elif attack == "lane":
        bindings[0]["receipt"]["lane_id"] = "wrong_lane"
    elif attack == "gpu":
        bindings[0]["receipt"]["peak_vram_bytes"] = 1
    elif attack == "exit":
        bindings[0]["receipt"]["process_exit_records"][0]["exit_code"] = 1
    elif attack == "order":
        bindings[0]["receipt"]["process_exit_records"] = [
            {"process_role": "worker", "worker_ordinal": 1, "exit_code": 0},
            {"process_role": "parent", "worker_ordinal": 0, "exit_code": 0},
        ]
    elif attack == "attribution":
        bindings[0]["receipt"]["candidate_ids"] = [C1_ID]
    else:
        bindings[0]["receipt"]["sample_interval_max_ms"] = 100.1
    if attack not in ("hash", "compact_hash"):
        bindings[0]["raw_sha256"] = hashlib.sha256(
            canonical_json_bytes(bindings[0]["receipt"])
        ).hexdigest()
    with pytest.raises(QualificationEvaluatorError):
        validate_runtime_bindings(bindings)


def test_canonical_json_object_key_order_is_semantically_inert() -> None:
    contract = _contract()
    original_binding = _binding(contract)
    binding_payload = json.loads(canonical_json_bytes(dict(original_binding.payload)))
    rebound = FinalPretruthBinding.from_mapping(binding_payload, contract=contract)
    assert tuple(rebound.source_model_versions) == MODEL_IDS

    custody_payload = json.loads(
        canonical_json_bytes(dict(_custody(contract, original_binding).payload))
    )
    recustodied = OneShotCustodyVerification.from_mapping(
        custody_payload,
        contract=contract,
        final_binding=rebound,
    )
    assert recustodied.payload["verification_completed_before_truth_open"] is True

    research_payload = json.loads(canonical_json_bytes(_research_records(contract)))
    validated_research = validate_research_diagnostics(research_payload, contract=contract)
    assert tuple(validated_research) == CANDIDATE_IDS

    runtime_payload = json.loads(canonical_json_bytes(_runtime_bindings()))
    validated_runtime = validate_runtime_bindings(runtime_payload)
    assert validated_runtime[0]["receipt"]["process_exit_records"] == [
        {"exit_code": 0, "process_role": "parent", "worker_ordinal": 0}
    ]


def test_full_324k_decoder_metrics_gates_rank_and_terminal_c5(full_result) -> None:
    assert full_result.geometry == {
        **full_result.geometry,
        "prediction_long_rows": 324_000,
        "identity_rows": 64_800,
        "common_mask_rows": 64_800,
        "seed_count": 5,
        "dgp_count": 10,
        "seed_dgp_cells": 50,
        "fold_blocks": 3_100,
        "candidate_count": 4,
        "model_specific_row_drops": 0,
        "sort_pivot_imputation_or_partial_join": False,
    }
    assert len(full_result.pooled_metrics) == 4
    assert len(full_result.seed_metrics) == 20
    assert len(full_result.dgp_metrics) == 40
    assert len(full_result.seed_dgp_metrics) == 200
    assert len(full_result.dgp_mean_metrics) == 40
    assert len(full_result.fold_metrics) == 12_400

    decisions = {row["candidate_id"]: row for row in full_result.decisions}
    assert decisions[C1_ID]["all_eight_performance_gates_pass"] is True
    assert decisions[C3_ID]["all_eight_performance_gates_pass"] is True
    assert decisions[C4_ID]["all_eight_performance_gates_pass"] is True
    assert decisions[C2_ID]["all_eight_performance_gates_pass"] is False
    assert decisions[C2_ID]["classification"] == "REJECTED"
    assert all(decisions[item]["seed_dgp_wins"] == 50 for item in (C1_ID, C3_ID, C4_ID))
    assert all(decisions[item]["dgp_mean_wins"] == 10 for item in (C1_ID, C3_ID, C4_ID))
    assert all(decisions[item]["seed_wins"] == 5 for item in (C1_ID, C3_ID, C4_ID))
    assert all(
        decisions[item]["direct_dgp_wins"] == 10 for item in (C1_ID, C3_ID, C4_ID)
    )
    assert decisions[C2_ID]["seed_wins"] == 0
    assert decisions[C2_ID]["direct_dgp_wins"] == 0
    assert decisions[C2_ID]["worst_seed_harm"] > 0.0
    assert decisions[C2_ID]["worst_direct_dgp_harm"] > 0.0
    assert [row["candidate_id"] for row in full_result.formal_survivor_ranking] == [
        C1_ID,
        C3_ID,
        C4_ID,
    ]
    assert len(full_result.diagnostic_ranking) == 4
    assert full_result.terminal_c5_record == {
        **full_result.terminal_c5_record,
        "candidate_id": C5_ID,
        "scoreable": False,
        "classification": "RESEARCH_ONLY",
        "current_portfolio_wave_rejected": True,
    }
    assert len(full_result.candidate_scorecard) == 5


def test_exact_33_column_scorecard_and_c5_null_policy(full_result) -> None:
    assert len(SCORECARD_COLUMNS) == 33
    assert all(tuple(row) == SCORECARD_COLUMNS for row in full_result.candidate_scorecard)
    for row in full_result.candidate_scorecard[:4]:
        assert row["fresh_qualification_status"] == "SCORED_EXACT_QUALIFICATION"
        assert row["deployable"] is False
        assert row["pit_safe"] is True
        assert row["causal_safe"] is True
        assert row["seed_total"] == 5
        assert row["dgp_total"] == 10
        assert row["portfolio_role"] in {
            "CERTIFIED_SURVIVOR",
            "PORTFOLIO_SPECIALIST_CANDIDATE",
            "DIVERSITY_CANDIDATE",
            "REJECTED",
            "RESEARCH_ONLY",
        }

    c5 = full_result.candidate_scorecard[4]
    unavailable = SCORECARD_COLUMNS[
        SCORECARD_COLUMNS.index("mae") : SCORECARD_COLUMNS.index("deployable")
    ]
    assert all(c5[field] is None for field in unavailable)
    assert c5["deployable"] is False
    assert c5["pit_safe"] is None
    assert c5["causal_safe"] is None
    assert c5["fresh_qualification_status"] == "NOT_RUN_TERMINAL_CUSTODY_NO_GO"
    assert c5["portfolio_role"] == "RESEARCH_ONLY"
    assert c5["certification_status"] == "NOT_RUN_TERMINAL_CUSTODY_NO_GO"


def test_overfit_diagnostics_are_exact_fresh_safe_definitions(full_result) -> None:
    decisions = {row["candidate_id"]: row for row in full_result.decisions}
    pooled = {row["candidate_id"]: row for row in full_result.pooled_metrics}
    for candidate_id in CANDIDATE_IDS:
        decision = decisions[candidate_id]
        assert decision["seed_mae_gain_population_variance"] >= 0.0
        assert decision["dgp_mean_gain_population_variance"] >= 0.0
        assert decision["fold_mae_gain_population_variance"] >= 0.0
        expected_p95_deterioration = (
            pooled[candidate_id]["candidate_p95_absolute_error"]
            - pooled[candidate_id]["champion_p95_absolute_error"]
        ) / pooled[candidate_id]["champion_p95_absolute_error"]
        assert decision["p95_relative_deterioration"] == expected_p95_deterioration
        assert decision["extreme_frequency_deterioration"] == (
            pooled[candidate_id]["candidate_extreme_error_frequency"]
            - pooled[candidate_id]["champion_extreme_error_frequency"]
        )
        assert decision["parameter_sensitivity"] is None
        assert decision["parameter_sensitivity_status"] == "NOT_REESTIMATED_ON_FRESH"
        assert decision["prediction_instability"] is None
        assert decision["prediction_instability_status"] == "NOT_REMEASURED_ON_FRESH"


def test_diagnostics_are_bound_not_runtime_measured(full_result) -> None:
    assert full_result.bound_diagnostics["diagnostics_are_pretruth_bound_inputs"] is True
    assert full_result.bound_diagnostics["runtime_measured_by_evaluator"] is False
    assert full_result.bound_diagnostics["oracle_is_achievable_model_or_gate"] is False
    assert full_result.bound_diagnostics["one_shot_custody_verification"][
        "prediction_rows_stream_from_verified_held_artifact"
    ] is True
    assert full_result.bound_diagnostics["one_shot_custody_verification"][
        "post_prediction_audit_links_prediction_artifact"
    ] is True
    decisions = {row["candidate_id"]: row for row in full_result.decisions}
    assert decisions[C1_ID]["runtime_attribution"] == "SHARED_NOT_SEPARATELY_ATTRIBUTABLE"
    assert decisions[C4_ID]["runtime_attribution"] == "ISOLATED"
    for candidate_id in CANDIDATE_IDS:
        expected = (
            decisions[candidate_id]["pooled_mae_relative_gain"]
            - decisions[candidate_id]["research_pooled_mae_relative_gain"]
        )
        assert decisions[candidate_id]["research_vs_qualification_gap"] == expected


def test_result_payload_is_strict_json_serializable(full_result) -> None:
    raw = json.dumps(full_result.as_payload(), allow_nan=False, sort_keys=True)
    assert '"candidate_id": "cvtcn_v8_private_process_tcn_residual"' in raw
