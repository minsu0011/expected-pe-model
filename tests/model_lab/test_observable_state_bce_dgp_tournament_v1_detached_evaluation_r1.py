from __future__ import annotations

from dataclasses import asdict
import json
import math
from pathlib import Path

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.contract import (  # noqa: E501
    BCE_B_ID,
    BCE_D_ID,
    CANDIDATES,
    DESIGN_PINS,
    DGP_IDS,
    FIXED_040_ID,
    FROZEN_IMPORT_ROOT,
    GATE,
    PREDICTION_PINS,
    R3_GO,
    R3_PINS,
    RANKING_RULE,
    SEED_ALIASES,
    SUPERSEDED_PINS,
    SUPERSEDED_PREFLIGHT_R1_PINS,
    SUPERSEDED_PREFLIGHT_R2_PINS,
    VAULT_PINS,
    EvaluationContractError,
    contract_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.custody import (  # noqa: E501
    source_boundary_audit,
    verify_independent_pre_score_go,
    windows_resource_guard,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.evaluator import (  # noqa: E501
    evaluate_joined_rows,
    join_predictions_and_truth,
)


def _synthetic_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    target = 10.0
    errors = {
        "incumbent__v04_expected_pe": 0.10,
        "candidate__bce_b": 0.09,
        "candidate__bce_d": 0.08,
        "candidate__fixed_alpha_040": 0.095,
        "challenger__lgbm_full_state": 0.07,
        "challenger__histgb_full_state": 0.06,
    }
    position = 504
    for seed_alias in SEED_ALIASES:
        for dgp_id in DGP_IDS:
            row: dict[str, object] = {
                "seed_alias": seed_alias,
                "dgp_id": dgp_id,
                "date": f"2020-01-{position % 28 + 1:02d}",
                "session_position": position,
                "fold_id": "fold_012",
                "true_fair_pe": target,
            }
            row.update({column: target * math.exp(error) for column, error in errors.items()})
            rows.append(row)
            position += 1
    return rows


def test_contract_is_exact_and_research_only() -> None:
    payload = contract_payload()
    assert [candidate for candidate, _ in CANDIDATES] == [
        BCE_B_ID,
        BCE_D_ID,
        FIXED_040_ID,
    ]
    assert asdict(GATE) == {
        "pooled_mae_relative_gain_min": 0.005,
        "pooled_rmse_relative_gain_min": 0.0,
        "seed_dgp_wins_min": 30,
        "seed_dgp_total": 50,
        "dgp_mean_wins_min": 6,
        "dgp_total": 10,
        "worst_dgp_mean_harm_max": 0.03,
        "worst_seed_dgp_harm_max": 0.05,
        "pooled_p95_non_worse": True,
        "pooled_extreme_frequency_non_worse": True,
    }
    assert RANKING_RULE == (
        "lowest_worst_dgp_mean_harm",
        "most_dgp_mean_wins",
        "highest_pooled_mae_relative_gain",
        "candidate_id_ascending",
    )
    assert payload["authority"] == {
        "one_detached_evaluation": True,
        "prediction_rerun": False,
        "model_fit": False,
        "parameter_or_alpha_sweep": False,
        "fresh_or_heldout": False,
        "promotion": False,
        "registry_or_champion_mutation": False,
    }


def test_frozen_pins_and_r3_supersession_are_exact() -> None:
    assert PREDICTION_PINS["PREDICTIONS.csv"] == (
        "f2d38f9de31aa89d502050babb5df185fd35a30851701eb3a90e8c50fe64064b"
    )
    assert PREDICTION_PINS["FOLD_DIAGNOSTICS.json"] == (
        "b5dc9d37f81736e91e512594fa002d79ae47bbbc9ac7e72b20d07084ec62b814"
    )
    assert PREDICTION_PINS["PREDICTION_MANIFEST.json"] == (
        "c78c942df28809696435fd90b5a3220fa3f3298a7db57d33a13f95f5cd7aab2d"
    )
    assert PREDICTION_PINS["CHECKSUMS.sha256"] == (
        "af2d910510ff31b988776ddcd5842628f6a4c991f4f19ee487bcc1b5a66ca624"
    )
    assert R3_PINS["AUDIT.json"] == (
        "8a6119b74cb0243f6b54cdd5bce7d5412bc4ffa8e8f1a7532963022951ac688d"
    )
    assert R3_PINS["AUDIT.semantic"] == (
        "f6b7af9d24ee372a2c0f5e0116b638e47543dde9473765c1270835ff14b56774"
    )
    assert R3_GO == "GO_ONE_DETACHED_RESEARCH_ONLY_DGP_TOURNAMENT_EVALUATION"
    assert SUPERSEDED_PINS["r1"]["status"] == "FAIL_CLOSED"
    assert SUPERSEDED_PINS["r2"]["status"] == "FAIL_CLOSED"
    assert DESIGN_PINS["DESIGN_LOCK.json"] == (
        "06c932070df18312eeda94362bcdccdb83a7bfb98c0986d02952cc02ced62509"
    )
    assert VAULT_PINS == {
        "VAULT_RECEIPT.json": (
            "93c414a8d15d1a2cce0d0c173cb1ccd2d79001d003a8962d12b331ce98a3888b"
        ),
        "CHECKSUMS.sha256": (
            "9139db5aff9ec248da01185d3778a172fe8f04445a3ebc21db8f7473c38562f2"
        ),
    }
    assert SUPERSEDED_PREFLIGHT_R1_PINS["CHECKSUMS.sha256"] == (
        "978f8b484b3f40af278287ab22c992206c7b4771f7f78fdf4ebf56f0cdf401e7"
    )
    assert SUPERSEDED_PREFLIGHT_R2_PINS["CHECKSUMS.sha256"] == (
        "d2e4444c138b20b943b900bbf69d3248ba782dcab47e4feada8bb569cb088932"
    )


def test_fixed_order_metrics_gates_and_ranking() -> None:
    result = evaluate_joined_rows(_synthetic_rows(), enforce_full_geometry=False)
    assert len(result.pooled_metrics) == 3
    assert len(result.seed_dgp_metrics) == 150
    assert len(result.dgp_mean_metrics) == 30
    assert len(result.fold_metrics) == 150
    assert len(result.tail_metrics) == 3
    assert len(result.constituent_diagnostics) == 2
    assert all(bool(row["gate_pass"]) for row in result.decisions)
    assert all(int(row["seed_dgp_wins"]) == 50 for row in result.decisions)
    assert all(int(row["dgp_mean_wins"]) == 10 for row in result.decisions)
    assert all(float(row["worst_dgp_mean_harm"]) == 0.0 for row in result.decisions)
    assert all(float(row["worst_seed_dgp_harm"]) == 0.0 for row in result.decisions)
    assert [row["candidate_id"] for row in result.ranking] == [
        BCE_D_ID,
        BCE_B_ID,
        FIXED_040_ID,
    ]
    assert sum(bool(row["single_research_winner"]) for row in result.ranking) == 1
    assert next(row for row in result.ranking if row["single_research_winner"])[
        "candidate_id"
    ] == BCE_D_ID
    assert all(bool(row["diagnostic_only"]) for row in result.constituent_diagnostics)
    assert not any(bool(row["gate_used"]) for row in result.constituent_diagnostics)
    assert not any(bool(row["rank_used"]) for row in result.constituent_diagnostics)


def test_join_is_exact_one_to_one_and_fails_closed() -> None:
    predictions = [
        {"seed_alias": "research_seed_01", "dgp_id": "A", "date": "2020-01-01"}
    ]
    targets = {("research_seed_01", "A", "2020-01-01"): 10.0}
    with pytest.raises(EvaluationContractError, match="joined identity count differs"):
        join_predictions_and_truth(predictions, targets)
    with pytest.raises(EvaluationContractError, match="one-to-one join differs"):
        join_predictions_and_truth(
            predictions,
            {("research_seed_01", "A", "2020-01-02"): 10.0},
        )


def test_source_scan_explicitly_rejects_frozen_package_import(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed.py"
    forbidden = tmp_path / "forbidden.py"
    launcher = tmp_path / "launcher.py"
    allowed.write_text("import math\n", encoding="utf-8")
    launcher.write_text(
        "from research.model_zoo.observable_state_bce_dgp_tournament_v1_"
        "detached_evaluation_r1 import contract\n",
        encoding="utf-8",
    )
    audit = source_boundary_audit((allowed, launcher), tmp_path)
    assert audit["status"] == "PASS_NO_FROZEN_PREDICTION_PACKAGE_IMPORT"
    assert audit["forbidden_imports"] == []
    forbidden.write_text(f"import {FROZEN_IMPORT_ROOT}.contracts\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="imports the frozen prediction package"):
        source_boundary_audit((forbidden, launcher), tmp_path)


def test_independent_go_requires_audit_in_exact_checksum_universe(tmp_path: Path) -> None:
    audit = {
        "status": "PASS_PRE_SCORE_AUDIT_SEALED",
        "decision": {"overall": "GO_ONE_SHOT_DETACHED_DGP_TOURNAMENT_SCORING"},
        "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
        "bindings": {
            "capability_raw_sha256": "a" * 64,
            "preflight_raw_sha256": "b" * 64,
            "preflight_checksums_raw_sha256": "c" * 64,
            "activation_token": "d" * 64,
        },
        "access_ledger": {
            "truth_payload_opened": False,
            "truth_payload_files_opened": 0,
            "truth_payload_bytes_read": 0,
            "truth_values_read": False,
            "score_computed": False,
        },
    }
    (tmp_path / "AUDIT.json").write_text(json.dumps(audit), encoding="utf-8")
    (tmp_path / "CHECKSUMS.sha256").write_text("", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="must seal AUDIT.json"):
        verify_independent_pre_score_go(
            tmp_path,
            capability_raw_sha256="a" * 64,
            preflight_raw_sha256="b" * 64,
            preflight_checksums_raw_sha256="c" * 64,
            activation_token="d" * 64,
        )


def test_dependency_free_windows_resource_guard_is_reachable() -> None:
    receipt = windows_resource_guard()
    assert receipt["resource_guard_implementation"] == (
        "python_stdlib_ctypes_windows_kernel32"
    )
    assert receipt["resource_guard_error"] is None
    assert receipt["affinity_mask_hex"] == "0xFFFFFFFF"
    assert receipt["cpu_ids"] == list(range(32))
    assert float(receipt["total_physical_memory_gib"]) >= 90.0
    assert float(receipt["available_physical_memory_gib"]) >= 12.0


def test_no_sweep_or_fit_surface_is_exported() -> None:
    import research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1 as package  # noqa: E501

    names = set(dir(package))
    assert not any(
        token in name.casefold()
        for name in names
        for token in ("sweep", "fit", "train", "promote")
    )
