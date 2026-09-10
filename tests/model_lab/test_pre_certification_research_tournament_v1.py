from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pre_certification_research_tournament_v1.adapters import (
    NORMALIZED_PREDICTION_COLUMNS,
    normalize_bce_wide_predictions,
    validate_normalized_predictions,
)
from research.model_zoo.pre_certification_research_tournament_v1.contracts import (
    BCE_B_ID,
    CHAMPION_ID,
    COMMON_IDENTITIES,
    DGP_IDS,
    FIVE_CANDIDATE_SLOTS,
    RESEARCH_EVIDENCE_CLASS,
    SCORE_END,
    SCORE_ROWS_PER_TASK,
    SCORE_START,
    SCORED_CANDIDATE_IDS,
    SCORED_MODEL_IDS,
    SEED_ALIASES,
    TASK_COUNT,
    ResearchTournamentContractError,
    design_lock_payload,
    fold_id_for_position,
)
from research.model_zoo.pre_certification_research_tournament_v1.evaluator import (
    _complementarity_rows,
    _hierarchical_bootstrap,
    _metric_row,
)
from research.model_zoo.pre_certification_research_tournament_v1.inventory import (
    build_inventory,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _identities() -> pd.DataFrame:
    seed = np.repeat(np.asarray(SEED_ALIASES, dtype=object), len(DGP_IDS) * SCORE_ROWS_PER_TASK)
    dgp = np.tile(
        np.repeat(np.asarray(DGP_IDS, dtype=object), SCORE_ROWS_PER_TASK),
        len(SEED_ALIASES),
    )
    position = np.tile(np.arange(SCORE_START, SCORE_END, dtype=np.int64), TASK_COUNT)
    dates = np.tile(
        pd.bdate_range("2015-01-02", periods=SCORE_ROWS_PER_TASK).strftime("%Y-%m-%d"),
        TASK_COUNT,
    )
    return pd.DataFrame(
        {
            "seed_alias": seed,
            "dgp_id": dgp,
            "session_position": position,
            "date": dates,
            "symbol": "DGP_ISSUER",
            "fold_id": [fold_id_for_position(int(value)) for value in position],
        }
    )


def test_design_is_research_only_and_has_exact_five_slots() -> None:
    payload = design_lock_payload()
    assert payload["evidence_class"] == "RESEARCH_ONLY"
    assert payload["authority"] == {
        "fresh": False,
        "heldout": False,
        "certification": False,
        "promotion": False,
        "portfolio_admission": False,
        "registry_mutation": False,
    }
    assert [slot.slot_id for slot in FIVE_CANDIDATE_SLOTS] == [
        "PE-C1",
        "PE-C2",
        "PE-C3",
        "PE-C4",
        "PE-C5",
    ]
    assert [slot.research_readiness for slot in FIVE_CANDIDATE_SLOTS][-2:] == [
        "BLOCKED_IMPLEMENTATION",
        "BLOCKED_IMPLEMENTATION",
    ]
    assert payload["geometry"]["common_identities"] == COMMON_IDENTITIES


def test_normalized_bce_adapter_enforces_exact_common_geometry() -> None:
    wide = _identities()
    wide["candidate__bce_b"] = 20.0 + wide["session_position"].to_numpy() * 1.0e-4
    normalized = normalize_bce_wide_predictions(wide, model_id=BCE_B_ID)
    assert tuple(normalized.columns) == NORMALIZED_PREDICTION_COLUMNS
    assert len(normalized) == COMMON_IDENTITIES
    assert set(normalized["evidence_class"]) == {RESEARCH_EVIDENCE_CLASS}
    assert np.allclose(
        np.log(normalized["expected_pe"].to_numpy()),
        normalized["expected_log_pe"].to_numpy(),
    )


def test_normalized_contract_rejects_nonresearch_label() -> None:
    wide = _identities()
    wide["candidate__bce_b"] = 20.0
    normalized = normalize_bce_wide_predictions(wide, model_id=BCE_B_ID)
    normalized.loc[0, "evidence_class"] = "CERTIFIED"
    with pytest.raises(ResearchTournamentContractError, match="evidence label"):
        validate_normalized_predictions(normalized, expected_model_id=BCE_B_ID)


def test_metric_math_and_complementarity_are_directionally_correct() -> None:
    champion_error = np.asarray([0.10, -0.20, 0.15, -0.05], dtype=np.float64)
    candidate_error = champion_error * 0.5
    metric = _metric_row(BCE_B_ID, candidate_error, champion_error)
    assert metric["mae_relative_gain_vs_v04"] == pytest.approx(0.5)
    assert metric["rmse_relative_gain_vs_v04"] == pytest.approx(0.5)
    truth = np.asarray([3.0, 3.1, 3.2, 3.3], dtype=np.float64)
    logs = {
        CHAMPION_ID: truth + champion_error,
        BCE_B_ID: truth + candidate_error,
        SCORED_CANDIDATE_IDS[1]: truth - candidate_error,
        SCORED_CANDIDATE_IDS[2]: truth + candidate_error * 0.8,
    }
    errors = {model_id: value - truth for model_id, value in logs.items()}
    rows = _complementarity_rows(logs, errors)
    assert len(rows) == 6
    pair = next(
        row
        for row in rows
        if {row["left_model_id"], row["right_model_id"]} == {CHAMPION_ID, BCE_B_ID}
    )
    assert pair["oracle_is_achievable_model_score"] is False
    assert pair["oracle_mae_gain_vs_v04"] == pytest.approx(0.5)


def test_hierarchical_bootstrap_uses_seed_dgp_fold_geometry(monkeypatch: pytest.MonkeyPatch) -> None:
    import research.model_zoo.pre_certification_research_tournament_v1.evaluator as evaluator

    monkeypatch.setattr(evaluator, "BOOTSTRAP_REPLICATES", 20)
    joined = _identities().drop(columns="symbol")
    phase = np.arange(COMMON_IDENTITIES, dtype=np.float64)
    champion = 0.08 + 0.01 * np.sin(phase / 31.0)
    errors = {
        CHAMPION_ID: champion,
        SCORED_CANDIDATE_IDS[0]: champion * 0.95,
        SCORED_CANDIDATE_IDS[1]: champion * 0.90,
        SCORED_CANDIDATE_IDS[2]: champion * 1.05,
    }
    rows = _hierarchical_bootstrap(joined, errors)
    assert len(rows) == 3
    assert rows[0]["replicates"] == 20
    assert rows[0]["mae_gain_lower_5pct"] > 0.0
    assert rows[2]["mae_gain_upper_95pct"] < 0.0


def test_exact_spent_inventory_closure_without_truth_payload_open() -> None:
    inventory = build_inventory(_project_root())
    assert inventory["status"] == "PASS_EXACT_SPENT_INPUTS_BCE_3_OF_5_SCOREABLE"
    assert inventory["access"]["truth_payload_files_opened"] == 0
    assert inventory["access"]["fresh_payload_files_opened"] == 0
    assert inventory["access"]["heldout_payload_files_opened"] == 0
    assert inventory["hofs_blocker"]["status"] == "BLOCKED_IMPLEMENTATION"
    assert inventory["tcn_blocker"]["status"] == "BLOCKED_IMPLEMENTATION"


def test_new_package_contains_no_reserved_or_heldout_seed_literals() -> None:
    root = _project_root()
    paths = [
        root / "research/model_zoo/pre_certification_research_tournament_v1",
        root / "scripts/model_lab/pre_certification_research_tournament_v1",
    ]
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for directory in paths
        for path in directory.rglob("*.py")
    )
    for forbidden in ("7573", "7577", "7583", "7589", "7591", "7603", "7607", "7621", "7639", "7643"):
        assert forbidden not in source


def test_scored_model_order_includes_champion_then_three_bce() -> None:
    assert SCORED_MODEL_IDS == (CHAMPION_ID, *SCORED_CANDIDATE_IDS)
    assert SCORE_END - SCORE_START == 1_296
