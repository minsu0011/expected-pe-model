from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from research.model_zoo.pe_c2_r2_sparse_router_v1.contracts import (
    BASE_MODEL_ID,
    FIRST_TEST_POSITION,
    FORBIDDEN_FEATURE_TOKENS,
    PUBLIC_LOAD_COLUMNS,
    RESEARCH_TARGET,
    ROUTER_BASE_COLUMNS,
    ROUTER_FEATURE_COLUMNS,
    ROWS_PER_TASK,
    VARIANT_IDS,
    VARIANT_SPECS,
)
from research.model_zoo.pe_c2_r2_sparse_router_v1.metrics import evaluate
from research.model_zoo.pe_c2_r2_sparse_router_v1.router import route_task


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/model_lab/pe_c2_r2_sparse_router_research_v1.py"
OUTPUT_ROOT = (
    PROJECT_ROOT / "outputs/model_zoo_pe_c2_r2_sparse_router_research_v1_20260825"
)


def _synthetic_task() -> tuple[pd.DataFrame, pd.DataFrame]:
    positions = np.arange(FIRST_TEST_POSITION, FIRST_TEST_POSITION + ROWS_PER_TASK)
    phase = np.arange(ROWS_PER_TASK, dtype=np.float64)
    champion = 20.0 + 0.1 * np.sin(phase / 31.0)
    base = pd.DataFrame(
        {
            "session_position": positions,
            "test_start_position": FIRST_TEST_POSITION
            + ((positions - FIRST_TEST_POSITION) // 21) * 21,
            "incumbent__v04_expected_pe": champion,
            "challenger__lgbm_full_state": champion * np.exp(0.006 * np.sin(phase / 7.0)),
            "challenger__histgb_full_state": champion
            * np.exp(-0.007 * np.cos(phase / 11.0)),
            "alpha__bce_d": 0.8 + 0.1 * np.sin(phase / 19.0),
            "raw_log_consensus_correction": 0.04 * np.sin(phase / 13.0),
        }
    ).loc[:, list(ROUTER_BASE_COLUMNS)]
    public_phase = np.arange(FIRST_TEST_POSITION + ROWS_PER_TASK, dtype=np.float64)
    public = pd.DataFrame(
        {
            "date": pd.date_range("2000-01-01", periods=len(public_phase)).astype(str),
            "symbol": ["SYNTH"] * len(public_phase),
            "regime_entropy": 0.4 + 0.2 * np.sin(public_phase / 23.0),
            "regime_confidence": 0.6 + 0.2 * np.cos(public_phase / 29.0),
            "regime_conditional_pe_percentile": 50.0
            + 45.0 * np.sin(public_phase / 17.0),
            "benchmark_realized_vol_20": 0.15 + 0.05 * np.cos(public_phase / 37.0),
            "eps_staleness_days": 30.0 + np.mod(public_phase, 80.0),
        }
    ).loc[:, list(PUBLIC_LOAD_COLUMNS)]
    return base, public


def test_design_is_exactly_five_score_free_sparse_routers() -> None:
    assert len(VARIANT_IDS) == 5
    assert tuple(VARIANT_SPECS) == VARIANT_IDS
    assert RESEARCH_TARGET["mae_relative_gain_min"] == 0.04
    assert RESEARCH_TARGET["systematic_joint_tail_failure_count_max"] == 0
    assert RESEARCH_TARGET["worst_dgp_mean_harm_max"] == 0.01
    assert RESEARCH_TARGET["worst_seed_dgp_cell_harm_max"] == 0.03
    accepted = (*ROUTER_BASE_COLUMNS, *ROUTER_FEATURE_COLUMNS)
    assert "dgp_id" not in accepted
    assert "seed_alias" not in accepted
    assert all(
        token not in column.casefold()
        for column in accepted
        for token in FORBIDDEN_FEATURE_TOKENS
    )


def test_router_is_deterministic_bounded_and_strictly_pit() -> None:
    base, public = _synthetic_task()
    public.loc[:198, "regime_entropy"] = np.nan
    public.loc[:249, "regime_conditional_pe_percentile"] = np.nan
    first = route_task(base, public)
    second = route_task(base.copy(), public.copy())
    assert tuple(first.predictions) == VARIANT_IDS
    assert first.prefix_receipt["strict_prefix_threshold_rows"] == ROWS_PER_TASK
    assert first.prefix_receipt["strict_prior_decision_rows"] == ROWS_PER_TASK
    assert first.prefix_receipt["dgp_label_used_as_feature"] is False
    for variant in VARIANT_IDS:
        assert np.array_equal(first.predictions[variant], second.predictions[variant])
        assert set(np.unique(first.scales[variant])) <= {0.0, 0.25, 0.35, 0.5, 1.0}


def test_future_public_perturbation_cannot_change_prior_predictions() -> None:
    base, public = _synthetic_task()
    cutoff = 1000
    baseline = route_task(base, public)
    attacked = public.copy()
    attacked.loc[cutoff:, list(ROUTER_FEATURE_COLUMNS)] = 1_000_000.0
    replay = route_task(base, attacked)
    prior_count = cutoff - FIRST_TEST_POSITION
    for variant in VARIANT_IDS:
        assert np.array_equal(
            baseline.predictions[variant][:prior_count],
            replay.predictions[variant][:prior_count],
        )


def test_local_metric_gate_accepts_only_conjunctive_candidate() -> None:
    seeds = [f"research_seed_{index:02d}" for index in range(1, 6)]
    dgps = list("ABCDEFGHIJ")
    identities = pd.DataFrame(
        [(seed, dgp) for seed in seeds for dgp in dgps],
        columns=["seed_alias", "dgp_id"],
    )
    truth = np.zeros(len(identities), dtype=np.float64)
    champion = np.full(len(identities), 0.1, dtype=np.float64)
    variants = {
        variant: np.full(len(identities), 0.09, dtype=np.float64)
        for variant in VARIANT_IDS
    }
    route_diagnostics = {
        variant: {
            "non_base_action_frequency": 0.1,
            "reject_to_v04_frequency": 0.01,
        }
        for variant in VARIANT_IDS
    }
    table, _ = evaluate(
        identities=identities,
        champion_log=champion,
        robust_cap_log=champion,
        variants=variants,
        truth_log=truth,
        route_diagnostics=route_diagnostics,
    )
    assert table["research_target_pass"].all()
    assert (table["research_mae_gain"] >= 0.04).all()


def test_script_freezes_predictions_before_opening_spent_truth() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    freeze_call = source.index('_write_new(root / "PREDICTION_FREEZE.json"')
    truth_call = source.index("truth_log, truth_refs = _load_truth(")
    assert freeze_call < truth_call
    assert "expected_pe_c4_c2_c5_wave_20260824" not in source
    assert "outputs/expected_pe_heldout" not in source
    assert "outputs/expected_pe_qualification" not in source


def test_published_output_integrity_when_present() -> None:
    if not OUTPUT_ROOT.exists():
        return
    ledger = (OUTPUT_ROOT / "CHECKSUMS.sha256").read_text(encoding="ascii")
    for line in ledger.splitlines():
        expected, name = line.split("  ", maxsplit=1)
        observed = hashlib.sha256((OUTPUT_ROOT / name).read_bytes()).hexdigest()
        assert observed == expected
    result = json.loads((OUTPUT_ROOT / "RESULT.json").read_text(encoding="utf-8"))
    assert result["family_decision"] in {
        "FREEZE_ONE_C2_R2_SPARSE_ROUTER_RESEARCH_SURVIVOR",
        "C2_RELIABILITY_REPAIR_FAMILY_SATURATED",
    }
    assert result["existing_c2_or_c4_formal_evidence_inherited"] is False
    predictions = pd.read_csv(OUTPUT_ROOT / "PREDICTIONS.csv", nrows=5)
    assert BASE_MODEL_ID not in predictions.columns
