from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.bounded_consensus_v1 import (
    BASE_MODEL_ID,
    VARIANT_IDS,
    design_lock_sha256,
)
from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration import (
    EVIDENCE_SCOPE,
    QUALIFICATION_SEEDS,
    EvaluationAuthorization,
    StateR2IntegrationError,
    TaskGeometry,
    assemble_prepared_seeds,
    audit_source_boundary,
    bind_state_r2_inputs,
    disabled_evaluation_gate_template,
    evaluate_authorized_files,
    integration_design_payload,
    integration_design_sha256,
    prepare_prediction_frames,
    run_score_free_preflight,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.contracts import (
    BASE_PREDICTION_COLUMN,
    CHALLENGER_A_COLUMN,
    CHALLENGER_B_COLUMN,
    STATE_DESIGN_LOCK,
    STATE_PREDICTION_FREEZE,
    STATE_PREDICTION_MANIFEST,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.custody import (
    FileRecord,
    sha256_file,
    verify_file_record_exact,
)
from research.model_zoo.observable_fair_value_state_v1 import contract_sha256


SMALL_GEOMETRY = TaskGeometry(
    canonical_rows_per_seed=30,
    prediction_rows_per_seed=20,
    first_session_position=10,
    final_session_position=29,
    fold_count_per_seed=4,
    first_fold_number=0,
    final_fold_number=3,
    regular_fold_rows=5,
    terminal_fold_rows=5,
)
SYNTHETIC_LANE = "synthetic_qualification_lane"


def _canonical(rows: int = 30) -> pd.DataFrame:
    position = np.arange(rows, dtype=np.float64)
    phase = position / 7.0
    return pd.DataFrame(
        {
            "date": pd.bdate_range("2020-01-02", periods=rows),
            "symbol": "DEMO",
            "observed_pe": 18.0 + 0.1 * position + 0.3 * np.sin(phase),
            "eps_ttm": 4.0 + 0.02 * position,
            "eps_ttm_growth_126": 0.04 + 0.001 * np.sin(phase),
            "eps_ttm_growth_252": 0.06 + 0.001 * np.cos(phase),
            "eps_staleness_days": position % 12,
            "eps_period_age_days": 30.0 + position,
            "eps_confidence": 0.88 - 0.01 * (position % 3),
            "eps_disagreement": 0.03 + 0.001 * (position % 4),
            "eps_approximation_flag": (position % 5 == 0).astype(float),
            "benchmark_return_21": 0.01 * np.sin(phase),
            "benchmark_return_63": 0.02 * np.sin(phase),
            "benchmark_return_252": 0.04 * np.cos(phase),
            "benchmark_realized_vol_20": 0.15 + 0.005 * np.sin(phase),
            "benchmark_realized_vol_63": 0.17 + 0.005 * np.cos(phase),
            "benchmark_drawdown_252": -0.08 + 0.01 * np.sin(phase),
            "benchmark_sma_50_vs_200": 0.03 + 0.005 * np.cos(phase),
            "benchmark_trend_efficiency_63": 0.4 + 0.02 * np.sin(phase),
            "p_bear": 0.20 + 0.01 * np.sin(phase),
            "p_sideways": 0.30 - 0.005 * np.sin(phase),
            "p_bull": 0.50 - 0.005 * np.sin(phase),
        }
    )


def _predictions(seed: int = 1701) -> pd.DataFrame:
    positions = np.arange(10, 30, dtype=np.int64)
    block = (positions - 10) // 5
    base = 19.0 + 0.03 * (positions - 10)
    return pd.DataFrame(
        {
            "source_lane": SYNTHETIC_LANE,
            "seed": seed,
            "date": pd.bdate_range("2020-01-02", periods=30)[positions],
            "symbol": "DEMO",
            "session_position": positions,
            "fold_id": [f"fold_{value:03d}" for value in block],
            "train_end_position": 9 + 5 * block,
            "test_start_position": 10 + 5 * block,
            BASE_PREDICTION_COLUMN: base,
            CHALLENGER_A_COLUMN: base * np.exp(0.030 + 0.001 * (positions % 3)),
            CHALLENGER_B_COLUMN: base * np.exp(0.024 + 0.001 * (positions % 2)),
        }
    )


def _prepared(*, seed: int = 1701):
    return prepare_prediction_frames(
        _canonical(),
        _predictions(seed),
        lane_id=SYNTHETIC_LANE,
        seed=seed,
        geometry=SMALL_GEOMETRY,
    )


def test_design_binds_exact_r2_surfaces_geometry_and_hashes() -> None:
    payload = integration_design_payload()
    assert QUALIFICATION_SEEDS == (7417, 7433, 7451, 7457, 7459, 7507, 7517, 7523, 7529, 7537)
    assert payload["base_prediction_column"] == "reference__v04_expected_pe"
    assert payload["challenger_a_column"] == "lgbm__ofs_v1_full_with_regime"
    assert payload["challenger_b_column"] == "histgb__ofs_v1_full_with_regime"
    assert tuple(payload["variant_ids"]) == VARIANT_IDS
    assert payload["expected_long_prediction_rows"] == 64800
    assert payload["bounded_consensus_design_lock_sha256"] == design_lock_sha256()
    assert payload["observable_state_contract_sha256"] == contract_sha256()
    assert payload["state_r2_design_lock"]["raw_sha256"] == STATE_DESIGN_LOCK.raw_sha256
    assert payload["state_r2_prediction_manifest"]["raw_sha256"] == (
        STATE_PREDICTION_MANIFEST.raw_sha256
    )
    assert payload["state_r2_prediction_freeze"]["raw_sha256"] == (
        STATE_PREDICTION_FREEZE.raw_sha256
    )
    assert payload["state_ablation_scores_used_for_construction"] is False
    assert payload["state_ablation_decisions_used_for_construction"] is False
    assert payload["independent_audit_structured_content_read_for_construction"] is False
    assert payload["formulas_or_hyperparameters_changed"] is False


def test_model_construction_source_boundary_is_static_and_column_closed() -> None:
    package = (
        Path(__file__).resolve().parents[2]
        / "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration"
    )
    audit = audit_source_boundary(package)
    assert audit.passed
    assert audit.dataframe_reader_count == 2
    assert audit.dataframe_readers_all_column_closed
    assert audit.evaluator_module_excluded_from_construction_scan
    assert not audit.forbidden_literal_hits
    assert not audit.evaluator_import_hits


def test_real_r2_custody_and_preflight_cover_exact_ten_spent_seeds() -> None:
    root = Path(__file__).resolve().parents[2]
    closure = bind_state_r2_inputs(root)
    assert tuple(binding.seed for binding in closure.seeds) == QUALIFICATION_SEEDS
    assert closure.to_payload()["independent_audit_structured_content_read"] is False
    assert closure.to_payload()["metric_files_opened"] is False
    rebound, preflight = run_score_free_preflight(root)
    assert tuple(binding.seed for binding in rebound.seeds) == QUALIFICATION_SEEDS
    assert preflight["status"] == "READY_PREDICTION_ONLY"
    assert preflight["canonical_rows_verified"] == 18000
    assert preflight["oof_prediction_rows_verified"] == 12960
    assert preflight["fold_blocks_verified"] == 620
    assert preflight["observable_confidence_rows_generated"] == 12960
    assert preflight["expected_long_prediction_rows"] == 64800
    assert preflight["actions"]["variant_prediction_assembly_executed"] is False
    assert preflight["actions"]["score_computation_executed"] is False
    assert preflight["actions"]["independent_audit_structured_content_read"] is False


def test_truth_blind_assembler_runs_exact_five_variants() -> None:
    prepared = _prepared()
    assert "observed_pe" not in prepared.adapter_frame.columns
    assert not any(column.startswith("true_") for column in prepared.adapter_frame.columns)
    assembly = assemble_prepared_seeds((prepared,))
    assert assembly.variant_ids == VARIANT_IDS
    assert len(assembly.predictions) == 100
    assert tuple(assembly.predictions["bce_v1_variant_id"].drop_duplicates()) == VARIANT_IDS
    assert assembly.predictions["bce_v1_base_model_id"].eq(BASE_MODEL_ID).all()
    assert assembly.predictions["bce_v1_challenger_a_id"].eq(CHALLENGER_A_COLUMN).all()
    assert assembly.predictions["bce_v1_challenger_b_id"].eq(CHALLENGER_B_COLUMN).all()
    assert assembly.predictions["bce_v1_design_lock_sha256"].eq(design_lock_sha256()).all()
    assert (
        assembly.predictions["bce_v1_observable_state_contract_sha256"].eq(contract_sha256()).all()
    )


def test_same_row_and_future_observed_pe_attacks_cannot_change_prefix_confidence() -> None:
    canonical = _canonical()
    baseline = _prepared().adapter_frame
    attacked_current = canonical.copy()
    attacked_current.loc[15, "observed_pe"] *= 8.0
    current = prepare_prediction_frames(
        attacked_current,
        _predictions(),
        lane_id=SYNTHETIC_LANE,
        seed=1701,
        geometry=SMALL_GEOMETRY,
    ).adapter_frame
    confidence = "bce_v1_observable_state_confidence"
    np.testing.assert_array_equal(
        baseline.loc[baseline["session_position"] <= 15, confidence].to_numpy(),
        current.loc[current["session_position"] <= 15, confidence].to_numpy(),
    )
    attacked_future = canonical.copy()
    attacked_future.loc[25:, "observed_pe"] *= 0.2
    future = prepare_prediction_frames(
        attacked_future,
        _predictions(),
        lane_id=SYNTHETIC_LANE,
        seed=1701,
        geometry=SMALL_GEOMETRY,
    ).adapter_frame
    np.testing.assert_array_equal(
        baseline.loc[baseline["session_position"] < 25, confidence].to_numpy(),
        future.loc[future["session_position"] < 25, confidence].to_numpy(),
    )


def test_truth_current_pe_lane_and_fold_attacks_fail_closed() -> None:
    for forbidden in ("true_fair_pe", "observed_pe", "heldout_cap", "future_return"):
        attacked = _predictions()
        attacked[forbidden] = 1.0
        with pytest.raises(StateR2IntegrationError, match="forbidden"):
            prepare_prediction_frames(
                _canonical(),
                attacked,
                lane_id=SYNTHETIC_LANE,
                seed=1701,
                geometry=SMALL_GEOMETRY,
            )
    attacked_canonical = _canonical()
    attacked_canonical["true_fair_pe"] = 20.0
    with pytest.raises(StateR2IntegrationError, match="truth/future"):
        prepare_prediction_frames(
            attacked_canonical,
            _predictions(),
            lane_id=SYNTHETIC_LANE,
            seed=1701,
            geometry=SMALL_GEOMETRY,
        )
    wrong_lane = _predictions()
    wrong_lane["source_lane"] = "heldout_lane"
    with pytest.raises(StateR2IntegrationError, match="source lane"):
        prepare_prediction_frames(
            _canonical(),
            wrong_lane,
            lane_id=SYNTHETIC_LANE,
            seed=1701,
            geometry=SMALL_GEOMETRY,
        )
    reappearing = _predictions()
    reappearing.loc[15:, "fold_id"] = "fold_000"
    with pytest.raises(StateR2IntegrationError, match="fold order/universe"):
        prepare_prediction_frames(
            _canonical(),
            reappearing,
            lane_id=SYNTHETIC_LANE,
            seed=1701,
            geometry=SMALL_GEOMETRY,
        )


def test_variant_e_uses_prior_fold_blocks_only() -> None:
    baseline = assemble_prepared_seeds((_prepared(),)).predictions
    attacked_predictions = _predictions()
    current_fold = attacked_predictions["fold_id"].eq("fold_002")
    attacked_predictions.loc[current_fold, CHALLENGER_A_COLUMN] *= np.exp(0.30)
    attacked_predictions.loc[current_fold, CHALLENGER_B_COLUMN] *= np.exp(0.25)
    attacked_prepared = prepare_prediction_frames(
        _canonical(),
        attacked_predictions,
        lane_id=SYNTHETIC_LANE,
        seed=1701,
        geometry=SMALL_GEOMETRY,
    )
    attacked = assemble_prepared_seeds((attacked_prepared,)).predictions
    variant = VARIANT_IDS[-1]
    baseline_e = baseline.loc[baseline["bce_v1_variant_id"].eq(variant)].reset_index(drop=True)
    attacked_e = attacked.loc[attacked["bce_v1_variant_id"].eq(variant)].reset_index(drop=True)
    same_fold = baseline_e["fold_id"].eq("fold_002")
    next_fold = baseline_e["fold_id"].eq("fold_003")
    np.testing.assert_array_equal(
        baseline_e.loc[same_fold, "bce_v1_correction_budget"].to_numpy(),
        attacked_e.loc[same_fold, "bce_v1_correction_budget"].to_numpy(),
    )
    assert not np.array_equal(
        baseline_e.loc[next_fold, "bce_v1_correction_budget"].to_numpy(),
        attacked_e.loc[next_fold, "bce_v1_correction_budget"].to_numpy(),
    )


def test_scored_heldout_and_hash_swap_paths_fail_closed(tmp_path: Path) -> None:
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    clean = qualification / "predictions.csv"
    clean.write_text("x\n1\n", encoding="utf-8")
    scored = qualification / "SCORED_ROWS.csv"
    scored.write_text("x\n1\n", encoding="utf-8")
    scored_record = FileRecord(str(scored.resolve()), scored.stat().st_size, sha256_file(scored))
    with pytest.raises(StateR2IntegrationError, match="score-free"):
        verify_file_record_exact(
            scored_record,
            expected_path=scored,
            project_root=tmp_path,
            label="attacked scored source",
        )
    heldout = tmp_path / "heldout" / "qualification"
    heldout.mkdir(parents=True)
    blocked = heldout / "predictions.csv"
    blocked.write_text("x\n1\n", encoding="utf-8")
    heldout_record = FileRecord(
        str(blocked.resolve()), blocked.stat().st_size, sha256_file(blocked)
    )
    with pytest.raises(StateR2IntegrationError, match="score-free"):
        verify_file_record_exact(
            heldout_record,
            expected_path=blocked,
            project_root=tmp_path,
            label="attacked heldout source",
        )
    swapped = replace(
        FileRecord(str(clean.resolve()), clean.stat().st_size, sha256_file(clean)),
        sha256="0" * 64,
    )
    with pytest.raises(StateR2IntegrationError, match="content hash"):
        verify_file_record_exact(
            swapped,
            expected_path=clean,
            project_root=tmp_path,
            label="swapped source",
        )


def test_evaluator_remains_locked_without_external_capability() -> None:
    template = disabled_evaluation_gate_template()
    assert template["status"] == "LOCKED_NO_CAPABILITY"
    assert template["truth_access_authorized"] is False
    assert template["score_computation_authorized"] is False
    assert template["heldout_access_authorized"] is False
    empty = FileRecord(path="not-opened.csv", bytes=0, sha256="0" * 64)
    authorization = EvaluationAuthorization(
        authorization_id="bounded_consensus_v1_state_r2_spent_qualification_evaluation_v1",
        evidence_scope=EVIDENCE_SCOPE,
        seeds=QUALIFICATION_SEEDS,
        prediction_artifact=empty,
        truth_artifact=empty,
        integration_design_sha256=integration_design_sha256(),
        bounded_consensus_design_lock_sha256=design_lock_sha256(),
        observable_state_contract_sha256=contract_sha256(),
        state_r2_prediction_manifest_raw_sha256=STATE_PREDICTION_MANIFEST.raw_sha256,
        truth_column="true_fair_pe",
        truth_access_authorized=False,
        score_computation_authorized=False,
        heldout_access_authorized=False,
        authorization_sha256="0" * 64,
    )
    with pytest.raises(StateR2IntegrationError, match="not been authorized"):
        evaluate_authorized_files(authorization)
    wrong_seed = replace(
        authorization,
        seeds=QUALIFICATION_SEEDS[:-1],
        truth_access_authorized=True,
        score_computation_authorized=True,
    )
    unsigned = wrong_seed.unsigned_payload()
    wrong_seed = replace(
        wrong_seed,
        authorization_sha256=hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    )
    with pytest.raises(StateR2IntegrationError, match="seed universe"):
        evaluate_authorized_files(wrong_seed)
