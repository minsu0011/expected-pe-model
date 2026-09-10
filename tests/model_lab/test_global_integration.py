from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.aggressive_lab.global_integration.builder import (
    LanePayload,
    build_ensemble_rows,
    build_status_evidence_rows,
    build_wave1_global_rows,
    combine_in_memory_tables,
    inspect_integration_plan,
    load_bound_dgp_tables,
    load_bound_lane_payloads,
)
from research.model_zoo.aggressive_lab.global_integration.catalog import (
    BindingReceipt,
    catalog_by_id,
    default_status_evidence,
    terminal_late_bindings,
    verify_status_evidence,
)
from research.model_zoo.aggressive_lab.global_integration.dgp_adapter import (
    normalize_dgp_leaderboard,
)
from research.model_zoo.aggressive_lab.global_integration.ensembles import EligibleModel
from research.model_zoo.aggressive_lab.global_integration.normalization import (
    CHEAP_MASK_ANCHOR_IDENTITY_SHA256,
    build_cheap_mask,
    identity_sha256,
)
from research.model_zoo.aggressive_lab.global_integration.schema import (
    ENSEMBLE_COLUMNS,
    ENSEMBLE_LEADERBOARD_FILENAME,
    GLOBAL_COLUMNS,
    GLOBAL_LEADERBOARD_FILENAME,
    MULTI_DGP_COLUMNS,
    MULTI_DGP_LEADERBOARD_FILENAME,
    OUTPUT_FILENAMES,
    validate_exact_schema,
)
from research.model_zoo.aggressive_lab.global_integration.thresholds import (
    threshold_metadata,
)


ROOT = Path(__file__).resolve().parents[2]


def _binding(lane_id: str) -> BindingReceipt:
    return BindingReceipt(
        lane_id,
        "BOUND",
        False,
        f"{lane_id}/manifest.json",
        "a" * 64,
        f"{lane_id}/predictions.csv",
        "b" * 64,
        2,
    )


def _predictions(model_values: dict[str, list[float]]) -> pd.DataFrame:
    identity = pd.DataFrame(
        {
            "seed": [1, 1, 2, 2],
            "date": pd.to_datetime(
                ["2020-01-01", "2020-01-02", "2020-01-01", "2020-01-02"],
                utc=True,
            ),
            "true_fair_pe": [10.0, 11.0, 12.0, 13.0],
        }
    )
    frames = []
    for model_id, values in model_values.items():
        frame = identity.copy()
        frame["model_id"] = model_id
        frame["prediction"] = values
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def _summary(
    model_ids: list[str],
    *,
    incomplete: str | None = None,
) -> pd.DataFrame:
    rows = []
    for rank, model_id in enumerate(model_ids, start=1):
        is_incomplete = model_id == incomplete
        rows.append(
            {
                "model_id": model_id,
                "family": model_id.split("_")[0],
                "evaluated_rows": 4,
                "natural_coverage": 0.75 if is_incomplete else 1.0,
                "full_coverage": not is_incomplete,
                "fair_log_mae": 0.01 * rank,
                "fair_log_rmse": 0.02 * rank,
                "fair_abs_log_error_median": 0.01,
                "fair_abs_log_error_p95": 0.03,
                "fair_log_bias": 0.0,
                "identity_sha256": "c" * 64,
                "full_rank_within_lane": rank,
            }
        )
    return pd.DataFrame(rows)


def _small_payloads() -> tuple[LanePayload, LanePayload]:
    catalog = catalog_by_id()
    incumbent = [10.1, 10.9, 12.1, 12.9]
    wave = LanePayload(
        catalog["wave1_stage1"],
        _binding("wave1_stage1"),
        _predictions(
            {
                "v04_expected_pe": incumbent,
                "huber_with_regime": [10.2, 11.2, 11.9, 13.2],
            }
        ),
        _summary(
            ["v04_expected_pe", "huber_with_regime"],
            incomplete="huber_with_regime",
        ),
        pd.DataFrame(
            {
                "model_id": ["huber_with_regime"],
                "decision": ["REJECT_GATE"],
                "family": ["huber"],
            }
        ),
    )
    state = LanePayload(
        catalog["state_space_v1"],
        _binding("state_space_v1"),
        _predictions(
            {
                "v04_expected_pe": incumbent,
                "uc_v04_residual_local_level_ar1_v1": [10.0, 11.1, 12.0, 13.1],
            }
        ),
        _summary(["v04_expected_pe", "uc_v04_residual_local_level_ar1_v1"]),
        pd.DataFrame(
            {
                "model_id": ["uc_v04_residual_local_level_ar1_v1"],
                "status": ["REJECTED"],
            }
        ),
    )
    return wave, state


def test_terminal_catalog_is_fully_bound_but_never_finalizes() -> None:
    plan = inspect_integration_plan(ROOT, late_bindings=terminal_late_bindings(ROOT))
    assert plan.all_sources_bound is True
    assert plan.pending_lane_ids == ()
    assert len(plan.receipts) == 10
    assert all(receipt.verified_artifact_count >= 2 for receipt in plan.receipts)
    assert plan.status_evidence_count == 11
    assert plan.finalization_authorized is False
    assert plan.output_filenames == OUTPUT_FILENAMES


def test_catalog_inventory_has_requested_lane_counts_and_incomplete_status() -> None:
    wave = pd.read_csv(
        ROOT / "outputs/model_zoo_wave1_screen_20260819/evaluation/wave1_summary.csv"
    )
    comparators = {
        "ml_expected_pe",
        "v04_expected_pe",
        "v04_ml_expected_pe_no_regime",
        "v04_ml_expected_pe_with_regime",
    }
    assert len(wave) == 21
    assert set(wave["model_id"]) & comparators == comparators
    assert len(set(wave["model_id"]) - comparators) == 17
    incomplete = wave.loc[~wave["full_coverage"].astype(bool), "model_id"].tolist()
    assert incomplete == [
        "huber_with_regime",
        "state_space_local_linear_trend_target_history_only",
    ]
    expected_counts = {
        "model_zoo_classical_exploration_v1_evaluation_20260820/summary.csv": 8,
        "model_zoo_state_space_exploration_v1_evaluation_20260820/summary.csv": 5,
        "model_zoo_structural_v7_full_load_evaluation_20260820/summary.csv": 9,
        "model_zoo_structural_v8_evaluation_20260820/summary.csv": 4,
        "model_zoo_probabilistic_exploration_v2_central_evaluation_20260820/summary.csv": 2,
        "model_zoo_simulator_specialist_v1_evaluation_20260820/summary.csv": 5,
    }
    for relative, candidate_count in expected_counts.items():
        summary = pd.read_csv(ROOT / "outputs" / relative)
        assert len(summary.loc[summary["model_id"] != "v04_expected_pe"]) == candidate_count
    probabilistic = json.loads(
        (
            ROOT / "outputs/model_zoo_probabilistic_exploration_v3_2_future_score_20260820/"
            "FUTURE_CANDIDATE_METRICS.json"
        ).read_text(encoding="utf-8")
    )
    assert len(probabilistic["candidates"]) == 4


def test_actual_cheap_mask_matches_central_evaluator_identity() -> None:
    predictions = pd.read_csv(
        ROOT / "outputs/model_zoo_state_space_exploration_v1_evaluation_20260820/"
        "joined_predictions.csv"
    )
    mask = build_cheap_mask(predictions)
    assert len(mask) == 1_230
    assert identity_sha256(mask) == CHEAP_MASK_ANCHOR_IDENTITY_SHA256


def test_common_mask_dedup_and_incomplete_coverage_are_explicit() -> None:
    global_rows, base_surface, metadata = build_wave1_global_rows(
        _small_payloads(), expected_cheap_rows=4
    )
    validate_exact_schema(global_rows, GLOBAL_LEADERBOARD_FILENAME)
    assert tuple(global_rows.columns) == GLOBAL_COLUMNS
    assert set(global_rows["model_id"]) == {
        "v04_expected_pe",
        "huber_with_regime",
        "uc_v04_residual_local_level_ar1_v1",
    }
    incumbent = global_rows.set_index("model_id").loc["v04_expected_pe"]
    assert incumbent["lane_id"] == "wave1_stage1"
    assert incumbent["duplicate_source_lanes"] == "wave1_stage1|state_space_v1"
    assert "EXACT_DUPLICATE_SURFACE_DEDUPED" in incumbent["source_status"]
    huber = global_rows.set_index("model_id").loc["huber_with_regime"]
    assert huber["numeric_metrics_available"]
    assert huber["full_coverage_complete"] == False  # noqa: E712
    assert huber["full_natural_coverage"] == pytest.approx(0.75)
    assert "INCOMPLETE_NATURAL_COVERAGE" in huber["status_reason"]
    assert set(base_surface["model_id"]) == set(metadata)
    for field in (
        "cheap_mae_relative_gain_vs_v04",
        "cheap_rmse_relative_gain_vs_v04",
        "cheap_tournament_gate_pass",
        "cheap_research_continue",
    ):
        assert field in global_rows


def test_duplicate_incumbent_mismatch_fails_closed() -> None:
    wave, state = _small_payloads()
    changed = state.predictions.copy()
    mask = changed["model_id"] == "v04_expected_pe"
    first = changed.index[mask][0]
    changed.loc[first, "prediction"] = np.nextafter(float(changed.loc[first, "prediction"]), np.inf)
    state = LanePayload(
        state.spec,
        state.binding,
        changed,
        state.full_summary,
        state.comparisons,
    )
    with pytest.raises(ValueError, match="duplicate model predictions differ"):
        build_wave1_global_rows((wave, state), expected_cheap_rows=4)


def test_status_evidence_has_no_numeric_metrics() -> None:
    rows = build_status_evidence_rows(default_status_evidence())
    validate_exact_schema(rows, GLOBAL_LEADERBOARD_FILENAME)
    assert len(rows) == 11
    assert not rows["numeric_metrics_available"].any()
    assert set(rows["candidate_kind"]) == {
        "STATUS_EVIDENCE_ONLY",
        "BROKEN_UNSCORED",
    }
    numeric = rows.filter(regex=r"^(cheap|full|dgp)_.*(mae|rmse|rows|count|gain)")
    assert numeric.isna().all().all()


def test_streamed_ensemble_universe_is_exhaustive_guarded_and_nonpromotional() -> None:
    _, base_surface, metadata = build_wave1_global_rows(_small_payloads(), expected_cheap_rows=4)
    metadata["simulator_not_in_surface"] = EligibleModel(
        "simulator_not_in_surface",
        "simulator_specialist_v1",
        False,
        True,
        True,
    )
    rows = build_ensemble_rows(base_surface, metadata)
    validate_exact_schema(rows, ENSEMBLE_LEADERBOARD_FILENAME)
    assert tuple(rows.columns) == ENSEMBLE_COLUMNS
    assert len(rows) == 4  # C(3,2) + C(3,3)
    assert set(rows["ensemble_family"].value_counts().to_dict().items()) == {
        ("equal_geometric_pair", 3),
        ("pointwise_level_median3", 1),
    }
    assert rows["total_search_space_size"].eq(4).all()
    assert rows["eligible_base_model_count"].eq(3).all()
    assert rows["evidence_class"].eq("POST_RESULT_EXHAUSTIVE_SEARCH").all()
    assert rows["promotion_authority"].eq("NOT_PROMOTION_EVIDENCE").all()
    assert rows["fresh_validation_required"].all()
    assert not rows["contains_simulator_specialist"].any()
    assert not rows["outcome_selected"].any()
    assert rows["selection_bias_caveat"].str.contains("MULTIPLE_COMPARISON").all()
    with pytest.raises(MemoryError, match="working-set guard"):
        build_ensemble_rows(base_surface, metadata, max_working_set_bytes=1)


def test_dgp_robust_gate_is_machine_readable_and_fails_b_or_h_harm() -> None:
    source = pd.DataFrame(
        {
            "model_id": ["candidate"],
            "mean_mae": [0.02],
            "median_mae": [0.02],
            "mean_rmse": [0.03],
            "median_rmse": [0.03],
            "worst_dgp_mae": [0.04],
            "worst_dgp_mae_id": ["B"],
            "worst_dgp_rmse": [0.05],
            "worst_dgp_rmse_id": ["B"],
            "dgp_win_count": [4],
            "dgp_count": [10],
            "status": ["PROMISING"],
        }
    )
    comparisons = pd.DataFrame(
        {
            "model_id": ["candidate"],
            "mean_mae_relative_gain": [0.10],
            "mean_rmse_relative_gain": [0.05],
            "seed_wins": [4],
            "seed_count": [5],
            "worst_relative_harm": [0.02],
            "signed_error_correlation": [0.7],
            "absolute_error_correlation": [0.7],
            "oracle_mae_relative_gain": [0.1],
        }
    )
    robustness = pd.DataFrame(
        {
            "model_id": ["candidate"],
            "dgp_b_mean_mae_relative_gain": [0.01],
            "dgp_b_worst_seed_relative_harm": [0.02],
            "dgp_h_mean_mae_relative_gain": [0.01],
            "dgp_h_worst_seed_relative_harm": [0.03],
        }
    )
    result = normalize_dgp_leaderboard(
        source,
        comparisons,
        lane_id="dgp_test",
        evidence_scope="DGP_A_J_5_SEEDS",
        outcome_aware=False,
        source_manifest_path="manifest.json",
        source_manifest_sha256="a" * 64,
        robustness=robustness,
    )
    validate_exact_schema(result, MULTI_DGP_LEADERBOARD_FILENAME)
    assert tuple(result.columns) == MULTI_DGP_COLUMNS
    row = result.iloc[0]
    assert row["base_tournament_gate_pass"]
    assert row["robust_gate_pass"]
    robustness.loc[0, "dgp_b_mean_mae_relative_gain"] = -0.01
    failed = normalize_dgp_leaderboard(
        source,
        comparisons,
        lane_id="dgp_test",
        evidence_scope="DGP_A_J_5_SEEDS",
        outcome_aware=False,
        source_manifest_path="manifest.json",
        source_manifest_sha256="a" * 64,
        robustness=robustness,
    )
    assert not failed.iloc[0]["robust_gate_pass"]
    missing = normalize_dgp_leaderboard(
        source,
        comparisons,
        lane_id="dgp_test",
        evidence_scope="DGP_A_J_5_SEEDS",
        outcome_aware=False,
        source_manifest_path="manifest.json",
        source_manifest_sha256="a" * 64,
    )
    assert pd.isna(missing.iloc[0]["robust_gate_pass"])


def test_schema_contract_has_exact_names_and_thresholds() -> None:
    contract = json.loads(
        (ROOT / "research/model_zoo/aggressive_lab/global_integration/CONTRACT.json").read_text(
            encoding="utf-8"
        )
    )
    assert tuple(contract["reserved_output_filenames"]) == OUTPUT_FILENAMES
    assert contract["finalization_authorized"] is False
    assert contract["publication_writer"] == {
        "implemented": False,
        "separate_root_token_required": True,
        "root_token_supplied": False,
    }
    assert contract["ensemble_universe"]["fresh_validation_required"] is True
    assert contract["tournament_thresholds"] == threshold_metadata()["values"]
    assert GLOBAL_LEADERBOARD_FILENAME == "EXPECTED_PE_GLOBAL_LEADERBOARD.csv"
    assert MULTI_DGP_LEADERBOARD_FILENAME == "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv"
    assert ENSEMBLE_LEADERBOARD_FILENAME == "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv"


def test_actual_data_end_to_end_all_three_tables_in_memory_only() -> None:
    bindings = terminal_late_bindings(ROOT)
    payloads = load_bound_lane_payloads(ROOT, late_bindings=bindings)
    global_base, base_surface, metadata = build_wave1_global_rows(payloads)
    validate_exact_schema(global_base, GLOBAL_LEADERBOARD_FILENAME)
    assert len(global_base) == 58
    assert base_surface["model_id"].nunique() == 51
    assert len(global_base.loc[global_base["lane_id"] == "wave1_stage1"]) == 21
    incumbent_sources = global_base.set_index("model_id").loc[
        "v04_expected_pe", "duplicate_source_lanes"
    ]
    assert "simulator_specialist_v1" in incumbent_sources.split("|")

    incomplete = global_base.loc[
        global_base["candidate_kind"] == "BASE_INCOMPLETE_COVERAGE"
    ].set_index("model_id")
    assert incomplete["projection_valid_positive_rows"].to_dict() == {
        "huber_with_regime": 936,
        "state_space_local_linear_trend_target_history_only": 1_146,
    }
    assert incomplete["projection_mask_rows"].eq(1_230).all()
    assert incomplete["cheap_apples_to_apples"].eq(False).all()  # noqa: E712
    assert incomplete["cheap_fair_log_mae"].isna().all()
    assert incomplete["cheap_tournament_gate_pass"].isna().all()
    assert incomplete["cheap_rank_within_partition"].isna().all()
    assert all(not metadata[model_id].exact_common_cheap_mask for model_id in incomplete.index)

    simulator = global_base.loc[global_base["simulator_specialist"].astype(bool)]
    assert len(simulator) == 5
    assert not simulator["directly_deployable"].any()
    probabilistic_v3 = global_base.loc[global_base["lane_id"] == "probabilistic_v3_2"]
    assert len(probabilistic_v3) == 4
    assert probabilistic_v3["status"].eq("REJECTED").all()

    ensemble = build_ensemble_rows(base_surface, metadata)
    validate_exact_schema(ensemble, ENSEMBLE_LEADERBOARD_FILENAME)
    assert ensemble["ensemble_family"].value_counts().to_dict() == {
        "pointwise_level_median3": 20_825,
        "equal_geometric_pair": 1_275,
    }
    assert len(ensemble) == 22_100
    assert ensemble["eligible_base_model_count"].eq(51).all()
    assert ensemble["total_search_space_size"].eq(22_100).all()
    assert ensemble["fresh_validation_required"].all()

    dgp_tables = load_bound_dgp_tables(ROOT)
    status = build_status_evidence_rows(verify_status_evidence(ROOT))
    tables = combine_in_memory_tables(
        global_base,
        dgp_tables,
        ensemble,
        status_evidence=status,
    )
    validate_exact_schema(tables.global_leaderboard, GLOBAL_LEADERBOARD_FILENAME)
    validate_exact_schema(tables.multi_dgp_leaderboard, MULTI_DGP_LEADERBOARD_FILENAME)
    validate_exact_schema(tables.ensemble_leaderboard, ENSEMBLE_LEADERBOARD_FILENAME)
    assert len(tables.global_leaderboard) == 82
    assert len(tables.multi_dgp_leaderboard) == 13
    assert tables.multi_dgp_leaderboard["model_id"].is_unique
    assert len(tables.ensemble_leaderboard) == 22_100

    # The package has no publication writer; this test never creates reserved files.
    package = ROOT / "research/model_zoo/aggressive_lab/global_integration"
    assert all(".to_csv(" not in path.read_text(encoding="utf-8") for path in package.glob("*.py"))
