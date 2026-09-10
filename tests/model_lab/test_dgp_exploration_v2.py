"""Lightweight tests for the isolated, prompt-aligned DGP exploration lane."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.contracts import EVALUATION_ONLY_TRUTH_COLUMN
from research.model_zoo.aggressive_lab.contracts import DESIGN_LOCK_RAW_SHA256
from research.model_zoo.dgp_suite.comparator_artifact import (
    OPTIONAL_CHILD_ENVIRONMENT_OVERRIDE_KEYS,
    validate_child_environment_overrides,
)
from research.model_zoo.dgp_suite.rng import DGPContractError
from research.model_zoo.dgp_exploration_v2.contracts import (
    CANDIDATE_SPECS,
    DGP_SPECS,
    EXPLORATION_LABELS,
    ExplorationContractError,
    folds_for_stage,
)
from research.model_zoo.dgp_exploration_v2.features import build_feature_surface
from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
from research.model_zoo.dgp_exploration_v2.incumbent import (
    CHILD_RESOURCE_ENVIRONMENT,
    _align_comparator_frames,
)
from research.model_zoo.dgp_exploration_v2.models import (
    _ridge_ar1_predictions,
    run_candidates,
)
from research.model_zoo.dgp_exploration_v2.precommit import verify_exact_hash_inventory
from research.model_zoo.dgp_exploration_v2.runner import verify_precommit
from research.model_zoo.dgp_exploration_v2.scoring import score_predictions


SEED = 2026082001


@pytest.fixture(scope="module")
def generated() -> dict[str, object]:
    return {spec.dgp_id: generate_dgp(spec.dgp_id, master_seed=SEED) for spec in DGP_SPECS}


def test_prompt_ids_are_not_silently_assumed_to_be_legacy_ids() -> None:
    assert tuple(spec.dgp_id for spec in DGP_SPECS) == tuple("ABCDEFGHIJ")
    assert tuple(spec.prompt_name for spec in DGP_SPECS) == (
        "SMOOTH_LATENT_PE",
        "SUDDEN_VALUATION_JUMPS",
        "STRONG_REGIME_SWITCHING",
        "HIGH_OBSERVATION_NOISE",
        "LOW_OBSERVATION_NOISE",
        "EARNINGS_DRIVEN_JUMPS",
        "RATE_COMPRESSION",
        "SECTOR_SHOCK",
        "MEAN_REVERTING_VALUATION",
        "STRUCTURAL_DRIFT",
    )
    assert all(spec.legacy_nearest and spec.legacy_difference for spec in DGP_SPECS)
    assert "Legacy B was smooth additive" in DGP_SPECS[1].legacy_difference
    assert "Legacy I was an accounting-action" in DGP_SPECS[8].legacy_difference


def test_every_generator_is_deterministic_separated_and_score_free(generated: dict[str, object]) -> None:
    for dgp_id, item in generated.items():
        assert set(item.public) == {
            "price",
            "benchmark",
            "eps_events",
            "public_factors",
            "corporate_actions",
        }
        assert set(item.evaluator_only) == {"truth", "latent_events"}
        assert len(item.public["price"]) == 1_800
        assert len(item.evaluator_only["truth"]) == 1_800
        assert item.generation_audit["candidate_executed"] is False
        assert item.generation_audit["score_computed"] is False
        assert item.generation_audit["production_promotion_allowed"] is False
        assert not any(
            str(column).startswith(("true_", "latent_", "future_", "rng_"))
            for frame in item.public.values()
            for column in frame.columns
        )
        replay = generate_dgp(dgp_id, master_seed=SEED)
        assert (
            replay.generation_audit["public_logical_sha256"]
            == item.generation_audit["public_logical_sha256"]
        )


def test_new_semantic_mechanisms_are_present_and_de_noise_pair_is_exact(
    generated: dict[str, object],
) -> None:
    d_truth = generated["D"].evaluator_only["truth"]
    e_truth = generated["E"].evaluator_only["truth"]
    np.testing.assert_array_equal(d_truth["true_fair_pe"], e_truth["true_fair_pe"])
    d_noise = generated["D"].evaluator_only["latent_events"]["latent_observation_error"]
    e_noise = generated["E"].evaluator_only["latent_events"]["latent_observation_error"]
    assert float(d_noise.std()) > 5.0 * float(e_noise.std())

    b_latent = generated["B"].evaluator_only["latent_events"]["latent_jump_step"]
    assert b_latent.iloc[719] == 0.0 and b_latent.iloc[720] != 0.0
    assert b_latent.iloc[1_259] != b_latent.iloc[1_260]
    assert generated["C"].evaluator_only["latent_events"]["latent_regime"].nunique() == 3
    assert (
        generated["F"].evaluator_only["latent_events"]["latent_earnings_pulse"].abs().max()
        > 0.0
    )
    assert generated["G"].evaluator_only["latent_events"]["latent_rate_compression"].iloc[959] == 0.0
    assert generated["G"].evaluator_only["latent_events"]["latent_rate_compression"].iloc[960] < 0.0
    assert generated["H"].evaluator_only["latent_events"]["latent_sector_compression"].iloc[990] < 0.0
    assert generated["I"].evaluator_only["latent_events"]["latent_mean_reverting_state"].std() > 0.05
    j_beta = generated["J"].evaluator_only["latent_events"]["latent_beta"]
    assert j_beta.iloc[899] == pytest.approx(0.08)
    assert j_beta.iloc[1_200] == pytest.approx(-0.08)


def test_public_feature_surface_blocks_same_row_market_and_future_interventions(
    generated: dict[str, object],
) -> None:
    public = {name: frame.copy(deep=True) for name, frame in generated["A"].public.items()}
    base = build_feature_surface(public)
    changed_market = deepcopy(public)
    changed_market["price"].loc[600, "close"] *= 10.0
    market_surface = build_feature_surface(changed_market)
    pd.testing.assert_frame_equal(base.features.iloc[:601], market_surface.features.iloc[:601])
    assert base.log_observed_pe_target.iloc[600] != market_surface.log_observed_pe_target.iloc[600]
    assert not base.features.iloc[601].equals(market_surface.features.iloc[601])

    changed_future = deepcopy(public)
    mask = changed_future["public_factors"]["effective_session"].eq(
        changed_future["price"].loc[700, "date"]
    )
    changed_future["public_factors"].loc[mask, "value"] += 999.0
    future_surface = build_feature_surface(changed_future)
    pd.testing.assert_frame_equal(base.features.iloc[:700], future_surface.features.iloc[:700])
    assert not base.features.iloc[700].equals(future_surface.features.iloc[700])
    assert "observed_pe" not in base.features
    assert "close" not in base.features
    assert all(not column.startswith(("true_", "latent_", "future_")) for column in base.features)


def test_chronological_folds_and_lightweight_candidate_surface_share_one_mask(
    generated: dict[str, object],
) -> None:
    folds = folds_for_stage("cheap")
    assert len(folds) == 6
    assert all(fold.train_end == fold.test_start for fold in folds)
    assert all(fold.train_end <= fold.test_start for fold in folds)
    assert not set(range(folds[0].test_start, folds[0].test_end)).intersection(
        range(folds[1].test_start, folds[1].test_end)
    )

    surface = build_feature_surface(generated["A"].public)
    proxy = surface.observed_pe.ewm(span=63, adjust=False, min_periods=1).mean().shift(1)
    proxy = proxy.bfill()
    comparators = pd.DataFrame(
        {
            "date": surface.identity["date"],
            "ml_expected_pe": proxy,
            "v04_expected_pe": proxy * 1.001,
        }
    )
    predictions, diagnostics, _ = run_candidates(
        surface,
        comparators,
        master_seed=SEED,
        dgp_id="A",
        folds=(folds[0],),
    )
    assert predictions["model_id"].nunique() == len(CANDIDATE_SPECS)
    assert predictions.groupby("model_id").size().nunique() == 1
    assert not predictions.duplicated(["seed", "dgp", "date", "model_id"]).any()
    assert diagnostics["train_end"].lt(diagnostics["test_end"]).all()


def test_incumbent_alignment_is_exactly_one_complete_session() -> None:
    canonical = pd.DataFrame(
        {"date": ["2020-01-01", "2020-01-02", "2020-01-03"], "ml_expected_pe": [20, 21, 22]}
    )
    overlay = pd.DataFrame(
        {"date": canonical["date"], "ml_expected_pe": [20, 21, 22], "v04_expected_pe": [30, 31, 32]}
    )
    aligned = _align_comparator_frames(canonical, overlay)
    assert pd.isna(aligned.loc[0, "v04_expected_pe"])
    assert aligned.loc[1, "v04_expected_pe"] == 30
    assert aligned.loc[2, "ml_expected_pe"] == 21


def test_exact_child_resource_override_is_narrow_complete_and_probeable() -> None:
    assert set(CHILD_RESOURCE_ENVIRONMENT) == set(OPTIONAL_CHILD_ENVIRONMENT_OVERRIDE_KEYS)
    assert CHILD_RESOURCE_ENVIRONMENT == {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }
    assert validate_child_environment_overrides(CHILD_RESOURCE_ENVIRONMENT) == dict(
        sorted(CHILD_RESOURCE_ENVIRONMENT.items())
    )
    assert validate_child_environment_overrides(None) == {}
    with pytest.raises(DGPContractError, match="not allowed"):
        validate_child_environment_overrides({"PATH": "forbidden"})


def test_ar1_residual_prediction_uses_only_prior_observed_residual() -> None:
    x_train = np.arange(10, dtype=np.float64).reshape(-1, 1)
    residual = np.asarray([0.0, 0.30, 0.24, 0.25, 0.20, 0.19, 0.16, 0.15, 0.13, 0.12])
    y_train = 2.0 + 0.05 * x_train[:, 0] + residual
    x_test = np.arange(10, 14, dtype=np.float64).reshape(-1, 1)
    test_positions = np.arange(10, 14, dtype=np.int64)
    target = pd.Series(np.r_[y_train, [2.62, 2.68, 2.71, 2.75]])
    baseline, phi = _ridge_ar1_predictions(
        x_train, y_train, x_test, test_positions, target
    )
    # The fitted trend absorbs most of this deliberately small residual path;
    # retain only a non-degeneracy guard so the intervention remains observable.
    assert abs(phi) > 1e-4

    current_changed = target.copy()
    current_changed.iloc[11] += 10.0
    changed, changed_phi = _ridge_ar1_predictions(
        x_train, y_train, x_test, test_positions, current_changed
    )
    assert changed_phi == phi
    np.testing.assert_array_equal(changed[:2], baseline[:2])
    assert changed[2] != baseline[2]

    future_changed = target.copy()
    future_changed.iloc[13] += 10.0
    future, _ = _ridge_ar1_predictions(
        x_train, y_train, x_test, test_positions, future_changed
    )
    np.testing.assert_array_equal(future, baseline)


def _fake_evaluator_frames() -> tuple[pd.DataFrame, pd.DataFrame]:
    prediction_rows: list[dict[str, object]] = []
    truth_rows: list[dict[str, object]] = []
    model_ids = [spec.model_id for spec in CANDIDATE_SPECS]
    for seed_index, seed in enumerate((1, 2)):
        for dgp_index, dgp in enumerate("ABCDEFGHIJ"):
            for day in range(3):
                date = f"2020-{dgp_index + 1:02d}-{day + 1:02d}"
                truth = 20.0 + 0.2 * dgp_index + 0.01 * seed_index
                truth_rows.append(
                    {
                        "seed": seed,
                        "dgp": dgp,
                        "date": date,
                        EVALUATION_ONLY_TRUTH_COLUMN: truth,
                    }
                )
                for model_index, model_id in enumerate(model_ids):
                    offset = 0.02 if model_id == "v04_expected_pe" else 0.002 * model_index
                    prediction_rows.append(
                        {
                            "seed": seed,
                            "dgp": dgp,
                            "date": date,
                            "fold_id": f"fake_{day}",
                            "model_id": model_id,
                            "prediction": truth * np.exp(offset),
                        }
                    )
    return pd.DataFrame(prediction_rows), pd.DataFrame(truth_rows)


def test_central_evaluator_produces_required_multi_dgp_metrics_and_labels() -> None:
    predictions, truth = _fake_evaluator_frames()
    scored = score_predictions(predictions, truth)
    required = {
        "mean_mae",
        "median_mae",
        "mean_rmse",
        "median_rmse",
        "worst_dgp_mae",
        "worst_dgp_rmse",
        "dgp_win_count",
    }
    assert required.issubset(scored.multi_dgp_leaderboard.columns)
    assert scored.multi_dgp_leaderboard["dgp_count"].eq(10).all()
    assert scored.multi_dgp_leaderboard["evidence_class"].eq(EXPLORATION_LABELS[0]).all()
    assert scored.multi_dgp_leaderboard["promotion_authority"].eq(EXPLORATION_LABELS[1]).all()
    assert scored.multi_dgp_leaderboard["central_design_lock_raw_sha256"].eq(
        DESIGN_LOCK_RAW_SHA256
    ).all()
    assert scored.per_dgp_metrics.groupby("model_id")["dgp"].nunique().eq(10).all()


def test_truth_identity_and_consistency_fail_closed() -> None:
    predictions, truth = _fake_evaluator_frames()
    duplicate = pd.concat([truth, truth.iloc[[0]]], ignore_index=True)
    with pytest.raises(ExplorationContractError, match="truth identity"):
        score_predictions(predictions, duplicate)
    last_model = CANDIDATE_SPECS[-1].model_id
    # Remove one explicit identity from one model.
    index = predictions.loc[predictions["model_id"].eq(last_model)].index[-1]
    damaged = predictions.drop(index)
    with pytest.raises(ExplorationContractError, match="same evaluator mask"):
        score_predictions(damaged, truth)


def test_external_precommit_hash_and_all_locked_inventories_verify() -> None:
    root = Path(__file__).resolve().parents[2]
    raw = (root / "outputs/model_zoo_dgp_exploration_v2_design_20260820/DESIGN_LOCK.json").read_bytes()
    external_hash = hashlib.sha256(raw).hexdigest()
    payload = verify_precommit(external_hash)
    assert payload["labels"] == list(EXPLORATION_LABELS)
    assert payload["heavy_execution_status"] == "NOT_LAUNCHED_WAITING_ROOT_APPROVAL"
    with pytest.raises(ExplorationContractError, match="externally passed"):
        verify_precommit("0" * 64)


def test_precommit_inventory_rejects_keyset_and_byte_changes() -> None:
    live = {"a.py": "a" * 64, "b.py": "b" * 64}
    verify_exact_hash_inventory(label="test", sealed=dict(live), live=live)
    with pytest.raises(ExplorationContractError, match="keyset changed"):
        verify_exact_hash_inventory(
            label="test",
            sealed={"a.py": "a" * 64},
            live=live,
        )
    changed = dict(live)
    changed["b.py"] = "c" * 64
    with pytest.raises(ExplorationContractError, match="bytes changed"):
        verify_exact_hash_inventory(label="test", sealed=changed, live=live)
