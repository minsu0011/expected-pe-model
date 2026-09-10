"""Spent-only scoring for one frozen C4-R2 research prediction artifact."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


SEEDS = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
SEED_ALIASES = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
DGPS = tuple("ABCDEFGHIJ")
TRUTH_ROOT = Path("outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821/vault")


def _load_truth(project: Path, predictions: pd.DataFrame) -> np.ndarray:
    values: list[float] = []
    identities: list[tuple[str, str, str]] = []
    for seed_alias, seed in zip(SEED_ALIASES, SEEDS, strict=True):
        for dgp in DGPS:
            frame = pd.read_csv(
                project / TRUTH_ROOT / f"seed_{seed}" / f"dgp_{dgp}" / "truth.csv",
                float_precision="round_trip",
            ).iloc[504:1800]
            if not frame["true_expected_pe_eligible"].astype(bool).all():
                raise RuntimeError("spent C4-R2 truth mask differs")
            values.extend(pd.to_numeric(frame["true_log_fair_pe"]).tolist())
            identities.extend(
                zip(
                    [seed_alias] * len(frame),
                    [dgp] * len(frame),
                    frame["date"].astype(str),
                    strict=True,
                )
            )
    observed = list(
        zip(
            predictions["seed_alias"].astype(str),
            predictions["dgp_id"].astype(str),
            predictions["date"].astype(str),
            strict=True,
        )
    )
    if identities != observed:
        raise RuntimeError("spent C4-R2 truth identity differs")
    return np.asarray(values, dtype=np.float64)


def score_spent_predictions(project: Path, predictions: pd.DataFrame) -> dict[str, Any]:
    from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.evaluator import (
        _summary,
        _systematic_tail,
    )

    if (
        len(predictions) != 64_800
        or predictions.duplicated(["seed_alias", "dgp_id", "session_position"]).any()
    ):
        raise RuntimeError("C4-R2 prediction geometry differs")
    target = _load_truth(project, predictions)
    champion_log = pd.to_numeric(predictions["v04_expected_log_pe"]).to_numpy(dtype=np.float64)
    candidate_log = pd.to_numeric(predictions["expected_log_pe"]).to_numpy(dtype=np.float64)
    champion_error = (champion_log - target).tolist()
    candidate_error = (candidate_log - target).tolist()
    champion = _summary(champion_error)
    candidate = _summary(candidate_error)
    seed_values = predictions["seed_alias"].to_numpy(dtype=object)
    dgp_values = predictions["dgp_id"].to_numpy(dtype=object)
    seed_groups = {seed: np.flatnonzero(seed_values == seed).tolist() for seed in SEED_ALIASES}
    dgp_groups = {dgp: np.flatnonzero(dgp_values == dgp).tolist() for dgp in DGPS}
    cells = {
        (seed, dgp): np.flatnonzero((seed_values == seed) & (dgp_values == dgp)).tolist()
        for seed in SEED_ALIASES
        for dgp in DGPS
    }
    seed_gains = {}
    cell_gains = {}
    for seed, indexes in seed_groups.items():
        reference = _summary(champion_error, indexes)
        model = _summary(candidate_error, indexes)
        seed_gains[seed] = (reference["mae"] - model["mae"]) / reference["mae"]
    for cell, indexes in cells.items():
        reference = _summary(champion_error, indexes)
        model = _summary(candidate_error, indexes)
        cell_gains["|".join(cell)] = (reference["mae"] - model["mae"]) / reference["mae"]
    dgp_gains = {
        dgp: math.fsum(cell_gains[f"{seed}|{dgp}"] for seed in SEED_ALIASES) / len(SEED_ALIASES)
        for dgp in DGPS
    }
    tail = _systematic_tail(
        "c4_r2_e_irls80_block_v04",
        candidate_error,
        champion_error,
        dgp_groups,
        candidate,
        champion,
    )
    return {
        "evidence_class": "RESEARCH_ONLY_SPENT_PUBLIC_SYNTHETIC",
        "mae_gain": (champion["mae"] - candidate["mae"]) / champion["mae"],
        "rmse_gain": (champion["rmse"] - candidate["rmse"]) / champion["rmse"],
        "seed_wins": sum(value > 0.0 for value in seed_gains.values()),
        "dgp_wins": sum(value > 0.0 for value in dgp_gains.values()),
        "seed_dgp_wins": sum(value > 0.0 for value in cell_gains.values()),
        "worst_dgp_harm": max(0.0, -min(dgp_gains.values())),
        "worst_cell_harm": max(0.0, -min(cell_gains.values())),
        "joint_tail_failures": int(tail["systematic_dgp_joint_tail_failure_count"]),
        "pooled_p95_non_worse": bool(tail["pooled_p95_non_worse"]),
        "pooled_extreme_frequency_non_worse": bool(tail["pooled_extreme_frequency_non_worse"]),
        "champion": champion,
        "candidate": candidate,
        "seed_gains": seed_gains,
        "dgp_gains": dgp_gains,
        "cell_gains": cell_gains,
        "tail": tail,
        "truth_open_count": 50,
        "fresh_or_heldout_truth_open_count": 0,
        "promotion_authority": False,
    }


__all__ = ["score_spent_predictions"]
