"""Research-only scoring for the pre-frozen C2-R2 sparse routers."""

from __future__ import annotations

import math
from operator import mul
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from .contracts import DGP_IDS, RESEARCH_TARGET, SEED_ALIASES, VARIANT_IDS


EXTREME_THRESHOLD = math.log(1.10)


def type7_quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered or not 0.0 <= probability <= 1.0:
        raise RuntimeError("quantile input differs")
    position = (len(ordered) - 1) * probability
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def summary(errors: Sequence[float], indexes: Sequence[int] | None = None) -> dict[str, Any]:
    values = list(errors) if indexes is None else [errors[index] for index in indexes]
    if not values or not all(math.isfinite(value) for value in values):
        raise RuntimeError("metric group is empty or nonfinite")
    absolute = [abs(value) for value in values]
    count = len(values)
    extreme = sum(value >= EXTREME_THRESHOLD for value in absolute)
    return {
        "rows": count,
        "mae": math.fsum(absolute) / count,
        "rmse": math.sqrt(math.fsum(map(mul, values, values)) / count),
        "mean_signed_error": math.fsum(values) / count,
        "p95_absolute_error": type7_quantile(absolute, 0.95),
        "p99_absolute_error": type7_quantile(absolute, 0.99),
        "max_absolute_error": max(absolute),
        "extreme_error_count": extreme,
        "extreme_error_frequency": extreme / count,
    }


def _systematic_tail(
    candidate_id: str,
    candidate_errors: Sequence[float],
    champion_errors: Sequence[float],
    dgp_groups: Mapping[str, Sequence[int]],
    candidate_pooled: Mapping[str, Any],
    champion_pooled: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_abs = [abs(value) for value in candidate_errors]
    champion_abs = [abs(value) for value in champion_errors]
    candidate_threshold = float(candidate_pooled["p95_absolute_error"])
    champion_threshold = float(champion_pooled["p95_absolute_error"])
    diagnostics = []
    failures = 0
    for dgp_id, indexes in dgp_groups.items():
        candidate_dgp = summary(candidate_errors, indexes)
        champion_dgp = summary(champion_errors, indexes)
        candidate_only = sum(
            candidate_abs[index] >= candidate_threshold
            and champion_abs[index] < champion_threshold
            for index in indexes
        )
        champion_only = sum(
            champion_abs[index] >= champion_threshold
            and candidate_abs[index] < candidate_threshold
            for index in indexes
        )
        joint = sum(
            candidate_abs[index] >= candidate_threshold
            and champion_abs[index] >= champion_threshold
            for index in indexes
        )
        failure = (
            float(candidate_dgp["p95_absolute_error"])
            > float(champion_dgp["p95_absolute_error"])
            and float(candidate_dgp["extreme_error_frequency"])
            > float(champion_dgp["extreme_error_frequency"])
            and candidate_only > champion_only
        )
        failures += int(failure)
        diagnostics.append(
            {
                "dgp_id": dgp_id,
                "joint_q95_count": joint,
                "candidate_only_q95_count": candidate_only,
                "champion_only_q95_count": champion_only,
                "candidate_dgp_p95": candidate_dgp["p95_absolute_error"],
                "champion_dgp_p95": champion_dgp["p95_absolute_error"],
                "candidate_dgp_extreme_frequency": candidate_dgp[
                    "extreme_error_frequency"
                ],
                "champion_dgp_extreme_frequency": champion_dgp[
                    "extreme_error_frequency"
                ],
                "systematic_joint_tail_failure": failure,
            }
        )
    return {
        "candidate_id": candidate_id,
        "candidate_p95_absolute_error": candidate_pooled["p95_absolute_error"],
        "champion_p95_absolute_error": champion_pooled["p95_absolute_error"],
        "candidate_p99_absolute_error": candidate_pooled["p99_absolute_error"],
        "champion_p99_absolute_error": champion_pooled["p99_absolute_error"],
        "candidate_extreme_error_frequency": candidate_pooled["extreme_error_frequency"],
        "champion_extreme_error_frequency": champion_pooled["extreme_error_frequency"],
        "pooled_p95_non_worse": float(candidate_pooled["p95_absolute_error"])
        <= float(champion_pooled["p95_absolute_error"]),
        "pooled_p99_non_worse": float(candidate_pooled["p99_absolute_error"])
        <= float(champion_pooled["p99_absolute_error"]),
        "pooled_extreme_frequency_non_worse": float(
            candidate_pooled["extreme_error_frequency"]
        )
        <= float(champion_pooled["extreme_error_frequency"]),
        "systematic_dgp_joint_tail_failure_count": failures,
        "dgp_diagnostics": diagnostics,
        "formal_qualification_gate_component": False,
    }


def _correlation(left: np.ndarray, right: np.ndarray) -> float | None:
    if len(left) != len(right) or len(left) < 2:
        return None
    if float(np.std(left)) == 0.0 or float(np.std(right)) == 0.0:
        return None
    return float(np.corrcoef(left, right)[0, 1])


def evaluate(
    *,
    identities: pd.DataFrame,
    champion_log: np.ndarray,
    robust_cap_log: np.ndarray,
    variants: Mapping[str, np.ndarray],
    truth_log: np.ndarray,
    route_diagnostics: Mapping[str, Mapping[str, int | float]],
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Score only after all candidate predictions have been frozen by the caller."""

    if tuple(variants) != VARIANT_IDS or len(truth_log) != len(identities):
        raise RuntimeError("sparse-router evaluation universe differs")
    champion_errors = champion_log - truth_log
    robust_errors = robust_cap_log - truth_log
    champion_summary = summary(champion_errors.tolist())
    seed_values = identities["seed_alias"].astype(str).to_numpy()
    dgp_values = identities["dgp_id"].astype(str).to_numpy()
    seed_groups = {seed: np.flatnonzero(seed_values == seed).tolist() for seed in SEED_ALIASES}
    dgp_groups = {dgp: np.flatnonzero(dgp_values == dgp).tolist() for dgp in DGP_IDS}
    cell_groups = {
        (seed, dgp): np.flatnonzero((seed_values == seed) & (dgp_values == dgp)).tolist()
        for seed in SEED_ALIASES
        for dgp in DGP_IDS
    }
    rows: list[dict[str, Any]] = []
    details: dict[str, Any] = {}
    for variant, prediction in variants.items():
        errors = prediction - truth_log
        pooled = summary(errors.tolist())
        mae_gain = (champion_summary["mae"] - pooled["mae"]) / champion_summary["mae"]
        rmse_gain = (champion_summary["rmse"] - pooled["rmse"]) / champion_summary["rmse"]
        seed_gains = {}
        cell_gains = {}
        for seed, indexes in seed_groups.items():
            candidate = summary(errors.tolist(), indexes)
            reference = summary(champion_errors.tolist(), indexes)
            seed_gains[seed] = (reference["mae"] - candidate["mae"]) / reference["mae"]
        for cell, indexes in cell_groups.items():
            candidate = summary(errors.tolist(), indexes)
            reference = summary(champion_errors.tolist(), indexes)
            cell_gains["|".join(cell)] = (
                reference["mae"] - candidate["mae"]
            ) / reference["mae"]
        dgp_gains = {
            dgp: math.fsum(cell_gains[f"{seed}|{dgp}"] for seed in SEED_ALIASES)
            / len(SEED_ALIASES)
            for dgp in DGP_IDS
        }
        tail = _systematic_tail(
            variant,
            errors.tolist(),
            champion_errors.tolist(),
            dgp_groups,
            pooled,
            champion_summary,
        )
        worst_dgp_harm = max(0.0, -min(dgp_gains.values()))
        worst_cell_harm = max(0.0, -min(cell_gains.values()))
        passed = (
            mae_gain >= float(RESEARCH_TARGET["mae_relative_gain_min"])
            and worst_dgp_harm <= float(RESEARCH_TARGET["worst_dgp_mean_harm_max"])
            and worst_cell_harm
            <= float(RESEARCH_TARGET["worst_seed_dgp_cell_harm_max"])
            and int(tail["systematic_dgp_joint_tail_failure_count"])
            <= int(RESEARCH_TARGET["systematic_joint_tail_failure_count_max"])
            and bool(tail["pooled_p95_non_worse"])
            and bool(tail["pooled_p99_non_worse"])
            and bool(tail["pooled_extreme_frequency_non_worse"])
        )
        row = {
            "variant": variant,
            "research_mae_gain": mae_gain,
            "research_rmse_gain": rmse_gain,
            "seed_wins": sum(value > 0.0 for value in seed_gains.values()),
            "dgp_wins": sum(value > 0.0 for value in dgp_gains.values()),
            "seed_dgp_wins": sum(value > 0.0 for value in cell_gains.values()),
            "worst_dgp_harm": worst_dgp_harm,
            "worst_cell_harm": worst_cell_harm,
            "joint_tail_failures": int(
                tail["systematic_dgp_joint_tail_failure_count"]
            ),
            "pooled_p95_non_worse": bool(tail["pooled_p95_non_worse"]),
            "pooled_p99_non_worse": bool(tail["pooled_p99_non_worse"]),
            "pooled_extreme_frequency_non_worse": bool(
                tail["pooled_extreme_frequency_non_worse"]
            ),
            "signed_error_corr_with_robust_cap": _correlation(errors, robust_errors),
            "non_base_action_frequency": route_diagnostics[variant][
                "non_base_action_frequency"
            ],
            "reject_to_v04_frequency": route_diagnostics[variant][
                "reject_to_v04_frequency"
            ],
            "research_target_pass": passed,
            "decision": "FREEZE_RESEARCH_SURVIVOR_FOR_NEW_FRESH_FORMAL"
            if passed
            else "REJECT_AND_SATURATE_IF_NO_OTHER_PASS",
        }
        rows.append(row)
        details[variant] = {
            "summary": pooled,
            "seed_gains": seed_gains,
            "dgp_gains": dgp_gains,
            "cell_gains": cell_gains,
            "tail": tail,
            "route_diagnostics": dict(route_diagnostics[variant]),
        }
    table = pd.DataFrame(rows).sort_values(
        [
            "research_target_pass",
            "joint_tail_failures",
            "worst_dgp_harm",
            "worst_cell_harm",
            "research_mae_gain",
            "non_base_action_frequency",
            "variant",
        ],
        ascending=[False, True, True, True, False, True, True],
        kind="mergesort",
    )
    return table, details


__all__ = ["EXTREME_THRESHOLD", "evaluate", "summary", "type7_quantile"]
