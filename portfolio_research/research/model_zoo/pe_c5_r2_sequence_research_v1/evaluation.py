"""Deterministic sequence-model diagnostics and portfolio-value metrics."""

from __future__ import annotations

import math
from typing import Any, Mapping

import numpy as np


def _safe_corr(left: np.ndarray, right: np.ndarray) -> float:
    mask = np.isfinite(left) & np.isfinite(right)
    if int(mask.sum()) < 3:
        return 0.0
    x = left[mask].astype(np.float64, copy=False)
    y = right[mask].astype(np.float64, copy=False)
    if float(np.std(x)) <= 1e-15 or float(np.std(y)) <= 1e-15:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])


def _summary(error: np.ndarray, *, extreme_threshold: float | None = None) -> dict[str, float]:
    absolute = np.abs(error.astype(np.float64, copy=False))
    threshold = (
        float(np.quantile(absolute, 0.95))
        if extreme_threshold is None
        else float(extreme_threshold)
    )
    return {
        "mae": float(np.mean(absolute)),
        "rmse": float(math.sqrt(float(np.mean(np.square(error, dtype=np.float64))))),
        "p95_absolute_error": float(np.quantile(absolute, 0.95)),
        "extreme_error_frequency": float(np.mean(absolute > threshold)),
    }


def _response_metrics(
    prediction: np.ndarray,
    target: np.ndarray,
) -> dict[str, float | int]:
    pred = np.asarray(prediction, dtype=np.float64)
    truth = np.asarray(target, dtype=np.float64)
    if pred.shape != truth.shape or pred.ndim != 2:
        raise ValueError("response metric geometry differs")
    deltas = truth[:, 1:] - truth[:, :-1]
    threshold = float(np.quantile(np.abs(deltas), 0.95))
    slow_threshold = float(np.quantile(np.abs(deltas), 0.50))
    jump_delays: list[int] = []
    half_lives: list[int] = []
    slow_errors: list[float] = []
    for task in range(truth.shape[0]):
        for offset in range(1, truth.shape[1]):
            change = float(truth[task, offset] - truth[task, offset - 1])
            if abs(change) <= slow_threshold:
                slow_errors.append(abs(float(pred[task, offset] - truth[task, offset])))
            if abs(change) < threshold:
                continue
            direction = 1.0 if change > 0.0 else -1.0
            base_prediction = float(pred[task, offset - 1])
            delay = 11
            for step in range(0, 11):
                cursor = offset + step
                if cursor >= truth.shape[1]:
                    break
                response = (float(pred[task, cursor]) - base_prediction) * direction
                if response >= 0.5 * abs(change):
                    delay = step
                    break
            jump_delays.append(delay)
            initial_error = abs(float(pred[task, offset] - truth[task, offset]))
            if initial_error <= 1e-15:
                half_lives.append(0)
                continue
            half_life = 22
            for step in range(0, 22):
                cursor = offset + step
                if cursor >= truth.shape[1]:
                    break
                error = abs(float(pred[task, cursor] - truth[task, cursor]))
                if error <= 0.5 * initial_error:
                    half_life = step
                    break
            half_lives.append(half_life)
    return {
        "jump_event_count": len(jump_delays),
        "jump_response_delay_median_sessions": float(np.median(jump_delays)),
        "slow_state_log_mae": float(np.mean(slow_errors)),
        "shock_recovery_half_life_median_sessions": float(np.median(half_lives)),
    }


def _group_metrics(
    candidate_error: np.ndarray,
    baseline_error: np.ndarray,
    dgp_ids: tuple[str, ...],
) -> dict[str, Any]:
    dgp_gain: dict[str, float] = {}
    joint_tail_failures: list[str] = []
    baseline_threshold = float(np.quantile(np.abs(baseline_error), 0.95))
    for dgp_index, dgp in enumerate(dgp_ids):
        indexes = np.arange(dgp_index, candidate_error.shape[0], len(dgp_ids))
        candidate = candidate_error[indexes].reshape(-1)
        baseline = baseline_error[indexes].reshape(-1)
        candidate_summary = _summary(candidate, extreme_threshold=baseline_threshold)
        baseline_summary = _summary(baseline, extreme_threshold=baseline_threshold)
        gain = (baseline_summary["mae"] - candidate_summary["mae"]) / baseline_summary["mae"]
        dgp_gain[dgp] = float(gain)
        if (
            candidate_summary["mae"] > baseline_summary["mae"]
            and candidate_summary["p95_absolute_error"] > baseline_summary["p95_absolute_error"]
            and candidate_summary["extreme_error_frequency"]
            > baseline_summary["extreme_error_frequency"]
        ):
            joint_tail_failures.append(dgp)
    return {
        "dgp_mae_gain": dgp_gain,
        "dgp_wins": sum(value > 0.0 for value in dgp_gain.values()),
        "worst_dgp_harm": max(0.0, -min(dgp_gain.values())),
        "systematic_joint_tail_failure_count": len(joint_tail_failures),
        "systematic_joint_tail_failure_dgps": joint_tail_failures,
    }


def score_track(
    *,
    predictions: Mapping[str, np.ndarray],
    target: np.ndarray,
    dgp_ids: tuple[str, ...],
    core_predictions: Mapping[str, np.ndarray] | None,
    survivor_rule: Mapping[str, object],
) -> dict[str, dict[str, Any]]:
    """Score a complete track against lagged-v04 persistence."""

    baseline = np.asarray(predictions["lagged_v04_persistence"], dtype=np.float64)
    truth = np.asarray(target, dtype=np.float64)
    if baseline.shape != truth.shape or baseline.ndim != 2 or not np.isfinite(truth).all():
        raise ValueError("track target/prediction geometry differs")
    baseline_error = baseline - truth
    baseline_threshold = float(np.quantile(np.abs(baseline_error), 0.95))
    baseline_summary = _summary(baseline_error, extreme_threshold=baseline_threshold)
    result: dict[str, dict[str, Any]] = {}
    for name, values in predictions.items():
        prediction = np.asarray(values, dtype=np.float64)
        if prediction.shape != truth.shape or not np.isfinite(prediction).all():
            raise ValueError(f"{name} prediction geometry/nonfinite differs")
        error = prediction - truth
        summary = _summary(error, extreme_threshold=baseline_threshold)
        mae_gain = (baseline_summary["mae"] - summary["mae"]) / baseline_summary["mae"]
        rmse_gain = (baseline_summary["rmse"] - summary["rmse"]) / baseline_summary["rmse"]
        p95_harm = max(
            0.0,
            (summary["p95_absolute_error"] - baseline_summary["p95_absolute_error"])
            / baseline_summary["p95_absolute_error"],
        )
        metrics: dict[str, Any] = {
            **summary,
            "mae_gain_vs_persistence": float(mae_gain),
            "rmse_gain_vs_persistence": float(rmse_gain),
            "p95_harm_vs_persistence": float(p95_harm),
            **_group_metrics(error, baseline_error, dgp_ids),
            **_response_metrics(prediction, truth),
            "signed_error_corr_with_persistence": _safe_corr(error, baseline_error),
            "absolute_error_corr_with_persistence": _safe_corr(
                np.abs(error), np.abs(baseline_error)
            ),
        }
        core_corr_pass = True
        best_oracle_gain = 0.0
        if core_predictions:
            core_metrics: dict[str, dict[str, float]] = {}
            for core_name, core_values in core_predictions.items():
                core = np.asarray(core_values, dtype=np.float64)
                if core.shape != truth.shape or not np.isfinite(core).all():
                    raise ValueError("core prediction geometry differs")
                core_error = core - truth
                core_mae = float(np.mean(np.abs(core_error)))
                oracle_mae = float(np.mean(np.minimum(np.abs(core_error), np.abs(error))))
                oracle_gain = (core_mae - oracle_mae) / core_mae
                blend_error = 0.5 * (core + prediction) - truth
                blend_gain = (core_mae - float(np.mean(np.abs(blend_error)))) / core_mae
                signed_corr = _safe_corr(error, core_error)
                absolute_corr = _safe_corr(np.abs(error), np.abs(core_error))
                core_metrics[core_name] = {
                    "signed_error_correlation": signed_corr,
                    "absolute_error_correlation": absolute_corr,
                    "oracle_pair_mae_gain": float(oracle_gain),
                    "fixed_half_blend_mae_gain": float(blend_gain),
                }
                best_oracle_gain = max(best_oracle_gain, float(oracle_gain))
                if abs(signed_corr) > float(
                    survivor_rule["max_abs_signed_error_corr_with_each_core"]
                ):
                    core_corr_pass = False
            metrics["core_complementarity"] = core_metrics
        standalone = mae_gain >= float(survivor_rule["standalone_mae_gain_min"])
        alternative = best_oracle_gain >= float(survivor_rule["alternative_oracle_pair_gain_min"])
        controlled_tail = p95_harm <= float(survivor_rule["p95_harm_max"]) and int(
            metrics["systematic_joint_tail_failure_count"]
        ) <= int(survivor_rule["systematic_joint_tail_failures_max"])
        metrics["research_survivor_rule_pass"] = bool(
            name != "lagged_v04_persistence"
            and (standalone or alternative)
            and controlled_tail
            and core_corr_pass
        )
        metrics["standalone_clause_pass"] = bool(standalone)
        metrics["oracle_clause_pass"] = bool(alternative)
        metrics["controlled_tail_clause_pass"] = bool(controlled_tail)
        metrics["core_correlation_clause_pass"] = bool(core_corr_pass)
        result[name] = metrics
    return result


def dlinear_signal(
    metrics_by_track: Mapping[str, Mapping[str, Mapping[str, Any]]],
    signal_rule: Mapping[str, object],
) -> tuple[bool, dict[str, bool]]:
    """Apply the predeclared conditional-GRU trigger."""

    decisions: dict[str, bool] = {}
    for track, models in metrics_by_track.items():
        metrics = models["dlinear_residual"]
        standalone = (
            float(metrics["mae_gain_vs_persistence"]) >= float(signal_rule["mae_gain_min"])
            and float(metrics["rmse_gain_vs_persistence"]) >= float(signal_rule["rmse_gain_min"])
            and float(metrics["p95_harm_vs_persistence"]) <= float(signal_rule["p95_harm_max"])
        )
        alternatives = metrics.get("core_complementarity", {})
        oracle = any(
            float(value["oracle_pair_mae_gain"])
            >= float(signal_rule["alternative_oracle_pair_gain_min"])
            and abs(float(value["signed_error_correlation"]))
            <= float(signal_rule["alternative_max_abs_signed_error_corr"])
            for value in alternatives.values()
        )
        decisions[track] = bool(standalone or oracle)
    return any(decisions.values()), decisions


__all__ = ["dlinear_signal", "score_track"]
