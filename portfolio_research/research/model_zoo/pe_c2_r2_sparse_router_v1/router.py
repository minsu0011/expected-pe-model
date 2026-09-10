"""Pure PIT-safe sparse routing over the frozen four-percent C2 robust cap."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping

import numpy as np
import pandas as pd

from .contracts import (
    FIRST_TEST_POSITION,
    LOG_1P0125,
    LOG_1P015,
    LOG_1P020,
    LOG_1P030,
    LOG_1P040,
    PUBLIC_LOAD_COLUMNS,
    ROUTER_BASE_COLUMNS,
    ROWS_PER_TASK,
    VARIANT_IDS,
)


@dataclass(frozen=True)
class RouterTaskResult:
    predictions: Mapping[str, np.ndarray]
    scales: Mapping[str, np.ndarray]
    base_log_prediction: np.ndarray
    base_applied_correction: np.ndarray
    route_diagnostics: Mapping[str, Mapping[str, int | float]]
    prefix_receipt: Mapping[str, int | bool]


def _numeric(frame: pd.DataFrame, column: str) -> np.ndarray:
    values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=np.float64)
    if len(values) == 0 or not np.isfinite(values).all():
        raise RuntimeError(f"sparse-router feature is empty or nonfinite: {column}")
    return values


def _public_numeric(frame: pd.DataFrame, column: str) -> np.ndarray:
    """Allow only the canonical pre-test indicator warm-up nulls."""

    values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=np.float64)
    prefix = values[:FIRST_TEST_POSITION]
    if (
        len(values) != 1800
        or np.count_nonzero(np.isfinite(prefix)) < 8
        or not np.isfinite(values[FIRST_TEST_POSITION:]).all()
    ):
        raise RuntimeError(f"sparse-router public feature geometry differs: {column}")
    return values


def _quantile(values: np.ndarray, probability: float, fallback: float) -> float:
    finite = values[np.isfinite(values)]
    if len(finite) < 8:
        return float(fallback)
    return float(np.quantile(finite, probability, method="linear"))


def _route_summary(scale: np.ndarray) -> dict[str, int | float]:
    rows = len(scale)
    changed = int(np.count_nonzero(scale != 1.0))
    rejected = int(np.count_nonzero(scale == 0.0))
    return {
        "rows": rows,
        "non_base_action_count": changed,
        "non_base_action_frequency": changed / rows,
        "reject_to_v04_count": rejected,
        "reject_to_v04_frequency": rejected / rows,
    }


def route_task(base: pd.DataFrame, public: pd.DataFrame) -> RouterTaskResult:
    """Route one 1,296-row task without accepting DGP identity or any score label."""

    if tuple(base.columns) != ROUTER_BASE_COLUMNS:
        raise RuntimeError("sparse-router base column contract differs")
    if tuple(public.columns) != PUBLIC_LOAD_COLUMNS or len(public) != 1800:
        raise RuntimeError("sparse-router public feature contract differs")
    if len(base) != ROWS_PER_TASK:
        raise RuntimeError("sparse-router task geometry differs")
    positions = _numeric(base, "session_position").astype(np.int64)
    if not np.array_equal(
        positions, np.arange(FIRST_TEST_POSITION, FIRST_TEST_POSITION + ROWS_PER_TASK)
    ):
        raise RuntimeError("sparse-router task positions differ")
    starts = _numeric(base, "test_start_position").astype(np.int64)
    if np.any(starts > positions) or np.any(starts < FIRST_TEST_POSITION):
        raise RuntimeError("sparse-router fold chronology differs")

    champion = _numeric(base, "incumbent__v04_expected_pe")
    challenger_a = _numeric(base, "challenger__lgbm_full_state")
    challenger_b = _numeric(base, "challenger__histgb_full_state")
    if np.any(champion <= 0.0) or np.any(challenger_a <= 0.0) or np.any(challenger_b <= 0.0):
        raise RuntimeError("sparse-router prediction constituent is nonpositive")
    alpha = np.clip(_numeric(base, "alpha__bce_d"), 0.0, 1.0)
    raw = _numeric(base, "raw_log_consensus_correction")
    applied = np.clip(alpha * raw, -LOG_1P040, LOG_1P040)
    champion_log = np.log(champion)
    disagreement = np.abs(np.log(challenger_a) - np.log(challenger_b)) / 2.0
    magnitude = np.abs(applied)

    entropy = _public_numeric(public, "regime_entropy")
    regime_confidence = _public_numeric(public, "regime_confidence")
    valuation_tail = np.abs(
        _public_numeric(public, "regime_conditional_pe_percentile") - 50.0
    ) / 50.0
    volatility = _public_numeric(public, "benchmark_realized_vol_20")
    staleness = _public_numeric(public, "eps_staleness_days")

    uncertain = np.zeros(ROWS_PER_TASK, dtype=bool)
    ood_count = np.zeros(ROWS_PER_TASK, dtype=np.int8)
    reversal = np.zeros(ROWS_PER_TASK, dtype=bool)
    adaptive_magnitude = np.empty(ROWS_PER_TASK, dtype=np.float64)
    disagreement_q75 = np.empty(ROWS_PER_TASK, dtype=np.float64)
    disagreement_q90 = np.empty(ROWS_PER_TASK, dtype=np.float64)
    prefix_source_max = np.empty(ROWS_PER_TASK, dtype=np.int64)
    prior_decision_source_max = np.empty(ROWS_PER_TASK, dtype=np.int64)

    cache: dict[int, tuple[float, ...]] = {}
    for index, (position, test_start) in enumerate(zip(positions, starts, strict=True)):
        start = int(test_start)
        if start not in cache:
            public_prefix = slice(0, start)
            prior_count = max(0, start - FIRST_TEST_POSITION)
            prior_magnitude = magnitude[:prior_count]
            prior_disagreement = disagreement[:prior_count]
            cache[start] = (
                _quantile(entropy[public_prefix], 0.75, 0.9995),
                _quantile(regime_confidence[public_prefix], 0.25, 0.00035),
                _quantile(valuation_tail[public_prefix], 0.95, 0.95),
                _quantile(volatility[public_prefix], 0.95, 0.21),
                _quantile(staleness[public_prefix], 0.95, 91.0),
                _quantile(prior_magnitude, 0.85, LOG_1P0125),
                _quantile(prior_disagreement, 0.75, math.log(1.004)),
                _quantile(prior_disagreement, 0.90, math.log(1.0065)),
            )
        (
            entropy_q75,
            confidence_q25,
            valuation_q95,
            volatility_q95,
            staleness_q95,
            magnitude_q85,
            dis_q75,
            dis_q90,
        ) = cache[start]
        source = start - 1
        prefix_source_max[index] = source
        uncertain[index] = (
            entropy[position] >= entropy_q75
            or regime_confidence[position] <= confidence_q25
        )
        ood_count[index] = int(valuation_tail[position] >= valuation_q95) + int(
            volatility[position] >= volatility_q95
        ) + int(staleness[position] >= staleness_q95)
        adaptive_magnitude[index] = max(LOG_1P0125, magnitude_q85)
        disagreement_q75[index] = dis_q75
        disagreement_q90[index] = dis_q90

        history_start = max(0, index - 21)
        history = np.sign(raw[history_start:index])
        nonzero = history[history != 0.0]
        prior_decision_source_max[index] = int(position) - 1 if len(history) else source
        if len(nonzero) >= 8 and raw[index] != 0.0:
            reversal[index] = float(np.sign(raw[index]) * np.mean(nonzero)) < -0.25

    if not np.all(prefix_source_max < positions) or not np.all(
        prior_decision_source_max < positions
    ):
        raise RuntimeError("sparse-router prefix chronology is not strict")

    scales: dict[str, np.ndarray] = {}

    scale = np.ones(ROWS_PER_TASK, dtype=np.float64)
    scale[magnitude >= LOG_1P020] = 0.5
    scale[magnitude >= LOG_1P030] = 0.0
    scales[VARIANT_IDS[0]] = scale

    scale = np.ones(ROWS_PER_TASK, dtype=np.float64)
    high = (
        (magnitude >= LOG_1P015)
        & (disagreement >= disagreement_q75)
        & uncertain
    )
    extreme = high & (magnitude >= LOG_1P020) & (
        disagreement >= disagreement_q90
    )
    scale[high] = 0.35
    scale[extreme] = 0.0
    scales[VARIANT_IDS[1]] = scale

    scale = np.ones(ROWS_PER_TASK, dtype=np.float64)
    high = (magnitude >= LOG_1P015) & (ood_count >= 1)
    extreme = (magnitude >= LOG_1P020) & (ood_count >= 2)
    scale[high] = 0.5
    scale[extreme] = 0.0
    scales[VARIANT_IDS[2]] = scale

    scale = np.ones(ROWS_PER_TASK, dtype=np.float64)
    high = (magnitude >= LOG_1P0125) & reversal
    extreme = high & (disagreement >= disagreement_q90)
    scale[high] = 0.25
    scale[extreme] = 0.0
    scales[VARIANT_IDS[3]] = scale

    magnitude_signal = magnitude >= adaptive_magnitude
    risk_score = (
        magnitude_signal.astype(np.int8)
        + (disagreement >= disagreement_q75).astype(np.int8)
        + uncertain.astype(np.int8)
        + (ood_count >= 1).astype(np.int8)
        + reversal.astype(np.int8)
    )
    scale = np.ones(ROWS_PER_TASK, dtype=np.float64)
    high = magnitude_signal & (risk_score >= 3)
    extreme = magnitude_signal & (risk_score >= 4)
    scale[high] = 0.5
    scale[extreme] = 0.0
    scales[VARIANT_IDS[4]] = scale

    allowed_scales = {0.0, 0.25, 0.35, 0.5, 1.0}
    if set(scales) != set(VARIANT_IDS) or any(
        not set(np.unique(values)).issubset(allowed_scales) for values in scales.values()
    ):
        raise RuntimeError("sparse-router action universe differs")
    predictions = {
        variant: champion_log + scale_values * applied
        for variant, scale_values in scales.items()
    }
    if any(not np.isfinite(values).all() for values in predictions.values()):
        raise RuntimeError("sparse-router produced nonfinite predictions")
    return RouterTaskResult(
        predictions=predictions,
        scales=scales,
        base_log_prediction=champion_log + applied,
        base_applied_correction=applied,
        route_diagnostics={variant: _route_summary(values) for variant, values in scales.items()},
        prefix_receipt={
            "rows": ROWS_PER_TASK,
            "strict_prefix_threshold_rows": int(np.count_nonzero(prefix_source_max < positions)),
            "strict_prior_decision_rows": int(
                np.count_nonzero(prior_decision_source_max < positions)
            ),
            "max_prefix_source_position": int(prefix_source_max.max()),
            "max_prediction_position": int(positions.max()),
            "dgp_label_used_as_feature": False,
            "truth_or_score_used_for_thresholds": False,
        },
    )


__all__ = ["RouterTaskResult", "route_task"]
