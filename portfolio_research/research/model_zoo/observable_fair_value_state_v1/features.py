"""Causal/PIT-safe observable state generator with no target or evaluator access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
import pandas as pd

from .contracts import (
    FEATURE_OUTPUT_COLUMNS,
    OPTIONAL_RELATIVE_SOURCE_COLUMNS,
    REQUIRED_SOURCE_COLUMNS,
    STATE_LEVEL_ALPHA,
    STATE_SLOPE_BETA,
    ObservableStateContractError,
    contract_sha256,
    forbidden_input_columns,
)


_MARKET_SOURCE_TO_OUTPUT = {
    "benchmark_return_21": "ofs_v1_market_return_21",
    "benchmark_return_63": "ofs_v1_market_return_63",
    "benchmark_return_252": "ofs_v1_market_return_252",
    "benchmark_realized_vol_20": "ofs_v1_market_volatility_20",
    "benchmark_realized_vol_63": "ofs_v1_market_volatility_63",
    "benchmark_drawdown_252": "ofs_v1_market_drawdown_252",
    "benchmark_sma_50_vs_200": "ofs_v1_market_sma_50_vs_200",
    "benchmark_trend_efficiency_63": "ofs_v1_market_trend_efficiency_63",
}


@dataclass(frozen=True)
class ObservableStateResult:
    features: pd.DataFrame
    group_columns: tuple[str, ...]
    relative_source_present: bool
    relative_available_rows: int
    contract_sha256: str

    def __post_init__(self) -> None:
        if tuple(self.features.columns) != FEATURE_OUTPUT_COLUMNS:
            raise ObservableStateContractError("generated feature schema differs from contract")
        if self.features.columns.has_duplicates:
            raise ObservableStateContractError("generated feature columns are duplicated")
        values = self.features.to_numpy(dtype=np.float64)
        if np.isinf(values).any():
            raise ObservableStateContractError("generated state contains infinity")
        if self.relative_available_rows < 0 or self.relative_available_rows > len(self.features):
            raise ObservableStateContractError("relative availability count is invalid")


def _numeric(frame: pd.DataFrame, column: str) -> pd.Series:
    values = pd.to_numeric(frame[column], errors="coerce").astype("float64")
    return values.mask(~np.isfinite(values.to_numpy(dtype=np.float64)))


def _positive_log(values: pd.Series) -> pd.Series:
    numeric = values.to_numpy(dtype=np.float64)
    output = np.full(len(values), np.nan, dtype=np.float64)
    valid = np.isfinite(numeric) & (numeric > 0.0)
    output[valid] = np.log(numeric[valid])
    return pd.Series(output, index=values.index, dtype="float64")


def _rolling_midrank(values: np.ndarray, *, window: int, minimum: int) -> np.ndarray:
    output = np.full(len(values), np.nan, dtype=np.float64)
    for position, current in enumerate(values):
        if not np.isfinite(current):
            continue
        start = max(0, position - window + 1)
        sample = values[start : position + 1]
        sample = sample[np.isfinite(sample)]
        if len(sample) < minimum:
            continue
        less = int(np.count_nonzero(sample < current))
        equal = int(np.count_nonzero(sample == current))
        output[position] = (less + 0.5 * equal) / len(sample)
    return output


def _rolling_slope(values: np.ndarray, *, window: int, minimum: int) -> np.ndarray:
    output = np.full(len(values), np.nan, dtype=np.float64)
    for position in range(len(values)):
        start = max(0, position - window + 1)
        sample = values[start : position + 1]
        valid = np.isfinite(sample)
        if int(valid.sum()) < minimum:
            continue
        x = np.arange(len(sample), dtype=np.float64)[valid]
        y = sample[valid]
        centered_x = x - x.mean()
        denominator = float(centered_x @ centered_x)
        if denominator > 0.0:
            output[position] = float(centered_x @ (y - y.mean()) / denominator)
    return output


def _one_step_state_features(log_pe: np.ndarray) -> tuple[np.ndarray, ...]:
    """Emit only state known before observing the current row, then update internally."""

    prior_level = np.full(len(log_pe), np.nan, dtype=np.float64)
    prior_slope = np.full(len(log_pe), np.nan, dtype=np.float64)
    innovation_lag1 = np.full(len(log_pe), np.nan, dtype=np.float64)
    abs_innovation_lag1 = np.full(len(log_pe), np.nan, dtype=np.float64)
    level = np.nan
    slope = 0.0
    previous_innovation = np.nan
    initialized = False

    for position, observation in enumerate(log_pe):
        if initialized:
            predicted = level + slope
            prior_level[position] = predicted
            prior_slope[position] = slope
            innovation_lag1[position] = previous_innovation
            if np.isfinite(previous_innovation):
                abs_innovation_lag1[position] = abs(previous_innovation)
        else:
            predicted = np.nan

        if not np.isfinite(observation):
            if initialized:
                level = predicted
            previous_innovation = np.nan
            continue
        if not initialized:
            level = float(observation)
            slope = 0.0
            initialized = True
            previous_innovation = np.nan
            continue

        innovation = float(observation - predicted)
        level = float(predicted + STATE_LEVEL_ALPHA * innovation)
        slope = float(slope + STATE_SLOPE_BETA * innovation)
        previous_innovation = innovation
    return prior_level, prior_slope, innovation_lag1, abs_innovation_lag1


def _regime_features(group: pd.DataFrame) -> dict[str, np.ndarray]:
    raw = np.column_stack(
        [
            _numeric(group, column).to_numpy(dtype=np.float64)
            for column in ("p_bear", "p_sideways", "p_bull")
        ]
    )
    valid = np.isfinite(raw).all(axis=1) & (raw >= 0.0).all(axis=1)
    totals = raw.sum(axis=1)
    valid &= totals > 0.0
    probabilities = np.full_like(raw, np.nan, dtype=np.float64)
    probabilities[valid] = raw[valid] / totals[valid, None]
    entropy = np.full(len(group), np.nan, dtype=np.float64)
    confidence = np.full(len(group), np.nan, dtype=np.float64)
    margin = np.full(len(group), np.nan, dtype=np.float64)
    duration = np.full(len(group), np.nan, dtype=np.float64)
    if valid.any():
        safe = np.clip(probabilities[valid], 1e-15, 1.0)
        entropy[valid] = -(safe * np.log(safe)).sum(axis=1) / np.log(3.0)
        ordered = np.sort(probabilities[valid], axis=1)
        confidence[valid] = ordered[:, -1]
        margin[valid] = ordered[:, -1] - ordered[:, -2]
    previous_state = -1
    run_length = 0
    for position in range(len(group)):
        if not valid[position]:
            previous_state = -1
            run_length = 0
            continue
        state = int(np.argmax(probabilities[position]))
        run_length = run_length + 1 if state == previous_state else 1
        duration[position] = float(run_length)
        previous_state = state
    return {
        "ofs_v1_regime_p_bear": probabilities[:, 0],
        "ofs_v1_regime_p_sideways": probabilities[:, 1],
        "ofs_v1_regime_p_bull": probabilities[:, 2],
        "ofs_v1_regime_entropy": entropy,
        "ofs_v1_regime_confidence": confidence,
        "ofs_v1_regime_margin": margin,
        "ofs_v1_regime_duration": duration,
    }


def _derive_group(group: pd.DataFrame, *, relative_source_present: bool) -> pd.DataFrame:
    output = pd.DataFrame(index=group.index)
    observed_log = _positive_log(_numeric(group, "observed_pe"))
    lagged_log = observed_log.shift(1)
    lagged_values = lagged_log.to_numpy(dtype=np.float64)
    output["ofs_v1_val_log_pe_lag1"] = lagged_log
    output["ofs_v1_val_earnings_yield_lag1"] = np.exp(-lagged_log)

    rolling_63 = lagged_log.rolling(63, min_periods=10)
    rolling_252 = lagged_log.rolling(252, min_periods=20)
    median_63 = rolling_63.median()
    median_252 = rolling_252.median()
    mean_252 = rolling_252.mean()
    std_252 = rolling_252.std(ddof=0).replace(0.0, np.nan)
    slope_21 = _rolling_slope(lagged_values, window=21, minimum=8)
    output["ofs_v1_val_log_median_63_lag1"] = median_63
    output["ofs_v1_val_log_median_252_lag1"] = median_252
    output["ofs_v1_val_percentile_252_lag1"] = _rolling_midrank(
        lagged_values, window=252, minimum=20
    )
    output["ofs_v1_val_zscore_252_lag1"] = (lagged_log - mean_252) / std_252
    output["ofs_v1_val_slope_21_lag1"] = slope_21
    output["ofs_v1_val_acceleration_21_lag1"] = slope_21 - pd.Series(
        slope_21, index=group.index
    ).shift(21).to_numpy(dtype=np.float64)
    output["ofs_v1_val_drawdown_252_lag1"] = lagged_log - rolling_252.max()
    output["ofs_v1_val_distance_median_252_lag1"] = lagged_log - median_252

    eps = _numeric(group, "eps_ttm")
    output["ofs_v1_eps_signed_log_level"] = np.sign(eps) * np.log1p(np.abs(eps))
    growth_126 = _numeric(group, "eps_ttm_growth_126")
    growth_252 = _numeric(group, "eps_ttm_growth_252")
    output["ofs_v1_eps_growth_126"] = growth_126
    output["ofs_v1_eps_growth_252"] = growth_252
    output["ofs_v1_eps_growth_curve"] = growth_126 - growth_252
    staleness = _numeric(group, "eps_staleness_days").clip(lower=0.0)
    period_age = _numeric(group, "eps_period_age_days").clip(lower=0.0)
    output["ofs_v1_eps_staleness_log1p"] = np.log1p(staleness)
    output["ofs_v1_eps_period_age_log1p"] = np.log1p(period_age)
    output["ofs_v1_eps_confidence_01"] = _numeric(group, "eps_confidence").clip(0.0, 100.0) / 100.0
    output["ofs_v1_eps_disagreement_log1p"] = np.log1p(np.abs(_numeric(group, "eps_disagreement")))
    output["ofs_v1_eps_approximation_flag"] = _numeric(group, "eps_approximation_flag").clip(
        0.0, 1.0
    )

    for source, destination in _MARKET_SOURCE_TO_OUTPUT.items():
        output[destination] = _numeric(group, source)
    for column, values in _regime_features(group).items():
        output[column] = values

    state = _one_step_state_features(observed_log.to_numpy(dtype=np.float64))
    for column, values in zip(
        (
            "ofs_v1_state_prior_log_pe",
            "ofs_v1_state_prior_slope",
            "ofs_v1_state_innovation_lag1",
            "ofs_v1_state_abs_innovation_lag1",
        ),
        state,
        strict=True,
    ):
        output[column] = values

    relative_available = np.zeros(len(group), dtype=np.float64)
    ticker_sector = np.full(len(group), np.nan, dtype=np.float64)
    ticker_market = np.full(len(group), np.nan, dtype=np.float64)
    sector_market = np.full(len(group), np.nan, dtype=np.float64)
    if relative_source_present:
        sector_log = _positive_log(_numeric(group, "sector_pe")).shift(1).to_numpy(dtype=np.float64)
        market_log = _positive_log(_numeric(group, "market_pe")).shift(1).to_numpy(dtype=np.float64)
        valid = np.isfinite(lagged_values) & np.isfinite(sector_log) & np.isfinite(market_log)
        relative_available[valid] = 1.0
        ticker_sector[valid] = lagged_values[valid] - sector_log[valid]
        ticker_market[valid] = lagged_values[valid] - market_log[valid]
        sector_market[valid] = sector_log[valid] - market_log[valid]
    output["ofs_v1_relative_available"] = relative_available
    output["ofs_v1_relative_ticker_sector_log_gap_lag1"] = ticker_sector
    output["ofs_v1_relative_ticker_market_log_gap_lag1"] = ticker_market
    output["ofs_v1_relative_sector_market_log_gap_lag1"] = sector_market
    return output.loc[:, list(FEATURE_OUTPUT_COLUMNS)].replace([np.inf, -np.inf], np.nan)


def _resolve_group_columns(frame: pd.DataFrame, requested: Sequence[str] | None) -> tuple[str, ...]:
    if requested is not None:
        columns = tuple(requested)
        if not columns or len(columns) != len(set(columns)):
            raise ObservableStateContractError("group columns must be non-empty and unique")
        missing = sorted(set(columns).difference(frame.columns))
        if missing:
            raise ObservableStateContractError(f"missing group columns: {missing}")
        return columns
    if {"seed", "entity_id"}.issubset(frame.columns):
        return ("seed", "entity_id")
    if {"seed", "symbol"}.issubset(frame.columns):
        return ("seed", "symbol")
    if "entity_id" in frame:
        return ("entity_id",)
    if "symbol" in frame:
        return ("symbol",)
    raise ObservableStateContractError(
        "an explicit entity group is required (entity_id/symbol, optionally with seed)"
    )


def generate_observable_state_features(
    frame: pd.DataFrame,
    *,
    group_columns: Sequence[str] | None = None,
) -> ObservableStateResult:
    """Generate a fixed-schema state frame using only rows at or before each decision.

    Valuation and temporal outputs at row ``t`` use ``observed_pe`` only through
    row ``t-1``. This makes the representation safe when same-row ``observed_pe``
    is the research training proxy.
    """

    if not isinstance(frame, pd.DataFrame) or frame.empty:
        raise ObservableStateContractError("input must be a non-empty pandas DataFrame")
    if frame.columns.has_duplicates:
        raise ObservableStateContractError("input columns must be unique")
    if not frame.index.is_unique:
        raise ObservableStateContractError("input index must be unique")
    forbidden = forbidden_input_columns([str(column) for column in frame.columns])
    if forbidden:
        raise ObservableStateContractError(f"evaluation/future columns are forbidden: {forbidden}")
    missing = sorted(set(REQUIRED_SOURCE_COLUMNS).difference(frame.columns))
    if missing:
        raise ObservableStateContractError(f"missing required observable sources: {missing}")
    relative_present = [column in frame for column in OPTIONAL_RELATIVE_SOURCE_COLUMNS]
    if any(relative_present) and not all(relative_present):
        raise ObservableStateContractError(
            "sector_pe and market_pe must be supplied together or both omitted"
        )

    groups = _resolve_group_columns(frame, group_columns)
    source = frame.copy()
    source["date"] = pd.to_datetime(source["date"], errors="coerce")
    if source["date"].isna().any():
        raise ObservableStateContractError("date must contain valid timestamps")
    if source.loc[:, list(groups)].isna().any().any():
        raise ObservableStateContractError("group identity cannot contain missing values")
    if source.duplicated([*groups, "date"]).any():
        raise ObservableStateContractError("each group/date identity must be unique")
    source["_ofs_v1_original_position"] = np.arange(len(source), dtype=np.int64)
    ordered = source.sort_values([*groups, "date"], kind="mergesort").reset_index(drop=True)

    derived = pd.DataFrame(index=ordered.index, columns=FEATURE_OUTPUT_COLUMNS, dtype="float64")
    grouped = ordered.groupby(list(groups), sort=False, observed=True, dropna=False)
    for indices in grouped.indices.values():
        positions = np.asarray(indices, dtype=np.int64)
        group = ordered.iloc[positions]
        group_features = _derive_group(group, relative_source_present=all(relative_present))
        derived.iloc[positions, :] = group_features.to_numpy(dtype=np.float64)
    derived["_ofs_v1_original_position"] = ordered["_ofs_v1_original_position"].to_numpy()
    restored = derived.sort_values("_ofs_v1_original_position", kind="mergesort").drop(
        columns="_ofs_v1_original_position"
    )
    restored.index = frame.index.copy()
    restored = restored.loc[:, list(FEATURE_OUTPUT_COLUMNS)].astype("float64")
    relative_rows = int((restored["ofs_v1_relative_available"] == 1.0).sum())
    return ObservableStateResult(
        features=restored,
        group_columns=groups,
        relative_source_present=all(relative_present),
        relative_available_rows=relative_rows,
        contract_sha256=contract_sha256(),
    )


__all__ = ["ObservableStateResult", "generate_observable_state_features"]
