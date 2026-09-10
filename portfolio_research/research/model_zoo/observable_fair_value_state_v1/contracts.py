"""Fail-closed feature and ablation contract for Observable State V1."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any


class ObservableStateContractError(ValueError):
    """Raised when an input or requested representation can violate the V1 contract."""


FORMAT_VERSION = 1
LAB_ID = "observable_fair_value_state_v1"
DECISION_TIMING = "same_session_after_pit_fundamentals_and_market_state_are_available"
VALUATION_SOURCE_LAG_SESSIONS = 1
STATE_LEVEL_ALPHA = 0.08
STATE_SLOPE_BETA = 0.02

REQUIRED_SOURCE_COLUMNS = (
    "date",
    "observed_pe",
    "eps_ttm",
    "eps_ttm_growth_126",
    "eps_ttm_growth_252",
    "eps_staleness_days",
    "eps_period_age_days",
    "eps_confidence",
    "eps_disagreement",
    "eps_approximation_flag",
    "benchmark_return_21",
    "benchmark_return_63",
    "benchmark_return_252",
    "benchmark_realized_vol_20",
    "benchmark_realized_vol_63",
    "benchmark_drawdown_252",
    "benchmark_sma_50_vs_200",
    "benchmark_trend_efficiency_63",
    "p_bear",
    "p_sideways",
    "p_bull",
)
OPTIONAL_RELATIVE_SOURCE_COLUMNS = ("sector_pe", "market_pe")
SAFE_SOURCE_COLUMNS = (
    tuple(column for column in REQUIRED_SOURCE_COLUMNS if column != "date")
    + OPTIONAL_RELATIVE_SOURCE_COLUMNS
)

FORBIDDEN_EXACT_COLUMNS = frozenset(
    {
        "true_fair_pe",
        "true_regime",
        "true_observed_pe",
        "true_economic_eps_contemporaneous",
        "true_expected_pe_eligible",
    }
)
_FORBIDDEN_PATTERNS = (
    re.compile(r"^true_", re.IGNORECASE),
    re.compile(r"^future_", re.IGNORECASE),
    re.compile(r"(?:^|_)lead(?:_|$)", re.IGNORECASE),
)


@dataclass(frozen=True)
class FeatureDefinition:
    column_name: str
    family: str
    source_columns: tuple[str, ...]
    transform: str
    availability_lag_sessions: int
    uses_same_row_observed_pe: bool
    point_in_time_safe: bool = True
    future_rows_used: bool = False
    evaluation_truth_used: bool = False
    output_dtype: str = "float64"

    def __post_init__(self) -> None:
        if not self.column_name.startswith("ofs_v1_"):
            raise ObservableStateContractError("derived columns must use the ofs_v1_ prefix")
        if self.family not in {
            "VALUATION",
            "EPS",
            "MARKET",
            "REGIME",
            "TEMPORAL",
            "RELATIVE",
        }:
            raise ObservableStateContractError(f"unsupported feature family: {self.family}")
        if self.availability_lag_sessions < 0:
            raise ObservableStateContractError("availability lag must be non-negative")
        if self.uses_same_row_observed_pe:
            raise ObservableStateContractError("same-row observed_pe is forbidden in V1")
        if not self.point_in_time_safe or self.future_rows_used or self.evaluation_truth_used:
            raise ObservableStateContractError("unsafe features cannot enter Observable State V1")
        for source in self.source_columns:
            if source not in SAFE_SOURCE_COLUMNS:
                raise ObservableStateContractError(f"undeclared source column: {source}")


def _feature(
    name: str,
    family: str,
    sources: tuple[str, ...],
    transform: str,
    lag: int,
) -> FeatureDefinition:
    return FeatureDefinition(
        column_name=name,
        family=family,
        source_columns=sources,
        transform=transform,
        availability_lag_sessions=lag,
        uses_same_row_observed_pe=False,
    )


FEATURE_DEFINITIONS = (
    _feature("ofs_v1_val_log_pe_lag1", "VALUATION", ("observed_pe",), "log_then_shift_1", 1),
    _feature(
        "ofs_v1_val_earnings_yield_lag1",
        "VALUATION",
        ("observed_pe",),
        "reciprocal_then_shift_1",
        1,
    ),
    _feature(
        "ofs_v1_val_log_median_63_lag1",
        "VALUATION",
        ("observed_pe",),
        "rolling_median_63_on_lag1_log_pe",
        1,
    ),
    _feature(
        "ofs_v1_val_log_median_252_lag1",
        "VALUATION",
        ("observed_pe",),
        "rolling_median_252_on_lag1_log_pe",
        1,
    ),
    _feature(
        "ofs_v1_val_percentile_252_lag1",
        "VALUATION",
        ("observed_pe",),
        "midrank_percentile_252_on_lag1_log_pe",
        1,
    ),
    _feature(
        "ofs_v1_val_zscore_252_lag1",
        "VALUATION",
        ("observed_pe",),
        "rolling_zscore_252_on_lag1_log_pe",
        1,
    ),
    _feature(
        "ofs_v1_val_slope_21_lag1",
        "VALUATION",
        ("observed_pe",),
        "rolling_ols_slope_21_on_lag1_log_pe",
        1,
    ),
    _feature(
        "ofs_v1_val_acceleration_21_lag1",
        "VALUATION",
        ("observed_pe",),
        "slope_21_minus_its_21_session_lag",
        1,
    ),
    _feature(
        "ofs_v1_val_drawdown_252_lag1",
        "VALUATION",
        ("observed_pe",),
        "lag1_log_pe_minus_rolling_max_252",
        1,
    ),
    _feature(
        "ofs_v1_val_distance_median_252_lag1",
        "VALUATION",
        ("observed_pe",),
        "lag1_log_pe_minus_rolling_median_252",
        1,
    ),
    _feature("ofs_v1_eps_signed_log_level", "EPS", ("eps_ttm",), "signed_log1p", 0),
    _feature("ofs_v1_eps_growth_126", "EPS", ("eps_ttm_growth_126",), "identity", 0),
    _feature("ofs_v1_eps_growth_252", "EPS", ("eps_ttm_growth_252",), "identity", 0),
    _feature(
        "ofs_v1_eps_growth_curve",
        "EPS",
        ("eps_ttm_growth_126", "eps_ttm_growth_252"),
        "growth_126_minus_growth_252",
        0,
    ),
    _feature("ofs_v1_eps_staleness_log1p", "EPS", ("eps_staleness_days",), "nonnegative_log1p", 0),
    _feature(
        "ofs_v1_eps_period_age_log1p", "EPS", ("eps_period_age_days",), "nonnegative_log1p", 0
    ),
    _feature("ofs_v1_eps_confidence_01", "EPS", ("eps_confidence",), "clip_0_100_divide_100", 0),
    _feature("ofs_v1_eps_disagreement_log1p", "EPS", ("eps_disagreement",), "absolute_log1p", 0),
    _feature(
        "ofs_v1_eps_approximation_flag", "EPS", ("eps_approximation_flag",), "boolean_to_float", 0
    ),
    _feature("ofs_v1_market_return_21", "MARKET", ("benchmark_return_21",), "identity", 0),
    _feature("ofs_v1_market_return_63", "MARKET", ("benchmark_return_63",), "identity", 0),
    _feature("ofs_v1_market_return_252", "MARKET", ("benchmark_return_252",), "identity", 0),
    _feature(
        "ofs_v1_market_volatility_20", "MARKET", ("benchmark_realized_vol_20",), "identity", 0
    ),
    _feature(
        "ofs_v1_market_volatility_63", "MARKET", ("benchmark_realized_vol_63",), "identity", 0
    ),
    _feature("ofs_v1_market_drawdown_252", "MARKET", ("benchmark_drawdown_252",), "identity", 0),
    _feature("ofs_v1_market_sma_50_vs_200", "MARKET", ("benchmark_sma_50_vs_200",), "identity", 0),
    _feature(
        "ofs_v1_market_trend_efficiency_63",
        "MARKET",
        ("benchmark_trend_efficiency_63",),
        "identity",
        0,
    ),
    _feature(
        "ofs_v1_regime_p_bear", "REGIME", ("p_bear", "p_sideways", "p_bull"), "simplex_normalize", 0
    ),
    _feature(
        "ofs_v1_regime_p_sideways",
        "REGIME",
        ("p_bear", "p_sideways", "p_bull"),
        "simplex_normalize",
        0,
    ),
    _feature(
        "ofs_v1_regime_p_bull", "REGIME", ("p_bear", "p_sideways", "p_bull"), "simplex_normalize", 0
    ),
    _feature(
        "ofs_v1_regime_entropy",
        "REGIME",
        ("p_bear", "p_sideways", "p_bull"),
        "normalized_entropy",
        0,
    ),
    _feature(
        "ofs_v1_regime_confidence",
        "REGIME",
        ("p_bear", "p_sideways", "p_bull"),
        "largest_probability",
        0,
    ),
    _feature(
        "ofs_v1_regime_margin",
        "REGIME",
        ("p_bear", "p_sideways", "p_bull"),
        "largest_minus_second",
        0,
    ),
    _feature(
        "ofs_v1_regime_duration",
        "REGIME",
        ("p_bear", "p_sideways", "p_bull"),
        "causal_argmax_run_length",
        0,
    ),
    _feature(
        "ofs_v1_state_prior_log_pe",
        "TEMPORAL",
        ("observed_pe",),
        "one_step_local_linear_prior_fixed_gain",
        1,
    ),
    _feature(
        "ofs_v1_state_prior_slope",
        "TEMPORAL",
        ("observed_pe",),
        "one_step_local_linear_prior_slope_fixed_gain",
        1,
    ),
    _feature(
        "ofs_v1_state_innovation_lag1",
        "TEMPORAL",
        ("observed_pe",),
        "previous_session_one_step_innovation",
        1,
    ),
    _feature(
        "ofs_v1_state_abs_innovation_lag1",
        "TEMPORAL",
        ("observed_pe",),
        "absolute_previous_session_one_step_innovation",
        1,
    ),
    _feature(
        "ofs_v1_relative_available",
        "RELATIVE",
        ("observed_pe", "sector_pe", "market_pe"),
        "positive_finite_lag1_inputs_available",
        1,
    ),
    _feature(
        "ofs_v1_relative_ticker_sector_log_gap_lag1",
        "RELATIVE",
        ("observed_pe", "sector_pe"),
        "lag1_log_ticker_minus_lag1_log_sector",
        1,
    ),
    _feature(
        "ofs_v1_relative_ticker_market_log_gap_lag1",
        "RELATIVE",
        ("observed_pe", "market_pe"),
        "lag1_log_ticker_minus_lag1_log_market",
        1,
    ),
    _feature(
        "ofs_v1_relative_sector_market_log_gap_lag1",
        "RELATIVE",
        ("sector_pe", "market_pe"),
        "lag1_log_sector_minus_lag1_log_market",
        1,
    ),
)

FEATURE_OUTPUT_COLUMNS = tuple(item.column_name for item in FEATURE_DEFINITIONS)
if len(FEATURE_OUTPUT_COLUMNS) != len(set(FEATURE_OUTPUT_COLUMNS)):
    raise ObservableStateContractError("feature output columns must be unique")


@dataclass(frozen=True)
class AblationDefinition:
    ablation_id: str
    families: tuple[str, ...]
    requires_relative_data: bool
    purpose: str

    def __post_init__(self) -> None:
        if not self.ablation_id.startswith("ofs_v1_"):
            raise ObservableStateContractError("ablation ids must use the ofs_v1_ prefix")
        if len(self.families) != len(set(self.families)):
            raise ObservableStateContractError("ablation families must be unique")
        if self.requires_relative_data != ("RELATIVE" in self.families):
            raise ObservableStateContractError("relative ablation flag and family must agree")


ABLATIONS = (
    AblationDefinition(
        "ofs_v1_valuation_eps",
        ("VALUATION", "EPS"),
        False,
        "Tests valuation memory plus PIT earnings state without market conditioning.",
    ),
    AblationDefinition(
        "ofs_v1_valuation_eps_market",
        ("VALUATION", "EPS", "MARKET"),
        False,
        "Adds observable broad-market pressure while leaving regime and latent state out.",
    ),
    AblationDefinition(
        "ofs_v1_full_without_regime",
        ("VALUATION", "EPS", "MARKET", "TEMPORAL"),
        False,
        "Tests temporal state independently of regime probabilities.",
    ),
    AblationDefinition(
        "ofs_v1_full_with_regime",
        ("VALUATION", "EPS", "MARKET", "REGIME", "TEMPORAL"),
        False,
        "Primary single-entity representation; isolates the incremental regime block.",
    ),
    AblationDefinition(
        "ofs_v1_full_with_relative_if_available",
        ("VALUATION", "EPS", "MARKET", "REGIME", "TEMPORAL", "RELATIVE"),
        True,
        "Conditional panel representation; invalid unless explicit sector and market P/E exist.",
    ),
)


def forbidden_input_columns(columns: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    forbidden: list[str] = []
    for column in columns:
        text = str(column)
        if text in FORBIDDEN_EXACT_COLUMNS or any(
            pattern.search(text) for pattern in _FORBIDDEN_PATTERNS
        ):
            forbidden.append(text)
    return tuple(sorted(set(forbidden)))


def feature_columns_for_ablation(
    ablation_id: str,
    *,
    relative_data_available: bool,
) -> tuple[str, ...]:
    matches = [item for item in ABLATIONS if item.ablation_id == ablation_id]
    if len(matches) != 1:
        raise ObservableStateContractError(f"unknown ablation: {ablation_id}")
    selected = matches[0]
    if selected.requires_relative_data and not relative_data_available:
        raise ObservableStateContractError(
            "relative ablation requires explicit sector_pe and market_pe coverage"
        )
    families = set(selected.families)
    return tuple(item.column_name for item in FEATURE_DEFINITIONS if item.family in families)


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def contract_payload() -> dict[str, Any]:
    return {
        "format_version": FORMAT_VERSION,
        "lab_id": LAB_ID,
        "decision_timing": DECISION_TIMING,
        "valuation_source_lag_sessions": VALUATION_SOURCE_LAG_SESSIONS,
        "state_filter": {
            "type": "code_owned_fixed_gain_local_linear_filter",
            "level_alpha": STATE_LEVEL_ALPHA,
            "slope_beta": STATE_SLOPE_BETA,
            "emitted_state": "one_step_prior_and_previous_session_innovation_only",
            "smoothing": False,
            "full_sequence_fit": False,
        },
        "required_source_columns": list(REQUIRED_SOURCE_COLUMNS),
        "optional_relative_source_columns": list(OPTIONAL_RELATIVE_SOURCE_COLUMNS),
        "forbidden_exact_columns": sorted(FORBIDDEN_EXACT_COLUMNS),
        "features": [asdict(item) for item in FEATURE_DEFINITIONS],
        "ablations": [asdict(item) for item in ABLATIONS],
    }


def contract_sha256() -> str:
    return hashlib.sha256(canonical_json_bytes(contract_payload())).hexdigest()


__all__ = [
    "ABLATIONS",
    "DECISION_TIMING",
    "FEATURE_DEFINITIONS",
    "FEATURE_OUTPUT_COLUMNS",
    "FORMAT_VERSION",
    "LAB_ID",
    "OPTIONAL_RELATIVE_SOURCE_COLUMNS",
    "ObservableStateContractError",
    "REQUIRED_SOURCE_COLUMNS",
    "SAFE_SOURCE_COLUMNS",
    "STATE_LEVEL_ALPHA",
    "STATE_SLOPE_BETA",
    "canonical_json_bytes",
    "contract_payload",
    "contract_sha256",
    "feature_columns_for_ablation",
    "forbidden_input_columns",
]
