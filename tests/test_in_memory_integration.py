from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import warnings

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.config import load_config
from pe_regime_v04.pipeline import V04_APPEND_COLUMNS, apply_v04_layers


_LEGACY_APPEND_SCHEMA_SHA256 = "b1efbbec3b667b224618ae0dcda405977bfaa3ad0c8c0dc65c636c532f7425a9"
_PRE_FUNDAMENTAL_APPEND_SCHEMA_SHA256 = (
    "03c6a09a1bde958f0ce4cd0a5c85e909b49d5c1c827762f137ebd8cb1c0fbcd0"
)
_PRE_LAGGED_APPEND_SCHEMA_SHA256 = (
    "68ac30bff2af92de050e581899c491b708ffdd40cb65f974c65df00d515ed4e1"
)
_PRE_SMOOTHING_APPEND_SCHEMA_SHA256 = (
    "9ff9f855f65c3b6dca7d401aa0c543cc1d0e9cfe01f88c33a3de3097a93f1966"
)
_LEGACY_MARKET_COLUMN = "v04_market_conditioned_kalman_diagnostic_expected_pe"
_PROMOTED_MARKET_COLUMN = "v04_market_conditioned_expected_pe"
_FUNDAMENTAL_TAIL = (
    "v04_fundamental_vintage_expected_pe",
    "v04_fundamental_vintage_mode",
    "v04_fundamental_vintage_usable_train_vintages",
    "v04_fundamental_vintage_fallback_used",
)
_LAGGED_TAIL = (
    "v04_lagged_market_conditioned_raw_expected_pe",
    "v04_gated_lagged_market_conditioned_expected_pe",
    "v04_gated_lagged_market_conditioned_paired_oos_count",
    "v04_gated_lagged_market_conditioned_challenger_weight",
    "v04_gated_lagged_market_conditioned_accepted",
    "v04_gated_lagged_market_conditioned_fallback_used",
)
_SMOOTHING_TAIL = (
    "v04_ml_weekly_median_shrinkage_expected_pe",
    "v04_ml_weekly_median_shrinkage_window_count",
    "v04_ml_weekly_median_shrinkage_fallback_used",
)
_MATURED_PROXY_TAIL = (
    "v04_matured_proxy_regularized_expected_pe",
    "v04_matured_proxy_baseline_oos_log_mae",
    "v04_matured_proxy_challenger_oos_log_mae",
    "v04_matured_proxy_paired_oos_count",
    "v04_matured_proxy_oos_gain",
    "v04_matured_proxy_challenger_weight",
    "v04_matured_proxy_accepted",
    "v04_matured_proxy_fallback_used",
)


# The supplied sample intentionally carries a compact 64-column projection. These
# are the other 86 names in v0.3's frozen canonical contract.
_MISSING_CANONICAL_COLUMNS = (
    "accession",
    "available_at",
    "benchmark_sma_20",
    "benchmark_sma_200",
    "benchmark_sma_50",
    "close",
    "earnings_yield",
    "effective_date",
    "ensemble_dynamic_active",
    "eps_definition",
    "eps_method",
    "eps_method_count",
    "eps_method_values",
    "eps_primary_method",
    "eps_quarter_sources",
    "eps_reconstruction_approximate",
    "eps_source_tag",
    "eps_split_factor",
    "eps_ttm",
    "eps_ttm_raw",
    "event_source",
    "expected_pe_blend_dynamic",
    "expected_pe_ml_oos_log_mae",
    "expected_pe_stat_oos_log_mae",
    "expected_pe_weight_ml",
    "expected_pe_weight_stat",
    "filed_at",
    "fiscal_period",
    "high",
    "log_pe_lag_21",
    "loss_hmm3",
    "loss_rule",
    "loss_sjm2_gate",
    "loss_sjm3",
    "low",
    "open",
    "pe_bear_log_mean",
    "pe_bear_log_std",
    "pe_bear_log_z",
    "pe_bear_percentile",
    "pe_bull_log_mean",
    "pe_bull_log_std",
    "pe_bull_log_z",
    "pe_bull_percentile",
    "pe_change_126",
    "pe_change_20",
    "pe_change_252",
    "pe_change_5",
    "pe_change_63",
    "pe_gap_log",
    "pe_lag_21",
    "pe_log_change_126",
    "pe_log_change_20",
    "pe_log_change_252",
    "pe_log_change_5",
    "pe_log_change_63",
    "pe_sideways_log_mean",
    "pe_sideways_log_std",
    "pe_sideways_log_z",
    "pe_sideways_percentile",
    "period_end",
    "price_basis",
    "regime_active_model_count",
    "regime_adjusted_valuation_score",
    "regime_conditional_pe_log_z",
    "regime_conditional_pe_percentile",
    "regime_confidence",
    "regime_diversity_factor",
    "regime_effective_model_count",
    "shares_source_tag",
    "sjm2_p_bear",
    "sjm2_p_bull",
    "sjm2_p_sideways",
    "source_tag",
    "stock_return_20",
    "stock_return_252",
    "stock_return_5",
    "stock_split",
    "symbol",
    "timestamp_exact",
    "valuation_confidence",
    "volume",
    "weight_hmm3",
    "weight_rule",
    "weight_sjm2_gate",
    "weight_sjm3",
)


def _full_canonical_frame(rows: int = 120) -> pd.DataFrame:
    root = Path(__file__).resolve().parents[1]
    frame = pd.read_csv(root / "sample_data" / "v03_high_sample.csv").iloc[:rows].copy()
    assert len(frame.columns) == 64
    for column in _MISSING_CANONICAL_COLUMNS:
        if column in {"symbol", "price_basis", "eps_method", "eps_definition"}:
            frame[column] = pd.Series(["AUDIT"] * len(frame), dtype="string")
        elif column in {
            "timestamp_exact",
            "eps_reconstruction_approximate",
            "ensemble_dynamic_active",
            "expected_pe_blend_dynamic",
        }:
            frame[column] = pd.Series([False] * len(frame), dtype="boolean")
        else:
            frame[column] = np.nan
    assert len(frame.columns) == len(set(frame.columns)) == 150
    return frame


def _fast_config() -> dict:
    config = load_config()
    config["regime_stacker"]["enabled"] = False
    config["statistics"].update({"global_min_history": 3, "global_lookback": 20})
    config["expected_pe"].update(
        {
            "train_no_regime": False,
            "train_with_regime": False,
            "min_train": 10,
            "train_window": 30,
            "refit_every": 10,
            "outer_n_jobs": 4,
        }
    )
    for section in (
        "statistical_gate",
        "ml_no_regime_gate",
        "ml_matched_regime_gate",
        "ml_incumbent_gate",
        "final_guard",
    ):
        config[section].update({"min_history": 3, "loss_window": 10})
    config["final_blend"].update({"min_history": 3, "loss_window": 10})
    config["valuation"].update({"min_history": 3, "rolling_window": 20})
    return config


def test_apply_v04_layers_preserves_all_150_columns_exactly() -> None:
    frame = _full_canonical_frame()
    snapshot = deepcopy(frame)
    output, diagnostics = apply_v04_layers(frame, _fast_config())

    pd.testing.assert_frame_equal(frame, snapshot, check_exact=True)
    pd.testing.assert_frame_equal(
        output.iloc[:, :150],
        snapshot,
        check_exact=True,
        check_dtype=True,
        check_column_type=True,
        check_index_type=True,
    )
    assert tuple(output.columns[150:]) == V04_APPEND_COLUMNS
    assert len(V04_APPEND_COLUMNS) == 104
    assert V04_APPEND_COLUMNS[82] == _PROMOTED_MARKET_COLUMN
    assert V04_APPEND_COLUMNS[83:87] == _FUNDAMENTAL_TAIL
    assert V04_APPEND_COLUMNS[87:93] == _LAGGED_TAIL
    assert V04_APPEND_COLUMNS[93:96] == _SMOOTHING_TAIL
    assert V04_APPEND_COLUMNS[96:] == _MATURED_PROXY_TAIL
    assert (
        hashlib.sha256("\0".join(V04_APPEND_COLUMNS[:82]).encode("utf-8")).hexdigest()
        == _LEGACY_APPEND_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256("\0".join(V04_APPEND_COLUMNS[:83]).encode("utf-8")).hexdigest()
        == _PRE_FUNDAMENTAL_APPEND_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256("\0".join(V04_APPEND_COLUMNS[:87]).encode("utf-8")).hexdigest()
        == _PRE_LAGGED_APPEND_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256("\0".join(V04_APPEND_COLUMNS[:93]).encode("utf-8")).hexdigest()
        == _PRE_SMOOTHING_APPEND_SCHEMA_SHA256
    )
    assert len(output.columns) == 254
    assert not output.columns.duplicated().any()
    assert all(column.startswith("v04_") for column in output.columns[150:])
    assert "stacker_p_bear" not in output.columns
    assert "v04_p_bear" not in output.columns
    assert diagnostics["invariants"]["all_input_columns_exact"] is True
    assert diagnostics["semantics"]["return_forecast_gate_status"] == (
        "not_gated_no_semantically_matched_baseline"
    )
    assert output["v04_fundamental_vintage_expected_pe"].isna().all()
    assert (output["v04_fundamental_vintage_mode"] == "unavailable_disabled").all()
    assert diagnostics["fundamental_vintage"]["status"] == "disabled"
    assert diagnostics["fundamental_vintage"]["current_price_consumed_as_feature"] is False
    assert diagnostics["fundamental_vintage"]["production_path_byte_exact_isolation_required"]
    assert output["v04_lagged_market_conditioned_raw_expected_pe"].isna().all()
    assert output["v04_gated_lagged_market_conditioned_expected_pe"].isna().all()
    assert diagnostics["lagged_market_conditioned"]["status"] == "disabled"
    assert output[_SMOOTHING_TAIL[0]].isna().all()
    assert (output[_SMOOTHING_TAIL[1]] == 0).all()
    assert not output[_SMOOTHING_TAIL[2]].any()
    assert diagnostics["ml_incumbent_weekly_median_shrinkage"]["status"] == "disabled"
    assert output[_MATURED_PROXY_TAIL[0]].isna().all()
    assert output[_MATURED_PROXY_TAIL[3]].eq(0).all()
    assert output[_MATURED_PROXY_TAIL[5]].eq(0.0).all()
    assert not output[[_MATURED_PROXY_TAIL[6], _MATURED_PROXY_TAIL[7]]].any().any()
    assert diagnostics["matured_proxy_gate"]["status"] == "unavailable_disabled"


def test_apply_v04_layers_rejects_duplicate_or_unsorted_dates() -> None:
    duplicate = _full_canonical_frame(20)
    duplicate.loc[duplicate.index[5], "date"] = duplicate.loc[duplicate.index[4], "date"]
    with pytest.raises(ValueError, match="date must be unique"):
        apply_v04_layers(duplicate, _fast_config())

    unsorted = _full_canonical_frame(20)
    unsorted.loc[unsorted.index[[4, 5]], "date"] = unsorted.loc[
        unsorted.index[[5, 4]], "date"
    ].to_numpy()
    with pytest.raises(ValueError, match="monotonically increasing"):
        apply_v04_layers(unsorted, _fast_config())


def test_negative_or_invalid_observed_pe_fails_closed() -> None:
    frame = _full_canonical_frame()
    negative_row = frame.index[70]
    invalid_row = frame.index[71]
    frame.loc[negative_row, "negative_earnings_flag"] = 1
    frame.loc[negative_row, "observed_pe"] = np.nan
    frame.loc[invalid_row, "observed_pe"] = np.nan

    output, _ = apply_v04_layers(frame, _fast_config())
    invalid_rows = [negative_row, invalid_row]
    nan_surfaces = [
        column
        for column in V04_APPEND_COLUMNS
        if "expected_pe" in column
        or "_oos_" in column
        or column.endswith("_blended")
        or column.startswith("v04_gap_")
        or column.startswith("v04_pe_gap_")
        or column == "v04_valuation_strength"
    ]
    assert output.loc[invalid_rows, nan_surfaces].isna().all(axis=None)

    weight_columns = [column for column in V04_APPEND_COLUMNS if column.endswith("_weight")]
    assert (output.loc[invalid_rows, weight_columns] == 0.0).all(axis=None)
    assert (output.loc[invalid_rows, "v04_valuation_confidence"] == 0.0).all()
    accepted_or_fallback = [
        column
        for column in V04_APPEND_COLUMNS
        if column.endswith("_accepted") or column.endswith("_fallback_used")
    ]
    assert (~output.loc[invalid_rows, accepted_or_fallback]).all(axis=None)
    assert output.loc[negative_row, "v04_valuation_state_adaptive"] == "NO_MEANINGFUL_PE"


def test_nullable_observed_pe_mask_fails_closed_without_runtime_warning() -> None:
    frame = _full_canonical_frame()
    frame["negative_earnings_flag"] = pd.Series(0, index=frame.index, dtype="Int64")
    frame["observed_pe"] = pd.Series(
        frame["observed_pe"].to_numpy(), index=frame.index, dtype="Float64"
    )
    invalid_rows = [frame.index[70], frame.index[71]]
    frame.loc[invalid_rows, "observed_pe"] = pd.NA

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        output, diagnostics = apply_v04_layers(frame, _fast_config())

    assert diagnostics["invariants"]["negative_or_invalid_observed_pe_fail_closed_rows"] == 2
    nan_surfaces = [
        column
        for column in V04_APPEND_COLUMNS
        if "expected_pe" in column
        or "_oos_" in column
        or column.endswith("_blended")
        or column.startswith("v04_gap_")
        or column.startswith("v04_pe_gap_")
        or column == "v04_valuation_strength"
    ]
    assert output.loc[invalid_rows, nan_surfaces].isna().all(axis=None)
    weight_columns = [column for column in V04_APPEND_COLUMNS if column.endswith("_weight")]
    assert (output.loc[invalid_rows, weight_columns] == 0.0).all(axis=None)
    assert (output.loc[invalid_rows, "v04_valuation_confidence"] == 0.0).all()


def test_current_and_forward_return_probabilities_are_not_mixed() -> None:
    frame = _full_canonical_frame()
    output, diagnostics = apply_v04_layers(frame, _fast_config())
    pd.testing.assert_series_equal(
        output["v04_current_p_bear"],
        frame["p_bear"].rename("v04_current_p_bear"),
        check_exact=True,
    )
    assert "v04_forecast_p_bear" not in output.columns
    assert "v04_balanced_p_bear" not in output.columns
    assert diagnostics["invariants"]["current_and_forward_return_probabilities_mixed"] is False


def test_missing_optional_negative_flag_uses_index_aligned_zero_default() -> None:
    frame = _full_canonical_frame(40).drop(columns=["negative_earnings_flag"])
    output, diagnostics = apply_v04_layers(frame, _fast_config())
    assert len(output) == len(frame)
    assert tuple(output.columns[: len(frame.columns)]) == tuple(frame.columns)
    assert diagnostics["invariants"]["negative_or_invalid_observed_pe_fail_closed_rows"] >= 0


def test_negative_flag_and_positive_observed_pe_contradiction_is_rejected() -> None:
    frame = _full_canonical_frame(40)
    frame.loc[frame.index[10], "negative_earnings_flag"] = 1
    frame.loc[frame.index[10], "observed_pe"] = 20.0
    with pytest.raises(ValueError, match="requires observed_pe to be missing"):
        apply_v04_layers(frame, _fast_config())


def test_negative_flag_enum_is_fail_closed() -> None:
    frame = _full_canonical_frame(40)
    frame.loc[frame.index[10], "negative_earnings_flag"] = 2
    with pytest.raises(ValueError, match="only 0/1"):
        apply_v04_layers(frame, _fast_config())


def test_no_regime_shrinkage_formula_endpoints_and_production_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frame = _full_canonical_frame(40)
    frame["ml_expected_pe"] = pd.Series(10.0, index=frame.index, dtype="Float64")

    def fixed_expected_pair(
        input_frame: pd.DataFrame,
        _config: dict,
        *,
        seed: int,
    ) -> tuple[pd.Series, pd.Series, list, list, list]:
        del seed
        no_regime = pd.Series(40.0, index=input_frame.index, dtype="Float64")
        with_regime = pd.Series(30.0, index=input_frame.index, dtype="Float64")
        return no_regime, with_regime, [], [], []

    monkeypatch.setattr(
        "pe_regime_v04.pipeline.walk_forward_expected_pe_pair",
        fixed_expected_pair,
    )
    expected_by_weight = {
        0.0: 10.0,
        0.25: float(np.exp(0.75 * np.log(10.0) + 0.25 * np.log(40.0))),
        1.0: 40.0,
    }
    production_reference: pd.Series | None = None
    for weight, expected in expected_by_weight.items():
        config = _fast_config()
        config["no_regime_shrinkage"]["weight"] = weight
        output, diagnostics = apply_v04_layers(frame, config)

        candidate = output["v04_ml_no_regime_shrinkage_expected_pe"]
        np.testing.assert_allclose(candidate.to_numpy(dtype=float), expected, rtol=1e-14)
        if weight in {0.0, 1.0}:
            assert candidate.iloc[0] == expected
        if production_reference is None:
            production_reference = output["v04_expected_pe"].copy()
        else:
            pd.testing.assert_series_equal(
                output["v04_expected_pe"], production_reference, check_exact=True
            )
        assert diagnostics["no_regime_shrinkage"]["weight"] == weight
        assert diagnostics["no_regime_shrinkage"]["both_available_rows"] == len(frame)
        assert diagnostics["no_regime_shrinkage"]["production_output_unchanged"] is True
        pd.testing.assert_frame_equal(output.iloc[:, :150], frame, check_exact=True)
        assert tuple(output.columns[150:]) == V04_APPEND_COLUMNS


def test_no_regime_shrinkage_nullable_availability_and_fail_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frame = _full_canonical_frame(20)
    frame["ml_expected_pe"] = pd.Series(10.0, index=frame.index, dtype="Float64")
    frame["observed_pe"] = pd.Series(
        frame["observed_pe"].to_numpy(), index=frame.index, dtype="Float64"
    )
    frame["negative_earnings_flag"] = pd.Series(0, index=frame.index, dtype="Int64")
    incumbent_values = [10.0, 10.0, pd.NA, pd.NA, -10.0, 10.0, np.inf, 0.0, 10.0]
    no_regime_values = [40.0, pd.NA, 40.0, pd.NA, 40.0, np.inf, -40.0, 40.0, 0.0]
    frame.loc[frame.index[:9], "ml_expected_pe"] = incumbent_values
    invalid_rows = frame.index[9:14]
    frame.loc[frame.index[9], "observed_pe"] = 0.0
    frame.loc[frame.index[10], "observed_pe"] = -1.0
    frame.loc[frame.index[11], "observed_pe"] = pd.NA
    frame.loc[frame.index[12], "observed_pe"] = np.inf
    frame.loc[frame.index[13], "negative_earnings_flag"] = 1
    frame.loc[frame.index[13], "observed_pe"] = pd.NA

    def mixed_expected_pair(
        input_frame: pd.DataFrame,
        _config: dict,
        *,
        seed: int,
    ) -> tuple[pd.Series, pd.Series, list, list, list]:
        del seed
        no_regime = pd.Series(40.0, index=input_frame.index, dtype="Float64")
        no_regime.iloc[:9] = no_regime_values
        with_regime = pd.Series(pd.NA, index=input_frame.index, dtype="Float64")
        return no_regime, with_regime, [], [], []

    monkeypatch.setattr(
        "pe_regime_v04.pipeline.walk_forward_expected_pe_pair",
        mixed_expected_pair,
    )
    config = _fast_config()
    config["no_regime_shrinkage"]["weight"] = 0.50
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        output, diagnostics = apply_v04_layers(frame, config)

    candidate = output["v04_ml_no_regime_shrinkage_expected_pe"]
    expected_first_nine = [20.0, 10.0, 40.0, np.nan, 40.0, 10.0, np.nan, 40.0, 10.0]
    np.testing.assert_allclose(
        candidate.iloc[:9].to_numpy(dtype=float),
        expected_first_nine,
        rtol=1e-14,
        equal_nan=True,
    )
    assert candidate.loc[invalid_rows].isna().all()
    audit = diagnostics["no_regime_shrinkage"]
    assert audit["both_available_rows"] == 7
    assert audit["incumbent_only_fallback_rows"] == 3
    assert audit["no_regime_only_fallback_rows"] == 3
    assert audit["neither_available_rows"] == 2
    assert audit["valuation_fail_closed_rows"] == 5
    assert audit["one_sided_fallback"] == "use_positive_finite_available_side"
    pd.testing.assert_frame_equal(output.iloc[:, :150], frame, check_exact=True)
    assert tuple(output.columns[150:]) == V04_APPEND_COLUMNS


def test_market_conditioned_promoted_alias_is_exact_and_isolated_from_production() -> None:
    frame = _full_canonical_frame()
    enabled_config = _fast_config()
    disabled_config = deepcopy(enabled_config)
    disabled_config["market_conditioned_diagnostic"]["enabled"] = False

    enabled, enabled_diagnostics = apply_v04_layers(frame, enabled_config)
    disabled, disabled_diagnostics = apply_v04_layers(frame, disabled_config)

    assert enabled[_LEGACY_MARKET_COLUMN].notna().any()
    pd.testing.assert_series_equal(
        enabled[_PROMOTED_MARKET_COLUMN],
        enabled[_LEGACY_MARKET_COLUMN].rename(_PROMOTED_MARKET_COLUMN),
        check_exact=True,
    )
    assert disabled[[_LEGACY_MARKET_COLUMN, _PROMOTED_MARKET_COLUMN]].isna().all(axis=None)
    pd.testing.assert_series_equal(
        disabled[_PROMOTED_MARKET_COLUMN],
        disabled[_LEGACY_MARKET_COLUMN].rename(_PROMOTED_MARKET_COLUMN),
        check_exact=True,
    )
    pd.testing.assert_frame_equal(
        enabled.drop(columns=[_LEGACY_MARKET_COLUMN, _PROMOTED_MARKET_COLUMN]),
        disabled.drop(columns=[_LEGACY_MARKET_COLUMN, _PROMOTED_MARKET_COLUMN]),
        check_exact=True,
    )
    pd.testing.assert_series_equal(
        enabled["v04_expected_pe"],
        disabled["v04_expected_pe"],
        check_exact=True,
    )
    valuation_columns = [
        column
        for column in V04_APPEND_COLUMNS
        if column.startswith("v04_gap_")
        or column.startswith("v04_pe_gap_")
        or column.startswith("v04_valuation_")
    ]
    pd.testing.assert_frame_equal(
        enabled[valuation_columns],
        disabled[valuation_columns],
        check_exact=True,
    )
    audit = enabled_diagnostics["market_conditioned_diagnostic"]
    assert audit["same_row_observed_pe_consumed"] is True
    assert audit["production_connected"] is False
    assert audit["production_path_byte_exact_isolation_required"] is True
    assert audit["legacy_diagnostic_output_column"] == _LEGACY_MARKET_COLUMN
    assert audit["promoted_parallel_output_column"] == _PROMOTED_MARKET_COLUMN
    assert audit["publication_status"] == "benchmark_promoted_parallel_surface"
    assert audit["formula_consumes_same_row_observed_pe"] is True
    assert audit["decision_timestamp"] == ("after_current_row_observed_pe_is_final_eod_only")
    assert audit["eod_only"] is True
    assert audit["main_expected_pe_path_connected"] is False
    assert audit["valuation_path_connected"] is False
    assert audit["fundamental_fair_pe_claim_allowed"] is False
    assert audit["promoted_alias_bit_exact"] is True
    assert disabled_diagnostics["market_conditioned_diagnostic"]["enabled"] is False


def test_market_conditioned_alias_fails_closed_on_invalid_rows() -> None:
    frame = _full_canonical_frame(24)
    frame["observed_pe"] = pd.Series(
        frame["observed_pe"].to_numpy(), index=frame.index, dtype="Float64"
    )
    frame["ml_expected_pe"] = pd.Series(
        frame["ml_expected_pe"].to_numpy(), index=frame.index, dtype="Float64"
    )
    frame["negative_earnings_flag"] = pd.Series(0, index=frame.index, dtype="Int64")
    invalid_rows = frame.index[:8]
    frame.loc[invalid_rows[0], "observed_pe"] = pd.NA
    frame.loc[invalid_rows[1], "observed_pe"] = 0.0
    frame.loc[invalid_rows[2], "observed_pe"] = -1.0
    frame.loc[invalid_rows[3], "observed_pe"] = np.inf
    frame.loc[invalid_rows[4], "ml_expected_pe"] = pd.NA
    frame.loc[invalid_rows[5], "ml_expected_pe"] = 0.0
    frame.loc[invalid_rows[6], "ml_expected_pe"] = -1.0
    frame.loc[invalid_rows[7], "negative_earnings_flag"] = 1
    frame.loc[invalid_rows[7], "observed_pe"] = pd.NA

    output, _ = apply_v04_layers(frame, _fast_config())

    assert (
        output.loc[invalid_rows, [_LEGACY_MARKET_COLUMN, _PROMOTED_MARKET_COLUMN]]
        .isna()
        .all(axis=None)
    )
    pd.testing.assert_series_equal(
        output[_PROMOTED_MARKET_COLUMN],
        output[_LEGACY_MARKET_COLUMN].rename(_PROMOTED_MARKET_COLUMN),
        check_exact=True,
    )


def test_market_conditioned_promotion_provenance_is_frozen() -> None:
    root = Path(__file__).resolve().parents[1]
    provenance = json.loads(
        (root / "config" / "v04_market_conditioned_promotion.json").read_text(encoding="utf-8")
    )
    assert provenance["status"] == "benchmark_promoted_parallel_surface"
    assert provenance["promotion_pass"] is True
    assert provenance["candidate_id"] == "kalman_diag_b25"
    assert provenance["evaluated_selection_column"] == _LEGACY_MARKET_COLUMN
    assert provenance["published_column"] == _PROMOTED_MARKET_COLUMN
    assert provenance["incumbent_column"] == "ml_expected_pe"
    assert provenance["selected_spec_sha256"] == (
        "6526c1b7cf74c5a2cbefd14cf71575602f1428e2e937fd541c3bad1975d05331"
    )
    assert provenance["candidate_logical_lock_sha256"] == (
        "c6600307c6f615c75a84aa64aeaa428ac117f729bcf4af0bf61e189271854e62"
    )
    assert provenance["heldout_report_logical_sha256"] == (
        "1f8f3cc5127b7f61f988c2bcb70c87fd8d5898c356e0491ab715b6ffb9b2e1e1"
    )
    assert provenance["exact_parameters"] == {
        "q_over_r": 0.01,
        "clip_sigma": 3.0,
        "scale_window": 252,
        "scale_min_history": 126,
        "scale_floor": 0.01,
        "latent_weight": 0.25,
    }
    assert provenance["same_row_observed_pe_consumed"] is True
    assert provenance["eod_only"] is True
    assert provenance["main_expected_pe_replaced"] is False
    assert provenance["valuation_connected"] is False
    assert provenance["fundamental_fair_pe_claim_allowed"] is False
    assert provenance["evidence_scope"] == "synthetic_generator_v5_only"


def test_fundamental_vintage_tail_is_price_free_and_isolated_from_prior_83_columns() -> None:
    root = Path(__file__).resolve().parents[1]
    canonical = pd.read_csv(
        root / "outputs" / "warmup_seed42_v03" / "DEMO_PE_Regime_DEMO_BENCH.csv"
    ).iloc[:900]
    assert len(canonical.columns) == 150
    enabled_config = _fast_config()
    enabled_config["fundamental_vintage"]["enabled"] = True
    disabled_config = deepcopy(enabled_config)
    disabled_config["fundamental_vintage"]["enabled"] = False

    enabled, enabled_diagnostics = apply_v04_layers(canonical, enabled_config)
    disabled, disabled_diagnostics = apply_v04_layers(canonical, disabled_config)

    pd.testing.assert_frame_equal(enabled.iloc[:, :233], disabled.iloc[:, :233], check_exact=True)
    pd.testing.assert_series_equal(
        enabled["v04_expected_pe"], disabled["v04_expected_pe"], check_exact=True
    )
    assert tuple(enabled.columns[150:233]) == V04_APPEND_COLUMNS[:83]
    assert tuple(enabled.columns[233:237]) == _FUNDAMENTAL_TAIL
    assert tuple(enabled.columns[237:243]) == _LAGGED_TAIL
    assert tuple(enabled.columns[243:246]) == _SMOOTHING_TAIL
    assert tuple(enabled.columns[246:]) == _MATURED_PROXY_TAIL
    assert enabled["v04_fundamental_vintage_expected_pe"].notna().any()
    assert disabled["v04_fundamental_vintage_expected_pe"].isna().all()
    assert (disabled["v04_fundamental_vintage_mode"] == "unavailable_disabled").all()
    assert enabled_diagnostics["fundamental_vintage"]["incumbent_fallback_used"] is False
    assert enabled_diagnostics["fundamental_vintage"]["production_connected"] is False
    assert enabled_diagnostics["fundamental_vintage"]["valuation_path_connected"] is False
    assert disabled_diagnostics["fundamental_vintage"]["status"] == "disabled"


def test_lagged_market_conditioned_tail_is_default_off_and_isolated_from_prior_87() -> None:
    root = Path(__file__).resolve().parents[1]
    canonical = pd.read_csv(
        root / "outputs" / "warmup_seed42_v03" / "DEMO_PE_Regime_DEMO_BENCH.csv"
    ).iloc[:900]
    enabled_config = _fast_config()
    enabled_config["lagged_market_conditioned"]["enabled"] = True
    disabled_config = deepcopy(enabled_config)
    disabled_config["lagged_market_conditioned"]["enabled"] = False

    enabled, enabled_diagnostics = apply_v04_layers(canonical, enabled_config)
    disabled, disabled_diagnostics = apply_v04_layers(canonical, disabled_config)

    pd.testing.assert_frame_equal(enabled.iloc[:, :237], disabled.iloc[:, :237], check_exact=True)
    assert tuple(enabled.columns[150:237]) == V04_APPEND_COLUMNS[:87]
    assert tuple(enabled.columns[237:243]) == _LAGGED_TAIL
    assert tuple(enabled.columns[243:246]) == _SMOOTHING_TAIL
    assert tuple(enabled.columns[246:]) == _MATURED_PROXY_TAIL
    assert enabled[_LAGGED_TAIL[0]].notna().any()
    assert enabled[_LAGGED_TAIL[1]].notna().any()
    assert disabled[[_LAGGED_TAIL[0], _LAGGED_TAIL[1]]].isna().all(axis=None)
    assert (disabled[_LAGGED_TAIL[3]] == 0.0).all()
    assert not disabled[[_LAGGED_TAIL[4], _LAGGED_TAIL[5]]].any().any()

    isolation_columns = [
        "v04_expected_pe",
        *[
            column
            for column in V04_APPEND_COLUMNS
            if column.startswith("v04_gap_")
            or column.startswith("v04_pe_gap_")
            or column.startswith("v04_valuation_")
        ],
    ]
    pd.testing.assert_frame_equal(
        enabled[isolation_columns],
        disabled[isolation_columns],
        check_exact=True,
    )
    audit = enabled_diagnostics["lagged_market_conditioned"]
    assert audit["same_row_observed_pe_consumed_for_prediction"] is False
    assert audit["incumbent_may_consume_same_row_price_derived_features"] is True
    assert audit["current_price_independence_claim_allowed"] is False
    assert audit["main_expected_pe_path_connected"] is False
    assert audit["valuation_path_connected"] is False
    assert audit["publication_position"] == "after_valuation_tail_only"
    assert disabled_diagnostics["lagged_market_conditioned"]["status"] == "disabled"


def test_ml_weekly_median_tail_is_default_off_and_isolated_from_prior_93() -> None:
    frame = _full_canonical_frame(120)
    enabled_config = _fast_config()
    enabled_config["ml_incumbent_weekly_median_shrinkage"]["enabled"] = True
    disabled_config = deepcopy(enabled_config)
    disabled_config["ml_incumbent_weekly_median_shrinkage"]["enabled"] = False

    enabled, enabled_diagnostics = apply_v04_layers(frame, enabled_config)
    disabled, disabled_diagnostics = apply_v04_layers(frame, disabled_config)

    pd.testing.assert_frame_equal(enabled.iloc[:, :243], disabled.iloc[:, :243], check_exact=True)
    assert tuple(enabled.columns[150:243]) == V04_APPEND_COLUMNS[:93]
    assert tuple(enabled.columns[243:246]) == _SMOOTHING_TAIL
    assert tuple(enabled.columns[246:]) == _MATURED_PROXY_TAIL
    assert enabled[_SMOOTHING_TAIL[0]].notna().any()
    assert enabled[_SMOOTHING_TAIL[1]].dtype == np.dtype("int64")
    assert disabled[_SMOOTHING_TAIL[1]].dtype == np.dtype("int64")
    assert disabled[_SMOOTHING_TAIL[0]].isna().all()
    assert (disabled[_SMOOTHING_TAIL[1]] == 0).all()
    assert not disabled[_SMOOTHING_TAIL[2]].any()

    isolation_columns = [
        "v04_expected_pe",
        *[
            column
            for column in V04_APPEND_COLUMNS
            if column.startswith("v04_gap_")
            or column.startswith("v04_pe_gap_")
            or column.startswith("v04_valuation_")
        ],
    ]
    pd.testing.assert_frame_equal(
        enabled[isolation_columns],
        disabled[isolation_columns],
        check_exact=True,
    )
    audit = enabled_diagnostics["ml_incumbent_weekly_median_shrinkage"]
    assert audit["direct_observed_pe_consumed"] is False
    assert audit["same_row_incumbent_consumed"] is True
    assert audit["pre_close_forecast_claim_allowed"] is False
    assert audit["main_expected_pe_path_connected"] is False
    assert audit["valuation_path_connected"] is False
    assert audit["publication_position"] == "after_valuation_tail_only"
    assert audit["pipeline_timeline_contract"] == ("globally_unique_monotone_date_single_timeline")
    assert audit["public_window_count_dtype"] == "int64"
    assert audit["invalid_valuation_window_count_behavior"] == (
        "retain_price_independent_operator_audit_count"
    )
    assert disabled_diagnostics["ml_incumbent_weekly_median_shrinkage"]["status"] == "disabled"


def test_ml_weekly_median_ignores_observed_intervention_then_publicly_masks_invalid_row() -> None:
    frame = _full_canonical_frame(40)
    config = _fast_config()
    config["ml_incumbent_weekly_median_shrinkage"]["enabled"] = True
    baseline, _ = apply_v04_layers(frame, config)

    observed_changed = frame.copy(deep=True)
    observed_changed.loc[observed_changed.index[20], "observed_pe"] *= 1.5
    changed, _ = apply_v04_layers(observed_changed, config)
    pd.testing.assert_series_equal(
        baseline[_SMOOTHING_TAIL[0]],
        changed[_SMOOTHING_TAIL[0]],
        check_exact=True,
    )

    invalid = frame.copy(deep=True)
    invalid_row = invalid.index[20]
    invalid.loc[invalid_row, "negative_earnings_flag"] = 1
    invalid.loc[invalid_row, "observed_pe"] = np.nan
    masked, _ = apply_v04_layers(invalid, config)
    assert pd.isna(masked.loc[invalid_row, _SMOOTHING_TAIL[0]])
    assert not bool(masked.loc[invalid_row, _SMOOTHING_TAIL[2]])
    assert masked[_SMOOTHING_TAIL[1]].dtype == np.dtype("int64")
    assert masked.loc[invalid_row, _SMOOTHING_TAIL[1]] == 5
    pd.testing.assert_series_equal(
        baseline.loc[baseline.index[21] :, _SMOOTHING_TAIL[0]],
        masked.loc[masked.index[21] :, _SMOOTHING_TAIL[0]],
        check_exact=True,
    )


def test_enabled_ml_weekly_median_requires_canonical_symbol_column() -> None:
    frame = _full_canonical_frame(20).drop(columns=["symbol"])
    config = _fast_config()
    config["ml_incumbent_weekly_median_shrinkage"]["enabled"] = True
    with pytest.raises(ValueError, match="requires a symbol column"):
        apply_v04_layers(frame, config)


def test_matured_proxy_tail_is_default_off_and_isolated_from_prior_96() -> None:
    root = Path(__file__).resolve().parents[1]
    frame = pd.read_csv(
        root / "outputs" / "warmup_seed42_v03" / "DEMO_PE_Regime_DEMO_BENCH.csv",
        float_precision="round_trip",
    ).iloc[:520]
    enabled_config = _fast_config()
    enabled_config["expected_pe"].update(
        {
            "train_no_regime": True,
            "train_with_regime": True,
            "min_train": 80,
            "train_window": 240,
            "refit_every": 80,
            "n_estimators": 20,
            "outer_n_jobs": 4,
        }
    )
    enabled_config["matured_proxy_gate"]["enabled"] = True
    disabled_config = deepcopy(enabled_config)
    disabled_config["matured_proxy_gate"]["enabled"] = False

    enabled, enabled_diagnostics = apply_v04_layers(frame, enabled_config)
    disabled, disabled_diagnostics = apply_v04_layers(frame, disabled_config)

    pd.testing.assert_frame_equal(enabled.iloc[:, :246], disabled.iloc[:, :246], check_exact=True)
    assert tuple(enabled.columns[150:246]) == V04_APPEND_COLUMNS[:96]
    assert tuple(enabled.columns[246:]) == _MATURED_PROXY_TAIL
    assert enabled[_MATURED_PROXY_TAIL[0]].notna().any()
    assert enabled[_MATURED_PROXY_TAIL[3]].max() >= 63
    assert disabled[_MATURED_PROXY_TAIL[0]].isna().all()
    assert disabled[_MATURED_PROXY_TAIL[3]].fillna(0).eq(0).all()
    assert disabled[_MATURED_PROXY_TAIL[5]].eq(0.0).all()
    assert not disabled[[_MATURED_PROXY_TAIL[6], _MATURED_PROXY_TAIL[7]]].any().any()

    isolation_columns = [
        "v04_expected_pe",
        *[
            column
            for column in V04_APPEND_COLUMNS[:96]
            if column.startswith("v04_gap_")
            or column.startswith("v04_pe_gap_")
            or column.startswith("v04_valuation_")
        ],
    ]
    pd.testing.assert_frame_equal(
        enabled[isolation_columns], disabled[isolation_columns], check_exact=True
    )
    audit = enabled_diagnostics["matured_proxy_gate"]
    assert audit["status"] == "ok"
    assert audit["availability_shift_sessions"] == 22
    assert audit["latest_target_observation_lag_sessions"] == 1
    assert audit["current_row_observed_target_consumed"] is False
    assert audit["synthetic_true_fair_pe_consumed"] is False
    assert audit["main_expected_pe_path_connected"] is False
    assert audit["valuation_path_connected"] is False
    assert audit["publication_position"] == "after_valuation_tail_only"
    assert disabled_diagnostics["matured_proxy_gate"]["status"] == "unavailable_disabled"
