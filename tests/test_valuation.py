from __future__ import annotations

import numpy as np
import pandas as pd

from pe_regime_v04.valuation import add_adaptive_valuation


def _frame(n: int) -> pd.DataFrame:
    steps = np.arange(n, dtype=float)
    observed = pd.Series(20.0 + 0.25 * steps + 0.30 * np.sin(steps / 5.0))
    expected = pd.Series(21.0 + 0.22 * steps)
    return pd.DataFrame(
        {
            "observed_pe": observed,
            "v04_expected_pe": expected,
            "negative_earnings_flag": 0,
            "eps_confidence": 90.0,
            "pe_history_count": np.arange(n),
            "v04_ml_regime_oos_gain": 0.01,
            "v04_ml_expected_pe_no_regime": expected * 1.01,
            "v04_ml_expected_pe_with_regime": expected,
        }
    )


def test_adaptive_gap_is_prefix_invariant() -> None:
    config = {
        "rolling_window": 30,
        "min_history": 10,
        "cheap_quantile": 0.15,
        "expensive_quantile": 0.85,
        "minimum_absolute_gap": 0.01,
    }
    prefix = add_adaptive_valuation(_frame(40), config)
    full = add_adaptive_valuation(_frame(60), config)
    columns = [
        "v04_gap_history_percentile",
        "v04_gap_robust_z",
        "v04_valuation_state_adaptive",
    ]
    pd.testing.assert_frame_equal(
        prefix[columns].reset_index(drop=True),
        full.iloc[:40][columns].reset_index(drop=True),
        check_dtype=False,
    )


def test_negative_or_nonfinite_pe_has_no_valuation_confidence() -> None:
    frame = _frame(20)
    frame.loc[10, "negative_earnings_flag"] = 1
    frame.loc[11, "v04_expected_pe"] = np.inf
    output = add_adaptive_valuation(
        frame,
        {
            "rolling_window": 10,
            "min_history": 3,
            "cheap_quantile": 0.15,
            "expensive_quantile": 0.85,
        },
    )
    assert pd.isna(output.loc[10, "v04_pe_gap_log"])
    assert output.loc[10, "v04_valuation_confidence"] == 0.0
    assert output.loc[10, "v04_valuation_state_adaptive"] == "NO_MEANINGFUL_PE"
    assert pd.isna(output.loc[11, "v04_pe_gap_log"])
    assert output.loc[11, "v04_valuation_confidence"] == 0.0
    numeric = output.select_dtypes(include=[np.number]).to_numpy(dtype=float)
    assert not np.isinf(numeric).any()


def test_nullable_pe_is_treated_as_invalid_not_three_valued() -> None:
    frame = _frame(20)
    frame["observed_pe"] = frame["observed_pe"].astype("Float64")
    frame["v04_expected_pe"] = frame["v04_expected_pe"].astype("Float64")
    frame.loc[10, "observed_pe"] = pd.NA
    frame.loc[11, "v04_expected_pe"] = pd.NA

    output = add_adaptive_valuation(
        frame,
        {
            "rolling_window": 10,
            "min_history": 3,
            "cheap_quantile": 0.15,
            "expensive_quantile": 0.85,
        },
    )

    for row in (10, 11):
        assert pd.isna(output.loc[row, "v04_expected_pe"])
        assert pd.isna(output.loc[row, "v04_pe_gap_log"])
        assert output.loc[row, "v04_valuation_confidence"] == 0.0
        assert output.loc[row, "v04_valuation_state_adaptive"] == "INSUFFICIENT_DATA"
