from __future__ import annotations

import pandas as pd

from pe_regime_v04.expected_pe import expected_pe_feature_columns


def test_expected_pe_allowlist_excludes_target_reconstruction_columns() -> None:
    frame = pd.DataFrame(
        columns=[
            "observed_pe",
            "close",
            "eps_ttm",
            "log_pe_lag_21",
            "benchmark_return_63",
            "pe_median_756_lag",
            "v04_current_p_bull",
            "v04_return_forecast_p_bull",
        ]
    )
    no_regime = expected_pe_feature_columns(frame, include_regime=False)
    with_regime = expected_pe_feature_columns(frame, include_regime=True)
    with_return_forecast = expected_pe_feature_columns(
        frame,
        include_regime=True,
        include_return_forecast=True,
    )
    assert "benchmark_return_63" in no_regime
    assert "pe_median_756_lag" in no_regime
    assert "v04_current_p_bull" in with_regime
    assert "v04_return_forecast_p_bull" not in with_regime
    assert "v04_return_forecast_p_bull" in with_return_forecast
    for forbidden in ["observed_pe", "close", "eps_ttm", "log_pe_lag_21"]:
        assert forbidden not in no_regime
        assert forbidden not in with_regime
        assert forbidden not in with_return_forecast
