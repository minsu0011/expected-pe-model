"""Synthetic tests for residual diagnostics."""

from __future__ import annotations

import numpy as np
import pandas as pd

from research.model_zoo.aggressive_lab.residual_diagnostics import (
    compute_residual_diagnostics,
)


def test_residual_diagnostics_recovers_serial_and_group_bias() -> None:
    rows = 200
    rng = np.random.default_rng(7)
    residual = np.empty(rows)
    residual[0] = 0.0
    for index in range(1, rows):
        residual[index] = 0.8 * residual[index - 1] + rng.normal(0.0, 0.01)
    truth = np.exp(3.0 + residual)
    frame = pd.DataFrame(
        {
            "seed": 1,
            "date": pd.date_range("2020-01-01", periods=rows),
            "prediction": np.exp(3.0),
            "true_fair_pe": truth,
            "eps_staleness_days": np.linspace(5, 500, rows),
            "eps_ttm_growth_126": np.linspace(-0.1, 0.1, rows),
            "benchmark_realized_vol_63": np.linspace(0.05, 0.4, rows),
            "benchmark_price_vs_sma_200": np.linspace(-0.2, 0.2, rows),
            "v04_current_p_bear": 0.2,
            "v04_current_p_sideways": 0.3,
            "v04_current_p_bull": 0.5,
        }
    )
    result = compute_residual_diagnostics(frame)
    lag_one = result["serial"].loc[result["serial"]["lag"] == 1].iloc[0]
    assert lag_one["autocorrelation"] > 0.6
    assert set(result) == {"rows", "serial", "subgroups", "correlations"}
    assert set(result["subgroups"]["group_family"]) == {
        "regime",
        "eps_staleness",
        "volatility",
        "market_trend",
        "eps_growth",
        "expected_pe_level",
    }
