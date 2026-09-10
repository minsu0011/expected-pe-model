from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from pe_regime_v04.config import load_config
from pe_regime_v04.pipeline import V04_APPEND_COLUMNS, run_overlay


def test_sample_pipeline_smoke(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    frame = pd.read_csv(root / "sample_data" / "v03_high_sample.csv").iloc[:420]
    truth = pd.read_csv(root / "sample_data" / "v03_high_sample_truth.csv")
    input_csv = tmp_path / "input.csv"
    truth_csv = tmp_path / "truth.csv"
    frame.to_csv(input_csv, index=False)
    truth.to_csv(truth_csv, index=False)
    config = load_config()
    config["regime_stacker"].update(
        {"min_train": 80, "train_window": 240, "refit_every": 80, "n_estimators": 20}
    )
    config["statistics"].update({"global_min_history": 30, "global_lookback": 120})
    config["expected_pe"].update(
        {"min_train": 80, "train_window": 240, "refit_every": 80, "n_estimators": 25}
    )
    config["statistical_gate"].update({"min_history": 10, "loss_window": 40})
    config["ml_no_regime_gate"].update({"min_history": 10, "loss_window": 40})
    config["final_blend"].update({"min_history": 10, "loss_window": 40})
    config["valuation"].update({"min_history": 30, "rolling_window": 120})
    result = run_overlay(input_csv, tmp_path / "output", config, truth_csv=truth_csv)
    output = pd.read_csv(result["output_csv"])
    assert len(output) == len(frame)
    pd.testing.assert_series_equal(
        output["observed_pe"],
        frame["observed_pe"],
        check_names=True,
        check_dtype=False,
    )
    assert "v04_expected_pe" in output.columns
    assert "v04_return_forecast_p_sideways" in output.columns
    assert len(frame.columns) == 64
    assert len(V04_APPEND_COLUMNS) == 104
    assert len(output.columns) == 168
    assert V04_APPEND_COLUMNS[82] == "v04_market_conditioned_expected_pe"
    assert V04_APPEND_COLUMNS[83:87] == (
        "v04_fundamental_vintage_expected_pe",
        "v04_fundamental_vintage_mode",
        "v04_fundamental_vintage_usable_train_vintages",
        "v04_fundamental_vintage_fallback_used",
    )
    assert V04_APPEND_COLUMNS[87:93] == (
        "v04_lagged_market_conditioned_raw_expected_pe",
        "v04_gated_lagged_market_conditioned_expected_pe",
        "v04_gated_lagged_market_conditioned_paired_oos_count",
        "v04_gated_lagged_market_conditioned_challenger_weight",
        "v04_gated_lagged_market_conditioned_accepted",
        "v04_gated_lagged_market_conditioned_fallback_used",
    )
    assert V04_APPEND_COLUMNS[93:96] == (
        "v04_ml_weekly_median_shrinkage_expected_pe",
        "v04_ml_weekly_median_shrinkage_window_count",
        "v04_ml_weekly_median_shrinkage_fallback_used",
    )
    assert V04_APPEND_COLUMNS[-8:] == (
        "v04_matured_proxy_regularized_expected_pe",
        "v04_matured_proxy_baseline_oos_log_mae",
        "v04_matured_proxy_challenger_oos_log_mae",
        "v04_matured_proxy_paired_oos_count",
        "v04_matured_proxy_oos_gain",
        "v04_matured_proxy_challenger_weight",
        "v04_matured_proxy_accepted",
        "v04_matured_proxy_fallback_used",
    )
    assert tuple(output.columns[len(frame.columns) :]) == V04_APPEND_COLUMNS
    assert all(column.startswith("v04_") for column in V04_APPEND_COLUMNS)
    pd.testing.assert_series_equal(
        output["v04_market_conditioned_expected_pe"],
        output["v04_market_conditioned_kalman_diagnostic_expected_pe"].rename(
            "v04_market_conditioned_expected_pe"
        ),
        check_exact=True,
    )
    assert output["v04_fundamental_vintage_expected_pe"].isna().all()
    assert (output["v04_fundamental_vintage_mode"] == "unavailable_disabled").all()
    assert output["v04_lagged_market_conditioned_raw_expected_pe"].isna().all()
    assert output["v04_gated_lagged_market_conditioned_expected_pe"].isna().all()
    assert output["v04_ml_weekly_median_shrinkage_expected_pe"].isna().all()
    assert (output["v04_ml_weekly_median_shrinkage_window_count"] == 0).all()
    assert not output["v04_ml_weekly_median_shrinkage_fallback_used"].any()
    assert output["v04_matured_proxy_regularized_expected_pe"].isna().all()
    assert output["v04_matured_proxy_paired_oos_count"].eq(0).all()
    assert output["v04_matured_proxy_challenger_weight"].eq(0.0).all()
    assert not output["v04_matured_proxy_accepted"].any()
    assert not output["v04_matured_proxy_fallback_used"].any()
    assert Path(result["report_json"]).exists()


def test_overlay_rejects_an_already_overlaid_input(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    frame = pd.read_csv(root / "sample_data" / "v03_high_sample.csv").iloc[:120]
    frame["v04_existing"] = 1.0
    input_csv = tmp_path / "already_overlaid.csv"
    frame.to_csv(input_csv, index=False)
    config = load_config()
    try:
        run_overlay(input_csv, tmp_path / "output", config)
    except ValueError as exc:
        assert "already contains v0.4 overlay columns" in str(exc)
    else:
        raise AssertionError("Expected existing-v04 guard to fail closed")


def test_csv_adapter_preserves_ulp_sensitive_prefix_and_minimal_report(
    tmp_path: Path,
) -> None:
    ulp_probe = np.array(
        [
            np.nextafter(1.0, 2.0),
            np.nextafter(np.nextafter(1.0, 2.0), 2.0),
            0.1,
            np.nextafter(0.1, np.inf),
            1_000_000_000_000_000.1,
            np.nextafter(1_000_000_000_000_000.1, np.inf),
        ],
        dtype=np.float64,
    )
    frame = pd.DataFrame(
        {
            "date": pd.date_range("2020-01-02", periods=6, freq="B").strftime("%Y-%m-%d"),
            "benchmark_close": [100.0, 101.0, 102.0, 101.5, 103.0, 104.0],
            "observed_pe": [10.0, 10.5, np.nan, 11.0, 11.5, 12.0],
            "p_bear": [0.2] * 6,
            "p_sideways": [0.3] * 6,
            "p_bull": [0.5] * 6,
            "market_regime": ["BULL"] * 6,
            "ulp_probe": ulp_probe,
        }
    )
    input_csv = tmp_path / "minimal.csv"
    frame.to_csv(input_csv, index=False)
    config = load_config()
    config["regime_stacker"]["enabled"] = False
    config["statistics"].update({"global_min_history": 1, "global_lookback": 3})
    config["expected_pe"].update({"train_no_regime": False, "train_with_regime": False})
    for section in (
        "statistical_gate",
        "ml_no_regime_gate",
        "ml_matched_regime_gate",
        "ml_incumbent_gate",
        "final_guard",
    ):
        config[section].update({"min_history": 1, "loss_window": 3})
    config["final_blend"].update({"min_history": 1, "loss_window": 3})
    config["valuation"].update({"min_history": 1, "rolling_window": 3})

    result = run_overlay(input_csv, tmp_path / "minimal_output", config)
    input_round_trip = pd.read_csv(input_csv, float_precision="round_trip")
    output_round_trip = pd.read_csv(result["output_csv"], float_precision="round_trip")

    pd.testing.assert_frame_equal(
        output_round_trip.loc[:, input_round_trip.columns],
        input_round_trip,
        check_exact=True,
        check_dtype=True,
    )
    np.testing.assert_array_equal(
        output_round_trip["ulp_probe"].to_numpy(dtype=np.float64).view(np.uint64),
        input_round_trip["ulp_probe"].to_numpy(dtype=np.float64).view(np.uint64),
    )
    assert result["report"]["invariants"]["csv_float_precision"] == "round_trip"
    assert result["report"]["invariants"]["csv_frozen_prefix_round_trip_exact"] is True
    assert result["report"]["candidate_ablation"]["M6_v04_final_safe"]["coverage_rows"] == 4
    assert "M0_v03_expected_pe" not in result["report"]["candidate_ablation"]
