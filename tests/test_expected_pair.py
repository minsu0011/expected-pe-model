from __future__ import annotations

import numpy as np
import pandas as pd

import pe_regime_v04.expected_pe as expected_module
from pe_regime_v04.expected_pe import (
    global_statistical_expected_pe,
    walk_forward_expected_pe_pair,
)


def _frame(rows: int = 96) -> pd.DataFrame:
    steps = np.arange(rows, dtype=float)
    p_bear = 0.25 + 0.03 * np.sin(steps / 9.0)
    p_bull = 0.35 + 0.03 * np.cos(steps / 11.0)
    p_sideways = 1.0 - p_bear - p_bull
    return pd.DataFrame(
        {
            "observed_pe": 20.0 + 0.02 * steps + 0.3 * np.sin(steps / 7.0),
            "benchmark_return_63": np.sin(steps / 13.0),
            "stock_return_63": np.cos(steps / 17.0),
            "eps_confidence": 70.0 + 10.0 * np.sin(steps / 19.0),
            "v04_current_p_bear": p_bear,
            "v04_current_p_sideways": p_sideways,
            "v04_current_p_bull": p_bull,
            "v04_return_forecast_p_bear": p_bear * 0.9,
            "v04_return_forecast_p_sideways": p_sideways * 1.05,
            "v04_return_forecast_p_bull": 1.0 - p_bear * 0.9 - p_sideways * 1.05,
            "v04_return_forecast_entropy": 0.7 + 0.02 * np.sin(steps / 8.0),
            "v04_return_forecast_confidence": 0.3 - 0.02 * np.sin(steps / 8.0),
        },
        index=pd.Index(np.arange(1000, 1000 + rows), name="source_row"),
    )


def _config(outer_n_jobs: int) -> dict[str, object]:
    return {
        "train_no_regime": True,
        "train_with_regime": True,
        "train_window": 64,
        "min_train": 24,
        "refit_every": 8,
        "n_estimators": 12,
        "learning_rate": 0.04,
        "num_leaves": 5,
        "min_child_samples": 5,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
        "n_jobs": 8,
        "outer_n_jobs": outer_n_jobs,
    }


def test_pair_outer_threads_are_exact_and_share_fold_contract() -> None:
    frame = _frame()
    serial_config = _config(16)
    serial_config["parallel_backend"] = "serial"
    parallel_config = _config(16)
    parallel_config["parallel_backend"] = "thread"
    serial = walk_forward_expected_pe_pair(frame, serial_config, seed=31)
    parallel = walk_forward_expected_pe_pair(frame, parallel_config, seed=31)
    pd.testing.assert_series_equal(serial[0], parallel[0], check_exact=True)
    pd.testing.assert_series_equal(serial[1], parallel[1], check_exact=True)

    serial_diagnostics = serial[2]
    parallel_diagnostics = parallel[2]
    assert len(serial_diagnostics) == len(parallel_diagnostics) > 0
    for serial_fold, parallel_fold in zip(serial_diagnostics, parallel_diagnostics):
        for key in (
            "test_start_position",
            "test_end_exclusive_position",
            "train_window_start_position",
            "train_window_end_exclusive_position",
            "train_rows",
            "test_rows",
            "train_row_hash",
            "test_row_hash",
            "seed",
            "backend",
            "fallback_reason",
        ):
            assert serial_fold[key] == parallel_fold[key]
        assert serial_fold["inner_n_jobs_effective"] == 1
        assert parallel_fold["inner_n_jobs_effective"] == 1
        assert serial_fold["outer_n_jobs_requested"] == 16
        assert serial_fold["outer_n_jobs_effective"] == 1
        assert serial_fold["outer_backend"] == "serial"
        assert parallel_fold["outer_n_jobs_effective"] > 1
        assert parallel_fold["outer_backend"] == "thread"
        assert serial_fold["no_regime"]["model_parameters"] == serial_fold[
            "with_regime"
        ]["model_parameters"]


def test_pair_uses_strict_common_min_train() -> None:
    frame = _frame(72)
    frame.loc[frame.index[::2], "observed_pe"] = np.nan
    _, _, diagnostics, _, _ = walk_forward_expected_pe_pair(
        frame,
        _config(1),
        seed=7,
    )
    assert diagnostics[0]["train_rows"] == 12
    assert diagnostics[0]["required_train_rows"] == 24
    assert diagnostics[0]["status"] == "skipped_insufficient_common_train_rows"
    assert diagnostics[3]["train_rows"] == 24
    assert diagnostics[3]["status"] == "ok"


def test_return_forecast_features_are_opt_in_without_changing_no_regime() -> None:
    frame = _frame()
    default_config = _config(1)
    opt_in_config = {**_config(1), "include_return_forecast_features": True}
    default = walk_forward_expected_pe_pair(frame, default_config, seed=43)
    opt_in = walk_forward_expected_pe_pair(frame, opt_in_config, seed=43)

    pd.testing.assert_series_equal(default[0], opt_in[0], check_exact=True)
    assert default[3] == opt_in[3]
    assert "v04_current_p_bull" in default[4]
    assert not any(column.startswith("v04_return_forecast_") for column in default[4])
    expected_added = {
        "v04_return_forecast_p_bear",
        "v04_return_forecast_p_sideways",
        "v04_return_forecast_p_bull",
        "v04_return_forecast_entropy",
        "v04_return_forecast_confidence",
    }
    assert set(opt_in[4]) - set(default[4]) == expected_added
    assert set(default[4]) - set(opt_in[4]) == set()


def test_pair_sanitizes_exponentiation_overflow(monkeypatch) -> None:
    class OverflowRegressor:
        def fit(self, X, y, sample_weight=None):
            return self

        def predict(self, X):
            return np.full(len(X), 1_000.0)

    monkeypatch.setattr(
        expected_module,
        "_resolve_backend",
        lambda: ("test_overflow_backend", "forced test backend"),
    )
    monkeypatch.setattr(
        expected_module,
        "_make_regressor",
        lambda config, *, backend, seed: (OverflowRegressor(), {"random_state": seed}),
    )
    no_regime, with_regime, diagnostics, _, _ = walk_forward_expected_pe_pair(
        _frame(40),
        {**_config(4), "min_train": 16, "train_window": 32, "refit_every": 8},
        seed=5,
    )
    assert no_regime.iloc[16:].isna().all()
    assert with_regime.iloc[16:].isna().all()
    ok_folds = [fold for fold in diagnostics if fold["status"] == "ok"]
    assert ok_folds
    assert all(
        fold["no_regime"]["nonfinite_or_nonpositive_prediction_count"] > 0
        and fold["with_regime"]["nonfinite_or_nonpositive_prediction_count"] > 0
        for fold in ok_folds
    )


def test_one_candidate_fold_failure_masks_both_matched_outputs() -> None:
    frame = _frame(56)
    frame["v04_current_p_bear"] = "not-a-number"
    no_regime, with_regime, diagnostics, _, _ = walk_forward_expected_pe_pair(
        frame,
        {**_config(4), "min_train": 16, "train_window": 40, "refit_every": 8},
        seed=17,
    )
    assert no_regime.iloc[16:].isna().all()
    assert with_regime.iloc[16:].isna().all()
    failed = [fold for fold in diagnostics if fold["status"] == "paired_failure"]
    assert failed
    assert all(fold["no_regime"]["status"] == "ok" for fold in failed)
    assert all(fold["with_regime"]["status"] == "failed" for fold in failed)
    assert all("paired_failure_reason" in fold for fold in failed)


def test_nullable_observed_pe_is_unambiguous_and_warning_free() -> None:
    frame = _frame(56)
    nullable = pd.Series(frame["observed_pe"], index=frame.index, dtype="Float64")
    nullable.iloc[9] = pd.NA
    frame["observed_pe"] = nullable

    with np.errstate(all="raise"):
        statistical = global_statistical_expected_pe(
            frame["observed_pe"],
            {"global_lookback": 12, "global_min_history": 4},
        )
        no_regime, with_regime, diagnostics, _, _ = walk_forward_expected_pe_pair(
            frame,
            {**_config(4), "min_train": 16, "train_window": 40, "refit_every": 8},
            seed=29,
        )

    assert statistical.dtype == np.dtype("float64")
    assert no_regime.notna().any()
    assert with_regime.notna().any()
    assert any(fold["status"] == "ok" for fold in diagnostics)
