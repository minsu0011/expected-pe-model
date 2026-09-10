from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.market_conditioned import (
    filter_market_conditioned_log_pe,
    market_conditioned_kalman_pe_diagnostic,
)


_LOCKED = {
    "enabled": True,
    "q_over_r": 0.01,
    "clip_sigma": 3.0,
    "scale_window": 252,
    "scale_min_history": 126,
    "scale_floor": 0.01,
    "latent_weight": 0.25,
}


def _filter(values: np.ndarray):
    return filter_market_conditioned_log_pe(
        values,
        q_over_r=0.01,
        clip_sigma=3.0,
        scale_window=252,
        scale_min_history=126,
        scale_floor=0.01,
    )


def test_prefix_and_future_intervention_are_exact() -> None:
    rng = np.random.default_rng(20260818)
    observed_log = np.log(20.0) + np.cumsum(rng.normal(0.0, 0.02, 700))
    observed_log[[17, 299]] = np.nan
    full = _filter(observed_log)

    prefix_length = 411
    prefix = _filter(observed_log[:prefix_length])
    np.testing.assert_array_equal(
        full.state_log_pe[:prefix_length],
        prefix.state_log_pe,
    )

    changed = observed_log.copy()
    changed[prefix_length:] += 7.0
    future_intervention = _filter(changed)
    np.testing.assert_array_equal(
        full.state_log_pe[:prefix_length],
        future_intervention.state_log_pe[:prefix_length],
    )


def test_same_row_observation_uses_only_past_scale_but_updates_current_state() -> None:
    observed_log = np.log(20.0) + 0.01 * np.sin(np.arange(500) / 9.0)
    position = 300
    baseline = _filter(observed_log)
    changed = observed_log.copy()
    changed[position] += 0.001
    intervention = _filter(changed)

    np.testing.assert_array_equal(
        baseline.state_log_pe[:position],
        intervention.state_log_pe[:position],
    )
    assert baseline.past_innovation_scale[position] == intervention.past_innovation_scale[position]
    assert baseline.state_log_pe[position] != intervention.state_log_pe[position]


@pytest.mark.parametrize(
    ("values", "overrides", "error", "message"),
    [
        (np.array([1.0, 2.0]), {"q_over_r": np.nan}, ValueError, "q_over_r"),
        (np.array([1.0, 2.0]), {"q_over_r": -0.01}, ValueError, "q_over_r"),
        (np.array([1.0, 2.0]), {"clip_sigma": 0.0}, ValueError, "clip_sigma"),
        (np.array([1.0, 2.0]), {"scale_window": 0}, ValueError, "scale_window"),
        (np.array([1.0, 2.0]), {"scale_window": 252.0}, ValueError, "scale_window"),
        (
            np.array([1.0, 2.0]),
            {"scale_min_history": 253},
            ValueError,
            "scale_min_history must be <= scale_window",
        ),
        (np.array([1.0, 2.0]), {"scale_floor": -0.01}, ValueError, "scale_floor"),
        (np.array([1.0, np.inf]), {}, ValueError, "not infinity"),
        (np.array([[1.0, 2.0]]), {}, ValueError, "one-dimensional"),
        (np.array(["1", "2"]), {}, TypeError, "real numeric dtype"),
        (np.array([True, False]), {}, TypeError, "real numeric dtype"),
        (np.array([1.0 + 1.0j]), {}, TypeError, "real numeric dtype"),
    ],
)
def test_low_level_filter_rejects_invalid_numeric_contract_without_warning(
    values: np.ndarray,
    overrides: dict[str, object],
    error: type[Exception],
    message: str,
) -> None:
    parameters: dict[str, object] = {
        "q_over_r": 0.01,
        "clip_sigma": 3.0,
        "scale_window": 252,
        "scale_min_history": 126,
        "scale_floor": 0.01,
    }
    parameters.update(overrides)
    with pytest.raises(error, match=message):
        filter_market_conditioned_log_pe(values, **parameters)


def test_invalid_observed_or_incumbent_pe_fails_closed_without_one_sided_fallback() -> None:
    observed = pd.Series(
        [20.0, 21.0, np.nan, -1.0, np.inf, 22.0, 23.0],
        dtype="Float64",
    )
    incumbent = pd.Series(
        [18.0, 18.5, 19.0, 19.5, 20.0, pd.NA, 21.0],
        dtype="Float64",
    )
    candidate, diagnostics = market_conditioned_kalman_pe_diagnostic(
        observed,
        incumbent,
        _LOCKED,
    )

    assert candidate.iloc[[0, 1, 6]].notna().all()
    assert candidate.iloc[[2, 3, 4, 5]].isna().all()
    assert diagnostics["same_row_observed_pe_consumed"] is True
    assert diagnostics["production_connected"] is False
    assert diagnostics["fundamental_fair_pe_claim_allowed"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("q_over_r", "0.01"),
        ("q_over_r", np.nan),
        ("clip_sigma", np.inf),
        ("scale_window", 252.0),
        ("latent_weight", 0.50),
    ],
)
def test_direct_diagnostic_api_rejects_invalid_or_unlocked_config(
    field: str,
    value: object,
) -> None:
    config = dict(_LOCKED)
    config[field] = value
    observed = pd.Series([20.0, 21.0])
    incumbent = pd.Series([19.0, 19.5])
    with pytest.raises(ValueError, match=f"market_conditioned_diagnostic.{field}"):
        market_conditioned_kalman_pe_diagnostic(observed, incumbent, config)


def test_sealed_21_seed_formula_and_metrics_reproduce_exactly() -> None:
    root = Path(__file__).resolve().parents[1]
    audit = root / "outputs" / "v04_local_level_fair_audit_20260818"
    prediction_path = audit / "causal_predictions.csv"
    assert hashlib.sha256(prediction_path.read_bytes()).hexdigest() == (
        "c99d9cad28a8f15cae15edc9a5ff1ac25928191c194e5a8c55ee8b5c78651ad6"
    )
    predictions = pd.read_csv(prediction_path, float_precision="round_trip")
    metric_rows = pd.read_csv(
        audit / "seed_candidate_metrics.csv",
        float_precision="round_trip",
    )
    metric_rows = metric_rows.loc[
        metric_rows["candidate_id"].eq("kalman_qr0p010_clip3__blend025")
    ].set_index("seed")

    for seed, group in predictions.groupby("seed", sort=True):
        observed_log = group["observed_log_pe"].to_numpy(dtype=np.float64)
        filtered = _filter(observed_log)
        np.testing.assert_array_equal(
            filtered.state_log_pe,
            group["kalman_qr0p010_clip3"].to_numpy(dtype=np.float64),
        )

        incumbent_log = group["incumbent_log_pe"].to_numpy(dtype=np.float64)
        fair_log = group["current_true_fair_log_pe"].to_numpy(dtype=np.float64)
        common = group["evaluation_common"].to_numpy(dtype=bool)
        candidate_log = 0.75 * incumbent_log + 0.25 * filtered.state_log_pe
        incumbent_error = incumbent_log[common] - fair_log[common]
        candidate_error = candidate_log[common] - fair_log[common]
        expected = metric_rows.loc[int(seed)]
        actual = np.array(
            [
                np.mean(np.abs(incumbent_error)),
                np.mean(np.abs(candidate_error)),
                np.sqrt(np.mean(np.square(incumbent_error))),
                np.sqrt(np.mean(np.square(candidate_error))),
            ]
        )
        sealed = expected[
            [
                "fair_baseline_log_mae",
                "fair_candidate_log_mae",
                "fair_baseline_log_rmse",
                "fair_candidate_log_rmse",
            ]
        ].to_numpy(dtype=np.float64)
        np.testing.assert_allclose(actual, sealed, rtol=0.0, atol=1e-15)
        assert int(common.sum()) == int(expected["common_rows"])
