from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from pe_regime_v04.config import DEFAULT_CONFIG, load_config, validate_config
from pe_regime_v04.fundamental_vintage import LOCKED_FUNDAMENTAL_VINTAGE_CONFIG
from pe_regime_v04.lagged_market_conditioned import (
    LOCKED_LAGGED_MARKET_CONDITIONED_CONFIG,
)
from pe_regime_v04.ml_incumbent_smoothing import (
    LOCKED_ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_CONFIG,
)
from pe_regime_v04.matured_proxy_gate import LOCKED_MATURED_PROXY_GATE_CONFIG


def test_invalid_valuation_quantiles_are_rejected() -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["valuation"]["cheap_quantile"] = 0.90
    config["valuation"]["expensive_quantile"] = 0.10
    with pytest.raises(ValueError, match="quantiles"):
        validate_config(config)


@pytest.mark.parametrize(
    ("section", "updates", "match"),
    [
        ("expected_pe", {"min_train": 379, "train_window": 378}, "train_window"),
        ("expected_pe", {"outer_n_jobs": 32, "n_jobs": 2}, "n_jobs"),
        ("expected_pe", {"parallel_backend": "loky"}, "parallel_backend"),
        ("expected_pe", {"subsample": 0.0}, "subsample"),
        ("regime_stacker", {"probability_floor": 1.0 / 3.0}, "probability_floor"),
        ("regime_stacker", {"horizon": -1}, "horizon"),
        ("statistical_gate", {"min_history": 253, "loss_window": 252}, "min_history"),
        ("final_guard", {"improvement_margin": 0.01, "decisive_margin": 0.002}, "decisive_margin"),
        ("expected_pe", {"max_depth": "bad"}, "max_depth"),
        ("expected_pe", {"fallback_max_iter": 0}, "fallback_max_iter"),
        ("expected_pe", {"deterministic": "false"}, "deterministic"),
        ("expected_pe", {"verbosity": "quiet"}, "verbosity"),
        ("valuation", {"minimum_absolute_gap": float("nan")}, "minimum_absolute_gap"),
        ("valuation", {"confirmed_robust_z": -1.0}, "confirmed_robust_z"),
        ("valuation", {"absolute_cheap_gap": 0.10}, "absolute gaps"),
    ],
)
def test_temporal_probability_and_parallel_contracts_fail_closed(
    section: str,
    updates: dict[str, object],
    match: str,
) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config[section].update(updates)
    with pytest.raises(ValueError, match=match):
        validate_config(config)


def test_unknown_config_key_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("expected_pe:\n  outer_workers_typo: 16\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        load_config(path)


def test_high_accuracy_expected_pe_defaults_match_v03_scheduler() -> None:
    expected = DEFAULT_CONFIG["expected_pe"]
    assert expected["train_window"] == 1890
    assert expected["min_train"] == 378
    assert expected["refit_every"] == 1
    assert expected["n_estimators"] == 200
    assert expected["num_leaves"] == 15
    assert expected["min_child_samples"] == 15
    assert expected["outer_n_jobs"] == 32
    assert expected["n_jobs"] == 1
    assert expected["subsample_freq"] == 1
    assert expected["include_return_forecast_features"] is False

    root = Path(__file__).resolve().parents[1]
    bundled = load_config(root / "config" / "v04_bottleneck.yaml")
    assert bundled["expected_pe"]["outer_n_jobs"] == 32
    assert bundled["expected_pe"]["n_jobs"] == 1
    assert bundled["regime_stacker"]["outer_n_jobs"] == 16
    assert bundled["regime_stacker"]["n_jobs"] == 1


def test_fundamental_vintage_defaults_and_bundled_config_are_locked() -> None:
    expected = {"enabled": False, **LOCKED_FUNDAMENTAL_VINTAGE_CONFIG}
    assert DEFAULT_CONFIG["fundamental_vintage"] == expected
    root = Path(__file__).resolve().parents[1]
    bundled = load_config(root / "config" / "v04_bottleneck.yaml")
    assert bundled["fundamental_vintage"] == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("min_completed_target_vintages", 3),
        ("min_usable_vintages", 7),
        ("max_train_vintages", 19),
        ("quantile", 0.4),
        ("alpha", float("nan")),
        ("solver", "interior-point"),
    ],
)
def test_fundamental_vintage_config_rejects_unlocked_values(field: str, value: object) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["fundamental_vintage"][field] = value
    with pytest.raises(ValueError, match=f"fundamental_vintage.{field}"):
        validate_config(config)


def test_lagged_market_conditioned_defaults_and_bundled_config_are_locked() -> None:
    expected = {"enabled": False, **LOCKED_LAGGED_MARKET_CONDITIONED_CONFIG}
    assert DEFAULT_CONFIG["lagged_market_conditioned"] == expected
    root = Path(__file__).resolve().parents[1]
    bundled = load_config(root / "config" / "v04_bottleneck.yaml")
    assert bundled["lagged_market_conditioned"] == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("q_over_r", 0.02),
        ("scale_window", 126),
        ("latent_weight", 0.50),
        ("incumbent_weight", 0.50),
        ("loss_window", 126),
        ("improvement_margin", 0.0),
        ("decision_mode", "soft"),
        ("availability_shift", 2),
    ],
)
def test_lagged_market_conditioned_config_rejects_unlocked_values(
    field: str,
    value: object,
) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["lagged_market_conditioned"][field] = value
    with pytest.raises(ValueError, match=f"lagged_market_conditioned.{field}"):
        validate_config(config)


def test_ml_incumbent_weekly_median_defaults_and_bundled_config_are_locked() -> None:
    expected = {
        "enabled": False,
        **LOCKED_ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_CONFIG,
    }
    assert DEFAULT_CONFIG["ml_incumbent_weekly_median_shrinkage"] == expected
    root = Path(__file__).resolve().parents[1]
    bundled = load_config(root / "config" / "v04_bottleneck.yaml")
    assert bundled["ml_incumbent_weekly_median_shrinkage"] == expected


def test_matured_proxy_gate_defaults_and_bundled_config_are_locked() -> None:
    expected = {"enabled": False, **LOCKED_MATURED_PROXY_GATE_CONFIG}
    assert DEFAULT_CONFIG["matured_proxy_gate"] == expected
    root = Path(__file__).resolve().parents[1]
    bundled = load_config(root / "config" / "v04_bottleneck.yaml")
    assert bundled["matured_proxy_gate"] == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("target_horizon_sessions", 20),
        ("target_method", "mean"),
        ("maturity_shift_sessions", 0),
        ("loss_window", 126),
        ("min_history", 62),
        ("improvement_margin", 0.001),
        ("temperature", 0.008),
        ("max_challenger_weight", 1.0),
        ("blend_method", "linear"),
    ],
)
def test_matured_proxy_gate_config_rejects_unlocked_values(field: str, value: object) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["matured_proxy_gate"][field] = value
    with pytest.raises(ValueError, match=f"matured_proxy_gate.{field}"):
        validate_config(config)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("window_sessions", 4),
        ("window_sessions", 5.0),
        ("incumbent_weight", 0.50),
        ("incumbent_weight", True),
        ("anchor_weight", 0.50),
        ("anchor_weight", float("nan")),
        ("method", "mean"),
    ],
)
def test_ml_incumbent_weekly_median_config_rejects_unlocked_values(
    field: str,
    value: object,
) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["ml_incumbent_weekly_median_shrinkage"][field] = value
    with pytest.raises(ValueError, match=f"ml_incumbent_weekly_median_shrinkage.{field}"):
        validate_config(config)


@pytest.mark.parametrize("outer_n_jobs", [16, 24])
def test_expected_pe_accepts_lower_outer_worker_overrides(outer_n_jobs: int) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["expected_pe"]["outer_n_jobs"] = outer_n_jobs
    validate_config(config)


def test_no_regime_shrinkage_default_and_yaml_are_fixed_at_half() -> None:
    assert DEFAULT_CONFIG["no_regime_shrinkage"]["weight"] == 0.50
    root = Path(__file__).resolve().parents[1]
    loaded = load_config(root / "config" / "v04_bottleneck.yaml")
    assert loaded["no_regime_shrinkage"]["weight"] == 0.50


@pytest.mark.parametrize(
    "weight",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.01,
        1.01,
        True,
        False,
        None,
        "bad",
    ],
)
def test_no_regime_shrinkage_weight_must_be_finite_unit_interval(
    weight: object,
) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["no_regime_shrinkage"]["weight"] = weight
    with pytest.raises(ValueError, match="no_regime_shrinkage.weight"):
        validate_config(config)


@pytest.mark.parametrize("weight", [0.0, 0.50, 1.0])
def test_no_regime_shrinkage_weight_accepts_endpoints(weight: float) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["no_regime_shrinkage"]["weight"] = weight
    validate_config(config)


def test_market_conditioned_diagnostic_defaults_and_yaml_are_exploration_locked() -> None:
    expected = {
        "enabled": True,
        "q_over_r": 0.01,
        "clip_sigma": 3.0,
        "scale_window": 252,
        "scale_min_history": 126,
        "scale_floor": 0.01,
        "latent_weight": 0.25,
    }
    assert DEFAULT_CONFIG["market_conditioned_diagnostic"] == expected
    root = Path(__file__).resolve().parents[1]
    loaded = load_config(root / "config" / "v04_bottleneck.yaml")
    assert loaded["market_conditioned_diagnostic"] == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "true"),
        ("q_over_r", 0.02),
        ("q_over_r", "0.01"),
        ("q_over_r", float("nan")),
        ("clip_sigma", float("inf")),
        ("clip_sigma", True),
        ("scale_window", 251),
        ("scale_window", 252.0),
        ("scale_min_history", 125),
        ("scale_floor", None),
        ("latent_weight", "bad"),
        ("latent_weight", 0.50),
    ],
)
def test_market_conditioned_diagnostic_rejects_unlocked_or_invalid_parameters(
    field: str,
    value: object,
) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["market_conditioned_diagnostic"][field] = value
    with pytest.raises(ValueError, match=f"market_conditioned_diagnostic.{field}"):
        validate_config(config)


def test_market_conditioned_diagnostic_unknown_key_is_rejected() -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["market_conditioned_diagnostic"]["future_tuning_knob"] = 1
    with pytest.raises(ValueError, match="unknown keys"):
        validate_config(config)
