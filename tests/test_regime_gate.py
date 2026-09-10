from __future__ import annotations

import os
import sys
from copy import deepcopy
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import pe_regime_v04.regime_stacker as regime_stacker
from pe_regime_v04.regime_stacker import (
    classwise_gate_stacker_with_existing_ensemble,
    gate_stacker_with_existing_ensemble,
    walk_forward_hierarchical_stacker,
)


def _probability_frames(
    base: np.ndarray,
    challenger: np.ndarray,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    frame = pd.DataFrame(base, columns=["p_bear", "p_sideways", "p_bull"])
    stacker = pd.DataFrame(
        challenger,
        columns=["stacker_p_bear", "stacker_p_sideways", "stacker_p_bull"],
    )
    return frame, stacker


def _stacker_config(**updates: object) -> dict[str, object]:
    config: dict[str, object] = {
        "enabled": True,
        "horizon": 5,
        "bull_return_threshold": 0.03,
        "bear_return_threshold": -0.03,
        "train_window": 240,
        "min_train": 80,
        "refit_every": 60,
        "n_estimators": 8,
        "learning_rate": 0.03,
        "num_leaves": 7,
        "min_child_samples": 10,
        "probability_floor": 0.01,
        "class_weight": None,
        "parallel_backend": "thread",
        "outer_n_jobs": 1,
        "n_jobs": 1,
    }
    config.update(updates)
    return config


def test_proxy_label_is_not_available_before_horizon() -> None:
    n = 80
    base = np.tile([0.35, 0.30, 0.35], (n, 1))
    stack = np.tile([0.15, 0.20, 0.65], (n, 1))
    frame = pd.DataFrame(base, columns=["p_bear", "p_sideways", "p_bull"])
    stacker = pd.DataFrame(
        stack,
        columns=["stacker_p_bear", "stacker_p_sideways", "stacker_p_bull"],
    )
    labels = pd.Series(np.full(n, 2.0))
    config = {
        "loss_window": 20,
        "min_history": 5,
        "improvement_margin": 0.0,
        "temperature": 0.05,
        "max_challenger_weight": 0.75,
    }
    first = gate_stacker_with_existing_ensemble(
        frame, stacker, labels, config, horizon=5
    )
    changed = labels.copy()
    changed.iloc[30] = 0.0
    second = gate_stacker_with_existing_ensemble(
        frame, stacker, changed, config, horizon=5
    )
    pd.testing.assert_series_equal(
        first.loc[:34, "v04_regime_stacker_weight"],
        second.loc[:34, "v04_regime_stacker_weight"],
    )
    assert first.loc[35, "v04_regime_stacker_weight"] != second.loc[
        35, "v04_regime_stacker_weight"
    ]


def test_guarded_regime_probabilities_sum_to_one() -> None:
    n = 40
    frame = pd.DataFrame(
        np.tile([0.4, 0.3, 0.3], (n, 1)),
        columns=["p_bear", "p_sideways", "p_bull"],
    )
    stacker = pd.DataFrame(
        np.tile([0.2, 0.5, 0.3], (n, 1)),
        columns=["stacker_p_bear", "stacker_p_sideways", "stacker_p_bull"],
    )
    labels = pd.Series(np.tile([0.0, 1.0, 2.0, 1.0], 10))
    output = gate_stacker_with_existing_ensemble(
        frame,
        stacker,
        labels,
        {
            "loss_window": 10,
            "min_history": 3,
            "temperature": 0.05,
            "max_challenger_weight": 0.75,
        },
        horizon=2,
    )
    total = output[["v04_p_bear", "v04_p_sideways", "v04_p_bull"]].sum(axis=1)
    assert np.allclose(total, 1.0)


def test_gate_uses_only_common_paired_history_with_disjoint_coverage() -> None:
    n = 24
    base = np.tile([0.6, 0.2, 0.2], (n, 1)).astype(float)
    challenger = np.tile([0.2, 0.2, 0.6], (n, 1)).astype(float)
    base[12:] = np.nan
    challenger[:12] = np.nan
    frame, stacker = _probability_frames(base, challenger)
    labels = pd.Series(np.tile([0.0, 1.0, 2.0], 8))

    output = gate_stacker_with_existing_ensemble(
        frame,
        stacker,
        labels,
        {"loss_window": 10, "min_history": 3, "improvement_margin": 0.0},
        horizon=1,
    )

    assert (output["v04_regime_proxy_paired_count"] == 0).all()
    assert (output["v04_regime_stacker_weight"] == 0.0).all()
    assert not output["v04_regime_stacker_accepted"].any()
    assert (output.loc[:11, "v04_regime_stacker_fallback_source"] == "incumbent_only").all()
    assert (output.loc[12:, "v04_regime_stacker_fallback_source"] == "challenger_only").all()
    np.testing.assert_array_equal(
        output.loc[:11, ["v04_p_bear", "v04_p_sideways", "v04_p_bull"]],
        base[:12],
    )
    np.testing.assert_array_equal(
        output.loc[12:, ["v04_p_bear", "v04_p_sideways", "v04_p_bull"]],
        challenger[12:],
    )


def test_equal_or_worse_gain_is_strict_no_harm() -> None:
    n = 48
    labels = pd.Series(np.tile([0.0, 1.0, 2.0], 16))
    base = np.full((n, 3), 0.1)
    base[np.arange(n), labels.to_numpy(dtype=int)] = 0.8
    challenger = np.tile([1.0 / 3.0] * 3, (n, 1))
    frame, stacker = _probability_frames(base, challenger)
    config = {
        "loss_window": 20,
        "min_history": 5,
        "improvement_margin": 0.0,
        "temperature": 0.02,
        "max_challenger_weight": 1.0,
    }

    worse = gate_stacker_with_existing_ensemble(
        frame, stacker, labels, config, horizon=1
    )
    equal_frame, equal_stacker = _probability_frames(base, base.copy())
    equal = gate_stacker_with_existing_ensemble(
        equal_frame, equal_stacker, labels, config, horizon=1
    )

    for output in (worse, equal):
        assert (output["v04_regime_stacker_weight"] == 0.0).all()
        assert not output["v04_regime_stacker_accepted"].any()
        np.testing.assert_array_equal(
            output[["v04_p_bear", "v04_p_sideways", "v04_p_bull"]], base
        )

    classwise_equal = classwise_gate_stacker_with_existing_ensemble(
        equal_frame, equal_stacker, labels, config, horizon=1
    )
    for name in ("bear", "sideways", "bull"):
        assert (classwise_equal[f"v04_balanced_weight_{name}"] == 0.0).all()
        assert not classwise_equal[f"v04_balanced_accepted_{name}"].any()
    np.testing.assert_array_equal(
        classwise_equal[
            ["v04_balanced_p_bear", "v04_balanced_p_sideways", "v04_balanced_p_bull"]
        ],
        base,
    )


def test_gate_rejects_nonfinite_or_non_simplex_rows_and_marks_fallback() -> None:
    n = 16
    base = np.tile([0.5, 0.3, 0.2], (n, 1)).astype(float)
    challenger = np.tile([0.2, 0.3, 0.5], (n, 1)).astype(float)
    base[5] = [0.5, 0.3, 0.3]
    base[6] = [np.inf, 0.0, 0.0]
    challenger[7] = [-0.1, 0.4, 0.7]
    base[8] = np.nan
    challenger[8] = np.nan
    frame, stacker = _probability_frames(base, challenger)
    labels = pd.Series(np.tile([0.0, 1.0, 2.0, 1.0], 4))

    output = gate_stacker_with_existing_ensemble(
        frame,
        stacker,
        labels,
        {"loss_window": 8, "min_history": 2, "improvement_margin": 0.0},
        horizon=1,
    )

    assert output.loc[5, "v04_regime_stacker_fallback_source"] == "challenger_only"
    assert output.loc[6, "v04_regime_stacker_fallback_source"] == "challenger_only"
    assert output.loc[7, "v04_regime_stacker_fallback_source"] == "incumbent_only"
    assert output.loc[8, "v04_regime_stacker_fallback_source"] == "unavailable"
    np.testing.assert_array_equal(
        output.loc[5, ["v04_p_bear", "v04_p_sideways", "v04_p_bull"]],
        challenger[5],
    )
    assert output.loc[8, ["v04_p_bear", "v04_p_sideways", "v04_p_bull"]].isna().all()
    assert output.loc[8, "v04_market_regime"] == "UNKNOWN"
    assert not output.loc[[5, 6, 7, 8], "v04_regime_stacker_accepted"].any()

    classwise = classwise_gate_stacker_with_existing_ensemble(
        frame,
        stacker,
        labels,
        {"loss_window": 8, "min_history": 2, "improvement_margin": 0.0},
        horizon=1,
    )
    assert classwise.loc[5, "v04_balanced_fallback_source"] == "challenger_only"
    assert classwise.loc[7, "v04_balanced_fallback_source"] == "incumbent_only"
    assert classwise.loc[8, "v04_balanced_fallback_source"] == "unavailable"
    assert classwise.loc[
        8,
        ["v04_balanced_p_bear", "v04_balanced_p_sideways", "v04_balanced_p_bull"],
    ].isna().all()


def test_logloss_and_classwise_gates_are_prefix_invariant() -> None:
    rng = np.random.default_rng(20260817)
    n = 80
    base = rng.dirichlet([2.0, 2.0, 2.0], size=n)
    challenger = rng.dirichlet([1.5, 2.5, 1.5], size=n)
    frame, stacker = _probability_frames(base, challenger)
    labels = pd.Series(rng.integers(0, 3, size=n), dtype=float)
    config = {
        "loss_window": 24,
        "min_history": 6,
        "improvement_margin": 0.001,
        "temperature": 0.02,
        "max_challenger_weight": 0.75,
    }

    for gate in (
        gate_stacker_with_existing_ensemble,
        classwise_gate_stacker_with_existing_ensemble,
    ):
        full = gate(frame, stacker, labels, config, horizon=4)
        prefix = gate(frame.iloc[:53], stacker.iloc[:53], labels.iloc[:53], config, horizon=4)
        pd.testing.assert_frame_equal(
            full.iloc[:53].reset_index(drop=True),
            prefix.reset_index(drop=True),
            check_exact=True,
        )


def test_classwise_gate_uses_paired_counts_and_strict_fallback() -> None:
    n = 30
    base = np.tile([0.6, 0.2, 0.2], (n, 1)).astype(float)
    challenger = np.tile([0.2, 0.2, 0.6], (n, 1)).astype(float)
    base[15:] = np.nan
    challenger[:15] = np.nan
    frame, stacker = _probability_frames(base, challenger)
    labels = pd.Series(np.tile([0.0, 1.0, 2.0], 10))

    output = classwise_gate_stacker_with_existing_ensemble(
        frame,
        stacker,
        labels,
        {"loss_window": 10, "min_history": 3, "improvement_margin": 0.0},
        horizon=2,
    )

    for name in ("bear", "sideways", "bull"):
        assert (output[f"v04_balanced_paired_count_{name}"] == 0).all()
        assert (output[f"v04_balanced_weight_{name}"] == 0.0).all()
        assert not output[f"v04_balanced_accepted_{name}"].any()
    assert (output.loc[:14, "v04_balanced_fallback_source"] == "incumbent_only").all()
    assert (output.loc[15:, "v04_balanced_fallback_source"] == "challenger_only").all()


def test_walk_forward_requires_full_usable_min_train(monkeypatch: pytest.MonkeyPatch) -> None:
    n = 125
    probabilities = np.tile([0.3, 0.4, 0.3], (n, 1)).astype(float)
    probabilities[:20] = np.nan
    frame = pd.DataFrame(
        {
            "benchmark_close": np.linspace(100.0, 120.0, n),
            "p_bear": probabilities[:, 0],
            "p_sideways": probabilities[:, 1],
            "p_bull": probabilities[:, 2],
        }
    )
    labels = pd.Series(np.resize([0.0, 1.0, 2.0], n), index=frame.index)
    monkeypatch.setattr(
        regime_stacker,
        "future_return_proxy_labels",
        lambda *args, **kwargs: labels.copy(),
    )

    output, diagnostics, _ = walk_forward_hierarchical_stacker(
        frame,
        _stacker_config(horizon=2, min_train=100, train_window=100, refit_every=100),
        seed=42,
    )

    assert output.isna().all().all()
    assert len(diagnostics) == 1
    assert diagnostics[0]["usable_train_rows"] == 80
    assert diagnostics[0]["required_usable_train_rows"] == 100
    assert diagnostics[0]["status"] == "skipped_insufficient_usable_train"


def test_serial_and_threaded_stacker_are_byte_exact() -> None:
    root = Path(__file__).resolve().parents[1]
    frame = pd.read_csv(root / "sample_data" / "v03_high_sample.csv").iloc[:420]
    frame = frame.reset_index(drop=True)
    serial_config = _stacker_config(outer_n_jobs=1, n_jobs=1)
    parallel_config = deepcopy(serial_config)
    parallel_config.update({"outer_n_jobs": 16, "n_jobs": 8})

    serial, serial_diagnostics, serial_labels = walk_forward_hierarchical_stacker(
        frame, serial_config, seed=42
    )
    parallel, parallel_diagnostics, parallel_labels = walk_forward_hierarchical_stacker(
        frame, parallel_config, seed=42
    )

    pd.testing.assert_frame_equal(serial, parallel, check_exact=True)
    pd.testing.assert_series_equal(serial_labels, parallel_labels, check_exact=True)
    assert [item["test_start"] for item in parallel_diagnostics] == sorted(
        item["test_start"] for item in parallel_diagnostics
    )
    ignored = {
        "outer_n_jobs_requested",
        "outer_n_jobs_effective",
        "outer_backend",
        "inner_n_jobs_requested",
        "inner_n_jobs_effective",
    }
    assert [
        {key: value for key, value in item.items() if key not in ignored}
        for item in serial_diagnostics
    ] == [
        {key: value for key, value in item.items() if key not in ignored}
        for item in parallel_diagnostics
    ]
    assert all(item["outer_backend"] == "thread" for item in parallel_diagnostics)
    assert all(item["inner_n_jobs_effective"] == 1 for item in parallel_diagnostics)
    assert all(item["class_weight"] is None for item in parallel_diagnostics)
    assert all(
        item["calibration_status"] == "natural_prior_raw"
        for item in parallel_diagnostics
    )
    assert all(item["subsample"] == 0.90 for item in parallel_diagnostics)
    assert all(item["subsample_freq"] == 1 for item in parallel_diagnostics)
    assert all(item["deterministic"] for item in parallel_diagnostics)
    assert all(item["force_col_wise"] for item in parallel_diagnostics)


def test_sklearn_fallback_is_explicit_in_fold_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    n = 48
    frame = pd.DataFrame(
        {
            "benchmark_close": np.linspace(100.0, 105.0, n),
            "p_bear": np.full(n, 0.3),
            "p_sideways": np.full(n, 0.4),
            "p_bull": np.full(n, 0.3),
        }
    )
    labels = pd.Series(np.resize([0.0, 1.0, 2.0], n), index=frame.index)
    monkeypatch.setattr(
        regime_stacker,
        "future_return_proxy_labels",
        lambda *args, **kwargs: labels.copy(),
    )
    monkeypatch.setitem(sys.modules, "lightgbm", None)

    _, diagnostics, _ = walk_forward_hierarchical_stacker(
        frame,
        _stacker_config(horizon=1, min_train=12, train_window=24, refit_every=20),
        seed=7,
    )

    successful = [item for item in diagnostics if item["status"] == "ok"]
    assert successful
    assert all(item["model_backend"] == "sklearn_logistic_regression" for item in successful)
    assert all(item["model_fallback_used"] for item in successful)
    assert all(item["backend"] == "sklearn_logistic_regression" for item in successful)
    assert all(item["fallback_reason"] for item in successful)
    assert all(item["class_weight"] is None for item in successful)


def test_threaded_fold_failure_is_ordered_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    n = 48
    frame = pd.DataFrame(
        {
            "benchmark_close": np.linspace(100.0, 105.0, n),
            "p_bear": np.full(n, 0.3),
            "p_sideways": np.full(n, 0.4),
            "p_bull": np.full(n, 0.3),
        }
    )
    labels = pd.Series(np.resize([0.0, 1.0, 2.0], n), index=frame.index)
    monkeypatch.setattr(
        regime_stacker,
        "future_return_proxy_labels",
        lambda *args, **kwargs: labels.copy(),
    )

    def fake_probability(
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_test: pd.DataFrame,
        config: dict[str, object],
        seed: int,
    ) -> tuple[np.ndarray, dict[str, object]]:
        del X_train, y_train, config
        if seed == 30:
            raise RuntimeError("intentional fold failure")
        return np.full(len(X_test), 0.4), {
            "model_backend": "test",
            "model_fallback_used": False,
            "class_weight": None,
            "calibration_status": "natural_prior_raw",
        }

    monkeypatch.setattr(regime_stacker, "_fit_binary_probability", fake_probability)
    output, diagnostics, _ = walk_forward_hierarchical_stacker(
        frame,
        _stacker_config(
            horizon=1,
            min_train=12,
            train_window=36,
            refit_every=10,
            outer_n_jobs=4,
        ),
        seed=7,
    )

    assert [item["test_start"] for item in diagnostics] == [13, 23, 33, 43]
    assert [item["status"] for item in diagnostics] == ["ok", "failed", "ok", "ok"]
    assert "intentional fold failure" in diagnostics[1]["error"]
    assert output.iloc[23:33].isna().all().all()
    assert output.iloc[13:23].notna().all().all()


def test_parallelism_and_natural_prior_fail_closed() -> None:
    with pytest.raises(ValueError, match="parallel_backend"):
        regime_stacker._parallel_settings(
            {"parallel_backend": "loky", "outer_n_jobs": 2}, fold_count=4
        )
    with pytest.raises(ValueError, match="outer_n_jobs"):
        regime_stacker._parallel_settings({"outer_n_jobs": 0}, fold_count=4)
    with pytest.raises(ValueError, match="class_weight"):
        regime_stacker._make_binary_classifier(
            {"outer_n_jobs": 1, "n_jobs": 1, "class_weight": "balanced"}, seed=42
        )

    settings = regime_stacker._parallel_settings(
        {"outer_n_jobs": (os.cpu_count() or 1) * 4, "n_jobs": 16},
        fold_count=(os.cpu_count() or 1) * 4,
    )
    assert settings[2] <= (os.cpu_count() or 1)
    assert settings[4] == 1
    serial_settings = regime_stacker._parallel_settings(
        {"parallel_backend": "serial", "outer_n_jobs": 16, "n_jobs": 1},
        fold_count=32,
    )
    assert serial_settings[0] == "serial"
    assert serial_settings[2] == 1
