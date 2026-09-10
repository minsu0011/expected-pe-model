from __future__ import annotations

import numpy as np
import pandas as pd

from pe_regime_v04.utility_gate import (
    shifted_candidate_gate,
    shifted_two_candidate_prior_blend,
)


def _safe_gate_config() -> dict[str, float | str]:
    return {
        "loss_window": 20,
        "min_history": 10,
        "improvement_margin": 0.001,
        "decisive_margin": 0.002,
        "temperature": 0.004,
        "max_challenger_weight": 1.0,
        "decision_mode": "winner_take_most",
    }


def test_current_target_cannot_change_current_weight() -> None:
    index = pd.RangeIndex(20)
    target = pd.Series(np.linspace(10.0, 12.0, len(index)), index=index)
    baseline = target * 1.03
    challenger = target * 1.01
    config = {
        "loss_window": 5,
        "min_history": 3,
        "improvement_margin": 0.0,
        "temperature": 0.01,
        "max_challenger_weight": 1.0,
    }
    first = shifted_candidate_gate(
        target, baseline, challenger, config, prefix="test"
    )
    changed = target.copy()
    changed.iloc[12] *= 10.0
    second = shifted_candidate_gate(
        changed, baseline, challenger, config, prefix="test"
    )
    assert first.loc[12, "test_challenger_weight"] == second.loc[
        12, "test_challenger_weight"
    ]
    assert first.loc[13, "test_challenger_weight"] != second.loc[
        13, "test_challenger_weight"
    ]


def test_consistently_worse_challenger_is_rejected_after_maturity() -> None:
    index = pd.RangeIndex(80)
    target = pd.Series(np.linspace(20.0, 30.0, len(index)), index=index)
    baseline = target * 1.01
    challenger = target * 1.20
    output = shifted_candidate_gate(
        target,
        baseline,
        challenger,
        _safe_gate_config(),
        prefix="safe",
    )
    mature = output["safe_baseline_oos_log_mae"].notna()
    assert mature.any()
    assert (output.loc[mature, "safe_challenger_weight"] == 0.0).all()
    assert np.array_equal(
        output.loc[mature, "safe_blended"].to_numpy(),
        baseline.loc[mature].to_numpy(),
    )


def test_tied_inferior_or_submargin_challenger_cannot_change_incumbent() -> None:
    target = pd.Series(np.full(80, 100.0))
    baseline = target * np.exp(0.010)

    # Worse, tied, and slightly better but still below the required margin.
    for challenger_error in (0.011, 0.010, 0.0095):
        challenger = target * np.exp(challenger_error)
        output = shifted_candidate_gate(
            target,
            baseline,
            challenger,
            _safe_gate_config(),
            prefix="strict",
        )
        mature = output["strict_paired_oos_count"].ge(10)
        assert mature.any()
        assert (output.loc[mature, "strict_challenger_weight"] == 0.0).all()
        assert (~output.loc[mature, "strict_accepted"]).all()
        assert np.array_equal(
            output.loc[mature, "strict_blended"].to_numpy(),
            baseline.loc[mature].to_numpy(),
        )


def test_accepted_is_exactly_positive_weight_and_improves_historical_loss() -> None:
    target = pd.Series(np.full(80, 100.0))
    baseline = target * np.exp(0.020)
    challenger = target * np.exp(0.005)
    output = shifted_candidate_gate(
        target,
        baseline,
        challenger,
        _safe_gate_config(),
        prefix="strict",
    )

    pd.testing.assert_series_equal(
        output["strict_accepted"],
        output["strict_challenger_weight"].gt(0.0).rename("strict_accepted"),
    )
    accepted = output["strict_accepted"]
    assert accepted.any()
    assert (output.loc[accepted, "strict_oos_gain"] > 0.001).all()
    blended_error = np.abs(np.log(output.loc[accepted, "strict_blended"] / target.loc[accepted]))
    baseline_error = np.abs(np.log(baseline.loc[accepted] / target.loc[accepted]))
    assert (blended_error < baseline_error).all()


def test_disjoint_history_is_not_mistaken_for_paired_oos_evidence() -> None:
    target = pd.Series(np.full(30, 100.0))
    baseline = pd.Series(np.nan, index=target.index)
    challenger = pd.Series(np.nan, index=target.index)
    baseline.iloc[:10] = 110.0
    challenger.iloc[10:20] = 101.0
    baseline.iloc[20:] = 110.0
    challenger.iloc[20:] = 101.0

    output = shifted_candidate_gate(
        target,
        baseline,
        challenger,
        {**_safe_gate_config(), "min_history": 5},
        prefix="paired",
    )

    assert output.loc[20, "paired_paired_oos_count"] == 0.0
    assert pd.isna(output.loc[20, "paired_baseline_oos_log_mae"])
    assert pd.isna(output.loc[20, "paired_challenger_oos_log_mae"])
    assert output.loc[20, "paired_challenger_weight"] == 0.0
    assert not output.loc[20, "paired_accepted"]
    assert output.loc[20, "paired_blended"] == baseline.loc[20]


def test_incumbent_missing_fallback_is_not_reported_as_promotion() -> None:
    target = pd.Series(np.full(40, 100.0))
    baseline = target * 1.02
    challenger = target * 1.01
    baseline.iloc[30] = np.inf

    output = shifted_candidate_gate(
        target,
        baseline,
        challenger,
        _safe_gate_config(),
        prefix="fallback",
    )

    assert output.loc[30, "fallback_fallback_used"]
    assert output.loc[30, "fallback_challenger_weight"] == 0.0
    assert not output.loc[30, "fallback_accepted"]
    assert output.loc[30, "fallback_blended"] == challenger.loc[30]

    invalid_challenger = challenger.copy()
    invalid_challenger.iloc[30] = -np.inf
    retained = shifted_candidate_gate(
        target,
        target * 1.02,
        invalid_challenger,
        _safe_gate_config(),
        prefix="fallback",
    )
    assert not retained.loc[30, "fallback_fallback_used"]
    assert retained.loc[30, "fallback_challenger_weight"] == 0.0
    assert retained.loc[30, "fallback_blended"] == target.loc[30] * 1.02


def test_prior_blend_losses_also_require_common_positive_finite_rows() -> None:
    target = pd.Series(np.full(30, 100.0))
    statistical = pd.Series(np.nan, index=target.index)
    machine_learning = pd.Series(np.nan, index=target.index)
    statistical.iloc[:10] = 110.0
    machine_learning.iloc[10:20] = 101.0
    statistical.iloc[20:] = 110.0
    machine_learning.iloc[20:] = 101.0
    output = shifted_two_candidate_prior_blend(
        target,
        statistical,
        machine_learning,
        {
            "loss_window": 20,
            "min_history": 5,
            "temperature": 0.012,
            "stat_prior": 0.10,
            "ml_prior": 0.90,
        },
        prefix="prior",
    )

    assert output.loc[20, "prior_paired_oos_count"] == 0.0
    assert pd.isna(output.loc[20, "prior_stat_oos_log_mae"])
    assert pd.isna(output.loc[20, "prior_ml_oos_log_mae"])
    assert np.isclose(output.loc[20, "prior_stat_weight"], 0.10)
    assert np.isclose(output.loc[20, "prior_ml_weight"], 0.90)


def test_candidate_and_prior_gates_are_prefix_invariant() -> None:
    index = pd.RangeIndex(100)
    target = pd.Series(100.0 + np.sin(np.arange(100) / 7.0), index=index)
    baseline = target * (1.02 + 0.002 * np.cos(np.arange(100) / 9.0))
    challenger = target * (1.01 + 0.002 * np.sin(np.arange(100) / 11.0))
    baseline.iloc[[8, 31, 73]] = np.nan
    challenger.iloc[[12, 31, 81]] = np.inf

    full_gate = shifted_candidate_gate(
        target,
        baseline,
        challenger,
        _safe_gate_config(),
        prefix="prefix",
    )
    short_gate = shifted_candidate_gate(
        target.iloc[:60],
        baseline.iloc[:60],
        challenger.iloc[:60],
        _safe_gate_config(),
        prefix="prefix",
    )
    pd.testing.assert_frame_equal(short_gate, full_gate.iloc[:60])

    prior_config = {
        "loss_window": 20,
        "min_history": 10,
        "temperature": 0.012,
        "stat_prior": 0.10,
        "ml_prior": 0.90,
    }
    full_prior = shifted_two_candidate_prior_blend(
        target,
        baseline,
        challenger,
        prior_config,
        prefix="prefix_prior",
    )
    short_prior = shifted_two_candidate_prior_blend(
        target.iloc[:60],
        baseline.iloc[:60],
        challenger.iloc[:60],
        prior_config,
        prefix="prefix_prior",
    )
    pd.testing.assert_frame_equal(short_prior, full_prior.iloc[:60])
