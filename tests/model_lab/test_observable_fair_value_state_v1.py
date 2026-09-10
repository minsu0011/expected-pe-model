from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.observable_fair_value_state_v1 import (
    ABLATIONS,
    FEATURE_OUTPUT_COLUMNS,
    ObservableStateContractError,
    contract_sha256,
    feature_columns_for_ablation,
    generate_observable_state_features,
    run_causality_audit,
)


def _frame(rows_per_entity: int = 180) -> pd.DataFrame:
    dates = pd.bdate_range("2020-01-02", periods=rows_per_entity)
    records: list[dict[str, object]] = []
    for entity_number, entity_id in enumerate(("ENTITY_A", "ENTITY_B")):
        positions = np.arange(rows_per_entity, dtype=np.float64)
        observed_pe = (
            18.0 + entity_number * 2.0 + 0.015 * positions + 0.4 * np.sin(positions / 13.0)
        )
        eps = 2.0 + entity_number * 0.2 + 0.003 * positions
        raw_p = np.column_stack(
            (
                0.3 + 0.05 * np.sin(positions / 17.0),
                0.4 + 0.04 * np.cos(positions / 19.0),
                0.3 - 0.03 * np.sin(positions / 23.0),
            )
        )
        probabilities = raw_p / raw_p.sum(axis=1, keepdims=True)
        for position, date in enumerate(dates):
            records.append(
                {
                    "seed": 1701,
                    "entity_id": entity_id,
                    "date": date,
                    "observed_pe": observed_pe[position],
                    "eps_ttm": eps[position],
                    "eps_ttm_growth_126": 0.05 + 0.01 * np.sin(position / 31.0),
                    "eps_ttm_growth_252": 0.04 + 0.008 * np.cos(position / 37.0),
                    "eps_staleness_days": float(position % 90),
                    "eps_period_age_days": float(30 + position % 90),
                    "eps_confidence": 92.0 - float(position % 5),
                    "eps_disagreement": float(position % 7) / 100.0,
                    "eps_approximation_flag": bool(position % 29 == 0),
                    "benchmark_return_21": 0.02 * np.sin(position / 11.0),
                    "benchmark_return_63": 0.04 * np.sin(position / 29.0),
                    "benchmark_return_252": 0.08 * np.sin(position / 71.0),
                    "benchmark_realized_vol_20": 0.16 + 0.01 * np.cos(position / 9.0),
                    "benchmark_realized_vol_63": 0.17 + 0.01 * np.cos(position / 21.0),
                    "benchmark_drawdown_252": -0.1 * abs(np.sin(position / 43.0)),
                    "benchmark_sma_50_vs_200": 0.03 * np.sin(position / 51.0),
                    "benchmark_trend_efficiency_63": abs(np.sin(position / 33.0)),
                    "p_bear": probabilities[position, 0],
                    "p_sideways": probabilities[position, 1],
                    "p_bull": probabilities[position, 2],
                    "expected_pe": 20.0,
                    "ml_expected_pe": 20.5,
                    "pe_gap_log": 0.01,
                }
            )
    return (
        pd.DataFrame.from_records(records)
        .sort_values(["date", "entity_id"], kind="mergesort")
        .reset_index(drop=True)
    )


def test_contract_is_fixed_ablatable_and_relative_fails_closed() -> None:
    frame = _frame()
    result = generate_observable_state_features(frame)
    assert tuple(result.features.columns) == FEATURE_OUTPUT_COLUMNS
    assert result.contract_sha256 == contract_sha256()
    assert len(contract_sha256()) == 64
    assert len(ABLATIONS) == 5
    assert result.relative_source_present is False
    assert result.relative_available_rows == 0
    assert result.features["ofs_v1_relative_available"].eq(0.0).all()
    assert result.features["ofs_v1_relative_ticker_sector_log_gap_lag1"].isna().all()
    assert not np.isinf(result.features.to_numpy(dtype=np.float64)).any()
    with pytest.raises(ObservableStateContractError, match="relative ablation"):
        feature_columns_for_ablation(
            "ofs_v1_full_with_relative_if_available",
            relative_data_available=False,
        )


def test_score_free_causal_and_adversarial_audit_passes() -> None:
    audit = run_causality_audit(_frame())
    assert audit.passed
    assert all(audit.as_dict().values())


def test_same_row_observed_pe_never_changes_same_row_state() -> None:
    frame = _frame()
    baseline = generate_observable_state_features(frame).features
    entity_positions = np.flatnonzero(frame["entity_id"].eq("ENTITY_A").to_numpy())
    pivot_position = int(entity_positions[100])
    next_position = int(entity_positions[101])
    changed = frame.copy()
    changed.loc[pivot_position, "observed_pe"] *= 10.0
    result = generate_observable_state_features(changed).features
    pd.testing.assert_frame_equal(
        baseline.loc[[pivot_position]], result.loc[[pivot_position]], check_exact=True
    )
    assert (
        baseline.loc[next_position, "ofs_v1_val_log_pe_lag1"]
        != result.loc[next_position, "ofs_v1_val_log_pe_lag1"]
    )
    assert (
        baseline.loc[next_position, "ofs_v1_state_prior_log_pe"]
        != result.loc[next_position, "ofs_v1_state_prior_log_pe"]
    )


def test_future_and_truth_named_columns_are_rejected() -> None:
    frame = _frame()
    for column in ("true_fair_pe", "true_regime", "future_return_21", "pe_lead_5"):
        attacked = frame.copy()
        attacked[column] = 1.0
        with pytest.raises(ObservableStateContractError, match="forbidden"):
            generate_observable_state_features(attacked)


def test_relative_state_uses_only_explicit_lagged_panel_inputs() -> None:
    frame = _frame()
    frame["sector_pe"] = 19.0 + 0.002 * np.arange(len(frame))
    frame["market_pe"] = 21.0 + 0.001 * np.arange(len(frame))
    result = generate_observable_state_features(frame)
    assert result.relative_source_present
    assert result.relative_available_rows == len(frame) - frame["entity_id"].nunique()
    columns = feature_columns_for_ablation(
        "ofs_v1_full_with_relative_if_available",
        relative_data_available=True,
    )
    assert "ofs_v1_relative_ticker_sector_log_gap_lag1" in columns

    partial = frame.drop(columns="market_pe")
    with pytest.raises(ObservableStateContractError, match="supplied together"):
        generate_observable_state_features(partial)


def test_canonical_150_sample_is_supported_without_relative_proxy() -> None:
    project_root = Path(__file__).resolve().parents[2]
    sample = pd.read_csv(
        project_root / "sample_data" / "v03_canonical_high_sample.csv",
        low_memory=False,
    )
    result = generate_observable_state_features(sample)
    assert len(result.features) == len(sample)
    assert tuple(result.group_columns) == ("symbol",)
    assert not result.relative_source_present
    assert result.relative_available_rows == 0
