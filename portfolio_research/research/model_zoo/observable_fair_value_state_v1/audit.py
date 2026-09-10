"""Score-free causal-prefix and adversarial audits for Observable State V1."""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from .contracts import ObservableStateContractError
from .features import generate_observable_state_features


@dataclass(frozen=True)
class CausalityAuditResult:
    prefix_invariance: bool
    future_source_intervention: bool
    same_row_observed_pe_ignored: bool
    subsequent_row_observed_pe_response: bool
    group_boundary_isolation: bool
    row_order_invariance: bool
    excluded_model_outputs_ignored: bool
    true_fair_pe_rejected: bool
    future_named_column_rejected: bool

    @property
    def passed(self) -> bool:
        return all(asdict(self).values())

    def as_dict(self) -> dict[str, bool]:
        return {**asdict(self), "passed": self.passed}


def _same(left: pd.DataFrame, right: pd.DataFrame) -> bool:
    try:
        pd.testing.assert_frame_equal(
            left,
            right,
            check_exact=True,
            check_dtype=True,
            check_names=True,
        )
    except AssertionError:
        return False
    return True


def _rejected(frame: pd.DataFrame) -> bool:
    try:
        generate_observable_state_features(frame)
    except ObservableStateContractError:
        return True
    return False


def run_causality_audit(frame: pd.DataFrame) -> CausalityAuditResult:
    """Intervene on source data without reading an evaluation target or score."""

    baseline = generate_observable_state_features(frame)
    dates = pd.to_datetime(frame["date"], errors="raise")
    unique_dates = pd.Index(dates.sort_values().unique())
    if len(unique_dates) < 8:
        raise ObservableStateContractError("causality audit requires at least eight dates")
    cutoff = pd.Timestamp(unique_dates[int(len(unique_dates) * 0.6)])
    prefix_mask = dates <= cutoff
    future_mask = dates > cutoff
    prefix_only = generate_observable_state_features(frame.loc[prefix_mask].copy())
    prefix_invariance = _same(
        baseline.features.loc[prefix_mask],
        prefix_only.features,
    )

    future_changed = frame.copy()
    future_changed.loc[future_mask, "observed_pe"] = (
        pd.to_numeric(future_changed.loc[future_mask, "observed_pe"], errors="coerce") * 7.0 + 11.0
    )
    future_changed.loc[future_mask, "eps_ttm"] = (
        pd.to_numeric(future_changed.loc[future_mask, "eps_ttm"], errors="coerce") - 9.0
    )
    future_changed.loc[future_mask, "benchmark_return_63"] = 3.0
    future_changed.loc[future_mask, ["p_bear", "p_sideways", "p_bull"]] = (0.98, 0.01, 0.01)
    future_result = generate_observable_state_features(future_changed)
    future_source_intervention = _same(
        baseline.features.loc[prefix_mask],
        future_result.features.loc[prefix_mask],
    )

    group_columns = baseline.group_columns
    first_group_key = tuple(frame.iloc[0][column] for column in group_columns)
    group_mask = np.ones(len(frame), dtype=bool)
    for column, value in zip(group_columns, first_group_key, strict=True):
        group_mask &= frame[column].to_numpy() == value
    group_positions = np.flatnonzero(group_mask)
    if len(group_positions) < 4:
        raise ObservableStateContractError("causality audit requires a group with four rows")
    pivot_position = int(group_positions[len(group_positions) // 2])
    pivot_index = frame.index[pivot_position]
    next_index = frame.index[int(group_positions[len(group_positions) // 2 + 1])]
    same_row_changed = frame.copy()
    original_pe = float(
        pd.to_numeric(pd.Series([same_row_changed.loc[pivot_index, "observed_pe"]])).iloc[0]
    )
    same_row_changed.loc[pivot_index, "observed_pe"] = original_pe * 4.0 + 5.0
    same_row_result = generate_observable_state_features(same_row_changed)
    same_row_observed_pe_ignored = _same(
        baseline.features.loc[[pivot_index]], same_row_result.features.loc[[pivot_index]]
    )
    subsequent_row_observed_pe_response = not _same(
        baseline.features.loc[[next_index]], same_row_result.features.loc[[next_index]]
    )

    if len(group_positions) < len(frame):
        other_changed = frame.copy()
        other_mask = ~group_mask
        other_changed.loc[other_mask, "observed_pe"] = (
            pd.to_numeric(other_changed.loc[other_mask, "observed_pe"], errors="coerce") * 13.0
            + 17.0
        )
        other_result = generate_observable_state_features(other_changed)
        group_boundary_isolation = _same(
            baseline.features.iloc[group_positions],
            other_result.features.iloc[group_positions],
        )
    else:
        group_boundary_isolation = True

    shuffled = frame.sample(frac=1.0, random_state=1701)
    shuffled_result = generate_observable_state_features(shuffled)
    row_order_invariance = _same(
        baseline.features.sort_index(), shuffled_result.features.sort_index()
    )

    excluded = frame.copy()
    comparable = baseline.features
    for column, value in (
        ("expected_pe", 999999.0),
        ("ml_expected_pe", -999999.0),
        ("pe_gap_log", 123456.0),
    ):
        if column in excluded:
            excluded[column] = value
    excluded_result = generate_observable_state_features(excluded)
    excluded_model_outputs_ignored = _same(comparable, excluded_result.features)

    with_truth = frame.copy()
    with_truth["true_fair_pe"] = 1.0
    with_future = frame.copy()
    with_future["future_return_21"] = 0.0
    return CausalityAuditResult(
        prefix_invariance=prefix_invariance,
        future_source_intervention=future_source_intervention,
        same_row_observed_pe_ignored=same_row_observed_pe_ignored,
        subsequent_row_observed_pe_response=subsequent_row_observed_pe_response,
        group_boundary_isolation=group_boundary_isolation,
        row_order_invariance=row_order_invariance,
        excluded_model_outputs_ignored=excluded_model_outputs_ignored,
        true_fair_pe_rejected=_rejected(with_truth),
        future_named_column_rejected=_rejected(with_future),
    )


__all__ = ["CausalityAuditResult", "run_causality_audit"]
