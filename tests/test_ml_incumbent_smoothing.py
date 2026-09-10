from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.config import load_config
from pe_regime_v04.ml_incumbent_smoothing import (
    LOCKED_ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_CONFIG,
    ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_OUTPUT_COLUMNS,
    causal_ml_incumbent_weekly_median_shrinkage,
)


EXPECTED, COUNT, FALLBACK = ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_OUTPUT_COLUMNS


def _config(*, enabled: bool = True) -> dict:
    config = deepcopy(load_config()["ml_incumbent_weekly_median_shrinkage"])
    config["enabled"] = enabled
    return config


def _run(
    values: object,
    *,
    dates: object | None = None,
    symbols: object | None = None,
    enabled: bool = True,
) -> tuple[pd.DataFrame, dict]:
    incumbent = pd.Series(values)
    size = len(incumbent)
    date_series = pd.Series(
        pd.date_range("2020-01-02", periods=size, freq="B") if dates is None else dates,
        index=incumbent.index,
    )
    symbol_series = pd.Series(
        ["TEST"] * size if symbols is None else symbols,
        index=incumbent.index,
        dtype="string",
    )
    return causal_ml_incumbent_weekly_median_shrinkage(
        incumbent,
        date_series,
        symbol_series,
        _config(enabled=enabled),
    )


def test_manual_formula_uses_current_inclusive_five_row_log_median() -> None:
    values = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0]
    output, diagnostics = _run(values)

    np.testing.assert_array_equal(output[COUNT], [1, 2, 3, 4, 5, 5])
    np.testing.assert_array_equal(output[FALLBACK], [True, True, True, True, False, False])
    np.testing.assert_array_equal(output.loc[:3, EXPECTED], values[:4])
    assert output.loc[4, EXPECTED] == math.exp(0.75 * math.log(50.0) + 0.25 * math.log(30.0))
    assert output.loc[5, EXPECTED] == math.exp(0.75 * math.log(60.0) + 0.25 * math.log(40.0))
    assert diagnostics["window_includes_current_incumbent"] is True
    assert diagnostics["decision_timestamp"] == "end_of_day_after_ml_expected_pe_t_is_final"
    assert diagnostics["pre_close_forecast_claim_allowed"] is False
    assert diagnostics["direct_observed_pe_consumed"] is False


def test_prefix_future_and_current_ml_interventions_are_causal_and_exact() -> None:
    positions = np.arange(40, dtype=float)
    values = np.exp(2.5 + 0.01 * np.sin(positions / 3.0))
    full, _ = _run(values)

    for cutoff in (1, 4, 5, 6, 23, 39):
        prefix, _ = _run(values[:cutoff])
        pd.testing.assert_frame_equal(full.iloc[:cutoff], prefix, check_exact=True)

    changed_future = values.copy()
    changed_future[25:] *= 3.0
    future, _ = _run(changed_future)
    pd.testing.assert_frame_equal(full.iloc[:25], future.iloc[:25], check_exact=True)

    changed_current = values.copy()
    changed_current[20] *= 2.0
    intervened, _ = _run(changed_current)
    assert full.loc[20, EXPECTED] != intervened.loc[20, EXPECTED]
    pd.testing.assert_frame_equal(full.iloc[:20], intervened.iloc[:20], check_exact=True)


def test_invalid_incumbent_breaks_window_but_calendar_gap_does_not() -> None:
    values = [10.0, 20.0, pd.NA, 30.0, 40.0, 50.0, 60.0, 70.0]
    dates = pd.to_datetime(
        [
            "2020-01-02",
            "2020-01-03",
            "2020-02-03",
            "2020-02-04",
            "2020-02-05",
            "2020-02-06",
            "2020-02-07",
            "2020-03-20",
        ]
    )
    output, diagnostics = _run(values, dates=dates)

    np.testing.assert_array_equal(output[COUNT], [1, 2, 0, 1, 2, 3, 4, 5])
    assert pd.isna(output.loc[2, EXPECTED])
    assert not bool(output.loc[2, FALLBACK])
    assert output.loc[7, COUNT] == 5
    assert not bool(output.loc[7, FALLBACK])
    assert diagnostics["invalid_incumbent_window_break_rows"] == 1
    assert "calendar-day gaps do not imply missing sessions" in diagnostics["window_definition"]


def test_adjacent_symbol_transition_defensively_resets_window() -> None:
    values = [10.0, 11.0, 12.0, 13.0, 14.0, 20.0, 21.0, 22.0, 23.0, 24.0]
    symbols = ["A"] * 5 + ["B"] * 5
    output, diagnostics = _run(values, symbols=symbols)

    np.testing.assert_array_equal(output[COUNT], [1, 2, 3, 4, 5, 1, 2, 3, 4, 5])
    assert bool(output.loc[5, FALLBACK])
    assert output.loc[5, EXPECTED] == values[5]
    assert diagnostics["symbol_transition_reset_rows"] == 1
    assert diagnostics["symbol_transition_behavior"] == (
        "defensive_reset_not_general_panel_support"
    )


@pytest.mark.parametrize("invalid", [pd.NA, np.nan, np.inf, -np.inf, 0.0, -1.0, "bad"])
def test_invalid_current_is_nan_zero_count_and_not_fallback(invalid: object) -> None:
    output, _ = _run([10.0, 11.0, 12.0, 13.0, invalid, 15.0])
    assert pd.isna(output.loc[4, EXPECTED])
    assert output.loc[4, COUNT] == 0
    assert not bool(output.loc[4, FALLBACK])
    assert output.loc[5, EXPECTED] == 15.0
    assert output.loc[5, COUNT] == 1
    assert bool(output.loc[5, FALLBACK])


def test_disabled_surface_and_locked_config_fail_closed() -> None:
    disabled, diagnostics = _run([10.0, 11.0, 12.0], enabled=False)
    assert disabled[EXPECTED].isna().all()
    assert (disabled[COUNT] == 0).all()
    assert not disabled[FALLBACK].any()
    assert diagnostics["status"] == "disabled"

    incumbent = pd.Series([10.0, 11.0], dtype=float)
    dates = pd.Series(pd.date_range("2020-01-02", periods=2, freq="B"))
    symbols = pd.Series(["A", "A"], dtype="string")
    disabled_without_symbols, _ = causal_ml_incumbent_weekly_median_shrinkage(
        incumbent,
        dates,
        None,
        _config(enabled=False),
    )
    assert disabled_without_symbols[EXPECTED].isna().all()
    with pytest.raises(ValueError, match="requires a symbol column"):
        causal_ml_incumbent_weekly_median_shrinkage(
            incumbent,
            dates,
            None,
            _config(enabled=True),
        )
    for field, value in (
        ("enabled", "true"),
        ("window_sessions", 4),
        ("incumbent_weight", 0.50),
        ("anchor_weight", 0.50),
        ("method", "mean"),
    ):
        config = _config()
        config[field] = value
        with pytest.raises(
            ValueError,
            match=f"ml_incumbent_weekly_median_shrinkage.{field}",
        ):
            causal_ml_incumbent_weekly_median_shrinkage(
                incumbent,
                dates,
                symbols,
                config,
            )

    assert LOCKED_ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_CONFIG == {
        "window_sessions": 5,
        "incumbent_weight": 0.75,
        "anchor_weight": 0.25,
        "method": "log_median",
    }


def test_enabled_dates_and_symbols_fail_closed_when_noncanonical() -> None:
    with pytest.raises(ValueError, match="globally unique"):
        _run([10.0, 11.0], dates=["2020-01-02", "2020-01-02"])
    with pytest.raises(ValueError, match="monotonically increasing"):
        _run([10.0, 11.0], dates=["2020-01-03", "2020-01-02"])
    with pytest.raises(ValueError, match="symbols"):
        _run([10.0, 11.0], symbols=["A", pd.NA])


def test_candidate_design_lock_and_artifact_provenance_are_self_verifying() -> None:
    root = Path(__file__).resolve().parents[1]
    candidate_path = root / "config" / "v04_ml_incumbent_weekly_median_shrinkage_candidate.json"
    design_path = root / "config" / "v04_ml_incumbent_weekly_median_shrinkage_design_lock.json"
    terminal_path = root / "MG1_TERMINAL_REJECTION.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    design = json.loads(design_path.read_text(encoding="utf-8"))
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))

    candidate_id = "causal_ml_incumbent_weekly_median_shrinkage_v1"
    assert list(candidate["candidates"]) == [candidate_id]
    assert candidate["candidates"][candidate_id] == {
        "selection_column": EXPECTED,
        "incumbent_column": "ml_expected_pe",
        "overrides": {"ml_incumbent_weekly_median_shrinkage": {"enabled": True}},
    }
    assert design["candidate_id"] == candidate_id
    assert design["candidate_count"] == 1
    assert (
        design["candidate_spec_sha256"] == hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    )
    assert design["locked_parameters"] == (LOCKED_ML_INCUMBENT_WEEKLY_MEDIAN_SHRINKAGE_CONFIG)
    assert design["retrospective_evidence"]["decision"] == "GO_RETROSPECTIVE_ONLY"
    assert design["retrospective_evidence"]["strict_joint_seed_wins"] == "26/26"
    assert design["retrospective_evidence"]["bootstrap_cells_passed"] == "12/12"
    assert design["status"] == "terminal_prospective_pass_keep_default_off_no_main_connection"
    prospective = design["prospective_validation"]
    assert (
        prospective["status"] == "terminal_prospective_pass_against_locked_ml_expected_pe_incumbent"
    )
    assert prospective["output_root"] == "outputs/ms1"
    assert prospective["tuning_seeds"] == [5303, 5407, 5501, 5603, 5701]
    assert prospective["locked_heldout_seeds"] == [5801, 5903, 6007, 6101, 6203]
    assert prospective["seed_values_reserved"] is True
    assert prospective["seed_sets_disjoint"] is True
    assert prospective["output_root_created"] is True
    assert prospective["registry_reservation"] == {
        "reservation_sequence": 4,
        "reservation_id": "f78fc3423b2d6823992008413472efa981fd7044f5361a72747ea42d3db9994a",
        "reservation_entry_sha256": (
            "046d2abb2dad685ebacd7331eeed4decf1e3fb4924db11a5d5962fbedd02bf6f"
        ),
        "heldout_seed_commitment_sha256": (
            "daa7310449678f4fc103d522012b8fbcd53e13c72e401989dd455deb8b86a852"
        ),
    }
    assert (
        prospective["source_config_sha256_at_start_and_end"]
        == "454cddd612a353208b2e1bcba842e54bbbb50e8874ce03e77393db917bfe8190"
    )
    assert prospective["tuning_result"]["deterministic_gates_pass"] is True
    assert prospective["tuning_result"]["bootstrap_cells_passed"] == "12/12"
    assert prospective["heldout_result"]["promotion_pass"] is True
    assert prospective["heldout_result"]["bootstrap_cells_passed"] == "12/12"
    assert prospective["terminal_audit"] == {
        "verdict": "PASS",
        "p0_findings": 0,
        "p1_findings": 0,
        "promotion_pass_confirmed": True,
    }

    downstream = design["downstream_product_decision"]
    assert downstream["decision"] == "KEEP_DEFAULT_OFF_PARALLEL_EOD_RESEARCH_ONLY"
    assert downstream["default_enabled"] is False
    assert downstream["replace_or_feed_v04_expected_pe"] is False
    assert downstream["main_expected_pe_path_connected"] is False
    assert (
        downstream["current_v04_expected_pe_replacement_assessment"]
        == "FAIL_AS_REPLACEMENT_COMPARATOR"
    )
    hierarchy = design["hierarchy_branch_family_followup"]
    assert hierarchy["decision"] == "NO_GO"
    assert hierarchy["fresh_seed_set_proposed"] is False
    assert hierarchy["implementation_contract_proposed"] is False
    assert design["schema_contract"] == {
        "preserved_v04_append_prefix_columns": 93,
        "preserved_prefix_exact": True,
        "new_tail_columns": 3,
        "smoothing_completion_prefix_columns": 96,
        "later_isolated_matured_proxy_tail_columns": 8,
        "v04_append_columns": 104,
        "canonical_total_columns": 254,
        "bundled_64_total_columns": 168,
    }
    for relative, expected in design["implementation_artifacts_sha256"].items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if relative == "tests/test_ml_incumbent_smoothing.py":
            supersession = terminal["historical_anchor_supersessions"]["test_files"][relative]
            assert supersession["pre_terminal_transition_sha256"] == expected
            assert supersession["terminal_transition_sha256"] == actual
        else:
            assert actual == expected
    for relative, expected in design["retrospective_evidence_sha256"].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected
    for relative, expected in design["prospective_evidence_sha256"].items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if relative == "outputs/v04_spent_seed_registry.json":
            transition = terminal["registry_transition"]
            assert expected == transition["pre_sequence_5_file_sha256"]
            assert actual == transition["current_file_sha256"]
        else:
            assert actual == expected
    for evidence_section in (downstream["evidence_sha256"], hierarchy["evidence_sha256"]):
        for relative, expected in evidence_section.items():
            assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected

    sealed = design["prospective_evidence_logical_sha256"]
    logical_artifact_fields = {
        "spent_seed_registry_registry_sha256": (
            "outputs/v04_spent_seed_registry.json",
            "registry_sha256",
        ),
        "run_manifest_manifest_sha256": ("outputs/ms1/run_manifest.json", "manifest_sha256"),
        "promotion_policy_lock_sha256": (
            "outputs/ms1/promotion_policy.lock.json",
            "policy_lock_sha256",
        ),
        "tuning_metrics_sha256": (
            "outputs/ms1/tuning_common_metrics.json",
            "tuning_metrics_sha256",
        ),
        "candidate_lock_sha256": ("outputs/ms1/candidate.lock.json", "lock_sha256"),
        "checkpoint_sha256": ("outputs/ms1/checkpoint.json", "checkpoint_sha256"),
        "heldout_report_sha256": ("outputs/ms1/heldout_report.json", "report_sha256"),
    }
    assert set(sealed) == set(logical_artifact_fields)
    for seal_name, (relative, field) in logical_artifact_fields.items():
        artifact = json.loads((root / relative).read_text(encoding="utf-8"))
        if relative == "outputs/v04_spent_seed_registry.json":
            transition = terminal["registry_transition"]
            assert sealed[seal_name] == transition["pre_sequence_5_logical_sha256"]
            assert artifact[field] == transition["current_logical_sha256"]
        else:
            assert artifact[field] == sealed[seal_name]

    logical = dict(design)
    recorded = logical.pop("logical_lock_sha256")
    encoded = json.dumps(logical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == recorded
