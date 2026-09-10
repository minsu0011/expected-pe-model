from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.config import load_config
from pe_regime_v04.fundamental_vintage import (
    FUNDAMENTAL_VINTAGE_OUTPUT_COLUMNS,
    walk_forward_fundamental_vintage_pe,
)


EXPECTED = "v04_fundamental_vintage_expected_pe"
MODE = "v04_fundamental_vintage_mode"
COUNT = "v04_fundamental_vintage_usable_train_vintages"
FALLBACK = "v04_fundamental_vintage_fallback_used"

LEADING_WARMUP_NULL_COLUMNS = (
    "available_at",
    "effective_date",
    "period_end",
    "eps_ttm_raw",
    "eps_ttm",
    "eps_ttm_growth_252",
    "eps_primary_method",
    "eps_definition",
    "eps_source_tag",
    "event_source",
    "timestamp_exact",
    "accession",
    "source_tag",
    "shares_source_tag",
    "eps_confidence",
    "eps_disagreement",
    "eps_approximation_flag",
    "eps_reconstruction_approximate",
)


def _config() -> dict:
    config = deepcopy(load_config()["fundamental_vintage"])
    config["enabled"] = True
    return config


def _vintage_frame(vintages: int = 13, rows_per_vintage: int = 3) -> pd.DataFrame:
    dates = pd.bdate_range("2013-01-02", periods=vintages * rows_per_vintage)
    rows: list[dict[str, object]] = []
    for vintage in range(vintages):
        first = dates[vintage * rows_per_vintage]
        growth = 0.01 + 0.015 * vintage
        eps = 1.0 + 0.04 * vintage
        center_log_pe = 2.0 + 3.0 * growth
        for offset in range(rows_per_vintage):
            date = dates[vintage * rows_per_vintage + offset]
            observed = float(np.exp(center_log_pe + 0.002 * (offset - 1)))
            rows.append(
                {
                    "date": date.strftime("%Y-%m-%d"),
                    "symbol": "TEST",
                    "available_at": first.strftime("%Y-%m-%d 12:00:00+00:00"),
                    "effective_date": first.strftime("%Y-%m-%d"),
                    "period_end": (first - pd.Timedelta(days=5)).strftime("%Y-%m-%d"),
                    "eps_ttm_raw": eps,
                    "eps_ttm": eps,
                    "eps_ttm_growth_252": growth,
                    "eps_primary_method": "DIRECT_TTM",
                    "eps_definition": "GAAP_DILUTED_TTM",
                    "eps_source_tag": "TEST_EPS",
                    "event_source": "TEST",
                    "timestamp_exact": True,
                    "accession": f"A{vintage:04d}",
                    "source_tag": "TEST_EPS",
                    "shares_source_tag": "TEST_SHARES",
                    "eps_confidence": 96.0,
                    "eps_disagreement": np.nan,
                    "eps_approximation_flag": False,
                    "eps_reconstruction_approximate": False,
                    "negative_earnings_flag": 0,
                    "observed_pe": observed,
                    "close": observed * eps,
                    "benchmark_close": 100.0 + vintage + offset,
                    "stock_return_63": 0.01 * vintage,
                    "benchmark_return_63": -0.01 * vintage,
                    "p_bear": 0.2,
                    "p_sideways": 0.3,
                    "p_bull": 0.5,
                    "ml_expected_pe": 999.0,
                }
            )
    return pd.DataFrame(rows)


def _block(frame: pd.DataFrame, vintage: int, rows_per_vintage: int = 3) -> pd.Index:
    start = vintage * rows_per_vintage
    return frame.index[start : start + rows_per_vintage]


def _null_leading_provenance(frame: pd.DataFrame, rows: list[int]) -> None:
    for column in LEADING_WARMUP_NULL_COLUMNS:
        frame[column] = frame[column].astype(object)
        frame.loc[rows, column] = pd.NA


def test_state_machine_uses_intercept_then_positive_slope_conditional_q50() -> None:
    frame = _vintage_frame()
    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert tuple(output.columns) == FUNDAMENTAL_VINTAGE_OUTPUT_COLUMNS
    assert output.loc[_block(frame, 3), EXPECTED].isna().all()
    assert (output.loc[_block(frame, 4), MODE] == "intercept_only_insufficient_usable").all()
    assert output.loc[_block(frame, 4), FALLBACK].all()
    assert (output.loc[_block(frame, 8), MODE] == "conditional_q50").all()
    assert not output.loc[_block(frame, 8), FALLBACK].any()
    assert (output.loc[_block(frame, 8), COUNT] == 8.0).all()
    assert output.loc[_block(frame, 8), EXPECTED].nunique() == 1
    assert diagnostics["current_price_consumed_as_feature"] is False
    assert diagnostics["incumbent_fallback_used"] is False
    assert diagnostics["production_connected"] is False


def test_prefix_and_future_interventions_are_exactly_causal() -> None:
    frame = _vintage_frame()
    full, _ = walk_forward_fundamental_vintage_pe(frame, _config())

    for rows in (1, 7, 16, 26, len(frame) - 1):
        prefix, _ = walk_forward_fundamental_vintage_pe(frame.iloc[:rows].copy(), _config())
        pd.testing.assert_frame_equal(full.iloc[:rows], prefix, check_exact=True)

    cutoff = 25
    perturbed = frame.copy()
    perturbed.loc[cutoff:, "observed_pe"] *= 100.0
    perturbed.loc[cutoff:, "close"] *= 100.0
    perturbed.loc[cutoff:, "eps_ttm_growth_252"] *= -50.0
    future_changed, _ = walk_forward_fundamental_vintage_pe(perturbed, _config())
    pd.testing.assert_frame_equal(
        full.iloc[:cutoff], future_changed.iloc[:cutoff], check_exact=True
    )


def test_current_price_is_forbidden_and_current_target_matures_next_vintage_only() -> None:
    frame = _vintage_frame()
    baseline, _ = walk_forward_fundamental_vintage_pe(frame, _config())

    price_poisoned = frame.copy()
    for column in (
        "close",
        "benchmark_close",
        "stock_return_63",
        "benchmark_return_63",
        "p_bear",
        "p_sideways",
        "p_bull",
        "ml_expected_pe",
    ):
        price_poisoned[column] = np.linspace(-1.0e9, 1.0e9, len(frame))
    price_output, _ = walk_forward_fundamental_vintage_pe(price_poisoned, _config())
    pd.testing.assert_frame_equal(baseline, price_output, check_exact=True)

    target_poisoned = frame.copy()
    changed_block = _block(frame, 1)
    target_poisoned.loc[changed_block, "observed_pe"] *= 100.0
    changed, _ = walk_forward_fundamental_vintage_pe(target_poisoned, _config())
    pd.testing.assert_frame_equal(
        baseline.loc[: changed_block[-1]], changed.loc[: changed_block[-1]], check_exact=True
    )
    assert not baseline.loc[_block(frame, 4), EXPECTED].equals(
        changed.loc[_block(frame, 4), EXPECTED]
    )

    active_block = _block(frame, 8)
    current_poisoned = frame.copy()
    current_poisoned.loc[active_block, "observed_pe"] *= 1.0e6
    current, _ = walk_forward_fundamental_vintage_pe(current_poisoned, _config())
    pd.testing.assert_frame_equal(
        baseline.loc[active_block], current.loc[active_block], check_exact=True
    )


def test_missing_growth_uses_price_free_intercept_and_never_incumbent() -> None:
    frame = _vintage_frame()
    current = _block(frame, 8)
    frame.loc[current[0], "eps_ttm_growth_252"] = np.inf
    frame.loc[current, "ml_expected_pe"] = [1.0, 2.0, 3.0]

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert (output.loc[current, MODE] == "intercept_only_missing_current_growth").all()
    assert output.loc[current, FALLBACK].all()
    assert output.loc[current, EXPECTED].nunique() == 1
    assert output.loc[current, EXPECTED].iloc[0] not in {1.0, 2.0, 3.0}
    assert diagnostics["incumbent_fallback_used"] is False


def test_negative_or_invalid_current_eps_fails_closed_without_price_masking() -> None:
    frame = _vintage_frame()
    active = _block(frame, 8)
    baseline, _ = walk_forward_fundamental_vintage_pe(frame, _config())
    assert baseline.loc[active, EXPECTED].notna().all()

    invalid = frame.copy()
    invalid.loc[active[0], "eps_ttm"] = 0.0
    invalid.loc[active[0], "negative_earnings_flag"] = 1
    invalid.loc[active[0], "observed_pe"] = np.nan
    invalid_output, _ = walk_forward_fundamental_vintage_pe(invalid, _config())
    assert invalid_output.loc[active, EXPECTED].isna().all()
    assert (invalid_output.loc[active, MODE] == "unavailable_invalid_current_eps").all()
    assert not invalid_output.loc[active, FALLBACK].any()

    price_missing = frame.copy()
    price_missing.loc[active, "observed_pe"] = pd.NA
    price_missing.loc[active, "close"] = pd.NA
    price_missing_output, _ = walk_forward_fundamental_vintage_pe(price_missing, _config())
    pd.testing.assert_frame_equal(
        baseline.loc[active], price_missing_output.loc[active], check_exact=True
    )


def test_missing_provenance_and_noncanonical_order_return_unavailable_not_errors() -> None:
    frame = _vintage_frame()
    missing, missing_diagnostics = walk_forward_fundamental_vintage_pe(
        frame.drop(columns=["available_at"]), _config()
    )
    assert missing[EXPECTED].isna().all()
    assert (missing[MODE] == "unavailable_missing_provenance").all()
    assert missing_diagnostics["missing_columns"] == ["available_at"]

    duplicate = frame.copy()
    duplicate.loc[5, "date"] = duplicate.loc[4, "date"]
    duplicate_output, duplicate_diagnostics = walk_forward_fundamental_vintage_pe(
        duplicate, _config()
    )
    assert duplicate_output[EXPECTED].isna().all()
    assert (duplicate_output[MODE] == "unavailable_noncanonical_order").all()
    assert duplicate_diagnostics["status"] == "unavailable_noncanonical_order"

    reverse = frame.iloc[::-1].copy()
    reverse_output, _ = walk_forward_fundamental_vintage_pe(reverse, _config())
    assert reverse_output[EXPECTED].isna().all()
    assert (reverse_output[MODE] == "unavailable_noncanonical_order").all()


def test_nullable_inputs_and_provenance_gaps_follow_warmup_contract() -> None:
    frame = _vintage_frame()
    for column in ("eps_ttm", "eps_ttm_growth_252", "observed_pe", "eps_confidence"):
        frame[column] = pd.Series(frame[column], dtype="Float64")
    frame["negative_earnings_flag"] = pd.Series(frame["negative_earnings_flag"], dtype="Int64")
    frame["eps_approximation_flag"] = pd.Series(frame["eps_approximation_flag"], dtype="boolean")
    frame["eps_reconstruction_approximate"] = pd.Series(
        frame["eps_reconstruction_approximate"], dtype="boolean"
    )
    baseline, _ = walk_forward_fundamental_vintage_pe(frame, _config())
    assert baseline[EXPECTED].notna().any()

    broken = frame.copy()
    break_position = 20
    broken.loc[break_position, "effective_date"] = pd.NA
    output, diagnostics = walk_forward_fundamental_vintage_pe(broken, _config())
    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert output[COUNT].isna().all()
    assert not output[FALLBACK].any()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True

    leading_warmup = frame.copy()
    _null_leading_provenance(leading_warmup, [0, 1])
    leading_output, leading_diagnostics = walk_forward_fundamental_vintage_pe(
        leading_warmup, _config()
    )
    assert leading_output.loc[:1, EXPECTED].isna().all()
    assert (leading_output.loc[:1, MODE] == "unavailable_no_vintage").all()
    assert leading_output.loc[2:, EXPECTED].notna().any()
    assert leading_diagnostics["state_machine_stopped_on_noncanonical_provenance"] is False


def test_partial_null_leading_timing_provenance_fails_closed_globally() -> None:
    frame = _vintage_frame()
    frame.loc[0, "available_at"] = pd.NA

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


@pytest.mark.parametrize("column", ["available_at", "effective_date", "period_end"])
def test_nonempty_invalid_leading_timing_provenance_fails_closed_globally(
    column: str,
) -> None:
    frame = _vintage_frame()
    frame.loc[0, column] = "definitely-not-a-date"

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


@pytest.mark.parametrize(
    ("column", "value"),
    [("symbol", pd.NA), ("symbol", "   "), ("timestamp_exact", "not-a-boolean")],
)
def test_invalid_leading_identity_provenance_fails_closed_globally(
    column: str,
    value: object,
) -> None:
    frame = _vintage_frame()
    _null_leading_provenance(frame, [0])
    frame.loc[0, column] = value

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


def test_partial_eps_provenance_is_not_treated_as_leading_warmup() -> None:
    frame = _vintage_frame()
    _null_leading_provenance(frame, [0])
    frame.loc[0, "eps_source_tag"] = "PARTIAL_ONLY"

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("eps_confidence", 25.0),
        ("eps_disagreement", 1.0),
        ("eps_approximation_flag", True),
        ("eps_reconstruction_approximate", True),
    ],
)
def test_weight_provenance_must_be_stable_within_information_vintage(
    column: str,
    value: object,
) -> None:
    frame = _vintage_frame()
    frame.loc[10, column] = value

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("period_end", "2013-01-04"),
        ("available_at", "2013-01-03 12:00:00+00:00"),
        ("effective_date", "2013-01-03"),
    ],
)
def test_provenance_calendar_order_is_causal_or_fails_closed(
    column: str,
    value: object,
) -> None:
    frame = _vintage_frame()
    frame.loc[0, column] = value

    output, diagnostics = walk_forward_fundamental_vintage_pe(frame, _config())

    assert output[EXPECTED].isna().all()
    assert (output[MODE] == "unavailable_noncanonical_provenance").all()
    assert diagnostics["state_machine_stopped_on_noncanonical_provenance"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("min_completed_target_vintages", 3),
        ("min_usable_vintages", 7),
        ("max_train_vintages", 19),
        ("quantile", 0.4),
        ("alpha", -0.05),
        ("solver", "interior-point"),
        ("growth_iqr_floor", np.nan),
        ("enabled", "true"),
    ],
)
def test_direct_api_rejects_unlocked_config(field: str, value: object) -> None:
    config = _config()
    config[field] = value
    with pytest.raises(ValueError, match=f"fundamental_vintage.{field}"):
        walk_forward_fundamental_vintage_pe(_vintage_frame(), config)


def test_candidate_design_lock_and_artifact_provenance_are_self_verifying() -> None:
    root = Path(__file__).resolve().parents[1]
    candidate_path = root / "config" / "v04_fundamental_vintage_q50_g252_candidate.json"
    design_path = root / "config" / "v04_fundamental_vintage_q50_g252_design_lock.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    design = json.loads(design_path.read_text(encoding="utf-8"))

    assert list(candidate["candidates"]) == ["fundamental_vintage_q50_g252"]
    assert candidate["candidates"]["fundamental_vintage_q50_g252"]["overrides"] == {
        "fundamental_vintage": {"enabled": True}
    }
    assert design["candidate_count"] == 1
    assert (
        design["candidate_spec_sha256"] == hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    )
    assert design["locked_parameters"] == {
        key: value for key, value in _config().items() if key != "enabled"
    }
    assert design["schema_contract"] == {
        "existing_v04_append_prefix_columns": 83,
        "new_tail_columns": 4,
        "fundamental_completion_prefix_columns": 87,
        "fundamental_completion_prefix_preserved_exact": True,
        "later_isolated_lagged_tail_columns": 6,
        "later_isolated_smoothing_tail_columns": 3,
        "later_isolated_matured_proxy_tail_columns": 8,
        "v04_append_columns": 104,
        "canonical_total_columns": 254,
        "bundled_64_total_columns": 168,
    }
    for relative, expected in design["implementation_artifacts_sha256"].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected
    assert design["retrospective_evidence_decision"]["decision"] == "REJECT"
    assert design["retrospective_evidence_decision"]["joint_seed_wins"] == "0/10"
    for relative, expected in design["retrospective_evidence_sha256"].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected

    logical = dict(design)
    recorded = logical.pop("logical_lock_sha256")
    encoded = json.dumps(logical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == recorded
