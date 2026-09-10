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
from pe_regime_v04.lagged_market_conditioned import (
    LAGGED_MARKET_CONDITIONED_OUTPUT_COLUMNS,
    lagged_market_conditioned_expected_pe,
)


RAW, FINAL, COUNT, WEIGHT, ACCEPTED, FALLBACK = LAGGED_MARKET_CONDITIONED_OUTPUT_COLUMNS


def _config(*, enabled: bool = True) -> dict:
    config = deepcopy(load_config()["lagged_market_conditioned"])
    config["enabled"] = enabled
    return config


def _series(values: object) -> pd.Series:
    return pd.Series(values, dtype=float)


def test_manual_predict_before_update_recurrence_and_clipping() -> None:
    observed = _series([10.0, 20.0, 30.0, 40.0])
    incumbent = _series([100.0] * len(observed))
    output, diagnostics = lagged_market_conditioned_expected_pe(observed, incumbent, _config())

    assert output.loc[0, RAW] == 100.0
    expected_row_1 = math.exp(0.75 * math.log(100.0) + 0.25 * math.log(10.0))
    assert output.loc[1, RAW] == expected_row_1
    gain = 1.01 / 2.01
    state_after_row_1 = math.log(10.0) + gain * (math.log(20.0) - math.log(10.0))
    expected_row_2 = math.exp(0.75 * math.log(100.0) + 0.25 * state_after_row_1)
    assert output.loc[2, RAW] == expected_row_2
    assert diagnostics["warmup_incumbent_fallback_rows"] == 1
    assert diagnostics["state_initialization_rows"] == 1

    clipping_observed = _series([10.0] * 127 + [1000.0, 10.0])
    clipping_incumbent = _series([20.0] * len(clipping_observed))
    clipped, clipped_diagnostics = lagged_market_conditioned_expected_pe(
        clipping_observed,
        clipping_incumbent,
        _config(),
    )
    covariance = 1.0
    for _ in range(126):
        prior_covariance = covariance + 0.01
        update_gain = prior_covariance / (prior_covariance + 1.0)
        covariance = (1.0 - update_gain) * prior_covariance
    shock_prior_covariance = covariance + 0.01
    shock_gain = shock_prior_covariance / (shock_prior_covariance + 1.0)
    clipped_state = math.log(10.0) + shock_gain * 0.03
    expected_after_shock = math.exp(0.75 * math.log(20.0) + 0.25 * clipped_state)
    assert clipped.loc[128, RAW] == expected_after_shock
    assert clipped_diagnostics["clipped_measurement_update_rows"] == 1


def test_same_row_observation_is_exactly_excluded_but_changes_future_state() -> None:
    positions = np.arange(180, dtype=float)
    observed = _series(np.exp(2.5 + 0.001 * positions))
    incumbent = _series(np.exp(2.6 + 0.0005 * positions))
    baseline, _ = lagged_market_conditioned_expected_pe(observed, incumbent, _config())

    changed_observed = observed.copy()
    changed_observed.iloc[100] *= 100.0
    changed, _ = lagged_market_conditioned_expected_pe(
        changed_observed,
        incumbent,
        _config(),
    )

    pd.testing.assert_series_equal(baseline.iloc[100], changed.iloc[100], check_exact=True)
    assert baseline.loc[101, RAW] != changed.loc[101, RAW]


def test_prefix_and_future_observation_invariance_are_exact() -> None:
    positions = np.arange(300, dtype=float)
    observed = _series(np.exp(2.4 + 0.002 * np.sin(positions / 9.0)))
    incumbent = _series(np.exp(2.5 + 0.001 * np.cos(positions / 7.0)))
    full, _ = lagged_market_conditioned_expected_pe(observed, incumbent, _config())

    for length in (1, 2, 63, 64, 126, 127, 252, 253):
        prefix, _ = lagged_market_conditioned_expected_pe(
            observed.iloc[:length].copy(),
            incumbent.iloc[:length].copy(),
            _config(),
        )
        pd.testing.assert_frame_equal(full.iloc[:length], prefix, check_exact=True)

    changed_observed = observed.copy()
    changed_observed.iloc[201:] *= 0.5
    future, _ = lagged_market_conditioned_expected_pe(
        changed_observed,
        incumbent,
        _config(),
    )
    pd.testing.assert_frame_equal(full.iloc[:201], future.iloc[:201], check_exact=True)


def test_incumbent_intervention_changes_current_output_and_forbids_price_free_claim() -> None:
    observed = _series(np.linspace(10.0, 20.0, 90))
    incumbent = _series(np.linspace(11.0, 21.0, 90))
    baseline, diagnostics = lagged_market_conditioned_expected_pe(observed, incumbent, _config())
    changed_incumbent = incumbent.copy()
    changed_incumbent.iloc[70] *= 2.0
    changed, _ = lagged_market_conditioned_expected_pe(
        observed,
        changed_incumbent,
        _config(),
    )

    assert baseline.loc[70, RAW] != changed.loc[70, RAW]
    assert baseline.loc[70, FINAL] != changed.loc[70, FINAL]
    assert diagnostics["current_price_independence_claim_allowed"] is False
    assert diagnostics["incumbent_may_consume_same_row_price_derived_features"] is True
    assert diagnostics["fundamental_or_intrinsic_fair_pe_claim_allowed"] is False


def test_shifted_gate_counts_and_nonfinite_fallback_contracts() -> None:
    observed = _series([10.0] * 70)
    incumbent = _series([12.0] * 70)
    output, _ = lagged_market_conditioned_expected_pe(observed, incumbent, _config())

    expected_count = np.minimum(np.arange(70), 252)
    np.testing.assert_array_equal(output[COUNT].to_numpy(dtype=int), expected_count)
    assert output.loc[62, WEIGHT] == 0.0
    assert not bool(output.loc[62, ACCEPTED])
    assert not output[FALLBACK].any()

    dirty_observed = _series([10.0, np.nan, np.inf, -1.0, 20.0, 20.0])
    dirty_incumbent = _series([20.0, 20.0, 20.0, 20.0, np.nan, 20.0])
    dirty, diagnostics = lagged_market_conditioned_expected_pe(
        dirty_observed,
        dirty_incumbent,
        _config(),
    )
    assert dirty.loc[1:3, RAW].notna().all()
    assert pd.isna(dirty.loc[4, RAW]) and pd.isna(dirty.loc[4, FINAL])
    assert diagnostics["skipped_measurement_update_rows"] == 3
    assert not dirty[FALLBACK].any()
    assert not np.isinf(dirty[[RAW, FINAL, WEIGHT]].to_numpy(dtype=float)).any()


def test_disabled_and_invalid_config_fail_closed() -> None:
    observed = _series([10.0, 11.0, 12.0])
    incumbent = _series([20.0, 21.0, 22.0])
    disabled, diagnostics = lagged_market_conditioned_expected_pe(
        observed,
        incumbent,
        _config(enabled=False),
    )
    assert disabled[[RAW, FINAL]].isna().all().all()
    assert (disabled[COUNT] == 0).all()
    assert (disabled[WEIGHT] == 0.0).all()
    assert not disabled[[ACCEPTED, FALLBACK]].any().any()
    assert diagnostics["status"] == "disabled"

    for field, value in (
        ("q_over_r", 0.02),
        ("latent_weight", 0.50),
        ("loss_window", 126),
        ("availability_shift", 2),
        ("decision_mode", "soft"),
        ("enabled", "true"),
    ):
        config = _config()
        config[field] = value
        with pytest.raises(ValueError, match=f"lagged_market_conditioned.{field}"):
            lagged_market_conditioned_expected_pe(observed, incumbent, config)


def test_candidate_design_lock_and_artifact_provenance_are_self_verifying() -> None:
    root = Path(__file__).resolve().parents[1]
    candidate_path = root / "config" / "v04_lagged_market_conditioned_candidate.json"
    design_path = root / "config" / "v04_lagged_market_conditioned_design_lock.json"
    registry_path = root / "outputs" / "v04_spent_seed_registry.json"
    terminal_path = root / "MG1_TERMINAL_REJECTION.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    design = json.loads(design_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))

    assert list(candidate["candidates"]) == ["gated_lagged_market_conditioned"]
    assert candidate["candidates"]["gated_lagged_market_conditioned"] == {
        "selection_column": "v04_gated_lagged_market_conditioned_expected_pe",
        "incumbent_column": "ml_expected_pe",
        "overrides": {"lagged_market_conditioned": {"enabled": True}},
    }
    assert design["candidate_count"] == 1
    assert (
        design["candidate_spec_sha256"] == hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    )
    assert design["locked_parameters"] == {
        key: value for key, value in _config().items() if key != "enabled"
    }
    assert design["schema_contract"] == {
        "preserved_v04_append_prefix_columns": 87,
        "preserved_prefix_exact": True,
        "new_tail_columns": 6,
        "lagged_completion_prefix_columns": 93,
        "later_isolated_smoothing_tail_columns": 3,
        "later_isolated_matured_proxy_tail_columns": 8,
        "v04_append_columns": 104,
        "canonical_total_columns": 254,
        "bundled_64_total_columns": 168,
    }

    protocol = design["prospective_validation"]
    assert protocol["status"] == "tuning_rejected_heldout_unopened"
    assert protocol["harness"] == "HARNESS 2.4"
    assert protocol["proposed_tuning_seeds"] == [4303, 4409, 4513, 4603, 4703]
    assert protocol["proposed_locked_heldout_seeds"] == [4801, 4903, 5003, 5101, 5209]
    assert protocol["output_root"] == "outputs/lk2"
    assert protocol["metrics_unseen"] is False
    assert protocol["heldout_opened"] is False
    assert protocol["heldout_metrics_computed"] is False
    assert protocol["formal_outcome"]["decision"] == "REJECT_TUNING"
    assert protocol["formal_outcome"]["bootstrap_cells_passed"] == "8/12"
    assert protocol["registry_id"] == registry["registry_id"]
    spent = set(registry["baseline_spent_evidence_seeds"])
    for entry in registry["entries"]:
        spent.update(entry["reserved_seeds"])
    assert set(
        protocol["proposed_tuning_seeds"] + protocol["proposed_locked_heldout_seeds"]
    ).issubset(spent)

    invalid_attempt = design["invalid_attempts"][-1]
    assert invalid_attempt["attempt_id"] == "lk1"
    assert invalid_attempt["output_root"] == "outputs/lk1"
    assert invalid_attempt["harness"] == "HARNESS 2.3"
    assert invalid_attempt["reservation_sequence"] == 2
    assert invalid_attempt["tuning_seeds"] == [3307, 3407, 3511, 3607, 3709]
    assert invalid_attempt["locked_heldout_seeds"] == [3803, 3907, 4001, 4111, 4201]
    assert invalid_attempt["reserved_seeds_permanently_spent"] is True
    assert invalid_attempt["candidate_or_locked_parameters_changed"] is False
    assert invalid_attempt["partial_output_formal_evidence_allowed"] is False
    assert invalid_attempt["promotion_metrics_computed"] is False
    assert set(invalid_attempt["tuning_seeds"] + invalid_attempt["locked_heldout_seeds"]).issubset(
        spent
    )

    for section in (
        "implementation_artifacts_sha256",
        "retrospective_evidence_sha256",
        "prospective_tuning_rejection_sha256",
    ):
        for relative, expected in design[section].items():
            actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            if relative == "outputs/v04_spent_seed_registry.json":
                transition = terminal["registry_transition"]
                assert expected == transition["pre_sequence_5_file_sha256"]
                assert actual == transition["current_file_sha256"]
            elif relative == "tests/test_lagged_market_conditioned.py":
                supersession = terminal["historical_anchor_supersessions"]["test_files"][relative]
                assert supersession["pre_terminal_transition_sha256"] == expected
                assert supersession["terminal_transition_sha256"] == actual
            else:
                assert actual == expected

    transition = terminal["registry_transition"]
    assert registry["entries"][-1]["sequence"] == transition["receipt"]["sequence"] == 5
    assert registry["entries"][-1]["entry_sha256"] == transition["receipt"]["entry_sha256"]
    assert registry["registry_sha256"] == transition["current_logical_sha256"]

    logical = dict(design)
    recorded = logical.pop("logical_lock_sha256")
    encoded = json.dumps(logical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == recorded
