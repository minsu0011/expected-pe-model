from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.matured_proxy_gate import (
    LOCKED_MATURED_PROXY_GATE_CONFIG,
    MATURED_PROXY_GATE_OUTPUT_COLUMNS,
    causal_matured_forward_median_gate as _causal_matured_forward_median_gate,
)


EXPECTED, BASE_LOSS, CHALLENGER_LOSS, COUNT, GAIN, WEIGHT, ACCEPTED, FALLBACK = (
    MATURED_PROXY_GATE_OUTPUT_COLUMNS
)


def _config(*, enabled: bool = True) -> dict[str, object]:
    return {"enabled": enabled, **deepcopy(LOCKED_MATURED_PROXY_GATE_CONFIG)}


def _series(values: object, *, index: pd.Index | None = None) -> pd.Series:
    return pd.Series(values, index=index, dtype=float)


def causal_matured_forward_median_gate(
    observed: pd.Series,
    baseline: pd.Series,
    challenger: pd.Series,
    config: dict[str, object],
):
    symbols = pd.Series("TEST", index=observed.index, dtype="string")
    return _causal_matured_forward_median_gate(
        observed,
        baseline,
        challenger,
        config,
        symbols=symbols,
    )


def test_manual_forward_target_maturity_and_weight_formula() -> None:
    size = 90
    observed = _series(np.exp(np.arange(size, dtype=float) / 100.0))
    baseline = _series(np.full(size, math.exp(0.20)))
    challenger = _series(np.exp(np.arange(size, dtype=float) / 100.0 + 0.11))
    config = _config()
    config["min_history"] = 63
    # Public candidate parameters are immutable, so use a sufficiently long frame
    # and independently reconstruct the first mature decision at t=21+1+62.
    output, diagnostics = causal_matured_forward_median_gate(observed, baseline, challenger, config)
    first_mature = 21 + 1 + 62
    assert output.loc[: first_mature - 1, WEIGHT].eq(0.0).all()
    assert output.loc[first_mature, COUNT] == 63

    baseline_errors = []
    challenger_errors = []
    for origin in range(63):
        target = float(np.median(np.log(observed.iloc[origin + 1 : origin + 22])))
        baseline_errors.append(abs(target - math.log(float(baseline.iloc[origin]))))
        challenger_errors.append(abs(target - math.log(float(challenger.iloc[origin]))))
    expected_gain = float(np.mean(baseline_errors) - np.mean(challenger_errors))
    assert output.loc[first_mature, GAIN] == pytest.approx(expected_gain, abs=1e-15)
    expected_weight = 0.5 * (-math.expm1(-max(expected_gain, 0.0) / 0.004))
    assert output.loc[first_mature, WEIGHT] == pytest.approx(expected_weight, abs=1e-15)
    expected_pe = math.exp(
        (1.0 - expected_weight) * math.log(float(baseline.iloc[first_mature]))
        + expected_weight * math.log(float(challenger.iloc[first_mature]))
    )
    assert output.loc[first_mature, EXPECTED] == pytest.approx(expected_pe, abs=1e-15)
    assert diagnostics["availability_shift_sessions"] == 22
    assert diagnostics["latest_target_observation_lag_sessions"] == 1
    assert diagnostics["routing_estimand"] == (
        "fully_matured_21_session_forward_median_of_observed_log_pe"
    )
    assert diagnostics["fundamental_or_intrinsic_fair_pe_claim_allowed"] is False


def test_current_and_future_observations_cannot_change_prefix_decisions() -> None:
    size = 180
    positions = np.arange(size, dtype=float)
    observed = _series(np.exp(2.5 + 0.002 * positions + 0.02 * np.sin(positions / 7.0)))
    baseline = _series(np.exp(2.55 + 0.001 * positions))
    challenger = _series(np.exp(2.48 + 0.002 * positions))
    original, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())
    cutoff = 130
    changed = observed.copy()
    changed.iloc[cutoff:] *= 1000.0
    intervened, _ = causal_matured_forward_median_gate(changed, baseline, challenger, _config())
    pd.testing.assert_frame_equal(
        original.iloc[:cutoff], intervened.iloc[:cutoff], check_exact=True
    )

    same_row = observed.copy()
    same_row.iloc[cutoff] *= 500.0
    same_row_output, _ = causal_matured_forward_median_gate(
        same_row, baseline, challenger, _config()
    )
    pd.testing.assert_series_equal(
        original.iloc[cutoff], same_row_output.iloc[cutoff], check_exact=True
    )
    assert not original.iloc[cutoff + 22 :].equals(same_row_output.iloc[cutoff + 22 :])


def test_truncated_input_is_prefix_exact_with_custom_index() -> None:
    size = 170
    index = pd.Index(np.arange(size) * 3 + 11)
    positions = np.arange(size, dtype=float)
    observed = _series(np.exp(2.4 + 0.002 * positions), index=index)
    baseline = _series(np.exp(2.45 + 0.001 * positions), index=index)
    challenger = _series(np.exp(2.42 + 0.0015 * positions), index=index)
    full, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())
    cutoff = 125
    short, _ = causal_matured_forward_median_gate(
        observed.iloc[:cutoff], baseline.iloc[:cutoff], challenger.iloc[:cutoff], _config()
    )
    pd.testing.assert_frame_equal(full.iloc[:cutoff], short, check_exact=True)
    assert full.index.equals(index)


def test_inferior_or_immature_challenger_preserves_raw_baseline_exactly() -> None:
    size = 120
    observed = _series(np.full(size, 20.0))
    baseline = _series(np.full(size, 20.0))
    challenger = _series(np.full(size, 200.0))
    output, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())
    pd.testing.assert_series_equal(output[EXPECTED], baseline.rename(EXPECTED), check_exact=True)
    assert output[WEIGHT].eq(0.0).all()
    assert not output[ACCEPTED].any()
    assert not output[FALLBACK].any()


def test_availability_is_raw_anchored_and_fail_closed() -> None:
    size = 100
    observed = _series(np.full(size, 20.0))
    baseline = _series(np.full(size, 20.0))
    challenger = _series(np.full(size, 18.0))
    challenger.iloc[10] = np.nan
    baseline.iloc[11] = np.nan
    output, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())
    assert output.loc[10, EXPECTED] == baseline.loc[10]
    assert output.loc[10, FALLBACK]
    assert math.isnan(output.loc[11, EXPECTED])
    assert not output.loc[11, ACCEPTED]
    assert output[COUNT].dtype == np.dtype("int64")
    assert output[ACCEPTED].dtype == np.dtype("bool")
    assert output[FALLBACK].dtype == np.dtype("bool")


def test_incomplete_future_target_window_is_excluded_from_both_losses() -> None:
    size = 130
    observed = _series(np.full(size, 20.0))
    baseline = _series(np.full(size, 19.0))
    challenger = _series(np.full(size, 21.0))
    observed.iloc[7] = np.nan
    output, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())
    # Origin windows 0..6 include row 7 and are jointly excluded.  Origin 7 is
    # also excluded because its own public observed valuation is invalid.
    assert output.loc[22 + 62, COUNT] == 55
    assert output.loc[22 + 69, COUNT] == 62
    assert output.loc[22 + 70, COUNT] == 63
    assert output.loc[22 + 70, BASE_LOSS] >= 0.0
    assert output.loc[22 + 70, CHALLENGER_LOSS] >= 0.0


def test_invalid_current_observation_fails_closed_and_origin_never_trains_gate() -> None:
    size = 130
    observed = _series(np.full(size, 20.0))
    baseline = _series(np.full(size, 19.0))
    challenger = _series(np.full(size, 21.0))
    invalid_origin = 30
    observed.iloc[invalid_origin] = np.nan
    output, _ = causal_matured_forward_median_gate(observed, baseline, challenger, _config())

    assert math.isnan(output.loc[invalid_origin, EXPECTED])
    assert output.loc[invalid_origin, WEIGHT] == 0.0
    assert not output.loc[invalid_origin, ACCEPTED]
    assert not output.loc[invalid_origin, FALLBACK]

    # The invalid observation is excluded both from every target window that
    # contains it and from the origin-30 prediction/loss itself.
    decision_for_origin = invalid_origin + 22
    clean_observed = _series(np.full(size, 20.0))
    clean, _ = causal_matured_forward_median_gate(clean_observed, baseline, challenger, _config())
    assert output.loc[decision_for_origin, COUNT] < clean.loc[decision_for_origin, COUNT]


def test_disabled_surface_is_typed_and_unavailable() -> None:
    index = pd.Index([10, 20, 30])
    values = _series([10.0, 11.0, 12.0], index=index)
    output, diagnostics = causal_matured_forward_median_gate(
        values, values, values, _config(enabled=False)
    )
    assert output[EXPECTED].isna().all()
    assert output[COUNT].eq(0).all()
    assert output[COUNT].dtype == np.dtype("int64")
    assert output[WEIGHT].eq(0.0).all()
    assert not output[ACCEPTED].any()
    assert not output[FALLBACK].any()
    assert diagnostics["status"] == "unavailable_disabled"


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
        ("temperature", float("nan")),
        ("max_challenger_weight", 1.0),
        ("blend_method", "linear"),
    ],
)
def test_config_is_exactly_locked(field: str, value: object) -> None:
    config = _config()
    config[field] = value
    values = _series([10.0] * 30)
    with pytest.raises(ValueError, match=f"matured_proxy_gate.{field}"):
        causal_matured_forward_median_gate(values, values, values, config)


def test_config_unknown_missing_and_index_mismatch_fail_closed() -> None:
    values = _series([10.0] * 30)
    unknown = _config()
    unknown["post_hoc_threshold"] = 0.1
    with pytest.raises(ValueError, match="unknown"):
        causal_matured_forward_median_gate(values, values, values, unknown)
    missing = _config()
    del missing["temperature"]
    with pytest.raises(ValueError, match="missing"):
        causal_matured_forward_median_gate(values, values, values, missing)
    with pytest.raises(ValueError, match="equal indices"):
        causal_matured_forward_median_gate(
            values,
            pd.Series([10.0] * 30, index=np.arange(30) + 1),
            values,
            _config(),
        )


def test_enabled_operator_rejects_missing_or_multiple_symbol_timelines() -> None:
    values = _series([10.0] * 100)
    with pytest.raises(ValueError, match="requires a symbol Series"):
        _causal_matured_forward_median_gate(values, values, values, _config())
    missing = pd.Series(["TEST"] * 99 + [pd.NA], dtype="string")
    with pytest.raises(ValueError, match="non-empty symbols"):
        _causal_matured_forward_median_gate(values, values, values, _config(), symbols=missing)
    multiple = pd.Series(["A"] * 50 + ["B"] * 50, dtype="string")
    with pytest.raises(ValueError, match="exactly one symbol timeline"):
        _causal_matured_forward_median_gate(values, values, values, _config(), symbols=multiple)


def test_design_lock_candidate_and_pre_reservation_contract_are_self_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    lock_path = root / "config" / "v04_matured_proxy_regularized_gate_design_lock.json"
    candidate_path = root / "config" / "v04_matured_proxy_regularized_gate_candidate.json"
    registry_path = root / "outputs" / "v04_spent_seed_registry.json"
    terminal_path = root / "MG1_TERMINAL_REJECTION.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))

    candidate_id = "causal_matured_forward_median_regularized_promotion_v1"
    assert lock["status"] == "pre_registered_unreserved_unopened"
    assert lock["candidate_id"] == candidate_id
    assert lock["candidate_count"] == lock["hyperparameter_grid_count"] == 1
    assert candidate == {
        "candidates": {
            candidate_id: {
                "selection_column": "v04_matured_proxy_regularized_expected_pe",
                "overrides": {"matured_proxy_gate": {"enabled": True}},
            }
        }
    }
    assert lock["locked_parameters"] == {
        **LOCKED_MATURED_PROXY_GATE_CONFIG,
        "decision_mode": "soft_only",
    }
    assert lock["schema_contract"] == {
        "preserved_v04_append_prefix_columns": 96,
        "preserved_prefix_exact": True,
        "new_tail_columns": 8,
        "v04_append_columns": 104,
        "canonical_total_columns": 254,
        "bundled_64_total_columns": 168,
    }
    formal = lock["formal_validation"]
    assert formal["harness"] == "HARNESS 2.6"
    assert formal["primary_comparator"] == "v04_expected_pe"
    assert formal["anti_gaming_comparator"] == "ml_expected_pe"
    assert formal["bootstrap_cells"] == 24
    assert formal["one_sided_comparator_metric_alpha"] == 0.0125
    allocation = lock["fresh_seed_allocation"]
    assert allocation["tuning_seeds"] == [6301, 6421, 6521, 6607, 6701]
    assert allocation["heldout_seeds"] == [6803, 6907, 7001, 7103, 7207]
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    allocation_seeds = set(allocation["tuning_seeds"] + allocation["heldout_seeds"])
    entries = sorted(registry["entries"], key=lambda entry: entry["sequence"])
    assert [entry["sequence"] for entry in entries] == [1, 2, 3, 4, 5]

    # The design lock is an immutable pre-reservation statement.  Verify that
    # these seeds were fresh through sequence 4, then verify their sole
    # append-only transition into the MG1 sequence-5 reservation.
    spent_before_mg1 = set(registry["baseline_spent_evidence_seeds"])
    for entry in entries[:-1]:
        spent_before_mg1.update(entry["reserved_seeds"])
    assert not spent_before_mg1.intersection(allocation_seeds)

    reservation = entries[-1]
    assert reservation["tuning_seeds"] == allocation["tuning_seeds"]
    assert reservation["locked_seeds"] == allocation["heldout_seeds"]
    assert set(reservation["reserved_seeds"]) == allocation_seeds
    assert reservation["previous_entry_sha256"] == entries[-2]["entry_sha256"]
    assert (
        reservation["reservation_id"]
        == terminal["registry_transition"]["receipt"]["reservation_id"]
    )
    assert reservation["entry_sha256"] == terminal["registry_transition"]["receipt"]["entry_sha256"]

    transition = terminal["registry_transition"]
    assert transition["pre_sequence_5_file_sha256"] == (
        "d23b53cf1f353c3a009c2b4453b13d78cb79854448ea5b9e0cdecaaa9b0fd156"
    )
    assert (
        hashlib.sha256(registry_path.read_bytes()).hexdigest() == transition["current_file_sha256"]
    )
    assert registry["registry_sha256"] == transition["current_logical_sha256"]
    registry_logical = dict(registry)
    registry_recorded = registry_logical.pop("registry_sha256")
    registry_encoded = json.dumps(registry_logical, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    assert hashlib.sha256(registry_encoded).hexdigest() == registry_recorded

    assert terminal["decision"]["status"] == "REJECT_TUNING"
    assert terminal["decision"]["heldout"] == "reserved_spent_unopened"
    assert terminal["production_disposition"] == {
        "candidate_default_enabled": False,
        "candidate_promoted": False,
        "main_expected_pe_path_connected": False,
        "main_expected_pe_replacement_allowed": False,
        "current_v04_expected_pe_retained": True,
        "same_family_retry_allowed": False,
    }

    terminal_logical = dict(terminal)
    terminal_recorded = terminal_logical.pop("terminal_record_sha256")
    terminal_encoded = json.dumps(terminal_logical, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    assert hashlib.sha256(terminal_encoded).hexdigest() == terminal_recorded

    for relative, expected in lock["implementation_artifacts_sha256"].items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if relative == "tests/test_matured_proxy_gate.py":
            supersession = terminal["historical_anchor_supersessions"]["test_files"][relative]
            assert supersession["pre_terminal_transition_sha256"] == expected
            assert supersession["terminal_transition_sha256"] == actual
        else:
            assert actual == expected
    logical = dict(lock)
    recorded = logical.pop("logical_lock_sha256")
    encoded = json.dumps(logical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == recorded

    design_binding = terminal["pre_registration"]["design_lock"]
    assert hashlib.sha256(lock_path.read_bytes()).hexdigest() == design_binding["file_sha256"]
    assert recorded == design_binding["logical_sha256"]
