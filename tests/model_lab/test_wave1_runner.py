from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import warnings

import numpy as np
from pandas.testing import assert_frame_equal
from statsmodels.tools.sm_exceptions import SpecificationWarning

from pe_regime_v04.model_lab.models.wave1.resources import seal_cpu_environment
from pe_regime_v04.model_lab.models.wave1.prediction_mode import (
    fold_execution_sha256,
    fold_schedule_sha256,
)
from pe_regime_v04.model_lab.models.wave1.runner import (
    STATE_SPACE_ALLOWED_WARNING,
    _training_eligible_positions,
    execution_warning_policy,
    run_seed_predictions,
)

from test_wave1_support import synthetic_model_and_baselines


def test_training_eligibility_is_target_only_and_keeps_all_missing_feature_row() -> None:
    model, _ = synthetic_model_and_baselines(273)
    model.loc[0, list(model.columns[3:])] = np.nan
    folds_result = run_seed_predictions
    del folds_result
    from pe_regime_v04.model_lab.models.wave1.runner import FOLD_SPEC
    from pe_regime_v04.model_lab.folds import generate_pit_folds

    folds = generate_pit_folds(model.loc[:, ["date"]], FOLD_SPEC)
    eligible = _training_eligible_positions(model, folds[0])
    assert 0 in eligible
    model.loc[1, "observed_pe"] = np.nan
    eligible = _training_eligible_positions(model, folds[0])
    assert 1 not in eligible


def test_full_fold_hash_binds_train_windows_beyond_secondary_schedule_hash() -> None:
    from pe_regime_v04.model_lab.folds import generate_pit_folds
    from pe_regime_v04.model_lab.models.wave1.runner import FOLD_SPEC

    model, _ = synthetic_model_and_baselines(315)
    original = generate_pit_folds(model.loc[:, ["date"]], FOLD_SPEC)
    altered_first = replace(
        original[0],
        train_positions=original[0].train_positions[1:],
    )
    altered = (altered_first, *original[1:])
    assert fold_schedule_sha256(original) == fold_schedule_sha256(altered)
    assert fold_execution_sha256(original) != fold_execution_sha256(altered)


def test_one_global_warning_policy_is_deterministic_under_threads() -> None:
    def unexpected(_: int) -> str:
        try:
            warnings.warn("wave1 unexpected", UserWarning)
        except UserWarning:
            return "ERROR"
        return "NOT_ERROR"

    def allowed(_: int) -> str:
        warnings.warn(STATE_SPACE_ALLOWED_WARNING, SpecificationWarning)
        return "IGNORED"

    with execution_warning_policy():
        with ThreadPoolExecutor(max_workers=32) as executor:
            assert set(executor.map(unexpected, range(128))) == {"ERROR"}
            assert set(executor.map(allowed, range(128))) == {"IGNORED"}


def test_serial1_parallel32_predictions_are_bit_exact() -> None:
    seal_cpu_environment()
    model, baselines = synthetic_model_and_baselines(294)
    selected = ("ridge_svd_common", "extra_trees_common")
    serial = run_seed_predictions(
        model,
        baselines,
        seed=6301,
        model_ids=selected,
        outer_workers=1,
        enforce_affinity=False,
    )
    parallel = run_seed_predictions(
        model,
        baselines,
        seed=6301,
        model_ids=selected,
        outer_workers=32,
        enforce_affinity=False,
    )
    assert_frame_equal(serial.predictions, parallel.predictions, check_exact=True)
    diagnostic_columns = [
        column for column in serial.diagnostics.columns if column != "runtime_seconds"
    ]
    assert_frame_equal(
        serial.diagnostics.loc[:, diagnostic_columns],
        parallel.diagnostics.loc[:, diagnostic_columns],
        check_exact=True,
    )


def test_prefix_and_future_intervention_do_not_change_earlier_predictions() -> None:
    seal_cpu_environment()
    full_model, full_baselines = synthetic_model_and_baselines(315)
    prefix_model = full_model.iloc[:294].copy()
    prefix_baselines = full_baselines.iloc[:294].copy()
    intervened_model = full_model.copy()
    intervened_model.loc[294:, "benchmark_return_63"] = 1.0e9
    prefix = run_seed_predictions(
        prefix_model,
        prefix_baselines,
        seed=6301,
        model_ids=("ridge_svd_common",),
        outer_workers=1,
        enforce_affinity=False,
    )
    full = run_seed_predictions(
        intervened_model,
        full_baselines,
        seed=6301,
        model_ids=("ridge_svd_common",),
        outer_workers=32,
        enforce_affinity=False,
    )
    cutoff = prefix_model["date"].iloc[-1]
    earlier = full.predictions.loc[full.predictions["date"] <= cutoff].reset_index(drop=True)
    assert_frame_equal(prefix.predictions, earlier, check_exact=True)


def test_state_space_training_history_does_not_depend_on_common_feature_availability() -> None:
    seal_cpu_environment()
    model, baselines = synthetic_model_and_baselines(273)
    from pe_regime_v04.model_lab.models.wave1.spec import COMMON_FEATURES

    model.loc[:251, list(COMMON_FEATURES)] = np.nan
    result = run_seed_predictions(
        model,
        baselines,
        seed=6301,
        model_ids=("state_space_local_linear_trend_target_history_only",),
        outer_workers=32,
        enforce_affinity=False,
    )
    diagnostic = result.diagnostics.iloc[0]
    assert diagnostic["eligible_train_rows"] == 252
    assert diagnostic["status"] == "OK"
    state_rows = result.predictions.loc[
        result.predictions["model_id"]
        == "state_space_local_linear_trend_target_history_only"
    ]
    assert np.isfinite(state_rows["prediction"]).all()
