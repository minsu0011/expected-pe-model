"""Synthetic-only Wave-1 dry evidence; candidate evaluation is impossible here."""

# ruff: noqa: E402 -- the resource seal must precede every potentially numerical import.

from __future__ import annotations

import os

for _name in (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    os.environ[_name] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import numpy as np
import pandas as pd
from pandas.testing import assert_frame_equal
from threadpoolctl import threadpool_limits

from pe_regime_v04.model_lab import ContractError
from pe_regime_v04.model_lab.models.wave1.adapters import resolved_parameter_manifest
from pe_regime_v04.model_lab.models.wave1.artifacts import seal_payload, write_immutable_json
from pe_regime_v04.model_lab.models.wave1.resources import assert_threadpools_one
from pe_regime_v04.model_lab.models.wave1.runner import (
    execution_warning_policy,
    run_seed_predictions,
)
from pe_regime_v04.model_lab.models.wave1.spec import (
    BASELINE_MODEL_IDS,
    COMMON_FEATURES,
    REGIME_EXTENSION,
)


def _synthetic(rows: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    position = np.arange(rows, dtype=np.float64)
    rng = np.random.default_rng(1)
    capacity = max(rows, 4096)
    slope = np.cumsum(rng.normal(0.0, 0.0002, capacity))
    observed = np.exp(
        (
            2.7
            + np.cumsum(0.001 + slope)
            + rng.normal(0.0, 0.02, capacity)
        )[:rows]
    )
    data: dict[str, object] = {
        "date": pd.date_range("2000-01-03", periods=rows, freq="B"),
        "symbol": ["SYNTH"] * rows,
        "observed_pe": observed,
    }
    for index, column in enumerate((*COMMON_FEATURES, *REGIME_EXTENSION)):
        feature_rng = np.random.default_rng(10_000 + index)
        values = feature_rng.normal(index * 0.01, 1.0, rows) + 0.0001 * position
        if column == "eps_confidence":
            values = feature_rng.uniform(5.0, 100.0, rows)
        elif column == "eps_approximation_flag":
            values = (position.astype(int) % 7 == 0).astype(float)
        elif column.startswith("v04_current_p_") or column.startswith("forecast_p_"):
            values = feature_rng.uniform(0.05, 0.95, rows)
        data[column] = values
    model = pd.DataFrame(data)
    baselines = pd.DataFrame(
        {
            "date": model["date"],
            "symbol": model["symbol"],
            "v04_expected_pe": observed * 1.01,
            "ml_expected_pe": observed * 0.99,
            "v04_ml_expected_pe_no_regime": observed * 1.02,
            "v04_ml_expected_pe_with_regime": observed * 1.005,
        }
    )
    return model, baselines.loc[:, ["date", "symbol", *BASELINE_MODEL_IDS]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run synthetic-only Wave1 no-score checks")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resolved-parameters-output", type=Path, required=True)
    args = parser.parse_args(argv)
    model, baselines = _synthetic(315)
    with execution_warning_policy(), threadpool_limits(limits=1):
        resolved = resolved_parameter_manifest(
            model,
            model["observed_pe"],
            fold_seed=6553,
        )
        inventory = assert_threadpools_one()
    resolved_payload = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_synthetic_resolved_model_parameters",
            "project_data_read": False,
            "candidate_scores_computed": False,
            "parameters": resolved,
        }
    )
    write_immutable_json(args.resolved_parameters_output, resolved_payload)

    selected = ("ridge_svd_common", "extra_trees_common")
    serial = run_seed_predictions(
        model.iloc[:294].copy(),
        baselines.iloc[:294].copy(),
        seed=6301,
        model_ids=selected,
        outer_workers=1,
        enforce_affinity=False,
    )
    parallel = run_seed_predictions(
        model.iloc[:294].copy(),
        baselines.iloc[:294].copy(),
        seed=6301,
        model_ids=selected,
        outer_workers=32,
        enforce_affinity=False,
    )
    assert_frame_equal(serial.predictions, parallel.predictions, check_exact=True)
    diagnostic_columns = [
        column for column in serial.diagnostics if column != "runtime_seconds"
    ]
    assert_frame_equal(
        serial.diagnostics.loc[:, diagnostic_columns],
        parallel.diagnostics.loc[:, diagnostic_columns],
        check_exact=True,
    )
    intervened = model.copy()
    intervened.loc[294:, "benchmark_return_63"] = 1.0e9
    future = run_seed_predictions(
        intervened,
        baselines,
        seed=6301,
        model_ids=("ridge_svd_common",),
        outer_workers=32,
        enforce_affinity=False,
    )
    prefix = run_seed_predictions(
        model.iloc[:294].copy(),
        baselines.iloc[:294].copy(),
        seed=6301,
        model_ids=("ridge_svd_common",),
        outer_workers=1,
        enforce_affinity=False,
    )
    earlier = future.predictions.loc[
        future.predictions["date"] <= model["date"].iloc[293]
    ].reset_index(drop=True)
    assert_frame_equal(prefix.predictions, earlier, check_exact=True)
    malicious = model.copy()
    malicious["true_fair_pe"] = malicious["observed_pe"]
    truth_rejected = False
    try:
        run_seed_predictions(
            malicious,
            baselines,
            seed=6301,
            model_ids=("ridge_svd_common",),
            outer_workers=1,
            enforce_affinity=False,
        )
    except ContractError:
        truth_rejected = True
    if not truth_rejected:
        raise RuntimeError("synthetic truth-path rejection dry test failed")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_synthetic_no_score_dry_run",
            "project_data_read": False,
            "candidate_scores_computed": False,
            "serial1_parallel32_exact": True,
            "prefix_future_intervention_exact": True,
            "truth_input_rejected": True,
            "baseline_schema_exact": tuple(baselines.columns)
            == ("date", "symbol", *BASELINE_MODEL_IDS),
            "prediction_schema": list(serial.predictions.columns),
            "diagnostic_schema": list(serial.diagnostics.columns),
            "resolved_model_count": len(resolved),
            "threadpool_inventory": inventory,
        }
    )
    write_immutable_json(args.output, payload)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
