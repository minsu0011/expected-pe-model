from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    PREDICTION_COLUMNS,
    load_predict_inputs,
    load_wave1_seed_frames,
)
from pe_regime_v04.model_lab.structural.contracts import StructuralContractError
from pe_regime_v04.model_lab.structural.preprocessing import fit_numeric_preprocessor


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v5.py"


def _runner():
    spec = importlib.util.spec_from_file_location("_structural_v5_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_v5_target_eligibility_filters_only_leading_invalid_prefix() -> None:
    module = _runner()
    features = pd.DataFrame({"x": [9.0, 8.0, np.nan, 4.0], "z": [1.0, 2.0, 3.0, 4.0]})
    target = pd.Series([np.nan, np.nan, 3.0, 4.0])
    dates = pd.Series(pd.date_range("2020-01-01", periods=4, freq="D"))
    selected, labels, selected_dates, audit = module._eligible_decomposition_training(
        features, target, dates, [0, 1, 2, 3]
    )
    assert labels.tolist() == [3.0, 4.0]
    assert selected_dates.tolist() == dates.iloc[2:].tolist()
    assert np.isnan(selected.loc[0, "x"])
    assert audit["filtered_session_positions"] == [0, 1]
    assert audit["eligible_train_rows"] == 2
    assert audit["train_feature_nonfinite_cells_imputed_train_only"] == 1


@pytest.mark.parametrize("target", [[np.nan, -1.0], [1.0, np.nan, 2.0]])
def test_v5_target_eligibility_fails_closed_on_zero_or_interior_gap(target: list[float]) -> None:
    module = _runner()
    rows = len(target)
    with pytest.raises(StructuralContractError):
        module._eligible_decomposition_training(
            pd.DataFrame({"x": np.arange(rows)}),
            pd.Series(target),
            pd.Series(pd.date_range("2020-01-01", periods=rows)),
            range(rows),
        )


def test_v5_train_only_feature_imputation_keeps_target_eligible_rows() -> None:
    frame = pd.DataFrame({"x": [np.nan, 2.0, 100.0], "z": [1.0, np.nan, 5.0]})
    fit, transformed = fit_numeric_preprocessor(frame.iloc[:2], ("x", "z"), context="v5-test")
    assert fit.medians == (2.0, 1.0)
    assert np.isfinite(transformed).all()
    # The future row must not influence outer-train medians.
    assert fit.medians != (51.0, 3.0)


def test_v5_chunks_partition_every_candidate_seed_and_reassemble_identically() -> None:
    module = _runner()
    payloads = module._payloads(
        activation_raw_sha256="a" * 64,
        policy_raw_sha256="b" * 64,
        policy_pin_raw_sha256="c" * 64,
    )
    assert len(payloads) == 200
    for seed in module.SEEDS:
        for candidate_id in module.EXPECTED_ENABLED:
            group = [
                row
                for row in payloads
                if row["seed"] == seed and row["candidate_id"] == candidate_id
            ]
            assert len(group) == 8
            folds = [fold_id for row in group for fold_id in row["fold_ids"]]
            assert sorted(folds) == sorted(module.FOLD_IDS)
            assert len(folds) == len(set(folds)) == 62
            assert max(len(row["fold_ids"]) for row in group) == 8

    prediction_rows = [
        {
            "seed": 6301,
            "date": date,
            "symbol": "SYN",
            "fold_id": fold,
            "test_start_position": position,
            "model_id": "m",
            "prediction": prediction,
        }
        for date, fold, position, prediction in (
            ("2020-01-02", "fold_013", 525, 2.0),
            ("2020-01-01", "fold_012", 504, 1.0),
        )
    ]
    diagnostic_rows = [
        {
            "seed": 6301,
            "model_id": "m",
            "fold_id": row["fold_id"],
            "test_start_position": row["test_start_position"],
            "test_rows": 1,
            "status": "PASS",
            "runtime_seconds": 1.0,
            "fit_sha256": "",
            "weight0": np.nan,
            "weight1": np.nan,
            "genuinely_distinct": None,
            "ar1_rho": np.nan,
            "warnings_json": "[]",
            "pid": 1,
        }
        for row in prediction_rows
    ]
    monolithic = [{"predictions": prediction_rows, "diagnostics": diagnostic_rows}]
    chunked = [
        {"predictions": [prediction_rows[index]], "diagnostics": [diagnostic_rows[index]]}
        for index in (1, 0)
    ]
    mono_prediction, mono_diagnostic = module._assemble_results(monolithic)
    chunk_prediction, chunk_diagnostic = module._assemble_results(chunked)
    pd.testing.assert_frame_equal(mono_prediction, chunk_prediction)
    pd.testing.assert_frame_equal(mono_diagnostic, chunk_diagnostic)
    assert tuple(mono_prediction.columns) == PREDICTION_COLUMNS


def test_v5_failure_shutdown_cancels_pending_and_does_not_wait() -> None:
    module = _runner()

    class Future:
        cancelled = False

        def cancel(self) -> None:
            self.cancelled = True

    class Process:
        terminated = False

        def terminate(self) -> None:
            self.terminated = True

    class Executor:
        def __init__(self) -> None:
            self._processes = {1: Process(), 2: Process()}
            self.shutdown_call = None

        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
            self.shutdown_call = (wait, cancel_futures)

    executor = Executor()
    futures = [Future(), Future()]
    module._shutdown_failed(executor, futures)
    assert all(future.cancelled for future in futures)
    assert all(process.terminated for process in executor._processes.values())
    assert executor.shutdown_call == (False, True)


def test_v5_exact_spent_invalid_target_audit() -> None:
    module = _runner()
    manifest = load_predict_inputs(
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
    )
    assert tuple(int(row["seed"]) for row in manifest["seeds"]) == module.SEEDS
    for row in manifest["seeds"]:
        frame, _ = load_wave1_seed_frames(row)
        target = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(
            dtype=np.float64, na_value=np.nan
        )
        invalid = np.flatnonzero((~np.isfinite(target)) | (target <= 0.0)).tolist()
        assert invalid == [0, 1]
        folds = module.v4._folds(frame)[12:]
        assert len(folds) == 62
        assert len(folds[0].train_positions) - len(invalid) == 502
        affected = [fold.fold_id for fold in folds if set(invalid).issubset(fold.train_positions)]
        assert affected == [f"fold_{index:03d}" for index in range(12, 37)]
        assert folds[25].train_positions[0] == 21
        assert np.isfinite(target[504:]).all() and (target[504:] > 0.0).all()


def test_v5_runtime_accepts_only_pinned_launcher() -> None:
    allowed = subprocess.run(
        [
            str(ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe"),
            str(RUNNER),
            "--runtime-preflight-only",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.returncode == 0
    assert "STRUCTURAL_V5_RUNTIME_PREFLIGHT_PASS" in allowed.stdout

    rejected = subprocess.run(
        ["C:/Users/minsu/anaconda3/python.exe", str(RUNNER), "--runtime-preflight-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "rejects non-pinned Python launcher" in rejected.stderr


def test_v5_failure_receipt_is_sealed_and_no_prediction_was_published() -> None:
    receipt = json.loads(
        (
            ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt["status"] == "TERMINAL_FAILED_NO_PREDICTION_ARTIFACT"
    assert receipt["custody"]["published_prediction_files"] == []
    assert receipt["custody"]["truth_opened"] is False
    assert receipt["supersession"]["relaunch_authorized"] is False
