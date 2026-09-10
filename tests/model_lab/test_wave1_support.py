"""Synthetic-only helpers shared by Wave1 tests; this module contains no project data."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    canonical_json_bytes,
    file_record,
    logical_frame_sha256,
    seal_payload,
    write_immutable_json,
)
from pe_regime_v04.model_lab.models.wave1.spec import (
    BASELINE_MODEL_IDS,
    COMMON_FEATURES,
    DESIGN_LOCK_SHA256,
    REGIME_EXTENSION,
)


def synthetic_model_and_baselines(rows: int = 315) -> tuple[pd.DataFrame, pd.DataFrame]:
    position = np.arange(rows, dtype=np.float64)
    # Generate a fixed-prefix local-linear-trend series that exercises the exact
    # statsmodels UCM fit without relying on project observations.
    rng = np.random.default_rng(1)
    synthetic_capacity = max(rows, 4096)
    slope = np.cumsum(rng.normal(0.0, 0.0002, synthetic_capacity))
    log_observed = (
        2.7
        + np.cumsum(0.001 + slope)
        + rng.normal(0.0, 0.02, synthetic_capacity)
    )[:rows]
    data: dict[str, object] = {
        "date": pd.date_range("2000-01-03", periods=rows, freq="B"),
        "symbol": ["SYNTH"] * rows,
        "observed_pe": np.exp(log_observed),
    }
    for index, column in enumerate((*COMMON_FEATURES, *REGIME_EXTENSION)):
        values = np.sin(position / (5.0 + index % 11)) + 0.001 * position + index * 0.01
        if column == "eps_confidence":
            values = 50.0 + 40.0 * np.sin(position / 17.0)
        elif column == "eps_approximation_flag":
            values = (position.astype(int) % 7 == 0).astype(float)
        elif column.startswith("v04_current_p_") or column.startswith("forecast_p_"):
            offset = (
                0.15
                if column.endswith("bear")
                else 0.55
                if column.endswith("sideways")
                else 0.30
            )
            values = np.clip(offset + 0.03 * np.sin(position / (9.0 + index)), 0.01, 0.98)
        data[column] = values
    model = pd.DataFrame(data)
    observed = pd.to_numeric(model["observed_pe"]).to_numpy(float)
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


def synthetic_canonical_output(rows: int = 315) -> tuple[pd.DataFrame, pd.DataFrame]:
    model, baselines = synthetic_model_and_baselines(rows)
    canonical_data: dict[str, object] = {
        "date": model["date"],
        "symbol": model["symbol"],
        "observed_pe": model["observed_pe"],
        **{column: model[column] for column in COMMON_FEATURES},
        **{column: model[column] for column in REGIME_EXTENSION[3:]},
        "ml_expected_pe": baselines["ml_expected_pe"],
    }
    fill_index = 0
    while len(canonical_data) < 150:
        name = f"synthetic_filler_{fill_index:03d}"
        canonical_data[name] = np.arange(rows, dtype=np.float64) + fill_index
        fill_index += 1
    canonical = pd.DataFrame(canonical_data)
    output = canonical.copy()
    for column in REGIME_EXTENSION[:3]:
        output[column] = model[column].to_numpy(copy=True)
    for column in BASELINE_MODEL_IDS:
        if column not in output:
            output[column] = baselines[column].to_numpy(copy=True)
    fill_index = 0
    output_fillers: dict[str, np.ndarray] = {}
    while len(output.columns) < 254:
        name = f"synthetic_output_filler_{fill_index:03d}"
        if name not in output and name not in output_fillers:
            output_fillers[name] = np.arange(rows, dtype=np.float64) - fill_index
        fill_index += 1
        if len(output.columns) + len(output_fillers) == 254:
            break
    output = pd.concat([output, pd.DataFrame(output_fillers)], axis=1)
    return canonical, output


def write_synthetic_predict_inputs(tmp_path: Path, *, rows: int = 315) -> Path:
    canonical, output = synthetic_canonical_output(rows)
    canonical_path = tmp_path / "canonical150.csv"
    output_path = tmp_path / "output254.csv"
    canonical.to_csv(
        canonical_path,
        index=False,
        lineterminator="\n",
        float_format="%.17g",
    )
    output.to_csv(output_path, index=False, lineterminator="\n", float_format="%.17g")
    binding_path = tmp_path / "execution_binding.json"
    precommit_path = tmp_path / "execution_precommit.json"
    binding_path.write_text("{}\n", encoding="utf-8")
    precommit_path.write_text("{}\n", encoding="utf-8")
    canonical_disk = pd.read_csv(canonical_path, low_memory=False, float_precision="round_trip")
    output_disk = pd.read_csv(output_path, low_memory=False, float_precision="round_trip")
    entry = {
        "seed": 6301,
        "source_record_bytes": 123,
        "source_record_sha256": "0" * 64,
        "canonical_csv": file_record(canonical_path),
        "output_csv": file_record(output_path),
        "expected_rows": rows,
        "expected_symbol": "SYNTH",
        "canonical_columns_sha256": hashlib.sha256(
            canonical_json_bytes(list(canonical_disk.columns))
        ).hexdigest(),
        "output_columns_sha256": hashlib.sha256(
            canonical_json_bytes(list(output_disk.columns))
        ).hexdigest(),
        "prefix150_logical_sha256": logical_frame_sha256(canonical_disk),
        "identity_logical_sha256": logical_frame_sha256(
            pd.DataFrame(
                {
                    "date": pd.to_datetime(canonical_disk["date"]).dt.strftime("%Y-%m-%d"),
                    "symbol": canonical_disk["symbol"].astype(str),
                }
            )
        ),
    }
    manifest = seal_payload(
        {
            "format_version": 1,
            "mode": "predict_inputs",
            "design_lock_sha256": DESIGN_LOCK_SHA256,
            "execution_binding": file_record(binding_path),
            "execution_precommit": file_record(precommit_path),
            "evaluation_data_excluded": True,
            "seeds": [entry],
        }
    )
    path = tmp_path / "PREDICT_INPUTS.json"
    write_immutable_json(path, manifest)
    return path
