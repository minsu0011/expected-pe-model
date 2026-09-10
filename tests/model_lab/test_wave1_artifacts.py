from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    PREDICTION_COLUMNS,
    Wave1ArtifactError,
    canonical_json_bytes,
    file_record,
    load_predict_inputs,
    load_wave1_seed_frames,
    logical_frame_sha256,
    seal_payload,
    write_immutable_json,
    write_round_trip_csv,
)
from pe_regime_v04.model_lab.models.wave1.spec import (
    COMMON_FEATURES,
    DESIGN_LOCK_SHA256,
    REGIME_EXTENSION,
)

from test_wave1_support import synthetic_canonical_output, write_synthetic_predict_inputs


def _entry_for_files(canonical_path: Path, output_path: Path) -> dict:
    canonical = pd.read_csv(canonical_path, low_memory=False, float_precision="round_trip")
    output = pd.read_csv(output_path, low_memory=False, float_precision="round_trip")
    return {
        "seed": 6301,
        "source_record_bytes": 123,
        "source_record_sha256": "0" * 64,
        "canonical_csv": file_record(canonical_path),
        "output_csv": file_record(output_path),
        "expected_rows": len(canonical),
        "expected_symbol": "SYNTH",
        "canonical_columns_sha256": hashlib.sha256(
            canonical_json_bytes(list(canonical.columns))
        ).hexdigest(),
        "output_columns_sha256": hashlib.sha256(
            canonical_json_bytes(list(output.columns))
        ).hexdigest(),
        "prefix150_logical_sha256": logical_frame_sha256(canonical),
        "identity_logical_sha256": logical_frame_sha256(
            pd.DataFrame(
                {
                    "date": pd.to_datetime(canonical["date"]).dt.strftime("%Y-%m-%d"),
                    "symbol": canonical["symbol"].astype(str),
                }
            )
        ),
    }


def test_safe_manifest_loads_all_36_features_from_split_sources(tmp_path: Path) -> None:
    manifest_path = write_synthetic_predict_inputs(tmp_path)
    payload = load_predict_inputs(manifest_path)
    model_frame, baselines = load_wave1_seed_frames(payload["seeds"][0])
    assert set((*COMMON_FEATURES, *REGIME_EXTENSION)).issubset(model_frame.columns)
    assert list(model_frame.loc[:, list(REGIME_EXTENSION[:3])].columns) == list(
        REGIME_EXTENSION[:3]
    )
    assert len(model_frame) == len(baselines) == 315


def test_predict_manifest_rejects_any_evaluation_path_before_schema_use(tmp_path: Path) -> None:
    binding = tmp_path / "binding.json"
    precommit = tmp_path / "precommit.json"
    binding.write_text("{}\n", encoding="utf-8")
    precommit.write_text("{}\n", encoding="utf-8")
    malicious = seal_payload(
        {
            "format_version": 1,
            "mode": "predict_inputs",
            "design_lock_sha256": DESIGN_LOCK_SHA256,
            "execution_binding": file_record(binding),
            "execution_precommit": file_record(precommit),
            "evaluation_data_excluded": True,
            "seeds": [],
            "truth_csv": {"path": "C:/sealed_truth.csv"},
        }
    )
    path = tmp_path / "malicious.json"
    write_immutable_json(path, malicious)
    with pytest.raises(Wave1ArtifactError, match="evaluation-data reference"):
        load_predict_inputs(path)


def test_current_regime_sidecar_collision_with_canonical_is_rejected(tmp_path: Path) -> None:
    canonical, output = synthetic_canonical_output(315)
    filler = next(column for column in canonical if column.startswith("synthetic_filler_"))
    collision = REGIME_EXTENSION[0]
    canonical = canonical.rename(columns={filler: collision})
    tail = output.iloc[:, 150:].drop(columns=[collision])
    output = pd.concat([canonical, tail], axis=1)
    while len(output.columns) < 254:
        output[f"collision_fill_{len(output.columns):03d}"] = np.arange(len(output), dtype=float)
    canonical_path = tmp_path / "canonical.csv"
    output_path = tmp_path / "output.csv"
    canonical.to_csv(canonical_path, index=False, lineterminator="\n", float_format="%.17g")
    output.to_csv(output_path, index=False, lineterminator="\n", float_format="%.17g")
    entry = _entry_for_files(canonical_path, output_path)
    with pytest.raises(Wave1ArtifactError, match="sidecar columns collide"):
        load_wave1_seed_frames(entry)


def test_prediction_csv_round_trip_is_bit_exact_and_schema_locked(tmp_path: Path) -> None:
    frame = pd.DataFrame(
        {
            "seed": [6301, 6301],
            "date": pd.to_datetime(["2015-01-02", "2015-01-05"]),
            "symbol": ["SYNTH", "SYNTH"],
            "fold_id": ["fold_000", "fold_000"],
            "test_start_position": [252, 252],
            "model_id": ["ridge_svd_common", "ridge_svd_common"],
            "prediction": [np.nextafter(10.0, 11.0), np.nan],
        },
        columns=PREDICTION_COLUMNS,
    )
    path = tmp_path / "predictions.csv"
    record = write_round_trip_csv(frame, path, columns=PREDICTION_COLUMNS)
    assert record["sha256"] == file_record(path)["sha256"]
    reread = pd.read_csv(path, float_precision="round_trip")
    assert reread["prediction"].iloc[0] == frame["prediction"].iloc[0]
    assert np.isnan(reread["prediction"].iloc[1])


def test_manifest_tampering_fails_seal(tmp_path: Path) -> None:
    path = write_synthetic_predict_inputs(tmp_path)
    payload = path.read_text(encoding="utf-8").replace('"expected_rows": 315', '"expected_rows": 314')
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(Wave1ArtifactError, match="manifest_sha256"):
        load_predict_inputs(path)
