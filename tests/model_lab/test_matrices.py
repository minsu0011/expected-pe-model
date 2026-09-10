from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from pe_regime_v04.model_lab import (
    ContractError,
    ParquetUnavailableError,
    canonicalize_oos_matrices,
    write_oos_matrices,
)
from pe_regime_v04.model_lab import matrices as matrices_module


def test_canonical_long_and_wide_matrices_are_stable(
    prediction_frame: pd.DataFrame,
) -> None:
    shuffled = prediction_frame.sample(frac=1.0, random_state=42)
    matrices = canonicalize_oos_matrices(shuffled)
    assert matrices.long["model_id"].tolist()[:2] == ["model_a", "model_b"]
    assert matrices.wide.columns.tolist() == [
        "seed",
        "date",
        "fold_id",
        "true_fair_pe",
        "prediction__model_a",
        "prediction__model_b",
    ]
    assert len(matrices.long) == 8
    assert len(matrices.wide) == 4


def test_matrix_validation_rejects_duplicate_and_inconsistent_truth(
    prediction_frame: pd.DataFrame,
) -> None:
    duplicate = pd.concat([prediction_frame, prediction_frame.iloc[[0]]], ignore_index=True)
    with pytest.raises(ContractError, match="unique"):
        canonicalize_oos_matrices(duplicate)
    inconsistent = prediction_frame.copy()
    inconsistent.loc[4, "true_fair_pe"] = 99.0
    with pytest.raises(ContractError, match="identical"):
        canonicalize_oos_matrices(inconsistent)
    inconsistent_fold = prediction_frame.copy()
    inconsistent_fold.loc[4, "fold_id"] = "fold_999"
    with pytest.raises(ContractError, match="fold_id"):
        canonicalize_oos_matrices(inconsistent_fold)


def test_csv_writer_is_mandatory_immutable_and_hashes_outputs(
    tmp_path: Path,
    prediction_frame: pd.DataFrame,
) -> None:
    artifacts = write_oos_matrices(prediction_frame, tmp_path / "matrix")
    assert artifacts.long_csv.exists()
    assert artifacts.wide_csv.exists()
    assert len(artifacts.long_csv_sha256) == 64
    assert len(artifacts.wide_csv_sha256) == 64
    assert artifacts.long_parquet is None
    assert artifacts.wide_parquet is None
    long_roundtrip = pd.read_csv(artifacts.long_csv)
    wide_roundtrip = pd.read_csv(artifacts.wide_csv)
    assert len(long_roundtrip) == 8
    assert len(wide_roundtrip) == 4
    with pytest.raises(FileExistsError, match="immutable"):
        write_oos_matrices(prediction_frame, tmp_path / "matrix")


def test_required_parquet_fails_before_any_output_when_engine_missing(
    tmp_path: Path,
    prediction_frame: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(matrices_module.importlib.util, "find_spec", lambda _name: None)
    output = tmp_path / "no-engine"
    with pytest.raises(ParquetUnavailableError, match="unavailable"):
        write_oos_matrices(prediction_frame, output, parquet="required")
    assert not output.exists()


@pytest.mark.parametrize("stem", ["", "bad/name", "bad\\name", "C:bad"])
def test_writer_rejects_unsafe_stem(
    tmp_path: Path,
    prediction_frame: pd.DataFrame,
    stem: str,
) -> None:
    with pytest.raises(ContractError, match="stem"):
        write_oos_matrices(prediction_frame, tmp_path, stem=stem)
