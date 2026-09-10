from __future__ import annotations

import hashlib
import json

import pandas as pd
import pytest

from pe_regime_v04.model_lab import (
    ContractError,
    PITFoldSpec,
    fold_manifest,
    generate_pit_folds,
    iter_fold_frames,
)


def _frame(*, sessions: int = 14, label_delay: int = 0) -> pd.DataFrame:
    dates = pd.date_range("2014-12-01", periods=sessions, freq="B")
    rows = []
    for date in dates:
        for seed in (1, 2):
            rows.append(
                {
                    "seed": seed,
                    "date": date,
                    "label_available_at": date + pd.offsets.BDay(label_delay),
                }
            )
    return pd.DataFrame(rows)


def test_pit_folds_use_sessions_embargo_and_nonoverlapping_tests() -> None:
    frame = _frame()
    spec = PITFoldSpec(
        min_train_sessions=4,
        test_sessions=2,
        step_sessions=2,
        embargo_sessions=1,
    )
    folds = generate_pit_folds(frame, spec, label_available_at_column="label_available_at")
    assert len(folds) == 4
    all_test_positions: set[int] = set()
    for fold in folds:
        assert fold.train_end < fold.test_start
        assert fold.label_information_cutoff < fold.test_start
        assert all_test_positions.isdisjoint(fold.test_positions)
        all_test_positions.update(fold.test_positions)
        train_dates = frame.iloc[list(fold.train_positions)]["date"]
        test_dates = frame.iloc[list(fold.test_positions)]["date"]
        assert train_dates.nunique() >= 4
        assert test_dates.nunique() == 2


def test_label_maturity_excludes_unavailable_training_rows() -> None:
    frame = _frame(label_delay=2)
    spec = PITFoldSpec(
        min_train_sessions=4,
        test_sessions=2,
        step_sessions=2,
        embargo_sessions=0,
    )
    folds = generate_pit_folds(frame, spec, label_available_at_column="label_available_at")
    first = folds[0]
    training = frame.iloc[list(first.train_positions)]
    assert (training["label_available_at"] <= first.label_information_cutoff).all()
    assert training["date"].nunique() >= 4
    assert first.label_information_cutoff < first.test_start


def test_rolling_train_window_and_manifest_are_deterministic() -> None:
    frame = _frame()
    spec = PITFoldSpec(4, 2, 2, max_train_sessions=5)
    first = generate_pit_folds(frame, spec)
    second = generate_pit_folds(frame.copy(), spec)
    assert first == second
    manifest = fold_manifest(first)
    assert manifest["fold_id"].tolist() == [fold.fold_id for fold in first]
    assert all(manifest["train_rows"] <= 10)
    chunks = list(iter_fold_frames(frame, first))
    assert len(chunks) == len(first)
    assert chunks[0][1].index.tolist() == list(first[0].train_positions)


@pytest.mark.parametrize(
    "spec",
    [
        PITFoldSpec(4, 2, 2),
        PITFoldSpec(4, 2, 3, embargo_sessions=1),
    ],
)
def test_fold_ids_are_contiguous(spec: PITFoldSpec) -> None:
    folds = generate_pit_folds(_frame(), spec)
    assert [fold.fold_id for fold in folds] == [f"fold_{i:03d}" for i in range(len(folds))]


def test_invalid_specs_and_temporal_data_fail_closed() -> None:
    with pytest.raises(ContractError, match="overlapping"):
        PITFoldSpec(4, 3, 2)
    with pytest.raises(ContractError, match="no PIT-safe"):
        generate_pit_folds(_frame(sessions=4), PITFoldSpec(4, 2, 2))
    frame = _frame()
    frame.loc[0, "label_available_at"] = frame.loc[0, "date"] - pd.Timedelta(days=1)
    with pytest.raises(ContractError, match="before"):
        generate_pit_folds(
            frame,
            PITFoldSpec(4, 2, 2),
            label_available_at_column="label_available_at",
        )
    frame.loc[0, "date"] = pd.NaT
    with pytest.raises(ContractError, match="invalid"):
        generate_pit_folds(frame, PITFoldSpec(4, 2, 2))


def test_v04_1800_schedule_includes_exact_partial_terminal_fold() -> None:
    frame = pd.DataFrame({"date": pd.bdate_range("2013-01-02", periods=1800)})
    spec = PITFoldSpec(
        min_train_sessions=252,
        test_sessions=21,
        step_sessions=21,
        allow_partial_final_test=True,
    )
    folds = generate_pit_folds(frame, spec)
    expected_starts = list(range(252, 1800, 21))
    actual_starts = [fold.test_positions[0] for fold in folds]
    assert actual_starts == expected_starts
    assert len(folds) == 74
    assert [len(fold.test_positions) for fold in folds[:-1]] == [21] * 73
    assert folds[-1].test_positions == tuple(range(1785, 1800))
    assert sorted(position for fold in folds for position in fold.test_positions) == list(
        range(252, 1800)
    )
    schedule = {
        "starts": actual_starts,
        "test_sizes": [len(fold.test_positions) for fold in folds],
    }
    digest = hashlib.sha256(
        json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    assert digest == "9b8bce1a68df3dd4655eab96450d6592aed2002d5bc71ec0d68a1d4c5b92d2ac"


def test_partial_terminal_fold_is_opt_in_and_boolean_typed() -> None:
    frame = _frame(sessions=7)
    strict = generate_pit_folds(frame, PITFoldSpec(4, 2, 2))
    partial = generate_pit_folds(
        frame,
        PITFoldSpec(4, 2, 2, allow_partial_final_test=True),
    )
    assert [len(fold.test_positions) for fold in strict] == [4]
    assert [len(fold.test_positions) for fold in partial] == [4, 2]
    with pytest.raises(ContractError, match="boolean"):
        PITFoldSpec(4, 2, 2, allow_partial_final_test=1)  # type: ignore[arg-type]
