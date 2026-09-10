"""Exact fold identity and all-call no-fit evidence for Structural V7."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from research.model_zoo.structural_v7.contracts import StructuralV7ContractError, sha256_file
from research.model_zoo.structural_v7.design import PREFLIGHT_RAW_SHA256
from research.model_zoo.structural_v7.folds import (
    build_base_fold_calls,
    build_outer_folds,
    fold_id_for_start,
)


ROOT = Path(__file__).resolve().parents[2]


def _dates() -> pd.DatetimeIndex:
    return pd.date_range("2013-01-02", periods=1800, freq="B")


def test_exact_base_and_outer_fold_schedules() -> None:
    base = build_base_fold_calls(_dates())
    outer = build_outer_folds(_dates())
    assert len(base) == 74
    assert base[0].fold_id == "fold_000"
    assert base[0].train_rows == 252
    assert base[0].test_rows == 21
    assert base[-1].fold_id == "fold_073"
    assert base[-1].test_rows == 15
    assert len(outer) == 62
    assert outer[0].fold_id == "fold_012"
    assert outer[0].train_rows == 504
    assert sum(fold.test_rows for fold in outer) == 1296
    assert fold_id_for_start(504) == "fold_012"
    with pytest.raises(StructuralV7ContractError):
        fold_id_for_start(505)


def test_fold_builder_rejects_reordered_or_wrong_length_identity() -> None:
    dates = list(_dates())
    dates[5], dates[6] = dates[6], dates[5]
    with pytest.raises(StructuralV7ContractError):
        build_base_fold_calls(dates)
    with pytest.raises(StructuralV7ContractError):
        build_outer_folds(_dates()[:-1])


def test_published_preflight_covers_every_call_and_is_score_free() -> None:
    path = ROOT / "outputs/model_zoo_structural_v7_preflight_20260820/PREFLIGHT.json"
    assert sha256_file(path) == PREFLIGHT_RAW_SHA256
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["status"] == "GO_NO_FIT_EXECUTABILITY_ONLY_HEAVY_LAUNCH_BLOCKED"
    assert payload["base_fit_call_count"] == 5 * 2 * 74 == 740
    assert payload["candidate_outer_consumer_edge_count"] == 5 * 10 * 62 == 3100
    assert payload["hard_failure_count"] == 0
    assert payload["preferred_min_exception_count"] == 10
    assert {row["usable_label_rows"] for row in payload["preferred_min_exceptions"]} == {250}
    assert {row["fold_id"] for row in payload["preferred_min_exceptions"]} == {"fold_000"}
    assert all(row["hard_min_pass"] for row in payload["preferred_min_exceptions"])
    assert payload["minimum_meta_usable_label_rows"] == 252
    assert payload["minimum_structural_usable_label_rows"] == 502
    assert payload["minimum_existing_pair_common_rows"] == 231
    assert payload["minimum_planned_pair_common_rows_after_v7_refit"] == 252
    assert payload["fit_calls_executed"] == 0
    assert payload["prediction_rows_generated"] == 0
    assert payload["evaluation_truth_opened"] is False
    assert payload["scores_computed"] is False
    assert payload["heavy_launch_authorized"] is False

