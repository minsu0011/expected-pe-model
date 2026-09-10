from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import FeatureMetadata


@pytest.fixture
def observed_feature() -> FeatureMetadata:
    return FeatureMetadata(
        feature_id="observed_pe",
        column_name="observed_pe",
        description="PIT observed P/E",
        source="test",
        dtype="float64",
        availability="point_in_time",
        availability_lag_sessions=0,
        lookahead_sessions=0,
        evaluation_only=False,
        allowed_for_fit=True,
        allowed_for_predict=True,
        point_in_time_safe=True,
        uses_revised_data=False,
        feature_family="VALUATION",
        provenance_reference="unit-test fixture",
        provenance_sha256=None,
        prefix_invariance_status="UNTESTED",
        future_intervention_status="UNTESTED",
        same_row_target_leakage_status="UNTESTED",
        pit_availability_status="UNTESTED",
        publication_date_status="NOT_APPLICABLE",
        restatement_availability_status="NOT_APPLICABLE",
        audit_notes="Synthetic unit-test metadata; audit assertions are tested separately.",
    )


@pytest.fixture
def canonical_150() -> pd.DataFrame:
    rows = 4
    data: dict[str, object] = {
        "date": pd.date_range("2015-01-02", periods=rows, freq="B"),
        "observed_pe": [10.0, 11.0, 12.0, 13.0],
    }
    for index in range(148):
        data[f"input_{index:03d}"] = np.arange(rows, dtype=float) + index
    return pd.DataFrame(data)


@pytest.fixture
def prediction_frame() -> pd.DataFrame:
    dates = pd.date_range("2015-01-02", periods=4, freq="B")
    rows: list[dict[str, object]] = []
    truth = [10.0, 10.0, 20.0, 20.0]
    for model_id, prediction in {
        "model_a": [10.0, 20.0, 20.0, 10.0],
        "model_b": [20.0, 10.0, 10.0, 20.0],
    }.items():
        for position, date in enumerate(dates):
            rows.append(
                {
                    "seed": 1 if position < 2 else 2,
                    "date": date,
                    "fold_id": "fold_000",
                    "model_id": model_id,
                    "prediction": prediction[position],
                    "true_fair_pe": truth[position],
                }
            )
    return pd.DataFrame(rows)
