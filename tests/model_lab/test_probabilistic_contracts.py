from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.probabilistic.binding import (
    feature_sidecar,
    verify_feature_sidecar,
)
from pe_regime_v04.model_lab.probabilistic.contracts import (
    PROBABILISTIC_DESIGN_SHA256,
    ProbabilisticContractError,
    QuantilePredictionBatch,
    VerifiedPredictionBatch,
    verify_probabilistic_design,
)
from pe_regime_v04.model_lab.probabilistic.crossing import (
    crossing_screen_status,
    make_prediction_batch,
    stable_monotone_rearrangement,
)
from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS, FEATURE_COLUMNS


ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "outputs/model_zoo_probabilistic_wave_design_20260819/DESIGN.json"


def test_probabilistic_design_exact_sha_binding() -> None:
    value = verify_probabilistic_design(DESIGN)
    assert value["status"].startswith("DESIGN_ONLY_SCORE_FREE")
    assert PROBABILISTIC_DESIGN_SHA256 == (
        "ae2442c8dfde4c70f45e3efe5a20f80a13ed7c8545a055dd05d57e931e433652"
    )
    assert len(CANDIDATE_IDS) == 3
    assert len(FEATURE_COLUMNS) == 36


def test_quantile_crossing_injection_stable_repair_and_screen() -> None:
    raw = np.array([[2.0, 1.5, 1.0, 2.5, 3.0], [1.0, 1.0, 2.0, 3.0, 4.0]])
    repaired, diagnostics = stable_monotone_rearrangement(raw)
    np.testing.assert_array_equal(repaired[0], [1.0, 1.5, 2.0, 2.5, 3.0])
    assert diagnostics.crossing_rows == 1
    assert diagnostics.post_repair_crossing_rows == 0
    assert crossing_screen_status(diagnostics) == "FAIL_RAW_CROSSING_RATE"
    batch = make_prediction_batch(model_id="synthetic", raw_log_quantiles=raw)
    np.testing.assert_array_equal(batch.pe_quantiles, np.exp(repaired))


def test_stable_crossing_ties_allowed_but_collapse_reported() -> None:
    batch = make_prediction_batch(
        model_id="synthetic", raw_log_quantiles=np.ones((2, 5), dtype=np.float64)
    )
    assert batch.diagnostics.interval_collapse_rows == 2


def test_feature_sidecar_tampering_fails_closed() -> None:
    sidecar = feature_sidecar()
    verify_feature_sidecar(sidecar)
    tampered = json.loads(json.dumps(sidecar))
    tampered["feature_columns"][0] = "evil_future_feature"
    with pytest.raises(ProbabilisticContractError):
        verify_feature_sidecar(tampered)


def test_prediction_contract_rejects_nonfinite_and_direct_construction() -> None:
    raw = np.tile(np.arange(5, dtype=np.float64), (2, 1))
    with pytest.raises(ProbabilisticContractError):
        QuantilePredictionBatch(
            model_id="x",
            raw_log_quantiles=raw,
            repaired_log_quantiles=raw,
            pe_quantiles=np.full((2, 5), np.nan),
            diagnostics=make_prediction_batch(model_id="x", raw_log_quantiles=raw).diagnostics,
        )
    with pytest.raises(ProbabilisticContractError):
        VerifiedPredictionBatch(
            frame=pd.DataFrame(), identity_sha256="0" * 64, prediction_sha256="0" * 64, _token=None
        )
