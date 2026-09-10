from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    BCE_TASK_SURFACE_COLUMNS,
    C1_ID,
    C2_ID,
    C3_ID,
    C4_ID,
    CHAMPION_ID,
    FOLD_GEOMETRY,
    HOFS_TASK_SURFACE_COLUMNS,
    MODEL_IDS,
    PredictionContractError,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.prediction import (
    build_qualification_prediction_rows,
    build_research_task_formula_rows,
    build_task_prediction_rows,
    compute_observable_state_confidence,
    merge_bound_task_surfaces,
    validate_qualification_prediction_rows,
    validate_task_prediction_rows,
)

FINAL_SOURCE_VERSIONS = {
    model_id: f"sha256:{hashlib.sha256(model_id.encode('utf-8')).hexdigest()}"
    for model_id in MODEL_IDS
}


def _build_rows(frame: pd.DataFrame) -> pd.DataFrame:
    return build_task_prediction_rows(
        frame,
        source_model_versions=FINAL_SOURCE_VERSIONS,
    )


def _surfaces() -> tuple[pd.DataFrame, pd.DataFrame]:
    positions = np.arange(504, 1800, dtype=np.int64)
    sizes = np.asarray(
        [FOLD_GEOMETRY.test_end_exclusive(start) - start for start in FOLD_GEOMETRY.test_starts]
    )
    starts = np.repeat(FOLD_GEOMETRY.test_starts, sizes)
    identity = {
        "seed_alias": "qualification_seed_01",
        "dgp_id": "A",
        "session_position": positions,
        "date": pd.date_range("2026-01-01", periods=len(positions), freq="D").strftime("%Y-%m-%d"),
        "symbol": "SYNTHETIC_ISSUER",
        "fold_id": np.repeat([FOLD_GEOMETRY.fold_id(start) for start in FOLD_GEOMETRY.test_starts], sizes),
        "train_end_position": starts - 1,
        "test_start_position": starts,
    }
    champion = 10.0 + positions / 100_000.0
    bce = pd.DataFrame(
        {
            **identity,
            "v04_expected_pe": champion,
            "lgbm_full_state_expected_pe": champion * np.exp(0.04 + 0.005 * np.sin(positions / 13.0)),
            "histgb_full_state_expected_pe": champion * np.exp(0.05 + 0.005 * np.cos(positions / 17.0)),
            "ofs_v1_eps_confidence_01": np.linspace(0.2, 0.9, len(positions)),
            "ofs_v1_eps_staleness_log1p": np.linspace(0.0, np.log1p(252.0), len(positions)),
            "ofs_v1_regime_entropy": np.linspace(0.8, 0.1, len(positions)),
            "ofs_v1_regime_confidence": np.linspace(1.0 / 3.0, 0.95, len(positions)),
            "ofs_v1_state_abs_innovation_lag1": np.linspace(0.0, 2.0, len(positions)),
        }
    ).loc[:, list(BCE_TASK_SURFACE_COLUMNS)]
    hofs = pd.DataFrame(
        {
            **identity,
            "hofs_r2_expected_log_pe": np.log(champion) + 0.08,
            "hofs_v7_tail_guard_weight": np.linspace(0.3, 0.8, len(positions)),
            "hofs_v7_log_scale": np.log(np.linspace(0.1, 0.4, len(positions))),
        }
    ).loc[:, list(HOFS_TASK_SURFACE_COLUMNS)]
    return bce, hofs


def test_exact_formulas_and_fixed_model_order() -> None:
    bce, hofs = _surfaces()
    merged = merge_bound_task_surfaces(bce, hofs)
    rows = _build_rows(merged)
    assert len(rows) == 1296 * 5
    assert rows["pe_model_id"].tolist()[:10] == [*MODEL_IDS, *MODEL_IDS]
    for model_id in MODEL_IDS:
        assert len(rows.loc[rows["pe_model_id"].eq(model_id)]) == 1296
    champion = rows.loc[rows["pe_model_id"].eq(CHAMPION_ID), "expected_pe"].to_numpy()
    assert np.array_equal(champion, bce["v04_expected_pe"].to_numpy())
    c3 = rows.loc[rows["pe_model_id"].eq(C3_ID)]
    assert np.allclose(c3["applied_alpha"].to_numpy(), 0.40, rtol=0.0, atol=0.0)
    c4 = rows.loc[rows["pe_model_id"].eq(C4_ID)]
    expected_c4_log = np.log(champion) + 0.5 * 0.08
    assert np.allclose(c4["expected_log_pe"].to_numpy(), expected_c4_log, rtol=0.0, atol=1e-14)
    assert {C1_ID, C2_ID, C3_ID, C4_ID}.issubset(set(rows["pe_model_id"]))


def test_c1_is_strictly_past_only_and_first_ten_rows_are_base() -> None:
    bce, hofs = _surfaces()
    base = _build_rows(merge_bound_task_surfaces(bce, hofs))
    changed = bce.copy(deep=True)
    changed.loc[700:, "lgbm_full_state_expected_pe"] *= 100.0
    changed.loc[700:, "histgb_full_state_expected_pe"] *= 100.0
    attacked = _build_rows(merge_bound_task_surfaces(changed, hofs))
    before = 700 * len(MODEL_IDS)
    pd.testing.assert_frame_equal(base.iloc[:before], attacked.iloc[:before], check_exact=True)
    c1 = base.loc[base["pe_model_id"].eq(C1_ID)]
    assert np.array_equal(c1["expected_pe"].to_numpy()[:10], bce["v04_expected_pe"].to_numpy()[:10])


def test_invalid_state_component_maps_c2_confidence_to_exact_zero() -> None:
    bce, _ = _surfaces()
    bce.loc[0, "ofs_v1_eps_confidence_01"] = np.nan
    bce.loc[1, "ofs_v1_regime_entropy"] = 2.0
    bce.loc[2, "ofs_v1_state_abs_innovation_lag1"] = -1e308
    with np.errstate(over="raise", invalid="raise"):
        confidence = compute_observable_state_confidence(
            bce.loc[:, list(BCE_TASK_SURFACE_COLUMNS[-5:])]
        )
    assert np.array_equal(confidence[:3], np.zeros(3))
    assert np.isfinite(confidence).all()
    assert ((confidence >= 0.0) & (confidence <= 1.0)).all()


def test_cross_service_identity_or_schema_drift_fails_closed() -> None:
    bce, hofs = _surfaces()
    attacked = hofs.copy(deep=True)
    attacked.loc[0, "date"] = "2099-01-01"
    with pytest.raises(PredictionContractError, match="identities differ|dates"):
        merge_bound_task_surfaces(bce, attacked)
    injected = bce.copy(deep=True)
    injected["true_fair_pe"] = 10.0
    with pytest.raises(PredictionContractError, match="schema"):
        merge_bound_task_surfaces(injected, hofs)


def test_hofs_invalid_tail_guard_or_scale_fails_closed() -> None:
    bce, hofs = _surfaces()
    attacked = hofs.copy(deep=True)
    attacked.loc[0, "hofs_v7_tail_guard_weight"] = 1.01
    with pytest.raises(PredictionContractError, match="tail guard"):
        _build_rows(merge_bound_task_surfaces(bce, attacked))
    attacked = hofs.copy(deep=True)
    attacked.loc[0, "hofs_v7_log_scale"] = 1_000.0
    with pytest.raises(PredictionContractError, match="uncertainty"):
        _build_rows(merge_bound_task_surfaces(bce, attacked))


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("seed_alias", "qualification_seed_99", "seed alias"),
        ("dgp_id", "K", "DGP identity"),
        ("session_position", 504.5, "exact integer"),
    ],
)
def test_identity_universe_and_integer_types_fail_closed(
    column: str, value: object, message: str
) -> None:
    bce, hofs = _surfaces()
    bce[column] = value if column != "session_position" else bce[column].astype(float)
    hofs[column] = value if column != "session_position" else hofs[column].astype(float)
    if column == "session_position":
        bce.loc[0, column] = value
        hofs.loc[0, column] = value
    with pytest.raises(PredictionContractError, match=message):
        merge_bound_task_surfaces(bce, hofs)


def test_output_metadata_tampering_fails_closed() -> None:
    bce, hofs = _surfaces()
    merged = merge_bound_task_surfaces(bce, hofs)
    rows = _build_rows(merged)
    attacked = rows.copy(deep=True)
    attacked.loc[attacked["pe_model_id"].eq(C2_ID), "source_model_version"] = "drifted"
    with pytest.raises(PredictionContractError, match="metadata identity"):
        validate_task_prediction_rows(
            attacked,
            source_surface=merged,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )
    attacked = rows.copy(deep=True)
    attacked.loc[attacked["pe_model_id"].eq(C4_ID), "state_uncertainty"] = 0.0
    with pytest.raises(PredictionContractError, match="optional prediction metadata"):
        validate_task_prediction_rows(
            attacked,
            source_surface=merged,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )


def test_coordinated_numeric_tampering_is_recomputed_against_source() -> None:
    bce, hofs = _surfaces()
    merged = merge_bound_task_surfaces(bce, hofs)
    rows = _build_rows(merged)
    attacked = rows.copy(deep=True)
    target = attacked["pe_model_id"].eq(C2_ID)
    attacked.loc[target, "expected_pe"] *= np.exp(0.01)
    attacked.loc[target, "expected_log_pe"] = np.log(
        attacked.loc[target, "expected_pe"].to_numpy(dtype=np.float64)
    )
    with pytest.raises(PredictionContractError, match="frozen source formula"):
        validate_task_prediction_rows(
            attacked,
            source_surface=merged,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )


def test_coordinated_identity_tampering_is_rejected_against_source() -> None:
    bce, hofs = _surfaces()
    merged = merge_bound_task_surfaces(bce, hofs)
    rows = _build_rows(merged)
    attacked = rows.copy(deep=True)
    attacked["date"] = (
        pd.to_datetime(attacked["date"]) + pd.Timedelta(days=1)
    ).dt.strftime("%Y-%m-%d")
    with pytest.raises(PredictionContractError, match="identity differs"):
        validate_task_prediction_rows(
            attacked,
            source_surface=merged,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )


def test_final_builder_rejects_pending_or_unordered_source_versions() -> None:
    bce, hofs = _surfaces()
    merged = merge_bound_task_surfaces(bce, hofs)
    pending = dict(FINAL_SOURCE_VERSIONS)
    pending[C2_ID] = "binding_pending"
    with pytest.raises(PredictionContractError, match="final SHA-256"):
        build_task_prediction_rows(merged, source_model_versions=pending)
    reordered = {model_id: FINAL_SOURCE_VERSIONS[model_id] for model_id in reversed(MODEL_IDS)}
    with pytest.raises(PredictionContractError, match="universe/order"):
        build_task_prediction_rows(merged, source_model_versions=reordered)


def test_research_formula_rows_are_explicitly_not_prediction_ready() -> None:
    bce, hofs = _surfaces()
    rows = build_research_task_formula_rows(merge_bound_task_surfaces(bce, hofs))
    assert rows["prediction_valid"].eq(False).all()
    assert rows["pit_valid"].eq(False).all()
    assert rows["source_model_version"].str.contains("pending|actual_common").all()
    with pytest.raises(TypeError):
        validate_task_prediction_rows(rows)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "extra_column",
    ("true_target_pe", "truth", "future_realized_pe", "actual_outcome", "y"),
)
def test_exported_confidence_helper_requires_exact_five_column_boundary(
    extra_column: str,
) -> None:
    bce, _ = _surfaces()
    confidence_columns = list(BCE_TASK_SURFACE_COLUMNS[-5:])
    clean = bce.loc[:, confidence_columns].copy()
    attacked = clean.copy()
    attacked[extra_column] = 10.0
    with pytest.raises(PredictionContractError, match="schema or column order"):
        compute_observable_state_confidence(attacked)
    with pytest.raises(PredictionContractError, match="schema or column order"):
        compute_observable_state_confidence(clean.loc[:, list(reversed(confidence_columns))])


def test_exact_50_task_batch_build_and_validation_fail_closed() -> None:
    bce, hofs = _surfaces()
    surfaces = []
    for seed_index in range(1, 6):
        for dgp_id in "ABCDEFGHIJ":
            task_bce = bce.copy()
            task_hofs = hofs.copy()
            alias = f"qualification_seed_{seed_index:02d}"
            task_bce.loc[:, "seed_alias"] = alias
            task_hofs.loc[:, "seed_alias"] = alias
            task_bce.loc[:, "dgp_id"] = dgp_id
            task_hofs.loc[:, "dgp_id"] = dgp_id
            surfaces.append(merge_bound_task_surfaces(task_bce, task_hofs))
    rows = build_qualification_prediction_rows(
        surfaces,
        source_model_versions=FINAL_SOURCE_VERSIONS,
    )
    assert len(rows) == 324_000
    validate_qualification_prediction_rows(
        rows,
        source_surfaces=surfaces,
        source_model_versions=FINAL_SOURCE_VERSIONS,
    )
    repeated = list(surfaces)
    repeated[1] = repeated[0]
    with pytest.raises(PredictionContractError, match="task order"):
        validate_qualification_prediction_rows(
            rows,
            source_surfaces=repeated,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )
    with pytest.raises(PredictionContractError, match="row count"):
        validate_qualification_prediction_rows(
            rows.iloc[:-1],
            source_surfaces=surfaces,
            source_model_versions=FINAL_SOURCE_VERSIONS,
        )
