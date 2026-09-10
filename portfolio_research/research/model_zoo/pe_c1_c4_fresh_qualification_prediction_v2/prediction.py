"""Frozen PE-C1--C4 formulas with no truth, score, fit selection, or routing."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

import numpy as np
import pandas as pd

from .contracts import (
    BCE_TASK_SURFACE_COLUMNS,
    C1_ID,
    C2_ID,
    C3_ID,
    C4_ID,
    CHAMPION_ID,
    DGP_IDS,
    DIRECTION_EPSILON,
    EXPECTED_MODEL_IDENTITY_ROWS,
    EXPECTED_TASKS,
    FIXED_DIRECTIONAL_ALPHA,
    FOLD_GEOMETRY,
    FORBIDDEN_TOKENS,
    GLOBAL_HOFS_LOG_SHRINK,
    HOFS_TASK_SURFACE_COLUMNS,
    IDENTITY_COLUMNS,
    MERGED_TASK_SURFACE_COLUMNS,
    MODEL_IDS,
    MODEL_ORDINALS,
    OBSERVABLE_STATE_CONFIDENCE_COLUMNS,
    PREDICTION_COLUMNS,
    ROLLING_DISPERSION_MIN_PERIODS,
    ROLLING_DISPERSION_WINDOW,
    SEED_ALIASES,
    SOURCE_MODEL_VERSION,
    SPECIALIST_TAGS,
    PredictionContractError,
)

_FINAL_SOURCE_VERSION = re.compile(r"^sha256:[0-9a-f]{64}$")


def _exact_columns(frame: pd.DataFrame, expected: Sequence[str], *, label: str) -> None:
    if not isinstance(frame, pd.DataFrame) or frame.empty or frame.columns.has_duplicates:
        raise PredictionContractError(f"{label} is not a nonempty unique-column frame")
    actual = tuple(map(str, frame.columns))
    if actual != tuple(expected):
        raise PredictionContractError(f"{label} schema or column order differs")


def _reject_forbidden_columns(frame: pd.DataFrame, *, label: str) -> None:
    if not isinstance(frame, pd.DataFrame) or frame.empty or frame.columns.has_duplicates:
        raise PredictionContractError(f"{label} is not a nonempty unique-column frame")
    for column in map(str, frame.columns):
        lowered = column.lower()
        if any(token in lowered for token in FORBIDDEN_TOKENS):
            raise PredictionContractError(f"{label} contains a forbidden column")


def _final_source_versions(value: Mapping[str, str]) -> dict[str, str]:
    if type(value) is not dict or tuple(value) != MODEL_IDS:
        raise PredictionContractError("final source-model-version universe/order differs")
    output: dict[str, str] = {}
    for model_id in MODEL_IDS:
        version = value[model_id]
        if type(version) is not str or _FINAL_SOURCE_VERSION.fullmatch(version) is None:
            raise PredictionContractError("source model version is not a final SHA-256 binding")
        output[model_id] = version
    return output


def _finite_vector(values: Sequence[object], *, label: str) -> np.ndarray:
    vector = pd.to_numeric(pd.Series(values), errors="coerce").to_numpy(dtype=np.float64)
    if vector.ndim != 1 or not len(vector) or not np.isfinite(vector).all():
        raise PredictionContractError(f"{label} is not finite")
    return vector


def _positive_vector(values: Sequence[object], *, label: str) -> np.ndarray:
    vector = _finite_vector(values, label=label)
    if np.any(vector <= 0.0):
        raise PredictionContractError(f"{label} is not positive")
    return vector


def _valid_unit_component(values: Sequence[object]) -> tuple[np.ndarray, np.ndarray]:
    vector = pd.to_numeric(pd.Series(values), errors="coerce").to_numpy(dtype=np.float64)
    valid = np.isfinite(vector) & (vector >= 0.0) & (vector <= 1.0)
    return vector, valid


def compute_observable_state_confidence(frame: pd.DataFrame) -> np.ndarray:
    """Return the exact four-component geometric mean, invalid rows exactly zero."""

    _exact_columns(
        frame,
        OBSERVABLE_STATE_CONFIDENCE_COLUMNS,
        label="observable-state confidence input",
    )

    eps, eps_valid = _valid_unit_component(frame["ofs_v1_eps_confidence_01"])
    entropy, entropy_valid = _valid_unit_component(frame["ofs_v1_regime_entropy"])
    regime, regime_valid = _valid_unit_component(frame["ofs_v1_regime_confidence"])
    staleness = pd.to_numeric(
        frame["ofs_v1_eps_staleness_log1p"], errors="coerce"
    ).to_numpy(dtype=np.float64)
    innovation = pd.to_numeric(
        frame["ofs_v1_state_abs_innovation_lag1"], errors="coerce"
    ).to_numpy(dtype=np.float64)
    staleness_valid = np.isfinite(staleness) & (staleness >= 0.0)
    innovation_valid = np.isfinite(innovation) & (innovation >= 0.0)
    valid = (
        eps_valid
        & entropy_valid
        & regime_valid
        & staleness_valid
        & innovation_valid
    )
    confidence = np.zeros(len(frame), dtype=np.float64)
    if valid.any():
        staleness_reliability = 1.0 - np.clip(
            staleness[valid] / np.log1p(252.0), 0.0, 1.0
        )
        regime_clarity = 0.5 * (
            (1.0 - entropy[valid])
            + np.clip(
                (regime[valid] - (1.0 / 3.0)) / (2.0 / 3.0),
                0.0,
                1.0,
            )
        )
        innovation_stability = np.exp(-innovation[valid])
        product = (
            eps[valid]
            * staleness_reliability
            * regime_clarity
            * innovation_stability
        )
        confidence[valid] = np.power(np.clip(product, 0.0, 1.0), 0.25)
    return confidence


def _validate_identity(frame: pd.DataFrame) -> None:
    if len(frame) != FOLD_GEOMETRY.prediction_rows_per_task:
        raise PredictionContractError("task must contain exactly 1,296 prediction identities")
    if frame[list(IDENTITY_COLUMNS)].duplicated().any():
        raise PredictionContractError("task identity is duplicated")
    if (
        frame["seed_alias"].nunique(dropna=False) != 1
        or frame["seed_alias"].iloc[0] not in SEED_ALIASES
    ):
        raise PredictionContractError("task seed alias escaped the frozen universe")
    if (
        frame["dgp_id"].nunique(dropna=False) != 1
        or frame["dgp_id"].iloc[0] not in DGP_IDS
    ):
        raise PredictionContractError("task DGP identity escaped the frozen universe")
    if frame["symbol"].nunique(dropna=False) != 1:
        raise PredictionContractError("task has multiple symbols")
    for column in ("session_position", "train_end_position", "test_start_position"):
        if not pd.api.types.is_integer_dtype(frame[column].dtype):
            raise PredictionContractError(f"{column} is not an exact integer column")
    positions = frame["session_position"].to_numpy(dtype=np.int64)
    expected_positions = np.arange(
        FOLD_GEOMETRY.first_prediction_position,
        FOLD_GEOMETRY.final_prediction_position + 1,
        dtype=np.int64,
    )
    if not np.array_equal(positions, expected_positions):
        raise PredictionContractError("task positions have a gap or reorder")
    dates = pd.to_datetime(frame["date"], errors="coerce")
    if dates.isna().any() or dates.duplicated().any() or not dates.is_monotonic_increasing:
        raise PredictionContractError("task dates are invalid or reordered")
    sizes = np.asarray(
        [FOLD_GEOMETRY.test_end_exclusive(start) - start for start in FOLD_GEOMETRY.test_starts]
    )
    starts = np.repeat(FOLD_GEOMETRY.test_starts, sizes).astype(np.int64)
    folds = np.repeat([FOLD_GEOMETRY.fold_id(start) for start in FOLD_GEOMETRY.test_starts], sizes)
    if not np.array_equal(frame["test_start_position"].to_numpy(dtype=np.int64), starts):
        raise PredictionContractError("test-start geometry differs")
    if not np.array_equal(frame["train_end_position"].to_numpy(dtype=np.int64), starts - 1):
        raise PredictionContractError("train-end geometry differs")
    if not np.array_equal(frame["fold_id"].astype(str).to_numpy(), folds):
        raise PredictionContractError("fold identities differ")


def merge_bound_task_surfaces(bce: pd.DataFrame, hofs: pd.DataFrame) -> pd.DataFrame:
    """Join two separately frozen services without sorting or accepting partial identity."""

    _exact_columns(bce, BCE_TASK_SURFACE_COLUMNS, label="BCE surface")
    _exact_columns(hofs, HOFS_TASK_SURFACE_COLUMNS, label="H-OFS surface")
    _validate_identity(bce)
    _validate_identity(hofs)
    left = bce.loc[:, list(IDENTITY_COLUMNS)].reset_index(drop=True)
    right = hofs.loc[:, list(IDENTITY_COLUMNS)].reset_index(drop=True)
    if not left.equals(right):
        raise PredictionContractError("BCE and H-OFS identities differ")
    merged = pd.concat(
        [bce.reset_index(drop=True), hofs.loc[:, list(HOFS_TASK_SURFACE_COLUMNS[len(IDENTITY_COLUMNS) :])].reset_index(drop=True)],
        axis=1,
    )
    _exact_columns(merged, MERGED_TASK_SURFACE_COLUMNS, label="merged surface")
    return merged


def _candidate_vectors(frame: pd.DataFrame) -> dict[str, dict[str, np.ndarray]]:
    champion = _positive_vector(frame["v04_expected_pe"], label="v04 expected P/E")
    lgbm = _positive_vector(frame["lgbm_full_state_expected_pe"], label="LGBM expected P/E")
    histgb = _positive_vector(frame["histgb_full_state_expected_pe"], label="HistGB expected P/E")
    log_champion = np.log(champion)
    correction_a = np.log(lgbm) - log_champion
    correction_b = np.log(histgb) - log_champion
    agreement = ((correction_a > DIRECTION_EPSILON) & (correction_b > DIRECTION_EPSILON)) | (
        (correction_a < -DIRECTION_EPSILON) & (correction_b < -DIRECTION_EPSILON)
    )
    raw = np.where(agreement, 0.5 * (correction_a + correction_b), 0.0)
    prior_variance = (
        pd.Series(0.5 * (correction_a**2 + correction_b**2), dtype="float64")
        .shift(1)
        .rolling(ROLLING_DISPERSION_WINDOW, min_periods=ROLLING_DISPERSION_MIN_PERIODS)
        .mean()
        .to_numpy(dtype=np.float64)
    )
    budget = np.sqrt(prior_variance)
    alpha_c1 = np.zeros(len(frame), dtype=np.float64)
    eligible = agreement & np.isfinite(budget) & (np.abs(raw) > DIRECTION_EPSILON)
    alpha_c1[eligible] = np.minimum(1.0, budget[eligible] / np.abs(raw[eligible]))
    state_confidence = compute_observable_state_confidence(
        frame.loc[:, list(OBSERVABLE_STATE_CONFIDENCE_COLUMNS)]
    )
    alpha_c2 = np.where(agreement, state_confidence, 0.0)
    alpha_c3 = np.where(agreement, FIXED_DIRECTIONAL_ALPHA, 0.0)
    disagreement = np.abs(correction_a - correction_b) / 2.0

    result: dict[str, dict[str, np.ndarray]] = {}
    for model_id, alpha in ((C1_ID, alpha_c1), (C2_ID, alpha_c2), (C3_ID, alpha_c3)):
        applied = np.where(agreement, alpha * raw, 0.0)
        expected_log = log_champion + applied
        expected = np.exp(expected_log)
        expected[applied == 0.0] = champion[applied == 0.0]
        result[model_id] = {
            "expected_pe": expected,
            "expected_log_pe": np.log(expected),
            "confidence": alpha,
            "uncertainty": disagreement,
            "model_disagreement": disagreement,
            "state_uncertainty": np.full(len(frame), np.nan),
            "valuation_state_confidence": np.full(len(frame), np.nan),
            "applied_alpha": alpha,
            "raw_log_correction": raw,
        }

    raw_hofs_log = _finite_vector(
        frame["hofs_r2_expected_log_pe"], label="H-OFS r2 expected log P/E"
    )
    tail_guard, tail_valid = _valid_unit_component(frame["hofs_v7_tail_guard_weight"])
    log_scale = _finite_vector(frame["hofs_v7_log_scale"], label="H-OFS log scale")
    if not tail_valid.all():
        raise PredictionContractError("H-OFS tail guard escaped [0,1]")
    hofs_log = log_champion + GLOBAL_HOFS_LOG_SHRINK * (raw_hofs_log - log_champion)
    hofs_expected = np.exp(hofs_log)
    if not np.isfinite(hofs_expected).all() or np.any(hofs_expected <= 0.0):
        raise PredictionContractError("H-OFS expected P/E is invalid")
    with np.errstate(over="ignore", invalid="ignore"):
        scale = np.exp(log_scale)
    if not np.isfinite(scale).all() or np.any(scale <= 0.0):
        raise PredictionContractError("H-OFS state uncertainty is invalid")
    result[C4_ID] = {
        "expected_pe": hofs_expected,
        "expected_log_pe": hofs_log,
        "confidence": tail_guard,
        "uncertainty": scale,
        "model_disagreement": np.full(len(frame), np.nan),
        "state_uncertainty": scale,
        "valuation_state_confidence": tail_guard,
        "applied_alpha": np.full(len(frame), GLOBAL_HOFS_LOG_SHRINK),
        "raw_log_correction": raw_hofs_log - log_champion,
    }
    return result


def _build_task_prediction_rows(
    frame: pd.DataFrame,
    *,
    source_model_versions: Mapping[str, str],
    prediction_ready: bool,
) -> pd.DataFrame:
    """Build one task after the caller has selected final or research metadata."""

    _exact_columns(frame, MERGED_TASK_SURFACE_COLUMNS, label="merged surface")
    _validate_identity(frame)
    values = _candidate_vectors(frame)
    champion = _positive_vector(frame["v04_expected_pe"], label="v04 expected P/E")
    values[CHAMPION_ID] = {
        "expected_pe": champion,
        "expected_log_pe": np.log(champion),
        "confidence": np.full(len(frame), np.nan),
        "uncertainty": np.full(len(frame), np.nan),
        "model_disagreement": np.full(len(frame), np.nan),
        "state_uncertainty": np.full(len(frame), np.nan),
        "valuation_state_confidence": np.full(len(frame), np.nan),
        "applied_alpha": np.zeros(len(frame)),
        "raw_log_correction": np.zeros(len(frame)),
    }
    row_indexes = np.repeat(np.arange(len(frame), dtype=np.int64), len(MODEL_IDS))
    model_ids = np.tile(np.asarray(MODEL_IDS, dtype=object), len(frame))
    output = frame.loc[row_indexes, list(IDENTITY_COLUMNS)].reset_index(drop=True)
    output["pe_model_id"] = model_ids
    output["model_ordinal"] = np.tile(np.arange(len(MODEL_IDS), dtype=np.int64), len(frame))
    for field in (
        "expected_pe",
        "expected_log_pe",
        "uncertainty",
        "confidence",
        "valuation_state_confidence",
        "model_disagreement",
        "state_uncertainty",
        "applied_alpha",
        "raw_log_correction",
    ):
        output[field] = np.column_stack([values[model_id][field] for model_id in MODEL_IDS]).reshape(-1)
    output["regime_state"] = "NON_ROUTING_ALL_REGIMES"
    output["specialist_tags"] = [SPECIALIST_TAGS[model_id] for model_id in model_ids]
    output["prediction_valid"] = prediction_ready
    output["pit_valid"] = prediction_ready
    output["source_model_version"] = [
        source_model_versions[model_id] for model_id in model_ids
    ]
    output["out_of_distribution_score"] = np.nan
    output = output.loc[:, list(PREDICTION_COLUMNS)]
    _validate_task_prediction_rows(
        output,
        source_surface=frame,
        source_model_versions=source_model_versions,
        prediction_ready=prediction_ready,
    )
    return output


def build_task_prediction_rows(
    frame: pd.DataFrame,
    *,
    source_model_versions: Mapping[str, str],
) -> pd.DataFrame:
    """Build one formally bound task; placeholder versions are forbidden."""

    versions = _final_source_versions(source_model_versions)
    return _build_task_prediction_rows(
        frame,
        source_model_versions=versions,
        prediction_ready=True,
    )


def build_research_task_formula_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Build formula-only research rows that explicitly remain invalid for prediction."""

    return _build_task_prediction_rows(
        frame,
        source_model_versions=SOURCE_MODEL_VERSION,
        prediction_ready=False,
    )


def _validate_task_prediction_rows(
    frame: pd.DataFrame,
    *,
    source_surface: pd.DataFrame,
    source_model_versions: Mapping[str, str],
    prediction_ready: bool,
) -> None:
    if source_surface is None:
        raise PredictionContractError("source surface is mandatory")
    _exact_columns(frame, PREDICTION_COLUMNS, label="prediction rows")
    expected_rows = FOLD_GEOMETRY.prediction_rows_per_task * len(MODEL_IDS)
    if len(frame) != expected_rows:
        raise PredictionContractError("prediction row count differs")
    expected_models = np.tile(np.asarray(MODEL_IDS, dtype=object), FOLD_GEOMETRY.prediction_rows_per_task)
    if not np.array_equal(frame["pe_model_id"].to_numpy(dtype=object), expected_models):
        raise PredictionContractError("model order differs")
    expected_ordinals = np.tile(
        np.asarray([MODEL_ORDINALS[model_id] for model_id in MODEL_IDS], dtype=np.int64),
        FOLD_GEOMETRY.prediction_rows_per_task,
    )
    if (
        not pd.api.types.is_integer_dtype(frame["model_ordinal"].dtype)
        or not np.array_equal(
            frame["model_ordinal"].to_numpy(dtype=np.int64), expected_ordinals
        )
    ):
        raise PredictionContractError("model ordinal differs")
    expected_positions = np.repeat(
        np.arange(FOLD_GEOMETRY.first_prediction_position, FOLD_GEOMETRY.final_prediction_position + 1),
        len(MODEL_IDS),
    )
    if not np.array_equal(frame["session_position"].to_numpy(dtype=np.int64), expected_positions):
        raise PredictionContractError("prediction identity order differs")
    if frame.duplicated([*IDENTITY_COLUMNS, "pe_model_id"]).any():
        raise PredictionContractError("prediction identity/model row is duplicated")
    expected_pe = frame["expected_pe"].to_numpy(dtype=np.float64)
    expected_log = frame["expected_log_pe"].to_numpy(dtype=np.float64)
    if (
        not np.isfinite(expected_pe).all()
        or np.any(expected_pe <= 0.0)
        or not np.isfinite(expected_log).all()
        or not np.allclose(expected_log, np.log(expected_pe), rtol=0.0, atol=1e-14)
    ):
        raise PredictionContractError("expected P/E and log P/E differ")
    if (
        not frame["prediction_valid"].eq(prediction_ready).all()
        or not frame["pit_valid"].eq(prediction_ready).all()
    ):
        raise PredictionContractError("prediction/PIT validity differs")
    expected_versions = np.tile(
        np.asarray([source_model_versions[model_id] for model_id in MODEL_IDS], dtype=object),
        FOLD_GEOMETRY.prediction_rows_per_task,
    )
    expected_tags = np.tile(
        np.asarray([SPECIALIST_TAGS[model_id] for model_id in MODEL_IDS], dtype=object),
        FOLD_GEOMETRY.prediction_rows_per_task,
    )
    if (
        not np.array_equal(
            frame["source_model_version"].to_numpy(dtype=object), expected_versions
        )
        or not np.array_equal(
            frame["specialist_tags"].to_numpy(dtype=object), expected_tags
        )
        or not frame["regime_state"].eq("NON_ROUTING_ALL_REGIMES").all()
    ):
        raise PredictionContractError("prediction metadata identity differs")
    alpha = frame["applied_alpha"].to_numpy(dtype=np.float64)
    raw_correction = frame["raw_log_correction"].to_numpy(dtype=np.float64)
    if (
        not np.isfinite(alpha).all()
        or np.any((alpha < 0.0) | (alpha > 1.0))
        or not np.isfinite(raw_correction).all()
    ):
        raise PredictionContractError("prediction correction metadata is invalid")
    champion_rows = frame["pe_model_id"].eq(CHAMPION_ID).to_numpy()
    c1_c3_rows = frame["pe_model_id"].isin((C1_ID, C2_ID, C3_ID)).to_numpy()
    c4_rows = frame["pe_model_id"].eq(C4_ID).to_numpy()
    confidence = frame["confidence"].to_numpy(dtype=np.float64)
    uncertainty = frame["uncertainty"].to_numpy(dtype=np.float64)
    if (
        not np.isnan(confidence[champion_rows]).all()
        or not np.isfinite(confidence[~champion_rows]).all()
        or np.any((confidence[~champion_rows] < 0.0) | (confidence[~champion_rows] > 1.0))
        or not np.array_equal(confidence[c1_c3_rows], alpha[c1_c3_rows])
        or not np.isfinite(uncertainty[~champion_rows]).all()
        or np.any(uncertainty[c1_c3_rows] < 0.0)
        or np.any(uncertainty[c4_rows] <= 0.0)
        or not np.isnan(uncertainty[champion_rows]).all()
    ):
        raise PredictionContractError("prediction confidence/uncertainty metadata is invalid")
    if (
        not np.isnan(frame["out_of_distribution_score"].to_numpy(dtype=np.float64)).all()
        or not np.isnan(
            frame.loc[~c4_rows, "state_uncertainty"].to_numpy(dtype=np.float64)
        ).all()
        or not np.isfinite(
            frame.loc[c4_rows, "state_uncertainty"].to_numpy(dtype=np.float64)
        ).all()
        or np.any(
            frame.loc[c4_rows, "state_uncertainty"].to_numpy(dtype=np.float64)
            <= 0.0
        )
        or not np.isnan(
            frame.loc[~c4_rows, "valuation_state_confidence"].to_numpy(dtype=np.float64)
        ).all()
        or not np.isfinite(
            frame.loc[c4_rows, "valuation_state_confidence"].to_numpy(dtype=np.float64)
        ).all()
        or not np.isnan(
            frame.loc[~c1_c3_rows, "model_disagreement"].to_numpy(dtype=np.float64)
        ).all()
        or not np.isfinite(
            frame.loc[c1_c3_rows, "model_disagreement"].to_numpy(dtype=np.float64)
        ).all()
    ):
        raise PredictionContractError("optional prediction metadata is invalid")
    if source_surface is not None:
        _exact_columns(
            source_surface,
            MERGED_TASK_SURFACE_COLUMNS,
            label="source surface",
        )
        _validate_identity(source_surface)
        source_row_indexes = np.repeat(
            np.arange(len(source_surface), dtype=np.int64), len(MODEL_IDS)
        )
        expected_identity = source_surface.loc[
            source_row_indexes, list(IDENTITY_COLUMNS)
        ].reset_index(drop=True)
        if not frame.loc[:, list(IDENTITY_COLUMNS)].reset_index(drop=True).equals(
            expected_identity
        ):
            raise PredictionContractError("prediction identity differs from source surface")

        expected_values = _candidate_vectors(source_surface)
        champion = _positive_vector(
            source_surface["v04_expected_pe"], label="source v04 expected P/E"
        )
        expected_values[CHAMPION_ID] = {
            "expected_pe": champion,
            "expected_log_pe": np.log(champion),
            "confidence": np.full(len(source_surface), np.nan),
            "uncertainty": np.full(len(source_surface), np.nan),
            "model_disagreement": np.full(len(source_surface), np.nan),
            "state_uncertainty": np.full(len(source_surface), np.nan),
            "valuation_state_confidence": np.full(len(source_surface), np.nan),
            "applied_alpha": np.zeros(len(source_surface)),
            "raw_log_correction": np.zeros(len(source_surface)),
        }
        for field in (
            "expected_pe",
            "expected_log_pe",
            "uncertainty",
            "confidence",
            "valuation_state_confidence",
            "model_disagreement",
            "state_uncertainty",
            "applied_alpha",
            "raw_log_correction",
        ):
            expected = np.column_stack(
                [expected_values[model_id][field] for model_id in MODEL_IDS]
            ).reshape(-1)
            actual = frame[field].to_numpy(dtype=np.float64)
            if not np.array_equal(actual, expected, equal_nan=True):
                raise PredictionContractError(
                    f"{field} differs from the frozen source formula"
                )


def validate_task_prediction_rows(
    frame: pd.DataFrame,
    *,
    source_surface: pd.DataFrame,
    source_model_versions: Mapping[str, str],
) -> None:
    """Recompute one formally bound task from its mandatory source surface."""

    versions = _final_source_versions(source_model_versions)
    _validate_task_prediction_rows(
        frame,
        source_surface=source_surface,
        source_model_versions=versions,
        prediction_ready=True,
    )


def _qualification_surfaces(
    source_surfaces: Sequence[pd.DataFrame],
) -> tuple[pd.DataFrame, ...]:
    if type(source_surfaces) not in (list, tuple) or len(source_surfaces) != EXPECTED_TASKS:
        raise PredictionContractError("qualification source task count differs")
    frozen = tuple(source_surfaces)
    for task_index, surface in enumerate(frozen):
        _exact_columns(surface, MERGED_TASK_SURFACE_COLUMNS, label="qualification source surface")
        _validate_identity(surface)
        expected_alias = SEED_ALIASES[task_index // len(DGP_IDS)]
        expected_dgp = DGP_IDS[task_index % len(DGP_IDS)]
        if (
            surface["seed_alias"].iloc[0] != expected_alias
            or surface["dgp_id"].iloc[0] != expected_dgp
        ):
            raise PredictionContractError("qualification task order differs")
    return frozen


def build_qualification_prediction_rows(
    source_surfaces: Sequence[pd.DataFrame],
    *,
    source_model_versions: Mapping[str, str],
) -> pd.DataFrame:
    """Build the exact 50-task, 324,000-row qualification artifact in fixed order."""

    frozen = _qualification_surfaces(source_surfaces)
    versions = _final_source_versions(source_model_versions)
    output = pd.concat(
        [
            _build_task_prediction_rows(
                surface,
                source_model_versions=versions,
                prediction_ready=True,
            )
            for surface in frozen
        ],
        axis=0,
        ignore_index=True,
    )
    validate_qualification_prediction_rows(
        output,
        source_surfaces=frozen,
        source_model_versions=versions,
    )
    return output


def validate_qualification_prediction_rows(
    frame: pd.DataFrame,
    *,
    source_surfaces: Sequence[pd.DataFrame],
    source_model_versions: Mapping[str, str],
) -> None:
    """Fail closed unless all 50 bound tasks and formulas are present exactly once."""

    _exact_columns(frame, PREDICTION_COLUMNS, label="qualification prediction rows")
    if len(frame) != EXPECTED_MODEL_IDENTITY_ROWS:
        raise PredictionContractError("qualification prediction row count differs")
    frozen = _qualification_surfaces(source_surfaces)
    versions = _final_source_versions(source_model_versions)
    rows_per_task = FOLD_GEOMETRY.prediction_rows_per_task * len(MODEL_IDS)
    for task_index, surface in enumerate(frozen):
        start = task_index * rows_per_task
        stop = start + rows_per_task
        _validate_task_prediction_rows(
            frame.iloc[start:stop].reset_index(drop=True),
            source_surface=surface,
            source_model_versions=versions,
            prediction_ready=True,
        )
    if frame.duplicated([*IDENTITY_COLUMNS, "pe_model_id"]).any():
        raise PredictionContractError("qualification identity/model row is duplicated")
