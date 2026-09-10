"""Normalized row contract and adapters for the common spent research surface."""

from __future__ import annotations

import math
from typing import Final

import numpy as np
import pandas as pd

from .contracts import (
    COMMON_IDENTITIES,
    DGP_IDS,
    MODEL_COLUMNS,
    RESEARCH_EVIDENCE_CLASS,
    SCORE_END,
    SCORE_ROWS_PER_TASK,
    SCORE_START,
    SEED_ALIASES,
    SEED_ALIAS_TO_VALUE,
    TASK_COUNT,
    ResearchTournamentContractError,
    fold_id_for_position,
)


NORMALIZED_PREDICTION_COLUMNS: Final = (
    "seed_alias",
    "dgp_id",
    "session_position",
    "date",
    "ticker",
    "fold_id",
    "pe_model_id",
    "expected_pe",
    "expected_log_pe",
    "uncertainty",
    "confidence",
    "regime_state",
    "specialist_tags",
    "prediction_valid",
    "pit_valid",
    "source_model_version",
    "evidence_class",
)

HOFS_SOURCE_COLUMNS: Final = (
    "task_ordinal",
    "task_seed",
    "task_dgp",
    "fold_index",
    "source_row_position",
    "entity_id",
    "decision_date",
    "hofs_v7_expected_pe",
    "hofs_v7_pe_p10",
    "hofs_v7_pe_p90",
    "hofs_v7_log_scale",
    "hofs_v7_tail_guard_weight",
    "parameter_sha256",
    "decision_block_ordered_membership_sha256",
    "decision_block_set_membership_sha256",
    "decision_source_positions_sha256",
    "output_manifest_sha256",
    "within_block_parameter_update_count",
)
HOFS_LOG_SCALE_BOUNDS: Final = (math.log(0.01), math.log(0.50))
HOFS_HASH_COLUMNS: Final = (
    "parameter_sha256",
    "decision_block_ordered_membership_sha256",
    "decision_block_set_membership_sha256",
    "decision_source_positions_sha256",
    "output_manifest_sha256",
)


def _expected_arrays() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    seeds = np.repeat(np.asarray(SEED_ALIASES, dtype=object), len(DGP_IDS) * SCORE_ROWS_PER_TASK)
    dgps = np.tile(
        np.repeat(np.asarray(DGP_IDS, dtype=object), SCORE_ROWS_PER_TASK),
        len(SEED_ALIASES),
    )
    positions = np.tile(np.arange(SCORE_START, SCORE_END, dtype=np.int64), TASK_COUNT)
    return seeds, dgps, positions


def validate_normalized_predictions(
    frame: pd.DataFrame,
    *,
    expected_model_id: str,
) -> pd.DataFrame:
    """Validate an exact 64,800-row normalized prediction artifact."""

    if type(frame) is not pd.DataFrame or tuple(map(str, frame.columns)) != (
        NORMALIZED_PREDICTION_COLUMNS
    ):
        raise ResearchTournamentContractError("normalized prediction header/order drifted")
    if len(frame) != COMMON_IDENTITIES:
        raise ResearchTournamentContractError("normalized prediction row geometry drifted")
    if type(expected_model_id) is not str or not expected_model_id:
        raise ResearchTournamentContractError("normalized prediction model ID is invalid")
    expected_seed, expected_dgp, expected_position = _expected_arrays()
    seed = frame["seed_alias"].astype(str).to_numpy(dtype=object)
    dgp = frame["dgp_id"].astype(str).to_numpy(dtype=object)
    position = pd.to_numeric(frame["session_position"], errors="raise").to_numpy(
        dtype=np.int64
    )
    if (
        not np.array_equal(seed, expected_seed)
        or not np.array_equal(dgp, expected_dgp)
        or not np.array_equal(position, expected_position)
    ):
        raise ResearchTournamentContractError("normalized prediction identity order drifted")
    if set(frame["pe_model_id"].astype(str)) != {expected_model_id}:
        raise ResearchTournamentContractError("normalized prediction model identity drifted")
    if set(frame["ticker"].astype(str)) != {"DGP_ISSUER"}:
        raise ResearchTournamentContractError("normalized prediction ticker drifted")
    expected_folds = np.asarray(
        [fold_id_for_position(int(value)) for value in expected_position], dtype=object
    )
    if not np.array_equal(frame["fold_id"].astype(str).to_numpy(dtype=object), expected_folds):
        raise ResearchTournamentContractError("normalized prediction fold identity drifted")
    expected_pe = pd.to_numeric(frame["expected_pe"], errors="raise").to_numpy(
        dtype=np.float64
    )
    expected_log = pd.to_numeric(frame["expected_log_pe"], errors="raise").to_numpy(
        dtype=np.float64
    )
    if (
        not np.isfinite(expected_pe).all()
        or np.any(expected_pe <= 0.0)
        or not np.isfinite(expected_log).all()
        or not np.allclose(np.log(expected_pe), expected_log, rtol=0.0, atol=2.0e-12)
    ):
        raise ResearchTournamentContractError("normalized prediction numeric domain drifted")
    if not frame["prediction_valid"].map(type).eq(bool).all() or not frame[
        "prediction_valid"
    ].all():
        raise ResearchTournamentContractError("normalized prediction validity drifted")
    if not frame["pit_valid"].map(type).eq(bool).all() or not frame["pit_valid"].all():
        raise ResearchTournamentContractError("normalized PIT validity drifted")
    if set(frame["evidence_class"].astype(str)) != {RESEARCH_EVIDENCE_CLASS}:
        raise ResearchTournamentContractError("normalized evidence label drifted")
    dates = frame["date"].astype(str).to_numpy(dtype=object)
    for task in range(TASK_COUNT):
        start = task * SCORE_ROWS_PER_TASK
        task_dates = dates[start : start + SCORE_ROWS_PER_TASK]
        if len(set(task_dates)) != SCORE_ROWS_PER_TASK or list(task_dates) != sorted(task_dates):
            raise ResearchTournamentContractError("normalized task dates drifted")
    uncertainty = pd.to_numeric(frame["uncertainty"], errors="coerce").to_numpy(
        dtype=np.float64
    )
    valid_uncertainty = np.isnan(uncertainty) | (
        np.isfinite(uncertainty) & (uncertainty >= 0.0)
    )
    confidence = pd.to_numeric(frame["confidence"], errors="coerce").to_numpy(
        dtype=np.float64
    )
    valid_confidence = np.isnan(confidence) | (
        np.isfinite(confidence) & (confidence >= 0.0) & (confidence <= 1.0)
    )
    if not valid_uncertainty.all() or not valid_confidence.all():
        raise ResearchTournamentContractError("normalized uncertainty/confidence domain drifted")
    if frame["source_model_version"].astype(str).str.strip().eq("").any():
        raise ResearchTournamentContractError("normalized source version is blank")
    return frame.copy(deep=True)


def normalize_bce_wide_predictions(
    frame: pd.DataFrame,
    *,
    model_id: str,
) -> pd.DataFrame:
    """Convert one frozen BCE/Champion column to the standard long-row contract."""

    if model_id not in MODEL_COLUMNS:
        raise ResearchTournamentContractError("unsupported BCE normalization model ID")
    required = {
        "seed_alias",
        "dgp_id",
        "session_position",
        "date",
        "symbol",
        "fold_id",
        MODEL_COLUMNS[model_id],
    }
    if type(frame) is not pd.DataFrame or not required.issubset(frame.columns):
        raise ResearchTournamentContractError("BCE wide frame lacks normalization columns")
    prediction = pd.to_numeric(frame[MODEL_COLUMNS[model_id]], errors="raise").to_numpy(
        dtype=np.float64
    )
    output = pd.DataFrame(
        {
            "seed_alias": frame["seed_alias"].astype(str),
            "dgp_id": frame["dgp_id"].astype(str),
            "session_position": frame["session_position"],
            "date": frame["date"].astype(str),
            "ticker": frame["symbol"].astype(str),
            "fold_id": frame["fold_id"].astype(str),
            "pe_model_id": model_id,
            "expected_pe": prediction,
            "expected_log_pe": np.log(prediction),
            "uncertainty": np.nan,
            "confidence": np.nan,
            "regime_state": "UNKNOWN",
            "specialist_tags": "bounded_consensus",
            "prediction_valid": True,
            "pit_valid": True,
            "source_model_version": "observable_state_bce_dgp_tournament_v1_r1",
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
        },
        columns=NORMALIZED_PREDICTION_COLUMNS,
    )
    return validate_normalized_predictions(output, expected_model_id=model_id)


def normalize_hofs_rows(frame: pd.DataFrame, *, new_model_id: str) -> pd.DataFrame:
    """Normalize a future new-identity H-OFS spent runner output.

    This adapter cannot make inert V11 executable.  It only accepts bytes from a
    separately implemented and audited new research runner.
    """

    if type(frame) is not pd.DataFrame or tuple(map(str, frame.columns)) != HOFS_SOURCE_COLUMNS:
        raise ResearchTournamentContractError("H-OFS source output header/order drifted")
    if type(new_model_id) is not str or not new_model_id.strip():
        raise ResearchTournamentContractError("H-OFS research model identity is invalid")
    seed_to_alias = {value: key for key, value in SEED_ALIAS_TO_VALUE.items()}
    seeds = pd.to_numeric(frame["task_seed"], errors="raise").astype(int)
    if not seeds.isin(seed_to_alias).all():
        raise ResearchTournamentContractError("H-OFS task seed is outside spent surface")
    pe = pd.to_numeric(frame["hofs_v7_expected_pe"], errors="raise").to_numpy(dtype=np.float64)
    p10 = pd.to_numeric(frame["hofs_v7_pe_p10"], errors="raise").to_numpy(dtype=np.float64)
    p90 = pd.to_numeric(frame["hofs_v7_pe_p90"], errors="raise").to_numpy(dtype=np.float64)
    log_scale = pd.to_numeric(frame["hofs_v7_log_scale"], errors="raise").to_numpy(
        dtype=np.float64
    )
    tail_guard = pd.to_numeric(frame["hofs_v7_tail_guard_weight"], errors="raise").to_numpy(
        dtype=np.float64
    )
    numeric_positions = pd.to_numeric(frame["source_row_position"], errors="raise").to_numpy(
        dtype=np.float64
    )
    numeric_folds = pd.to_numeric(frame["fold_index"], errors="raise").to_numpy(
        dtype=np.float64
    )
    numeric_ordinals = pd.to_numeric(frame["task_ordinal"], errors="raise").to_numpy(
        dtype=np.float64
    )
    numeric_updates = pd.to_numeric(
        frame["within_block_parameter_update_count"], errors="raise"
    ).to_numpy(dtype=np.float64)
    integral_fields = (numeric_positions, numeric_folds, numeric_ordinals, numeric_updates)
    if any(
        not np.isfinite(values).all() or not np.equal(values, np.floor(values)).all()
        for values in integral_fields
    ):
        raise ResearchTournamentContractError("H-OFS integer custody field drifted")
    positions = pd.Series(numeric_positions.astype(np.int64), index=frame.index)
    fold_indices = numeric_folds.astype(np.int64)
    task_ordinals = numeric_ordinals.astype(np.int64)
    expected_fold_indices = (positions - SCORE_START) // 21
    expected_task_ordinals = np.repeat(np.arange(TASK_COUNT, dtype=np.int64), SCORE_ROWS_PER_TASK)
    dates = pd.to_datetime(frame["decision_date"], errors="coerce")
    hashes_valid = all(
        frame[name].map(type).eq(str).all()
        and frame[name].str.fullmatch(r"[0-9a-f]{64}").all()
        for name in HOFS_HASH_COLUMNS
    )
    if (
        not np.isfinite(pe).all()
        or np.any(pe <= 0.0)
        or not np.isfinite(p10).all()
        or not np.isfinite(p90).all()
        or np.any((p10 <= 0.0) | (p90 <= 0.0) | (p10 > pe) | (pe > p90))
        or not np.isfinite(log_scale).all()
        or np.any(log_scale < HOFS_LOG_SCALE_BOUNDS[0])
        or np.any(log_scale > HOFS_LOG_SCALE_BOUNDS[1])
        or not np.isfinite(tail_guard).all()
        or np.any((tail_guard < 0.0) | (tail_guard > 1.0))
        or dates.isna().any()
        or getattr(dates.dt, "tz", None) is not None
        or not np.array_equal(fold_indices, expected_fold_indices.to_numpy())
        or not np.array_equal(task_ordinals, expected_task_ordinals)
        or not np.equal(numeric_updates, 0.0).all()
        or not hashes_valid
    ):
        raise ResearchTournamentContractError("H-OFS source prediction domain drifted")
    output = pd.DataFrame(
        {
            "seed_alias": seeds.map(seed_to_alias),
            "dgp_id": frame["task_dgp"].astype(str),
            "session_position": positions,
            "date": dates.dt.strftime("%Y-%m-%d"),
            "ticker": frame["entity_id"].astype(str),
            "fold_id": positions.map(lambda value: fold_id_for_position(int(value))),
            "pe_model_id": new_model_id,
            "expected_pe": pe,
            "expected_log_pe": np.log(pe),
            "uncertainty": np.exp(log_scale),
            "confidence": np.nan,
            "regime_state": "UNKNOWN",
            "specialist_tags": "hierarchical_observable_state",
            "prediction_valid": True,
            "pit_valid": True,
            "source_model_version": new_model_id,
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
        },
        columns=NORMALIZED_PREDICTION_COLUMNS,
    )
    return validate_normalized_predictions(output, expected_model_id=new_model_id)


def expected_log_pe_matches(expected_pe: float, expected_log_pe: float) -> bool:
    """Small scalar helper for private-process IPC implementations."""

    return (
        math.isfinite(expected_pe)
        and expected_pe > 0.0
        and math.isfinite(expected_log_pe)
        and abs(math.log(expected_pe) - expected_log_pe) <= 2.0e-12
    )


__all__ = [
    "HOFS_LOG_SCALE_BOUNDS",
    "HOFS_SOURCE_COLUMNS",
    "NORMALIZED_PREDICTION_COLUMNS",
    "expected_log_pe_matches",
    "normalize_bce_wide_predictions",
    "normalize_hofs_rows",
    "validate_normalized_predictions",
]
