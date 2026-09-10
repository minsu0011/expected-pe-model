"""Exact spent-R4 loader, scorer, robustness, and complementarity diagnostics."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import itertools
import json
import math
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from .contracts import (
    BCE_CHECKSUMS_SHA256,
    BCE_MANIFEST_SHA256,
    BCE_PREDICTION_ROOT,
    BCE_PREDICTIONS_SHA256,
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_RNG_SEED,
    CHAMPION_ID,
    COMMON_IDENTITIES,
    DETAILED_EVIDENCE_CLASS,
    DGP_IDS,
    DISAGREEMENT_THRESHOLDS,
    EXTREME_ABS_LOG_ERROR_THRESHOLD,
    FOLD_BLOCKS,
    FOLDS_PER_TASK,
    MODEL_COLUMNS,
    PREDICTION_COLUMNS,
    RESEARCH_EVIDENCE_CLASS,
    ROWS_PER_TASK,
    SCORE_END,
    SCORE_ROWS_PER_TASK,
    SCORE_START,
    SCORED_CANDIDATE_IDS,
    SCORED_MODEL_IDS,
    SEED_ALIASES,
    SEEDS,
    TAIL_QUANTILES,
    TASK_COUNT,
    TRUTH_CHECKSUMS_SHA256,
    TRUTH_COLUMNS,
    TRUTH_RECEIPT_SHA256,
    TRUTH_ROOT,
    ResearchTournamentContractError,
    fold_id_for_position,
)


@dataclass(frozen=True)
class TournamentResult:
    pooled_metrics: tuple[dict[str, Any], ...]
    seed_metrics: tuple[dict[str, Any], ...]
    dgp_metrics: tuple[dict[str, Any], ...]
    seed_dgp_metrics: tuple[dict[str, Any], ...]
    fold_metrics: tuple[dict[str, Any], ...]
    tail_metrics: tuple[dict[str, Any], ...]
    complementarity: tuple[dict[str, Any], ...]
    bootstrap_metrics: tuple[dict[str, Any], ...]
    candidate_summary: tuple[dict[str, Any], ...]
    access_receipt: Mapping[str, Any]
    runtime_receipt: Mapping[str, Any]


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _strict_json(content: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ResearchTournamentContractError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResearchTournamentContractError(f"invalid JSON: {label}") from exc
    if type(value) is not dict:
        raise ResearchTournamentContractError(f"JSON root is not an object: {label}")
    return value


def _bound_file(project: Path, relative: str, expected_sha256: str) -> Path:
    root = Path(project).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ResearchTournamentContractError(f"bound path escaped project: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise ResearchTournamentContractError(f"bound input is not an ordinary file: {relative}")
    actual = _sha256(path.read_bytes())
    if actual != expected_sha256:
        raise ResearchTournamentContractError(f"bound input hash drifted: {relative}: {actual}")
    return path


def _expected_identity_arrays() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    seeds = np.repeat(np.asarray(SEED_ALIASES, dtype=object), len(DGP_IDS) * SCORE_ROWS_PER_TASK)
    dgps = np.tile(
        np.repeat(np.asarray(DGP_IDS, dtype=object), SCORE_ROWS_PER_TASK),
        len(SEED_ALIASES),
    )
    positions = np.tile(np.arange(SCORE_START, SCORE_END, dtype=np.int64), TASK_COUNT)
    return seeds, dgps, positions


def _load_predictions(project: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    root = Path(project).resolve()
    prediction_path = _bound_file(
        root, f"{BCE_PREDICTION_ROOT}/PREDICTIONS.csv", BCE_PREDICTIONS_SHA256
    )
    manifest_path = _bound_file(
        root, f"{BCE_PREDICTION_ROOT}/PREDICTION_MANIFEST.json", BCE_MANIFEST_SHA256
    )
    checksums_path = _bound_file(
        root, f"{BCE_PREDICTION_ROOT}/CHECKSUMS.sha256", BCE_CHECKSUMS_SHA256
    )
    manifest = _strict_json(manifest_path.read_bytes(), label="BCE prediction manifest")
    if (
        manifest.get("status") != "PREDICTIONS_FROZEN_EVALUATOR_CUSTODY_UNOPENED"
        or manifest.get("identity_rows") != COMMON_IDENTITIES
        or manifest.get("task_count") != TASK_COUNT
        or manifest.get("fold_blocks") != FOLD_BLOCKS
        or manifest.get("prediction_raw_sha256") != BCE_PREDICTIONS_SHA256
    ):
        raise ResearchTournamentContractError("BCE prediction manifest semantic closure drifted")

    frame = pd.read_csv(prediction_path, low_memory=False)
    if tuple(map(str, frame.columns)) != PREDICTION_COLUMNS:
        raise ResearchTournamentContractError("BCE prediction header/order drifted")
    if len(frame) != COMMON_IDENTITIES:
        raise ResearchTournamentContractError("BCE prediction row count differs from 64,800")

    expected_seed, expected_dgp, expected_position = _expected_identity_arrays()
    observed_seed = frame["seed_alias"].astype(str).to_numpy(dtype=object)
    observed_dgp = frame["dgp_id"].astype(str).to_numpy(dtype=object)
    positions = pd.to_numeric(frame["session_position"], errors="raise").to_numpy(dtype=np.int64)
    if (
        not np.array_equal(observed_seed, expected_seed)
        or not np.array_equal(observed_dgp, expected_dgp)
        or not np.array_equal(positions, expected_position)
    ):
        raise ResearchTournamentContractError("BCE prediction identity/order geometry drifted")

    dates = frame["date"].astype(str).to_numpy(dtype=object)
    symbols = frame["symbol"].astype(str).to_numpy(dtype=object)
    if set(symbols) != {"DGP_ISSUER"}:
        raise ResearchTournamentContractError("BCE prediction entity identity drifted")
    for task in range(TASK_COUNT):
        start = task * SCORE_ROWS_PER_TASK
        end = start + SCORE_ROWS_PER_TASK
        task_dates = dates[start:end]
        if len(set(task_dates)) != SCORE_ROWS_PER_TASK or list(task_dates) != sorted(task_dates):
            raise ResearchTournamentContractError("BCE task dates are duplicate or nonmonotonic")

    expected_folds = np.asarray(
        [fold_id_for_position(int(position)) for position in expected_position], dtype=object
    )
    if not np.array_equal(frame["fold_id"].astype(str).to_numpy(dtype=object), expected_folds):
        raise ResearchTournamentContractError("BCE prediction fold identity drifted")
    expected_test_start = SCORE_START + ((expected_position - SCORE_START) // 21) * 21
    observed_test_start = pd.to_numeric(
        frame["test_start_position"], errors="raise"
    ).to_numpy(dtype=np.int64)
    observed_train_end = pd.to_numeric(
        frame["train_end_position"], errors="raise"
    ).to_numpy(dtype=np.int64)
    if not np.array_equal(observed_test_start, expected_test_start) or not np.array_equal(
        observed_train_end, expected_test_start - 1
    ):
        raise ResearchTournamentContractError("BCE expanding-prefix geometry drifted")

    for column in MODEL_COLUMNS.values():
        values = pd.to_numeric(frame[column], errors="raise").to_numpy(dtype=np.float64)
        if not np.isfinite(values).all() or np.any(values <= 0.0):
            raise ResearchTournamentContractError(f"BCE prediction domain invalid: {column}")
        frame[column] = values

    agreement_raw = frame["directional_agreement"]
    if agreement_raw.dtype == bool:
        agreement = agreement_raw.to_numpy(dtype=bool)
    else:
        values = agreement_raw.astype(str).str.casefold()
        if not values.isin(["true", "false"]).all():
            raise ResearchTournamentContractError("directional agreement is not canonical boolean")
        agreement = values.eq("true").to_numpy(dtype=bool)
    alpha_fixed = pd.to_numeric(frame["alpha__fixed_alpha_040"], errors="raise").to_numpy(
        dtype=np.float64
    )
    expected_alpha = np.where(agreement, 0.4, 0.0)
    if not np.array_equal(alpha_fixed, expected_alpha):
        raise ResearchTournamentContractError("fixed alpha=0.40 formula identity drifted")
    for column in ("alpha__bce_b", "alpha__bce_d"):
        alpha = pd.to_numeric(frame[column], errors="raise").to_numpy(dtype=np.float64)
        if (
            not np.isfinite(alpha).all()
            or np.any((alpha < 0.0) | (alpha > 1.0))
            or not np.array_equal(alpha[~agreement], np.zeros(int((~agreement).sum())))
        ):
            raise ResearchTournamentContractError(f"BCE alpha contract drifted: {column}")

    return frame, {
        "prediction_payload_files_opened": 1,
        "prediction_payload_bytes_read": prediction_path.stat().st_size,
        "prediction_rows_validated": len(frame),
        "prediction_raw_sha256": BCE_PREDICTIONS_SHA256,
        "prediction_manifest_raw_sha256": BCE_MANIFEST_SHA256,
        "prediction_checksums_raw_sha256": BCE_CHECKSUMS_SHA256,
        "prediction_manifest_status": manifest["status"],
        "prediction_path": prediction_path.relative_to(root).as_posix(),
        "checksums_path": checksums_path.relative_to(root).as_posix(),
    }


def _load_spent_truth(project: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    root = Path(project).resolve()
    receipt_path = _bound_file(
        root, f"{TRUTH_ROOT}/VAULT_RECEIPT.json", TRUTH_RECEIPT_SHA256
    )
    checksums_path = _bound_file(
        root, f"{TRUTH_ROOT}/CHECKSUMS.sha256", TRUTH_CHECKSUMS_SHA256
    )
    receipt = _strict_json(receipt_path.read_bytes(), label="spent R4 truth receipt")
    if (
        receipt.get("artifact_count") != 100
        or receipt.get("evidence_class")
        != "RESEARCH_ONLY_SPENT_OUTCOME_EXPOSED_NOT_PROMOTION_EVIDENCE"
        or receipt.get("fresh_or_heldout_authority") is not False
        or type(receipt.get("artifacts_by_task")) is not dict
    ):
        raise ResearchTournamentContractError("spent truth receipt semantic closure drifted")

    vault = (root / TRUTH_ROOT).resolve()
    artifacts: Mapping[str, Any] = receipt["artifacts_by_task"]
    frames: list[pd.DataFrame] = []
    opened: list[dict[str, Any]] = []
    for seed_alias, seed in zip(SEED_ALIASES, SEEDS, strict=True):
        for dgp_id in DGP_IDS:
            key = f"{seed}:{dgp_id}"
            task_record = artifacts.get(key)
            if type(task_record) is not dict or type(task_record.get("truth")) is not dict:
                raise ResearchTournamentContractError(f"spent truth task metadata missing: {key}")
            record: Mapping[str, Any] = task_record["truth"]
            relative = record.get("relative_path")
            expected_hash = record.get("raw_sha256")
            expected_bytes = record.get("bytes")
            expected_rows = record.get("rows")
            if (
                type(relative) is not str
                or not relative.endswith("/truth.csv")
                or type(expected_hash) is not str
                or type(expected_bytes) is not int
                or expected_rows != ROWS_PER_TASK
            ):
                raise ResearchTournamentContractError(f"spent truth task metadata malformed: {key}")
            path = (vault / relative).resolve()
            try:
                path.relative_to(vault)
            except ValueError as exc:
                raise ResearchTournamentContractError("spent truth path escaped vault") from exc
            if not path.is_file() or path.is_symlink():
                raise ResearchTournamentContractError("spent truth is not an ordinary file")
            content = path.read_bytes()
            observed_hash = _sha256(content)
            if len(content) != expected_bytes or observed_hash != expected_hash:
                raise ResearchTournamentContractError(f"spent truth bytes drifted: {key}")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ResearchTournamentContractError("spent truth is not UTF-8") from exc
            reader = csv.reader(io.StringIO(text, newline=""))
            header = tuple(next(reader, ()))
            if header != TRUTH_COLUMNS:
                raise ResearchTournamentContractError(f"spent truth seven-column header drifted: {key}")
            frame = pd.read_csv(io.BytesIO(content), low_memory=False)
            if tuple(map(str, frame.columns)) != TRUTH_COLUMNS or len(frame) != ROWS_PER_TASK:
                raise ResearchTournamentContractError(f"spent truth frame geometry drifted: {key}")
            dates = frame["date"].astype(str)
            if dates.duplicated().any() or dates.tolist() != sorted(dates.tolist()):
                raise ResearchTournamentContractError(f"spent truth dates drifted: {key}")
            score = frame.iloc[SCORE_START:SCORE_END].copy()
            eligible = score["true_expected_pe_eligible"]
            if eligible.dtype == bool:
                eligible_values = eligible.to_numpy(dtype=bool)
            else:
                normalized = eligible.astype(str).str.casefold()
                if not normalized.isin(["true", "false"]).all():
                    raise ResearchTournamentContractError("truth eligibility is not boolean")
                eligible_values = normalized.eq("true").to_numpy(dtype=bool)
            if not eligible_values.all():
                raise ResearchTournamentContractError(
                    f"spent score interval is not fully Expected-P/E eligible: {key}"
                )
            fair = pd.to_numeric(score["true_fair_pe"], errors="raise").to_numpy(dtype=np.float64)
            log_fair = pd.to_numeric(
                score["true_log_fair_pe"], errors="raise"
            ).to_numpy(dtype=np.float64)
            if (
                not np.isfinite(fair).all()
                or np.any(fair <= 0.0)
                or not np.isfinite(log_fair).all()
                or not np.allclose(np.log(fair), log_fair, rtol=0.0, atol=2.0e-12)
            ):
                raise ResearchTournamentContractError(f"spent truth target domain drifted: {key}")
            frames.append(
                pd.DataFrame(
                    {
                        "seed_alias": seed_alias,
                        "dgp_id": dgp_id,
                        "date": score["date"].astype(str).to_numpy(dtype=object),
                        "session_position": np.arange(SCORE_START, SCORE_END, dtype=np.int64),
                        "true_fair_pe": fair,
                        "true_log_fair_pe": log_fair,
                        "true_expected_pe_eligible": True,
                    }
                )
            )
            opened.append(
                {
                    "seed_alias": seed_alias,
                    "seed": seed,
                    "dgp_id": dgp_id,
                    "relative_path": path.relative_to(root).as_posix(),
                    "bytes": len(content),
                    "raw_sha256": observed_hash,
                    "rows": ROWS_PER_TASK,
                    "score_rows": SCORE_ROWS_PER_TASK,
                    "evidence_class": RESEARCH_EVIDENCE_CLASS,
                }
            )

    truth = pd.concat(frames, ignore_index=True)
    if len(truth) != COMMON_IDENTITIES:
        raise ResearchTournamentContractError("spent truth common identity geometry drifted")
    return truth, {
        "truth_payload_files_opened": len(opened),
        "truth_payload_bytes_read": sum(int(row["bytes"]) for row in opened),
        "truth_rows_parsed": TASK_COUNT * ROWS_PER_TASK,
        "truth_score_rows_selected": len(truth),
        "truth_receipt_raw_sha256": TRUTH_RECEIPT_SHA256,
        "truth_checksums_raw_sha256": TRUTH_CHECKSUMS_SHA256,
        "truth_receipt_path": receipt_path.relative_to(root).as_posix(),
        "truth_checksums_path": checksums_path.relative_to(root).as_posix(),
        "opened_truth_records": opened,
        "latent_payload_files_opened": 0,
    }


def _join(predictions: pd.DataFrame, truth: pd.DataFrame) -> pd.DataFrame:
    keys = ["seed_alias", "dgp_id", "date", "session_position"]
    if predictions[keys].duplicated().any() or truth[keys].duplicated().any():
        raise ResearchTournamentContractError("prediction or truth identities are duplicated")
    left = predictions.loc[:, keys].reset_index(drop=True)
    right = truth.loc[:, keys].reset_index(drop=True)
    if not left.equals(right):
        raise ResearchTournamentContractError("prediction/truth identity and order differ")
    joined = predictions.copy()
    joined["true_fair_pe"] = truth["true_fair_pe"].to_numpy(dtype=np.float64)
    joined["true_log_fair_pe"] = truth["true_log_fair_pe"].to_numpy(dtype=np.float64)
    joined["true_expected_pe_eligible"] = True
    if len(joined) != COMMON_IDENTITIES:
        raise ResearchTournamentContractError("joined common geometry drifted")
    return joined


def _summary(signed_error: np.ndarray) -> dict[str, Any]:
    values = np.asarray(signed_error, dtype=np.float64)
    if values.ndim != 1 or len(values) == 0 or not np.isfinite(values).all():
        raise ResearchTournamentContractError("metric error vector is invalid")
    absolute = np.abs(values)
    extreme = absolute >= EXTREME_ABS_LOG_ERROR_THRESHOLD
    return {
        "rows": int(len(values)),
        "mae": float(np.mean(absolute, dtype=np.float64)),
        "rmse": float(np.sqrt(np.mean(np.square(values), dtype=np.float64))),
        "mean_signed_error": float(np.mean(values, dtype=np.float64)),
        "p95_absolute_error": float(np.quantile(absolute, TAIL_QUANTILES[0], method="linear")),
        "p99_absolute_error": float(np.quantile(absolute, TAIL_QUANTILES[1], method="linear")),
        "max_absolute_error": float(np.max(absolute)),
        "extreme_error_count": int(extreme.sum()),
        "extreme_error_frequency": float(np.mean(extreme)),
    }


def _gain(candidate: float, champion: float) -> float:
    if not math.isfinite(candidate) or not math.isfinite(champion) or champion <= 0.0:
        raise ResearchTournamentContractError("relative-gain domain is invalid")
    return (champion - candidate) / champion


def _metric_row(
    model_id: str,
    signed_error: np.ndarray,
    champion_error: np.ndarray,
) -> dict[str, Any]:
    candidate = _summary(signed_error)
    champion = _summary(champion_error)
    return {
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "model_id": model_id,
        **{f"model_{key}": value for key, value in candidate.items()},
        "champion_mae": champion["mae"],
        "champion_rmse": champion["rmse"],
        "mae_relative_gain_vs_v04": _gain(candidate["mae"], champion["mae"]),
        "rmse_relative_gain_vs_v04": _gain(candidate["rmse"], champion["rmse"]),
        "p95_relative_gain_vs_v04": _gain(
            candidate["p95_absolute_error"], champion["p95_absolute_error"]
        ),
        "p99_relative_gain_vs_v04": _gain(
            candidate["p99_absolute_error"], champion["p99_absolute_error"]
        ),
        "is_champion": model_id == CHAMPION_ID,
        "certification_evidence": False,
    }


def _correlation(left: np.ndarray, right: np.ndarray) -> float | None:
    a = np.asarray(left, dtype=np.float64)
    b = np.asarray(right, dtype=np.float64)
    if len(a) < 2 or not np.isfinite(a).all() or not np.isfinite(b).all():
        return None
    if float(np.std(a)) == 0.0 or float(np.std(b)) == 0.0:
        return None
    return float(np.corrcoef(a, b)[0, 1])


def _group_metric_rows(
    joined: pd.DataFrame,
    errors: Mapping[str, np.ndarray],
    keys: Sequence[str],
) -> list[dict[str, Any]]:
    champion = errors[CHAMPION_ID]
    output: list[dict[str, Any]] = []
    groups = joined.groupby(list(keys), sort=False, observed=True).indices
    for identity, positions in groups.items():
        identity_tuple = identity if isinstance(identity, tuple) else (identity,)
        indexes = np.asarray(positions, dtype=np.int64)
        context = dict(zip(keys, identity_tuple, strict=True))
        for candidate_id in SCORED_CANDIDATE_IDS:
            metric = _metric_row(candidate_id, errors[candidate_id][indexes], champion[indexes])
            output.append({**context, **metric})
    return output


def _tail_rows(
    joined: pd.DataFrame,
    errors: Mapping[str, np.ndarray],
) -> list[dict[str, Any]]:
    champion_abs = np.abs(errors[CHAMPION_ID])
    champion_summary = _summary(errors[CHAMPION_ID])
    dgp_groups = joined.groupby("dgp_id", sort=False, observed=True).indices
    result: list[dict[str, Any]] = []
    for candidate_id in SCORED_CANDIDATE_IDS:
        candidate_abs = np.abs(errors[candidate_id])
        candidate_summary = _summary(errors[candidate_id])
        champion_tail = champion_abs >= float(champion_summary["p95_absolute_error"])
        candidate_tail = candidate_abs >= float(candidate_summary["p95_absolute_error"])
        dgp_failures = 0
        dgp_diagnostics: list[dict[str, Any]] = []
        for dgp_id in DGP_IDS:
            indexes = np.asarray(dgp_groups[dgp_id], dtype=np.int64)
            champion_dgp = _summary(errors[CHAMPION_ID][indexes])
            candidate_dgp = _summary(errors[candidate_id][indexes])
            joint = champion_tail[indexes] & candidate_tail[indexes]
            candidate_only = candidate_tail[indexes] & ~champion_tail[indexes]
            champion_only = champion_tail[indexes] & ~candidate_tail[indexes]
            failure = (
                candidate_dgp["p95_absolute_error"] > champion_dgp["p95_absolute_error"]
                and candidate_dgp["extreme_error_frequency"]
                > champion_dgp["extreme_error_frequency"]
                and int(candidate_only.sum()) > int(champion_only.sum())
            )
            dgp_failures += int(failure)
            dgp_diagnostics.append(
                {
                    "dgp_id": dgp_id,
                    "joint_q95_count": int(joint.sum()),
                    "candidate_only_q95_count": int(candidate_only.sum()),
                    "champion_only_q95_count": int(champion_only.sum()),
                    "systematic_joint_tail_failure": bool(failure),
                }
            )
        result.append(
            {
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "candidate_id": candidate_id,
                "rows": COMMON_IDENTITIES,
                "champion_p95_absolute_error": champion_summary["p95_absolute_error"],
                "candidate_p95_absolute_error": candidate_summary["p95_absolute_error"],
                "champion_p99_absolute_error": champion_summary["p99_absolute_error"],
                "candidate_p99_absolute_error": candidate_summary["p99_absolute_error"],
                "champion_max_absolute_error": champion_summary["max_absolute_error"],
                "candidate_max_absolute_error": candidate_summary["max_absolute_error"],
                "champion_extreme_error_count": champion_summary["extreme_error_count"],
                "candidate_extreme_error_count": candidate_summary["extreme_error_count"],
                "champion_extreme_error_frequency": champion_summary[
                    "extreme_error_frequency"
                ],
                "candidate_extreme_error_frequency": candidate_summary[
                    "extreme_error_frequency"
                ],
                "pooled_p95_non_worse": candidate_summary["p95_absolute_error"]
                <= champion_summary["p95_absolute_error"],
                "pooled_p99_non_worse": candidate_summary["p99_absolute_error"]
                <= champion_summary["p99_absolute_error"],
                "extreme_frequency_non_worse": candidate_summary["extreme_error_frequency"]
                <= champion_summary["extreme_error_frequency"],
                "systematic_dgp_joint_tail_failure_count": dgp_failures,
                "dgp_tail_diagnostics_json": json.dumps(
                    dgp_diagnostics,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ),
                "formal_gate": False,
            }
        )
    return result


def _complementarity_rows(
    log_predictions: Mapping[str, np.ndarray],
    errors: Mapping[str, np.ndarray],
) -> list[dict[str, Any]]:
    champion_summary = _summary(errors[CHAMPION_ID])
    rows: list[dict[str, Any]] = []
    for left_id, right_id in itertools.combinations(SCORED_MODEL_IDS, 2):
        left_error = errors[left_id]
        right_error = errors[right_id]
        left_abs = np.abs(left_error)
        right_abs = np.abs(right_error)
        oracle_abs = np.minimum(left_abs, right_abs)
        oracle_mae = float(np.mean(oracle_abs, dtype=np.float64))
        oracle_rmse = float(np.sqrt(np.mean(np.square(oracle_abs), dtype=np.float64)))
        disagreement = np.abs(log_predictions[left_id] - log_predictions[right_id])
        row: dict[str, Any] = {
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
            "left_model_id": left_id,
            "right_model_id": right_id,
            "rows": COMMON_IDENTITIES,
            "signed_error_correlation": _correlation(left_error, right_error),
            "absolute_error_correlation": _correlation(left_abs, right_abs),
            "log_prediction_correlation": _correlation(
                log_predictions[left_id], log_predictions[right_id]
            ),
            "median_absolute_log_prediction_disagreement": float(np.median(disagreement)),
            "q90_absolute_log_prediction_disagreement": float(
                np.quantile(disagreement, 0.90, method="linear")
            ),
            "q95_absolute_log_prediction_disagreement": float(
                np.quantile(disagreement, 0.95, method="linear")
            ),
            "oracle_pair_mae": oracle_mae,
            "oracle_pair_rmse": oracle_rmse,
            "oracle_mae_gain_vs_v04": _gain(oracle_mae, champion_summary["mae"]),
            "oracle_rmse_gain_vs_v04": _gain(oracle_rmse, champion_summary["rmse"]),
            "oracle_is_achievable_model_score": False,
        }
        for threshold in DISAGREEMENT_THRESHOLDS:
            label = str(int(threshold * 100))
            row[f"disagreement_frequency_gt_{label}pct"] = float(
                np.mean(disagreement > math.log1p(threshold))
            )
        rows.append(row)
    return rows


def _hierarchical_bootstrap(
    joined: pd.DataFrame,
    errors: Mapping[str, np.ndarray],
) -> list[dict[str, Any]]:
    model_ids = SCORED_MODEL_IDS
    fold_sums = np.zeros((len(SEEDS), len(DGP_IDS), FOLDS_PER_TASK, len(model_ids)))
    fold_counts = np.zeros((len(SEEDS), len(DGP_IDS), FOLDS_PER_TASK), dtype=np.int64)
    seed_index = {value: index for index, value in enumerate(SEED_ALIASES)}
    dgp_index = {value: index for index, value in enumerate(DGP_IDS)}
    for (seed_alias, dgp_id, fold_id), positions in joined.groupby(
        ["seed_alias", "dgp_id", "fold_id"], sort=False, observed=True
    ).indices.items():
        s = seed_index[str(seed_alias)]
        d = dgp_index[str(dgp_id)]
        f = int(str(fold_id).split("_")[1]) - 12
        indexes = np.asarray(positions, dtype=np.int64)
        fold_counts[s, d, f] = len(indexes)
        for model_position, model_id in enumerate(model_ids):
            fold_sums[s, d, f, model_position] = float(
                np.sum(np.abs(errors[model_id][indexes]), dtype=np.float64)
            )
    if (
        np.count_nonzero(fold_counts) != FOLD_BLOCKS
        or set(fold_counts.ravel().tolist()) != {15, 21}
        or int(fold_counts.sum()) != COMMON_IDENTITIES
    ):
        raise ResearchTournamentContractError("bootstrap fold geometry drifted")

    rng = np.random.default_rng(BOOTSTRAP_RNG_SEED)
    gains = np.empty((BOOTSTRAP_REPLICATES, len(SCORED_CANDIDATE_IDS)), dtype=np.float64)
    chunk_size = 100
    for offset in range(0, BOOTSTRAP_REPLICATES, chunk_size):
        count = min(chunk_size, BOOTSTRAP_REPLICATES - offset)
        sampled_seed = rng.integers(0, len(SEEDS), size=(count, len(SEEDS)))
        sampled_dgp = rng.integers(
            0, len(DGP_IDS), size=(count, len(SEEDS), len(DGP_IDS))
        )
        sampled_fold = rng.integers(
            0,
            FOLDS_PER_TASK,
            size=(count, len(SEEDS), len(DGP_IDS), FOLDS_PER_TASK),
        )
        s = sampled_seed[:, :, None, None]
        d = sampled_dgp[:, :, :, None]
        selected_sums = fold_sums[s, d, sampled_fold, :].sum(axis=(1, 2, 3))
        selected_counts = fold_counts[s, d, sampled_fold].sum(axis=(1, 2, 3))
        mae = selected_sums / selected_counts[:, None]
        gains[offset : offset + count] = (
            mae[:, [0]] - mae[:, 1:]
        ) / mae[:, [0]]
    if not np.isfinite(gains).all():
        raise ResearchTournamentContractError("bootstrap produced nonfinite gains")
    return [
        {
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
            "candidate_id": candidate_id,
            "replicates": BOOTSTRAP_REPLICATES,
            "rng_seed": BOOTSTRAP_RNG_SEED,
            "hierarchy": "seed_then_dgp_then_chronological_fold",
            "mae_gain_lower_5pct": float(
                np.quantile(gains[:, index], 0.05, method="linear")
            ),
            "mae_gain_median": float(np.quantile(gains[:, index], 0.50, method="linear")),
            "mae_gain_upper_95pct": float(
                np.quantile(gains[:, index], 0.95, method="linear")
            ),
            "probability_mae_gain_gt_zero": float(np.mean(gains[:, index] > 0.0)),
            "formal_gate": False,
        }
        for index, candidate_id in enumerate(SCORED_CANDIDATE_IDS)
    ]


def _candidate_summary(
    pooled: Sequence[Mapping[str, Any]],
    seed: Sequence[Mapping[str, Any]],
    dgp: Sequence[Mapping[str, Any]],
    seed_dgp: Sequence[Mapping[str, Any]],
    tails: Sequence[Mapping[str, Any]],
    complementarity: Sequence[Mapping[str, Any]],
    bootstrap: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for candidate_id in SCORED_CANDIDATE_IDS:
        pooled_row = next(row for row in pooled if row["model_id"] == candidate_id)
        seed_rows = [row for row in seed if row["model_id"] == candidate_id]
        dgp_rows = [row for row in dgp if row["model_id"] == candidate_id]
        joint_rows = [row for row in seed_dgp if row["model_id"] == candidate_id]
        tail = next(row for row in tails if row["candidate_id"] == candidate_id)
        pair = next(
            row
            for row in complementarity
            if {row["left_model_id"], row["right_model_id"]}
            == {CHAMPION_ID, candidate_id}
        )
        boot = next(row for row in bootstrap if row["candidate_id"] == candidate_id)
        seed_gains = [float(row["mae_relative_gain_vs_v04"]) for row in seed_rows]
        dgp_gains = [float(row["mae_relative_gain_vs_v04"]) for row in dgp_rows]
        joint_gains = [float(row["mae_relative_gain_vs_v04"]) for row in joint_rows]
        output.append(
            {
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "candidate_id": candidate_id,
                "research_score_status": "SCORED_SPENT_R4",
                "pooled_mae": pooled_row["model_mae"],
                "pooled_rmse": pooled_row["model_rmse"],
                "mae_gain_vs_v04": pooled_row["mae_relative_gain_vs_v04"],
                "rmse_gain_vs_v04": pooled_row["rmse_relative_gain_vs_v04"],
                "seed_wins": sum(value > 0.0 for value in seed_gains),
                "seed_total": len(seed_gains),
                "dgp_wins": sum(value > 0.0 for value in dgp_gains),
                "dgp_total": len(dgp_gains),
                "seed_dgp_wins": sum(value > 0.0 for value in joint_gains),
                "seed_dgp_total": len(joint_gains),
                "worst_seed_harm": max(0.0, -min(seed_gains)),
                "worst_dgp_harm": max(0.0, -min(dgp_gains)),
                "worst_seed_dgp_harm": max(0.0, -min(joint_gains)),
                "p95_absolute_error": tail["candidate_p95_absolute_error"],
                "p99_absolute_error": tail["candidate_p99_absolute_error"],
                "extreme_error_count": tail["candidate_extreme_error_count"],
                "systematic_dgp_joint_tail_failures": tail[
                    "systematic_dgp_joint_tail_failure_count"
                ],
                "signed_error_corr_v04": pair["signed_error_correlation"],
                "abs_error_corr_v04": pair["absolute_error_correlation"],
                "prediction_corr_v04": pair["log_prediction_correlation"],
                "oracle_pair_mae_gain_vs_v04": pair["oracle_mae_gain_vs_v04"],
                "bootstrap_mae_gain_lower_5pct": boot["mae_gain_lower_5pct"],
                "certification_status": "RESEARCH_ONLY_NOT_CERTIFIED",
                "promotion_eligible": False,
            }
        )
    return output


def evaluate_spent_bce_surface(project_root: Path) -> TournamentResult:
    """Score Champion plus three BCE candidates on the exact spent R4 surface."""

    started = time.perf_counter()
    project = Path(project_root).resolve()
    predictions, prediction_access = _load_predictions(project)
    truth, truth_access = _load_spent_truth(project)
    joined = _join(predictions, truth)

    truth_log = joined["true_log_fair_pe"].to_numpy(dtype=np.float64)
    log_predictions = {
        model_id: np.log(joined[column].to_numpy(dtype=np.float64))
        for model_id, column in MODEL_COLUMNS.items()
    }
    errors = {
        model_id: prediction - truth_log for model_id, prediction in log_predictions.items()
    }
    champion_error = errors[CHAMPION_ID]
    pooled = [
        _metric_row(model_id, errors[model_id], champion_error) for model_id in SCORED_MODEL_IDS
    ]
    seed = _group_metric_rows(joined, errors, ("seed_alias",))
    dgp = _group_metric_rows(joined, errors, ("dgp_id",))
    seed_dgp = _group_metric_rows(joined, errors, ("seed_alias", "dgp_id"))
    folds = _group_metric_rows(joined, errors, ("seed_alias", "dgp_id", "fold_id"))
    if (
        len(seed) != len(SCORED_CANDIDATE_IDS) * len(SEEDS)
        or len(dgp) != len(SCORED_CANDIDATE_IDS) * len(DGP_IDS)
        or len(seed_dgp) != len(SCORED_CANDIDATE_IDS) * TASK_COUNT
        or len(folds) != len(SCORED_CANDIDATE_IDS) * FOLD_BLOCKS
    ):
        raise ResearchTournamentContractError("metric slice geometry drifted")
    tails = _tail_rows(joined, errors)
    complementarity = _complementarity_rows(log_predictions, errors)
    bootstrap = _hierarchical_bootstrap(joined, errors)
    summary = _candidate_summary(
        pooled, seed, dgp, seed_dgp, tails, complementarity, bootstrap
    )
    elapsed = time.perf_counter() - started
    access = {
        "schema_version": "expected_pe.pre_cert_research.access.v1",
        "status": "PASS_SPENT_RESEARCH_TRUTH_AND_BCE_PREDICTIONS_SCORED",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        **prediction_access,
        **truth_access,
        "exact_one_to_one_common_rows": len(joined),
        "common_mask_rows": len(joined),
        "model_specific_row_drops": 0,
        "latent_payload_files_opened": 0,
        "fresh_payload_files_opened": 0,
        "heldout_payload_files_opened": 0,
        "certification_or_promotion_authority": False,
        "registry_or_champion_mutations": 0,
        "model_fits_during_scoring": 0,
        "predictions_created_during_scoring": 0,
    }
    runtime = {
        "schema_version": "expected_pe.pre_cert_research.runtime.v1",
        "status": "PASS_RESEARCH_SCORING_RUNTIME",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "elapsed_seconds": elapsed,
        "logical_cpu_count": __import__("os").cpu_count(),
        "scoring_outer_workers": 1,
        "numpy_vectorized": True,
        "gpu_used": False,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_rng_seed": BOOTSTRAP_RNG_SEED,
        "input_rows": COMMON_IDENTITIES,
        "scored_models": len(SCORED_MODEL_IDS),
    }
    return TournamentResult(
        pooled_metrics=tuple(pooled),
        seed_metrics=tuple(seed),
        dgp_metrics=tuple(dgp),
        seed_dgp_metrics=tuple(seed_dgp),
        fold_metrics=tuple(folds),
        tail_metrics=tuple(tails),
        complementarity=tuple(complementarity),
        bootstrap_metrics=tuple(bootstrap),
        candidate_summary=tuple(summary),
        access_receipt=access,
        runtime_receipt=runtime,
    )


__all__ = ["TournamentResult", "evaluate_spent_bce_surface"]
