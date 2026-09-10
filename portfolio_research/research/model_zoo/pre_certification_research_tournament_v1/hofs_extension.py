"""Isolated spent-only tournament extension for the H-OFS r2 prediction artifact."""

from __future__ import annotations

import itertools
import json
import math
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from research.model_zoo.hofs_research_adapter_v1.contracts import MODEL_ID as HOFS_MODEL_ID

from .adapters import NORMALIZED_PREDICTION_COLUMNS, validate_normalized_predictions
from .contracts import (
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_RNG_SEED,
    CHAMPION_ID,
    COMMON_IDENTITIES,
    DETAILED_EVIDENCE_CLASS,
    DGP_IDS,
    DISAGREEMENT_THRESHOLDS,
    FOLD_BLOCKS,
    FOLDS_PER_TASK,
    MODEL_COLUMNS,
    RESEARCH_EVIDENCE_CLASS,
    SCORED_CANDIDATE_IDS,
    SCORED_MODEL_IDS,
    SEED_ALIASES,
    SEEDS,
    TASK_COUNT,
    ResearchTournamentContractError,
)
from .evaluator import (
    TournamentResult,
    _bound_file,
    _correlation,
    _gain,
    _join,
    _load_predictions,
    _load_spent_truth,
    _metric_row,
    _summary,
)


HOFS_FULL_ROOT = "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822"
HOFS_MANIFEST_SHA256 = "7d7ec53e5ca12fff3f65cb8c1eec9e8794ba349741f7d13a45e52e7a4928450a"
HOFS_CHECKSUMS_SHA256 = "4453e6ac01c0479cee794a4ef825fba392fde5ed22fe1dbbbb6729961b072b80"
HOFS_STANDARDIZED_SHA256 = "cccb3a384d4ad6a32eba16f2a6a4a84e6864ba02b90478739f31107ae3540b52"
HOFS_COLUMN = "candidate__hofs_research_adapter_v1_r2"
EXTENDED_CANDIDATE_IDS = (*SCORED_CANDIDATE_IDS, HOFS_MODEL_ID)
EXTENDED_MODEL_IDS = (*SCORED_MODEL_IDS, HOFS_MODEL_ID)
EXTENDED_MODEL_COLUMNS = {**MODEL_COLUMNS, HOFS_MODEL_ID: HOFS_COLUMN}
EXTENSION_OUTPUT_ROOT = (
    "outputs/model_zoo_pre_certification_research_tournament_v1_"
    "hofs_r2_extension_spent_r1_20260822"
)


def _load_hofs(project: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    manifest_path = _bound_file(
        project,
        f"{HOFS_FULL_ROOT}/MANIFEST.json",
        HOFS_MANIFEST_SHA256,
    )
    checksums_path = _bound_file(
        project,
        f"{HOFS_FULL_ROOT}/CHECKSUMS.sha256",
        HOFS_CHECKSUMS_SHA256,
    )
    prediction_path = _bound_file(
        project,
        f"{HOFS_FULL_ROOT}/STANDARDIZED_PREDICTIONS.csv",
        HOFS_STANDARDIZED_SHA256,
    )
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    if (
        manifest.get("status") != "PASS_RESEARCH_ONLY_FULL_HOFS_PREDICTION"
        or manifest.get("prediction_row_count") != COMMON_IDENTITIES
        or manifest.get("standardized_prediction_rows") != COMMON_IDENTITIES
        or manifest.get("score_or_evaluation_performed") is not False
        or manifest.get("formal_or_registry_authority") is not False
    ):
        raise ResearchTournamentContractError("H-OFS full manifest semantic closure drifted")
    frame = pd.read_csv(prediction_path, low_memory=False)
    if tuple(map(str, frame.columns)) != NORMALIZED_PREDICTION_COLUMNS:
        raise ResearchTournamentContractError("H-OFS standardized header drifted")
    frame = validate_normalized_predictions(frame, expected_model_id=HOFS_MODEL_ID)
    return frame, {
        "hofs_prediction_payload_files_opened": 1,
        "hofs_prediction_payload_bytes_read": prediction_path.stat().st_size,
        "hofs_prediction_rows_validated": len(frame),
        "hofs_standardized_raw_sha256": HOFS_STANDARDIZED_SHA256,
        "hofs_manifest_raw_sha256": HOFS_MANIFEST_SHA256,
        "hofs_checksums_raw_sha256": HOFS_CHECKSUMS_SHA256,
        "hofs_manifest_path": manifest_path.relative_to(project).as_posix(),
        "hofs_prediction_path": prediction_path.relative_to(project).as_posix(),
        "hofs_checksums_path": checksums_path.relative_to(project).as_posix(),
    }


def _attach_hofs(bce: pd.DataFrame, hofs: pd.DataFrame) -> pd.DataFrame:
    bce_keys = bce.loc[:, ["seed_alias", "dgp_id", "session_position"]].reset_index(drop=True)
    hofs_keys = hofs.loc[:, ["seed_alias", "dgp_id", "session_position"]].reset_index(drop=True)
    if not bce_keys.equals(hofs_keys):
        raise ResearchTournamentContractError("BCE/H-OFS core identity order differs")
    if (
        not bce["date"].astype(str).reset_index(drop=True).equals(
            hofs["date"].astype(str).reset_index(drop=True)
        )
        or not bce["symbol"].astype(str).reset_index(drop=True).equals(
            hofs["ticker"].astype(str).reset_index(drop=True)
        )
        or not bce["fold_id"].astype(str).reset_index(drop=True).equals(
            hofs["fold_id"].astype(str).reset_index(drop=True)
        )
    ):
        raise ResearchTournamentContractError("BCE/H-OFS date/entity/fold custody differs")
    output = bce.copy()
    output[HOFS_COLUMN] = hofs["expected_pe"].to_numpy(dtype=np.float64)
    if not np.isfinite(output[HOFS_COLUMN]).all() or np.any(output[HOFS_COLUMN] <= 0.0):
        raise ResearchTournamentContractError("H-OFS attached prediction domain drifted")
    return output


def _group_rows(
    joined: pd.DataFrame,
    errors: Mapping[str, np.ndarray],
    keys: Sequence[str],
) -> list[dict[str, Any]]:
    champion = errors[CHAMPION_ID]
    rows: list[dict[str, Any]] = []
    for identity, positions in joined.groupby(list(keys), sort=False, observed=True).indices.items():
        identity_tuple = identity if isinstance(identity, tuple) else (identity,)
        indexes = np.asarray(positions, dtype=np.int64)
        context = dict(zip(keys, identity_tuple, strict=True))
        for candidate_id in EXTENDED_CANDIDATE_IDS:
            rows.append(
                {
                    **context,
                    **_metric_row(candidate_id, errors[candidate_id][indexes], champion[indexes]),
                }
            )
    return rows


def _tail_rows(
    joined: pd.DataFrame,
    errors: Mapping[str, np.ndarray],
) -> list[dict[str, Any]]:
    champion_abs = np.abs(errors[CHAMPION_ID])
    champion_summary = _summary(errors[CHAMPION_ID])
    dgp_groups = joined.groupby("dgp_id", sort=False, observed=True).indices
    rows: list[dict[str, Any]] = []
    for candidate_id in EXTENDED_CANDIDATE_IDS:
        candidate_abs = np.abs(errors[candidate_id])
        candidate_summary = _summary(errors[candidate_id])
        champion_tail = champion_abs >= float(champion_summary["p95_absolute_error"])
        candidate_tail = candidate_abs >= float(candidate_summary["p95_absolute_error"])
        failures = 0
        diagnostics: list[dict[str, Any]] = []
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
            failures += int(failure)
            diagnostics.append(
                {
                    "dgp_id": dgp_id,
                    "joint_q95_count": int(joint.sum()),
                    "candidate_only_q95_count": int(candidate_only.sum()),
                    "champion_only_q95_count": int(champion_only.sum()),
                    "systematic_joint_tail_failure": bool(failure),
                }
            )
        rows.append(
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
                "champion_extreme_error_frequency": champion_summary["extreme_error_frequency"],
                "candidate_extreme_error_frequency": candidate_summary["extreme_error_frequency"],
                "pooled_p95_non_worse": candidate_summary["p95_absolute_error"]
                <= champion_summary["p95_absolute_error"],
                "pooled_p99_non_worse": candidate_summary["p99_absolute_error"]
                <= champion_summary["p99_absolute_error"],
                "extreme_frequency_non_worse": candidate_summary["extreme_error_frequency"]
                <= champion_summary["extreme_error_frequency"],
                "systematic_dgp_joint_tail_failure_count": failures,
                "dgp_tail_diagnostics_json": json.dumps(
                    diagnostics, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ),
                "formal_gate": False,
            }
        )
    return rows


def _complementarity_rows(
    log_predictions: Mapping[str, np.ndarray],
    errors: Mapping[str, np.ndarray],
) -> list[dict[str, Any]]:
    champion_summary = _summary(errors[CHAMPION_ID])
    rows: list[dict[str, Any]] = []
    for left_id, right_id in itertools.combinations(EXTENDED_MODEL_IDS, 2):
        left_error = errors[left_id]
        right_error = errors[right_id]
        left_abs = np.abs(left_error)
        right_abs = np.abs(right_error)
        oracle_abs = np.minimum(left_abs, right_abs)
        disagreement = np.abs(log_predictions[left_id] - log_predictions[right_id])
        oracle_mae = float(np.mean(oracle_abs, dtype=np.float64))
        oracle_rmse = float(np.sqrt(np.mean(np.square(oracle_abs), dtype=np.float64)))
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


def _bootstrap(joined: pd.DataFrame, errors: Mapping[str, np.ndarray]) -> list[dict[str, Any]]:
    model_ids = EXTENDED_MODEL_IDS
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
        raise ResearchTournamentContractError("H-OFS extension bootstrap geometry drifted")
    rng = np.random.default_rng(BOOTSTRAP_RNG_SEED)
    gains = np.empty((BOOTSTRAP_REPLICATES, len(EXTENDED_CANDIDATE_IDS)))
    for offset in range(0, BOOTSTRAP_REPLICATES, 100):
        count = min(100, BOOTSTRAP_REPLICATES - offset)
        sampled_seed = rng.integers(0, len(SEEDS), size=(count, len(SEEDS)))
        sampled_dgp = rng.integers(0, len(DGP_IDS), size=(count, len(SEEDS), len(DGP_IDS)))
        sampled_fold = rng.integers(
            0,
            FOLDS_PER_TASK,
            size=(count, len(SEEDS), len(DGP_IDS), FOLDS_PER_TASK),
        )
        selected_sums = fold_sums[
            sampled_seed[:, :, None, None],
            sampled_dgp[:, :, :, None],
            sampled_fold,
            :,
        ].sum(axis=(1, 2, 3))
        selected_counts = fold_counts[
            sampled_seed[:, :, None, None],
            sampled_dgp[:, :, :, None],
            sampled_fold,
        ].sum(axis=(1, 2, 3))
        mae = selected_sums / selected_counts[:, None]
        gains[offset : offset + count] = (mae[:, [0]] - mae[:, 1:]) / mae[:, [0]]
    if not np.isfinite(gains).all():
        raise ResearchTournamentContractError("H-OFS extension bootstrap is nonfinite")
    return [
        {
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
            "candidate_id": candidate_id,
            "replicates": BOOTSTRAP_REPLICATES,
            "rng_seed": BOOTSTRAP_RNG_SEED,
            "hierarchy": "seed_then_dgp_then_chronological_fold",
            "mae_gain_lower_5pct": float(np.quantile(gains[:, index], 0.05, method="linear")),
            "mae_gain_median": float(np.quantile(gains[:, index], 0.50, method="linear")),
            "mae_gain_upper_95pct": float(
                np.quantile(gains[:, index], 0.95, method="linear")
            ),
            "probability_mae_gain_gt_zero": float(np.mean(gains[:, index] > 0.0)),
            "formal_gate": False,
        }
        for index, candidate_id in enumerate(EXTENDED_CANDIDATE_IDS)
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
    rows: list[dict[str, Any]] = []
    for candidate_id in EXTENDED_CANDIDATE_IDS:
        pooled_row = next(row for row in pooled if row["model_id"] == candidate_id)
        seed_rows = [row for row in seed if row["model_id"] == candidate_id]
        dgp_rows = [row for row in dgp if row["model_id"] == candidate_id]
        joint_rows = [row for row in seed_dgp if row["model_id"] == candidate_id]
        tail = next(row for row in tails if row["candidate_id"] == candidate_id)
        pair = next(
            row
            for row in complementarity
            if {row["left_model_id"], row["right_model_id"]} == {CHAMPION_ID, candidate_id}
        )
        boot = next(row for row in bootstrap if row["candidate_id"] == candidate_id)
        seed_gains = [float(row["mae_relative_gain_vs_v04"]) for row in seed_rows]
        dgp_gains = [float(row["mae_relative_gain_vs_v04"]) for row in dgp_rows]
        joint_gains = [float(row["mae_relative_gain_vs_v04"]) for row in joint_rows]
        rows.append(
            {
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "candidate_id": candidate_id,
                "research_score_status": "SCORED_SPENT_R4_HOFS_EXTENSION",
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
    return rows


def evaluate_spent_hofs_extension(project_root: Path) -> TournamentResult:
    """Score Champion, BCE candidates, and H-OFS on one exact spent common mask."""

    started = time.perf_counter()
    project = Path(project_root).resolve()
    bce, bce_access = _load_predictions(project)
    hofs, hofs_access = _load_hofs(project)
    predictions = _attach_hofs(bce, hofs)
    truth, truth_access = _load_spent_truth(project)
    joined = _join(predictions, truth)
    truth_log = joined["true_log_fair_pe"].to_numpy(dtype=np.float64)
    log_predictions = {
        model_id: np.log(joined[column].to_numpy(dtype=np.float64))
        for model_id, column in EXTENDED_MODEL_COLUMNS.items()
    }
    errors = {
        model_id: prediction - truth_log for model_id, prediction in log_predictions.items()
    }
    champion_error = errors[CHAMPION_ID]
    pooled = [
        _metric_row(model_id, errors[model_id], champion_error) for model_id in EXTENDED_MODEL_IDS
    ]
    seed = _group_rows(joined, errors, ("seed_alias",))
    dgp = _group_rows(joined, errors, ("dgp_id",))
    seed_dgp = _group_rows(joined, errors, ("seed_alias", "dgp_id"))
    folds = _group_rows(joined, errors, ("seed_alias", "dgp_id", "fold_id"))
    if (
        len(seed) != len(EXTENDED_CANDIDATE_IDS) * len(SEEDS)
        or len(dgp) != len(EXTENDED_CANDIDATE_IDS) * len(DGP_IDS)
        or len(seed_dgp) != len(EXTENDED_CANDIDATE_IDS) * TASK_COUNT
        or len(folds) != len(EXTENDED_CANDIDATE_IDS) * FOLD_BLOCKS
    ):
        raise ResearchTournamentContractError("H-OFS extension metric slice geometry drifted")
    tails = _tail_rows(joined, errors)
    complementarity = _complementarity_rows(log_predictions, errors)
    bootstrap = _bootstrap(joined, errors)
    summary = _candidate_summary(
        pooled, seed, dgp, seed_dgp, tails, complementarity, bootstrap
    )
    access = {
        "schema_version": "expected_pe.pre_cert_research.hofs_extension_access.v1",
        "status": "PASS_SPENT_RESEARCH_HOFS_EXTENSION_SCORED",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        **bce_access,
        **hofs_access,
        **truth_access,
        "exact_one_to_one_common_rows": len(joined),
        "common_mask_rows": len(joined),
        "scored_models": list(EXTENDED_MODEL_IDS),
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
        "schema_version": "expected_pe.pre_cert_research.hofs_extension_runtime.v1",
        "status": "PASS_RESEARCH_HOFS_EXTENSION_SCORING_RUNTIME",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "elapsed_seconds": time.perf_counter() - started,
        "logical_cpu_count": __import__("os").cpu_count(),
        "scoring_outer_workers": 1,
        "numpy_vectorized": True,
        "gpu_used": False,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_rng_seed": BOOTSTRAP_RNG_SEED,
        "input_rows": COMMON_IDENTITIES,
        "scored_models": len(EXTENDED_MODEL_IDS),
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


__all__ = [
    "EXTENDED_CANDIDATE_IDS",
    "EXTENDED_MODEL_IDS",
    "EXTENSION_OUTPUT_ROOT",
    "HOFS_MODEL_ID",
    "evaluate_spent_hofs_extension",
]
