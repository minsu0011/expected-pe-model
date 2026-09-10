"""Build the split Track-P/Track-S cache from spent/public R4 synthetic data."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import io
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .contracts import (
    DGP_IDS,
    EVALUATION_END_EXCLUSIVE,
    EVALUATION_POSITIONS,
    FEATURE_NAMES,
    LOOKBACK,
    SEED_ALIASES,
    SEED_VALUES,
    canonical_json_bytes,
    raw_sha256,
    validate_sample_boundary,
)


PUBLIC_ROOT_RELATIVE = "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
TRUTH_ROOT_RELATIVE = "outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821/vault"
TRUTH_RECEIPT_RELATIVE = (
    "outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821/VAULT_RECEIPT.json"
)
C4_RELATIVE = (
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/STANDARDIZED_PREDICTIONS.csv"
)
C2_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_20260821/"
    "PREDICTIONS.csv"
)
CANONICAL_COLUMNS = (
    "date",
    "symbol",
    "observed_pe",
    "eps_ttm_growth_252",
    "eps_confidence",
    "eps_staleness_days",
    "regime_entropy",
    "regime_confidence",
    "regime_conditional_pe_log_z",
    "benchmark_realized_vol_20",
    "expected_pe",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_record(project_root: Path, path: Path, *, role: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    return {
        "relative_path": resolved.relative_to(project_root).as_posix(),
        "raw_sha256": _sha(resolved),
        "size_bytes": resolved.stat().st_size,
        "role": role,
    }


def _positive_log(values: pd.Series) -> np.ndarray:
    numeric = pd.to_numeric(values, errors="coerce").to_numpy(dtype=np.float64)
    result = np.full(numeric.shape, np.nan, dtype=np.float64)
    valid = np.isfinite(numeric) & (numeric > 0.0)
    result[valid] = np.log(numeric[valid])
    return result


def _read_task(
    project_root: Path,
    seed_alias: str,
    seed: int,
    dgp: str,
) -> dict[str, Any]:
    public_root = project_root / PUBLIC_ROOT_RELATIVE
    task_root = public_root / "replays/pass_1" / f"seed_{seed}" / f"dgp_{dgp}"
    canonical_path = task_root / "canonical150.csv"
    factor_path = task_root / "public/public_factors.csv"
    truth_path = project_root / TRUTH_ROOT_RELATIVE / f"seed_{seed}" / f"dgp_{dgp}/truth.csv"
    canonical = pd.read_csv(
        canonical_path,
        usecols=list(CANONICAL_COLUMNS),
        float_precision="round_trip",
    )
    if len(canonical) != EVALUATION_END_EXCLUSIVE:
        raise RuntimeError("public canonical row geometry differs")
    dates = canonical["date"].astype(str).to_numpy(dtype="U10")
    factors = pd.read_csv(
        factor_path,
        usecols=["factor_id", "effective_session", "value"],
        float_precision="round_trip",
    )
    rate = factors.loc[factors["factor_id"] == "real_rate_z"].copy()
    if rate.empty:
        rate = factors.loc[factors["factor_id"] == "short_rate_z"].copy()
    if rate.empty:
        rate_values = np.full(EVALUATION_END_EXCLUSIVE, np.nan, dtype=np.float64)
    else:
        if len(rate) != EVALUATION_END_EXCLUSIVE:
            raise RuntimeError("public rate-state row geometry differs")
        rate_dates = rate["effective_session"].astype(str).to_numpy(dtype="U10")
        if not np.array_equal(rate_dates, dates):
            raise RuntimeError("public rate-state date identity differs")
        rate_values = pd.to_numeric(rate["value"], errors="coerce").to_numpy(dtype=np.float64)
    columns = (
        _positive_log(canonical["expected_pe"]),
        _positive_log(canonical["observed_pe"]),
        pd.to_numeric(canonical["eps_ttm_growth_252"], errors="coerce").to_numpy(dtype=np.float64),
        pd.to_numeric(canonical["eps_confidence"], errors="coerce").to_numpy(dtype=np.float64),
        pd.to_numeric(canonical["eps_staleness_days"], errors="coerce").to_numpy(dtype=np.float64),
        pd.to_numeric(canonical["regime_entropy"], errors="coerce").to_numpy(dtype=np.float64),
        pd.to_numeric(canonical["regime_confidence"], errors="coerce").to_numpy(dtype=np.float64),
        pd.to_numeric(canonical["regime_conditional_pe_log_z"], errors="coerce").to_numpy(
            dtype=np.float64
        ),
        pd.to_numeric(canonical["benchmark_realized_vol_20"], errors="coerce").to_numpy(
            dtype=np.float64
        ),
        rate_values,
    )
    features = np.column_stack(columns).astype(np.float32)
    if features.shape != (EVALUATION_END_EXCLUSIVE, len(FEATURE_NAMES)):
        raise RuntimeError("public feature geometry differs")
    truth = pd.read_csv(
        truth_path,
        usecols=["date", "true_log_fair_pe"],
        float_precision="round_trip",
    )
    if len(truth) != EVALUATION_END_EXCLUSIVE or not np.array_equal(
        truth["date"].astype(str).to_numpy(dtype="U10"), dates
    ):
        raise RuntimeError("spent simulator truth identity differs")
    simulator_label = pd.to_numeric(truth["true_log_fair_pe"], errors="coerce").to_numpy(
        dtype=np.float64
    )
    public_label = _positive_log(canonical["observed_pe"])
    return {
        "seed_alias": seed_alias,
        "seed": seed,
        "dgp": dgp,
        "dates": dates,
        "symbol": str(canonical["symbol"].iloc[-1]),
        "features": features,
        "public_label": public_label,
        "simulator_label": simulator_label,
        "records": (
            _source_record(project_root, canonical_path, role="PUBLIC_CANONICAL_SURFACE"),
            _source_record(project_root, factor_path, role="PUBLIC_PIT_RATE_STATE"),
            _source_record(project_root, truth_path, role="SPENT_SIMULATOR_TRUTH_TRACK_S_ONLY"),
        ),
    }


def _load_core_predictions(
    project_root: Path,
    dates: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, tuple[dict[str, object], ...]]:
    c4_path = project_root / C4_RELATIVE
    c2_path = project_root / C2_RELATIVE
    c4 = pd.read_csv(c4_path, float_precision="round_trip")
    c2 = pd.read_csv(c2_path, float_precision="round_trip")
    expected_rows = len(SEED_VALUES) * len(DGP_IDS) * len(EVALUATION_POSITIONS)
    if len(c4) != expected_rows or len(c2) != expected_rows:
        raise RuntimeError("spent core prediction geometry differs")
    expected_identity: list[tuple[str, str, int, str]] = []
    for task_index, (seed_alias, dgp) in enumerate(
        (item for seed in SEED_ALIASES for item in ((seed, dgp) for dgp in DGP_IDS))
    ):
        for position in EVALUATION_POSITIONS:
            expected_identity.append((seed_alias, dgp, position, str(dates[task_index, position])))
    c4_identity = list(
        zip(
            c4["seed_alias"].astype(str),
            c4["dgp_id"].astype(str),
            pd.to_numeric(c4["session_position"]).astype(int),
            c4["date"].astype(str),
            strict=True,
        )
    )
    c2_identity = list(
        zip(
            c2["seed_alias"].astype(str),
            c2["dgp_id"].astype(str),
            pd.to_numeric(c2["session_position"]).astype(int),
            c2["date"].astype(str),
            strict=True,
        )
    )
    if c4_identity != expected_identity or c2_identity != expected_identity:
        raise RuntimeError("spent core prediction identity differs")
    c4_values = pd.to_numeric(c4["expected_log_pe"], errors="coerce").to_numpy(dtype=np.float64)
    c2_pe = pd.to_numeric(c2["candidate__bce_d"], errors="coerce").to_numpy(dtype=np.float64)
    if not np.isfinite(c4_values).all() or not (np.isfinite(c2_pe) & (c2_pe > 0.0)).all():
        raise RuntimeError("spent core prediction contains nonfinite values")
    shape = (len(SEED_VALUES) * len(DGP_IDS), len(EVALUATION_POSITIONS))
    records = (
        _source_record(project_root, c4_path, role="SPENT_C4_COMPLEMENTARITY_REFERENCE"),
        _source_record(project_root, c2_path, role="SPENT_C2_COMPLEMENTARITY_REFERENCE"),
    )
    return c4_values.reshape(shape), np.log(c2_pe).reshape(shape), records


def _sample_receipt_bytes(dates: np.ndarray) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        (
            "task_index",
            "seed_alias",
            "dgp_id",
            "date",
            "label_position",
            "source_position_min",
            "source_position_max",
            "max_source_strictly_less_than_label",
            "within_block_parameter_updates",
        )
    )
    task_index = 0
    for seed_alias in SEED_ALIASES:
        for dgp in DGP_IDS:
            for position in EVALUATION_POSITIONS:
                validate_sample_boundary(
                    label_position=position,
                    source_position_min=position - LOOKBACK,
                    source_position_max=position - 1,
                )
                writer.writerow(
                    (
                        task_index,
                        seed_alias,
                        dgp,
                        str(dates[task_index, position]),
                        position,
                        position - LOOKBACK,
                        position - 1,
                        "true",
                        0,
                    )
                )
            task_index += 1
    return stream.getvalue().encode("utf-8")


def build_research_caches(
    *,
    project_root: Path,
    output_root: Path,
    config_lock_raw_sha256: str,
    workers: int = 16,
) -> dict[str, object]:
    """Build split caches only after the candidate configuration has been frozen."""

    project = Path(project_root).resolve(strict=True)
    root = Path(output_root).resolve(strict=True)
    config_path = root / "CANDIDATE_CONFIG_LOCK.json"
    if _sha(config_path) != config_lock_raw_sha256:
        raise RuntimeError("candidate config changed before data build")
    tasks = [
        (seed_alias, seed, dgp)
        for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True)
        for dgp in DGP_IDS
    ]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="c5r2-data") as pool:
        payloads = list(
            pool.map(
                lambda item: _read_task(project, item[0], item[1], item[2]),
                tasks,
            )
        )
    expected_tasks = [(alias, seed, dgp) for alias, seed, dgp in tasks]
    observed_tasks = [(item["seed_alias"], item["seed"], item["dgp"]) for item in payloads]
    if observed_tasks != expected_tasks:
        raise RuntimeError("research task order differs")
    dates = np.stack([item["dates"] for item in payloads])
    if any(not np.array_equal(dates[0], row) for row in dates[1:]):
        raise RuntimeError("research task calendars differ")
    features = np.stack([item["features"] for item in payloads]).astype(np.float32)
    public_label = np.stack([item["public_label"] for item in payloads]).astype(np.float64)
    simulator_label = np.stack([item["simulator_label"] for item in payloads]).astype(np.float64)
    eval_slice = slice(EVALUATION_POSITIONS[0], EVALUATION_END_EXCLUSIVE)
    anchor = features[:, :, 0].astype(np.float64)
    if (
        not np.isfinite(anchor[:, EVALUATION_POSITIONS[0] - 1 : -1]).all()
        or not np.isfinite(public_label[:, eval_slice]).all()
        or not np.isfinite(simulator_label[:, eval_slice]).all()
    ):
        raise RuntimeError("evaluation anchor/label contains nonfinite values")
    c4, c2, core_records = _load_core_predictions(project, dates)
    work = root / "work_cache"
    work.mkdir()
    public_cache = work / "TRACK_P_PUBLIC_PANEL.npz"
    simulator_cache = work / "TRACK_S_SIMULATOR_PANEL.npz"
    np.savez_compressed(
        public_cache,
        feature_names=np.asarray(FEATURE_NAMES, dtype="U64"),
        features=features,
        dates=dates,
        public_observed_log_pe=public_label,
        task_seed_aliases=np.asarray([item["seed_alias"] for item in payloads], dtype="U32"),
        task_dgps=np.asarray([item["dgp"] for item in payloads], dtype="U1"),
        task_symbols=np.asarray([item["symbol"] for item in payloads], dtype="U64"),
    )
    np.savez_compressed(
        simulator_cache,
        simulator_true_log_fair_pe=simulator_label,
        c4_expected_log_pe=c4,
        c2_expected_log_pe=c2,
    )
    receipt_raw = _sample_receipt_bytes(dates)
    receipt_path = root / "SAMPLE_RECEIPTS.csv"
    receipt_path.write_bytes(receipt_raw)
    source_records = [record for item in payloads for record in item["records"]]
    source_records.extend(core_records)
    truth_receipt_path = project / TRUTH_RECEIPT_RELATIVE
    source_records.append(
        _source_record(project, truth_receipt_path, role="SPENT_TRUTH_VAULT_RECEIPT")
    )
    manifest = {
        "schema_version": "expected_pe.c5_r2.sequence_research.data_manifest.v1",
        "status": "PASS_SPLIT_TRACK_CACHE_AFTER_SCORE_BLIND_CONFIG_LOCK",
        "evidence_class": "RESEARCH_ONLY_SPENT_PUBLIC_SYNTHETIC",
        "candidate_config_lock_raw_sha256": config_lock_raw_sha256,
        "task_count": len(payloads),
        "rows_per_task": EVALUATION_END_EXCLUSIVE,
        "evaluation_rows_per_task": len(EVALUATION_POSITIONS),
        "evaluation_sample_count": len(EVALUATION_POSITIONS) * len(payloads),
        "feature_names": list(FEATURE_NAMES),
        "feature_tensor_shape": list(features.shape),
        "track_separation": {
            "P": {
                "cache_relative_path": public_cache.relative_to(root).as_posix(),
                "simulator_truth_present": False,
                "target": "observed_log_pe[t]",
                "pit_observable": True,
            },
            "S": {
                "cache_relative_path": simulator_cache.relative_to(root).as_posix(),
                "public_features_stored_in_track_p_cache": True,
                "target": "true_log_fair_pe[t]",
                "role": "SIMULATOR_SPECIALIST",
                "deployable": False,
            },
        },
        "access": {
            "config_lock_published_before_any_label_open": True,
            "spent_truth_open_count_before_config_lock": 0,
            "spent_truth_open_count_after_config_lock_track_s_only": len(payloads),
            "fresh_or_heldout_truth_open_count": 0,
            "qualification_or_r3_selection_result_open_count": 0,
            "dgp_label_used_as_model_feature": False,
        },
        "chronology": {
            "sample_receipt_count": len(EVALUATION_POSITIONS) * len(payloads),
            "all_max_source_strictly_less_than_label": True,
            "within_test_block_parameter_updates": 0,
            "sample_receipt_raw_sha256": raw_sha256(receipt_raw),
        },
        "cache_refs": {
            "track_p": {
                "raw_sha256": _sha(public_cache),
                "size_bytes": public_cache.stat().st_size,
            },
            "track_s": {
                "raw_sha256": _sha(simulator_cache),
                "size_bytes": simulator_cache.stat().st_size,
            },
        },
        "source_records": sorted(source_records, key=lambda item: str(item["relative_path"])),
        "source_record_count": len(source_records),
        "promotion_authority": False,
    }
    manifest_raw = canonical_json_bytes(manifest)
    (root / "DATA_MANIFEST.json").write_bytes(manifest_raw)
    return manifest


__all__ = [
    "C2_RELATIVE",
    "C4_RELATIVE",
    "PUBLIC_ROOT_RELATIVE",
    "TRUTH_RECEIPT_RELATIVE",
    "TRUTH_ROOT_RELATIVE",
    "build_research_caches",
]
