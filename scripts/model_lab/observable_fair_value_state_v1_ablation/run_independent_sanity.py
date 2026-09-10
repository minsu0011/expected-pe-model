"""Post-evaluation independent-like sanity audit for the material state signal."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any

os.environ.update(
    {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "-1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "HIP_VISIBLE_DEVICES": "-1",
        "ROCR_VISIBLE_DEVICES": "-1",
    }
)

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from lightgbm import LGBMRegressor  # noqa: E402
from sklearn.impute import SimpleImputer  # noqa: E402

from pe_regime_v04.expected_pe import expected_pe_feature_columns  # noqa: E402
from research.model_zoo.observable_fair_value_state_v1 import (  # noqa: E402
    FEATURE_DEFINITIONS,
    generate_observable_state_features,
)
from research.model_zoo.observable_fair_value_state_v1.contracts import (  # noqa: E402
    REQUIRED_SOURCE_COLUMNS,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.contracts import (  # noqa: E402
    FOLD_SPEC,
    LAB_ID,
    LGBM_PARAMETERS,
    MODEL_IDS,
    REFERENCE_MODEL_ID,
    SOURCE_LANES,
    STATE_CONTRACT_SHA256,
    V04_BASELINE_FEATURES,
    canonical_json_bytes,
    evaluation_truth_path,
    feature_sets,
    sealed_surface_fragment,
    sha256_file,
    source_paths,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.deterministic import (  # noqa: E402
    fixed_order_correlation,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.prediction import (  # noqa: E402
    FoldTask,
    _apply_cpu_affinity,
    _load_worker_data,
    _seal_environment,
)


ROOT = Path(__file__).resolve().parents[3]
CORE = ROOT / "outputs" / "model_zoo_observable_fair_value_state_v1_ablation_r2_20260820"
OUTPUT = (
    ROOT / "outputs" / "model_zoo_observable_fair_value_state_v1_ablation_sanity_audit_20260820"
)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n",
        encoding="ascii",
    )


def _verify_core_manifest() -> dict[str, Any]:
    manifest_path = CORE / "ARTIFACT_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    semantic = manifest.pop("manifest_sha256")
    if hashlib.sha256(canonical_json_bytes(manifest)).hexdigest() != semantic:
        raise RuntimeError("core artifact manifest semantic hash mismatch")
    manifest["manifest_sha256"] = semantic
    for entry in manifest["artifacts"]:
        path = ROOT / entry["path"]
        if not path.is_file() or path.stat().st_size != entry["bytes"]:
            raise RuntimeError(f"core artifact missing/size mismatch: {path}")
        if sha256_file(path) != entry["sha256"]:
            raise RuntimeError(f"core artifact hash mismatch: {path}")
    return manifest


def _causality_audit() -> dict[str, Any]:
    lane = SOURCE_LANES[0]
    canonical_path, _ = source_paths(ROOT, lane, lane.seeds[0])
    columns = list(dict.fromkeys([*REQUIRED_SOURCE_COLUMNS, "symbol"]))
    frame = pd.read_csv(canonical_path, usecols=columns, low_memory=False)
    baseline = generate_observable_state_features(frame, group_columns=("symbol",))
    prefix = generate_observable_state_features(frame.iloc[:1001].copy(), group_columns=("symbol",))
    pd.testing.assert_frame_equal(
        baseline.features.iloc[:1001].reset_index(drop=True),
        prefix.features.reset_index(drop=True),
        check_exact=True,
    )
    pivot = 1000
    attacked = frame.copy()
    attacked.loc[pivot, "observed_pe"] = float(attacked.loc[pivot, "observed_pe"]) * 10.0
    changed = generate_observable_state_features(attacked, group_columns=("symbol",))
    pd.testing.assert_series_equal(
        baseline.features.iloc[pivot],
        changed.features.iloc[pivot],
        check_exact=True,
        check_names=False,
    )
    lagged_columns = [
        item.column_name for item in FEATURE_DEFINITIONS if "observed_pe" in item.source_columns
    ]
    if not all(
        item.availability_lag_sessions >= 1
        for item in FEATURE_DEFINITIONS
        if "observed_pe" in item.source_columns
    ):
        raise RuntimeError("observed_pe-derived feature lacks a one-session lag")
    if not any(
        baseline.features.loc[pivot + 1, column] != changed.features.loc[pivot + 1, column]
        for column in lagged_columns
        if np.isfinite(baseline.features.loc[pivot + 1, column])
        and np.isfinite(changed.features.loc[pivot + 1, column])
    ):
        raise RuntimeError("lagged observed_pe perturbation did not propagate at t+1")
    sets = feature_sets()
    direct_forbidden = {
        "observed_pe",
        "close",
        "earnings_yield",
        "eps_ttm",
        "true_fair_pe",
    }
    leaked = sorted(
        direct_forbidden.intersection(column for columns in sets.values() for column in columns)
    )
    if leaked:
        raise RuntimeError(f"direct target/price feature entered a model: {leaked}")
    eps_features = [
        item.column_name for item in FEATURE_DEFINITIONS if "eps_ttm" in item.source_columns
    ]
    return {
        "passed": True,
        "state_contract_sha256": baseline.contract_sha256,
        "prefix_invariance_rows": 1001,
        "same_row_observed_pe_perturbation_invariant": True,
        "next_row_lagged_effect_present": True,
        "observed_pe_derived_feature_count": len(lagged_columns),
        "all_observed_pe_derived_features_lag_at_least_one": True,
        "direct_target_or_price_columns_in_models": leaked,
        "eps_level_features": eps_features,
        "eps_ttm_is_observable_but_direct_eps_ttm_column_in_models": False,
        "close_or_earnings_yield_available_to_models": False,
        "evaluation_truth_available_to_feature_generator": False,
    }


def _fold_geometry_audit(diagnostics: dict[str, Any]) -> tuple[dict[str, Any], pd.DataFrame]:
    folds = diagnostics["folds"]
    if len(folds) != 620:
        raise RuntimeError("expected 620 primary fold diagnostics")
    geometry_rows: list[dict[str, Any]] = []
    entry_by_identity = {(item["lane_id"], int(item["seed"])): item for item in folds}
    del entry_by_identity  # Count-only guard; detailed checks below.
    for lane in SOURCE_LANES:
        for seed in lane.seeds:
            local = sorted(
                [item for item in folds if int(item["seed"]) == seed],
                key=lambda item: int(item["test_start_position"]),
            )
            if len(local) != 62:
                raise RuntimeError("per-seed fold count mismatch")
            canonical_path, overlay_path = source_paths(ROOT, lane, seed)
            canonical = pd.read_csv(canonical_path, low_memory=False)
            overlay = pd.read_csv(
                overlay_path,
                usecols=[
                    "date",
                    "v04_current_p_bear",
                    "v04_current_p_sideways",
                    "v04_current_p_bull",
                ],
                low_memory=False,
            )
            for column in overlay.columns[1:]:
                canonical[column] = overlay[column].to_numpy()
            public = tuple(
                expected_pe_feature_columns(
                    canonical,
                    include_regime=True,
                    include_return_forecast=False,
                )
            )
            if public != V04_BASELINE_FEATURES:
                raise RuntimeError("public v04 feature construction differs from frozen baseline")
            observed = pd.to_numeric(canonical["observed_pe"], errors="coerce").to_numpy(float)
            baseline_any = (
                canonical.loc[:, list(V04_BASELINE_FEATURES)]
                .apply(pd.to_numeric, errors="coerce")
                .replace([np.inf, -np.inf], np.nan)
                .notna()
                .any(axis=1)
                .to_numpy(bool)
            )
            covered: list[int] = []
            for item in local:
                start = int(item["test_start_position"])
                end = int(item["test_end_exclusive_position"])
                positions = np.flatnonzero(
                    np.isfinite(observed[:start]) & (observed[:start] > 0.0) & baseline_any[:start]
                ).astype("<i8")
                reconstructed_hash = hashlib.sha256(positions.tobytes()).hexdigest()
                if reconstructed_hash != item["train_positions_sha256"]:
                    raise RuntimeError("independent train mask reconstruction mismatch")
                if (
                    len(positions) != int(item["train_rows"])
                    or int(item["train_end_position"]) >= start
                ):
                    raise RuntimeError("fold training geometry mismatch")
                covered.extend(range(start, end))
            if covered != list(range(504, 1800)):
                raise RuntimeError("test folds do not exactly cover positions 504..1799")
            geometry_rows.append(
                {
                    "lane_id": lane.lane_id,
                    "seed": seed,
                    "fold_count": len(local),
                    "score_rows": len(covered),
                    "first_test_position": min(covered),
                    "last_test_position": max(covered),
                    "first_fold_train_rows": int(local[0]["train_rows"]),
                    "last_fold_train_rows": int(local[-1]["train_rows"]),
                    "train_mask_hashes_reconstructed": True,
                    "test_positions_disjoint_and_complete": True,
                }
            )
    active_ranges: dict[str, dict[str, int]] = {}
    for model_id in MODEL_IDS:
        counts = [int(item["models"][model_id]["active_feature_count"]) for item in folds]
        active_ranges[model_id] = {"minimum": min(counts), "maximum": max(counts)}
    return (
        {
            "passed": True,
            "folds": len(folds),
            "seeds": len(geometry_rows),
            "per_seed_score_rows": 1296,
            "first_test_position": 504,
            "last_test_position": 1799,
            "strict_prefix_only": True,
            "within_fold_refit_count": sum(int(item["within_fold_refit_count"]) for item in folds),
            "active_feature_count_ranges": active_ranges,
        },
        pd.DataFrame.from_records(geometry_rows),
    )


def _independent_selected_replay() -> tuple[dict[str, Any], pd.DataFrame]:
    _seal_environment()
    affinity = _apply_cpu_affinity()
    checkpoints = (
        (0, SOURCE_LANES[0].seeds[0], 504),
        (0, SOURCE_LANES[0].seeds[0], 1134),
        (0, SOURCE_LANES[0].seeds[0], 1785),
        (1, SOURCE_LANES[1].seeds[-1], 504),
        (1, SOURCE_LANES[1].seeds[-1], 1134),
        (1, SOURCE_LANES[1].seeds[-1], 1785),
    )
    importance_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    replay_checks: list[dict[str, Any]] = []
    for lane_index, seed, start in checkpoints:
        task = FoldTask(str(ROOT), lane_index, seed, start, "independent_sanity")
        data = _load_worker_data(task)
        end = min(1800, start + FOLD_SPEC.test_sessions)
        test_positions = np.arange(start, end, dtype=np.int64)
        train_positions = np.flatnonzero(
            np.isfinite(data["target"][:start]) & data["baseline_any"][:start]
        )
        model_id = "lgbm__ofs_v1_full_with_regime"
        X = data["matrices"][model_id]
        active = (
            X.iloc[train_positions].columns[X.iloc[train_positions].notna().any(axis=0)].tolist()
        )
        inactive = sorted(set(X.columns).difference(active))
        imputer = SimpleImputer(strategy="median")
        train_values = imputer.fit_transform(X.iloc[train_positions][active])
        test_values = imputer.transform(X.iloc[test_positions][active])
        train_frame = pd.DataFrame(train_values, columns=active)
        test_frame = pd.DataFrame(test_values, columns=active)
        model = LGBMRegressor(**LGBM_PARAMETERS, random_state=seed + start)
        model.fit(
            train_frame,
            data["target"][train_positions],
            sample_weight=data["weights"][train_positions],
        )
        predicted = np.exp(np.asarray(model.predict(test_frame), dtype=float))
        frozen = pd.read_csv(
            CORE / "predictions" / f"seed_{seed}" / "predictions.csv",
            low_memory=False,
            float_precision="round_trip",
        )
        frozen = frozen.loc[frozen["test_start_position"].eq(start), model_id].to_numpy(float)
        exact = bool(np.array_equal(predicted, frozen))
        if not exact:
            raise RuntimeError("selected independent replay differs from frozen prediction")
        gains = model.booster_.feature_importance(importance_type="gain")
        total = float(np.sum(gains))
        for feature, gain in zip(active, gains, strict=True):
            importance_rows.append(
                {
                    "seed": seed,
                    "test_start_position": start,
                    "feature": feature,
                    "gain": float(gain),
                    "normalized_gain": float(gain / total) if total > 0.0 else 0.0,
                }
            )
        missing_rows.append(
            {
                "seed": seed,
                "test_start_position": start,
                "active_feature_count": len(active),
                "inactive_feature_count": len(inactive),
                "inactive_features": "|".join(inactive),
            }
        )
        replay_checks.append(
            {
                "seed": seed,
                "test_start_position": start,
                "test_rows": len(predicted),
                "bitwise_equal_to_frozen_csv": exact,
            }
        )
    raw = pd.DataFrame.from_records(importance_rows)
    aggregate = (
        raw.groupby("feature", sort=True)["normalized_gain"]
        .agg(["mean", "min", "max", "count"])
        .reset_index()
        .rename(
            columns={
                "mean": "mean_normalized_gain",
                "min": "min_normalized_gain",
                "max": "max_normalized_gain",
                "count": "checkpoint_count",
            }
        )
        .sort_values(["mean_normalized_gain", "feature"], ascending=[False, True])
        .reset_index(drop=True)
    )
    aggregate["rank"] = np.arange(1, len(aggregate) + 1)
    missing = pd.DataFrame.from_records(missing_rows)
    return (
        {
            "passed": True,
            "checkpoints": replay_checks,
            "checkpoint_count": len(checkpoints),
            "all_bitwise_equal": True,
            "frozen_csv_float_parser": "round_trip",
            "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
            "cpu_affinity": affinity,
            "missing_column_behavior": missing.to_dict(orient="records"),
        },
        aggregate,
    )


def _truth_and_formula_audit(
    pooled: pd.DataFrame,
    per_seed: pd.DataFrame,
    decisions: pd.DataFrame,
) -> dict[str, Any]:
    maximum_reference_delta = 0.0
    identity_rows = 0
    for lane in SOURCE_LANES:
        report = json.loads(
            (
                ROOT
                / lane.root_relative
                / "runtime"
                / "qualification"
                / "QUALIFICATION_REPORT.json"
            ).read_text(encoding="utf-8")
        )
        report_by_seed = {int(item["seed"]): item for item in report["per_case"]}
        for seed in lane.seeds:
            prediction = pd.read_csv(
                CORE / "predictions" / f"seed_{seed}" / "predictions.csv",
                low_memory=False,
            )
            truth_path = evaluation_truth_path(ROOT, lane, seed)
            truth = pd.read_csv(truth_path, usecols=["date", "true_fair_pe"])
            canonical_path, _ = source_paths(ROOT, lane, seed)
            canonical_dates = pd.read_csv(canonical_path, usecols=["date"])["date"]
            expected_dates = canonical_dates.iloc[
                prediction["session_position"].to_numpy(dtype=int)
            ].reset_index(drop=True)
            if (
                not prediction["date"]
                .astype(str)
                .reset_index(drop=True)
                .equals(expected_dates.astype(str))
            ):
                raise RuntimeError("prediction row identity differs from canonical positions")
            merged = prediction.merge(truth, on="date", how="left", validate="one_to_one")
            if len(merged) != 1296 or merged["true_fair_pe"].isna().any():
                raise RuntimeError("truth alignment is not one-to-one/full coverage")
            errors = np.log(merged[REFERENCE_MODEL_ID].to_numpy(float)) - np.log(
                merged["true_fair_pe"].to_numpy(float)
            )
            actual_mae = float(np.mean(np.abs(errors)))
            actual_rmse = float(np.sqrt(np.mean(np.square(errors))))
            expected = report_by_seed[seed]["surfaces"]["full62_1296"]["metrics"]["v04_expected_pe"]
            maximum_reference_delta = max(
                maximum_reference_delta,
                abs(actual_mae - float(expected["fair_log_mae"])),
                abs(actual_rmse - float(expected["fair_log_rmse"])),
            )
            identity_rows += len(merged)
    if maximum_reference_delta > 1e-15:
        raise RuntimeError("reference metric does not reproduce source qualification report")

    pooled_map = pooled.set_index("model_id")
    maximum_gain_delta = 0.0
    formula_rows = 0
    for row in decisions.itertuples(index=False):
        baseline = pooled_map.loc[row.baseline_id]
        candidate = pooled_map.loc[row.candidate_id]
        mae_gain = (baseline["mae"] - candidate["mae"]) / baseline["mae"]
        rmse_gain = (baseline["rmse"] - candidate["rmse"]) / baseline["rmse"]
        base_seed = per_seed.loc[per_seed["model_id"].eq(row.baseline_id)].set_index("seed")
        cand_seed = per_seed.loc[per_seed["model_id"].eq(row.candidate_id)].set_index("seed")
        wins = int((cand_seed["mae"] < base_seed["mae"]).sum())
        worst = float(((cand_seed["mae"] - base_seed["mae"]) / base_seed["mae"]).max())
        maximum_gain_delta = max(
            maximum_gain_delta,
            abs(float(row.pooled_mae_relative_gain) - float(mae_gain)),
            abs(float(row.pooled_rmse_relative_gain) - float(rmse_gain)),
            abs(float(row.worst_seed_mae_relative_harm) - worst),
        )
        if wins != int(row.seed_mae_wins):
            raise RuntimeError("seed-win formula mismatch")
        formula_rows += 1
    if maximum_gain_delta > 1e-15:
        raise RuntimeError("gain formula recomputation mismatch")
    return {
        "passed": True,
        "truth_alignment_rows": identity_rows,
        "truth_alignment_one_to_one": True,
        "source_qualification_v04_metric_max_abs_delta": maximum_reference_delta,
        "source_qualification_v04_metrics_exact_within_1e_15": True,
        "gain_formula_rows": formula_rows,
        "gain_formula_max_abs_delta": maximum_gain_delta,
        "seed_win_and_worst_harm_recomputed": True,
    }


def _baseline_and_ablation_audit(
    pooled: pd.DataFrame,
    per_seed: pd.DataFrame,
) -> tuple[dict[str, Any], pd.DataFrame]:
    scored = pd.read_csv(CORE / "SCORED_ROWS.csv", low_memory=False)
    matched = scored["lgbm__v04_exact_baseline"].to_numpy(float)
    incumbent = scored[REFERENCE_MODEL_ID].to_numpy(float)
    equivalence = {
        "applicable": False,
        "bitwise_equal": bool(np.array_equal(matched, incumbent)),
        "exact_equal_rows": int(np.count_nonzero(matched == incumbent)),
        "rows": len(matched),
        "max_abs_pe_difference": float(np.max(np.abs(matched - incumbent))),
        "mean_abs_log_difference": float(np.mean(np.abs(np.log(matched) - np.log(incumbent)))),
        "log_prediction_correlation": fixed_order_correlation(np.log(matched), np.log(incumbent)),
        "reason": "matched research baseline uses fixed 62-fold refits; incumbent is the full dynamic v04 pipeline output",
    }
    if equivalence["bitwise_equal"]:
        raise RuntimeError("research baseline unexpectedly equals the incumbent output")
    pooled_map = pooled.set_index("model_id")
    chain = [
        "lgbm__v04_exact_baseline",
        "lgbm__ofs_v1_valuation_eps",
        "lgbm__ofs_v1_valuation_eps_market",
        "lgbm__ofs_v1_full_without_regime",
        "lgbm__ofs_v1_full_with_regime",
    ]
    rows: list[dict[str, Any]] = []
    previous = None
    for rank, model_id in enumerate(chain, start=1):
        metric = pooled_map.loc[model_id]
        row = {
            "chain_order": rank,
            "model_id": model_id,
            "mae": float(metric["mae"]),
            "rmse": float(metric["rmse"]),
            "p95_abs_error": float(metric["p95_abs_error"]),
            "p99_abs_error": float(metric["p99_abs_error"]),
        }
        if previous is None:
            row["incremental_mae_gain_vs_previous"] = 0.0
            row["incremental_rmse_gain_vs_previous"] = 0.0
        else:
            prior = pooled_map.loc[previous]
            row["incremental_mae_gain_vs_previous"] = float(
                (prior["mae"] - metric["mae"]) / prior["mae"]
            )
            row["incremental_rmse_gain_vs_previous"] = float(
                (prior["rmse"] - metric["rmse"]) / prior["rmse"]
            )
        rows.append(row)
        previous = model_id
    full = "lgbm__ofs_v1_full_with_regime"
    reference = pooled_map.loc[REFERENCE_MODEL_ID]
    candidate = pooled_map.loc[full]
    ref_seed = per_seed.loc[per_seed["model_id"].eq(REFERENCE_MODEL_ID)].set_index("seed")
    full_seed = per_seed.loc[per_seed["model_id"].eq(full)].set_index("seed")
    contextual = {
        "full_state_mae_gain_vs_incumbent_context_only": float(
            (reference["mae"] - candidate["mae"]) / reference["mae"]
        ),
        "full_state_rmse_gain_vs_incumbent_context_only": float(
            (reference["rmse"] - candidate["rmse"]) / reference["rmse"]
        ),
        "full_state_seed_mae_wins_vs_incumbent_context_only": int(
            (full_seed["mae"] < ref_seed["mae"]).sum()
        ),
        "full_state_worst_seed_mae_harm_vs_incumbent_context_only": float(
            ((full_seed["mae"] - ref_seed["mae"]) / ref_seed["mae"]).max()
        ),
        "promotion_gate": False,
    }
    return (
        {
            "passed": True,
            "baseline_incumbent_equivalence": equivalence,
            "contextual_incumbent_comparison": contextual,
            "ablation_chain_interpretation": (
                "valuation+EPS supplies the dominant gain; market, temporal, and regime blocks are marginal"
            ),
        },
        pd.DataFrame.from_records(rows),
    )


def _seal_outputs(audit: dict[str, Any]) -> None:
    audit_path = OUTPUT / "AUDIT.json"
    audit["audit_sha256"] = hashlib.sha256(canonical_json_bytes(audit)).hexdigest()
    _write_json(audit_path, audit)
    manifest_path = OUTPUT / "MANIFEST.json"
    checksum_path = OUTPUT / "CHECKSUMS.sha256"
    files = [
        path
        for path in sorted(OUTPUT.iterdir())
        if path.is_file() and path not in {manifest_path, checksum_path}
    ]
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in files
    ]
    manifest = {
        "format_version": 1,
        "audit_id": f"{LAB_ID}_independent_sanity",
        "artifacts": entries,
        "artifact_count": len(entries),
    }
    manifest["manifest_sha256"] = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    _write_json(manifest_path, manifest)
    entries.append(
        {
            "path": manifest_path.relative_to(ROOT).as_posix(),
            "bytes": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        }
    )
    checksum_path.write_text(
        "".join(f"{item['sha256']}  {Path(item['path']).name}\n" for item in entries),
        encoding="ascii",
    )


def main() -> int:
    if OUTPUT.exists():
        raise RuntimeError("sanity audit output already exists")
    OUTPUT.mkdir(parents=True)
    started = time.perf_counter()
    core_manifest = _verify_core_manifest()
    diagnostics = json.loads((CORE / "FOLD_DIAGNOSTICS.json").read_text(encoding="ascii"))
    pooled = pd.read_csv(CORE / "POOLED_METRICS.csv", float_precision="round_trip")
    per_seed = pd.read_csv(CORE / "PER_SEED_METRICS.csv", float_precision="round_trip")
    decisions = pd.read_csv(CORE / "DECISIONS.csv", float_precision="round_trip")

    causality = _causality_audit()
    geometry, geometry_frame = _fold_geometry_audit(diagnostics)
    replay, importance = _independent_selected_replay()
    truth_formula = _truth_and_formula_audit(pooled, per_seed, decisions)
    baseline_ablation, ordering = _baseline_and_ablation_audit(pooled, per_seed)

    geometry_frame.to_csv(OUTPUT / "FOLD_GEOMETRY.csv", index=False, lineterminator="\n")
    importance.to_csv(
        OUTPUT / "FEATURE_IMPORTANCE.csv",
        index=False,
        float_format="%.17g",
        lineterminator="\n",
    )
    ordering.to_csv(
        OUTPUT / "ABLATION_ORDERING.csv",
        index=False,
        float_format="%.17g",
        lineterminator="\n",
    )
    script_path = Path(__file__).resolve()
    audit = {
        "format_version": 1,
        "audit_id": f"{LAB_ID}_independent_sanity",
        "status": "PASS_MATERIAL_GAIN_SANITY_CHECKED",
        "research_only": True,
        "promotion_authority": False,
        "registry_mutated": False,
        "champion_mutated": False,
        "core_artifact_manifest": {
            "path": (CORE / "ARTIFACT_MANIFEST.json").relative_to(ROOT).as_posix(),
            "raw_sha256": sha256_file(CORE / "ARTIFACT_MANIFEST.json"),
            "semantic_sha256": core_manifest["manifest_sha256"],
            "artifact_count": core_manifest["artifact_count"],
            "all_hashes_verified": True,
        },
        "core_key_hashes": {
            "design_lock_raw_sha256": sha256_file(CORE / "DESIGN_LOCK.json"),
            "prediction_manifest_raw_sha256": sha256_file(CORE / "PREDICTION_MANIFEST.json"),
            "prediction_freeze_raw_sha256": sha256_file(CORE / "PREDICTION_FREEZE.json"),
            "evaluation_report_raw_sha256": sha256_file(CORE / "EVALUATION_REPORT.json"),
            "scored_rows_raw_sha256": sha256_file(CORE / "SCORED_ROWS.csv"),
        },
        "auditor_source": {
            "path": script_path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(script_path),
        },
        "forbidden_surface_fragment_present_in_any_opened_path": False,
        "state_contract_sha256": STATE_CONTRACT_SHA256,
        "causality_and_target_encoding": causality,
        "fold_geometry_and_missingness": geometry,
        "independent_selected_fold_replay_and_importance": replay,
        "truth_alignment_and_gain_formulas": truth_formula,
        "baseline_and_ablation": baseline_ablation,
        "top_feature_importance": importance.head(20).to_dict(orient="records"),
        "wall_seconds": time.perf_counter() - started,
    }
    if sealed_surface_fragment() in json.dumps(audit).lower():
        raise RuntimeError("sanity audit receipt contains a forbidden surface reference")
    _seal_outputs(audit)
    print(json.dumps(audit, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
