"""Run the one authorized spent/public C2-R2 sparse-router research wave."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time
from typing import Any, Iterable, Mapping

for _thread_variable in (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ.setdefault(_thread_variable, "1")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from research.model_zoo.pe_c2_r2_sparse_router_v1.contracts import (  # noqa: E402
    BASE_COLUMNS,
    BASE_MODEL_ID,
    DGP_IDS,
    EVIDENCE_CLASS,
    FIRST_TEST_POSITION,
    IDENTITY_COLUMNS,
    PREDICTION_ROWS,
    PUBLIC_LOAD_COLUMNS,
    RESEARCH_TARGET,
    ROUTER_BASE_COLUMNS,
    ROUTER_FEATURE_COLUMNS,
    ROWS_PER_TASK,
    SEED_ALIASES,
    SEED_VALUES,
    TASK_COUNT,
    VARIANT_IDS,
    VARIANT_SPECS,
    WORKER_COUNT,
)
from research.model_zoo.pe_c2_r2_sparse_router_v1.metrics import evaluate  # noqa: E402
from research.model_zoo.pe_c2_r2_sparse_router_v1.router import (  # noqa: E402
    RouterTaskResult,
    route_task,
)


OUTPUT_ROOT = (
    PROJECT_ROOT / "outputs/model_zoo_pe_c2_r2_sparse_router_research_v1_20260825"
)
PRIOR_ROOT = PROJECT_ROOT / "outputs/model_zoo_pe_c2_r2_spent_research_v1_20260824"
SPENT_BCE_PREDICTIONS = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_"
    "20260821/PREDICTIONS.csv"
)
PUBLIC_ROOT = PROJECT_ROOT / "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
SPENT_TRUTH_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821/vault"
)
SPENT_TRUTH_RECEIPT = SPENT_TRUTH_ROOT.parent / "VAULT_RECEIPT.json"
EXPECTED_INPUT_HASHES = {
    "prior_design_lock": "a14526148642802143102820da4ae533c4fd8b9cc3916c6fc0a84d4b529616f8",
    "prior_predictions": "1a682967ccc5ddc4b3a695c6365ae0e4a87b7126b57dd3da6cd7a8ecd0482dd0",
    "prior_prediction_freeze": (
        "0f636ce606bbbcf305b13fc68d6d608a85d3b63ff73584e8f6ae67f5dd6b63f8"
    ),
    "prior_result": "8d097656175d7b4c766cbe703c762d083de525eda77abbf3c61e8397e63989fd",
    "prior_scorecard": "05d1df71ab5c9e98408c5b7356017849848bdb2f33371263996de301c9a1f548",
    "spent_bce_predictions": (
        "f2d38f9de31aa89d502050babb5df185fd35a30851701eb3a90e8c50fe64064b"
    ),
    "spent_truth_receipt": (
        "93c414a8d15d1a2cce0d0c173cb1ccd2d79001d003a8962d12b331ce98a3888b"
    ),
}
SOURCE_RELATIVES = (
    "research/model_zoo/pe_c2_r2_sparse_router_v1/__init__.py",
    "research/model_zoo/pe_c2_r2_sparse_router_v1/contracts.py",
    "research/model_zoo/pe_c2_r2_sparse_router_v1/metrics.py",
    "research/model_zoo/pe_c2_r2_sparse_router_v1/router.py",
    "scripts/model_lab/pe_c2_r2_sparse_router_research_v1.py",
)
OUTPUT_LEAVES = (
    "DESIGN_LOCK.json",
    "DETAILS.json",
    "INPUT_MANIFEST.json",
    "PREDICTIONS.csv",
    "PREDICTION_FREEZE.json",
    "PREFIX_CHRONOLOGY_RECEIPT.json",
    "REPORT.md",
    "RESOURCE_RECEIPT.json",
    "RESULT.json",
    "SOURCE_MANIFEST.json",
    "TRUTH_ACCESS_RECEIPT.json",
    "VARIANT_SCORECARD.csv",
)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _semantic(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _write_new(path: Path, raw: bytes) -> None:
    if type(raw) is not bytes or not raw:
        raise RuntimeError("research publication bytes differ")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise RuntimeError(f"research publication changed: {path.name}")


def _record(path: Path) -> dict[str, object]:
    return {
        "relative_path": path.relative_to(PROJECT_ROOT).as_posix(),
        "raw_sha256": _sha(path),
        "size_bytes": path.stat().st_size,
    }


def _canonical_path(seed: int, dgp: str) -> Path:
    return (
        PUBLIC_ROOT
        / "replays/pass_1"
        / f"seed_{seed}"
        / f"dgp_{dgp}"
        / "canonical150.csv"
    )


def _truth_path(seed: int, dgp: str) -> Path:
    return SPENT_TRUTH_ROOT / f"seed_{seed}" / f"dgp_{dgp}" / "truth.csv"


def _input_records() -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    anchors = {
        "prior_design_lock": _record(PRIOR_ROOT / "DESIGN_LOCK.json"),
        "prior_predictions": _record(PRIOR_ROOT / "PREDICTIONS.csv"),
        "prior_prediction_freeze": _record(PRIOR_ROOT / "PREDICTION_FREEZE.json"),
        "prior_result": _record(PRIOR_ROOT / "RESULT.json"),
        "prior_scorecard": _record(PRIOR_ROOT / "VARIANT_SCORECARD.csv"),
        "spent_bce_predictions": _record(SPENT_BCE_PREDICTIONS),
        "spent_truth_receipt": _record(SPENT_TRUTH_RECEIPT),
    }
    observed = {name: str(record["raw_sha256"]) for name, record in anchors.items()}
    if observed != EXPECTED_INPUT_HASHES:
        raise RuntimeError("C2-R2 sparse-router input anchor drifted")
    public_records = [
        {
            "task_ordinal": ordinal,
            "seed_alias": seed_alias,
            "relative_path": _canonical_path(seed, dgp).relative_to(PROJECT_ROOT).as_posix(),
            "raw_sha256": _sha(_canonical_path(seed, dgp)),
            "size_bytes": _canonical_path(seed, dgp).stat().st_size,
        }
        for ordinal, (seed_alias, seed, dgp) in enumerate(
            (
                (seed_alias, seed, dgp)
                for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True)
                for dgp in DGP_IDS
            )
        )
    ]
    if len(public_records) != TASK_COUNT:
        raise RuntimeError("public input record universe differs")
    return anchors, public_records


def _design(
    anchors: Mapping[str, Mapping[str, object]],
    public_records: list[dict[str, object]],
) -> dict[str, Any]:
    prior_result = json.loads((PRIOR_ROOT / "RESULT.json").read_text(encoding="utf-8"))
    if (
        prior_result.get("status") != "NO_VARIANT_MET_RESEARCH_TARGET"
        or prior_result.get("passed_variants_in_rank_order") != []
        or prior_result.get("recommended_variant") is not None
    ):
        raise RuntimeError("prior C2-R2 decision differs")
    core = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.design",
        "status": "FROZEN_BEFORE_ANY_NEW_TRUTH_OR_SCORE_ACCESS",
        "as_of_date": "2026-08-25",
        "evidence_class": EVIDENCE_CLASS,
        "base_model_id": BASE_MODEL_ID,
        "base_definition": "clip(alpha__bce_d*raw_log_consensus_correction,+/-log(1.04))",
        "variant_ids_in_order": list(VARIANT_IDS),
        "variant_count": len(VARIANT_IDS),
        "variant_specs": VARIANT_SPECS,
        "router_feature_columns": list(ROUTER_FEATURE_COLUMNS),
        "feature_policy": {
            "pit_observable_only": True,
            "current_row_observable_state_allowed": True,
            "thresholds_from_strict_prior_prefix_only": True,
            "prefix_calibration_label_count": 0,
            "dgp_name_used_as_feature": False,
            "true_or_future_feature_count": 0,
            "observed_pe_or_pe_gap_proxy_feature_count": 0,
            "qualification_or_heldout_feature_count": 0,
        },
        "actions": {
            "normal": "retain robust-cap correction",
            "high_risk": "multiply robust-cap correction by a fixed bounded scale",
            "extreme_risk": "reject correction to exact v04 prediction",
            "action_parameter_fit_count": 0,
        },
        "research_target": RESEARCH_TARGET,
        "selection_rule": (
            "conjunctive target pass first; then joint-tail, worst-DGP harm, "
            "worst-cell harm, higher MAE gain, lower action frequency, frozen variant order"
        ),
        "study_budget": {
            "authorized_sparse_router_study_count": 1,
            "variant_count_max": 5,
            "post_score_formula_or_threshold_change_allowed": False,
            "further_family_experiment_if_no_pass": False,
        },
        "failure_decision": "C2_RELIABILITY_REPAIR_FAMILY_SATURATED",
        "input_anchor_refs": dict(anchors),
        "public_input_records_semantic_sha256": _semantic(public_records),
        "public_input_record_count": len(public_records),
        "prior_spent_result_status": prior_result["status"],
        "new_truth_open_count_before_lock": 0,
        "new_score_count_before_lock": 0,
        "existing_c2_or_c4_formal_artifact_used_for_selection": False,
        "qualification_or_heldout_artifact_used_for_selection": False,
        "promotion_authority": False,
    }
    return {**core, "design_semantic_sha256": _semantic(core)}


def _load_base() -> tuple[pd.DataFrame, pd.DataFrame]:
    base = pd.read_csv(
        SPENT_BCE_PREDICTIONS,
        usecols=list(BASE_COLUMNS),
        float_precision="round_trip",
    ).loc[:, list(BASE_COLUMNS)]
    prior = pd.read_csv(
        PRIOR_ROOT / "PREDICTIONS.csv",
        usecols=[*IDENTITY_COLUMNS, BASE_MODEL_ID],
        float_precision="round_trip",
    ).loc[:, [*IDENTITY_COLUMNS, BASE_MODEL_ID]]
    if (
        len(base) != PREDICTION_ROWS
        or len(prior) != PREDICTION_ROWS
        or not base.loc[:, list(IDENTITY_COLUMNS)].equals(
            prior.loc[:, list(IDENTITY_COLUMNS)]
        )
    ):
        raise RuntimeError("spent robust-cap identity differs")
    return base, prior


def _route_job(
    job: tuple[int, int, str, str, pd.DataFrame],
) -> tuple[int, RouterTaskResult]:
    ordinal, seed, _seed_alias, dgp, base = job
    public = pd.read_csv(
        _canonical_path(seed, dgp),
        usecols=list(PUBLIC_LOAD_COLUMNS),
        float_precision="round_trip",
    ).loc[:, list(PUBLIC_LOAD_COLUMNS)]
    expected_public = public.iloc[FIRST_TEST_POSITION:].reset_index(drop=True)
    if not expected_public.loc[:, ["date", "symbol"]].astype(str).equals(
        base.loc[:, ["date", "symbol"]].astype(str).reset_index(drop=True)
    ):
        raise RuntimeError("public/router identity differs")
    return ordinal, route_task(
        base.loc[:, list(ROUTER_BASE_COLUMNS)].reset_index(drop=True),
        public.reset_index(drop=True),
    )


def _jobs(base: pd.DataFrame) -> list[tuple[int, int, str, str, pd.DataFrame]]:
    jobs = []
    ordinal = 0
    for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True):
        for dgp in DGP_IDS:
            task = base.loc[
                (base["seed_alias"] == seed_alias) & (base["dgp_id"] == dgp),
                list(BASE_COLUMNS),
            ].reset_index(drop=True)
            if len(task) != ROWS_PER_TASK:
                raise RuntimeError("sparse-router task split differs")
            jobs.append((ordinal, seed, seed_alias, dgp, task))
            ordinal += 1
    return jobs


def _run_jobs(
    jobs: list[tuple[int, int, str, str, pd.DataFrame]],
) -> list[RouterTaskResult]:
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=WORKER_COUNT, mp_context=context) as executor:
        rows = list(executor.map(_route_job, jobs, chunksize=1))
    rows.sort(key=lambda row: row[0])
    if [ordinal for ordinal, _ in rows] != list(range(TASK_COUNT)):
        raise RuntimeError("parallel sparse-router task order differs")
    return [result for _, result in rows]


def _aggregate_routes(results: Iterable[RouterTaskResult]) -> dict[str, dict[str, int | float]]:
    totals = {
        variant: {"rows": 0, "non_base_action_count": 0, "reject_to_v04_count": 0}
        for variant in VARIANT_IDS
    }
    for result in results:
        for variant in VARIANT_IDS:
            row = result.route_diagnostics[variant]
            for field in ("rows", "non_base_action_count", "reject_to_v04_count"):
                totals[variant][field] += int(row[field])
    for row in totals.values():
        rows = int(row["rows"])
        row["non_base_action_frequency"] = int(row["non_base_action_count"]) / rows
        row["reject_to_v04_frequency"] = int(row["reject_to_v04_count"]) / rows
    return totals


def _prediction_frame(
    base: pd.DataFrame,
    prior: pd.DataFrame,
    results: list[RouterTaskResult],
) -> tuple[pd.DataFrame, dict[str, np.ndarray], np.ndarray, np.ndarray]:
    robust = np.concatenate([result.base_log_prediction for result in results])
    prior_robust = pd.to_numeric(prior[BASE_MODEL_ID]).to_numpy(dtype=np.float64)
    if not np.allclose(robust, prior_robust, rtol=1e-13, atol=1e-13):
        raise RuntimeError("robust-cap base does not reconstruct the prior spent freeze")
    champion_log = np.log(
        pd.to_numeric(base["incumbent__v04_expected_pe"]).to_numpy(dtype=np.float64)
    )
    variants = {
        variant: np.concatenate([result.predictions[variant] for result in results])
        for variant in VARIANT_IDS
    }
    frame = base.loc[:, list(IDENTITY_COLUMNS)].copy()
    frame["base_robust_cap_log_pe"] = robust
    for variant in VARIANT_IDS:
        frame[variant] = variants[variant]
        frame[f"{variant}__scale"] = np.concatenate(
            [result.scales[variant] for result in results]
        )
    if len(frame) != PREDICTION_ROWS or frame.isna().any().any():
        raise RuntimeError("sparse-router prediction frame differs")
    return frame, variants, champion_log, robust


def _load_truth(identities: pd.DataFrame) -> tuple[np.ndarray, list[dict[str, object]]]:
    values: list[float] = []
    observed_identities: list[tuple[str, str, str]] = []
    refs = []
    for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True):
        for dgp in DGP_IDS:
            path = _truth_path(seed, dgp)
            frame = pd.read_csv(path, float_precision="round_trip").iloc[
                FIRST_TEST_POSITION:1800
            ]
            values.extend(pd.to_numeric(frame["true_log_fair_pe"]).tolist())
            observed_identities.extend(
                zip(
                    [seed_alias] * len(frame),
                    [dgp] * len(frame),
                    frame["date"].astype(str),
                    strict=True,
                )
            )
            refs.append(_record(path))
    expected = list(
        zip(
            identities["seed_alias"].astype(str),
            identities["dgp_id"].astype(str),
            identities["date"].astype(str),
            strict=True,
        )
    )
    target = np.asarray(values, dtype=np.float64)
    if observed_identities != expected or len(target) != PREDICTION_ROWS:
        raise RuntimeError("spent truth identity differs")
    if not np.isfinite(target).all() or len(refs) != TASK_COUNT:
        raise RuntimeError("spent truth geometry differs")
    return target, refs


def _report(table: pd.DataFrame, result: Mapping[str, Any]) -> bytes:
    lines = [
        "# C2-R2 Sparse Router Research Result",
        "",
        "Evidence: research-only, already spent/public synthetic surface.",
        "No C4, qualification, heldout, or formal artifact was used for candidate selection.",
        "",
        "| Variant | MAE gain | RMSE gain | Tail | Worst DGP | Worst cell | "
        "p95/p99/extreme | Action freq | Reject freq | Decision |",
        "|---|---:|---:|---:|---:|---:|---|---:|---:|---|",
    ]
    for row in table.to_dict(orient="records"):
        tails = "/".join(
            "PASS" if bool(row[field]) else "FAIL"
            for field in (
                "pooled_p95_non_worse",
                "pooled_p99_non_worse",
                "pooled_extreme_frequency_non_worse",
            )
        )
        lines.append(
            "| {variant} | {mae:.4%} | {rmse:.4%} | {tail} | {dgp:.4%} | "
            "{cell:.4%} | {tails} | {action:.4%} | {reject:.4%} | {decision} |".format(
                variant=row["variant"],
                mae=row["research_mae_gain"],
                rmse=row["research_rmse_gain"],
                tail=row["joint_tail_failures"],
                dgp=row["worst_dgp_harm"],
                cell=row["worst_cell_harm"],
                tails=tails,
                action=row["non_base_action_frequency"],
                reject=row["reject_to_v04_frequency"],
                decision=row["decision"],
            )
        )
    lines.extend(
        [
            "",
            f"Family decision: `{result['family_decision']}`",
            f"Recommended research survivor: `{result['recommended_variant']}`",
            "",
            "A survivor, if any, still requires a new identity and fresh formal evidence.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def run(output_root: Path = OUTPUT_ROOT) -> dict[str, Any]:
    start_time = time.perf_counter()
    root = Path(output_root).resolve(strict=False)
    if root != OUTPUT_ROOT.resolve(strict=False) or root.exists():
        raise RuntimeError("C2-R2 sparse-router output identity is invalid or consumed")
    anchors, public_records = _input_records()
    source_records = [_record(PROJECT_ROOT / relative) for relative in SOURCE_RELATIVES]
    root.mkdir(parents=False)
    design = _design(anchors, public_records)
    _write_new(root / "DESIGN_LOCK.json", _json_bytes(design))
    input_manifest = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.inputs",
        "status": "BOUND_SPENT_PUBLIC_INPUTS_ONLY",
        "anchor_refs": anchors,
        "public_source_records": public_records,
        "public_source_records_semantic_sha256": _semantic(public_records),
        "truth_receipt_ref": anchors["spent_truth_receipt"],
        "truth_leaf_open_count": 0,
        "c4_input_count": 0,
        "qualification_or_heldout_input_count": 0,
    }
    _write_new(root / "INPUT_MANIFEST.json", _json_bytes(input_manifest))

    base, prior = _load_base()
    jobs = _jobs(base)
    route_started = time.perf_counter()
    results = _run_jobs(jobs)
    prediction_frame, variants, champion_log, robust_log = _prediction_frame(
        base, prior, results
    )
    prediction_raw = prediction_frame.to_csv(index=False, lineterminator="\n").encode(
        "utf-8"
    )
    prediction_hash = hashlib.sha256(prediction_raw).hexdigest()
    route_seconds = time.perf_counter() - route_started

    repeat_results = _run_jobs(jobs)
    repeat_frame, _, _, _ = _prediction_frame(base, prior, repeat_results)
    repeat_raw = repeat_frame.to_csv(index=False, lineterminator="\n").encode("utf-8")
    if repeat_raw != prediction_raw:
        raise RuntimeError("independent sparse-router prediction replay differs")
    _write_new(root / "PREDICTIONS.csv", prediction_raw)
    aggregate_routes = _aggregate_routes(results)
    prefix_rows = sum(int(result.prefix_receipt["rows"]) for result in results)
    strict_threshold_rows = sum(
        int(result.prefix_receipt["strict_prefix_threshold_rows"]) for result in results
    )
    strict_decision_rows = sum(
        int(result.prefix_receipt["strict_prior_decision_rows"]) for result in results
    )
    prefix_receipt = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.prefix_receipt",
        "status": "PASS_STRICT_PIT_PREFIX_NO_LABEL_CALIBRATION",
        "rows": prefix_rows,
        "strict_prefix_threshold_rows": strict_threshold_rows,
        "strict_prior_decision_rows": strict_decision_rows,
        "all_prefix_sources_strictly_before_prediction": (
            prefix_rows == strict_threshold_rows == strict_decision_rows == PREDICTION_ROWS
        ),
        "prefix_calibration_label_count": 0,
        "truth_or_score_used_for_thresholds": False,
        "dgp_label_used_as_feature": False,
        "current_row_true_or_future_feature_count": 0,
    }
    if not prefix_receipt["all_prefix_sources_strictly_before_prediction"]:
        raise RuntimeError("sparse-router prefix receipt failed")
    _write_new(root / "PREFIX_CHRONOLOGY_RECEIPT.json", _json_bytes(prefix_receipt))
    freeze = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.prediction_freeze",
        "status": "FROZEN_FIVE_SPARSE_ROUTERS_BEFORE_SPENT_TRUTH_SCORE",
        "design_lock_raw_sha256": _sha(root / "DESIGN_LOCK.json"),
        "prediction_raw_sha256": prediction_hash,
        "prediction_rows": len(prediction_frame),
        "variant_ids_in_order": list(VARIANT_IDS),
        "route_diagnostics": aggregate_routes,
        "independent_prediction_replay_raw_sha256": hashlib.sha256(
            repeat_raw
        ).hexdigest(),
        "independent_prediction_digest_equal": True,
        "truth_open_count_before_freeze": 0,
        "score_count_before_freeze": 0,
        "formal_authority": False,
    }
    _write_new(root / "PREDICTION_FREEZE.json", _json_bytes(freeze))

    truth_log, truth_refs = _load_truth(base.loc[:, list(IDENTITY_COLUMNS)])
    truth_receipt = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.truth_access",
        "status": "OPENED_EXACT_SPENT_TRUTH_AFTER_PREDICTION_FREEZE",
        "prediction_freeze_ref": _record(root / "PREDICTION_FREEZE.json"),
        "prediction_ref": _record(root / "PREDICTIONS.csv"),
        "truth_refs": truth_refs,
        "truth_ref_count": len(truth_refs),
        "truth_rows": len(truth_log),
        "truth_opened_after_prediction_freeze": True,
        "latent_or_pass_2_open_count": 0,
        "qualification_or_heldout_open_count": 0,
    }
    _write_new(root / "TRUTH_ACCESS_RECEIPT.json", _json_bytes(truth_receipt))
    table, details = evaluate(
        identities=base.loc[:, list(IDENTITY_COLUMNS)],
        champion_log=champion_log,
        robust_cap_log=robust_log,
        variants=variants,
        truth_log=truth_log,
        route_diagnostics=aggregate_routes,
    )
    scorecard_raw = table.to_csv(index=False, lineterminator="\n").encode("utf-8")
    _write_new(root / "VARIANT_SCORECARD.csv", scorecard_raw)
    _write_new(root / "DETAILS.json", _json_bytes(details))
    passed = table.loc[table["research_target_pass"], "variant"].tolist()
    recommended = passed[0] if passed else None
    result = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.result",
        "status": "PASS_RESEARCH_SURVIVOR_FOUND" if passed else "NO_ROUTER_MET_TARGET",
        "family_decision": (
            "FREEZE_ONE_C2_R2_SPARSE_ROUTER_RESEARCH_SURVIVOR"
            if passed
            else "C2_RELIABILITY_REPAIR_FAMILY_SATURATED"
        ),
        "evidence_class": EVIDENCE_CLASS,
        "passed_variants_in_rank_order": passed,
        "recommended_variant": recommended,
        "research_target": RESEARCH_TARGET,
        "formal_qualification_required": bool(passed),
        "existing_c2_or_c4_formal_evidence_inherited": False,
        "qualification_or_heldout_used_for_selection": False,
        "c4_error_correlation_computed": False,
        "c4_error_correlation_omission_reason": (
            "C4 artifacts were excluded from this isolated lane by contract"
        ),
        "post_score_router_tuning_allowed": False,
        "further_reliability_repair_experiment_allowed": False,
        "promotion_authority": False,
        "scorecard_raw_sha256": hashlib.sha256(scorecard_raw).hexdigest(),
    }
    _write_new(root / "RESULT.json", _json_bytes(result))
    _write_new(root / "REPORT.md", _report(table, result))
    source_manifest = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.sources",
        "status": "SOURCE_BOUND_RESEARCH_ONLY",
        "source_records": source_records,
        "source_records_semantic_sha256": _semantic(source_records),
        "source_record_count": len(source_records),
        "formal_source_freeze": False,
    }
    _write_new(root / "SOURCE_MANIFEST.json", _json_bytes(source_manifest))
    resource_receipt = {
        "schema_version": "expected_pe.c2_r2.sparse_router_research.v1.resources",
        "status": "COMPLETED_BOUNDED_CPU_LANE",
        "logical_cpu_count": os.cpu_count(),
        "outer_process_workers": WORKER_COUNT,
        "inner_thread_limits": {
            name: os.environ.get(name)
            for name in (
                "OMP_NUM_THREADS",
                "MKL_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
            )
        },
        "task_count_per_prediction_pass": TASK_COUNT,
        "prediction_pass_count": 2,
        "route_first_pass_seconds": route_seconds,
        "total_wall_seconds_before_receipt": time.perf_counter() - start_time,
        "prediction_rows_per_first_pass_second": PREDICTION_ROWS / route_seconds,
        "deterministic_replay_equal": True,
        "gpu_used": False,
        "gpu_omission_reason": "bounded sparse routers are CPU-only",
    }
    _write_new(root / "RESOURCE_RECEIPT.json", _json_bytes(resource_receipt))
    if tuple(sorted(path.name for path in root.iterdir())) != tuple(sorted(OUTPUT_LEAVES)):
        raise RuntimeError("sparse-router pre-checksum leaf universe differs")
    checksums = "".join(f"{_sha(root / leaf)}  {leaf}\n" for leaf in OUTPUT_LEAVES).encode(
        "ascii"
    )
    _write_new(root / "CHECKSUMS.sha256", checksums)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.output_root), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
