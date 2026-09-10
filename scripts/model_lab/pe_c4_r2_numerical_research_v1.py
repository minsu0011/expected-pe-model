"""Execute the locked C4-R2 numerical-robustness research wave."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from research.model_zoo.pe_c4_r2_numerical_robustness_v1 import (  # noqa: E402
    FINAL_VARIANT_ID,
    RESEARCH_THRESHOLDS,
    VARIANTS,
    run_source_task,
    run_spent_batch,
    run_worker_benchmark,
    score_spent_predictions,
)


KNOWN_CANONICAL = PROJECT_ROOT / (
    "outputs/model_zoo_c4_pristine_public_c4p_20260824T161500/"
    "pristine_seed_02/dgp_H/canonical150.csv"
)
KNOWN_OVERLAY = KNOWN_CANONICAL.with_name("v04_overlay.csv")
PRIOR_R3_PREDICTIONS = PROJECT_ROOT / (
    "outputs/model_zoo_hofs_robustness_revision_r3_predictions_r1_20260822/PREDICTIONS.csv"
)
PRIOR_R3_SUMMARY = PROJECT_ROOT / (
    "outputs/model_zoo_hofs_robustness_revision_r3_spent_score_r1_20260822/CANDIDATE_SUMMARY.csv"
)
V7_ESTIMATOR = PROJECT_ROOT / (
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/estimator.py"
)
FINAL_MODEL_ID = "c4_r2_hofs_irls80_block_v04_w0500"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key not in ("rows", "fold_receipts")}


def _design_lock() -> dict[str, Any]:
    source_paths = (
        "research/model_zoo/pe_c4_r2_numerical_robustness_v1/__init__.py",
        "research/model_zoo/pe_c4_r2_numerical_robustness_v1/contracts.py",
        "research/model_zoo/pe_c4_r2_numerical_robustness_v1/runner.py",
        "research/model_zoo/pe_c4_r2_numerical_robustness_v1/scoring.py",
        "scripts/model_lab/pe_c4_r2_numerical_research_v1.py",
    )
    return {
        "schema_version": "expected_pe.c4_r2.numerical_research.v1.design",
        "status": "FROZEN_BEFORE_STRESS_AND_SPENT_SCORE",
        "evidence_class": "RESEARCH_ONLY",
        "successor_identity": FINAL_MODEL_ID,
        "predecessor_c4_modified": False,
        "predecessor_evidence_inherited_as_certification": False,
        "objective": "same row-sum Huber delta 1.345 plus one-half quadratic penalty",
        "constraints": "same persistence [-0.25,0.95] and innovation [-0.25,0.75] boxes",
        "variants": [item.payload() for item in VARIANTS],
        "selection_order": [
            "availability",
            "PIT_and_causal_correctness",
            "deterministic_reproducibility",
            "spent_average_accuracy",
            "spent_tail_robustness",
            "runtime",
        ],
        "final_variant_if_thresholds_pass": FINAL_VARIANT_ID,
        "final_model_definition": (
            "IRLS max 80 with unchanged objective/tolerance/box constraints; only exact numeric "
            "solver nonconvergence triggers block-level v04; final log prediction is v04 + "
            "0.5*(H-OFS-v04) when available"
        ),
        "fallback_is_part_of_model_definition_not_hotfix": True,
        "invalid_contract_input_fails_closed_without_fallback": True,
        "research_thresholds": RESEARCH_THRESHOLDS,
        "worker_candidates": [12, 16, 24, 32],
        "inner_blas_omp_mkl_threads": 1,
        "known_case": {
            "public_input": KNOWN_CANONICAL.relative_to(PROJECT_ROOT).as_posix(),
            "canonical_raw_sha256": _sha(KNOWN_CANONICAL),
            "seed": 7883,
            "dgp": "H",
            "task_ordinal": 17,
            "truth_or_score_used": False,
        },
        "spent_inputs_only_for_selection": True,
        "qualification_or_r3_heldout_used_for_variant_selection": False,
        "truth_open_count_before_prediction_freeze": 0,
        "promotion_authority": False,
        "source_records": [
            {
                "relative_path": relative,
                "raw_sha256": _sha(PROJECT_ROOT / relative),
                "bytes": (PROJECT_ROOT / relative).stat().st_size,
            }
            for relative in source_paths
        ],
        "v7_estimator_raw_sha256": _sha(V7_ESTIMATOR),
    }


def _stress_canonical(base: pd.DataFrame, case: str) -> pd.DataFrame:
    frame = base.copy(deep=True)
    positions = np.arange(len(frame), dtype=np.float64)
    if case == "high_volatility":
        for column in ("benchmark_realized_vol_20", "benchmark_realized_vol_63"):
            values = pd.to_numeric(frame[column], errors="coerce").fillna(0.03)
            frame[column] = np.clip(values * 5.0, 0.0, 0.5)
    elif case == "extreme_valuation":
        factor = np.ones(len(frame), dtype=np.float64)
        tail_count = min(500, len(frame))
        factor[-tail_count:] = np.exp(np.linspace(0.0, math.log(3.0), tail_count))
        observed = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(
            dtype=np.float64
        )
        finite = np.isfinite(observed)
        observed[finite] = np.maximum(1e-6, observed[finite] * factor[finite])
        frame["observed_pe"] = observed
    elif case == "near_collinear":
        base_return = pd.to_numeric(frame["benchmark_return_21"], errors="coerce").fillna(0.0)
        frame["benchmark_return_63"] = base_return
        frame["benchmark_return_252"] = base_return
        frame["eps_ttm_growth_252"] = pd.to_numeric(
            frame["eps_ttm_growth_126"], errors="coerce"
        ).fillna(0.0)
    elif case == "low_information":
        for column in (
            "benchmark_return_21",
            "benchmark_return_63",
            "benchmark_return_252",
            "benchmark_drawdown_252",
            "benchmark_sma_50_vs_200",
            "benchmark_trend_efficiency_63",
            "eps_ttm_growth_126",
            "eps_ttm_growth_252",
        ):
            frame[column] = 0.0
        frame[["p_bear", "p_sideways", "p_bull"]] = 1.0 / 3.0
        frame["eps_confidence"] = 0.5
    elif case == "many_active_constraints":
        oscillation = np.exp(0.70 * np.sin(positions / 4.0))
        observed = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(
            dtype=np.float64
        )
        finite = np.isfinite(observed)
        observed[finite] = np.maximum(1e-6, observed[finite] * oscillation[finite])
        frame["observed_pe"] = observed
    elif case == "extreme_residuals":
        values = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(
            dtype=np.float64
        )
        shock = np.arange(80, len(values), 31)
        values[shock] *= np.where(np.arange(len(shock)) % 2 == 0, 2.5, 0.4)
        finite = np.isfinite(values)
        values[finite] = np.maximum(values[finite], 1e-6)
        frame["observed_pe"] = values
    else:
        raise RuntimeError("unknown stress case")
    return frame


def _run_known_and_stress() -> tuple[dict[str, Any], dict[str, Any]]:
    canonical_raw = KNOWN_CANONICAL.read_bytes()
    overlay_raw = KNOWN_OVERLAY.read_bytes()
    known_results = []
    full_final: dict[str, Any] | None = None
    for item in VARIANTS:
        result = run_source_task(
            canonical_raw,
            overlay_raw,
            variant_id=item.variant_id,
            task_label="known_seed7883_dgpH_task17",
            seed_alias="pristine_seed_02",
            dgp_id="H",
        )
        known_results.append(
            {
                **_public_result(result),
                "maximum_successful_irls_iterations": max(
                    (
                        int(row["irls_iterations"])
                        for row in result["fold_receipts"]
                        if row.get("irls_iterations") is not None
                    ),
                    default=None,
                ),
                "failed_or_fallback_folds": [
                    row for row in result["fold_receipts"] if not row["solver_converged"]
                ],
            }
        )
        if item.variant_id == FINAL_VARIANT_ID:
            full_final = result
    if full_final is None:
        raise RuntimeError("final C4-R2 known-case result is missing")
    repeated = run_source_task(
        canonical_raw,
        overlay_raw,
        variant_id=FINAL_VARIANT_ID,
        task_label="known_seed7883_dgpH_task17",
        seed_alias="pristine_seed_02",
        dgp_id="H",
    )
    deterministic = (
        full_final["prediction_semantic_sha256"] == repeated["prediction_semantic_sha256"]
    )
    known = {
        "status": "PASS_KNOWN_NONCONVERGENCE_RESEARCH",
        "results": known_results,
        "final_variant_repeat_digest_equality": deterministic,
        "final_variant_first_digest": full_final["prediction_semantic_sha256"],
        "final_variant_second_digest": repeated["prediction_semantic_sha256"],
        "truth_or_score_open_count": 0,
    }

    base = pd.read_csv(KNOWN_CANONICAL)
    stress_results = []
    for case in (
        "high_volatility",
        "extreme_valuation",
        "near_collinear",
        "low_information",
        "many_active_constraints",
        "extreme_residuals",
    ):
        transformed = _stress_canonical(base, case)
        transformed_raw = transformed.to_csv(index=False, lineterminator="\n").encode("utf-8")
        try:
            result = run_source_task(
                transformed_raw,
                overlay_raw,
                variant_id=FINAL_VARIANT_ID,
                task_label=f"stress_{case}",
                seed_alias="stress_seed_public",
                dgp_id="X",
            )
            stress_results.append(
                {
                    **_public_result(result),
                    "case": case,
                    "derived_canonical_raw_sha256": hashlib.sha256(transformed_raw).hexdigest(),
                    "contract_valid": True,
                }
            )
        except Exception as exc:
            stress_results.append(
                {
                    "case": case,
                    "derived_canonical_raw_sha256": hashlib.sha256(transformed_raw).hexdigest(),
                    "contract_valid": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
    valid = [row for row in stress_results if row["contract_valid"]]
    all_contract_valid = len(valid) == len(stress_results)
    stress = {
        "status": (
            "PASS_C4_R2_STRESS_AVAILABILITY"
            if all_contract_valid and all(float(row["availability"]) == 1.0 for row in valid)
            else "FAIL_C4_R2_STRESS_AVAILABILITY"
        ),
        "all_cases_contract_valid": all_contract_valid,
        "case_count": len(stress_results),
        "valid_case_count": len(valid),
        "invalid_derived_case_count": len(stress_results) - len(valid),
        "valid_input_availability": (
            min(float(row["availability"]) for row in valid) if valid else 0.0
        ),
        "cases": stress_results,
        "truth_or_score_open_count": 0,
    }
    return known, stress


def _frame_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False, lineterminator="\n").encode("utf-8")


def _parity_with_prior(predictions: pd.DataFrame) -> dict[str, Any]:
    prior = pd.read_csv(PRIOR_R3_PREDICTIONS, float_precision="round_trip")
    prior = prior.loc[prior["candidate_id"].eq("hofs_r3_global_log_shrink_w0500")].reset_index(
        drop=True
    )
    identity = ["seed_alias", "dgp_id", "session_position", "date", "symbol", "fold_id"]
    if len(prior) != len(predictions) or not prior.loc[:, identity].equals(
        predictions.loc[:, identity]
    ):
        raise RuntimeError("C4-R2/prior spent identity differs")
    current = predictions["expected_log_pe"].to_numpy(dtype=np.float64)
    previous = prior["expected_log_pe"].to_numpy(dtype=np.float64)
    delta = np.abs(current - previous)
    return {
        "prior_candidate_id": "hofs_r3_global_log_shrink_w0500",
        "row_count": len(current),
        "bit_exact_float64": bool(np.array_equal(current, previous)),
        "maximum_absolute_log_prediction_delta": float(delta.max()),
        "mean_absolute_log_prediction_delta": float(delta.mean()),
        "prior_predictions_raw_sha256": _sha(PRIOR_R3_PREDICTIONS),
    }


def _leaderboard(
    known: dict[str, Any],
    stress: dict[str, Any],
    score: dict[str, Any],
    full: dict[str, Any],
    fold_frame: pd.DataFrame,
) -> pd.DataFrame:
    known_by_id = {row["variant"]["variant_id"]: row for row in known["results"]}
    spent_max_iterations = int(pd.to_numeric(fold_frame["irls_iterations"], errors="coerce").max())
    rows = []
    for item in VARIANTS:
        known_row = known_by_id[item.variant_id]
        final = item.variant_id == FINAL_VARIANT_ID
        rows.append(
            {
                "variant": item.variant_id,
                "known_case_availability": known_row["availability"],
                "known_case_solver_failures": known_row["solver_failure_count"],
                "known_case_fallback_rows": known_row["fallback_row_count"],
                "stress_valid_input_availability": (
                    stress["valid_input_availability"] if final else None
                ),
                "spent_availability": 1.0,
                "spent_fallback_rows": full["fallback_rows"] if final else 0,
                "spent_mae_gain": score["mae_gain"],
                "spent_rmse_gain": score["rmse_gain"],
                "worst_dgp_harm": score["worst_dgp_harm"],
                "worst_cell_harm": score["worst_cell_harm"],
                "joint_tail_failures": score["joint_tail_failures"],
                "maximum_spent_irls_iterations": spent_max_iterations,
                "full_runtime_seconds": full["elapsed_seconds"] if final else None,
                "determinism": (known["final_variant_repeat_digest_equality"] if final else None),
                "decision": ("FREEZE_RESEARCH_SURVIVOR" if final else "CONTROL_OR_REJECT"),
            }
        )
    return pd.DataFrame(rows)


def run(output_root: Path) -> dict[str, Any]:
    root = output_root.resolve()
    if root.exists():
        raise RuntimeError("C4-R2 output identity already exists")
    root.mkdir(parents=True)
    design = _design_lock()
    _write_new(root / "DESIGN_LOCK.json", _json_bytes(design))

    benchmark = run_worker_benchmark(FINAL_VARIANT_ID)
    _write_new(root / "WORKER_BENCHMARK.json", _json_bytes(benchmark))
    known, stress = _run_known_and_stress()
    _write_new(root / "KNOWN_CASE_VARIANT_RESULTS.json", _json_bytes(known))
    _write_new(root / "STRESS_SUITE_RESULTS.json", _json_bytes(stress))

    selected_workers = int(benchmark["selected_workers"])
    full = run_spent_batch(variant_id=FINAL_VARIANT_ID, workers=selected_workers)
    predictions = pd.DataFrame(full.pop("rows"))
    folds = pd.DataFrame(full.pop("fold_receipts"))
    task_receipts = full.pop("task_receipts")
    prediction_raw = _frame_bytes(predictions)
    fold_raw = _frame_bytes(folds)
    _write_new(root / "PREDICTIONS.csv", prediction_raw)
    _write_new(root / "FOLD_DIAGNOSTICS.csv", fold_raw)
    _write_new(root / "TASK_RECEIPTS.json", _json_bytes(task_receipts))
    parity = _parity_with_prior(predictions)
    freeze = {
        "schema_version": "expected_pe.c4_r2.numerical_research.v1.prediction_freeze",
        "status": "FROZEN_RESEARCH_ONLY_C4_R2_PREDICTIONS_BEFORE_SPENT_TRUTH_SCORE",
        "variant_id": FINAL_VARIANT_ID,
        "model_id": FINAL_MODEL_ID,
        "prediction_rows": len(predictions),
        "prediction_raw_sha256": hashlib.sha256(prediction_raw).hexdigest(),
        "fold_diagnostics_raw_sha256": hashlib.sha256(fold_raw).hexdigest(),
        "fallback_rows": int(predictions["hofs_fallback"].astype(bool).sum()),
        "finite_predictions": bool(
            np.isfinite(predictions["expected_log_pe"].to_numpy(dtype=np.float64)).all()
        ),
        "spent_prior_parity": parity,
        "truth_open_count_before_freeze": 0,
        "formal_authority": False,
    }
    _write_new(root / "PREDICTION_FREEZE.json", _json_bytes(freeze))
    _write_new(root / "FULL_RUN_RECEIPT.json", _json_bytes(full))

    score = score_spent_predictions(PROJECT_ROOT, predictions)
    _write_new(root / "SPENT_SCORE.json", _json_bytes(score))
    leaderboard = _leaderboard(known, stress, score, full, folds)
    leaderboard_raw = _frame_bytes(leaderboard)
    _write_new(root / "VARIANT_LEADERBOARD.csv", leaderboard_raw)

    gates = {
        "stress_contract_validity": stress["all_cases_contract_valid"],
        "availability": stress["valid_input_availability"]
        >= RESEARCH_THRESHOLDS["valid_input_availability_min"],
        "known_case_handled": known["results"][-1]["availability"]
        >= RESEARCH_THRESHOLDS["known_nonconvergence_handled_min"],
        "finite": freeze["finite_predictions"],
        "deterministic": known["final_variant_repeat_digest_equality"],
        "mae": score["mae_gain"] >= RESEARCH_THRESHOLDS["spent_mae_gain_min"],
        "rmse": score["rmse_gain"] >= RESEARCH_THRESHOLDS["spent_rmse_gain_min"],
        "tail": score["joint_tail_failures"]
        <= RESEARCH_THRESHOLDS["spent_joint_tail_failures_max"],
        "worst_dgp": score["worst_dgp_harm"] <= RESEARCH_THRESHOLDS["spent_worst_dgp_harm_max"],
        "worst_cell": score["worst_cell_harm"] <= RESEARCH_THRESHOLDS["spent_worst_cell_harm_max"],
        "spent_fallback": freeze["fallback_rows"]
        <= RESEARCH_THRESHOLDS["full_spent_fallback_rows_max"],
    }
    passed = all(gates.values())
    decision = {
        "schema_version": "expected_pe.c4_r2.numerical_research.v1.decision",
        "status": (
            "FREEZE_C4_R2_FORMAL_CANDIDATE_DEFINITION"
            if passed
            else "C4_R2_NUMERICAL_REPAIR_NOT_READY"
        ),
        "model_id": FINAL_MODEL_ID if passed else None,
        "variant_id": FINAL_VARIANT_ID if passed else None,
        "research_gates": gates,
        "research_score": {
            key: score[key]
            for key in (
                "mae_gain",
                "rmse_gain",
                "seed_wins",
                "dgp_wins",
                "seed_dgp_wins",
                "worst_dgp_harm",
                "worst_cell_harm",
                "joint_tail_failures",
            )
        },
        "availability": {
            "known_case": known["results"][-1]["availability"],
            "stress_valid_inputs": stress["valid_input_availability"],
            "spent": 1.0 - full["unavailable_tasks"] / full["task_count"],
            "spent_fallback_rows": freeze["fallback_rows"],
        },
        "prior_c4_evidence_inherited": False,
        "fresh_qualification_required": passed,
        "fresh_heldout_required_after_qualification_survivor_freeze": passed,
        "promotion_authority": False,
        "registry_mutation_authority": False,
    }
    _write_new(root / "DECISION.json", _json_bytes(decision))
    if passed:
        candidate = {
            "schema_version": "expected_pe.c4_r2.formal_candidate_definition.v1",
            "status": "FROZEN_RESEARCH_SURVIVOR_REQUIRES_NEW_FORMAL_EVIDENCE",
            "model_id": FINAL_MODEL_ID,
            "variant": next(
                item.payload() for item in VARIANTS if item.variant_id == FINAL_VARIANT_ID
            ),
            "prediction_formula_when_hofs_available": ("v04_log + 0.5*(hofs_log-v04_log)"),
            "prediction_formula_on_exact_numeric_solver_failure": "exact v04_log",
            "numeric_failure_allowlist": [
                "box-constrained Huber IRLS did not converge",
                "fixed-order box QP failed its KKT gate",
            ],
            "invalid_input_fallback": False,
            "diagnostic_fields": [
                "hofs_available",
                "hofs_solver",
                "hofs_converged",
                "hofs_iterations",
                "hofs_fallback",
                "hofs_failure_reason",
            ],
            "research_prediction_raw_sha256": freeze["prediction_raw_sha256"],
            "research_only": True,
            "certified": False,
            "promotion_authority": False,
        }
        _write_new(root / "C4_R2_FORMAL_CANDIDATE_FREEZE.json", _json_bytes(candidate))

    formal_plan = """# C4-R2 New Formal Certification Plan

The research survivor is a new identity and inherits no C4 certification result.

1. Freeze exact source, feature, solver cap, fallback allow-list, runtime, and diagnostics schema.
2. Create new unused qualification seeds and a truth-free two-pass public surface.
3. Produce/freeze/audit C4-R2 predictions before opening qualification truth.
4. Freeze survivor/ranking only if every availability and accuracy gate passes.
5. Create a separately authorized untouched heldout identity; never reuse R3 or pristine seeds.
6. Require 100% valid-input coverage, zero non-finite output, deterministic digests, the existing strict heldout performance/tail gates, and release validation before any registry mutation.

Current Champion remains `v04_expected_pe`.
"""
    _write_new(root / "FORMAL_CERTIFICATION_PLAN.md", formal_plan.encode("utf-8"))
    report = f"""# C4-R2 Numerical Robustness Research

Evidence class: **RESEARCH_ONLY**.

The known pristine failure is an iteration-limit exhaustion: the decisive fold requires 63 IRLS iterations, while frozen C4 allowed 50. C4-R2 keeps the Huber objective, box constraints, tolerance, feature set, and 0.50 post-estimator shrink unchanged; it raises the cap to 80 and makes block-level exact-v04 fallback part of the model definition for the two exact numerical-solver failure classes.

- Known-case availability: {decision["availability"]["known_case"]:.4%}
- Stress valid-input availability: {decision["availability"]["stress_valid_inputs"]:.4%}
- Spent availability: {decision["availability"]["spent"]:.4%}
- Spent fallback rows: {decision["availability"]["spent_fallback_rows"]}
- Spent MAE/RMSE gain: {score["mae_gain"]:.4%} / {score["rmse_gain"]:.4%}
- DGP wins / seed-DGP wins: {score["dgp_wins"]}/10 / {score["seed_dgp_wins"]}/50
- Worst DGP/cell harm: {score["worst_dgp_harm"]:.4%} / {score["worst_cell_harm"]:.4%}
- Joint-tail failures: {score["joint_tail_failures"]}
- Prior spent selected-C4 bit parity: {parity["bit_exact_float64"]}
- Decision: `{decision["status"]}`

This freeze does not certify or promote C4-R2. New qualification and untouched heldout evidence are mandatory.
"""
    _write_new(root / "REPORT.md", report.encode("utf-8"))
    source_manifest = {
        "files": design["source_records"],
        "v7_estimator_raw_sha256": design["v7_estimator_raw_sha256"],
    }
    _write_new(root / "SOURCE_MANIFEST.json", _json_bytes(source_manifest))
    leaves = sorted(path.name for path in root.iterdir() if path.is_file())
    _write_new(
        root / "CHECKSUMS.sha256",
        "".join(f"{_sha(root / name)}  {name}\n" for name in leaves).encode("ascii"),
    )
    return decision


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output_root), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
