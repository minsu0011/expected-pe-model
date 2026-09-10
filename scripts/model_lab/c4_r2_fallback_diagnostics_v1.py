"""Read-only exception-frame diagnostics for already observed stress fallback."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
from scripts.model_lab.c4_r2_final_closure_v1 import (  # noqa: E402
    FINAL_VARIANT_ID, KNOWN_CANONICAL, KNOWN_OVERLAY, NUMERIC_FAILURE_MESSAGES,
    _stress_canonical, require, run_source_task, write,
)
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402


def run(root):
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import estimator
    baseline = json.loads((root / "stress/extreme_residuals_A.json").read_text())
    expected_fallbacks = [r for r in baseline["fold_receipts"] if r["fallback"]]
    transformed = _stress_canonical(pd.read_csv(KNOWN_CANONICAL), "extreme_residuals")
    raw = transformed.to_csv(index=False, lineterminator="\n").encode()
    records = []
    for fold in expected_fallbacks:
        capture = []

        def trace(frame, event, arg):
            if event == "call":
                if frame.f_code.co_filename == estimator.__file__ and frame.f_code.co_name == "fit_hierarchical_state_v7":
                    frame.f_trace_lines = False
                    return trace
                return None
            if event == "exception" and str(arg[1]) in NUMERIC_FAILURE_MESSAGES:
                local = frame.f_locals
                beta = local["coefficients"]
                lower, upper = local["lower"], local["upper"]
                objective = estimator._huber_objective(
                    local["residual"], local["scale"], beta, local["penalty_matrix"])
                capture.append({
                    "stress_id": "extreme_residuals", "task": "known_exposed_public_stress",
                    "seed": 7883, "dgp": "H_derived_stress", "fold_index": fold["fold_index"],
                    "fold_id": f"fold_{fold['fold_index']+12:03d}",
                    "decision_start": fold["decision_start"], "decision_end": fold["decision_end"],
                    "iteration_count": int(local["iterations"]), "termination_reason": str(arg[1]),
                    "last_finite_objective": float(objective),
                    "stationarity_KKT": float(local["final_kkt"]),
                    "coefficient_delta": float(local["final_delta"]),
                    "weight_delta": float(local["final_weight_delta"]),
                    "condition_number_penalized_gram": float(np.linalg.cond(local["final_gram"])),
                    "active_lower_indexes": np.flatnonzero(np.isfinite(lower) & np.isclose(beta, lower, rtol=0, atol=1e-10)).tolist(),
                    "active_upper_indexes": np.flatnonzero(np.isfinite(upper) & np.isclose(beta, upper, rtol=0, atol=1e-10)).tolist(),
                    "fallback_authorized": True,
                    "capture_method": "exception-frame observer; unchanged estimator bytes and numeric operations",
                })
            return trace

        sys.settrace(trace)
        try:
            rerun = run_source_task(raw, KNOWN_OVERLAY.read_bytes(), variant_id=FINAL_VARIANT_ID,
                                    task_label="stress_extreme_residuals", seed_alias="stress_seed_public",
                                    dgp_id="X", fold_indices=(fold["fold_index"],))
        finally:
            sys.settrace(None)
        require(len(capture) == 1, "missing/ambiguous fallback diagnostic capture")
        prior_rows = [r for r in baseline["rows"] if fold["decision_start"] <= r["session_position"] < fold["decision_end"]]
        require(prior_rows == rerun["rows"], "diagnostic observer changed fallback predictions")
        overlay = pd.read_csv(KNOWN_OVERLAY, float_precision="round_trip")
        values = overlay.iloc[fold["decision_start"]:fold["decision_end"]].v04_expected_pe.to_numpy()
        predicted = np.asarray([r["expected_pe"] for r in rerun["rows"]])
        require(np.array_equal(values, predicted), "fallback is not exact v04 PE")
        require(np.array_equal(np.log(values), [r["expected_log_pe"] for r in rerun["rows"]]), "fallback log differs")
        capture[0].update(exact_v04_pe=True, exact_v04_log=True, diagnostic_prediction_parity=True)
        records.extend(capture)
        print(f"FALLBACK diagnostic fold={fold['fold_index']}: {capture[0]['iteration_count']} iterations", flush=True)
    write(root / "C4_R2_FALLBACK_DIAGNOSTICS.csv", pd.DataFrame(records))
    write(root / "FALLBACK_DIAGNOSTIC_RECEIPT.json", {"status": "PASS", "records": records,
          "stress_fallback_folds_per_pass": len(records), "stress_fallback_rows_per_pass": sum(f["decision_end"]-f["decision_start"] for f in expected_fallbacks),
          "instrumented_diagnostic_excluded_from_primary_runtime_and_solver_counts": True})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    run(parser.parse_args().output_root.resolve())
