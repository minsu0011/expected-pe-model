"""Read-only C4-R2 diagnostic for pristine task-17 / DGP-H / fold_068.

This file is deliberately outside the frozen implementation tree.  It imports
the pinned implementation, instruments it in memory, and prints one JSON
diagnostic to stdout.  It does not write model or certification artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import numpy as np
import pandas as pd


PROJECT = Path(__file__).resolve().parents[2]
PUBLIC_ROOT = (
    PROJECT
    / "outputs"
    / "model_zoo_c4_pristine_public_c4p_20260824T161500"
    / "pristine_seed_02"
    / "dgp_H"
)
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "src"))

from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: E402
    adapt_r4_canonical_source_v7,
    build_hierarchical_state_features_v7,
    fit_chronological_prefix_v7,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: E402
    estimator as est,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import (  # noqa: E402
    service,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (  # noqa: E402
    NONINFORMATIVE_GROUP_LABEL,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def f(value: float) -> float:
    return float(value)


def q(values: np.ndarray) -> dict[str, float]:
    return {
        str(level): f(np.quantile(values, level))
        for level in (0.0, 0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99, 1.0)
    }


def active_bounds(beta: np.ndarray, lower: np.ndarray, upper: np.ndarray) -> dict[str, object]:
    lo = np.flatnonzero(np.isfinite(lower) & (beta <= lower + 1e-10)).tolist()
    hi = np.flatnonzero(np.isfinite(upper) & (beta >= upper - 1e-10)).tolist()
    return {"lower_indices": lo, "upper_indices": hi, "count": len(lo) + len(hi)}


def run_irls(
    design: np.ndarray,
    target: np.ndarray,
    penalty: np.ndarray,
    lower: np.ndarray,
    upper: np.ndarray,
    *,
    start_beta: np.ndarray,
    start_weights: np.ndarray,
    max_iterations: int,
    damping: float,
) -> dict[str, object]:
    beta = start_beta.copy()
    weights = start_weights.copy()
    rows: list[dict[str, object]] = []
    total_sweeps = 0
    converged = False
    for iteration in range(1, max_iterations + 1):
        gram, right = est._fixed_quadratic_system(design, target, weights, penalty)
        solved, sweeps, qp_kkt = ORIGINAL_QP(gram, right, lower, upper, beta)
        total_sweeps += sweeps
        coefficient_delta = f(
            np.max(np.abs(solved - beta)) / max(1.0, f(np.max(np.abs(beta))))
        )
        beta = solved
        residual = target - design @ beta
        scale = est._residual_scale(residual)
        standardized = np.abs(residual) / scale
        implied = np.ones(len(target), dtype=np.float64)
        tail = standardized > est.HUBER_DELTA
        implied[tail] = est.HUBER_DELTA / standardized[tail]
        implied_weight_delta = f(np.max(np.abs(implied - weights)))
        next_weights = weights + damping * (implied - weights)
        next_weight_delta = f(np.max(np.abs(next_weights - weights)))
        final_gram, final_right = est._fixed_quadratic_system(
            design, target, implied, penalty
        )
        implied_kkt = est._kkt_violation(beta, final_gram, final_right, lower, upper)
        row = {
            "iteration": iteration,
            "coefficient_delta": coefficient_delta,
            "implied_weight_delta": implied_weight_delta,
            "applied_weight_delta": next_weight_delta,
            "implied_kkt": f(implied_kkt),
            "qp_kkt": f(qp_kkt),
            "qp_sweeps": int(sweeps),
            "scale": f(scale),
            "objective": est._huber_objective(residual, scale, beta, penalty),
            "tail_count": int(tail.sum()),
        }
        rows.append(row)
        weights = next_weights
        if (
            iteration >= 2
            and coefficient_delta <= est.IRLS_TOLERANCE
            and implied_weight_delta <= est.IRLS_TOLERANCE
            and implied_kkt <= est.QP_KKT_TOLERANCE
        ):
            converged = True
            break
    residual = target - design @ beta
    scale = est._residual_scale(residual)
    implied = np.minimum(
        1.0, est.HUBER_DELTA / np.maximum(np.abs(residual) / scale, np.finfo(float).tiny)
    )
    fixed_gram, fixed_right = est._fixed_quadratic_system(design, target, implied, penalty)
    return {
        "damping": damping,
        "converged": converged,
        "iterations": len(rows),
        "total_qp_sweeps": total_sweeps,
        "last": rows[-1],
        "tail": rows[-10:],
        "beta_sha256": hashlib.sha256(beta.astype("<f8").tobytes()).hexdigest(),
        "weights_sha256": hashlib.sha256(implied.astype("<f8").tobytes()).hexdigest(),
        "fixed_point_kkt": f(est._kkt_violation(beta, fixed_gram, fixed_right, lower, upper)),
        "active_bounds": active_bounds(beta, lower, upper),
        "beta": [f(value) for value in beta],
    }


for name in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    if os.environ.get(name) != "1":
        raise RuntimeError(f"{name}=1 is required")
if os.environ.get("CUDA_VISIBLE_DEVICES") != "-1":
    raise RuntimeError("CUDA_VISIBLE_DEVICES=-1 is required")
if os.environ.get("NVIDIA_VISIBLE_DEVICES") != "void":
    raise RuntimeError("NVIDIA_VISIBLE_DEVICES=void is required")

canonical_path = PUBLIC_ROOT / "canonical150.csv"
canonical_raw = canonical_path.read_bytes()
canonical = service._parse_exact_canonical_csv(canonical_raw)
numeric = service._select_v7_numeric_source(canonical)
source = adapt_r4_canonical_source_v7(numeric)
full_state = build_hierarchical_state_features_v7(source)
plan = service.build_qualification_fold_plan()
spec = plan[56]
start = spec.decision_block_start_inclusive
end = spec.decision_block_end_exclusive
requested = full_state.identities.iloc[start:end].copy()
observed = source["observed_pe"].copy()
groups = pd.Series(
    [NONINFORMATIVE_GROUP_LABEL] * len(source), index=source.index, dtype="object"
)

captured_systems: list[dict[str, np.ndarray]] = []
captured_solves: list[dict[str, object]] = []
ORIGINAL_SYSTEM = est._fixed_quadratic_system
ORIGINAL_QP = est._fixed_box_qp_solve


def capture_system(
    design: np.ndarray,
    target: np.ndarray,
    weights: np.ndarray,
    penalty: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    gram, right = ORIGINAL_SYSTEM(design, target, weights, penalty)
    captured_systems.append(
        {
            "design": design.copy(),
            "target": target.copy(),
            "weights": weights.copy(),
            "penalty": penalty.copy(),
            "gram": gram.copy(),
            "right": right.copy(),
        }
    )
    return gram, right


def capture_qp(
    gram: np.ndarray,
    right: np.ndarray,
    lower: np.ndarray,
    upper: np.ndarray,
    start_beta: np.ndarray,
) -> tuple[np.ndarray, int, float]:
    solved, sweeps, kkt = ORIGINAL_QP(gram, right, lower, upper, start_beta)
    captured_solves.append(
        {
            "start": start_beta.copy(),
            "solved": solved.copy(),
            "sweeps": int(sweeps),
            "kkt": f(kkt),
            "lower": lower.copy(),
            "upper": upper.copy(),
        }
    )
    return solved, sweeps, kkt


est._fixed_quadratic_system = capture_system
est._fixed_box_qp_solve = capture_qp
exception = None
try:
    fit_chronological_prefix_v7(
        source,
        decision_block_identities=requested,
        observed_pe=observed,
        research_dgp_groups=groups,
    )
except Exception as error:  # expected frozen failure; record exact type/message
    exception = {"type": type(error).__name__, "message": str(error)}
finally:
    est._fixed_quadratic_system = ORIGINAL_SYSTEM
    est._fixed_box_qp_solve = ORIGINAL_QP

if len(captured_solves) != est.IRLS_MAX_ITERATIONS:
    raise RuntimeError(f"expected 50 captured solves, got {len(captured_solves)}")
if len(captured_systems) != 2 * est.IRLS_MAX_ITERATIONS:
    raise RuntimeError(f"expected 100 captured systems, got {len(captured_systems)}")

base = captured_systems[0]
design = base["design"]
target = base["target"]
penalty = base["penalty"]
lower = captured_solves[0]["lower"]
upper = captured_solves[0]["upper"]
trajectory: list[dict[str, object]] = []
betas: list[np.ndarray] = []
for index, solve in enumerate(captured_solves):
    old_system = captured_systems[2 * index]
    implied_system = captured_systems[2 * index + 1]
    beta = solve["solved"]
    betas.append(beta)
    residual = target - design @ beta
    scale = est._residual_scale(residual)
    old_weights = old_system["weights"]
    implied_weights = implied_system["weights"]
    coefficient_delta = f(
        np.max(np.abs(beta - solve["start"]))
        / max(1.0, f(np.max(np.abs(solve["start"]))))
    )
    trajectory.append(
        {
            "iteration": index + 1,
            "coefficient_delta": coefficient_delta,
            "weight_delta": f(np.max(np.abs(implied_weights - old_weights))),
            "updated_weight_kkt": f(
                est._kkt_violation(
                    beta,
                    implied_system["gram"],
                    implied_system["right"],
                    lower,
                    upper,
                )
            ),
            "old_weight_qp_kkt": solve["kkt"],
            "qp_sweeps": solve["sweeps"],
            "scale": f(scale),
            "objective": est._huber_objective(residual, scale, beta, penalty),
            "weight_quantiles": q(implied_weights),
            "tail_count": int((implied_weights < 1.0).sum()),
            "active_bounds": active_bounds(beta, lower, upper),
            "old_gram_condition_2": f(np.linalg.cond(old_system["gram"])),
            "implied_gram_condition_2": f(np.linalg.cond(implied_system["gram"])),
        }
    )

last_beta = betas[-1]
last_implied_weights = captured_systems[-1]["weights"]
rescue_vanilla = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=last_beta,
    start_weights=last_implied_weights,
    max_iterations=450,
    damping=1.0,
)
rescue_vanilla_cold = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=np.zeros(design.shape[1], dtype=np.float64),
    start_weights=np.ones(len(target), dtype=np.float64),
    max_iterations=100,
    damping=1.0,
)
rescue_vanilla_cold_repeat = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=np.zeros(design.shape[1], dtype=np.float64),
    start_weights=np.ones(len(target), dtype=np.float64),
    max_iterations=100,
    damping=1.0,
)
rescue_damped_050 = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=np.zeros(design.shape[1], dtype=np.float64),
    start_weights=np.ones(len(target), dtype=np.float64),
    max_iterations=250,
    damping=0.5,
)
rescue_damped_025 = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=np.zeros(design.shape[1], dtype=np.float64),
    start_weights=np.ones(len(target), dtype=np.float64),
    max_iterations=350,
    damping=0.25,
)
rescue_damped_050_repeat = run_irls(
    design,
    target,
    penalty,
    lower,
    upper,
    start_beta=np.zeros(design.shape[1], dtype=np.float64),
    start_weights=np.ones(len(target), dtype=np.float64),
    max_iterations=250,
    damping=0.5,
)

design_singular = np.linalg.svd(design, compute_uv=False)
penalty_eigen = np.linalg.eigvalsh(penalty)
last_residual = target - design @ last_beta
report = {
    "diagnostic_schema": "expected_pe.c4_r2.fold_068.read_only_diagnostic.v1",
    "scope": {
        "task_ordinal": 17,
        "qualification_seed": 7883,
        "seed_alias": "pristine_seed_02",
        "dgp_id": "H",
        "fold_plan_index": 56,
        "fold_id": spec.fold_id,
        "decision_start_inclusive": int(start),
        "decision_end_exclusive": int(end),
        "fit_rows_after_warmup": int(design.shape[0]),
        "design_columns": int(design.shape[1]),
    },
    "inputs": {
        "canonical_path": str(canonical_path),
        "canonical_size": canonical_path.stat().st_size,
        "canonical_sha256": sha256_file(canonical_path),
        "public_manifest_path": str(PUBLIC_ROOT / "PUBLIC_TASK_MANIFEST.json"),
        "public_manifest_sha256": sha256_file(PUBLIC_ROOT / "PUBLIC_TASK_MANIFEST.json"),
        "v04_overlay_path": str(PUBLIC_ROOT / "v04_overlay.csv"),
        "v04_overlay_sha256": sha256_file(PUBLIC_ROOT / "v04_overlay.csv"),
        "estimator_path": str(Path(est.__file__).resolve()),
        "estimator_sha256": sha256_file(Path(est.__file__).resolve()),
        "service_path": str(Path(service.__file__).resolve()),
        "service_sha256": sha256_file(Path(service.__file__).resolve()),
    },
    "environment": {
        name: os.environ.get(name)
        for name in (
            "OMP_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "MKL_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "VECLIB_MAXIMUM_THREADS",
            "CUDA_VISIBLE_DEVICES",
            "NVIDIA_VISIBLE_DEVICES",
        )
    },
    "frozen_result": {
        "exception": exception,
        "irls_iterations": len(captured_solves),
        "total_qp_sweeps": int(sum(item["sweeps"] for item in captured_solves)),
        "first": trajectory[0],
        "last": trajectory[-1],
        "last_15": trajectory[-15:],
        "last_beta": [f(value) for value in last_beta],
        "last_beta_sha256": hashlib.sha256(last_beta.astype("<f8").tobytes()).hexdigest(),
        "last_vs_previous_beta_max": f(np.max(np.abs(betas[-1] - betas[-2]))),
        "last_vs_two_back_beta_max": f(np.max(np.abs(betas[-1] - betas[-3]))),
        "last_residual_quantiles": q(last_residual),
    },
    "conditioning": {
        "design_rank": int(np.linalg.matrix_rank(design)),
        "design_singular_max": f(design_singular[0]),
        "design_singular_min": f(design_singular[-1]),
        "design_condition_2": f(design_singular[0] / design_singular[-1]),
        "penalty_rank": int(np.linalg.matrix_rank(penalty)),
        "penalty_eigen_min": f(penalty_eigen[0]),
        "penalty_eigen_max": f(penalty_eigen[-1]),
        "unweighted_penalized_gram_eigen_min": f(
            np.linalg.eigvalsh(captured_systems[0]["gram"])[0]
        ),
        "unweighted_penalized_gram_eigen_max": f(
            np.linalg.eigvalsh(captured_systems[0]["gram"])[-1]
        ),
    },
    "constants": {
        "huber_delta": est.HUBER_DELTA,
        "robust_scale_floor": est.ROBUST_SCALE_FLOOR,
        "robust_scale_ceiling": est.ROBUST_SCALE_CEILING,
        "irls_max_iterations": est.IRLS_MAX_ITERATIONS,
        "irls_tolerance": est.IRLS_TOLERANCE,
        "qp_max_sweeps": est.QP_MAX_SWEEPS,
        "qp_kkt_tolerance": est.QP_KKT_TOLERANCE,
        "persistence_bounds": [f(lower[3]), f(upper[3])],
        "innovation_bounds": [f(lower[6]), f(upper[6])],
    },
    "rescues": {
        "continue_undamped_from_frozen_iteration_50": rescue_vanilla,
        "undamped_cap_100_from_zero": rescue_vanilla_cold,
        "undamped_cap_100_exact_repeat": rescue_vanilla_cold_repeat,
        "undamped_cap_100_repeat_equal": (
            rescue_vanilla_cold["beta_sha256"]
            == rescue_vanilla_cold_repeat["beta_sha256"]
            and rescue_vanilla_cold["weights_sha256"]
            == rescue_vanilla_cold_repeat["weights_sha256"]
        ),
        "damped_0_50_from_zero": rescue_damped_050,
        "damped_0_25_from_zero": rescue_damped_025,
        "damped_0_50_exact_repeat": rescue_damped_050_repeat,
        "damped_0_50_repeat_equal": (
            rescue_damped_050["beta_sha256"] == rescue_damped_050_repeat["beta_sha256"]
            and rescue_damped_050["weights_sha256"]
            == rescue_damped_050_repeat["weights_sha256"]
        ),
    },
}
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
