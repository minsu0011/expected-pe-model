"""Write the immutable, pre-score Structural V7 exploration design lock."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_design_20260820"


def main() -> int:
    from research.model_zoo.aggressive_lab.contracts import (
        DESIGN_LOCK_RAW_SHA256,
        load_sealed_design_lock,
    )
    from research.model_zoo.structural_v7.contracts import (
        ALLOWED_LOGICAL_CPUS,
        CORRECTION_BOUND_LOG,
        EVIDENCE_CLASS,
        EVALUATION_TARGET,
        FRESH_OR_HELDOUT_ALLOWED,
        GPU_POLICY,
        HARD_MIN_TRAIN_ROWS,
        INNER_THREADS,
        MAX_WORKERS,
        PAIR_BASE_IDS,
        PARENT_LANE_ID,
        PREFERRED_MIN_TRAIN_ROWS,
        PRIMARY_BASE_ID,
        PROMOTION_ROLE,
        SIMPLEX_BASE_IDS,
        SPENT_SEEDS,
        STRUCTURAL_LANE_ID,
        TRAINING_TARGET,
        candidate_design_payload,
        seal_payload,
        sha256_file,
    )

    parent = load_sealed_design_lock(ROOT)
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V7 design directory exists: {OUTPUT}")
    input_paths = (
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
        ROOT
        / "outputs/model_zoo_wave1_screen_20260819/prediction/PREDICTION_MANIFEST.json",
    )
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v7_exploration_design_lock",
            "locked_at_date_kst": "2026-08-20",
            "parent_lane_id": PARENT_LANE_ID,
            "structural_lane_id": STRUCTURAL_LANE_ID,
            "parent_design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "evidence_class": EVIDENCE_CLASS,
            "promotion_authority": PROMOTION_ROLE,
            "production_promotion_allowed": False,
            "fresh_or_heldout_allowed": FRESH_OR_HELDOUT_ALLOWED,
            "spent_seeds": list(SPENT_SEEDS),
            "training_target": TRAINING_TARGET,
            "evaluation_target": EVALUATION_TARGET,
            "evaluation_contract": {
                "evaluator": (
                    "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament"
                ),
                "input_schema": [
                    "seed",
                    "date",
                    "model_id",
                    "prediction",
                    "true_fair_pe",
                ],
                "identical_global_common_mask": True,
                "accounting_basis": parent["accounting_basis"],
                "incumbent_model_id": PRIMARY_BASE_ID,
            },
            "minimum_train_policy": {
                "preferred_min": PREFERRED_MIN_TRAIN_ROWS,
                "hard_min": HARD_MIN_TRAIN_ROWS,
                "scope": [
                    "every base OOF fit",
                    "every training-OOF meta fit",
                    "every structural outer fit",
                ],
                "precommitted_before_results": True,
                "rationale": (
                    "252 approximates one trading year. 200 remains longer than the "
                    "126-session causal return/growth horizon and gives at least about "
                    "ten observations per 20--25 active tabular degrees of freedom. "
                    "Below 252 is recorded, never silently changed; below 200 is fatal."
                ),
            },
            "base_surface_policy": {
                "prequential_start_position": 252,
                "outer_evaluation_start_position": 504,
                "test_sessions": 21,
                "step_sessions": 21,
                "primary_base": PRIMARY_BASE_ID,
                "pair_bases": list(PAIR_BASE_IDS),
                "simplex_bases": list(SIMPLEX_BASE_IDS),
                "xgb_and_spline_refit_under_v7_hard_min": True,
                "v04_source": "already-spent causal prequential prediction surface",
                "within_outer_test_target_updates": False,
            },
            "candidates": candidate_design_payload(),
            "candidate_parameters": {
                "S1_fixed_weight": [0.5, 0.5],
                "S1_learned_weight_bounds": [0.0, 1.0],
                "S2_simplex": "weights>=0; sum(weights)=1; SLSQP log-MSE",
                "S3_spline": "train-median imputer; scale; cubic spline 4 knots; Ridge alpha 10",
                "S3_extra_trees": (
                    "192 trees; min_samples_leaf 8; max_features 0.75; n_jobs 1"
                ),
                "S3_state_space": (
                    "local linear trend plus AR(1); LBFGS maxiter 100; fixed-origin forecast"
                ),
                "S4_decomposition": (
                    "train-median imputer; scale; Ridge alpha 10; zero-intercept AR(1) "
                    "clipped [-0.95,0.95]; fixed-origin forecast"
                ),
                "residual_correction_bound_log": CORRECTION_BOUND_LOG,
            },
            "regime_ablation": {
                "residual_spline": ["common", "with_regime"],
                "residual_extra_trees": ["common", "with_regime"],
                "structural_decomposition": ["common", "with_regime"],
            },
            "all_nested_call_preflight": {
                "required_before_fit": True,
                "checks": [
                    "exact seed/date/entity/fold identity",
                    "chronological train-before-test",
                    "usable observed_pe labels",
                    "train-derived active features and imputation",
                    "base OOF/meta common-mask coverage",
                    "preferred and hard minimum policies",
                ],
                "fit_calls": 0,
                "truth_reads": 0,
                "score_calls": 0,
            },
            "resource_policy": {
                "mode": "BATTLEGROUND",
                "logical_cpu_ids": list(ALLOWED_LOGICAL_CPUS),
                "max_outer_workers": MAX_WORKERS,
                "inner_threads": INNER_THREADS,
                "gpu": GPU_POLICY,
            },
            "heavy_launch_authorized": False,
            "heavy_launch_condition": (
                "root approval plus exact design/preflight pins; exploration-only"
            ),
            "prohibited_reuse": {
                "prior_structural_execution_authority": "NOT_AN_INPUT",
                "prior_structural_policy": "NOT_AN_INPUT",
                "prior_structural_activation_pin": "NOT_AN_INPUT",
                "partial_prior_predictions": "NOT_AN_INPUT",
            },
            "input_artifacts": [
                {
                    "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "bytes": path.stat().st_size,
                    "raw_sha256": sha256_file(path),
                }
                for path in input_paths
            ],
            "out_of_scope": [
                "production source or release mutation",
                "registry mutation",
                "fresh or heldout seeds",
                "production promotion evidence",
                "real-market accuracy claim",
            ],
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    (OUTPUT / "DESIGN_LOCK.json").write_bytes(raw)
    report = (
        "# Structural V7 Exploration Design Lock\n\n"
        "- Evidence: `EXPLORATION_ONLY / NOT_PROMOTION_EVIDENCE`\n"
        "- Seeds: already-spent 6301, 6421, 6521, 6607, 6701 only\n"
        "- Minimum policy: preferred 252, hard 200, locked before results\n"
        "- Candidates: 10 across static/learned blend, simplex, residual, and decomposition\n"
        "- Resources: CPUs 16-31, outer <=16, inner 1, GPU sealed\n"
        "- State: heavy launch blocked pending root approval and no-fit preflight\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(OUTPUT / "DESIGN_LOCK.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
