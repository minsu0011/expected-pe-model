"""Freeze the blocker-repair-only Structural V7 revision-2 design."""

# ruff: noqa: E402 -- resource sealing intentionally precedes numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_design_v2_20260820"


def main() -> int:
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    receipt = seal_battleground_process(outer_workers=1)
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
    from research.model_zoo.structural_v7.design import (
        DESIGN_LOCK_RAW_SHA256 as REVISION_1_DESIGN_RAW_SHA256,
    )
    from research.model_zoo.structural_v7.evaluation_identity import (
        EXPECTED_MODEL_IDS,
        EXPECTED_OUTER_SCHEDULE_SHA256,
        EXPECTED_ROWS_PER_SEED_MODEL,
    )

    parent = load_sealed_design_lock(ROOT)
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V7 V2 design exists: {OUTPUT}")
    input_paths = (
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
        ROOT
        / "outputs/model_zoo_wave1_screen_20260819/prediction/PREDICTION_MANIFEST.json",
    )
    rationale = (
        "hard_min=200 is an exploration executability floor, not a parameter/sample "
        "sufficiency claim. SplineTransformer with cubic degree and four knots expands "
        "the active feature dimensionality materially; Ridge alpha=10 regularizes that "
        "expanded design. On the sealed spent surfaces the earliest base call has 250 "
        "usable labels from 252 raw sessions, the earliest meta fit has 252, and the "
        "earliest structural fit has 502. Thus 200 supplies a 50-label margin below the "
        "empirical minimum for warm-up missingness. Stability is judged only by later "
        "exploration results, never inferred from this floor."
    )
    payload = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v7_exploration_design_lock_v2",
            "locked_at_date_kst": "2026-08-20",
            "revision_scope": (
                "audit-blocker repair only: immutable dependency closure, corrected "
                "minimum rationale, and exact evaluator identity"
            ),
            "supersedes_revision_1_design_raw_sha256": REVISION_1_DESIGN_RAW_SHA256,
            "candidate_or_minimum_changes_from_revision_1": False,
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
                "scoring_input_schema": [
                    "seed",
                    "date",
                    "model_id",
                    "prediction",
                    "true_fair_pe",
                ],
                "prediction_identity_columns": [
                    "seed",
                    "date",
                    "symbol",
                    "fold_id",
                    "test_start_position",
                    "model_id",
                ],
                "exact_seed_count": len(SPENT_SEEDS),
                "exact_rows_per_seed_model": EXPECTED_ROWS_PER_SEED_MODEL,
                "exact_model_ids": list(EXPECTED_MODEL_IDS),
                "outer_schedule_sha256": EXPECTED_OUTER_SCHEDULE_SHA256,
                "identity_gate_must_precede_truth_open": True,
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
                "rationale": rationale,
                "empirical_usable_support": {
                    "earliest_base_usable_of_raw": [250, 252],
                    "earliest_meta_usable": 252,
                    "earliest_structural_usable": 502,
                    "hard_floor_margin_below_empirical_minimum": 50,
                },
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
                "S3_spline": (
                    "train-median imputer; scale; cubic spline 4 knots; Ridge alpha 10"
                ),
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
            "dependency_freeze_policy": {
                "required_before_parent_launcher_imports": True,
                "required_before_worker_imports_or_fit": True,
                "required_before_evaluator_imports_or_truth": True,
                "exact_local_runtime_dependency_count": 16,
                "v7_source_closure_required": True,
                "post_freeze_non_cyclic_pin_required": True,
            },
            "all_nested_call_preflight": {
                "required_after_dependency_freeze_before_fit": True,
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
            "design_freeze_resource_receipt": receipt.as_dict(),
            "heavy_launch_authorized": False,
            "heavy_launch_condition": (
                "root approval plus exact dependency/design/preflight pins; exploration-only"
            ),
            "prohibited_reuse": {
                "prior_structural_execution_authority": "NOT_AN_INPUT",
                "prior_structural_policy": "NOT_AN_INPUT",
                "prior_structural_activation_pin": "NOT_AN_INPUT",
                "partial_prior_predictions": "NOT_AN_INPUT",
            },
            "input_artifacts": [
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "bytes": path.stat().st_size,
                    "raw_sha256": sha256_file(path),
                }
                for path in input_paths
            ],
            "out_of_scope": [
                "production authority standards",
                "production source or release mutation",
                "registry mutation",
                "fresh or heldout seeds",
                "production promotion evidence",
                "real-market accuracy claim",
            ],
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "DESIGN_LOCK_V2.json"
    path.write_bytes(raw)
    report = (
        "# Structural V7 Exploration Design Lock V2\n\n"
        "- Scope: audit-blocker repair only; candidates and 252/200 policy unchanged.\n"
        "- Hard floor: executability only; regularized spline expansion is acknowledged.\n"
        "- Empirical usable support: base/meta/structural = 250/252/502.\n"
        "- Evaluator identity: exact 5 seeds x 1,296 rows/model plus outer hash.\n"
        "- State: exploration-only; dependency freeze and preflight still required.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
