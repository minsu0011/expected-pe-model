"""Freeze the Structural V8 distinct-math design before any V8 fit."""

# ruff: noqa: E402 -- parent dependency/resource checks precede numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

OUTPUT = ROOT / "outputs/model_zoo_structural_v8_design_v2_20260820"


def main() -> int:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256 as V7_FULL_DEPENDENCY_RAW_SHA256,
        verify_full_dependency_freeze,
    )

    v7_dependency = verify_full_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    from research.model_zoo.structural_v7_full_load.contracts import (
        lane_gpu_usage_receipt,
        load_common_full_load_lock,
    )
    from research.model_zoo.structural_v8.contracts import (
        CANDIDATES,
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        HARD_MIN_TRAIN_ROWS,
        HIERARCHICAL_GLOBAL_ALPHA,
        HIERARCHICAL_REGIME_ALPHA,
        LOCAL_ANALOGUE_K,
        LOCAL_LINEAR_ALPHA,
        PREFERRED_MIN_TRAIN_ROWS,
        RBF_COMPONENTS,
        RBF_RIDGE_ALPHA,
        SPENT_SEEDS,
        V7_GATE_COMPONENT_IDS,
        V7_PREDICTION_MANIFEST_RAW_SHA256,
        V7_TERMINAL_MANIFEST_RAW_SHA256,
        candidate_payload,
        seal_payload,
        sha256_file,
    )
    from research.model_zoo.structural_v8.data import load_v8_truth_blind_inputs

    common_lock = load_common_full_load_lock(ROOT)
    inputs, input_evidence = load_v8_truth_blind_inputs(ROOT)
    cache_bytes = sum(
        int(bundle.spent.model_frame.memory_usage(deep=True).sum())
        + int(bundle.v7_outer_surfaces.memory_usage(deep=True).sum())
        + int(bundle.incumbent_all.nbytes)
        for bundle in inputs.values()
    )
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V8 design exists: {OUTPUT}")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v8_distinct_math_design",
            "status": "FROZEN_HEAVY_PREDICTION_APPROVAL_REQUIRED",
            "revision": 2,
            "supersedes_non_executable_design_raw_sha256": (
                "c65510f46fd9b55d1889a63c846daf330c6351c43cbb92e77ec7a7d6c1459810"
            ),
            "supersession_reason": (
                "score-free input support inspection established an exact earliest "
                "residual-meta count of 252 rather than the provisional 250; candidates "
                "and hyperparameters are unchanged"
            ),
            "locked_at_date_kst": "2026-08-20",
            "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
            "common_full_load_lock_schema": common_lock["schema_version"],
            "v7_full_dependency_raw_sha256": V7_FULL_DEPENDENCY_RAW_SHA256,
            "v7_prediction_manifest_raw_sha256": V7_PREDICTION_MANIFEST_RAW_SHA256,
            "v7_terminal_manifest_raw_sha256": V7_TERMINAL_MANIFEST_RAW_SHA256,
            "v7_terminal_result_known_before_v8_design": True,
            "v7_terminal_design_influence": (
                "All nine V7 scoreable candidates rejected; this V8 lane therefore locks "
                "different local-analogue, joint partial-pooling, causal-gate, and kernel "
                "mathematics. The two valid V7 ExtraTrees OOF surfaces are reused only as "
                "truth-blind component predictions for the fixed gate."
            ),
            "evidence_class": "EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "production_promotion_allowed": False,
            "fresh_or_heldout_allowed": False,
            "spent_seeds": list(SPENT_SEEDS),
            "candidate_count": len(CANDIDATES),
            "candidates": candidate_payload(),
            "pre_result_fixed_hyperparameters": {
                "local_analogue_k": LOCAL_ANALOGUE_K,
                "local_linear_alpha": LOCAL_LINEAR_ALPHA,
                "hierarchical_global_alpha": HIERARCHICAL_GLOBAL_ALPHA,
                "hierarchical_regime_deviation_alpha": HIERARCHICAL_REGIME_ALPHA,
                "fixed_gate_weight": "forecast_p_bear + forecast_p_bull",
                "fixed_gate_component_ids": list(V7_GATE_COMPONENT_IDS),
                "rbf_nystroem_components": RBF_COMPONENTS,
                "rbf_ridge_alpha": RBF_RIDGE_ALPHA,
            },
            "hyperparameter_rationales": {
                "local_analogue": (
                    "k=32 was fixed before V8 fits: it exceeds the at-most 24 active "
                    "standardized feature dimensions at the earliest fold while retaining "
                    "locality; alpha=4 regularizes the local-linear system. It is not a "
                    "claim of statistical sufficiency."
                ),
                "hierarchical": (
                    "A jointly estimated global block uses alpha=10 while each regime "
                    "deviation block uses alpha=100, enforcing partial pooling rather than "
                    "three independent regime fits."
                ),
                "gate": (
                    "The non-sideways forecast probability is causal and precommitted as "
                    "the regime-surface weight; missing forecast probabilities fall back "
                    "to current probabilities and then a sideways one-hot vector."
                ),
                "rbf": (
                    "A 64-component Nyström map avoids an O(n^2) exact-kernel matrix; "
                    "gamma=1/active_dimension and ridge alpha=10 are fixed."
                ),
            },
            "training_floor": {
                "preferred_min": PREFERRED_MIN_TRAIN_ROWS,
                "hard_min": HARD_MIN_TRAIN_ROWS,
                "rationale": (
                    "The operational hard floor 200 was locked before V8 results. The "
                    "known schedule supplies 252 residual-meta rows at its earliest outer "
                    "call, exactly meeting preferred 252, and 502 rows to the earliest structural "
                    "partial-pooling call. Regularization supports execution of the "
                    "expanded local-linear and up-to-4*(24+1) hierarchical design columns, "
                    "but the floor is not asserted as inferential adequacy."
                ),
            },
            "causal_label_contract": {
                "fit_label": "observed_pe only within each outer fold train positions",
                "residual_family_reference": (
                    "kNN and RBF use v04_expected_pe prediction-side OOF residuals"
                ),
                "hierarchical_target": (
                    "direct log observed_pe; outer prediction is safety-bounded around "
                    "the incumbent without consuming an outer label"
                ),
                "evaluation_truth_in_prediction_source": False,
                "within_test_target_updates": False,
            },
            "same_evaluation_contract": {
                "target_opened_only_by_separate_evaluator": "true_fair_pe",
                "evaluator": "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament",
                "identity": "seed/date/model_id/prediction joined to truth after exact gate",
            },
            "expected_execution": {
                "outer_folds_per_seed": 62,
                "candidate_outer_edges": 5 * 62 * len(CANDIDATES),
                "planned_fit_calls": 5 * 62 * 3,
                "planned_transform_only_calls": 5 * 62,
                "expected_prediction_rows": 5 * 1296 * (1 + len(CANDIDATES)),
                "outer_schedule_sha256": (
                    "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
                ),
                "retry_policy": "none; candidate/fold failure is FAILED_NO_RETRY",
                "prediction_and_evaluation_split": True,
            },
            "resource_policy": {
                "logical_cpu_ids": list(range(32)),
                "max_outer_workers": 32,
                "inner_threads": 1,
                "ram_soft_budget_gib": 80.0,
                "ram_min_free_gib": 12.0,
                "truth_blind_cache_mib": cache_bytes / 1024**2,
                "truth_blind_cache_projection_32_mib": cache_bytes * 32 / 1024**2,
            },
            "lane_gpu_usage": {
                **lane_gpu_usage_receipt(),
                "reason": "all four Structural V8 candidates are CPU estimators",
            },
            "design_freeze_resource_receipt": resource_receipt.as_dict(),
            "v7_dependency_receipt": v7_dependency.as_dict(),
            "input_evidence": input_evidence,
            "fit_calls_executed": 0,
            "prediction_rows_generated": 0,
            "evaluation_truth_opened": False,
            "scores_computed": False,
            "heavy_prediction_authorized": False,
            "heavy_prediction_gate": "separate exact root-session approval token",
            "evaluation_gate": "separate approval after immutable prediction identity",
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "DESIGN_LOCK.json"
    path.write_bytes(raw)
    (OUTPUT / "REPORT.md").write_text(
        "# Structural V8 Distinct-Math Design\n\n"
        "Four families are locked: local analogue, hierarchical partial pooling, "
        "fixed causal regime gate, and Nyström RBF residual. This is spent-seed "
        "exploration only. Heavy prediction and all scoring remain blocked.\n",
        encoding="utf-8",
        newline="\n",
    )
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
