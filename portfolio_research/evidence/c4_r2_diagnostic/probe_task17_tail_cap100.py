"""Counterfactual read-only probe: unchanged V7 IRLS map with hard cap 100.

This diagnostic executes only the failed and not-yet-reached tail folds of task
17.  The cap is changed in memory, under a new research-only identity, and is
restored before exit.  No model/certification files are written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pandas as pd


PROJECT = Path(__file__).resolve().parents[2]
PUBLIC_ROOT = (
    PROJECT
    / "outputs"
    / "model_zoo_c4_pristine_public_c4p_20260824T161500"
    / "pristine_seed_02"
    / "dgp_H"
)
sys.path[:0] = [str(PROJECT), str(PROJECT / "src")]

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

canonical = service._parse_exact_canonical_csv((PUBLIC_ROOT / "canonical150.csv").read_bytes())
source = adapt_r4_canonical_source_v7(service._select_v7_numeric_source(canonical))
full_state = build_hierarchical_state_features_v7(source)
observed = source["observed_pe"].copy()
groups = pd.Series(
    [NONINFORMATIVE_GROUP_LABEL] * len(source), index=source.index, dtype="object"
)
plan = service.build_qualification_fold_plan()

original_cap = est.IRLS_MAX_ITERATIONS
rows: list[dict[str, object]] = []
try:
    est.IRLS_MAX_ITERATIONS = 100
    for plan_index in range(56, len(plan)):
        spec = plan[plan_index]
        requested = full_state.identities.iloc[
            spec.decision_block_start_inclusive : spec.decision_block_end_exclusive
        ].copy()
        result = fit_chronological_prefix_v7(
            source,
            decision_block_identities=requested,
            observed_pe=observed,
            research_dgp_groups=groups,
        )
        receipt = result.fit.fit_receipt
        rows.append(
            {
                "plan_index": plan_index,
                "fold_id": spec.fold_id,
                "decision_start_inclusive": spec.decision_block_start_inclusive,
                "decision_end_exclusive": spec.decision_block_end_exclusive,
                "fit_rows": receipt.fit_row_count,
                "irls_iterations": receipt.irls_iterations,
                "coefficient_delta": receipt.final_coefficient_delta,
                "weight_delta": receipt.final_weight_delta,
                "updated_weight_kkt": receipt.final_kkt_violation,
                "objective": receipt.final_huber_objective,
                "scale": receipt.final_conditional_huber_scale,
                "active_bound_count": receipt.active_bound_count,
                "total_qp_sweeps": receipt.total_qp_coordinate_sweeps,
                "fit_receipt_sha256": receipt.sha256(),
                "parameter_sha256": result.fit.parameters.sha256(),
            }
        )
finally:
    est.IRLS_MAX_ITERATIONS = original_cap

print(
    json.dumps(
        {
            "status": "PASS_TASK17_TAIL_FOLDS_WITH_COUNTERFACTUAL_CAP_100",
            "authority": "RESEARCH_DIAGNOSTIC_ONLY",
            "original_cap": original_cap,
            "counterfactual_cap": 100,
            "folds": rows,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
