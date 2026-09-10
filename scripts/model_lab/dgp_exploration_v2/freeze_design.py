"""Freeze the score-free v2 DGP/candidate/mask design before any heavy run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from research.model_zoo.aggressive_lab.contracts import (
    DESIGN_LOCK_RAW_SHA256 as CENTRAL_DESIGN_LOCK_RAW_SHA256,
    load_sealed_design_lock,
)
from research.model_zoo.dgp_exploration_v2.artifacts import (
    atomic_write,
    canonical_json_bytes,
    write_checksums,
)
from research.model_zoo.dgp_exploration_v2.contracts import (
    EXPLORATION_LABELS,
    SUITE_VERSION,
    candidate_design_payload,
    dgp_design_payload,
)
from research.model_zoo.dgp_exploration_v2.precommit import (
    dependency_sha256,
    source_sha256,
)


DEFAULT_OUTPUT = Path("outputs/model_zoo_dgp_exploration_v2_design_20260820")


def build_lock(root: Path) -> dict[str, Any]:
    central = load_sealed_design_lock(root)
    return {
        "schema_version": "expected_pe_dgp_exploration_v2.design_lock.v1",
        "suite_version": SUITE_VERSION,
        "labels": list(EXPLORATION_LABELS),
        "production_promotion_allowed": False,
        "heavy_execution_status": "NOT_LAUNCHED_WAITING_ROOT_APPROVAL",
        "launch_requires_external_exact_design_lock_raw_sha256": True,
        "old_sealed_dgp_implementation_status": "NO_GO_NOT_RESEALED_NOT_RESEARCH_AUTHORITY",
        "research_lane_isolation": (
            "v2 code/artifacts only; optional child resource override does not confer old seal GO"
        ),
        "central_design_lock_raw_sha256": CENTRAL_DESIGN_LOCK_RAW_SHA256,
        "central_design_lock": central,
        "dgp_design": dgp_design_payload(),
        "candidate_design": candidate_design_payload(),
        "identity_columns": ["seed", "dgp", "date"],
        "truth_materialization": {
            "simulator_behavior": (
                "the simulator constructs both public and evaluator-only namespaces in its returned object"
            ),
            "prediction_adapter_boundary": (
                "prediction adapters receive only the public mapping; evaluator frames are not arguments"
            ),
            "scoring_behavior": (
                "after prediction bytes freeze, the evaluator regenerates the deterministic simulator and selects truth"
            ),
            "physical_production_custody_claimed": False,
            "truth_never_constructed_before_prediction": False,
        },
        "truth_consistency": "exactly_one_positive_finite_true_fair_pe_per_seed_dgp_date",
        "common_mask": {
            "policy": "every_precommitted_participant_predicts_every_and_only_selected_truth_eligible_identity",
            "row_dropping": "FORBIDDEN",
            "selection": "union_of_precommitted_chronological_test_blocks_intersect_true_expected_pe_eligible",
        },
        "same_target": {
            "training": "log(public_close_t / PIT_EPS_available_by_t_1230_UTC)",
            "evaluation": "log(predicted_expected_pe_t / evaluator_only_true_fair_pe_t)",
        },
        "causal_controls": {
            "same_row_market_columns": "FORBIDDEN",
            "market_timing": "t_minus_1_complete_session_or_earlier",
            "PIT_fundamental_timing": "available_at_or_before_t_1230_UTC",
            "future_intervention_invariance_required": True,
            "random_train_test_shuffle": "FORBIDDEN",
            "train_end_equals_test_start": True,
        },
        "scoring": {
            "primary": "fair_log_mae",
            "secondary": "fair_log_rmse",
            "per_model_required": [
                "mean_mae",
                "median_mae",
                "mean_rmse",
                "median_rmse",
                "worst_dgp_mae",
                "worst_dgp_rmse",
                "dgp_win_count",
            ],
            "DGP_weighting": "equal_macro_weight_after_seed_aggregation",
            "DGP_win_definition": "minimum_mean_seed_fair_log_mae_ties_at_1e-15",
            "central_evaluator": "research.model_zoo.aggressive_lab.evaluation.evaluate_tournament",
        },
        "resource_policy": central["resource_policy"],
        "source_sha256": source_sha256(root),
        "dependency_sha256": dependency_sha256(root),
    }


def _markdown(lock_hash: str, payload: dict[str, Any]) -> str:
    dgp_lines = "\n".join(
        f"- {item['dgp_id']}: `{item['prompt_name']}` — nearest prior {', '.join(item['legacy_nearest'])}; {item['legacy_difference']}"
        for item in payload["dgp_design"]["dgps"]
    )
    candidate_lines = "\n".join(
        f"- `{item['model_id']}` ({item['family']}): {item['rationale']}"
        for item in payload["candidate_design"]["candidates"]
    )
    return f"""# DGP Exploration V2 — Pre-score Design Lock

Status: `EXPLORATION_ONLY / NOT_PROMOTION_EVIDENCE`  
Heavy execution: `NOT_LAUNCHED_WAITING_ROOT_APPROVAL`  
Design lock raw SHA-256: `{lock_hash}`  
Central Research Lane lock: `{CENTRAL_DESIGN_LOCK_RAW_SHA256}`

## Why a new A–J namespace exists

The new prompt's A–J names do not match the prior sealed suite's A–J IDs.  The
old generator is therefore used only for XNYS/PIT-EPS scaffolding.  V2 defines
new prompt-aligned mechanisms and records the nearest old mechanism and the
material difference instead of silently relabelling old scores.

{dgp_lines}

## Precommitted participants

{candidate_lines}

## Evaluation boundary

Predictions are written and hashed before evaluator truth is regenerated.
Every model must cover the same `(seed,dgp,date)` identities.  Training uses
public observed P/E, while evaluation alone uses `true_fair_pe`.  All market
features are lagged at least one complete session; same-day PIT filings and
explicit public event fields are allowed only when available by 12:30 UTC.

The simulator necessarily constructs its evaluator-only namespace when it
constructs a scenario.  Prediction adapters receive only the public mapping;
this is a research code boundary, not claimed physical production custody.
The old sealed DGP implementation remains `NO_GO` and is not resealed here.

This lock is research discovery evidence only and cannot alter the production
registry, champion, release, fresh seeds, or heldout status.
"""


def _run_plan(lock_hash: str) -> str:
    return f"""# DGP Exploration V2 — Launch Plan

Design lock: `{lock_hash}`

No heavy execution has occurred.  After the root agent explicitly approves,
launch only the cheap stage with:

```powershell
$env:PYTHONPATH='src;.'
& 'C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_py310\\Scripts\\python.exe' `
  scripts/model_lab/dgp_exploration_v2/run_exploration.py `
  --output outputs/model_zoo_dgp_exploration_v2_cheap_20260820 `
  --max-workers 16 `
  --design-lock-sha256 {lock_hash} `
  --activation RUN_DGP_EXPLORATION_V2_CHEAP_EXPLORATION_ONLY
```

The launcher seals logical CPUs 16–31 exactly, sets every inner-thread variable
to one, and seals GPU visibility before importing NumPy or model libraries.
Fifty independent `(5 seeds × 10 DGPs)` tasks run with at most 16 outer workers.
Any task, coverage, truth-consistency, or mask failure produces a terminal
failure receipt and keeps the evaluator closed.  Full/tournament DGP scoring is
not authorized by this revision.
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = (root / args.output).resolve()
    payload = build_lock(root)
    raw = canonical_json_bytes(payload)
    lock_hash = hashlib.sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    atomic_write(output / "DESIGN_LOCK.json", raw)
    atomic_write(output / "DESIGN.md", _markdown(lock_hash, payload).encode("utf-8"))
    atomic_write(output / "RUN_PLAN.md", _run_plan(lock_hash).encode("utf-8"))
    atomic_write(output / "DESIGN_LOCK.sha256", f"{lock_hash}  DESIGN_LOCK.json\n".encode("ascii"))
    checksums = write_checksums(output)
    print(json.dumps({"design_lock_raw_sha256": lock_hash, "checksums_raw_sha256": checksums}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
