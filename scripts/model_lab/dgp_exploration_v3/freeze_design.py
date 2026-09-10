"""Freeze V3 only after the score-free DGP-A comparator smoke passes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from research.model_zoo.dgp_exploration_v3.artifacts import (
    atomic_write,
    canonical_json_bytes,
    write_checksums,
)
from research.model_zoo.dgp_exploration_v3.contracts import (
    COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    EXPLORATION_LABELS,
    PRODUCTION_AUTHORITY,
    SUITE_VERSION,
    candidate_design_payload,
    dgp_design_payload,
)
from research.model_zoo.dgp_exploration_v3.precommit import (
    CENTRAL_LOCK_RAW_SHA256,
    DESIGN_OUTPUT,
    dependency_sha256,
    load_common_full_load_lock,
    repository_root,
    source_sha256,
)
from research.model_zoo.dgp_exploration_v3.replay_adapter import capture_replay_inventory


DEFAULT_SMOKE = Path("outputs/model_zoo_dgp_exploration_v3_comparator_smoke_20260820")


def _load_smoke(root: Path, smoke_directory: Path) -> tuple[dict[str, Any], str, str]:
    directory = (root / smoke_directory).resolve()
    expected_parent = (root / "outputs").resolve()
    if directory.parent != expected_parent or not directory.name.startswith(
        "model_zoo_dgp_exploration_v3_"
    ):
        raise RuntimeError("V3 smoke directory escaped the isolated output namespace")
    receipt_path = directory / "SMOKE_RECEIPT.json"
    checksums_path = directory / "CHECKSUMS.sha256"
    raw = receipt_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise RuntimeError("V3 smoke receipt is not canonical JSON")
    required = {
        "status": "PASS_SCORE_FREE_DGP_A_RESEARCH_COMPARATOR_REPLAY",
        "labels": list(EXPLORATION_LABELS),
        "production_authority": False,
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "truth_frame_accessed_by_smoke": False,
        "truth_score_computed": False,
        "candidate_fit_executed": False,
        "production_attestation_used": False,
        "production_registry_modified": False,
        "production_champion_modified": False,
        "fresh_or_heldout_authority": False,
        "comparator_backend": "CPU",
        "comparator_gpu_selected": False,
        "comparator_child_gpu_sealed_off": True,
    }
    for key, expected in required.items():
        if payload.get(key) != expected:
            raise RuntimeError(f"V3 smoke receipt {key} differs")
    checksums_raw = checksums_path.read_bytes()
    expected_line = f"{hashlib.sha256(raw).hexdigest()}  SMOKE_RECEIPT.json\n".encode(
        "ascii"
    )
    if checksums_raw != expected_line:
        raise RuntimeError("V3 smoke checksum manifest differs")
    return payload, hashlib.sha256(raw).hexdigest(), hashlib.sha256(checksums_raw).hexdigest()


def build_lock(
    *,
    root: Path,
    common_lock_raw_sha256: str,
    smoke_directory: Path,
) -> dict[str, Any]:
    common = load_common_full_load_lock(
        root=root,
        expected_raw_sha256=common_lock_raw_sha256,
    )
    smoke, smoke_hash, smoke_checksums_hash = _load_smoke(root, smoke_directory)
    replay_inventory = capture_replay_inventory(root=root)
    if smoke.get("replay_inventory_combined_sha256") != replay_inventory["combined_sha256"]:
        raise RuntimeError("live replay inventory differs from the passed smoke")
    return {
        "schema_version": "expected_pe_dgp_exploration_v3.design_lock.v1",
        "suite_version": SUITE_VERSION,
        "labels": list(EXPLORATION_LABELS),
        "production_authority": PRODUCTION_AUTHORITY,
        "production_promotion_allowed": False,
        "fresh_or_heldout_authority": False,
        "heavy_execution_status": (
            "PREDICTION_STAGE_NOT_LAUNCHED_WAITING_ROOT_APPROVAL_TRUTH_SCORING_LOCKED"
        ),
        "prediction_activation_literal": (
            "RUN_DGP_EXPLORATION_V3_A_J_CHEAP_EXPLORATION_ONLY"
        ),
        "truth_scoring_status": "LOCKED_REQUIRES_SEPARATE_ROOT_ACTIVATION",
        "truth_scoring_activation_literal": (
            "SCORE_DGP_EXPLORATION_V3_FROZEN_PREDICTIONS_ONLY"
        ),
        "launch_requires_external_exact_design_lock_raw_sha256": True,
        "launch_requires_external_common_full_load_lock_raw_sha256": True,
        "common_full_load_lock_raw_sha256": common_lock_raw_sha256,
        "common_full_load_lock": common,
        "central_design_lock_raw_sha256": CENTRAL_LOCK_RAW_SHA256,
        "old_production_implementation_status": "NO_GO_NOT_RESEALED",
        "production_attestation_used": False,
        "research_replay_isolation": (
            "V3 stages current v03/v04 bytes in temporary children; it neither calls nor "
            "weakens production attestation and has no production authority"
        ),
        "score_free_dgp_a_smoke": {
            "receipt_raw_sha256": smoke_hash,
            "checksums_raw_sha256": smoke_checksums_hash,
            "status": smoke["status"],
            "replay_inventory_combined_sha256": smoke[
                "replay_inventory_combined_sha256"
            ],
        },
        "child_runtime_reference": {
            stage: smoke["comparator_receipt"]["child_attestation"][stage][
                "runtime_before"
            ]
            for stage in ("v03", "v04")
        },
        "replay_inventory": replay_inventory,
        "dgp_design": dgp_design_payload(),
        "candidate_design": candidate_design_payload(),
        "identity_columns": ["seed", "dgp", "date"],
        "truth_materialization": {
            "simulator_behavior": (
                "the simulator constructs public and evaluator-only namespaces in one object"
            ),
            "prediction_adapter_boundary": (
                "prediction and comparator adapters receive only the public mapping"
            ),
            "scoring_behavior": (
                "after prediction bytes freeze, evaluator replay selects simulator truth"
            ),
            "physical_production_custody_claimed": False,
            "truth_never_constructed_before_prediction": False,
        },
        "common_mask": {
            "policy": (
                "every precommitted participant predicts every and only selected "
                "truth-eligible (seed,dgp,date) identity"
            ),
            "row_dropping": "FORBIDDEN",
        },
        "causal_controls": {
            "same_row_market_columns": "FORBIDDEN",
            "market_timing": "t_minus_1_complete_session_or_earlier",
            "PIT_fundamental_timing": "available_at_or_before_t_1230_UTC",
            "future_intervention_invariance_required": True,
            "random_train_test_shuffle": "FORBIDDEN",
        },
        "resource_policy": {
            "parent": "BOUND_TO_COMMON_FULL_LOAD_LOCK",
            "cpu_ids": list(range(32)),
            "outer_workers_max": 32,
            "inner_threads": 1,
            "ram_soft_budget_gib": 80.0,
            "ram_min_free_gib": 12.0,
            "parent_gpu": "RTX_5080_INDEX_0_AVAILABLE",
            "comparator_backend": "CPU",
            "comparator_gpu_selected": False,
            "comparator_child_gpu_visibility": "SEALED_OFF_UNSUPPORTED",
        },
        "source_sha256": source_sha256(root),
        "dependency_sha256": dependency_sha256(root),
    }


def _markdown(lock_hash: str, payload: dict[str, Any]) -> str:
    return f"""# DGP Exploration V3 - Full-load Research Design Lock

Status: `EXPLORATION_ONLY / NOT_PROMOTION_EVIDENCE`  
Production authority: `false`  
V3 design lock raw SHA-256: `{lock_hash}`  
Common full-load lock: `{payload['common_full_load_lock_raw_sha256']}`

The score-free DGP-A smoke passed before this lock was frozen. V3 does not call
or modify the old production attestation path. It stages the currently hashed
v03 wheel/config/archive and v04 sources/config into temporary children, checks
source/config/runtime hashes before and after replay, and records exact child
CPU/environment/thread probes. The comparator declares no GPU backend, so its
children explicitly hide the GPU and execute on CPU.

The simulator constructs evaluator-only data internally, but prediction
adapters receive only public frames. This is a research code boundary, not a
claim of physical production truth custody. The old DGP production
implementation remains `NO_GO_NOT_RESEALED`.

The prediction-stage activation stops after predictions and common identities
are atomically checksummed. Truth selection and scoring require a different,
separately approved activation and a distinct output directory. No A-J score,
fresh/heldout result, registry update, champion change, or promotion evidence
is authorized by the prediction-stage activation.
"""


def _run_plan(lock_hash: str) -> str:
    return f"""# DGP Exploration V3 - Root-approved A-J Cheap Screen

Design lock: `{lock_hash}`  
Common full-load lock: `{COMMON_FULL_LOAD_LOCK_RAW_SHA256}`

After a separate root launch approval, run:

```powershell
$env:PYTHONPATH='src;.'
& '..\\.venv_pe_model_lab_py310\\Scripts\\python.exe' `
  scripts/model_lab/dgp_exploration_v3/run_cheap_screen.py `
  --output outputs/model_zoo_dgp_exploration_v3_predictions_20260820 `
  --max-workers 32 `
  --design-lock-sha256 {lock_hash} `
  --common-full-load-lock-sha256 {COMMON_FULL_LOAD_LOCK_RAW_SHA256} `
  --activation RUN_DGP_EXPLORATION_V3_A_J_CHEAP_EXPLORATION_ONLY
```

This runs 50 `(5 research seeds x 10 DGPs)` tasks. Prediction adapters receive
public frames only. The command atomically seals predictions, diagnostics, and
their exact common identities, then exits with evaluator truth still closed.
Truth selection/scoring uses a separately locked activation and is not part of
this command. Any task, coverage, source/config/runtime, resource-probe, or
common-identity failure emits a terminal no-truth/no-score receipt.
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    parser.add_argument("--smoke-output", type=Path, default=DEFAULT_SMOKE)
    parser.add_argument("--output", type=Path, default=DESIGN_OUTPUT)
    args = parser.parse_args()
    root = repository_root()
    output = (root / args.output).resolve()
    payload = build_lock(
        root=root,
        common_lock_raw_sha256=args.common_full_load_lock_sha256,
        smoke_directory=args.smoke_output,
    )
    raw = canonical_json_bytes(payload)
    lock_hash = hashlib.sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    atomic_write(output / "DESIGN_LOCK.json", raw)
    atomic_write(output / "DESIGN.md", _markdown(lock_hash, payload).encode("utf-8"))
    atomic_write(output / "RUN_PLAN.md", _run_plan(lock_hash).encode("utf-8"))
    atomic_write(
        output / "DESIGN_LOCK.sha256",
        f"{lock_hash}  DESIGN_LOCK.json\n".encode("ascii"),
    )
    checksums = write_checksums(output)
    print(
        json.dumps(
            {
                "design_lock_raw_sha256": lock_hash,
                "checksums_raw_sha256": checksums,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
