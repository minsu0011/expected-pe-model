"""Freeze the common input-only design after a score-blind double smoke."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from research.model_zoo.dgp_state_tournament_v1.artifacts import (
    atomic_write_new,
    canonical_json_bytes,
    canonical_value_sha256,
    write_checksums_new,
)
from research.model_zoo.dgp_state_tournament_v1.contracts import (
    ACTIVATION_LITERAL,
    CANONICAL_HEADER_SHA256,
    CANONICAL_WIDTH,
    COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    DESIGN_OUTPUT_RELATIVE_PATH,
    DEFAULT_TRUTH_VAULT_OUTPUT_RELATIVE_PATH,
    DGPS,
    EVIDENCE_CLASS,
    EXPERIMENT_ID,
    FEASIBILITY_AUDIT_RAW_SHA256,
    FEASIBILITY_AUDIT_RELATIVE_PATH,
    FRESH_OR_HELDOUT_AUTHORITY,
    GPU_OFF_ENVIRONMENT,
    LEGACY_CURRENT_CONTRACT_SHA256,
    LEGACY_CURRENT_IMPLEMENTATION_SHA256,
    LEGACY_GUARD_FIRST_TRANSITION_CONTRACT_SHA256,
    LEGACY_GUARD_FIRST_TRANSITION_IMPLEMENTATION_SHA256,
    LEGACY_SEALED_EXECUTION_CONTRACT_RAW_SHA256,
    LEGACY_SEALED_IMPLEMENTATION_SHA256,
    LEGACY_SEALED_LOGICAL_CONTRACT_SHA256,
    OBSERVABLE_STATE_CONTRACT_SHA256,
    PRODUCTION_AUTHORITY,
    PUBLIC_NAMES,
    RAM_MIN_FREE_GIB,
    RAM_SOFT_BUDGET_GIB,
    ROWS,
    SCORE_END,
    SCORE_START,
    SEEDS,
    SUITE_VERSION,
    THREAD_ENVIRONMENT,
    TRUTH_VAULT_ACTIVATION_LITERAL,
    V3_COMMON_IDENTITIES_RAW_SHA256,
    V3_DESIGN_LOCK_RAW_SHA256,
    V3_DGP_PAYLOAD_SHA256,
    V3_PREDICTION_CHECKSUMS_RAW_SHA256,
    V3_PREDICTION_RECEIPT_RAW_SHA256,
    V3_PREDICTIONS_RAW_SHA256,
    V3_PUBLIC_LEDGER_SEMANTIC_SHA256,
    V3_REPLAY_INVENTORY_COMBINED_SHA256,
)
from research.model_zoo.dgp_state_tournament_v1.precommit import (
    dependency_sha256,
    load_and_verify_v3_bindings,
    repository_root,
    source_sha256,
)
from research.model_zoo.dgp_state_tournament_v1.source_audit import (
    audit_score_blind_source_boundary,
)
from research.model_zoo.dgp_suite.design import implementation_source_hashes
from research.model_zoo.dgp_suite.model_surface import execution_contract_payload
from research.model_zoo.observable_fair_value_state_v1.contracts import (
    OPTIONAL_RELATIVE_SOURCE_COLUMNS,
    REQUIRED_SOURCE_COLUMNS,
    contract_sha256 as observable_state_contract_sha256,
)


DEFAULT_SMOKE = Path("outputs/model_zoo_dgp_state_tournament_v1_smoke_20260820")


def _load_smoke(root: Path, relative: Path) -> tuple[dict[str, Any], str, str]:
    directory = (root / relative).resolve()
    if (
        directory.parent != (root / "outputs").resolve()
        or not directory.name.startswith("model_zoo_dgp_state_tournament_v1_smoke_")
    ):
        raise RuntimeError("smoke directory escaped isolated namespace")
    receipt_path = directory / "SMOKE_RECEIPT.json"
    checksums_path = directory / "CHECKSUMS.sha256"
    raw = receipt_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise RuntimeError("smoke receipt is not canonical JSON")
    required = {
        "status": "PASS_SCORE_BLIND_DOUBLE_REPLAY_SPENT_2026082001_A",
        "production_authority": False,
        "fresh_or_heldout_authority": False,
        "seed": 2026082001,
        "dgp": "A",
        "passes": 2,
        "fresh_process_pool_lifetimes": 2,
        "evaluator_mapping_accessed": False,
        "truth_file_read": False,
        "truth_value_selected": False,
        "score_computed": False,
        "candidate_or_survivor_fit_executed": False,
        "legacy_formal_execution_used": False,
        "old_production_implementation_status": "NO_GO_NOT_RESEALED",
    }
    for key, expected in required.items():
        if payload.get(key) != expected:
            raise RuntimeError(f"smoke receipt {key} differs")
    if not all(payload.get("byte_exact_comparisons", {}).values()):
        raise RuntimeError("smoke byte parity is not exact")
    receipt_hash = hashlib.sha256(raw).hexdigest()
    expected_checksums = f"{receipt_hash}  SMOKE_RECEIPT.json\n".encode("ascii")
    checksums_raw = checksums_path.read_bytes()
    if checksums_raw != expected_checksums:
        raise RuntimeError("smoke checksum manifest differs")
    return payload, receipt_hash, hashlib.sha256(checksums_raw).hexdigest()


def _legacy_formal_no_go(root: Path) -> Mapping[str, Any]:
    sealed_path = root / "research/model_zoo/dgp_suite/EXECUTION_CONTRACT.json"
    sealed_raw = sealed_path.read_bytes()
    if hashlib.sha256(sealed_raw).hexdigest() != LEGACY_SEALED_EXECUTION_CONTRACT_RAW_SHA256:
        raise RuntimeError("legacy sealed execution contract bytes differ")
    sealed = json.loads(sealed_raw.decode("utf-8"))
    current = dict(execution_contract_payload())
    current_implementation = implementation_source_hashes()[1]
    if sealed.get("contract_sha256") != LEGACY_SEALED_LOGICAL_CONTRACT_SHA256:
        raise RuntimeError("legacy sealed logical contract differs")
    if (
        sealed.get("dgp_suite_implementation_combined_sha256")
        != LEGACY_SEALED_IMPLEMENTATION_SHA256
    ):
        raise RuntimeError("legacy sealed implementation hash differs")
    if current.get("contract_sha256") != LEGACY_CURRENT_CONTRACT_SHA256:
        raise RuntimeError("legacy current second-transition contract differs")
    if current_implementation != LEGACY_CURRENT_IMPLEMENTATION_SHA256:
        raise RuntimeError("legacy current second-transition implementation differs")
    if current.get("execution_authorized") is not False or current.get(
        "score_computation_authorized"
    ) is not False:
        raise RuntimeError("legacy formal authority unexpectedly changed")
    return {
        "status": "NO_GO_ISOLATED_NOT_RESEALED_NOT_USED",
        "sealed_execution_contract_raw_sha256": LEGACY_SEALED_EXECUTION_CONTRACT_RAW_SHA256,
        "sealed_logical_contract_sha256": LEGACY_SEALED_LOGICAL_CONTRACT_SHA256,
        "sealed_implementation_combined_sha256": LEGACY_SEALED_IMPLEMENTATION_SHA256,
        "test_guard_first_known_transition_contract_sha256": (
            LEGACY_GUARD_FIRST_TRANSITION_CONTRACT_SHA256
        ),
        "test_guard_first_known_transition_implementation_sha256": (
            LEGACY_GUARD_FIRST_TRANSITION_IMPLEMENTATION_SHA256
        ),
        "current_second_transition_contract_sha256": LEGACY_CURRENT_CONTRACT_SHA256,
        "current_second_transition_implementation_sha256": (
            LEGACY_CURRENT_IMPLEMENTATION_SHA256
        ),
        "execution_authorized": False,
        "score_computation_authorized": False,
        "superseded_or_resealed": False,
        "called_by_input_freeze": False,
    }


def build_lock(*, root: Path, smoke_directory: Path) -> dict[str, Any]:
    v3_lock, v3_receipt = load_and_verify_v3_bindings(root)
    smoke, smoke_hash, smoke_checksums_hash = _load_smoke(root, smoke_directory)
    if observable_state_contract_sha256() != OBSERVABLE_STATE_CONTRACT_SHA256:
        raise RuntimeError("Observable State V1 contract differs")
    public_ledger = v3_receipt["generation_public_hash_by_task"]
    source_audit = audit_score_blind_source_boundary(root)
    return {
        "schema_version": "expected_pe_dgp_state_tournament_v1.input_freeze_design.v1",
        "suite_version": SUITE_VERSION,
        "experiment_id": EXPERIMENT_ID,
        "evidence_class": EVIDENCE_CLASS,
        "production_authority": PRODUCTION_AUTHORITY,
        "fresh_or_heldout_authority": FRESH_OR_HELDOUT_AUTHORITY,
        "execution_status": "PRECOMMITTED_INPUT_FREEZE_NOT_YET_EXECUTED",
        "activation_literal": ACTIVATION_LITERAL,
        "scope": "COMMON_PUBLIC_CANONICAL150_V04_DIAGNOSTICS_PREREQUISITE_ONLY",
        "survivor_binding_status": "NOT_IN_SCOPE_WAITING_EXTERNAL_STATE_BCE_DECISION",
        "survivor_model_ids": [],
        "survivor_fit_authorized": False,
        "truth_file_or_value_selection_authorized": False,
        "scoring_authorized": False,
        "seed_reservation_authorized": False,
        "v3_design_lock_relative_path": (
            "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json"
        ),
        "v3_design_lock_raw_sha256": V3_DESIGN_LOCK_RAW_SHA256,
        "v3_dgp_payload_sha256": V3_DGP_PAYLOAD_SHA256,
        "v3_replay_inventory_combined_sha256": V3_REPLAY_INVENTORY_COMBINED_SHA256,
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "v3_prediction_receipt_raw_sha256": V3_PREDICTION_RECEIPT_RAW_SHA256,
        "v3_predictions_raw_sha256": V3_PREDICTIONS_RAW_SHA256,
        "v3_common_identities_raw_sha256": V3_COMMON_IDENTITIES_RAW_SHA256,
        "v3_prediction_checksums_raw_sha256": V3_PREDICTION_CHECKSUMS_RAW_SHA256,
        "v3_public_ledger_semantic_sha256": V3_PUBLIC_LEDGER_SEMANTIC_SHA256,
        "v3_public_logical_sha256_by_task": public_ledger,
        "v3_closure": {
            "source_hash_matches": len(v3_lock["source_sha256"]),
            "dependency_hash_matches": len(v3_lock["dependency_sha256"]),
            "mismatches": 0,
        },
        "feasibility_audit": {
            "relative_path": FEASIBILITY_AUDIT_RELATIVE_PATH,
            "raw_sha256": FEASIBILITY_AUDIT_RAW_SHA256,
            "decision": "CONDITIONAL_GO_RESEARCH_ONLY_AFTER_NEW_PUBLIC_CANONICAL_OVERLAY_FREEZE",
        },
        "legacy_formal": _legacy_formal_no_go(root),
        "score_free_double_smoke": {
            "relative_path": smoke_directory.as_posix(),
            "receipt_raw_sha256": smoke_hash,
            "checksums_raw_sha256": smoke_checksums_hash,
            "status": smoke["status"],
            "canonical150_raw_sha256": smoke["canonical150_raw_sha256"],
            "v04_overlay_raw_sha256": smoke["v04_overlay_raw_sha256"],
            "normalized_replay_receipt_raw_sha256": smoke[
                "normalized_replay_receipt_raw_sha256"
            ],
            "v3_incumbent_anchor_parity": smoke["v3_incumbent_anchor_parity"],
        },
        "task_geometry": {
            "seeds": list(SEEDS),
            "dgps": list(DGPS),
            "task_count_per_pass": len(SEEDS) * len(DGPS),
            "replay_pass_count": 2,
            "total_comparator_replays": 100,
            "total_child_stages": 200,
            "rows_per_task": ROWS,
            "total_rows_per_pass": len(SEEDS) * len(DGPS) * ROWS,
            "score_start_inclusive": SCORE_START,
            "score_end_exclusive": SCORE_END,
            "target_interval_rows_per_task": SCORE_END - SCORE_START,
            "public_artifacts": list(PUBLIC_NAMES),
            "public_hash_assertions": 500,
        },
        "output_contract": {
            "both_passes_physically_retained": True,
            "downstream_input_pass": "replays/pass_1",
            "task_layout": "replays/pass_<1|2>/seed_<seed>/dgp_<A-J>",
            "per_task_files": [
                "public/{price,benchmark,eps_events,public_factors,corporate_actions}.csv",
                "canonical150.csv",
                "v04_overlay.csv",
                "comparator_diagnostics.csv",
                "REPLAY_RECEIPT.json",
                "PUBLIC_LEDGER.json",
                "GEOMETRY.json",
                "TASK_RECEIPT.json",
            ],
            "canonical_header_sha256": CANONICAL_HEADER_SHA256,
            "canonical_width": CANONICAL_WIDTH,
            "normalization": (
                "only ephemeral child receipt paths and invocation argv below a replay "
                "work root are replaced by $REPLAY_ROOT"
            ),
            "all_public_canonical_overlay_diagnostic_bytes_equal_between_passes": True,
            "immutable_absent_destination_atomic_publish": True,
            "resume_or_overwrite": "FORBIDDEN",
        },
        "truth_vault_contract": {
            "status_before_execution": "PRECOMMITTED_NOT_YET_FROZEN",
            "relative_output_path": DEFAULT_TRUTH_VAULT_OUTPUT_RELATIVE_PATH,
            "activation_literal": TRUTH_VAULT_ACTIVATION_LITERAL,
            "separate_process_pool_from_public_replay_workers": True,
            "prediction_workers_receive_vault_path": False,
            "generator_invocations": 50,
            "complete_evaluator_frames_serialized_without_column_or_row_selection": True,
            "receipt_metadata": ["relative_path", "bytes", "raw_sha256", "rows"],
            "truth_file_reopened_after_write_for_raw_hash_verification": True,
            "truth_file_parsed_after_write": False,
            "truth_value_or_identity_selection": False,
            "truth_join_or_score": False,
            "future_scoring_requires_separate_capability_and_activation": True,
            "public_freeze_requires_external_vault_receipt_raw_sha256": True,
        },
        "observable_state_readiness": {
            "contract_sha256": OBSERVABLE_STATE_CONTRACT_SHA256,
            "required_source_columns": list(REQUIRED_SOURCE_COLUMNS),
            "optional_relative_source_columns": list(OPTIONAL_RELATIVE_SOURCE_COLUMNS),
            "relative_ablation_expected_eligible": False,
            "future_fold_geometry": {
                "first_test_position": 504,
                "test_sessions": 21,
                "step_sessions": 21,
                "fold_count_per_task": 62,
                "terminal_test_sessions": 15,
            },
        },
        "resource_policy": {
            "cpu_ids": list(range(32)),
            "outer_workers_max": 32,
            "inner_threads": 1,
            "thread_environment": THREAD_ENVIRONMENT,
            "gpu_enabled": False,
            "gpu_environment": GPU_OFF_ENVIRONMENT,
            "ram_soft_budget_gib": RAM_SOFT_BUDGET_GIB,
            "ram_min_free_gib": RAM_MIN_FREE_GIB,
            "passes_overlap": False,
            "worker_pool_context": "spawn",
            "ram_reserved_claim": False,
        },
        "custody": {
            "simulator_constructs_public_and_evaluator_namespaces": True,
            "expected_public_replay_simulator_constructions": 100,
            "expected_detached_vault_simulator_constructions": 50,
            "runner_copies_public_mapping_only": True,
            "evaluator_mapping_accessed": False,
            "full_generation_audit_copied": False,
            "truth_file_read": False,
            "truth_value_selected": False,
            "score_computed": False,
            "candidate_or_survivor_fit_executed": False,
        },
        "source_boundary_audit": source_audit,
        "source_sha256": source_sha256(root),
        "dependency_sha256": dependency_sha256(root),
    }


def _design_markdown(lock_hash: str, payload: Mapping[str, Any]) -> str:
    return f"""# Spent V3 DGP Public-Input Freeze Design

Status: `PRECOMMITTED_INPUT_FREEZE_NOT_YET_EXECUTED`  
Evidence: `{EVIDENCE_CLASS}`  
Design lock raw SHA-256: `{lock_hash}`

This design authorizes only two independent score-blind replays of the 50
already-spent V3 A--J public tasks. Both physical passes are retained and must
match byte-for-byte for all five public artifacts, canonical150, v04 overlay,
and full-row comparator diagnostics. Only ephemeral receipt paths/invocation
argv are normalized.

The legacy formal DGP chain remains `{payload['legacy_formal']['status']}`.
This lane uses the separately valid V3 research lock and has no production,
fresh/heldout, promotion, survivor-fit, truth-selection, scoring, or seed
reservation authority. A later stage may bind one externally selected survivor
to the frozen pass-1 inputs; this design cannot select or fit it.
"""


def _run_plan(lock_hash: str) -> str:
    return f"""# Detached vault then input-only double replay commands

First freeze the inert vault (files are only byte-hashed; values are never parsed or selected):

```powershell
$env:PYTHONPATH='src;.'
& 'C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_py310\\Scripts\\python.exe' `
  scripts/model_lab/dgp_state_tournament_v1/freeze_truth_vault.py `
  --output {DEFAULT_TRUTH_VAULT_OUTPUT_RELATIVE_PATH} `
  --workers 32 `
  --design-lock-sha256 {lock_hash} `
  --v3-design-lock-sha256 {V3_DESIGN_LOCK_RAW_SHA256} `
  --v3-prediction-receipt-sha256 {V3_PREDICTION_RECEIPT_RAW_SHA256} `
  --v3-predictions-sha256 {V3_PREDICTIONS_RAW_SHA256} `
  --v3-common-identities-sha256 {V3_COMMON_IDENTITIES_RAW_SHA256} `
  --common-full-load-lock-sha256 {COMMON_FULL_LOAD_LOCK_RAW_SHA256} `
  --activation {TRUTH_VAULT_ACTIVATION_LITERAL}
```

Then externally pass the emitted vault receipt hash to the public freeze:

```powershell
$env:PYTHONPATH='src;.'
& 'C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_py310\\Scripts\\python.exe' `
  scripts/model_lab/dgp_state_tournament_v1/run_tournament.py freeze-inputs `
  --output outputs/model_zoo_dgp_state_tournament_v1_inputs_20260820 `
  --workers 32 `
  --design-lock-sha256 {lock_hash} `
  --v3-design-lock-sha256 {V3_DESIGN_LOCK_RAW_SHA256} `
  --v3-prediction-receipt-sha256 {V3_PREDICTION_RECEIPT_RAW_SHA256} `
  --v3-predictions-sha256 {V3_PREDICTIONS_RAW_SHA256} `
  --v3-common-identities-sha256 {V3_COMMON_IDENTITIES_RAW_SHA256} `
  --truth-vault-receipt-sha256 <EXTERNAL_VAULT_RECEIPT_RAW_SHA256> `
  --common-full-load-lock-sha256 {COMMON_FULL_LOAD_LOCK_RAW_SHA256} `
  --activation {ACTIVATION_LITERAL}
```

The command exits after immutable public/canonical/overlay/diagnostic freeze.
It cannot fit a survivor, open truth, score, or reserve a seed.
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-output", type=Path, default=DEFAULT_SMOKE)
    parser.add_argument("--output", type=Path, default=Path(DESIGN_OUTPUT_RELATIVE_PATH))
    args = parser.parse_args()
    root = repository_root()
    output = (root / args.output).resolve()
    if output.parent != (root / "outputs").resolve():
        raise RuntimeError("design output escaped direct outputs child")
    if output.exists():
        raise RuntimeError("immutable design output already exists")
    payload = build_lock(root=root, smoke_directory=args.smoke_output)
    raw = canonical_json_bytes(payload)
    lock_hash = hashlib.sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    atomic_write_new(output / "DESIGN_LOCK.json", raw)
    atomic_write_new(output / "DESIGN.md", _design_markdown(lock_hash, payload).encode("utf-8"))
    atomic_write_new(output / "RUN_PLAN.md", _run_plan(lock_hash).encode("utf-8"))
    atomic_write_new(
        output / "DESIGN_LOCK.sha256",
        f"{lock_hash}  DESIGN_LOCK.json\n".encode("ascii"),
    )
    checksums_sha = write_checksums_new(output)
    print(
        json.dumps(
            {
                "design_lock_raw_sha256": lock_hash,
                "checksums_raw_sha256": checksums_sha,
                "source_semantic_sha256": canonical_value_sha256(payload["source_sha256"]),
                "dependency_semantic_sha256": canonical_value_sha256(
                    payload["dependency_sha256"]
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
