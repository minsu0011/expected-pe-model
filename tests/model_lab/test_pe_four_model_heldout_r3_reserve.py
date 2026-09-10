from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Mapping

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/model_lab/pe_four_model_heldout_r3_reserve.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pe_r3_reserve_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Fixture:
    module: ModuleType
    root: Path
    runtime: object
    run_id: str
    precommit_path: Path
    precommit_sha: str
    independent_audit_path: Path
    independent_audit_sha: str
    gate_path: Path
    gate_sha: str
    registry_path: Path
    predecessor_entry: Mapping[str, object]
    tracker: dict[str, int]


def _write_json(module: ModuleType, path: Path, value: object) -> bytes:
    raw = module._canonical_pretty_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _sealed(module: ModuleType, value: Mapping[str, object], key: str) -> dict[str, object]:
    result = copy.deepcopy(dict(value))
    unsigned = {name: item for name, item in result.items() if name != key}
    result[key] = module._semantic_sha256(unsigned)
    return result


def _fixture(tmp_path: Path) -> Fixture:
    module = _load()
    root = tmp_path.resolve()
    (root / "outputs").mkdir()
    run_id = "r3_synthetic_reservation"
    quarantine = (101, 103, 107, 109, 113)
    heldout = (127, 131, 137, 139, 149)
    selected = (*quarantine, *heldout)
    rehearsal_seeds = (901, 903, 907, 909, 913)
    model_ids = ("champion", "candidate_c4", "candidate_c2", "candidate_c3")
    tracker = {"lock_acquire": 0, "registry_write": 0, "protocol_build": 0}

    evidence_path = root / "research/producer_evidence.py"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_bytes(b"synthetic producer evidence\n")
    constants_path = root / "research/evaluator_constants.py"
    constants_path.write_bytes(b"synthetic evaluator constants with 18 keys\n")
    validator_path = root / "scripts/registry_validator.py"
    validator_path.parent.mkdir()
    validator_path.write_bytes(b"synthetic pinned registry validator\n")
    qualification_path = root / "research/qualification_seed_authority.py"
    qualification_path.write_bytes(b"synthetic qualification seed authority\n")

    terminal_core = {
        "schema_version": module.R2_TERMINAL_SCHEMA,
        "status": module.R2_TERMINAL_STATUS,
        "run_id": "r2_synthetic_terminal",
        "terminal": True,
        "retry_allowed": False,
        "recovery_allowed": False,
        "certification_authority": False,
        "seed_disposition": {
            "all_reserved_seeds_conservatively_spent": True,
            "seed_reuse_allowed": False,
            "additional_recovery_reservation_allowed": False,
        },
        "prohibitions": {
            "numeric_predictions_rerun": False,
            "prediction_bundle_activated": False,
            "heldout_scorer_invoked": False,
            "model_selection_or_tuning_performed": False,
        },
        "access": {
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
        },
    }
    terminal = {
        **terminal_core,
        "terminal_semantic_sha256": module._semantic_sha256(terminal_core),
    }
    terminal_relative = "outputs/r2_terminal/TERMINAL_FAILURE.json"
    terminal_raw = _write_json(module, root / terminal_relative, terminal)
    terminal_sha = module._sha256(terminal_raw)

    registry_contract_keys = (
        "format_version",
        "registry_id",
        "owner_output_root",
        "source_config_sha256",
        "candidates_sha256",
        "policy_config_sha256",
        "tuning_seeds",
        "locked_seeds",
        "reserved_seeds",
    )
    prior_contract = {
        "format_version": 1,
        "registry_id": "synthetic-registry-v1",
        "owner_output_root": str(root / "outputs/prior"),
        "source_config_sha256": "1" * 64,
        "candidates_sha256": "2" * 64,
        "policy_config_sha256": "3" * 64,
        "tuning_seeds": [41],
        "locked_seeds": [43],
        "reserved_seeds": [41, 43],
    }
    genesis = "4" * 64
    prior_entry_core = {
        **prior_contract,
        "sequence": 1,
        "previous_entry_sha256": genesis,
        "reservation_id": module._semantic_sha256(prior_contract),
        "created_at_utc": "synthetic-prior",
    }
    prior_entry = _sealed(module, prior_entry_core, "entry_sha256")
    registry_core = {
        "format_version": 1,
        "registry_id": "synthetic-registry-v1",
        "genesis_sha256": genesis,
        "entries": [prior_entry],
        "updated_at_utc": "synthetic-prior",
    }
    registry = _sealed(module, registry_core, "registry_sha256")
    registry_relative = "outputs/v04_spent_seed_registry.json"
    registry_raw = _write_json(module, root / registry_relative, registry)
    registry_sha = module._sha256(registry_raw)
    predecessor = {
        "entry_count": 1,
        "last_entry_sha256": prior_entry["entry_sha256"],
        "maximum_reserved_seed": 43,
        "raw_sha256": registry_sha,
        "registry_self_sha256": registry["registry_sha256"],
        "relative_path": registry_relative,
    }

    gate_core = {
        "schema_version": module.REHEARSAL_SCHEMA,
        "status": module.REHEARSAL_STATUS,
        "run_id": "r3full_synthetic",
        "fixture_profile": {
            "seeds_in_order": list(rehearsal_seeds),
            "seed_selection": "EXPLICIT_FIXED_NONRANDOM_FIXTURE",
            "seed_profile_frozen_before_execution": True,
            "permanently_excluded_from_formal_reservation": True,
            "formal_seed_reservation_count": 0,
            "dgp_ids_in_order": list("ABCDEFGHIJ"),
        },
        "task_count": 50,
        "identity_count": 64_800,
        "prediction_row_count": 259_200,
        "model_ids_in_order": list(model_ids),
        "c1_prediction_row_count": 0,
        "registry_before_raw_sha256": registry_sha,
        "registry_after_raw_sha256": registry_sha,
        "registry_entry_count": 1,
        "registry_bytes_unchanged": True,
        "spent_seed_overlap_count": 0,
        "formal_seed_reservation_count": 0,
        "handle_write_to_read_only_custody_transition": "PASS",
        "independent_path_reopen_hash_fileid_recompute": "PASS",
        "commit_last_audit_checksums_seal": "PASS",
        "rehearsal_activation": "PASS",
        "detached_evaluator_plumbing": "PASS",
        "all_child_processes_reaped": True,
        "no_r2_path_or_artifact_reuse": True,
        "candidate_tuning_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    gate = {
        **gate_core,
        "result_semantic_sha256": module._semantic_sha256(gate_core),
    }
    gate_relative = "build/rehearsal/R3_REHEARSAL_RESULT.json"
    gate_raw = _write_json(module, root / gate_relative, gate)
    gate_sha = module._sha256(gate_raw)

    independence = {
        "candidate_performance_consulted": False,
        "dgp_outcome_consulted": False,
        "heldout_truth_consulted": False,
        "qualification_error_surface_consulted": False,
        "score_content_consulted": False,
        "selection_retry_allowed": False,
    }
    derivation = "Synthetic deterministic ascending selection frozen before values"
    assignment = "First five quarantine and final five heldout in order"
    policy = {
        "allocation_role_policy": {
            "compatibility_quarantine_count": 5,
            "compatibility_quarantine_generator_invocation_allowed": False,
            "compatibility_quarantine_reason": "legacy registry schema",
            "compatibility_quarantine_scoring_allowed": False,
            "formal_heldout_count": 5,
            "formal_heldout_role": "ONLY_FORMAL_HELDOUT",
            "new_reserved_seed_count": 10,
        },
        "authority_inputs": {
            "formal_audit_contract_alignment": {
                "audit_check_key_count": 18,
                "evaluator_constants_raw_sha256": module._sha256(
                    constants_path.read_bytes()
                ),
                "evaluator_constants_relative_path": constants_path.relative_to(
                    root
                ).as_posix(),
                "producer_evidence_raw_sha256": module._sha256(
                    evidence_path.read_bytes()
                ),
                "producer_evidence_relative_path": evidence_path.relative_to(
                    root
                ).as_posix(),
            },
            "r2_terminal_handoff": {
                "relative_path": "build/synthetic_handoff.md",
                "raw_sha256": "5" * 64,
            },
            "r2_terminal_prediction": {
                "relative_path": terminal_relative,
                "raw_sha256": terminal_sha,
            },
            "r3_direction_prompt": {
                "source_path": "C:/synthetic/prompt.txt",
                "raw_sha256": "6" * 64,
            },
            "r3_full_nonreserved_rehearsal": {
                "relative_path": gate_relative,
                "raw_sha256": gate_sha,
                "status": module.REHEARSAL_STATUS,
                "task_count": 50,
                "identity_count": 64_800,
                "prediction_row_count": 259_200,
                "registry_mutation_count": 0,
                "truth_open_count": 0,
                "score_open_count": 0,
            },
            "remediation_source_hashes": {
                "synthetic_remediation": "7" * 64,
            },
            "spent_seed_registry_predecessor": predecessor,
            "spent_seed_registry_validation_source": {
                "relative_path": validator_path.relative_to(root).as_posix(),
                "raw_sha256": module._sha256(validator_path.read_bytes()),
            },
        },
        "candidate_and_evidence_independence": independence,
        "exclusion_policy": {
            "all_registry_reserved_seeds_excluded": True,
            "qualification_seeds_excluded": True,
            "r1_and_r2_formal_seeds_excluded": True,
            "r3_rehearsal_fixture_seeds_excluded": True,
            "r3_rehearsal_fixture_seeds_in_order": list(rehearsal_seeds),
        },
        "formal_execution_policy": {
            "additional_recovery_reservation_allowed": False,
            "candidate_formula_change_allowed": False,
            "candidate_order_change_allowed": False,
            "candidate_tuning_allowed": False,
            "exact_formal_heldout_seed_count": 5,
            "post_result_seed_change_allowed": False,
            "r2_artifact_reuse_allowed": False,
            "r2_seed_reuse_allowed": False,
            "reservation_append_count": 1,
            "reservation_retry_allowed": False,
            "seed_cherry_picking_allowed": False,
        },
        "new_seed_values_present": False,
        "run_id": run_id,
        "schema_version": module.POLICY_SCHEMA,
        "selection_rule": {
            "assignment": assignment,
            "derivation": derivation,
            "primality_definition": "Synthetic values are precommitted, not derived here",
            "tie_or_randomness": "NONE_DETERMINISTIC_ASCENDING_INTEGER_SCAN",
            "value_derivation_authorized_only_after_this_policy_raw_sha256_is_RECORDED": True,
        },
        "status": module.POLICY_STATUS,
    }
    policy_relative = "build/r3_value_free_policy.json"
    policy_raw = _write_json(module, root / policy_relative, policy)
    policy_sha = module._sha256(policy_raw)

    pre_derivation_gate = {
        "authority_bindings": {
            "evaluator_repin_helper": {
                "relative_path": "scripts/model_lab/synthetic_repin.py",
                "raw_sha256": "8" * 64,
                "test_raw_sha256": "9" * 64,
            },
            "post_generation_auditor": {
                "relative_path": "scripts/model_lab/synthetic_postgen.py",
                "raw_sha256": "a" * 64,
                "test_raw_sha256": "b" * 64,
            },
            "r2_terminal_prediction": {
                "relative_path": terminal_relative,
                "raw_sha256": terminal_sha,
            },
            "r3_full_nonreserved_rehearsal": {
                "relative_path": gate_relative,
                "raw_sha256": gate_sha,
                "status": module.REHEARSAL_STATUS,
            },
            "seed_allocator": {
                "raw_sha256_before_gate_binding": "c" * 64,
                "relative_path": "scripts/model_lab/synthetic_allocator.py",
                "test_raw_sha256_before_gate_binding": "d" * 64,
            },
            "spent_seed_registry_predecessor": {
                key: predecessor[key]
                for key in (
                    "entry_count",
                    "last_entry_sha256",
                    "raw_sha256",
                    "registry_self_sha256",
                    "relative_path",
                )
            },
            "value_free_seed_policy": {
                "relative_path": policy_relative,
                "raw_sha256": policy_sha,
                "status": module.POLICY_STATUS,
            },
        },
        "blocked_actions_until_later_reservation_gate": [
            "SPENT_SEED_REGISTRY_APPEND",
            "FORMAL_HELDOUT_GENERATION",
            "FORMAL_PREDICTION",
            "ACTIVATION_MINT",
            "TRUTH_OPEN",
            "SCORING",
        ],
        "formal_seed_derivation_count_at_gate": 0,
        "formula_lock_semantic_sha256": module._semantic_sha256(
            {"formula": "frozen"}
        ),
        "model_ids_in_order": list(model_ids),
        "registry_mutation_count_at_gate": 0,
        "resource_execution_plan": {
            "formal_generation_outer_workers": 16,
            "formal_prediction_cpu_workers": 32,
            "gpu_execution_authorized": False,
        },
        "run_id": run_id,
        "schema_version": module.PRE_DERIVATION_GATE_SCHEMA,
        "status": module.PRE_DERIVATION_GATE_STATUS,
        "test_evidence": {
            "evaluator_repin_complete_byte_no_op": "PASS",
            "handle_lifecycle_windows_subprocess": "PASS",
            "post_generation_full_synthetic_50_task_run_audit": "PASS",
            "post_generation_resealed_extra_key_attacks": "PASS",
            "producer_evaluator_exact_18_key_parity": "PASS",
            "ruff_lint": "PASS",
        },
        "truth_open_count_at_gate": 0,
    }
    pre_derivation_relative = "build/r3_pre_derivation_gate.json"
    pre_derivation_raw = _write_json(
        module,
        root / pre_derivation_relative,
        pre_derivation_gate,
    )
    pre_derivation_sha = module._sha256(pre_derivation_raw)

    commitment_payload = {"locked_seeds": list(heldout)}
    overlap = {
        "prior_spent_overlap_count": 0,
        "qualification_seed_overlap_count": 0,
        "r2_formal_seed_overlap_count": 0,
        "rehearsal_fixture_overlap_count": 0,
        "within_allocation_duplicate_count": 0,
    }
    precommit = {
        "deterministic_next_ten_primes": list(selected),
        "formal_execution_policy": {
            "additional_recovery_reservation_allowed": False,
            "exact_heldout_seed_count": 5,
            "post_result_seed_change_allowed": False,
            "quarantine_generator_invocation_allowed": False,
            "r2_seed_reuse_allowed": False,
            "seed_cherry_picking_allowed": False,
        },
        "heldout_seed_commitment_payload": commitment_payload,
        "heldout_seed_commitment_sha256": module._semantic_sha256(
            commitment_payload
        ),
        "heldout_seeds_in_order": list(heldout),
        "overlap_audit": overlap,
        "pre_derivation_gate": {
            "relative_path": pre_derivation_relative,
            "raw_sha256": pre_derivation_sha,
            "status": module.PRE_DERIVATION_GATE_STATUS,
        },
        "quarantine_seeds_never_generate_or_score": list(quarantine),
        "registry_before": {
            **predecessor,
            "globally_spent_seed_count": 2,
        },
        "run_id": run_id,
        "schema_version": module.PRECOMMIT_SCHEMA,
        "selection_rule": {
            "algorithm": derivation,
            "assignment": assignment,
            **independence,
        },
        "status": module.PRECOMMIT_STATUS,
        "value_free_policy_raw_sha256": policy_sha,
        "value_free_policy_relative_path": policy_relative,
    }
    precommit_relative = "build/r3_seed_precommit.json"
    precommit_raw = _write_json(module, root / precommit_relative, precommit)
    precommit_sha = module._sha256(precommit_raw)

    live_checks = {
        "all_checks_pass": True,
        "evaluator_repin_helper_raw_sha256_exact": True,
        "evaluator_repin_test_raw_sha256_exact": True,
        "historical_seed_allocator_raw_sha256_reconstructed_exact": True,
        "historical_seed_allocator_test_raw_sha256_reconstructed_exact": True,
        "post_generation_auditor_raw_sha256_exact": True,
        "post_generation_auditor_test_raw_sha256_exact": True,
        "r2_terminal_prediction_raw_sha256_exact": True,
        "r3_full_nonreserved_rehearsal_raw_sha256_exact": True,
        "spent_seed_registry_predecessor_raw_sha256_exact": True,
        "value_free_seed_policy_raw_sha256_exact": True,
    }
    audit_core = {
        "access_counts": {
            "heldout_protected_open_count": 0,
            "performance_content_consulted_count": 0,
            "score_open_count": 0,
            "truth_open_count": 0,
        },
        "append_performed": False,
        "audit_method": {
            "allocator_build_precommit_invoked": False,
            "allocator_main_invoked": False,
            "independent_primality_method": (
                "TRIAL_DIVISION_2_THROUGH_INTEGER_SQRT"
            ),
            "read_only_recomputation": True,
            "source_modified": False,
        },
        "independent_recomputation": {
            "deterministic_next_ten_primes": list(selected),
            "heldout_seed_commitment_payload": commitment_payload,
            "heldout_seed_commitment_sha256": precommit[
                "heldout_seed_commitment_sha256"
            ],
            "heldout_seeds_in_order": list(heldout),
            "predecessor_maximum_reserved_seed": predecessor[
                "maximum_reserved_seed"
            ],
            "primality_all_exact": True,
            "quarantine_seeds_never_generate_or_score": list(quarantine),
            "role_assignment_exact": True,
            "sequence_exact": True,
            "strictly_ascending_unique": True,
        },
        "input_bindings": {
            "pre_derivation_gate": {
                "canonical_full_payload_sha256": module._semantic_sha256(
                    pre_derivation_gate
                ),
                "raw_sha256": pre_derivation_sha,
                "relative_path": pre_derivation_relative,
                "status": module.PRE_DERIVATION_GATE_STATUS,
            },
            "qualification_seed_authority_source": {
                "raw_sha256": module._sha256(qualification_path.read_bytes()),
                "relative_path": qualification_path.relative_to(root).as_posix(),
            },
            "r2_terminal_prediction": {
                "raw_sha256": terminal_sha,
                "relative_path": terminal_relative,
                "semantic_sha256": terminal["terminal_semantic_sha256"],
                "status": module.R2_TERMINAL_STATUS,
            },
            "r3_full_nonreserved_rehearsal": {
                "raw_sha256": gate_sha,
                "relative_path": gate_relative,
                "semantic_sha256": gate["result_semantic_sha256"],
                "status": module.REHEARSAL_STATUS,
            },
            "seed_precommit": {
                "canonical_full_payload_sha256": module._semantic_sha256(
                    precommit
                ),
                "raw_sha256": precommit_sha,
                "relative_path": precommit_relative,
                "status": module.PRECOMMIT_STATUS,
            },
            "spent_seed_registry_predecessor": {
                "raw_sha256": predecessor["raw_sha256"],
                "registry_self_sha256": predecessor["registry_self_sha256"],
                "relative_path": predecessor["relative_path"],
            },
            "spent_seed_validation_source": {
                "raw_sha256": module._sha256(validator_path.read_bytes()),
                "relative_path": validator_path.relative_to(root).as_posix(),
            },
            "value_free_seed_policy": {
                "canonical_full_payload_sha256": module._semantic_sha256(policy),
                "raw_sha256": policy_sha,
                "relative_path": policy_relative,
                "status": module.POLICY_STATUS,
            },
        },
        "live_gate_source_pin_checks": live_checks,
        "overlap_counts": overlap,
        "registry_predecessor_state": {
            "append_performed": False,
            "entry_count": predecessor["entry_count"],
            "globally_spent_seed_count": 2,
            "last_entry_sha256": predecessor["last_entry_sha256"],
            "maximum_reserved_seed": predecessor["maximum_reserved_seed"],
            "mutation_count": 0,
            "raw_sha256": predecessor["raw_sha256"],
            "registry_self_sha256": predecessor["registry_self_sha256"],
            "reservation_performed": False,
        },
        "reservation_authorization": {
            "additional_reservation_or_retry_allowed": False,
            "authorized_next_registry_append_count": 1,
            "compatibility_quarantine_count": 5,
            "formal_heldout_count": 5,
            "formal_truth_or_score_access_authorized": False,
            "scope": "ONE_R3_REGISTRY_RESERVATION_APPEND_ONLY_PRETRUTH",
        },
        "run_id": run_id,
        "schema_version": module.INDEPENDENT_AUDIT_SCHEMA,
        "spent_seed_accounting": {
            "baseline_spent_seed_count": 0,
            "globally_spent_seed_count": 2,
            "qualification_seed_count": 5,
            "qualification_seeds_all_in_spent": True,
            "r2_seed_count": 10,
            "r2_seeds_all_in_spent": True,
            "registry_reserved_seed_count": 2,
            "rehearsal_fixture_count": len(rehearsal_seeds),
            "rehearsal_fixture_disjoint_from_spent": True,
        },
        "status": module.INDEPENDENT_AUDIT_STATUS,
    }
    audit = {
        **audit_core,
        "audit_semantic_sha256": module._semantic_sha256(audit_core),
    }
    audit_relative = "build/r3_independent_audit.json"
    audit_raw = _write_json(module, root / audit_relative, audit)
    audit_sha = module._sha256(audit_raw)

    def verify_registry(value: Mapping[str, Any]) -> None:
        unsigned = dict(value)
        stored = unsigned.pop("registry_sha256")
        assert stored == module._semantic_sha256(unsigned)
        entries = value["entries"]
        for ordinal, entry in enumerate(entries, start=1):
            assert entry["sequence"] == ordinal
            entry_unsigned = dict(entry)
            entry_stored = entry_unsigned.pop("entry_sha256")
            assert entry_stored == module._semantic_sha256(entry_unsigned)

    def read_registry(path: Path) -> Mapping[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        verify_registry(value)
        return value

    def reservation_contract_from_entry(entry: Mapping[str, Any]) -> Mapping[str, Any]:
        return {name: copy.deepcopy(entry[name]) for name in registry_contract_keys}

    def verify_contract(contract: Mapping[str, Any]) -> None:
        assert set(contract) == set(registry_contract_keys)
        assert contract["format_version"] == 1
        assert contract["registry_id"] == "synthetic-registry-v1"
        assert len(contract["tuning_seeds"]) == len(contract["locked_seeds"]) == 5
        assert contract["reserved_seeds"] == sorted(
            [*contract["tuning_seeds"], *contract["locked_seeds"]]
        )

    def build_protocol_lock(
        *, run_id: str, r2_protocol_binding: Mapping[str, object]
    ) -> Mapping[str, object]:
        tracker["protocol_build"] += 1
        assert set(r2_protocol_binding["overlap_audit"]) == {
            "prior_spent_overlap_count",
            "r1_heldout_overlap_count",
            "qualification_seed_overlap_count",
            "within_allocation_duplicate_count",
        }
        assert r2_protocol_binding["final_nonreserved_preflight"]["status"] == (
            module.REHEARSAL_STATUS
        )
        core = {
            "schema_version": "expected_pe.four_model.r3_protocol_lock.v1",
            "status": "FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH",
            "run_id": run_id,
            "r2_protocol_binding": copy.deepcopy(dict(r2_protocol_binding)),
            "r2_protocol_binding_semantic_sha256": module._semantic_sha256(
                r2_protocol_binding
            ),
        }
        return {**core, "policy_lock_sha256": module._semantic_sha256(core)}

    def validate_protocol_lock(
        value: Mapping[str, object],
        *,
        expected_run_id: str,
        project_root: Path | None = None,
        expected_lock_relative_path: str | None = None,
    ) -> Mapping[str, object]:
        del project_root, expected_lock_relative_path
        assert value["schema_version"] == "expected_pe.four_model.r3_protocol_lock.v1"
        assert value["status"] == "FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH"
        assert value["run_id"] == expected_run_id
        unsigned = dict(value)
        seal = unsigned.pop("policy_lock_sha256")
        assert seal == module._semantic_sha256(unsigned)
        return dict(value)

    def read_protocol_lock(
        path: Path,
        *,
        project_root: Path,
        expected_run_id: str,
        expected_raw_sha256: str,
    ) -> Mapping[str, object]:
        del project_root
        raw = path.read_bytes()
        assert module._sha256(raw) == expected_raw_sha256
        return validate_protocol_lock(
            json.loads(raw.decode("utf-8")), expected_run_id=expected_run_id
        )

    def acquire_registry_lock(path: Path) -> tuple[int, Path]:
        tracker["lock_acquire"] += 1
        lock_path = path.with_suffix(path.suffix + ".lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        return descriptor, lock_path

    def release_registry_lock(descriptor: int, path: Path) -> None:
        os.close(descriptor)
        path.unlink()

    utc_counter = iter(("synthetic-new-entry", "synthetic-registry-update"))

    def atomic_write_registry(path: Path, value: Mapping[str, Any]) -> None:
        tracker["registry_write"] += 1
        raw = (
            json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode()
        path.write_bytes(raw)

    runtime = module.RuntimeBindings(
        canonical_pretty_bytes=module._canonical_pretty_bytes,
        semantic_sha256=module._semantic_sha256,
        safe_run_id=lambda value: value
        if type(value) is str and value.startswith("r3_")
        else (_ for _ in ()).throw(ValueError("unsafe run")),
        heldout_seeds=heldout,
        quarantine_seeds=quarantine,
        heldout_seed_commitment_sha256=precommit[
            "heldout_seed_commitment_sha256"
        ],
        precommit_relative_path=precommit_relative,
        precommit_raw_sha256=precommit_sha,
        independent_audit_relative_path=audit_relative,
        independent_audit_raw_sha256=audit_sha,
        r2_terminal_relative_path=terminal_relative,
        r2_terminal_raw_sha256=terminal_sha,
        registry_relative_path=registry_relative,
        registry_before_raw_sha256=registry_sha,
        registry_before_entry_count=1,
        registry_previous_entry_sha256=prior_entry["entry_sha256"],
        protocol_schema="expected_pe.four_model.r3_protocol_lock.v1",
        protocol_status="FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH",
        protocol_root_prefix="model_zoo_pe_four_model_heldout_r3_reservation_",
        protocol_leaf="promotion_policy.lock.json",
        model_ids_in_order=model_ids,
        survivor_ids_in_order=model_ids[1:],
        source_model_versions={"synthetic": "v1"},
        formula_lock={"formula": "frozen"},
        build_source_manifest=lambda **_: {
            "source_manifest_semantic_sha256": "8" * 64
        },
        source_manifest_inputs=lambda _: {},
        generation_plan=lambda: {
            "heldout_seeds_in_order": list(heldout),
            "estimator_rng_seeds_in_order": list(heldout),
            "task_count": 50,
            "identity_count": 64_800,
            "prediction_row_count": 259_200,
        },
        build_protocol_lock=build_protocol_lock,
        validate_protocol_lock=validate_protocol_lock,
        read_protocol_lock=read_protocol_lock,
        registry_format_version=1,
        registry_id="synthetic-registry-v1",
        canonical_output_root=lambda path: str(path.resolve()),
        require_managed_output_root=lambda path: path.resolve(),
        read_registry=read_registry,
        reservation_contract_from_entry=reservation_contract_from_entry,
        reservation_id=module._semantic_sha256,
        acquire_registry_lock=acquire_registry_lock,
        release_registry_lock=release_registry_lock,
        verify_reservation_contract=verify_contract,
        verify_registry=verify_registry,
        seal_payload=lambda value, key: _sealed(module, value, key),
        utc_now=lambda: next(utc_counter),
        atomic_write_registry=atomic_write_registry,
        registry_jsonable=lambda value: value,
        baseline_spent_seeds=(),
    )
    return Fixture(
        module=module,
        root=root,
        runtime=runtime,
        run_id=run_id,
        precommit_path=Path(precommit_relative),
        precommit_sha=precommit_sha,
        independent_audit_path=Path(audit_relative),
        independent_audit_sha=audit_sha,
        gate_path=Path(gate_relative),
        gate_sha=gate_sha,
        registry_path=root / registry_relative,
        predecessor_entry=prior_entry,
        tracker=tracker,
    )


def _plan(fixture: Fixture, *, runtime: object | None = None) -> object:
    return fixture.module.build_reservation_plan(
        project_root=fixture.root,
        run_id=fixture.run_id,
        seed_precommit=fixture.precommit_path,
        seed_precommit_raw_sha256=fixture.precommit_sha,
        independent_audit=fixture.independent_audit_path,
        independent_audit_raw_sha256=fixture.independent_audit_sha,
        rehearsal_gate=fixture.gate_path,
        rehearsal_gate_raw_sha256=fixture.gate_sha,
        runtime=fixture.runtime if runtime is None else runtime,
    )


def test_read_only_plan_is_exact_and_performs_zero_mutation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    before = {
        path.relative_to(fixture.root).as_posix(): path.read_bytes()
        for path in fixture.root.rglob("*")
        if path.is_file()
    }

    plan = _plan(fixture)

    after = {
        path.relative_to(fixture.root).as_posix(): path.read_bytes()
        for path in fixture.root.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert not plan.output_root.exists()
    assert plan.report["planned_registry_append_count"] == 1
    assert plan.report["new_reserved_seed_count"] == 10
    assert plan.report["independent_audit_ref"] == {
        "relative_path": fixture.independent_audit_path.as_posix(),
        "raw_sha256": fixture.independent_audit_sha,
        "status": fixture.module.INDEPENDENT_AUDIT_STATUS,
        "audit_semantic_sha256": plan.independent_audit.value[
            "audit_semantic_sha256"
        ],
    }
    assert plan.report["policy_config_sha256"] == plan.reservation_contract[
        "policy_config_sha256"
    ]
    assert fixture.tracker == {
        "lock_acquire": 0,
        "registry_write": 0,
        "protocol_build": 1,
    }
    report_text = json.dumps(plan.report, sort_keys=True)
    assert "heldout_seeds_in_order" not in report_text
    assert "quarantine_seeds_never_generate_or_score" not in report_text


@pytest.mark.parametrize(
    "drift", ("heldout", "quarantine", "precommit_hash", "audit_hash")
)
def test_producer_or_cli_pin_drift_rejects_before_registry_access(
    tmp_path: Path, drift: str
) -> None:
    fixture = _fixture(tmp_path)
    runtime = fixture.runtime
    precommit_sha = fixture.precommit_sha
    audit_sha = fixture.independent_audit_sha
    if drift == "heldout":
        runtime = replace(runtime, heldout_seeds=tuple(reversed(runtime.heldout_seeds)))
    elif drift == "quarantine":
        runtime = replace(runtime, quarantine_seeds=tuple(reversed(runtime.quarantine_seeds)))
    elif drift == "precommit_hash":
        precommit_sha = "f" * 64
    else:
        audit_sha = "f" * 64
    registry_before = fixture.registry_path.read_bytes()

    with pytest.raises(fixture.module.R3ReservationError):
        fixture.module.build_reservation_plan(
            project_root=fixture.root,
            run_id=fixture.run_id,
            seed_precommit=fixture.precommit_path,
            seed_precommit_raw_sha256=precommit_sha,
            independent_audit=fixture.independent_audit_path,
            independent_audit_raw_sha256=audit_sha,
            rehearsal_gate=fixture.gate_path,
            rehearsal_gate_raw_sha256=fixture.gate_sha,
            runtime=runtime,
        )

    assert fixture.registry_path.read_bytes() == registry_before
    assert fixture.tracker["lock_acquire"] == fixture.tracker["registry_write"] == 0


def test_resealed_attacked_independent_audit_cannot_authorize_append(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    path = fixture.root / fixture.independent_audit_path
    attacked = json.loads(path.read_text(encoding="utf-8"))
    attacked["reservation_authorization"][
        "additional_reservation_or_retry_allowed"
    ] = True
    unsigned = dict(attacked)
    unsigned.pop("audit_semantic_sha256")
    attacked["audit_semantic_sha256"] = fixture.module._semantic_sha256(unsigned)
    attacked_raw = _write_json(fixture.module, path, attacked)
    attacked_sha = fixture.module._sha256(attacked_raw)
    runtime = replace(
        fixture.runtime,
        independent_audit_raw_sha256=attacked_sha,
    )
    registry_before = fixture.registry_path.read_bytes()

    with pytest.raises(
        fixture.module.R3ReservationError,
        match="independent audit authorization differs",
    ):
        fixture.module.build_reservation_plan(
            project_root=fixture.root,
            run_id=fixture.run_id,
            seed_precommit=fixture.precommit_path,
            seed_precommit_raw_sha256=fixture.precommit_sha,
            independent_audit=fixture.independent_audit_path,
            independent_audit_raw_sha256=attacked_sha,
            rehearsal_gate=fixture.gate_path,
            rehearsal_gate_raw_sha256=fixture.gate_sha,
            runtime=runtime,
        )

    assert fixture.registry_path.read_bytes() == registry_before
    assert fixture.tracker["lock_acquire"] == fixture.tracker["registry_write"] == 0


def test_policy_or_precommit_drift_is_rejected_exactly(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    precommit = json.loads(
        (fixture.root / fixture.precommit_path).read_text(encoding="utf-8")
    )
    policy = json.loads(
        (fixture.root / precommit["value_free_policy_relative_path"]).read_text(
            encoding="utf-8"
        )
    )
    predecessor = policy["authority_inputs"]["spent_seed_registry_predecessor"]
    pinned_policy = fixture.module.PinnedJson(
        precommit["value_free_policy_relative_path"],
        precommit["value_free_policy_raw_sha256"],
        fixture.module._canonical_pretty_bytes(policy),
        policy,
    )
    pinned_precommit = fixture.module.PinnedJson(
        fixture.precommit_path.as_posix(),
        fixture.precommit_sha,
        fixture.module._canonical_pretty_bytes(precommit),
        precommit,
    )

    attacked = copy.deepcopy(precommit)
    attacked["overlap_audit"]["rehearsal_fixture_overlap_count"] = 1
    with pytest.raises(fixture.module.R3ReservationError, match="precommit differs"):
        fixture.module._validate_precommit(
            replace(pinned_precommit, value=attacked),
            policy=pinned_policy,
            run_id=fixture.run_id,
            predecessor=predecessor,
        )

    attacked = copy.deepcopy(policy)
    attacked["formal_execution_policy"]["reservation_retry_allowed"] = True
    with pytest.raises(fixture.module.R3ReservationError, match="policy differs"):
        fixture.module._validate_value_free_policy(
            replace(pinned_policy, value=attacked),
            run_id=fixture.run_id,
            rehearsal_gate=fixture.module._read_pinned_json(
                fixture.root,
                fixture.gate_path,
                fixture.gate_sha,
                label="synthetic gate",
            ),
            project_root=fixture.root,
        )


def test_apply_holds_cas_lock_appends_once_and_creates_one_legacy_wire_lock(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    plan = _plan(fixture)
    registry_before = json.loads(fixture.registry_path.read_text(encoding="utf-8"))

    report = fixture.module.apply_reservation_plan(plan)

    registry_after = json.loads(fixture.registry_path.read_text(encoding="utf-8"))
    assert len(registry_after["entries"]) == len(registry_before["entries"]) + 1
    assert registry_after["entries"][:-1] == registry_before["entries"]
    assert report["registry_append_count"] == 1
    assert fixture.tracker["lock_acquire"] == fixture.tracker["registry_write"] == 1
    assert {path.name for path in plan.output_root.iterdir()} == {
        "promotion_policy.lock.json"
    }
    lock = json.loads(plan.lock_path.read_text(encoding="utf-8"))
    assert lock["schema_version"] == "expected_pe.four_model.r3_protocol_lock.v1"
    assert lock["status"] == "FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH"
    assert "r2_protocol_binding" in lock
    assert lock["r2_protocol_binding"]["reservation_contract"][
        "policy_config_sha256"
    ] == plan.report["policy_config_sha256"]
    assert set(lock["r2_protocol_binding"]["overlap_audit"]) == {
        "prior_spent_overlap_count",
        "r1_heldout_overlap_count",
        "qualification_seed_overlap_count",
        "within_allocation_duplicate_count",
    }
    with pytest.raises(fixture.module.R3ReservationError):
        fixture.module.apply_reservation_plan(plan)
    assert len(json.loads(fixture.registry_path.read_text())["entries"]) == 2


def test_lock_held_predecessor_drift_rejects_without_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    plan = _plan(fixture)
    original_acquire = fixture.runtime.acquire_registry_lock
    drift = b'{"synthetic":"concurrent predecessor drift"}\n'

    def attacked_acquire(path: Path) -> tuple[int, Path]:
        result = original_acquire(path)
        path.write_bytes(drift)
        return result

    attacked_runtime = replace(fixture.runtime, acquire_registry_lock=attacked_acquire)
    attacked_plan = replace(plan, runtime=attacked_runtime)
    monkeypatch.setattr(
        fixture.module,
        "build_reservation_plan",
        lambda **_: replace(plan, runtime=attacked_runtime),
    )

    with pytest.raises(
        fixture.module.R3ReservationError, match="changed before locked append"
    ):
        fixture.module.apply_reservation_plan(attacked_plan)

    assert fixture.registry_path.read_bytes() == drift
    assert fixture.tracker["registry_write"] == 0


def test_cli_requires_exact_pins_and_defaults_to_read_only() -> None:
    module = _load()
    arguments = module.parser().parse_args(
        [
            "--run-id",
            "r3_synthetic",
            "--seed-precommit",
            "build/precommit.json",
            "--seed-precommit-raw-sha256",
            "a" * 64,
            "--independent-audit",
            "build/independent-audit.json",
            "--independent-audit-raw-sha256",
            "c" * 64,
            "--rehearsal-gate",
            "build/rehearsal.json",
            "--rehearsal-gate-raw-sha256",
            "b" * 64,
        ]
    )
    assert arguments.apply is False

    with pytest.raises(SystemExit):
        module.parser().parse_args(
            [
                "--run-id",
                "r3_synthetic",
                "--seed-precommit",
                "build/precommit.json",
                "--seed-precommit-raw-sha256",
                "a" * 64,
                "--rehearsal-gate",
                "build/rehearsal.json",
                "--rehearsal-gate-raw-sha256",
                "b" * 64,
            ]
        )
