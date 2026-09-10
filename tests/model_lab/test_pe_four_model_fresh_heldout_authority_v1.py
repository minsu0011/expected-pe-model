from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import authority
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import activation
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
    execution_authority as execution_authority_module,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
    r2_protocol_lock as r2_protocol_lock_module,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import prediction
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
    canonical_pretty_bytes,
    raw_sha256,
    semantic_sha256,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
    BCE_NUMERIC_ENVIRONMENT,
    BCE_TASK_SURFACE_COLUMNS,
    C1_ID,
    C2_ID,
    C3_ID,
    C4_ID,
    C4_NUMERIC_ENVIRONMENT,
    CHAMPION_ID,
    DGP_IDS,
    ESTIMATOR_RNG_SEEDS,
    FORMULA_LOCK,
    HELDOUT_SEEDS,
    HELDOUT_SEED_ALIASES,
    HOFS_TASK_SURFACE_COLUMNS,
    MODEL_IDS_IN_ORDER,
    PREDICTION_OUTPUT_FILE_UNIVERSE,
    PREDICTION_ROW_COUNT,
    QUALIFICATION_FREEZE_STATUS,
    QUALIFICATION_RESULT_RAW_SHA256,
    QUALIFICATION_RESULT_SCHEMA,
    QUALIFICATION_RESULT_STATUS,
    SOURCE_MODEL_VERSIONS,
    SURVIVOR_FREEZE_SCHEMA,
    SURVIVOR_FREEZE_STATUS,
    SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER,
    TASK_COUNT,
    IDENTITY_COUNT,
    RESEARCH_ONLY_IDS,
    R2_FINAL_NONRESERVED_PREFLIGHT_RAW_SHA256,
    R2_FINAL_NONRESERVED_PREFLIGHT_RELATIVE_PATH,
    R2_HELDOUT_SEED_COMMITMENT_SHA256,
    R2_PROTOCOL_LOCK_ROOT_PREFIX,
    R2_PROTOCOL_LOCK_SCHEMA,
    R2_PROTOCOL_LOCK_STATUS,
    R2_QUARANTINE_SEEDS,
    R2_R1_TERMINAL_FAILURE_RAW_SHA256,
    R2_R1_TERMINAL_FAILURE_RELATIVE_PATH,
    R2_REPLACEMENT_SEED_PRECOMMIT_RAW_SHA256,
    R2_REPLACEMENT_SEED_PRECOMMIT_RELATIVE_PATH,
    R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT,
    R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
    R2_SPENT_SEED_REGISTRY_PREVIOUS_ENTRY_SHA256,
    R2_SPENT_SEED_REGISTRY_RELATIVE_PATH,
    HeldoutAuthorityError,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation import (
    generation_plan,
    heldout_tasks,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation_execution import (
    child_environment,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
    build_execution_authority,
    validate_execution_authority,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.independent_audit import (
    _expected_task,
    _validate_live_runtime_binding,
    _validate_numeric_worker_runtime,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction import (
    build_task_prediction_rows,
    validate_synthetic_five_model_reference_equivalence,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.r2_protocol_lock import (
    build_r2_protocol_lock,
    validate_r2_protocol_lock,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.source_inventory import (
    source_record_groups,
)


def _identity() -> pd.DataFrame:
    positions = np.arange(504, 1800, dtype=np.int64)
    starts_tuple = tuple(range(504, 1800, 21))
    sizes = np.asarray([min(1800, start + 21) - start for start in starts_tuple])
    starts = np.repeat(starts_tuple, sizes).astype(np.int64)
    folds = np.repeat([f"fold_{12 + ordinal:03d}" for ordinal in range(len(starts_tuple))], sizes)
    return pd.DataFrame(
        {
            "seed_alias": HELDOUT_SEED_ALIASES[0],
            "dgp_id": DGP_IDS[0],
            "session_position": positions,
            "date": pd.date_range("2030-01-01", periods=len(positions), freq="D").strftime(
                "%Y-%m-%d"
            ),
            "symbol": "DGP_ISSUER",
            "fold_id": folds,
            "train_end_position": starts - 1,
            "test_start_position": starts,
        }
    )


def _surfaces() -> tuple[pd.DataFrame, pd.DataFrame]:
    identity = _identity()
    rows = len(identity)
    bce = identity.copy()
    bce["v04_expected_pe"] = np.linspace(18.0, 24.0, rows)
    bce["lgbm_full_state_expected_pe"] = bce["v04_expected_pe"] * 1.08
    bce["histgb_full_state_expected_pe"] = bce["v04_expected_pe"] * 1.04
    bce["ofs_v1_eps_confidence_01"] = 0.8
    bce["ofs_v1_eps_staleness_log1p"] = 0.2
    bce["ofs_v1_regime_entropy"] = 0.25
    bce["ofs_v1_regime_confidence"] = 0.75
    bce["ofs_v1_state_abs_innovation_lag1"] = 0.1
    bce = bce.loc[:, list(BCE_TASK_SURFACE_COLUMNS)]
    hofs = identity.copy()
    hofs["hofs_r2_expected_log_pe"] = np.log(bce["v04_expected_pe"] * 1.12)
    hofs["hofs_v7_tail_guard_weight"] = 0.7
    hofs["hofs_v7_log_scale"] = -1.0
    hofs = hofs.loc[:, list(HOFS_TASK_SURFACE_COLUMNS)]
    return bce, hofs


def _qualification_payload() -> dict[str, object]:
    roles = {
        C1_ID: "RESEARCH_ONLY",
        C2_ID: "CERTIFIED_SURVIVOR",
        C3_ID: "CERTIFIED_SURVIVOR",
        C4_ID: "CERTIFIED_SURVIVOR",
    }
    return {
        "schema_version": QUALIFICATION_RESULT_SCHEMA,
        "status": QUALIFICATION_RESULT_STATUS,
        "run_id": "20260824T000005",
        "heldout_authority": False,
        "heldout_open_count": 0,
        "post_result_candidate_tuning_allowed": False,
        "qualification_result_mutable": False,
        "retry_allowed": False,
        "score": {
            "champion": {
                "candidate_id": CHAMPION_ID,
                "version": SOURCE_MODEL_VERSIONS[CHAMPION_ID],
            },
            "scorecard": [
                {
                    "candidate_id": model_id,
                    "version": SOURCE_MODEL_VERSIONS.get(model_id, SOURCE_MODEL_VERSIONS[C2_ID]),
                }
                for model_id in (C1_ID, C2_ID, C3_ID, C4_ID)
            ],
            "decisions": [
                {"candidate_id": model_id, "classification": classification}
                for model_id, classification in roles.items()
            ],
            "survivor_role_ranking_freeze": {
                "candidate_definition_mutable": False,
                "candidate_roles": roles,
                "certified_survivor_ids_in_rank_order": list(
                    SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER
                ),
                "heldout_authority": False,
                "heldout_open_count": 0,
                "qualification_results_mutable": False,
                "role_assignment_mutable": False,
                "status": QUALIFICATION_FREEZE_STATUS,
            },
        },
    }


def _synthetic_survivor() -> dict[str, object]:
    core: dict[str, object] = {
        "schema_version": SURVIVOR_FREEZE_SCHEMA,
        "status": SURVIVOR_FREEZE_STATUS,
        "qualification_result_ref": {
            "relative_path": "outputs/synthetic/QUALIFICATION_RESULT.json",
            "raw_sha256": QUALIFICATION_RESULT_RAW_SHA256,
            "size_bytes": 1,
            "volume_serial_number": 1,
            "file_id_128": "1" * 32,
        },
        "qualification_result_raw_sha256": QUALIFICATION_RESULT_RAW_SHA256,
        "qualification_result_schema_version": QUALIFICATION_RESULT_SCHEMA,
        "qualification_result_status": QUALIFICATION_RESULT_STATUS,
        "qualification_run_id": "synthetic_qualification",
        "champion_id": CHAMPION_ID,
        "survivor_ids_in_qualification_rank_order": list(SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER),
        "model_ids_in_order": list(MODEL_IDS_IN_ORDER),
        "research_only_ids_excluded": list(RESEARCH_ONLY_IDS),
        "excluded_c1_prediction_row_count": 0,
        "source_model_versions": [
            {
                "model_id": model_id,
                "source_model_version": SOURCE_MODEL_VERSIONS[model_id],
            }
            for model_id in MODEL_IDS_IN_ORDER
        ],
        "formula_lock": FORMULA_LOCK,
        "heldout_seeds_in_order": list(HELDOUT_SEEDS),
        "estimator_rng_seeds_in_order": list(ESTIMATOR_RNG_SEEDS),
        "estimator_rng_is_bound_generation_seed": True,
        "estimator_rng_is_feature_router_weight_or_formula_parameter": False,
        "dgp_ids_in_order": list(DGP_IDS),
        "task_count": TASK_COUNT,
        "identity_count": IDENTITY_COUNT,
        "prediction_row_count": PREDICTION_ROW_COUNT,
        "candidate_tuning_allowed": False,
        "prediction_before_truth": True,
        "truth_open_count": 0,
        "heldout_content_open_count": 0,
        "score_open_count": 0,
    }
    return {**core, "survivor_freeze_semantic_sha256": semantic_sha256(core)}


def _synthetic_protocol(
    project: Path,
    *,
    run_id: str,
    source_config_sha256: str = "1" * 64,
    candidates_sha256: str = "2" * 64,
) -> tuple[dict[str, object], str, str]:
    relative = f"outputs/{R2_PROTOCOL_LOCK_ROOT_PREFIX}{run_id}/promotion_policy.lock.json"
    owner = str((project / relative).resolve(strict=False).parent)
    contract = {
        "format_version": 1,
        "registry_id": "v04-prospective-spent-seeds-v1",
        "owner_output_root": owner,
        "source_config_sha256": source_config_sha256,
        "candidates_sha256": candidates_sha256,
        "policy_config_sha256": semantic_sha256(
            r2_protocol_lock_module._expected_reservation_policy_config(run_id)
        ),
        "tuning_seeds": list(R2_QUARANTINE_SEEDS),
        "locked_seeds": list(HELDOUT_SEEDS),
        "reserved_seeds": sorted((*R2_QUARANTINE_SEEDS, *HELDOUT_SEEDS)),
    }
    binding = {
        "r1_terminal_failure": {
            "relative_path": R2_R1_TERMINAL_FAILURE_RELATIVE_PATH,
            "raw_sha256": R2_R1_TERMINAL_FAILURE_RAW_SHA256,
        },
        "replacement_seed_precommit": {
            "relative_path": R2_REPLACEMENT_SEED_PRECOMMIT_RELATIVE_PATH,
            "raw_sha256": R2_REPLACEMENT_SEED_PRECOMMIT_RAW_SHA256,
        },
        "final_nonreserved_preflight": {
            "relative_path": R2_FINAL_NONRESERVED_PREFLIGHT_RELATIVE_PATH,
            "raw_sha256": R2_FINAL_NONRESERVED_PREFLIGHT_RAW_SHA256,
            "status": "GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE",
            "reserved_generator_invocation_count": 0,
            "truth_leakage_count": 0,
            "heldout_access_count": 0,
            "score_open_count": 0,
            "registry_mutation_count": 0,
        },
        "quarantine_seeds_never_generate_or_score": list(R2_QUARANTINE_SEEDS),
        "heldout_seeds_in_order": list(HELDOUT_SEEDS),
        "heldout_seed_commitment_sha256": R2_HELDOUT_SEED_COMMITMENT_SHA256,
        "reservation_contract": contract,
        "spent_seed_reservation": {
            "format_version": 1,
            "registry_id": "v04-prospective-spent-seeds-v1",
            "registry_path": str(
                (project / "outputs/v04_spent_seed_registry.json").resolve(strict=False)
            ),
            "genesis_sha256": "5" * 64,
            "reservation_id": semantic_sha256(contract),
            "reservation_sequence": R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT + 1,
            "reservation_entry_sha256": "6" * 64,
        },
        "registry_transition": {
            "registry_relative_path": R2_SPENT_SEED_REGISTRY_RELATIVE_PATH,
            "registry_before_raw_sha256": R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
            "registry_after_raw_sha256": "7" * 64,
            "entry_count_before": R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT,
            "entry_count_after": R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT + 1,
            "append_count": 1,
            "previous_entry_sha256": R2_SPENT_SEED_REGISTRY_PREVIOUS_ENTRY_SHA256,
            "reservation_entry_sha256": "6" * 64,
            "reservation_created_at_utc": "2026-08-23T14:00:00Z",
        },
        "overlap_audit": {
            "prior_spent_overlap_count": 0,
            "r1_heldout_overlap_count": 0,
            "qualification_seed_overlap_count": 0,
            "within_allocation_duplicate_count": 0,
        },
        "candidate_performance_consulted": False,
        "heldout_truth_consulted": False,
        "retry_allowed": False,
        "additional_recovery_reservation_allowed": False,
        "candidate_tuning_allowed": False,
        "truth_open_count_at_lock": 0,
        "score_open_count_at_lock": 0,
        "heldout_content_open_count_at_lock": 0,
    }
    lock = build_r2_protocol_lock(run_id=run_id, r2_protocol_binding=binding)
    validate_r2_protocol_lock(
        lock,
        expected_run_id=run_id,
        project_root=project,
        expected_lock_relative_path=relative,
    )
    return lock, relative, raw_sha256(canonical_pretty_bytes(lock))


def test_fixed_authority_and_generation_seed_contract() -> None:
    assert QUALIFICATION_RESULT_RAW_SHA256 == (
        "4fbf83c18bbd6f339d4cc3f9ce94b4140349c601d01a9790581adae2d4a8f3a1"
    )
    assert MODEL_IDS_IN_ORDER == (CHAMPION_ID, C4_ID, C2_ID, C3_ID)
    assert R2_PROTOCOL_LOCK_SCHEMA == "expected_pe.four_model.r3_protocol_lock.v1"
    assert R2_PROTOCOL_LOCK_STATUS == "FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH"
    assert R2_PROTOCOL_LOCK_ROOT_PREFIX == ("model_zoo_pe_four_model_heldout_r3_reservation_")
    assert R2_QUARANTINE_SEEDS == (7727, 7741, 7753, 7757, 7759)
    assert HELDOUT_SEEDS == (7789, 7793, 7817, 7823, 7829)
    assert R2_HELDOUT_SEED_COMMITMENT_SHA256 == (
        "517acd3b8e033dc10087a1ae8ff8ef237a00b8c193ab758796860ff2dc575ede"
    )
    assert ESTIMATOR_RNG_SEEDS == HELDOUT_SEEDS
    tasks = heldout_tasks()
    assert len(tasks) == 50
    assert all(task.estimator_rng_seed == task.data_seed for task in tasks)
    assert [task.dgp_id for task in tasks[:10]] == list(DGP_IDS)
    plan = generation_plan()
    assert plan["estimator_rng_is_mechanical_heldout_data_seed"] is True
    assert plan["estimator_rng_is_feature_router_weight_or_formula_parameter"] is False
    assert plan["truth_open_count"] == 0
    assert plan["heldout_content_open_count_at_authority"] == 0


def test_r2_protocol_lock_binds_one_reservation_and_rejects_policy_drift() -> None:
    project = Path(__file__).resolve().parents[2]
    lock, relative, _ = _synthetic_protocol(project, run_id="synthetic_protocol")
    assert lock["r2_protocol_binding"]["registry_transition"]["append_count"] == 1
    assert (
        lock["r2_protocol_binding"]["spent_seed_reservation"]["reservation_sequence"]
        == R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT + 1
    )
    tampered_binding = copy.deepcopy(lock["r2_protocol_binding"])
    tampered_binding["additional_recovery_reservation_allowed"] = True
    with pytest.raises(HeldoutAuthorityError, match="seed/access policy"):
        build_r2_protocol_lock(
            run_id="synthetic_protocol",
            r2_protocol_binding=tampered_binding,
        )
    tampered_policy = copy.deepcopy(lock["r2_protocol_binding"])
    tampered_policy["reservation_contract"]["policy_config_sha256"] = "f" * 64
    with pytest.raises(HeldoutAuthorityError, match="reservation contract"):
        build_r2_protocol_lock(
            run_id="synthetic_protocol",
            r2_protocol_binding=tampered_policy,
        )
    assert (
        validate_r2_protocol_lock(
            lock,
            expected_run_id="synthetic_protocol",
            project_root=project,
            expected_lock_relative_path=relative,
        )
        == lock
    )


def test_r2_live_evidence_accepts_raw_bound_noncanonical_precommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = "synthetic_noncanonical_precommit"
    lock, _, _ = _synthetic_protocol(tmp_path, run_id=run_id)
    binding = copy.deepcopy(lock["r2_protocol_binding"])
    receipt = binding["spent_seed_reservation"]
    transition = binding["registry_transition"]
    contract = binding["reservation_contract"]
    unsigned_entry = {
        "sequence": receipt["reservation_sequence"],
        "previous_entry_sha256": transition["previous_entry_sha256"],
        "reservation_id": receipt["reservation_id"],
        "created_at_utc": transition["reservation_created_at_utc"],
        **contract,
    }
    entry_sha256 = semantic_sha256(unsigned_entry)
    entry = {**unsigned_entry, "entry_sha256": entry_sha256}
    receipt["reservation_entry_sha256"] = entry_sha256
    transition["reservation_entry_sha256"] = entry_sha256
    lock = build_r2_protocol_lock(
        run_id=run_id,
        r2_protocol_binding=binding,
    )

    precommit = {
        "schema_version": "expected_pe.four_model.r3_seed_precommit.v1",
        "status": "FROZEN_PRE_RESERVATION_PERFORMANCE_INDEPENDENT_R3_ALLOCATION",
        "quarantine_seeds_never_generate_or_score": list(R2_QUARANTINE_SEEDS),
        "heldout_seeds_in_order": list(HELDOUT_SEEDS),
        "heldout_seed_commitment_sha256": R2_HELDOUT_SEED_COMMITMENT_SHA256,
        "heldout_seed_commitment_payload": {"locked_seeds": list(HELDOUT_SEEDS)},
        "formal_execution_policy": {
            "additional_recovery_reservation_allowed": False,
            "exact_heldout_seed_count": 5,
            "quarantine_generator_invocation_allowed": False,
        },
        "overlap_audit": {
            "prior_spent_overlap_count": 0,
            "r2_formal_seed_overlap_count": 0,
            "qualification_seed_overlap_count": 0,
            "within_allocation_duplicate_count": 0,
            "rehearsal_fixture_overlap_count": 0,
        },
        "registry_before": {
            "relative_path": R2_SPENT_SEED_REGISTRY_RELATIVE_PATH,
            "raw_sha256": R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
            "entry_count": R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT,
            "last_entry_sha256": R2_SPENT_SEED_REGISTRY_PREVIOUS_ENTRY_SHA256,
        },
    }
    precommit_raw = json.dumps(precommit, separators=(",", ":")).encode("utf-8")
    assert precommit_raw != canonical_pretty_bytes(precommit)
    preflight_core = {
        "schema_version": ("expected_pe.four_model.r3_full_nonreserved_rehearsal.result.v1"),
        "status": "GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE",
        "formal_seed_reservation_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
        "registry_before_raw_sha256": R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
        "registry_after_raw_sha256": R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
        "registry_entry_count": R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT,
        "registry_bytes_unchanged": True,
        "spent_seed_overlap_count": 0,
        "candidate_tuning_allowed": False,
        "no_r2_path_or_artifact_reuse": True,
    }
    preflight = {
        **preflight_core,
        "result_semantic_sha256": semantic_sha256(preflight_core),
    }
    terminal_core = {
        "schema_version": ("expected_pe.four_model.r2_prediction_publication_terminal.v1"),
        "status": "TERMINAL_UNSEALED_PREDICTION_PREFIX_NO_ACTIVATION_OR_SCORING",
        "terminal": True,
        "retry_allowed": False,
        "recovery_allowed": False,
        "certification_authority": False,
        "access": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_content_open_count": 0,
        },
        "prohibitions": {
            "candidate_tuning_allowed": False,
            "prediction_retry_allowed": False,
        },
    }
    terminal = {
        **terminal_core,
        "terminal_semantic_sha256": semantic_sha256(terminal_core),
    }
    unsigned_registry = {
        "entries": [{} for _ in range(R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT)] + [entry]
    }
    registry = {
        **unsigned_registry,
        "registry_sha256": semantic_sha256(unsigned_registry),
    }
    raw_by_label = {
        "terminal R2 no-retry evidence": canonical_pretty_bytes(terminal),
        "R3 seed precommit": precommit_raw,
        "full nonreserved R3 rehearsal": canonical_pretty_bytes(preflight),
        "spent-seed registry after reservation": canonical_pretty_bytes(registry),
    }

    def _synthetic_stable_read(
        project: Path,
        relative_path: str,
        expected_raw_sha256: str,
        *,
        label: str,
    ) -> bytes:
        del project, relative_path, expected_raw_sha256
        return raw_by_label[label]

    monkeypatch.setattr(
        r2_protocol_lock_module,
        "_stable_project_read",
        _synthetic_stable_read,
    )
    monkeypatch.setattr(
        r2_protocol_lock_module,
        "_verify_independent_audit_live",
        lambda *args, **kwargs: None,
    )
    r2_protocol_lock_module._verify_live_evidence(tmp_path, lock)


def test_r3_independent_audit_live_authorizes_once_and_rejects_resealed_attack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Path(__file__).resolve().parents[2]

    def value(relative: str) -> dict[str, object]:
        return json.loads((project / relative).read_text(encoding="utf-8"))

    precommit = value(R2_REPLACEMENT_SEED_PRECOMMIT_RELATIVE_PATH)
    terminal = value(R2_R1_TERMINAL_FAILURE_RELATIVE_PATH)
    preflight = value(R2_FINAL_NONRESERVED_PREFLIGHT_RELATIVE_PATH)
    lock = {"run_id": "r3_20260824T134417"}
    r2_protocol_lock_module._verify_independent_audit_live(
        project,
        lock=lock,
        precommit=precommit,
        terminal=terminal,
        preflight=preflight,
    )

    original_stable_read = r2_protocol_lock_module._stable_project_read
    audit_raw = original_stable_read(
        project,
        r2_protocol_lock_module.R3_INDEPENDENT_AUDIT_RELATIVE_PATH,
        r2_protocol_lock_module.R3_INDEPENDENT_AUDIT_RAW_SHA256,
        label="R3 independent reservation audit",
    )
    attacked = json.loads(audit_raw.decode("utf-8"))
    attacked["reservation_authorization"]["additional_reservation_or_retry_allowed"] = True
    unsigned = dict(attacked)
    unsigned.pop("audit_semantic_sha256")
    attacked["audit_semantic_sha256"] = semantic_sha256(unsigned)
    attacked_raw = canonical_pretty_bytes(attacked)

    def attacked_stable_read(
        project_root: Path,
        relative_path: str,
        expected_raw_sha256: str,
        *,
        label: str,
    ) -> bytes:
        if label == "R3 independent reservation audit":
            return attacked_raw
        return original_stable_read(
            project_root,
            relative_path,
            expected_raw_sha256,
            label=label,
        )

    monkeypatch.setattr(
        r2_protocol_lock_module,
        "_stable_project_read",
        attacked_stable_read,
    )
    with pytest.raises(HeldoutAuthorityError, match="independent reservation audit"):
        r2_protocol_lock_module._verify_independent_audit_live(
            project,
            lock=lock,
            precommit=precommit,
            terminal=terminal,
            preflight=preflight,
        )


def test_survivor_freeze_is_result_bound_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = json.dumps(_qualification_payload(), sort_keys=True).encode("utf-8")
    digest = raw_sha256(raw)
    monkeypatch.setattr(authority, "QUALIFICATION_RESULT_RAW_SHA256", digest)
    ref = {
        "relative_path": "outputs/public-result/QUALIFICATION_RESULT.json",
        "raw_sha256": digest,
        "size_bytes": len(raw),
        "volume_serial_number": 1,
        "file_id_128": "1" * 32,
    }
    freeze = authority.qualification_survivor_freeze(raw, qualification_result_ref=ref)
    assert freeze["model_ids_in_order"] == list(MODEL_IDS_IN_ORDER)
    assert freeze["excluded_c1_prediction_row_count"] == 0
    assert freeze["candidate_tuning_allowed"] is False
    tampered = bytearray(raw)
    tampered[-1] = ord(" ")
    with pytest.raises(HeldoutAuthorityError, match="raw SHA-256"):
        authority.qualification_survivor_freeze(bytes(tampered), qualification_result_ref=ref)


def test_four_model_formula_matches_five_model_reference_without_c1_output() -> None:
    bce, hofs = _surfaces()
    validate_synthetic_five_model_reference_equivalence(bce, hofs)
    rows = build_task_prediction_rows(
        bce,
        hofs,
        source_versions=SOURCE_MODEL_VERSIONS,
    )
    assert len(rows) == 1_296 * 4
    assert tuple(rows["pe_model_id"].iloc[:4]) == MODEL_IDS_IN_ORDER
    assert not rows["pe_model_id"].eq(C1_ID).any()
    assert tuple(sorted(rows["model_ordinal"].unique())) == (0, 1, 2, 3)
    champion = rows.loc[rows["pe_model_id"].eq(CHAMPION_ID), "expected_pe"].to_numpy()
    c4 = rows.loc[rows["pe_model_id"].eq(C4_ID), "expected_pe"].to_numpy()
    expected_c4 = np.exp(
        np.log(champion) + 0.5 * (hofs["hofs_r2_expected_log_pe"].to_numpy() - np.log(champion))
    )
    np.testing.assert_array_equal(c4, expected_c4)


def test_production_four_model_path_never_invokes_five_model_or_c1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bce, hofs = _surfaces()
    calls = 0

    def forbidden(*args: object, **kwargs: object) -> pd.DataFrame:
        nonlocal calls
        calls += 1
        raise AssertionError("five-model/C1 seam reached production path")

    monkeypatch.setattr(prediction, "_five_model_reference_projection", forbidden)
    rows = prediction.build_task_prediction_rows(
        bce,
        hofs,
        source_versions=SOURCE_MODEL_VERSIONS,
    )
    assert calls == 0
    assert not rows["pe_model_id"].eq(C1_ID).any()


def test_prediction_tamper_and_source_version_drift_fail_closed() -> None:
    bce, hofs = _surfaces()
    bad = bce.copy()
    bad.loc[0, "seed_alias"] = "qualification_seed_01"
    with pytest.raises(HeldoutAuthorityError, match="heldout universe"):
        build_task_prediction_rows(bad, hofs, source_versions=SOURCE_MODEL_VERSIONS)
    versions = dict(SOURCE_MODEL_VERSIONS)
    versions[C4_ID] = "sha256:" + "0" * 64
    with pytest.raises(HeldoutAuthorityError, match="binding differs"):
        build_task_prediction_rows(bce, hofs, source_versions=versions)


def test_public_leaf_universe_and_isolated_cli_help() -> None:
    assert PREDICTION_OUTPUT_FILE_UNIVERSE == tuple(sorted(PREDICTION_OUTPUT_FILE_UNIVERSE))
    assert PREDICTION_OUTPUT_FILE_UNIVERSE == (
        "AUDIT_SEAL.json",
        "CHECKSUMS.sha256",
        "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
        "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
        "PREDICTIONS.csv",
        "PREDICTION_MANIFEST.json",
        "SOURCE_MANIFEST.json",
    )
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1/"
        "freeze_survivor_authority.py"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--qualification-result" in completed.stdout


def test_execution_authority_freezes_disjoint_live_sources_before_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Path(__file__).resolve().parents[2]
    live_source = execution_authority_module.build_source_manifest(
        **execution_authority_module.source_manifest_inputs(project)
    )
    candidate_config_sha256 = semantic_sha256(
        execution_authority_module._reservation_candidate_config(generation_plan())
    )
    protocol, protocol_relative, protocol_raw_sha = _synthetic_protocol(
        project,
        run_id="synthetic_source_only",
        source_config_sha256=str(live_source["source_manifest_semantic_sha256"]),
        candidates_sha256=candidate_config_sha256,
    )
    monkeypatch.setattr(
        execution_authority_module,
        "read_r2_protocol_lock",
        lambda *args, **kwargs: protocol,
    )
    groups = source_record_groups(project)
    paths = [str(row["relative_path"]) for group in groups for row in group]
    assert len(groups) == 4
    assert all(groups)
    assert len(paths) == len(set(paths))
    assert all(path.startswith(("research/", "scripts/")) for path in paths)
    assert not any(path.startswith(("tests/", "outputs/")) for path in paths)
    frozen = build_execution_authority(
        project_root=project,
        run_id="synthetic_source_only",
        survivor_freeze=_synthetic_survivor(),
        r2_protocol_lock=protocol,
        r2_protocol_lock_relative_path=protocol_relative,
        r2_protocol_lock_raw_sha256=protocol_raw_sha,
    )
    assert frozen["source_frozen_before_generation"] is True
    assert frozen["truth_open_count"] == 0
    assert (
        validate_execution_authority(
            frozen,
            project_root=project,
            expected_run_id="synthetic_source_only",
        )
        == frozen
    )

    drift_protocol, drift_relative, drift_raw_sha = _synthetic_protocol(
        project,
        run_id="synthetic_source_drift",
        source_config_sha256="f" * 64,
        candidates_sha256=candidate_config_sha256,
    )
    with pytest.raises(HeldoutAuthorityError, match="reservation-time source"):
        build_execution_authority(
            project_root=project,
            run_id="synthetic_source_drift",
            survivor_freeze=_synthetic_survivor(),
            r2_protocol_lock=drift_protocol,
            r2_protocol_lock_relative_path=drift_relative,
            r2_protocol_lock_raw_sha256=drift_raw_sha,
        )

    candidate_drift_protocol, candidate_drift_relative, candidate_drift_raw = _synthetic_protocol(
        project,
        run_id="synthetic_candidate_drift",
        source_config_sha256=str(live_source["source_manifest_semantic_sha256"]),
        candidates_sha256="f" * 64,
    )
    with pytest.raises(HeldoutAuthorityError, match="reservation-time candidate"):
        build_execution_authority(
            project_root=project,
            run_id="synthetic_candidate_drift",
            survivor_freeze=_synthetic_survivor(),
            r2_protocol_lock=candidate_drift_protocol,
            r2_protocol_lock_relative_path=candidate_drift_relative,
            r2_protocol_lock_raw_sha256=candidate_drift_raw,
        )
    tampered = copy.deepcopy(frozen)
    tampered["source_manifest"]["adapter_source_records"][0]["raw_sha256"] = "0" * 64
    unsigned = dict(tampered)
    unsigned.pop("execution_authority_semantic_sha256")
    tampered["execution_authority_semantic_sha256"] = semantic_sha256(unsigned)
    with pytest.raises(HeldoutAuthorityError, match="live source/plan drifted"):
        validate_execution_authority(
            tampered,
            project_root=project,
            expected_run_id="synthetic_source_only",
        )

    refrozen_protocol, refrozen_relative, refrozen_raw = _synthetic_protocol(
        project,
        run_id="synthetic_source_only",
        source_config_sha256=str(live_source["source_manifest_semantic_sha256"]),
        candidates_sha256="f" * 64,
    )
    refrozen_candidate = copy.deepcopy(frozen)
    refrozen_candidate["r2_protocol_lock"] = refrozen_protocol
    refrozen_candidate["r2_protocol_lock_relative_path"] = refrozen_relative
    refrozen_candidate["r2_protocol_lock_raw_sha256"] = refrozen_raw
    refrozen_candidate["r2_protocol_binding_semantic_sha256"] = refrozen_protocol[
        "r2_protocol_binding_semantic_sha256"
    ]
    refrozen_candidate_unsigned = dict(refrozen_candidate)
    refrozen_candidate_unsigned.pop("execution_authority_semantic_sha256")
    refrozen_candidate["execution_authority_semantic_sha256"] = semantic_sha256(
        refrozen_candidate_unsigned
    )
    monkeypatch.setattr(
        execution_authority_module,
        "read_r2_protocol_lock",
        lambda *args, **kwargs: refrozen_protocol,
    )
    with pytest.raises(HeldoutAuthorityError, match="reservation-time candidate"):
        validate_execution_authority(
            refrozen_candidate,
            project_root=project,
            expected_run_id="synthetic_source_only",
        )
    monkeypatch.setattr(
        execution_authority_module,
        "read_r2_protocol_lock",
        lambda *args, **kwargs: protocol,
    )

    stale = _synthetic_survivor()
    stale["heldout_seeds_in_order"] = [7603, 7607, 7621, 7639, 7643]
    stale_unsigned = dict(stale)
    stale_unsigned.pop("survivor_freeze_semantic_sha256")
    stale["survivor_freeze_semantic_sha256"] = semantic_sha256(stale_unsigned)
    with pytest.raises(HeldoutAuthorityError, match="survivor authority differs"):
        build_execution_authority(
            project_root=project,
            run_id="synthetic_source_only",
            survivor_freeze=stale,
            r2_protocol_lock=protocol,
            r2_protocol_lock_relative_path=protocol_relative,
            r2_protocol_lock_raw_sha256=protocol_raw_sha,
        )

    refrozen_source = copy.deepcopy(frozen["source_manifest"])
    refrozen_source["source_manifest_semantic_sha256"] = "f" * 64
    refrozen = copy.deepcopy(frozen)
    refrozen["source_manifest"] = refrozen_source
    refrozen["source_manifest_semantic_sha256"] = "f" * 64
    refrozen_unsigned = dict(refrozen)
    refrozen_unsigned.pop("execution_authority_semantic_sha256")
    refrozen["execution_authority_semantic_sha256"] = semantic_sha256(refrozen_unsigned)
    monkeypatch.setattr(
        execution_authority_module,
        "build_source_manifest",
        lambda **_: refrozen_source,
    )
    with pytest.raises(HeldoutAuthorityError, match="reservation-time source"):
        validate_execution_authority(
            refrozen,
            project_root=project,
            expected_run_id="synthetic_source_only",
        )


def test_independent_geometry_rejects_fold_and_symbol_mutation() -> None:
    bce, hofs = _surfaces()
    task = heldout_tasks()[0]
    rows = _expected_task(bce, hofs, task=task)
    assert len(rows) == 1_296 * 4
    bad_fold = bce.copy()
    bad_fold.loc[0, "fold_id"] = "fold_999"
    with pytest.raises(HeldoutAuthorityError, match="identity/fold geometry"):
        _expected_task(bad_fold, hofs, task=task)
    bad_symbol = hofs.copy()
    bad_symbol.loc[0, "symbol"] = "SYNTH"
    with pytest.raises(HeldoutAuthorityError, match="identity/fold geometry"):
        _expected_task(bce, bad_symbol, task=task)


def _numeric_runtime(lane: str, worker_slot: int) -> dict[str, object]:
    if lane == "bce":
        cpu_ids = [2 * worker_slot, 2 * worker_slot + 1]
        environment = dict(BCE_NUMERIC_ENVIRONMENT)
    else:
        cpu_ids = list(range(32))
        environment = dict(C4_NUMERIC_ENVIRONMENT)
    return {
        "worker_slot": worker_slot,
        "cpu_ids": cpu_ids,
        "affinity_mask": sum(1 << cpu_id for cpu_id in cpu_ids),
        "environment": environment,
        "inner_threads": 1,
    }


def test_independent_numeric_runtime_accepts_adapter_specific_contracts() -> None:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
        EXACT_ENVIRONMENT,
    )
    from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.contracts import (
        RESOURCE_POLICY,
    )

    assert C4_NUMERIC_ENVIRONMENT == dict(EXACT_ENVIRONMENT)
    assert BCE_NUMERIC_ENVIRONMENT == dict(RESOURCE_POLICY.environment)
    assert len(C4_NUMERIC_ENVIRONMENT) == 7
    assert len(BCE_NUMERIC_ENVIRONMENT) == 9
    _validate_numeric_worker_runtime(_numeric_runtime("bce", 5), lane="bce", worker_slot=5)
    _validate_numeric_worker_runtime(_numeric_runtime("c4", 5), lane="c4", worker_slot=5)


@pytest.mark.parametrize(
    ("lane", "wrong_environment"),
    (
        ("bce", C4_NUMERIC_ENVIRONMENT),
        ("c4", BCE_NUMERIC_ENVIRONMENT),
    ),
)
def test_independent_numeric_runtime_rejects_cross_adapter_environment(
    lane: str,
    wrong_environment: dict[str, str],
) -> None:
    runtime = _numeric_runtime(lane, 3)
    runtime["environment"] = dict(wrong_environment)
    with pytest.raises(HeldoutAuthorityError, match=f"{lane.upper()} numeric runtime"):
        _validate_numeric_worker_runtime(runtime, lane=lane, worker_slot=3)


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    (
        (lambda runtime: runtime["environment"].update({"PYTHONPATH": "x"}), "BCE"),
        (
            lambda runtime: runtime["environment"].update({"CUDA_VISIBLE_DEVICES": "0"}),
            "BCE",
        ),
        (lambda runtime: runtime.update({"inner_threads": 2}), "BCE"),
        (
            lambda runtime: runtime["environment"].update({"OMP_NUM_THREADS": "2"}),
            "BCE",
        ),
    ),
)
def test_independent_numeric_runtime_rejects_forbidden_python_gpu_and_thread_drift(
    mutation: object,
    expected_message: str,
) -> None:
    runtime = _numeric_runtime("bce", 1)
    mutation(runtime)
    with pytest.raises(HeldoutAuthorityError, match=expected_message):
        _validate_numeric_worker_runtime(runtime, lane="bce", worker_slot=1)


def test_independent_python_and_package_runtime_hash_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
        independent_audit as audit_module,
    )

    runtime = {
        "python_implementation": "CPython",
        "python_version": "3.10.0",
        "numpy": "1.0",
    }
    monkeypatch.setattr(audit_module, "runtime_versions", lambda: dict(runtime))
    source = {
        "runtime_versions": dict(runtime),
        "runtime_semantic_sha256": semantic_sha256(runtime),
    }
    assert _validate_live_runtime_binding(source) == runtime
    source["runtime_semantic_sha256"] = "0" * 64
    with pytest.raises(HeldoutAuthorityError, match="live runtime binding"):
        _validate_live_runtime_binding(source)


def test_activation_payload_is_exactly_scorer_canonical_32_field_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1 import (
        contracts as evaluator_contracts,
    )
    from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.contracts import (
        ACTIVATION_FIELDS,
        Activation,
    )

    run_id = "synthetic_activation"
    survivor_hash = "a" * 64
    authority_payload: dict[str, object] = {
        "run_id": run_id,
        "survivor_freeze": {},
        "qualification_survivor_freeze_semantic_sha256": survivor_hash,
        "generation_plan_semantic_sha256": (evaluator_contracts.GENERATION_PLAN_SEMANTIC_SHA256),
        "formula_lock_semantic_sha256": (
            "0f0a0fca901252d2e128a3ee4ab63bc9f20a7f76ead170171f4ec6af0472ce30"
        ),
        "r2_protocol_lock_raw_sha256": "d" * 64,
        "r2_protocol_binding_semantic_sha256": "e" * 64,
    }

    def ref(path: str, ordinal: int, *, digest: str | None = None) -> dict[str, object]:
        return {
            "relative_path": path,
            "raw_sha256": digest or f"{ordinal:064x}",
            "size_bytes": 100 + ordinal,
            "volume_serial_number": 1,
            "file_id_128": f"{ordinal:032x}",
        }

    qualification_ref = ref(
        "outputs/model_zoo_pe_five_candidate_fresh_qualification_result_"
        "r4_r8_r14_20260824T000005/QUALIFICATION_RESULT.json",
        1,
        digest=QUALIFICATION_RESULT_RAW_SHA256,
    )
    prediction_root = "outputs/model_zoo_pe_four_model_heldout_predictions_synthetic_activation"
    prediction_bundle: dict[str, object] = {
        "prediction_ref": ref(f"{prediction_root}/PREDICTIONS.csv", 2),
        "prediction_freeze_receipt_ref": ref(
            f"{prediction_root}/HELDOUT_PREDICTION_FREEZE_RECEIPT.json", 3
        ),
        "prediction_audit_ref": ref(f"{prediction_root}/HELDOUT_PREDICTION_FREEZE_AUDIT.json", 4),
        "prediction_audit_seal_ref": ref(f"{prediction_root}/AUDIT_SEAL.json", 5),
        "prediction_checksums_ref": ref(f"{prediction_root}/CHECKSUMS.sha256", 6),
        "prediction_semantic_sha256": f"{2:064x}",
        "common_identity_semantic_sha256": "b" * 64,
    }
    vault_root = "outputs/.model_zoo_pe_four_model_heldout_vault_synthetic_activation"
    vault_ref = ref(f"{vault_root}/VAULT_MANIFEST.json", 7)
    truth_refs = [
        ref(
            f"{vault_root}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv",
            8 + ordinal,
        )
        for ordinal, (seed, dgp) in enumerate(
            (seed, dgp) for seed in HELDOUT_SEEDS for dgp in DGP_IDS
        )
    ]
    monkeypatch.setattr(
        activation,
        "validate_execution_authority",
        lambda *args, **kwargs: authority_payload,
    )
    monkeypatch.setattr(activation, "_qualification_ref", lambda *args, **kwargs: qualification_ref)
    monkeypatch.setattr(activation, "_prediction_bundle", lambda *args, **kwargs: prediction_bundle)
    monkeypatch.setattr(
        activation,
        "_vault_bundle",
        lambda *args, **kwargs: (vault_ref, "c" * 64, truth_refs),
    )
    payload = activation.build_activation_payload(
        project_root=Path(__file__).resolve().parents[2],
        run_id=run_id,
        execution_authority=authority_payload,
        vault_manifest_path=Path("unused"),
        prediction_root=Path("unused"),
    )
    assert tuple(payload) == ACTIVATION_FIELDS
    raw = canonical_pretty_bytes(payload)
    monkeypatch.setattr(evaluator_contracts, "R2_PROTOCOL_LOCK_RAW_SHA256", "d" * 64)
    monkeypatch.setattr(
        evaluator_contracts,
        "R2_PROTOCOL_BINDING_SEMANTIC_SHA256",
        "e" * 64,
    )
    parsed = Activation.from_json_bytes(
        raw,
        expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert parsed.run_id == run_id
    assert len(parsed.truth_refs) == 50


def test_all_stage_clis_have_isolated_help(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[2]
    python = (project.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)
    script_root = project / "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1"
    for leaf in (
        "freeze_execution_authority.py",
        "run_heldout_generation.py",
        "publish_heldout_predictions.py",
        "mint_heldout_activation.py",
        "heldout_prediction_auditor.py",
        "heldout_role_worker.py",
    ):
        prefix = tmp_path / leaf.replace(".py", "")
        prefix.mkdir()
        completed = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-X",
                f"pycache_prefix={prefix}",
                str(script_root / leaf),
                "--help",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=child_environment(),
        )
        assert completed.returncode == 0, f"{leaf}: {completed.stderr}"
        assert not any(prefix.iterdir())
