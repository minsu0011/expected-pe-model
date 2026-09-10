"""Reserve the precommitted R2 seeds once and publish their protocol lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
REGISTRY_RELATIVE = "outputs/v04_spent_seed_registry.json"
PRECOMMIT_RELATIVE = (
    "build/pe_four_model_heldout_seed_precommit_r2_20260824T000005.json"
)
PRECOMMIT_RAW_SHA256 = (
    "ae854e30a24bf39c95ecfb9130140ea3cfc4b928435b5a7c39c5d171a022eacf"
)
R1_TERMINAL_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_generation_terminal_failure_"
    "20260824T000005/TERMINAL_FAILURE.json"
)
R1_TERMINAL_RAW_SHA256 = (
    "a9bc90afae1dc022c3adc54ae3adb50ed07b9bda947681645761b5461c1de295"
)
EXPECTED_REGISTRY_BEFORE_RAW_SHA256 = (
    "36ec508fff6affeb67b343dec522610e3bec914eae3ca2542495fdce8afbb941"
)
QUARANTINE_SEEDS = (7649, 7669, 7673, 7681, 7687)
LOCKED_SEEDS = (7691, 7699, 7703, 7717, 7723)
LOCKED_SEED_COMMITMENT_SHA256 = (
    "1fbaea190b11ca6d3b2a2664c793aab459f9f62cc5eced3dea32cb3bb4336c13"
)


class R2ReservationError(RuntimeError):
    """Fail-closed replacement-seed reservation error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R2ReservationError("R2 reservation requires -I -B")
    if sys.pycache_prefix is None:
        raise R2ReservationError("R2 reservation pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise R2ReservationError("R2 reservation pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_exact_json(relative: str, expected_raw_sha256: str) -> tuple[bytes, dict[str, Any]]:
    path = (PROJECT_ROOT / relative).resolve(strict=True)
    if PROJECT_ROOT not in path.parents or path.is_symlink() or not path.is_file():
        raise R2ReservationError(f"evidence path escaped or differs: {relative}")
    raw = path.read_bytes()
    if _raw_sha256(raw) != expected_raw_sha256:
        raise R2ReservationError(f"evidence raw SHA-256 differs: {relative}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R2ReservationError(f"evidence JSON differs: {relative}") from exc
    if type(value) is not dict:
        raise R2ReservationError(f"evidence is not an object: {relative}")
    return raw, value


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    result.add_argument("--final-preflight", required=True)
    result.add_argument("--final-preflight-raw-sha256", required=True)
    result.add_argument("--dry-run", action="store_true")
    return result


def _require_precommit(value: Mapping[str, Any], *, run_id: str) -> None:
    expected_overlap = {
        "prior_spent_overlap_count": 0,
        "r1_heldout_overlap_count": 0,
        "qualification_seed_overlap_count": 0,
        "within_allocation_duplicate_count": 0,
    }
    selection = value.get("selection_rule")
    policy = value.get("formal_execution_policy")
    if (
        value.get("schema_version")
        != "expected_pe.four_model.r2_replacement_seed_precommit.v1"
        or value.get("status")
        != "FROZEN_PRE_RESERVATION_PERFORMANCE_INDEPENDENT_REPLACEMENT_ALLOCATION"
        or value.get("run_id") != run_id
        or value.get("quarantine_seeds_never_generate_or_score")
        != list(QUARANTINE_SEEDS)
        or value.get("heldout_seeds_in_order") != list(LOCKED_SEEDS)
        or value.get("deterministic_next_ten_primes")
        != list((*QUARANTINE_SEEDS, *LOCKED_SEEDS))
        or value.get("heldout_seed_commitment_sha256")
        != LOCKED_SEED_COMMITMENT_SHA256
        or value.get("overlap_audit") != expected_overlap
        or type(selection) is not dict
        or selection.get("candidate_performance_consulted") is not False
        or selection.get("qualification_error_surface_consulted") is not False
        or selection.get("dgp_outcome_consulted") is not False
        or selection.get("heldout_truth_consulted") is not False
        or selection.get("selection_retry_allowed") is not False
        or type(policy) is not dict
        or policy.get("exact_heldout_seed_count") != 5
        or policy.get("quarantine_generator_invocation_allowed") is not False
        or policy.get("additional_recovery_reservation_allowed") is not False
        or policy.get("r1_seed_reuse_allowed") is not False
        or policy.get("seed_cherry_picking_allowed") is not False
        or policy.get("post_result_seed_change_allowed") is not False
    ):
        raise R2ReservationError("R2 replacement-seed precommit differs")


def _require_r1_terminal(value: Mapping[str, Any]) -> None:
    counts = value.get("access_and_downstream_counts")
    measured = value.get("measured_task_counts")
    if (
        value.get("schema_version")
        != "expected_pe.four_model.heldout_generation_terminal_failure.v1"
        or value.get("status")
        != "TERMINAL_NO_RETRY_GENERATION_PROCESS_FAILURE_PRE_PUBLICATION"
        or value.get("run_id") != "20260824T000005"
        or value.get("terminal") is not True
        or value.get("retry_allowed") is not False
        or value.get("authorizing") is not False
        or type(counts) is not dict
        or any(counts.get(name) != 0 for name in counts)
        or type(measured) is not dict
        or measured.get("completed_and_persisted_task_count") != 0
    ):
        raise R2ReservationError("R1 terminal/no-retry evidence differs")


def _require_preflight(
    value: Mapping[str, Any], *, registry_before_raw_sha256: str
) -> None:
    receipt = value.get("public_receipt")
    if (
        value.get("schema_version")
        != "expected_pe.four_model.r2_nonreserved_full_process_preflight.controller.v2"
        or value.get("status")
        != "PASS_NONRESERVED_FULL_PROCESS_PREFLIGHT_NO_HELDOUT_ACCESS"
        or value.get("test_seed") != 9_900_001
        or value.get("test_seed_was_unreserved") is not True
        or value.get("reserved_generator_invocation_count") != 0
        or value.get("truth_leakage_count") != 0
        or value.get("heldout_access_count") != 0
        or value.get("score_open_count") != 0
        or value.get("spent_seed_overlap") != 0
        or value.get("registry_before_raw_sha256") != registry_before_raw_sha256
        or value.get("registry_after_raw_sha256") != registry_before_raw_sha256
        or value.get("path_length") != "PASS"
        or value.get("atomic_publication") != "PASS"
        or type(receipt) is not dict
        or receipt.get("status")
        != "PASS_COLD_PUBLIC_REPLAY_NUMERIC_PREDICTION_ATOMIC_PUBLICATION"
        or receipt.get("heldout_access_count") != 0
        or receipt.get("truth_open_count") != 0
        or receipt.get("score_open_count") != 0
        or receipt.get("c1_prediction_rows") != 0
    ):
        raise R2ReservationError("final non-reserved preflight differs")


def main() -> int:
    _bootstrap()
    arguments = _parser().parse_args()

    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        FORMULA_LOCK,
        HELDOUT_SEEDS,
        MODEL_IDS_IN_ORDER,
        SOURCE_MODEL_VERSIONS,
        SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.evidence import (
        build_source_manifest,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        safe_run_id,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation import (
        generation_plan,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.r2_protocol_lock import (
        build_r2_protocol_lock,
        read_r2_protocol_lock,
        validate_r2_protocol_lock,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.source_inventory import (
        source_manifest_inputs,
    )
    from scripts.run_v04_multiseed_validation import (
        SPENT_SEED_REGISTRY_FORMAT_VERSION,
        SPENT_SEED_REGISTRY_ID,
        _canonical_output_root,
        _read_spent_seed_registry,
        _require_managed_output_root,
        _reservation_contract_from_entry,
        _reservation_id,
        _reserve_or_verify_spent_seeds,
    )

    run_id = safe_run_id(arguments.run_id)
    if run_id != "r2_20260824T000005":
        raise R2ReservationError("R2 reservation run identity differs")
    if tuple(HELDOUT_SEEDS) != LOCKED_SEEDS:
        raise R2ReservationError("live producer heldout seeds differ from precommit")

    _, precommit = _read_exact_json(PRECOMMIT_RELATIVE, PRECOMMIT_RAW_SHA256)
    _require_precommit(precommit, run_id=run_id)
    _, r1_terminal = _read_exact_json(
        R1_TERMINAL_RELATIVE, R1_TERMINAL_RAW_SHA256
    )
    _require_r1_terminal(r1_terminal)

    preflight_path = Path(arguments.final_preflight).resolve(strict=True)
    try:
        preflight_relative = preflight_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise R2ReservationError("final preflight escaped project") from exc
    if (
        not preflight_relative.startswith("build/pe_r2_pf_")
        or not preflight_relative.endswith("/PREFLIGHT_RESULT.json")
        or len(arguments.final_preflight_raw_sha256) != 64
    ):
        raise R2ReservationError("final preflight identity is unsafe")
    _, preflight = _read_exact_json(
        preflight_relative, arguments.final_preflight_raw_sha256
    )

    registry_path = (PROJECT_ROOT / REGISTRY_RELATIVE).resolve(strict=True)
    registry_before_raw = registry_path.read_bytes()
    registry_before_raw_sha256 = _raw_sha256(registry_before_raw)
    if registry_before_raw_sha256 != EXPECTED_REGISTRY_BEFORE_RAW_SHA256:
        raise R2ReservationError("spent-seed registry is not the precommitted predecessor")
    registry_before = _read_spent_seed_registry(registry_path)
    before_entry_count = len(registry_before["entries"])
    if (
        before_entry_count != 10
        or registry_before.get("registry_sha256")
        != precommit["registry_before"]["registry_self_sha256"]
        or registry_before["entries"][-1]["entry_sha256"]
        != precommit["registry_before"]["last_entry_sha256"]
    ):
        raise R2ReservationError("spent-seed registry predecessor chain differs")
    _require_preflight(
        preflight, registry_before_raw_sha256=registry_before_raw_sha256
    )

    source = build_source_manifest(**source_manifest_inputs(PROJECT_ROOT))
    candidate_config = {
        "model_ids_in_order": list(MODEL_IDS_IN_ORDER),
        "survivor_ids_in_qualification_rank_order": list(
            SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER
        ),
        "source_model_versions": dict(SOURCE_MODEL_VERSIONS),
        "formula_lock": FORMULA_LOCK,
        "formula_lock_semantic_sha256": semantic_sha256(FORMULA_LOCK),
        "generation_plan": generation_plan(),
    }
    policy_config = {
        "schema_version": "expected_pe.four_model.r2_replacement_reservation_policy.v1",
        "run_id": run_id,
        "replacement_seed_precommit_raw_sha256": PRECOMMIT_RAW_SHA256,
        "r1_terminal_failure_raw_sha256": R1_TERMINAL_RAW_SHA256,
        "final_nonreserved_preflight_raw_sha256": (
            arguments.final_preflight_raw_sha256
        ),
        "quarantine_seeds_never_generate_or_score": list(QUARANTINE_SEEDS),
        "heldout_seeds_in_order": list(LOCKED_SEEDS),
        "heldout_seed_commitment_sha256": LOCKED_SEED_COMMITMENT_SHA256,
        "candidate_performance_consulted": False,
        "heldout_truth_consulted": False,
        "additional_recovery_reservation_allowed": False,
        "retry_allowed": False,
    }
    output_root = _require_managed_output_root(
        PROJECT_ROOT
        / "outputs"
        / f"model_zoo_pe_four_model_heldout_r2_reservation_{run_id}"
    )
    lock_path = output_root / "promotion_policy.lock.json"
    contract = {
        "format_version": SPENT_SEED_REGISTRY_FORMAT_VERSION,
        "registry_id": SPENT_SEED_REGISTRY_ID,
        "owner_output_root": _canonical_output_root(output_root),
        "source_config_sha256": str(source["source_manifest_semantic_sha256"]),
        "candidates_sha256": semantic_sha256(candidate_config),
        "policy_config_sha256": semantic_sha256(policy_config),
        "tuning_seeds": list(QUARANTINE_SEEDS),
        "locked_seeds": list(LOCKED_SEEDS),
        "reserved_seeds": sorted((*QUARANTINE_SEEDS, *LOCKED_SEEDS)),
    }
    planned = {
        "status": "PASS_R2_RESERVATION_DRY_RUN_NO_MUTATION"
        if arguments.dry_run
        else "READY_FOR_SINGLE_R2_RESERVATION_APPEND",
        "run_id": run_id,
        "owner_output_root": output_root.relative_to(PROJECT_ROOT).as_posix(),
        "protocol_lock_relative_path": lock_path.relative_to(PROJECT_ROOT).as_posix(),
        "source_manifest_semantic_sha256": source["source_manifest_semantic_sha256"],
        "reservation_id": _reservation_id(contract),
        "reservation_contract": contract,
        "registry_before_raw_sha256": registry_before_raw_sha256,
        "registry_entry_count_before": before_entry_count,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    if arguments.dry_run:
        print(json.dumps(planned, sort_keys=True, separators=(",", ":")))
        return 0
    if output_root.exists():
        raise R2ReservationError("R2 reservation output root already exists")
    output_root.mkdir(exist_ok=False)

    receipt = _reserve_or_verify_spent_seeds(
        registry_path, contract, allow_create=True
    )
    registry_after_raw = registry_path.read_bytes()
    registry_after_raw_sha256 = _raw_sha256(registry_after_raw)
    registry_after = _read_spent_seed_registry(registry_path)
    after_entry_count = len(registry_after["entries"])
    entry = registry_after["entries"][-1]
    if (
        after_entry_count != before_entry_count + 1
        or registry_after_raw_sha256 == registry_before_raw_sha256
        or _reservation_contract_from_entry(entry) != contract
        or entry["reservation_id"] != _reservation_id(contract)
        or receipt["reservation_sequence"] != after_entry_count
        or receipt["reservation_entry_sha256"] != entry["entry_sha256"]
    ):
        raise R2ReservationError("single registry append verification failed")

    binding = {
        "r1_terminal_failure": {
            "relative_path": R1_TERMINAL_RELATIVE,
            "raw_sha256": R1_TERMINAL_RAW_SHA256,
        },
        "replacement_seed_precommit": {
            "relative_path": PRECOMMIT_RELATIVE,
            "raw_sha256": PRECOMMIT_RAW_SHA256,
        },
        "final_nonreserved_preflight": {
            "relative_path": preflight_relative,
            "raw_sha256": arguments.final_preflight_raw_sha256,
            "status": preflight["status"],
            "reserved_generator_invocation_count": 0,
            "truth_leakage_count": 0,
            "heldout_access_count": 0,
            "score_open_count": 0,
            "registry_mutation_count": 0,
        },
        "quarantine_seeds_never_generate_or_score": list(QUARANTINE_SEEDS),
        "heldout_seeds_in_order": list(LOCKED_SEEDS),
        "heldout_seed_commitment_sha256": LOCKED_SEED_COMMITMENT_SHA256,
        "reservation_contract": contract,
        "spent_seed_reservation": receipt,
        "registry_transition": {
            "registry_relative_path": REGISTRY_RELATIVE,
            "registry_before_raw_sha256": registry_before_raw_sha256,
            "registry_after_raw_sha256": registry_after_raw_sha256,
            "entry_count_before": before_entry_count,
            "entry_count_after": after_entry_count,
            "append_count": 1,
            "previous_entry_sha256": entry["previous_entry_sha256"],
            "reservation_entry_sha256": entry["entry_sha256"],
            "reservation_created_at_utc": entry["created_at_utc"],
        },
        "overlap_audit": dict(precommit["overlap_audit"]),
        "candidate_performance_consulted": False,
        "heldout_truth_consulted": False,
        "retry_allowed": False,
        "additional_recovery_reservation_allowed": False,
        "candidate_tuning_allowed": False,
        "truth_open_count_at_lock": 0,
        "score_open_count_at_lock": 0,
        "heldout_content_open_count_at_lock": 0,
    }
    protocol_lock = build_r2_protocol_lock(
        run_id=run_id, r2_protocol_binding=binding
    )
    validate_r2_protocol_lock(
        protocol_lock,
        expected_run_id=run_id,
        project_root=PROJECT_ROOT,
        expected_lock_relative_path=lock_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    lock_raw = canonical_pretty_bytes(protocol_lock)
    _write_new(lock_path, lock_raw)
    reread = read_r2_protocol_lock(
        lock_path,
        project_root=PROJECT_ROOT,
        expected_run_id=run_id,
        expected_raw_sha256=_raw_sha256(lock_raw),
    )
    if reread != protocol_lock:
        raise R2ReservationError("R2 protocol lock atomic round-trip differs")
    source_after = build_source_manifest(**source_manifest_inputs(PROJECT_ROOT))
    if source_after != source:
        raise R2ReservationError("producer source changed across registry append")
    print(
        json.dumps(
            {
                **planned,
                "status": "FROZEN_R2_REPLACEMENT_SEEDS_RESERVED_PRETRUTH",
                "registry_after_raw_sha256": registry_after_raw_sha256,
                "registry_after_self_sha256": registry_after["registry_sha256"],
                "registry_entry_count_after": after_entry_count,
                "reservation_entry_sha256": entry["entry_sha256"],
                "protocol_lock_raw_sha256": _raw_sha256(lock_raw),
                "protocol_lock_semantic_sha256": protocol_lock[
                    "r2_protocol_binding_semantic_sha256"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
