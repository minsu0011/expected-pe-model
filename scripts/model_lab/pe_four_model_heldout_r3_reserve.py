"""Reserve one pinned R3 allocation and publish its legacy-wire protocol lock.

This helper is deliberately outside the producer and evaluator source closures.
It never derives seed values: it accepts one already-frozen R3 precommit, validates
its evidence chain, and checks the values against the subsequently migrated
producer constants.  The default is a read-only plan; ``--apply`` is the only
mutation authority.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Callable, Final, Mapping, Sequence


sys.dont_write_bytecode = True

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SITE_PACKAGES: Final = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
HEX64: Final = re.compile(r"^[0-9a-f]{64}$")

POLICY_SCHEMA: Final = "expected_pe.four_model.r3_value_free_seed_selection_policy.v1"
POLICY_STATUS: Final = "FROZEN_BEFORE_NEW_SEED_VALUE_DERIVATION"
PRECOMMIT_SCHEMA: Final = "expected_pe.four_model.r3_seed_precommit.v1"
PRECOMMIT_STATUS: Final = (
    "FROZEN_PRE_RESERVATION_PERFORMANCE_INDEPENDENT_R3_ALLOCATION"
)
PRE_DERIVATION_GATE_SCHEMA: Final = (
    "expected_pe.four_model.r3_pre_derivation_gate.v1"
)
PRE_DERIVATION_GATE_STATUS: Final = (
    "GO_DERIVE_AND_FREEZE_PRECOMMIT_ONLY_NO_REGISTRY_APPEND"
)
INDEPENDENT_AUDIT_SCHEMA: Final = (
    "expected_pe.four_model.r3_seed_precommit_independent_audit.v1"
)
INDEPENDENT_AUDIT_STATUS: Final = "GO_R3_SINGLE_RESERVATION_PRETRUTH"
REHEARSAL_SCHEMA: Final = (
    "expected_pe.four_model.r3_full_nonreserved_rehearsal.result.v1"
)
REHEARSAL_STATUS: Final = "GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE"
R2_TERMINAL_SCHEMA: Final = (
    "expected_pe.four_model.r2_prediction_publication_terminal.v1"
)
R2_TERMINAL_STATUS: Final = (
    "TERMINAL_UNSEALED_PREDICTION_PREFIX_NO_ACTIVATION_OR_SCORING"
)


class R3ReservationError(RuntimeError):
    """Fail-closed R3 single-reservation error."""


@dataclass(frozen=True)
class PinnedJson:
    relative_path: str
    raw_sha256: str
    raw: bytes
    value: Mapping[str, Any]


@dataclass(frozen=True)
class RuntimeBindings:
    """Late-bound producer/protocol/registry API used after R3 source migration."""

    canonical_pretty_bytes: Callable[[object], bytes]
    semantic_sha256: Callable[[object], str]
    safe_run_id: Callable[[object], str]
    heldout_seeds: tuple[int, ...]
    quarantine_seeds: tuple[int, ...]
    heldout_seed_commitment_sha256: str
    precommit_relative_path: str
    precommit_raw_sha256: str
    independent_audit_relative_path: str
    independent_audit_raw_sha256: str
    r2_terminal_relative_path: str
    r2_terminal_raw_sha256: str
    registry_relative_path: str
    registry_before_raw_sha256: str
    registry_before_entry_count: int
    registry_previous_entry_sha256: str
    protocol_schema: str
    protocol_status: str
    protocol_root_prefix: str
    protocol_leaf: str
    model_ids_in_order: tuple[str, ...]
    survivor_ids_in_order: tuple[str, ...]
    source_model_versions: Mapping[str, str]
    formula_lock: Mapping[str, object]
    build_source_manifest: Callable[..., Mapping[str, object]]
    source_manifest_inputs: Callable[[Path], Mapping[str, object]]
    generation_plan: Callable[[], Mapping[str, object]]
    build_protocol_lock: Callable[..., Mapping[str, object]]
    validate_protocol_lock: Callable[..., Mapping[str, object]]
    read_protocol_lock: Callable[..., Mapping[str, object]]
    registry_format_version: int
    registry_id: str
    canonical_output_root: Callable[[Path], str]
    require_managed_output_root: Callable[[Path], Path]
    read_registry: Callable[[Path], Mapping[str, Any]]
    reservation_contract_from_entry: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    reservation_id: Callable[[Mapping[str, Any]], str]
    acquire_registry_lock: Callable[[Path], tuple[int, Path]]
    release_registry_lock: Callable[[int, Path], None]
    verify_reservation_contract: Callable[[Mapping[str, Any]], None]
    verify_registry: Callable[[Mapping[str, Any]], None]
    seal_payload: Callable[[Mapping[str, Any], str], Mapping[str, Any]]
    utc_now: Callable[[], str]
    atomic_write_registry: Callable[[Path, Mapping[str, Any]], None]
    registry_jsonable: Callable[[object], object]
    baseline_spent_seeds: tuple[int, ...]


@dataclass(frozen=True)
class ReservationPlan:
    project_root: Path
    run_id: str
    runtime: RuntimeBindings
    precommit: PinnedJson
    pre_derivation_gate: PinnedJson
    independent_audit: PinnedJson
    policy: PinnedJson
    rehearsal_gate: PinnedJson
    r2_terminal: PinnedJson
    registry_path: Path
    registry_before_raw: bytes
    registry_before: Mapping[str, Any]
    source_manifest: Mapping[str, object]
    output_root: Path
    lock_path: Path
    reservation_contract: Mapping[str, object]
    report: Mapping[str, object]


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R3ReservationError("R3 reservation requires -I -B")
    if sys.pycache_prefix is None:
        raise R3ReservationError("R3 reservation pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise R3ReservationError("R3 reservation pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash(value: object, *, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None or value == "0" * 64:
        raise R3ReservationError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def _relative(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise R3ReservationError(f"{label} is not a POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
    ):
        raise R3ReservationError(f"{label} normalization differs")
    return value


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise R3ReservationError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                R3ReservationError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3ReservationError(f"{label} JSON differs") from exc
    if type(value) is not dict:
        raise R3ReservationError(f"{label} is not an object")
    return value


def _canonical_pretty_bytes(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise R3ReservationError("canonical JSON encoding failed") from exc
    return (text + "\n").encode("utf-8")


def _semantic_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise R3ReservationError("semantic JSON encoding failed") from exc
    return _sha256(raw)


def _project_file(project_root: Path, relative: str) -> Path:
    project = project_root.resolve(strict=True)
    normalized = _relative(relative, label="project file")
    requested = project.joinpath(*PurePosixPath(normalized).parts)
    if requested.is_symlink():
        raise R3ReservationError(f"project file is a symlink: {normalized}")
    resolved = requested.resolve(strict=True)
    if project not in resolved.parents or not resolved.is_file() or resolved.is_symlink():
        raise R3ReservationError(f"project file escaped or differs: {normalized}")
    return resolved


def _read_pinned_json(
    project_root: Path,
    path_argument: Path,
    expected_raw_sha256: str,
    *,
    label: str,
) -> PinnedJson:
    expected = _hash(expected_raw_sha256, label=f"{label} raw SHA-256")
    project = project_root.resolve(strict=True)
    requested = path_argument if path_argument.is_absolute() else project / path_argument
    if requested.is_symlink():
        raise R3ReservationError(f"{label} path is a symlink")
    candidate = requested.resolve(strict=True)
    if project not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
        raise R3ReservationError(f"{label} escaped the project")
    relative = candidate.relative_to(project).as_posix()
    first = candidate.read_bytes()
    second = candidate.read_bytes()
    if first != second or _sha256(first) != expected:
        raise R3ReservationError(f"{label} raw bytes differ")
    value = _strict_json_object(first, label=label)
    if _canonical_pretty_bytes(value) != first:
        raise R3ReservationError(f"{label} canonical bytes differ")
    return PinnedJson(relative, expected, first, value)


def _read_live_ref(project_root: Path, value: object, *, label: str) -> bytes:
    if type(value) is not dict or set(value) != {"relative_path", "raw_sha256"}:
        raise R3ReservationError(f"{label} reference differs")
    relative = _relative(value["relative_path"], label=f"{label} path")
    digest = _hash(value["raw_sha256"], label=f"{label} raw SHA-256")
    raw = _project_file(project_root, relative).read_bytes()
    if _sha256(raw) != digest:
        raise R3ReservationError(f"{label} live raw SHA-256 differs")
    return raw


def _validate_value_free_policy(
    policy: PinnedJson,
    *,
    run_id: str,
    rehearsal_gate: PinnedJson,
    project_root: Path,
) -> tuple[dict[str, Any], tuple[int, ...]]:
    value = policy.value
    roles = value.get("allocation_role_policy")
    authority = value.get("authority_inputs")
    independence = value.get("candidate_and_evidence_independence")
    exclusion = value.get("exclusion_policy")
    execution = value.get("formal_execution_policy")
    selection = value.get("selection_rule")
    if (
        set(value)
        != {
            "allocation_role_policy",
            "authority_inputs",
            "candidate_and_evidence_independence",
            "exclusion_policy",
            "formal_execution_policy",
            "new_seed_values_present",
            "run_id",
            "schema_version",
            "selection_rule",
            "status",
        }
        or value.get("schema_version") != POLICY_SCHEMA
        or value.get("status") != POLICY_STATUS
        or value.get("run_id") != run_id
        or value.get("new_seed_values_present") is not False
        or type(roles) is not dict
        or set(roles)
        != {
            "compatibility_quarantine_count",
            "compatibility_quarantine_generator_invocation_allowed",
            "compatibility_quarantine_reason",
            "compatibility_quarantine_scoring_allowed",
            "formal_heldout_count",
            "formal_heldout_role",
            "new_reserved_seed_count",
        }
        or roles.get("compatibility_quarantine_count") != 5
        or roles.get("formal_heldout_count") != 5
        or roles.get("new_reserved_seed_count") != 10
        or roles.get("compatibility_quarantine_generator_invocation_allowed") is not False
        or roles.get("compatibility_quarantine_scoring_allowed") is not False
        or type(independence) is not dict
        or set(independence)
        != {
            "candidate_performance_consulted",
            "dgp_outcome_consulted",
            "heldout_truth_consulted",
            "qualification_error_surface_consulted",
            "score_content_consulted",
            "selection_retry_allowed",
        }
        or any(item is not False for item in independence.values())
        or type(execution) is not dict
        or set(execution)
        != {
            "additional_recovery_reservation_allowed",
            "candidate_formula_change_allowed",
            "candidate_order_change_allowed",
            "candidate_tuning_allowed",
            "exact_formal_heldout_seed_count",
            "post_result_seed_change_allowed",
            "r2_artifact_reuse_allowed",
            "r2_seed_reuse_allowed",
            "reservation_append_count",
            "reservation_retry_allowed",
            "seed_cherry_picking_allowed",
        }
        or execution.get("exact_formal_heldout_seed_count") != 5
        or execution.get("reservation_append_count") != 1
        or any(
            execution.get(name) is not False
            for name in (
                "additional_recovery_reservation_allowed",
                "candidate_formula_change_allowed",
                "candidate_order_change_allowed",
                "candidate_tuning_allowed",
                "post_result_seed_change_allowed",
                "reservation_retry_allowed",
                "r2_artifact_reuse_allowed",
                "r2_seed_reuse_allowed",
                "seed_cherry_picking_allowed",
            )
        )
        or type(selection) is not dict
        or set(selection)
        != {
            "assignment",
            "derivation",
            "primality_definition",
            "tie_or_randomness",
            "value_derivation_authorized_only_after_this_policy_raw_sha256_is_RECORDED",
        }
        or selection.get("tie_or_randomness")
        != "NONE_DETERMINISTIC_ASCENDING_INTEGER_SCAN"
        or selection.get(
            "value_derivation_authorized_only_after_this_policy_raw_sha256_is_RECORDED"
        )
        is not True
        or any(
            type(selection.get(name)) is not str or not selection[name]
            for name in ("assignment", "derivation", "primality_definition")
        )
        or type(authority) is not dict
        or set(authority)
        != {
            "formal_audit_contract_alignment",
            "r2_terminal_handoff",
            "r2_terminal_prediction",
            "r3_direction_prompt",
            "r3_full_nonreserved_rehearsal",
            "remediation_source_hashes",
            "spent_seed_registry_predecessor",
            "spent_seed_registry_validation_source",
        }
        or type(exclusion) is not dict
        or set(exclusion)
        != {
            "all_registry_reserved_seeds_excluded",
            "qualification_seeds_excluded",
            "r1_and_r2_formal_seeds_excluded",
            "r3_rehearsal_fixture_seeds_excluded",
            "r3_rehearsal_fixture_seeds_in_order",
        }
    ):
        raise R3ReservationError("frozen value-free R3 policy differs")

    predecessor = authority.get("spent_seed_registry_predecessor")
    rehearsal = authority.get("r3_full_nonreserved_rehearsal")
    terminal = authority.get("r2_terminal_prediction")
    validation_source = authority.get("spent_seed_registry_validation_source")
    fixture = exclusion.get("r3_rehearsal_fixture_seeds_in_order")
    if (
        type(predecessor) is not dict
        or set(predecessor)
        != {
            "entry_count",
            "last_entry_sha256",
            "maximum_reserved_seed",
            "raw_sha256",
            "registry_self_sha256",
            "relative_path",
        }
        or type(rehearsal) is not dict
        or rehearsal.get("relative_path") != rehearsal_gate.relative_path
        or rehearsal.get("raw_sha256") != rehearsal_gate.raw_sha256
        or rehearsal.get("status") != REHEARSAL_STATUS
        or rehearsal.get("task_count") != 50
        or rehearsal.get("identity_count") != 64_800
        or rehearsal.get("prediction_row_count") != 259_200
        or rehearsal.get("registry_mutation_count") != 0
        or rehearsal.get("truth_open_count") != 0
        or rehearsal.get("score_open_count") != 0
        or type(terminal) is not dict
        or set(terminal) != {"relative_path", "raw_sha256"}
        or type(validation_source) is not dict
        or type(fixture) is not list
        or len(fixture) != 5
        or any(type(seed) is not int or seed <= 0 for seed in fixture)
        or len(set(fixture)) != 5
        or exclusion.get("all_registry_reserved_seeds_excluded") is not True
        or exclusion.get("qualification_seeds_excluded") is not True
        or exclusion.get("r1_and_r2_formal_seeds_excluded") is not True
        or exclusion.get("r3_rehearsal_fixture_seeds_excluded") is not True
    ):
        raise R3ReservationError("R3 policy authority/exclusion binding differs")
    _read_live_ref(project_root, validation_source, label="registry validation source")

    alignment = authority.get("formal_audit_contract_alignment")
    if (
        type(alignment) is not dict
        or alignment.get("audit_check_key_count") != 18
    ):
        raise R3ReservationError("R3 18-key audit alignment differs")
    for prefix in ("evaluator_constants", "producer_evidence"):
        _read_live_ref(
            project_root,
            {
                "relative_path": alignment.get(f"{prefix}_relative_path"),
                "raw_sha256": alignment.get(f"{prefix}_raw_sha256"),
            },
            label=f"R3 {prefix.replace('_', ' ')}",
        )
    return dict(predecessor), tuple(fixture)


def _validate_precommit(
    precommit: PinnedJson,
    *,
    policy: PinnedJson,
    run_id: str,
    predecessor: Mapping[str, Any],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    value = precommit.value
    selected = value.get("deterministic_next_ten_primes")
    quarantine = value.get("quarantine_seeds_never_generate_or_score")
    heldout = value.get("heldout_seeds_in_order")
    commitment_payload = value.get("heldout_seed_commitment_payload")
    formal = value.get("formal_execution_policy")
    overlap = value.get("overlap_audit")
    registry_before = value.get("registry_before")
    selection = value.get("selection_rule")
    if (
        set(value)
        != {
            "deterministic_next_ten_primes",
            "formal_execution_policy",
            "heldout_seed_commitment_payload",
            "heldout_seed_commitment_sha256",
            "heldout_seeds_in_order",
            "overlap_audit",
            "pre_derivation_gate",
            "quarantine_seeds_never_generate_or_score",
            "registry_before",
            "run_id",
            "schema_version",
            "selection_rule",
            "status",
            "value_free_policy_raw_sha256",
            "value_free_policy_relative_path",
        }
        or value.get("schema_version") != PRECOMMIT_SCHEMA
        or value.get("status") != PRECOMMIT_STATUS
        or value.get("run_id") != run_id
        or value.get("value_free_policy_relative_path") != policy.relative_path
        or value.get("value_free_policy_raw_sha256") != policy.raw_sha256
        or type(value.get("pre_derivation_gate")) is not dict
        or set(value["pre_derivation_gate"])
        != {"relative_path", "raw_sha256", "status"}
        or value["pre_derivation_gate"].get("status")
        != PRE_DERIVATION_GATE_STATUS
        or type(selected) is not list
        or type(quarantine) is not list
        or type(heldout) is not list
        or len(selected) != 10
        or len(quarantine) != 5
        or len(heldout) != 5
        or any(type(seed) is not int or seed <= 0 for seed in selected)
        or len(set(selected)) != 10
        or selected != sorted(selected)
        or selected != [*quarantine, *heldout]
        or commitment_payload != {"locked_seeds": heldout}
        or value.get("heldout_seed_commitment_sha256")
        != _semantic_sha256(commitment_payload)
        or type(formal) is not dict
        or set(formal)
        != {
            "additional_recovery_reservation_allowed",
            "exact_heldout_seed_count",
            "post_result_seed_change_allowed",
            "quarantine_generator_invocation_allowed",
            "r2_seed_reuse_allowed",
            "seed_cherry_picking_allowed",
        }
        or formal.get("exact_heldout_seed_count") != 5
        or formal.get("additional_recovery_reservation_allowed") is not False
        or formal.get("post_result_seed_change_allowed") is not False
        or formal.get("quarantine_generator_invocation_allowed") is not False
        or formal.get("r2_seed_reuse_allowed") is not False
        or formal.get("seed_cherry_picking_allowed") is not False
        or type(overlap) is not dict
        or set(overlap)
        != {
            "prior_spent_overlap_count",
            "qualification_seed_overlap_count",
            "r2_formal_seed_overlap_count",
            "rehearsal_fixture_overlap_count",
            "within_allocation_duplicate_count",
        }
        or any(item != 0 for item in overlap.values())
        or type(registry_before) is not dict
        or set(registry_before)
        != {
            "entry_count",
            "globally_spent_seed_count",
            "last_entry_sha256",
            "maximum_reserved_seed",
            "raw_sha256",
            "registry_self_sha256",
            "relative_path",
        }
        or {
            key: item
            for key, item in registry_before.items()
            if key != "globally_spent_seed_count"
        }
        != predecessor
        or type(registry_before["globally_spent_seed_count"]) is not int
        or registry_before["globally_spent_seed_count"] <= 0
        or type(selection) is not dict
    ):
        raise R3ReservationError("frozen R3 seed precommit differs")
    policy_independence = policy.value["candidate_and_evidence_independence"]
    policy_rule = policy.value["selection_rule"]
    expected_selection = {
        "algorithm": policy_rule["derivation"],
        "assignment": policy_rule["assignment"],
        **dict(policy_independence),
    }
    if selection != expected_selection:
        raise R3ReservationError("R3 precommit selection rule differs from policy")
    return tuple(quarantine), tuple(heldout)


def _read_pre_derivation_gate(
    *, project_root: Path, precommit: PinnedJson
) -> PinnedJson:
    ref = precommit.value.get("pre_derivation_gate")
    if type(ref) is not dict or set(ref) != {
        "relative_path",
        "raw_sha256",
        "status",
    }:
        raise R3ReservationError("R3 pre-derivation gate reference differs")
    relative = _relative(ref["relative_path"], label="R3 pre-derivation gate path")
    digest = _hash(
        ref["raw_sha256"], label="R3 pre-derivation gate raw SHA-256"
    )
    if ref["status"] != PRE_DERIVATION_GATE_STATUS:
        raise R3ReservationError("R3 pre-derivation gate status differs")
    gate = _read_pinned_json(
        project_root,
        Path(relative),
        digest,
        label="R3 pre-derivation gate",
    )
    if gate.relative_path != relative:
        raise R3ReservationError("R3 pre-derivation gate path differs")
    return gate


def _validate_pre_derivation_gate(
    gate: PinnedJson,
    *,
    run_id: str,
    policy: PinnedJson,
    rehearsal_gate: PinnedJson,
    r2_terminal: PinnedJson,
    predecessor: Mapping[str, Any],
    model_ids_in_order: tuple[str, ...],
    formula_lock_semantic_sha256: str,
) -> None:
    value = gate.value
    authority = value.get("authority_bindings")
    blocked = value.get("blocked_actions_until_later_reservation_gate")
    if (
        set(value)
        != {
            "authority_bindings",
            "blocked_actions_until_later_reservation_gate",
            "formal_seed_derivation_count_at_gate",
            "formula_lock_semantic_sha256",
            "model_ids_in_order",
            "registry_mutation_count_at_gate",
            "resource_execution_plan",
            "run_id",
            "schema_version",
            "status",
            "test_evidence",
            "truth_open_count_at_gate",
        }
        or value.get("schema_version") != PRE_DERIVATION_GATE_SCHEMA
        or value.get("status") != PRE_DERIVATION_GATE_STATUS
        or value.get("run_id") != run_id
        or value.get("formal_seed_derivation_count_at_gate") != 0
        or value.get("registry_mutation_count_at_gate") != 0
        or value.get("truth_open_count_at_gate") != 0
        or value.get("model_ids_in_order") != list(model_ids_in_order)
        or value.get("formula_lock_semantic_sha256")
        != formula_lock_semantic_sha256
        or blocked
        != [
            "SPENT_SEED_REGISTRY_APPEND",
            "FORMAL_HELDOUT_GENERATION",
            "FORMAL_PREDICTION",
            "ACTIVATION_MINT",
            "TRUTH_OPEN",
            "SCORING",
        ]
        or type(authority) is not dict
        or set(authority)
        != {
            "evaluator_repin_helper",
            "post_generation_auditor",
            "r2_terminal_prediction",
            "r3_full_nonreserved_rehearsal",
            "seed_allocator",
            "spent_seed_registry_predecessor",
            "value_free_seed_policy",
        }
    ):
        raise R3ReservationError("R3 pre-derivation gate differs")

    policy_ref = authority["value_free_seed_policy"]
    rehearsal_ref = authority["r3_full_nonreserved_rehearsal"]
    terminal_ref = authority["r2_terminal_prediction"]
    predecessor_ref = authority["spent_seed_registry_predecessor"]
    expected_predecessor = {
        key: predecessor[key]
        for key in (
            "entry_count",
            "last_entry_sha256",
            "raw_sha256",
            "registry_self_sha256",
            "relative_path",
        )
    }
    if (
        policy_ref
        != {
            "relative_path": policy.relative_path,
            "raw_sha256": policy.raw_sha256,
            "status": POLICY_STATUS,
        }
        or rehearsal_ref
        != {
            "relative_path": rehearsal_gate.relative_path,
            "raw_sha256": rehearsal_gate.raw_sha256,
            "status": REHEARSAL_STATUS,
        }
        or terminal_ref
        != {
            "relative_path": r2_terminal.relative_path,
            "raw_sha256": r2_terminal.raw_sha256,
        }
        or predecessor_ref != expected_predecessor
    ):
        raise R3ReservationError("R3 pre-derivation authority binding differs")

    for name in ("evaluator_repin_helper", "post_generation_auditor"):
        ref = authority[name]
        if (
            type(ref) is not dict
            or set(ref) != {"relative_path", "raw_sha256", "test_raw_sha256"}
            or _relative(ref["relative_path"], label=f"{name} path")
            != ref["relative_path"]
            or _hash(ref["raw_sha256"], label=f"{name} raw SHA-256")
            != ref["raw_sha256"]
            or _hash(ref["test_raw_sha256"], label=f"{name} test raw SHA-256")
            != ref["test_raw_sha256"]
        ):
            raise R3ReservationError("R3 pre-derivation helper binding differs")
    allocator = authority["seed_allocator"]
    if (
        type(allocator) is not dict
        or set(allocator)
        != {
            "raw_sha256_before_gate_binding",
            "relative_path",
            "test_raw_sha256_before_gate_binding",
        }
        or _relative(allocator["relative_path"], label="seed allocator path")
        != allocator["relative_path"]
        or _hash(
            allocator["raw_sha256_before_gate_binding"],
            label="seed allocator raw SHA-256",
        )
        != allocator["raw_sha256_before_gate_binding"]
        or _hash(
            allocator["test_raw_sha256_before_gate_binding"],
            label="seed allocator test raw SHA-256",
        )
        != allocator["test_raw_sha256_before_gate_binding"]
    ):
        raise R3ReservationError("R3 pre-derivation allocator binding differs")
    resources = value["resource_execution_plan"]
    evidence = value["test_evidence"]
    if (
        type(resources) is not dict
        or resources.get("gpu_execution_authorized") is not False
        or resources.get("formal_generation_outer_workers") != 16
        or resources.get("formal_prediction_cpu_workers") != 32
        or type(evidence) is not dict
        or evidence.get("producer_evaluator_exact_18_key_parity") != "PASS"
        or evidence.get("ruff_lint") != "PASS"
        or any(
            evidence.get(name) != "PASS"
            for name in (
                "evaluator_repin_complete_byte_no_op",
                "handle_lifecycle_windows_subprocess",
                "post_generation_full_synthetic_50_task_run_audit",
                "post_generation_resealed_extra_key_attacks",
            )
        )
    ):
        raise R3ReservationError("R3 pre-derivation execution evidence differs")


def _validate_independent_audit(
    audit: PinnedJson,
    *,
    project_root: Path,
    run_id: str,
    precommit: PinnedJson,
    pre_derivation_gate: PinnedJson,
    policy: PinnedJson,
    rehearsal_gate: PinnedJson,
    r2_terminal: PinnedJson,
    predecessor: Mapping[str, Any],
    quarantine: tuple[int, ...],
    heldout: tuple[int, ...],
    rehearsal_fixture_seeds: tuple[int, ...],
    baseline_spent_seed_count: int,
) -> None:
    value = audit.value
    unsigned = dict(value)
    stored_semantic = unsigned.pop("audit_semantic_sha256", None)
    access = value.get("access_counts")
    method = value.get("audit_method")
    recomputation = value.get("independent_recomputation")
    inputs = value.get("input_bindings")
    live_checks = value.get("live_gate_source_pin_checks")
    overlap = value.get("overlap_counts")
    registry_state = value.get("registry_predecessor_state")
    authorization = value.get("reservation_authorization")
    accounting = value.get("spent_seed_accounting")
    if (
        set(value)
        != {
            "access_counts",
            "append_performed",
            "audit_method",
            "audit_semantic_sha256",
            "independent_recomputation",
            "input_bindings",
            "live_gate_source_pin_checks",
            "overlap_counts",
            "registry_predecessor_state",
            "reservation_authorization",
            "run_id",
            "schema_version",
            "spent_seed_accounting",
            "status",
        }
        or value.get("schema_version") != INDEPENDENT_AUDIT_SCHEMA
        or value.get("status") != INDEPENDENT_AUDIT_STATUS
        or value.get("run_id") != run_id
        or value.get("append_performed") is not False
        or stored_semantic != _semantic_sha256(unsigned)
        or access
        != {
            "heldout_protected_open_count": 0,
            "performance_content_consulted_count": 0,
            "score_open_count": 0,
            "truth_open_count": 0,
        }
        or method
        != {
            "allocator_build_precommit_invoked": False,
            "allocator_main_invoked": False,
            "independent_primality_method": (
                "TRIAL_DIVISION_2_THROUGH_INTEGER_SQRT"
            ),
            "read_only_recomputation": True,
            "source_modified": False,
        }
    ):
        raise R3ReservationError("R3 independent reservation audit differs")

    expected_recomputation = {
        "deterministic_next_ten_primes": [*quarantine, *heldout],
        "heldout_seed_commitment_payload": {"locked_seeds": list(heldout)},
        "heldout_seed_commitment_sha256": precommit.value[
            "heldout_seed_commitment_sha256"
        ],
        "heldout_seeds_in_order": list(heldout),
        "predecessor_maximum_reserved_seed": predecessor["maximum_reserved_seed"],
        "primality_all_exact": True,
        "quarantine_seeds_never_generate_or_score": list(quarantine),
        "role_assignment_exact": True,
        "sequence_exact": True,
        "strictly_ascending_unique": True,
    }
    expected_authorization = {
        "additional_reservation_or_retry_allowed": False,
        "authorized_next_registry_append_count": 1,
        "compatibility_quarantine_count": 5,
        "formal_heldout_count": 5,
        "formal_truth_or_score_access_authorized": False,
        "scope": "ONE_R3_REGISTRY_RESERVATION_APPEND_ONLY_PRETRUTH",
    }
    expected_registry_state = {
        "append_performed": False,
        "entry_count": predecessor["entry_count"],
        "globally_spent_seed_count": precommit.value["registry_before"][
            "globally_spent_seed_count"
        ],
        "last_entry_sha256": predecessor["last_entry_sha256"],
        "maximum_reserved_seed": predecessor["maximum_reserved_seed"],
        "mutation_count": 0,
        "raw_sha256": predecessor["raw_sha256"],
        "registry_self_sha256": predecessor["registry_self_sha256"],
        "reservation_performed": False,
    }
    globally_spent = precommit.value["registry_before"][
        "globally_spent_seed_count"
    ]
    expected_accounting = {
        "baseline_spent_seed_count": baseline_spent_seed_count,
        "globally_spent_seed_count": globally_spent,
        "qualification_seed_count": 5,
        "qualification_seeds_all_in_spent": True,
        "r2_seed_count": 10,
        "r2_seeds_all_in_spent": True,
        "registry_reserved_seed_count": globally_spent - baseline_spent_seed_count,
        "rehearsal_fixture_count": len(rehearsal_fixture_seeds),
        "rehearsal_fixture_disjoint_from_spent": True,
    }
    expected_live_checks = {
        "all_checks_pass",
        "evaluator_repin_helper_raw_sha256_exact",
        "evaluator_repin_test_raw_sha256_exact",
        "historical_seed_allocator_raw_sha256_reconstructed_exact",
        "historical_seed_allocator_test_raw_sha256_reconstructed_exact",
        "post_generation_auditor_raw_sha256_exact",
        "post_generation_auditor_test_raw_sha256_exact",
        "r2_terminal_prediction_raw_sha256_exact",
        "r3_full_nonreserved_rehearsal_raw_sha256_exact",
        "spent_seed_registry_predecessor_raw_sha256_exact",
        "value_free_seed_policy_raw_sha256_exact",
    }
    if (
        recomputation != expected_recomputation
        or overlap != precommit.value["overlap_audit"]
        or registry_state != expected_registry_state
        or authorization != expected_authorization
        or accounting != expected_accounting
        or type(live_checks) is not dict
        or set(live_checks) != expected_live_checks
        or any(item is not True for item in live_checks.values())
    ):
        raise R3ReservationError("R3 independent audit authorization differs")

    if type(inputs) is not dict or set(inputs) != {
        "pre_derivation_gate",
        "qualification_seed_authority_source",
        "r2_terminal_prediction",
        "r3_full_nonreserved_rehearsal",
        "seed_precommit",
        "spent_seed_registry_predecessor",
        "spent_seed_validation_source",
        "value_free_seed_policy",
    }:
        raise R3ReservationError("R3 independent audit input universe differs")
    expected_gate_ref = {
        "canonical_full_payload_sha256": _semantic_sha256(
            pre_derivation_gate.value
        ),
        "raw_sha256": pre_derivation_gate.raw_sha256,
        "relative_path": pre_derivation_gate.relative_path,
        "status": PRE_DERIVATION_GATE_STATUS,
    }
    expected_precommit_ref = {
        "canonical_full_payload_sha256": _semantic_sha256(precommit.value),
        "raw_sha256": precommit.raw_sha256,
        "relative_path": precommit.relative_path,
        "status": PRECOMMIT_STATUS,
    }
    expected_policy_ref = {
        "canonical_full_payload_sha256": _semantic_sha256(policy.value),
        "raw_sha256": policy.raw_sha256,
        "relative_path": policy.relative_path,
        "status": POLICY_STATUS,
    }
    expected_terminal_ref = {
        "raw_sha256": r2_terminal.raw_sha256,
        "relative_path": r2_terminal.relative_path,
        "semantic_sha256": r2_terminal.value["terminal_semantic_sha256"],
        "status": R2_TERMINAL_STATUS,
    }
    expected_rehearsal_ref = {
        "raw_sha256": rehearsal_gate.raw_sha256,
        "relative_path": rehearsal_gate.relative_path,
        "semantic_sha256": rehearsal_gate.value["result_semantic_sha256"],
        "status": REHEARSAL_STATUS,
    }
    expected_registry_ref = {
        "raw_sha256": predecessor["raw_sha256"],
        "registry_self_sha256": predecessor["registry_self_sha256"],
        "relative_path": predecessor["relative_path"],
    }
    validation_ref = policy.value["authority_inputs"][
        "spent_seed_registry_validation_source"
    ]
    if (
        inputs["pre_derivation_gate"] != expected_gate_ref
        or inputs["seed_precommit"] != expected_precommit_ref
        or inputs["value_free_seed_policy"] != expected_policy_ref
        or inputs["r2_terminal_prediction"] != expected_terminal_ref
        or inputs["r3_full_nonreserved_rehearsal"] != expected_rehearsal_ref
        or inputs["spent_seed_registry_predecessor"] != expected_registry_ref
        or inputs["spent_seed_validation_source"] != validation_ref
    ):
        raise R3ReservationError("R3 independent audit input binding differs")
    _read_live_ref(
        project_root,
        inputs["qualification_seed_authority_source"],
        label="qualification seed authority source",
    )
    _read_live_ref(
        project_root,
        inputs["spent_seed_validation_source"],
        label="independent audit registry validation source",
    )


def _validate_rehearsal_gate(
    gate: PinnedJson,
    *,
    predecessor: Mapping[str, Any],
    fixture_seeds: tuple[int, ...],
    model_ids_in_order: tuple[str, ...],
) -> None:
    value = gate.value
    unsigned = dict(value)
    stored_semantic = unsigned.pop("result_semantic_sha256", None)
    fixture = value.get("fixture_profile")
    if (
        value.get("schema_version") != REHEARSAL_SCHEMA
        or value.get("status") != REHEARSAL_STATUS
        or stored_semantic != _semantic_sha256(unsigned)
        or type(value.get("run_id")) is not str
        or not str(value["run_id"]).startswith("r3")
        or value.get("task_count") != 50
        or value.get("identity_count") != 64_800
        or value.get("prediction_row_count") != 259_200
        or value.get("model_ids_in_order") != list(model_ids_in_order)
        or value.get("c1_prediction_row_count") != 0
        or value.get("registry_before_raw_sha256") != predecessor["raw_sha256"]
        or value.get("registry_after_raw_sha256") != predecessor["raw_sha256"]
        or value.get("registry_entry_count") != predecessor["entry_count"]
        or value.get("registry_bytes_unchanged") is not True
        or value.get("spent_seed_overlap_count") != 0
        or value.get("formal_seed_reservation_count") != 0
        or value.get("handle_write_to_read_only_custody_transition") != "PASS"
        or value.get("independent_path_reopen_hash_fileid_recompute") != "PASS"
        or value.get("commit_last_audit_checksums_seal") != "PASS"
        or value.get("rehearsal_activation") != "PASS"
        or value.get("detached_evaluator_plumbing") != "PASS"
        or value.get("all_child_processes_reaped") is not True
        or value.get("no_r2_path_or_artifact_reuse") is not True
        or value.get("candidate_tuning_allowed") is not False
        or value.get("truth_open_count") != 0
        or value.get("score_open_count") != 0
        or value.get("heldout_content_open_count") != 0
        or type(fixture) is not dict
        or fixture.get("seeds_in_order") != list(fixture_seeds)
        or fixture.get("seed_selection") != "EXPLICIT_FIXED_NONRANDOM_FIXTURE"
        or fixture.get("seed_profile_frozen_before_execution") is not True
        or fixture.get("permanently_excluded_from_formal_reservation") is not True
        or fixture.get("formal_seed_reservation_count") != 0
    ):
        raise R3ReservationError("full nonreserved R3 rehearsal gate differs")


def _validate_r2_terminal(terminal: PinnedJson) -> None:
    value = terminal.value
    unsigned = dict(value)
    stored_semantic = unsigned.pop("terminal_semantic_sha256", None)
    seed_disposition = value.get("seed_disposition")
    prohibitions = value.get("prohibitions")
    access = value.get("access")
    if (
        value.get("schema_version") != R2_TERMINAL_SCHEMA
        or value.get("status") != R2_TERMINAL_STATUS
        or type(value.get("run_id")) is not str
        or not str(value["run_id"]).startswith("r2_")
        or value.get("terminal") is not True
        or value.get("retry_allowed") is not False
        or value.get("recovery_allowed") is not False
        or value.get("certification_authority") is not False
        or stored_semantic != _semantic_sha256(unsigned)
        or type(seed_disposition) is not dict
        or seed_disposition.get("all_reserved_seeds_conservatively_spent") is not True
        or seed_disposition.get("seed_reuse_allowed") is not False
        or seed_disposition.get("additional_recovery_reservation_allowed") is not False
        or type(prohibitions) is not dict
        or any(item is not False for item in prohibitions.values())
        or type(access) is not dict
        or any(item != 0 for item in access.values())
    ):
        raise R3ReservationError("terminal R2 no-retry evidence differs")


def _registry_seed_set(
    registry: Mapping[str, Any], *, baseline_spent_seeds: tuple[int, ...]
) -> set[int]:
    entries = registry.get("entries")
    if type(entries) is not list:
        raise R3ReservationError("spent-seed registry entries differ")
    spent = set(baseline_spent_seeds)
    for ordinal, entry in enumerate(entries, start=1):
        if type(entry) is not dict or entry.get("sequence") != ordinal:
            raise R3ReservationError("spent-seed registry sequence differs")
        seeds = entry.get("reserved_seeds")
        if type(seeds) is not list or any(type(seed) is not int for seed in seeds):
            raise R3ReservationError("spent-seed registry seed list differs")
        if spent.intersection(seeds):
            raise R3ReservationError("spent-seed registry contains duplicate seeds")
        spent.update(seeds)
    return spent


def _validate_registry_predecessor(
    *,
    raw: bytes,
    registry: Mapping[str, Any],
    predecessor: Mapping[str, Any],
    globally_spent_seed_count: int,
    runtime: RuntimeBindings,
    selected: tuple[int, ...],
) -> None:
    unsigned = dict(registry)
    stored_self = unsigned.pop("registry_sha256", None)
    entries = registry.get("entries")
    if (
        _sha256(raw) != predecessor["raw_sha256"]
        or stored_self != predecessor["registry_self_sha256"]
        or stored_self != _semantic_sha256(unsigned)
        or type(entries) is not list
        or len(entries) != predecessor["entry_count"]
        or not entries
        or type(entries[-1]) is not dict
        or entries[-1].get("entry_sha256") != predecessor["last_entry_sha256"]
    ):
        raise R3ReservationError("spent-seed registry predecessor chain differs")
    spent = _registry_seed_set(
        registry, baseline_spent_seeds=runtime.baseline_spent_seeds
    )
    if (
        len(spent) != globally_spent_seed_count
        or max(spent) != predecessor["maximum_reserved_seed"]
        or set(selected).intersection(spent)
    ):
        raise R3ReservationError("R3 allocation overlaps the predecessor registry")


def _producer_alignment(
    *,
    runtime: RuntimeBindings,
    run_id: str,
    precommit: PinnedJson,
    r2_terminal: PinnedJson,
    predecessor: Mapping[str, Any],
    quarantine: tuple[int, ...],
    heldout: tuple[int, ...],
    commitment: str,
) -> None:
    if (
        runtime.safe_run_id(run_id) != run_id
        or not run_id.startswith("r3_")
        or runtime.precommit_relative_path != precommit.relative_path
        or runtime.precommit_raw_sha256 != precommit.raw_sha256
        or runtime.r2_terminal_relative_path != r2_terminal.relative_path
        or runtime.r2_terminal_raw_sha256 != r2_terminal.raw_sha256
        or runtime.registry_relative_path != predecessor["relative_path"]
        or runtime.registry_before_raw_sha256 != predecessor["raw_sha256"]
        or runtime.registry_before_entry_count != predecessor["entry_count"]
        or runtime.registry_previous_entry_sha256 != predecessor["last_entry_sha256"]
        or runtime.quarantine_seeds != quarantine
        or runtime.heldout_seeds != heldout
        or runtime.heldout_seed_commitment_sha256 != commitment
        or ".r3_" not in runtime.protocol_schema
        or "R3" not in runtime.protocol_status
    ):
        raise R3ReservationError("producer/protocol source is not exactly migrated to R3")


def _gate_binding(gate: PinnedJson) -> dict[str, object]:
    return {
        "relative_path": gate.relative_path,
        "raw_sha256": gate.raw_sha256,
        "status": gate.value["status"],
        "reserved_generator_invocation_count": 0,
        "truth_leakage_count": 0,
        "heldout_access_count": 0,
        "score_open_count": 0,
        "registry_mutation_count": 0,
    }


def _protocol_binding(
    plan: ReservationPlan,
    *,
    receipt: Mapping[str, object],
    transition: Mapping[str, object],
) -> dict[str, object]:
    precommit = plan.precommit.value
    return {
        # These legacy wire field names intentionally remain stable in R3.
        "r1_terminal_failure": {
            "relative_path": plan.r2_terminal.relative_path,
            "raw_sha256": plan.r2_terminal.raw_sha256,
        },
        "replacement_seed_precommit": {
            "relative_path": plan.precommit.relative_path,
            "raw_sha256": plan.precommit.raw_sha256,
        },
        "final_nonreserved_preflight": _gate_binding(plan.rehearsal_gate),
        "quarantine_seeds_never_generate_or_score": list(
            precommit["quarantine_seeds_never_generate_or_score"]
        ),
        "heldout_seeds_in_order": list(precommit["heldout_seeds_in_order"]),
        "heldout_seed_commitment_sha256": precommit[
            "heldout_seed_commitment_sha256"
        ],
        "reservation_contract": dict(plan.reservation_contract),
        "spent_seed_reservation": dict(receipt),
        "registry_transition": dict(transition),
        # Preserve the frozen four-key legacy wire.  The R3-only rehearsal
        # overlap is independently required to be zero before this projection.
        "overlap_audit": {
            "prior_spent_overlap_count": precommit["overlap_audit"][
                "prior_spent_overlap_count"
            ],
            "r1_heldout_overlap_count": precommit["overlap_audit"][
                "r2_formal_seed_overlap_count"
            ],
            "qualification_seed_overlap_count": precommit["overlap_audit"][
                "qualification_seed_overlap_count"
            ],
            "within_allocation_duplicate_count": precommit["overlap_audit"][
                "within_allocation_duplicate_count"
            ],
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


def _provisional_transition(plan: ReservationPlan) -> tuple[dict[str, object], dict[str, object]]:
    runtime = plan.runtime
    marker = _semantic_sha256(
        {"r3_preappend_protocol_validation": dict(plan.reservation_contract)}
    )
    after_marker = _semantic_sha256({"registry_after_prevalidation": marker})
    receipt = {
        "format_version": runtime.registry_format_version,
        "registry_id": runtime.registry_id,
        "registry_path": str(plan.registry_path.resolve()),
        "genesis_sha256": plan.registry_before["genesis_sha256"],
        "reservation_id": runtime.reservation_id(plan.reservation_contract),
        "reservation_sequence": runtime.registry_before_entry_count + 1,
        "reservation_entry_sha256": marker,
    }
    transition = {
        "registry_relative_path": runtime.registry_relative_path,
        "registry_before_raw_sha256": runtime.registry_before_raw_sha256,
        "registry_after_raw_sha256": after_marker,
        "entry_count_before": runtime.registry_before_entry_count,
        "entry_count_after": runtime.registry_before_entry_count + 1,
        "append_count": 1,
        "previous_entry_sha256": runtime.registry_previous_entry_sha256,
        "reservation_entry_sha256": marker,
        "reservation_created_at_utc": "PREAPPEND_PROTOCOL_VALIDATION",
    }
    return receipt, transition


def _validate_planned_protocol_shape(
    plan: ReservationPlan,
    *,
    receipt: Mapping[str, object],
    transition: Mapping[str, object],
) -> Mapping[str, object]:
    runtime = plan.runtime
    binding = _protocol_binding(plan, receipt=receipt, transition=transition)
    try:
        lock = runtime.build_protocol_lock(
            run_id=plan.run_id,
            r2_protocol_binding=binding,
        )
        validated = runtime.validate_protocol_lock(
            lock,
            expected_run_id=plan.run_id,
            project_root=plan.project_root,
            expected_lock_relative_path=plan.lock_path.relative_to(
                plan.project_root
            ).as_posix(),
        )
    except Exception as exc:
        raise R3ReservationError(
            "migrated legacy-wire protocol rejects the R3 reservation binding"
        ) from exc
    if (
        validated != lock
        or lock.get("schema_version") != runtime.protocol_schema
        or lock.get("status") != runtime.protocol_status
        or lock.get("run_id") != plan.run_id
        or lock.get("r2_protocol_binding") != binding
    ):
        raise R3ReservationError("planned legacy-wire R3 protocol lock differs")
    return lock


def build_reservation_plan(
    *,
    project_root: Path,
    run_id: str,
    seed_precommit: Path,
    seed_precommit_raw_sha256: str,
    independent_audit: Path,
    independent_audit_raw_sha256: str,
    rehearsal_gate: Path,
    rehearsal_gate_raw_sha256: str,
    runtime: RuntimeBindings,
) -> ReservationPlan:
    """Build a complete read-only plan from pinned artifacts and live predecessor."""

    project = project_root.resolve(strict=True)
    run = runtime.safe_run_id(run_id)
    if run != run_id or not run.startswith("r3_"):
        raise R3ReservationError("R3 reservation run identity differs")
    precommit = _read_pinned_json(
        project,
        seed_precommit,
        seed_precommit_raw_sha256,
        label="R3 seed precommit",
    )
    if (
        precommit.relative_path != runtime.precommit_relative_path
        or precommit.raw_sha256 != runtime.precommit_raw_sha256
    ):
        raise R3ReservationError("CLI precommit pin differs from migrated producer")
    audit = _read_pinned_json(
        project,
        independent_audit,
        independent_audit_raw_sha256,
        label="R3 independent reservation audit",
    )
    if (
        audit.relative_path != runtime.independent_audit_relative_path
        or audit.raw_sha256 != runtime.independent_audit_raw_sha256
    ):
        raise R3ReservationError("CLI independent audit pin differs")
    policy_relative = _relative(
        precommit.value.get("value_free_policy_relative_path"),
        label="R3 value-free policy path",
    )
    policy_raw = _hash(
        precommit.value.get("value_free_policy_raw_sha256"),
        label="R3 value-free policy raw SHA-256",
    )
    policy = _read_pinned_json(
        project, Path(policy_relative), policy_raw, label="R3 value-free policy"
    )
    gate = _read_pinned_json(
        project,
        rehearsal_gate,
        rehearsal_gate_raw_sha256,
        label="R3 full rehearsal gate",
    )
    predecessor, fixture_seeds = _validate_value_free_policy(
        policy,
        run_id=run,
        rehearsal_gate=gate,
        project_root=project,
    )
    pre_derivation_gate = _read_pre_derivation_gate(
        project_root=project,
        precommit=precommit,
    )
    quarantine, heldout = _validate_precommit(
        precommit,
        policy=policy,
        run_id=run,
        predecessor=predecessor,
    )
    terminal_ref = policy.value["authority_inputs"]["r2_terminal_prediction"]
    terminal = _read_pinned_json(
        project,
        Path(terminal_ref["relative_path"]),
        terminal_ref["raw_sha256"],
        label="terminal R2 prediction evidence",
    )
    _validate_r2_terminal(terminal)
    _validate_pre_derivation_gate(
        pre_derivation_gate,
        run_id=run,
        policy=policy,
        rehearsal_gate=gate,
        r2_terminal=terminal,
        predecessor=predecessor,
        model_ids_in_order=runtime.model_ids_in_order,
        formula_lock_semantic_sha256=runtime.semantic_sha256(runtime.formula_lock),
    )
    _validate_rehearsal_gate(
        gate,
        predecessor=predecessor,
        fixture_seeds=fixture_seeds,
        model_ids_in_order=runtime.model_ids_in_order,
    )
    _validate_independent_audit(
        audit,
        project_root=project,
        run_id=run,
        precommit=precommit,
        pre_derivation_gate=pre_derivation_gate,
        policy=policy,
        rehearsal_gate=gate,
        r2_terminal=terminal,
        predecessor=predecessor,
        quarantine=quarantine,
        heldout=heldout,
        rehearsal_fixture_seeds=fixture_seeds,
        baseline_spent_seed_count=len(runtime.baseline_spent_seeds),
    )
    _producer_alignment(
        runtime=runtime,
        run_id=run,
        precommit=precommit,
        r2_terminal=terminal,
        predecessor=predecessor,
        quarantine=quarantine,
        heldout=heldout,
        commitment=precommit.value["heldout_seed_commitment_sha256"],
    )

    registry_relative = _relative(
        predecessor["relative_path"], label="spent-seed registry path"
    )
    registry_path = _project_file(project, registry_relative)
    registry_before_raw = registry_path.read_bytes()
    if _sha256(registry_before_raw) != predecessor["raw_sha256"]:
        raise R3ReservationError("spent-seed registry is not the pinned predecessor")
    try:
        registry_before = runtime.read_registry(registry_path)
    except Exception as exc:
        raise R3ReservationError("spent-seed registry validation failed") from exc
    selected = (*quarantine, *heldout)
    _validate_registry_predecessor(
        raw=registry_before_raw,
        registry=registry_before,
        predecessor=predecessor,
        globally_spent_seed_count=precommit.value["registry_before"][
            "globally_spent_seed_count"
        ],
        runtime=runtime,
        selected=selected,
    )

    try:
        source_manifest = runtime.build_source_manifest(
            **runtime.source_manifest_inputs(project)
        )
        generation = runtime.generation_plan()
    except Exception as exc:
        raise R3ReservationError("live producer source/generation closure failed") from exc
    if (
        generation.get("heldout_seeds_in_order") != list(heldout)
        or generation.get("estimator_rng_seeds_in_order") != list(heldout)
        or generation.get("task_count") != 50
        or generation.get("identity_count") != 64_800
        or generation.get("prediction_row_count") != 259_200
    ):
        raise R3ReservationError("live producer generation plan differs from precommit")
    candidate_config = {
        "model_ids_in_order": list(runtime.model_ids_in_order),
        "survivor_ids_in_qualification_rank_order": list(runtime.survivor_ids_in_order),
        "source_model_versions": dict(runtime.source_model_versions),
        "formula_lock": dict(runtime.formula_lock),
        "formula_lock_semantic_sha256": runtime.semantic_sha256(runtime.formula_lock),
        "generation_plan": dict(generation),
    }
    policy_config = {
        "schema_version": "expected_pe.four_model.r3_reservation_policy.v1",
        "run_id": run,
        "value_free_policy_raw_sha256": policy.raw_sha256,
        "seed_precommit_raw_sha256": precommit.raw_sha256,
        "independent_audit_ref": {
            "relative_path": audit.relative_path,
            "raw_sha256": audit.raw_sha256,
            "status": audit.value["status"],
            "audit_semantic_sha256": audit.value["audit_semantic_sha256"],
        },
        "rehearsal_gate_raw_sha256": gate.raw_sha256,
        "r2_terminal_raw_sha256": terminal.raw_sha256,
        "quarantine_seeds_never_generate_or_score": list(quarantine),
        "heldout_seeds_in_order": list(heldout),
        "heldout_seed_commitment_sha256": precommit.value[
            "heldout_seed_commitment_sha256"
        ],
        "candidate_performance_consulted": False,
        "heldout_truth_consulted": False,
        "additional_recovery_reservation_allowed": False,
        "retry_allowed": False,
    }
    output_root = runtime.require_managed_output_root(
        project / "outputs" / f"{runtime.protocol_root_prefix}{run}"
    )
    if output_root.exists():
        raise R3ReservationError("R3 reservation output root already exists")
    lock_path = output_root / runtime.protocol_leaf
    contract = {
        "format_version": runtime.registry_format_version,
        "registry_id": runtime.registry_id,
        "owner_output_root": runtime.canonical_output_root(output_root),
        "source_config_sha256": str(
            source_manifest["source_manifest_semantic_sha256"]
        ),
        "candidates_sha256": runtime.semantic_sha256(candidate_config),
        "policy_config_sha256": runtime.semantic_sha256(policy_config),
        "tuning_seeds": list(quarantine),
        "locked_seeds": list(heldout),
        "reserved_seeds": sorted(selected),
    }
    try:
        runtime.verify_reservation_contract(contract)
    except Exception as exc:
        raise R3ReservationError("R3 registry reservation contract differs") from exc

    report = {
        "schema_version": "expected_pe.four_model.r3_reservation_plan.v1",
        "status": "PASS_R3_RESERVATION_DRY_RUN_NO_MUTATION",
        "run_id": run,
        "precommit_ref": {
            "relative_path": precommit.relative_path,
            "raw_sha256": precommit.raw_sha256,
        },
        "value_free_policy_ref": {
            "relative_path": policy.relative_path,
            "raw_sha256": policy.raw_sha256,
        },
        "pre_derivation_gate_ref": {
            "relative_path": pre_derivation_gate.relative_path,
            "raw_sha256": pre_derivation_gate.raw_sha256,
        },
        "independent_audit_ref": {
            "relative_path": audit.relative_path,
            "raw_sha256": audit.raw_sha256,
            "status": audit.value["status"],
            "audit_semantic_sha256": audit.value["audit_semantic_sha256"],
        },
        "rehearsal_gate_ref": {
            "relative_path": gate.relative_path,
            "raw_sha256": gate.raw_sha256,
        },
        "r2_terminal_ref": {
            "relative_path": terminal.relative_path,
            "raw_sha256": terminal.raw_sha256,
        },
        "registry_relative_path": registry_relative,
        "registry_before_raw_sha256": _sha256(registry_before_raw),
        "registry_entry_count_before": len(registry_before["entries"]),
        "new_reserved_seed_count": 10,
        "compatibility_quarantine_count": 5,
        "formal_heldout_count": 5,
        "heldout_seed_commitment_sha256": precommit.value[
            "heldout_seed_commitment_sha256"
        ],
        "reservation_id": runtime.reservation_id(contract),
        "policy_config_sha256": contract["policy_config_sha256"],
        "protocol_lock_relative_path": lock_path.relative_to(project).as_posix(),
        "planned_registry_append_count": 1,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    plan = ReservationPlan(
        project_root=project,
        run_id=run,
        runtime=runtime,
        precommit=precommit,
        pre_derivation_gate=pre_derivation_gate,
        independent_audit=audit,
        policy=policy,
        rehearsal_gate=gate,
        r2_terminal=terminal,
        registry_path=registry_path,
        registry_before_raw=registry_before_raw,
        registry_before=registry_before,
        source_manifest=source_manifest,
        output_root=output_root,
        lock_path=lock_path,
        reservation_contract=contract,
        report=report,
    )
    receipt, transition = _provisional_transition(plan)
    _validate_planned_protocol_shape(plan, receipt=receipt, transition=transition)
    return plan


def _registry_bytes(runtime: RuntimeBindings, value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                runtime.registry_jsonable(value),
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise R3ReservationError("planned registry JSON differs") from exc


def _prepare_exact_append(
    plan: ReservationPlan, registry: Mapping[str, Any]
) -> tuple[Mapping[str, Any], bytes, Mapping[str, object], Mapping[str, object]]:
    runtime = plan.runtime
    runtime.verify_reservation_contract(plan.reservation_contract)
    reservation_id = runtime.reservation_id(plan.reservation_contract)
    entries = registry.get("entries")
    if type(entries) is not list or len(entries) != runtime.registry_before_entry_count:
        raise R3ReservationError("locked registry predecessor count differs")
    owner = plan.reservation_contract["owner_output_root"]
    for entry in entries:
        existing = runtime.reservation_contract_from_entry(entry)
        if entry.get("reservation_id") == reservation_id or existing.get(
            "owner_output_root"
        ) == owner:
            raise R3ReservationError("R3 reservation already exists; retry/no-op forbidden")
    spent = _registry_seed_set(
        registry, baseline_spent_seeds=runtime.baseline_spent_seeds
    )
    reserved = set(plan.reservation_contract["reserved_seeds"])
    if spent.intersection(reserved):
        raise R3ReservationError("R3 reservation reuses spent evidence")
    created_at = runtime.utc_now()
    entry = runtime.seal_payload(
        {
            **dict(plan.reservation_contract),
            "sequence": len(entries) + 1,
            "previous_entry_sha256": runtime.registry_previous_entry_sha256,
            "reservation_id": reservation_id,
            "created_at_utc": created_at,
        },
        "entry_sha256",
    )
    updated = copy.deepcopy(dict(registry))
    updated["entries"].append(entry)
    updated["updated_at_utc"] = runtime.utc_now()
    updated = runtime.seal_payload(updated, "registry_sha256")
    runtime.verify_registry(updated)
    updated_raw = _registry_bytes(runtime, updated)
    receipt = {
        "format_version": runtime.registry_format_version,
        "registry_id": runtime.registry_id,
        "registry_path": str(plan.registry_path.resolve()),
        "genesis_sha256": registry["genesis_sha256"],
        "reservation_id": reservation_id,
        "reservation_sequence": len(entries) + 1,
        "reservation_entry_sha256": entry["entry_sha256"],
    }
    transition = {
        "registry_relative_path": runtime.registry_relative_path,
        "registry_before_raw_sha256": runtime.registry_before_raw_sha256,
        "registry_after_raw_sha256": _sha256(updated_raw),
        "entry_count_before": len(entries),
        "entry_count_after": len(entries) + 1,
        "append_count": 1,
        "previous_entry_sha256": entry["previous_entry_sha256"],
        "reservation_entry_sha256": entry["entry_sha256"],
        "reservation_created_at_utc": entry["created_at_utc"],
    }
    return updated, updated_raw, receipt, transition


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o444,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise R3ReservationError("protocol lock write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_reservation_plan(plan: ReservationPlan) -> Mapping[str, object]:
    """CAS the exact predecessor to one append and create one protocol lock."""

    fresh = build_reservation_plan(
        project_root=plan.project_root,
        run_id=plan.run_id,
        seed_precommit=Path(plan.precommit.relative_path),
        seed_precommit_raw_sha256=plan.precommit.raw_sha256,
        independent_audit=Path(plan.independent_audit.relative_path),
        independent_audit_raw_sha256=plan.independent_audit.raw_sha256,
        rehearsal_gate=Path(plan.rehearsal_gate.relative_path),
        rehearsal_gate_raw_sha256=plan.rehearsal_gate.raw_sha256,
        runtime=plan.runtime,
    )
    if (
        fresh.registry_before_raw != plan.registry_before_raw
        or fresh.reservation_contract != plan.reservation_contract
        or fresh.report != plan.report
    ):
        raise R3ReservationError("R3 reservation plan drifted before apply")
    plan.output_root.mkdir(exist_ok=False)
    descriptor: int | None = None
    registry_lock_path: Path | None = None
    try:
        descriptor, registry_lock_path = plan.runtime.acquire_registry_lock(
            plan.registry_path
        )
        locked_raw = plan.registry_path.read_bytes()
        if locked_raw != plan.registry_before_raw:
            raise R3ReservationError("registry predecessor changed before locked append")
        locked_registry = plan.runtime.read_registry(plan.registry_path)
        _validate_registry_predecessor(
            raw=locked_raw,
            registry=locked_registry,
            predecessor=plan.precommit.value["registry_before"],
            globally_spent_seed_count=plan.precommit.value["registry_before"][
                "globally_spent_seed_count"
            ],
            runtime=plan.runtime,
            selected=tuple(plan.reservation_contract["reserved_seeds"]),
        )
        updated, updated_raw, receipt, transition = _prepare_exact_append(
            plan, locked_registry
        )
        protocol_lock = _validate_planned_protocol_shape(
            plan,
            receipt=receipt,
            transition=transition,
        )
        lock_raw = plan.runtime.canonical_pretty_bytes(protocol_lock)

        plan.runtime.atomic_write_registry(plan.registry_path, updated)
        if plan.registry_path.read_bytes() != updated_raw:
            raise R3ReservationError("single registry append bytes differ")
        reread_registry = plan.runtime.read_registry(plan.registry_path)
        if reread_registry != updated or len(reread_registry["entries"]) != len(
            locked_registry["entries"]
        ) + 1:
            raise R3ReservationError("single registry append verification failed")
        _write_new(plan.lock_path, lock_raw)
        reread_lock = plan.runtime.read_protocol_lock(
            plan.lock_path,
            project_root=plan.project_root,
            expected_run_id=plan.run_id,
            expected_raw_sha256=_sha256(lock_raw),
        )
        if reread_lock != protocol_lock:
            raise R3ReservationError("legacy-wire R3 protocol lock round-trip differs")
        source_after = plan.runtime.build_source_manifest(
            **plan.runtime.source_manifest_inputs(plan.project_root)
        )
        if source_after != plan.source_manifest:
            raise R3ReservationError("producer source changed across R3 reservation")
        if {path.name for path in plan.output_root.iterdir()} != {
            plan.runtime.protocol_leaf
        }:
            raise R3ReservationError("R3 reservation output file universe differs")
        return {
            **plan.report,
            "status": "FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH",
            "registry_after_raw_sha256": _sha256(updated_raw),
            "registry_after_self_sha256": updated["registry_sha256"],
            "registry_entry_count_after": len(updated["entries"]),
            "reservation_entry_sha256": receipt["reservation_entry_sha256"],
            "protocol_lock_raw_sha256": _sha256(lock_raw),
            "protocol_lock_semantic_sha256": protocol_lock[
                "r2_protocol_binding_semantic_sha256"
            ],
            "registry_append_count": 1,
        }
    finally:
        if descriptor is not None and registry_lock_path is not None:
            plan.runtime.release_registry_lock(descriptor, registry_lock_path)


def _load_runtime() -> RuntimeBindings:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import contracts
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
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
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
        r2_protocol_lock,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.source_inventory import (
        source_manifest_inputs,
    )
    from scripts import run_v04_multiseed_validation as registry

    return RuntimeBindings(
        canonical_pretty_bytes=canonical_pretty_bytes,
        semantic_sha256=semantic_sha256,
        safe_run_id=safe_run_id,
        heldout_seeds=tuple(contracts.HELDOUT_SEEDS),
        quarantine_seeds=tuple(contracts.R2_QUARANTINE_SEEDS),
        heldout_seed_commitment_sha256=contracts.R2_HELDOUT_SEED_COMMITMENT_SHA256,
        precommit_relative_path=contracts.R2_REPLACEMENT_SEED_PRECOMMIT_RELATIVE_PATH,
        precommit_raw_sha256=contracts.R2_REPLACEMENT_SEED_PRECOMMIT_RAW_SHA256,
        independent_audit_relative_path=contracts.R3_INDEPENDENT_AUDIT_RELATIVE_PATH,
        independent_audit_raw_sha256=contracts.R3_INDEPENDENT_AUDIT_RAW_SHA256,
        r2_terminal_relative_path=contracts.R2_R1_TERMINAL_FAILURE_RELATIVE_PATH,
        r2_terminal_raw_sha256=contracts.R2_R1_TERMINAL_FAILURE_RAW_SHA256,
        registry_relative_path=contracts.R2_SPENT_SEED_REGISTRY_RELATIVE_PATH,
        registry_before_raw_sha256=contracts.R2_SPENT_SEED_REGISTRY_BEFORE_RAW_SHA256,
        registry_before_entry_count=contracts.R2_SPENT_SEED_REGISTRY_BEFORE_ENTRY_COUNT,
        registry_previous_entry_sha256=contracts.R2_SPENT_SEED_REGISTRY_PREVIOUS_ENTRY_SHA256,
        protocol_schema=contracts.R2_PROTOCOL_LOCK_SCHEMA,
        protocol_status=contracts.R2_PROTOCOL_LOCK_STATUS,
        protocol_root_prefix=contracts.R2_PROTOCOL_LOCK_ROOT_PREFIX,
        protocol_leaf=contracts.R2_PROTOCOL_LOCK_LEAF,
        model_ids_in_order=tuple(contracts.MODEL_IDS_IN_ORDER),
        survivor_ids_in_order=tuple(
            contracts.SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER
        ),
        source_model_versions=dict(contracts.SOURCE_MODEL_VERSIONS),
        formula_lock=dict(contracts.FORMULA_LOCK),
        build_source_manifest=build_source_manifest,
        source_manifest_inputs=source_manifest_inputs,
        generation_plan=generation_plan,
        build_protocol_lock=r2_protocol_lock.build_r2_protocol_lock,
        validate_protocol_lock=r2_protocol_lock.validate_r2_protocol_lock,
        read_protocol_lock=r2_protocol_lock.read_r2_protocol_lock,
        registry_format_version=registry.SPENT_SEED_REGISTRY_FORMAT_VERSION,
        registry_id=registry.SPENT_SEED_REGISTRY_ID,
        canonical_output_root=registry._canonical_output_root,
        require_managed_output_root=registry._require_managed_output_root,
        read_registry=registry._read_spent_seed_registry,
        reservation_contract_from_entry=registry._reservation_contract_from_entry,
        reservation_id=registry._reservation_id,
        acquire_registry_lock=registry._acquire_spent_registry_lock,
        release_registry_lock=registry._release_spent_registry_lock,
        verify_reservation_contract=registry._verify_reservation_contract,
        verify_registry=registry._verify_spent_seed_registry,
        seal_payload=registry._seal_payload,
        utc_now=registry._utc_now,
        atomic_write_registry=registry._atomic_write_json,
        registry_jsonable=registry._jsonable,
        baseline_spent_seeds=tuple(registry.SPENT_EVIDENCE_SEEDS),
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Dry-run or apply one precommitted R3 seed reservation"
    )
    result.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    result.add_argument("--run-id", required=True)
    result.add_argument("--seed-precommit", type=Path, required=True)
    result.add_argument("--seed-precommit-raw-sha256", required=True)
    result.add_argument("--independent-audit", type=Path, required=True)
    result.add_argument("--independent-audit-raw-sha256", required=True)
    result.add_argument("--rehearsal-gate", type=Path, required=True)
    result.add_argument("--rehearsal-gate-raw-sha256", required=True)
    result.add_argument(
        "--apply",
        action="store_true",
        help="perform the exact one registry append and create-new protocol lock",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    _bootstrap()
    try:
        plan = build_reservation_plan(
            project_root=arguments.repository_root,
            run_id=arguments.run_id,
            seed_precommit=arguments.seed_precommit,
            seed_precommit_raw_sha256=arguments.seed_precommit_raw_sha256,
            independent_audit=arguments.independent_audit,
            independent_audit_raw_sha256=arguments.independent_audit_raw_sha256,
            rehearsal_gate=arguments.rehearsal_gate,
            rehearsal_gate_raw_sha256=arguments.rehearsal_gate_raw_sha256,
            runtime=_load_runtime(),
        )
        report = apply_reservation_plan(plan) if arguments.apply else plan.report
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except R3ReservationError as exc:
        raise SystemExit(f"R3 reservation rejected: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
