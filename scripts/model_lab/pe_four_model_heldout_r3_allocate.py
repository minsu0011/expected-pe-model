"""Derive and freeze the R3 seed allocation after its value-free policy is sealed."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_RELATIVE = "build/pe_four_model_heldout_seed_selection_policy_r3_20260824T134417.json"
POLICY_RAW_SHA256 = "00fe549114f24e5cc942358100ed3772457eb0aa9abcd8b83bd7767570bed55d"
DERIVATION_GATE_RELATIVE = (
    "build/pe_four_model_heldout_r3_pre_derivation_gate_r3_20260824T134417.json"
)
DERIVATION_GATE_RAW_SHA256 = "b83903344a01dd59c48527368517405d5e70592fc2d82f726a39154caabf3e98"
REGISTRY_RELATIVE = "outputs/v04_spent_seed_registry.json"
REGISTRY_BEFORE_RAW_SHA256 = "a8658fd084c8786212e4560459df4c83f6f2ed44f8365670c290dfe4fcfb20ec"
REGISTRY_BEFORE_SELF_SHA256 = "2678b6de5be0779079e11cdfc69a3c0ffc6b9fc68b312b97d5c490c3ea6aa533"
REGISTRY_BEFORE_ENTRY_COUNT = 11
REGISTRY_BEFORE_LAST_ENTRY_SHA256 = (
    "b369ddf802b08927501e218843f37677dfedfc7299b576e146ceae3242cd5c94"
)
REGISTRY_BEFORE_MAXIMUM_RESERVED_SEED = 7723
REGISTRY_VALIDATION_SOURCE_RELATIVE = "scripts/run_v04_multiseed_validation.py"
REGISTRY_VALIDATION_SOURCE_RAW_SHA256 = (
    "c37082831c8df78bf0a0d11a34d9c556fa7ccbf9cc2a254df7a7ca005293b1c9"
)
FULL_SPENT_SEED_COUNT = 136
RUN_ID = "r3_20260824T134417"
OUTPUT_RELATIVE = "build/pe_four_model_heldout_seed_precommit_r3_20260824T134417.json"
R2_FORMAL_SEEDS = (7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723)
QUALIFICATION_SEEDS = (7573, 7577, 7583, 7589, 7591)
REHEARSAL_FIXTURE_SEEDS = (9_900_001, 9_900_002, 9_900_003, 9_900_004, 9_900_005)


class R3AllocationError(RuntimeError):
    """Fail-closed error before the R3 registry append."""


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _semantic_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return _raw_sha256(raw)


def _canonical_pretty_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise R3AllocationError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                R3AllocationError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3AllocationError(f"invalid JSON in {label}") from exc
    if type(value) is not dict:
        raise R3AllocationError(f"{label} is not an object")
    return value


def _is_prime(value: int) -> bool:
    if type(value) is not int or value <= 1:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False
    limit = math.isqrt(value)
    return all(value % divisor for divisor in range(3, limit + 1, 2))


def _baseline_spent_seeds() -> set[int]:
    source_path = (PROJECT_ROOT / REGISTRY_VALIDATION_SOURCE_RELATIVE).resolve(strict=True)
    source_raw = source_path.read_bytes()
    if _raw_sha256(source_raw) != REGISTRY_VALIDATION_SOURCE_RAW_SHA256:
        raise R3AllocationError("spent-seed validation source hash differs")
    try:
        tree = ast.parse(source_raw.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise R3AllocationError("spent-seed validation source is invalid") from exc
    values: list[object] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "SPENT_EVIDENCE_SEEDS"
            for target in node.targets
        ):
            values.append(ast.literal_eval(node.value))
    if len(values) != 1 or type(values[0]) is not tuple:
        raise R3AllocationError("baseline spent-seed source binding differs")
    seeds = values[0]
    if (
        any(type(seed) is not int or seed < 0 for seed in seeds)
        or len(seeds) != len(set(seeds))
        or not seeds
    ):
        raise R3AllocationError("baseline spent-seed values differ")
    return set(seeds)


def _registry_spent_seeds(registry: Mapping[str, object]) -> set[int]:
    entries = registry.get("entries")
    if type(entries) is not list:
        raise R3AllocationError("registry entries differ")
    spent = _baseline_spent_seeds()
    for ordinal, entry in enumerate(entries, start=1):
        if type(entry) is not dict or entry.get("sequence") != ordinal:
            raise R3AllocationError("registry entry sequence differs")
        seeds = entry.get("reserved_seeds")
        if type(seeds) is not list or any(type(seed) is not int for seed in seeds):
            raise R3AllocationError("registry reserved seed list differs")
        if spent.intersection(seeds):
            raise R3AllocationError("registry contains duplicate reserved seeds")
        spent.update(seeds)
    return spent


def _validate_policy(policy: Mapping[str, object]) -> None:
    authority = policy.get("authority_inputs")
    predecessor = (
        authority.get("spent_seed_registry_predecessor") if type(authority) is dict else None
    )
    roles = policy.get("allocation_role_policy")
    independence = policy.get("candidate_and_evidence_independence")
    execution = policy.get("formal_execution_policy")
    rule = policy.get("selection_rule")
    if (
        policy.get("schema_version")
        != "expected_pe.four_model.r3_value_free_seed_selection_policy.v1"
        or policy.get("status") != "FROZEN_BEFORE_NEW_SEED_VALUE_DERIVATION"
        or policy.get("run_id") != RUN_ID
        or policy.get("new_seed_values_present") is not False
        or type(predecessor) is not dict
        or predecessor.get("raw_sha256") != REGISTRY_BEFORE_RAW_SHA256
        or predecessor.get("registry_self_sha256") != REGISTRY_BEFORE_SELF_SHA256
        or predecessor.get("entry_count") != REGISTRY_BEFORE_ENTRY_COUNT
        or predecessor.get("last_entry_sha256") != REGISTRY_BEFORE_LAST_ENTRY_SHA256
        or predecessor.get("maximum_reserved_seed") != REGISTRY_BEFORE_MAXIMUM_RESERVED_SEED
        or type(roles) is not dict
        or roles.get("compatibility_quarantine_count") != 5
        or roles.get("formal_heldout_count") != 5
        or roles.get("new_reserved_seed_count") != 10
        or roles.get("compatibility_quarantine_generator_invocation_allowed") is not False
        or roles.get("compatibility_quarantine_scoring_allowed") is not False
        or type(independence) is not dict
        or any(value is not False for value in independence.values())
        or type(execution) is not dict
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
        or type(rule) is not dict
        or rule.get("tie_or_randomness") != "NONE_DETERMINISTIC_ASCENDING_INTEGER_SCAN"
        or rule.get("value_derivation_authorized_only_after_this_policy_raw_sha256_is_RECORDED")
        is not True
    ):
        raise R3AllocationError("frozen value-free seed policy differs")


def _validate_derivation_gate(gate: Mapping[str, object]) -> None:
    authority = gate.get("authority_bindings")
    policy_ref = authority.get("value_free_seed_policy") if type(authority) is dict else None
    registry_ref = (
        authority.get("spent_seed_registry_predecessor") if type(authority) is dict else None
    )
    blocked = gate.get("blocked_actions_until_later_reservation_gate")
    if (
        gate.get("schema_version") != "expected_pe.four_model.r3_pre_derivation_gate.v1"
        or gate.get("status") != "GO_DERIVE_AND_FREEZE_PRECOMMIT_ONLY_NO_REGISTRY_APPEND"
        or gate.get("run_id") != RUN_ID
        or gate.get("formal_seed_derivation_count_at_gate") != 0
        or gate.get("registry_mutation_count_at_gate") != 0
        or gate.get("truth_open_count_at_gate") != 0
        or type(policy_ref) is not dict
        or policy_ref.get("relative_path") != POLICY_RELATIVE
        or policy_ref.get("raw_sha256") != POLICY_RAW_SHA256
        or type(registry_ref) is not dict
        or registry_ref.get("relative_path") != REGISTRY_RELATIVE
        or registry_ref.get("raw_sha256") != REGISTRY_BEFORE_RAW_SHA256
        or type(blocked) is not list
        or "SPENT_SEED_REGISTRY_APPEND" not in blocked
        or "TRUTH_OPEN" not in blocked
        or "SCORING" not in blocked
    ):
        raise R3AllocationError("pre-derivation gate differs")


def build_precommit(
    *,
    policy: Mapping[str, object],
    derivation_gate: Mapping[str, object],
    registry: Mapping[str, object],
) -> dict[str, object]:
    """Derive the allocation mechanically from already-frozen public state."""

    _validate_policy(policy)
    _validate_derivation_gate(derivation_gate)
    unsigned_registry = dict(registry)
    stored_registry_sha = unsigned_registry.pop("registry_sha256", None)
    entries = registry.get("entries")
    if (
        stored_registry_sha != REGISTRY_BEFORE_SELF_SHA256
        or stored_registry_sha != _semantic_sha256(unsigned_registry)
        or type(entries) is not list
        or len(entries) != REGISTRY_BEFORE_ENTRY_COUNT
        or type(entries[-1]) is not dict
        or entries[-1].get("entry_sha256") != REGISTRY_BEFORE_LAST_ENTRY_SHA256
    ):
        raise R3AllocationError("spent-seed registry predecessor chain differs")
    spent = _registry_spent_seeds(registry)
    if len(spent) != FULL_SPENT_SEED_COUNT or max(spent) != REGISTRY_BEFORE_MAXIMUM_RESERVED_SEED:
        raise R3AllocationError("spent-seed registry maximum differs")

    excluded = spent.union(REHEARSAL_FIXTURE_SEEDS)
    selected: list[int] = []
    candidate = REGISTRY_BEFORE_MAXIMUM_RESERVED_SEED + 1
    while len(selected) < 10:
        if candidate not in excluded and _is_prime(candidate):
            selected.append(candidate)
        candidate += 1
    quarantine = selected[:5]
    heldout = selected[5:]
    commitment_payload = {"locked_seeds": heldout}
    overlap = {
        "prior_spent_overlap_count": len(set(selected).intersection(spent)),
        "qualification_seed_overlap_count": len(set(selected).intersection(QUALIFICATION_SEEDS)),
        "r2_formal_seed_overlap_count": len(set(selected).intersection(R2_FORMAL_SEEDS)),
        "rehearsal_fixture_overlap_count": len(set(selected).intersection(REHEARSAL_FIXTURE_SEEDS)),
        "within_allocation_duplicate_count": len(selected) - len(set(selected)),
    }
    if any(overlap.values()):
        raise R3AllocationError("derived R3 allocation overlaps excluded evidence")
    return {
        "deterministic_next_ten_primes": selected,
        "formal_execution_policy": {
            "additional_recovery_reservation_allowed": False,
            "exact_heldout_seed_count": 5,
            "post_result_seed_change_allowed": False,
            "quarantine_generator_invocation_allowed": False,
            "r2_seed_reuse_allowed": False,
            "seed_cherry_picking_allowed": False,
        },
        "heldout_seed_commitment_payload": commitment_payload,
        "heldout_seed_commitment_sha256": _semantic_sha256(commitment_payload),
        "heldout_seeds_in_order": heldout,
        "overlap_audit": overlap,
        "pre_derivation_gate": {
            "raw_sha256": DERIVATION_GATE_RAW_SHA256,
            "relative_path": DERIVATION_GATE_RELATIVE,
            "status": derivation_gate["status"],
        },
        "quarantine_seeds_never_generate_or_score": quarantine,
        "registry_before": {
            "entry_count": REGISTRY_BEFORE_ENTRY_COUNT,
            "globally_spent_seed_count": len(spent),
            "last_entry_sha256": REGISTRY_BEFORE_LAST_ENTRY_SHA256,
            "maximum_reserved_seed": REGISTRY_BEFORE_MAXIMUM_RESERVED_SEED,
            "raw_sha256": REGISTRY_BEFORE_RAW_SHA256,
            "registry_self_sha256": REGISTRY_BEFORE_SELF_SHA256,
            "relative_path": REGISTRY_RELATIVE,
        },
        "run_id": RUN_ID,
        "schema_version": "expected_pe.four_model.r3_seed_precommit.v1",
        "selection_rule": {
            "algorithm": policy["selection_rule"]["derivation"],
            "assignment": policy["selection_rule"]["assignment"],
            **dict(policy["candidate_and_evidence_independence"]),
        },
        "status": "FROZEN_PRE_RESERVATION_PERFORMANCE_INDEPENDENT_R3_ALLOCATION",
        "value_free_policy_raw_sha256": POLICY_RAW_SHA256,
        "value_free_policy_relative_path": POLICY_RELATIVE,
    }


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
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    policy_path = (PROJECT_ROOT / POLICY_RELATIVE).resolve(strict=True)
    policy_raw = policy_path.read_bytes()
    if _raw_sha256(policy_raw) != POLICY_RAW_SHA256:
        raise R3AllocationError("value-free policy raw SHA-256 differs")
    policy = _json_object(policy_raw, label="value-free seed policy")
    if _canonical_pretty_bytes(policy) != policy_raw:
        raise R3AllocationError("value-free seed policy canonical bytes differ")

    gate_path = (PROJECT_ROOT / DERIVATION_GATE_RELATIVE).resolve(strict=True)
    gate_raw = gate_path.read_bytes()
    if _raw_sha256(gate_raw) != DERIVATION_GATE_RAW_SHA256:
        raise R3AllocationError("pre-derivation gate raw SHA-256 differs")
    derivation_gate = _json_object(gate_raw, label="pre-derivation gate")
    if _canonical_pretty_bytes(derivation_gate) != gate_raw:
        raise R3AllocationError("pre-derivation gate canonical bytes differ")

    registry_path = (PROJECT_ROOT / REGISTRY_RELATIVE).resolve(strict=True)
    registry_raw = registry_path.read_bytes()
    if _raw_sha256(registry_raw) != REGISTRY_BEFORE_RAW_SHA256:
        raise R3AllocationError("spent-seed registry raw predecessor differs")
    registry = _json_object(registry_raw, label="spent-seed registry")
    precommit = build_precommit(
        policy=policy,
        derivation_gate=derivation_gate,
        registry=registry,
    )
    raw = _canonical_pretty_bytes(precommit)
    summary = {
        "heldout_seed_commitment_sha256": precommit["heldout_seed_commitment_sha256"],
        "heldout_seeds_in_order": precommit["heldout_seeds_in_order"],
        "output_relative_path": OUTPUT_RELATIVE,
        "precommit_raw_sha256": _raw_sha256(raw),
        "quarantine_seeds_never_generate_or_score": precommit[
            "quarantine_seeds_never_generate_or_score"
        ],
        "run_id": RUN_ID,
        "status": "DRY_RUN_DERIVED_NO_WRITE",
    }
    if not arguments.apply:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    output_path = (PROJECT_ROOT / OUTPUT_RELATIVE).resolve(strict=False)
    if output_path.parent != (PROJECT_ROOT / "build").resolve(strict=True):
        raise R3AllocationError("precommit output escaped fixed build root")
    _write_new(output_path, raw)
    reread = output_path.read_bytes()
    if reread != raw:
        raise R3AllocationError("precommit create-new round trip differs")
    print(
        json.dumps(
            {**summary, "status": "FROZEN_R3_SEED_PRECOMMIT_CREATE_NEW"},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
