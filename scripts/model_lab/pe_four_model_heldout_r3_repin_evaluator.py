"""Mechanically repin the frozen heldout evaluator to an R3 authority.

This helper deliberately lives outside the producer and evaluator source closures.
Its default mode is a read-only dry run; ``--apply`` is the only write authority.
The evaluator schema and its legacy ``R2_PROTOCOL_*`` wire names stay unchanged.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Final, Mapping, Sequence


sys.dont_write_bytecode = True

HELPER_ROOT: Final = Path(__file__).resolve().parent
if str(HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(HELPER_ROOT))

import pe_four_model_heldout_r2_repin_evaluator as _r2  # noqa: E402


PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
CONSTANTS_RELATIVE: Final = _r2.CONSTANTS_RELATIVE
SOURCE_LOCK_RELATIVE: Final = _r2.SOURCE_LOCK_RELATIVE
RUN_ONCE_RELATIVE: Final = _r2.RUN_ONCE_RELATIVE
EXPECTED_SOURCE_GROUP_COUNTS: Final = _r2.EXPECTED_SOURCE_GROUP_COUNTS
EXPECTED_SOURCE_RECORD_COUNT: Final = _r2.EXPECTED_SOURCE_RECORD_COUNT
EXPECTED_LAUNCHER_SOURCE_COUNT: Final = _r2.EXPECTED_LAUNCHER_SOURCE_COUNT
EVALUATOR_PACKAGE_RELATIVES: Final = _r2.EVALUATOR_PACKAGE_RELATIVES
EXPECTED_EVALUATOR_PACKAGE_FILE_COUNTS: Final = _r2.EXPECTED_EVALUATOR_PACKAGE_FILE_COUNTS
HEX64: Final = _r2.HEX64

# The evaluator v1 wire schema is frozen.  These names remain legacy aliases even
# when their values bind the new R3 reservation lock.
PROTOCOL_CONSTANT_NAMES: Final = (
    "R2_PROTOCOL_LOCK_RAW_SHA256",
    "R2_PROTOCOL_BINDING_SEMANTIC_SHA256",
)
SEED_CONSTANT_NAME: Final = "HELDOUT_SEEDS"
PLAN_CONSTANT_NAME: Final = "GENERATION_PLAN_SEMANTIC_SHA256"
REPINNED_CONSTANT_NAMES: Final = (
    *PROTOCOL_CONSTANT_NAMES,
    SEED_CONSTANT_NAME,
    PLAN_CONSTANT_NAME,
)

# Exact terminal R2 evaluator bindings.  A nonzero prior state is accepted only
# when all four values match this single frozen state; mixed/arbitrary values fail.
FROZEN_R2_PRIOR_BINDINGS: Final[dict[str, object]] = {
    "R2_PROTOCOL_LOCK_RAW_SHA256": (
        "5d480fc9161fe65c1d8aacd4c10e138ec5839c7b3048e5f22c14b303ca56d193"
    ),
    "R2_PROTOCOL_BINDING_SEMANTIC_SHA256": (
        "f82126d1f1b1aff53453e174771e6f7e35044484c5ca0e94bc145f2c0314a2f1"
    ),
    "HELDOUT_SEEDS": (7691, 7699, 7703, 7717, 7723),
    "GENERATION_PLAN_SEMANTIC_SHA256": (
        "722b3395202174a688d5d7f8083c1eccb81237834d9bfaa0e136ab1157076162"
    ),
}
FROZEN_R2_CONSTANTS_RAW_SHA256: Final = (
    "4c3181ca3e8dc07c90b2ed9617b15015f5f53753930dab31dd19fafd075a4abe"
)
FROZEN_R3_PRE_REPIN_CONSTANTS_RAW_SHA256: Final = (
    "3916e611f288c5d11b678d62a5dd3c121ec56e59ae91539a5337faa55cd1e393"
)
FROZEN_R2_SOURCE_LOCK_RAW_SHA256: Final = (
    "e6389379ab3ee0b55d346bf13ab4ed9f9a549ded90ca6d363f20794fee7ecd34"
)
FROZEN_R2_RUN_ONCE_RAW_SHA256: Final = (
    "df368926465ab92af73434c3c7105c22488c2faeec07fc8fb91d78b17ab74529"
)

EvaluatorRepinError = _r2.EvaluatorRepinError


@dataclass(frozen=True)
class RepinPlan:
    """Validated current bytes, future bytes, and an audit report."""

    project_root: Path
    authority_path: Path
    authority_raw_sha256: str
    current_bytes: Mapping[str, bytes]
    planned_bytes: Mapping[str, bytes]
    report: Mapping[str, object]


def _sha256(raw: bytes) -> str:
    return _r2._sha256(raw)


def _require_nonzero_hash(value: object, *, label: str) -> str:
    return _r2._require_nonzero_hash(value, label=label)


def _load_validated_execution_authority(
    *,
    project_root: Path,
    authority_path: Path,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    """Read a canonical, live-valid R3 execution authority without seed discovery."""

    expected_raw = _require_nonzero_hash(
        expected_raw_sha256, label="execution authority raw SHA-256"
    )
    project = project_root.resolve(strict=True)
    candidate = authority_path
    if not candidate.is_absolute():
        candidate = project / candidate
    candidate = candidate.resolve(strict=True)
    if project not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
        raise EvaluatorRepinError("execution authority escaped the project")
    raw, _ = _r2._read_exact_utf8(candidate, label="execution authority")
    if _sha256(raw) != expected_raw:
        raise EvaluatorRepinError("execution authority raw SHA-256 differs")
    parsed = _r2._strict_json_object(raw, label="execution authority")
    if _r2._canonical_pretty_bytes(parsed) != raw:
        raise EvaluatorRepinError("execution authority canonical bytes differ")
    run_id = parsed.get("run_id")
    if type(run_id) is not str or not run_id.startswith("r3_"):
        raise EvaluatorRepinError("execution authority is not a new R3 authority")
    expected_relative = f"build/pe_four_model_heldout_execution_authority_{run_id}.json"
    if candidate.relative_to(project).as_posix() != expected_relative:
        raise EvaluatorRepinError("execution authority path/run identity differs")

    project_text = str(project)
    if project_text not in sys.path:
        sys.path.insert(0, project_text)
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (  # noqa: E501
        read_execution_authority,
    )

    try:
        validated = read_execution_authority(
            candidate,
            project_root=project,
            expected_run_id=run_id,
            expected_raw_sha256=expected_raw,
        )
    except Exception as exc:
        raise EvaluatorRepinError("execution authority validation failed") from exc
    if validated != parsed:
        raise EvaluatorRepinError("validated execution authority bytes differ")

    protocol_raw = _require_nonzero_hash(
        validated.get("r2_protocol_lock_raw_sha256"),
        label="legacy R2 protocol wire raw SHA-256",
    )
    protocol_semantic = _require_nonzero_hash(
        validated.get("r2_protocol_binding_semantic_sha256"),
        label="legacy R2 protocol wire semantic SHA-256",
    )
    protocol = validated.get("r2_protocol_lock")
    if (
        type(protocol) is not dict
        or protocol.get("r2_protocol_binding_semantic_sha256") != protocol_semantic
        or _sha256(_r2._canonical_pretty_bytes(protocol)) != protocol_raw
    ):
        raise EvaluatorRepinError("R3 protocol authority legacy-wire binding differs")
    return validated


def _target_bindings_from_authority(
    authority: Mapping[str, object],
) -> dict[str, object]:
    """Extract the exact four evaluator bindings from one validated authority."""

    protocol_raw = _require_nonzero_hash(
        authority.get("r2_protocol_lock_raw_sha256"),
        label="R3 lock raw SHA-256",
    )
    protocol_semantic = _require_nonzero_hash(
        authority.get("r2_protocol_binding_semantic_sha256"),
        label="R3 lock binding semantic SHA-256",
    )
    plan_semantic = _require_nonzero_hash(
        authority.get("generation_plan_semantic_sha256"),
        label="R3 generation plan semantic SHA-256",
    )
    plan = authority.get("generation_plan")
    survivor = authority.get("survivor_freeze")
    if type(plan) is not dict or type(survivor) is not dict:
        raise EvaluatorRepinError("R3 authority plan/survivor payload differs")
    seed_values = plan.get("heldout_seeds_in_order")
    if (
        type(seed_values) is not list
        or len(seed_values) != 5
        or any(type(seed) is not int or seed <= 0 for seed in seed_values)
        or len(set(seed_values)) != 5
        or plan.get("estimator_rng_seeds_in_order") != seed_values
        or survivor.get("heldout_seeds_in_order") != seed_values
        or survivor.get("estimator_rng_seeds_in_order") != seed_values
        or plan.get("plan_semantic_sha256") != plan_semantic
        or plan.get("task_count") != 50
        or plan.get("identity_count") != 64_800
        or plan.get("prediction_row_count") != 259_200
    ):
        raise EvaluatorRepinError("R3 authority heldout seed/geometry binding differs")
    return {
        "R2_PROTOCOL_LOCK_RAW_SHA256": protocol_raw,
        "R2_PROTOCOL_BINDING_SEMANTIC_SHA256": protocol_semantic,
        "HELDOUT_SEEDS": tuple(seed_values),
        "GENERATION_PLAN_SEMANTIC_SHA256": plan_semantic,
    }


def _module_assignments(
    raw: bytes, names: Sequence[str]
) -> tuple[ast.Module, dict[str, ast.AnnAssign], dict[str, object]]:
    try:
        text = raw.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise EvaluatorRepinError("evaluator constants source differs") from exc
    requested = set(names)
    nodes: dict[str, ast.AnnAssign] = {}
    values: dict[str, object] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id in requested
        ):
            name = node.target.id
            if name in nodes or node.value is None:
                raise EvaluatorRepinError(f"duplicate evaluator binding: {name}")
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, SyntaxError) as exc:
                raise EvaluatorRepinError(f"evaluator binding is not literal: {name}") from exc
            nodes[name] = node
            values[name] = value
    if set(nodes) != requested:
        raise EvaluatorRepinError("evaluator binding assignment universe differs")
    return tree, nodes, values


def _normalized_ast(raw: bytes) -> str:
    tree, nodes, _ = _module_assignments(raw, REPINNED_CONSTANT_NAMES)
    for name in REPINNED_CONSTANT_NAMES:
        nodes[name].value = ast.Constant(value=f"__R3_REPIN_BINDING_{name}__")
    return ast.dump(tree, include_attributes=False)


def _binding_source(name: str, value: object) -> str:
    if name == SEED_CONSTANT_NAME:
        if (
            type(value) is not tuple
            or len(value) != 5
            or any(type(seed) is not int or seed <= 0 for seed in value)
            or len(set(value)) != 5
        ):
            raise EvaluatorRepinError("target heldout seeds differ")
        return repr(value)
    return json.dumps(
        _require_nonzero_hash(value, label=f"target {name}"),
        ensure_ascii=True,
    )


def _rewrite_binding_literals(raw: bytes, bindings: Mapping[str, object]) -> bytes:
    if set(bindings) != set(REPINNED_CONSTANT_NAMES):
        raise EvaluatorRepinError("rewritten evaluator binding universe differs")
    _, nodes, _ = _module_assignments(raw, REPINNED_CONSTANT_NAMES)
    text = raw.decode("utf-8")
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    replacements: list[tuple[int, int, str]] = []
    for name in REPINNED_CONSTANT_NAMES:
        value_node = nodes[name].value
        if value_node is None or value_node.end_lineno is None or value_node.end_col_offset is None:
            raise EvaluatorRepinError(f"evaluator binding span differs: {name}")
        start = offsets[value_node.lineno - 1] + value_node.col_offset
        end = offsets[value_node.end_lineno - 1] + value_node.end_col_offset
        replacements.append((start, end, _binding_source(name, bindings[name])))
    for start, end, replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text.encode("utf-8")


def replace_evaluator_bindings(
    raw: bytes, *, target_bindings: Mapping[str, object]
) -> tuple[bytes, str, dict[str, object]]:
    """Replace four literal values while preserving every other evaluator byte."""

    if set(target_bindings) != set(REPINNED_CONSTANT_NAMES):
        raise EvaluatorRepinError("target evaluator binding universe differs")
    normalized_target = {
        name: (
            tuple(target_bindings[name])
            if name == SEED_CONSTANT_NAME and type(target_bindings[name]) in {list, tuple}
            else target_bindings[name]
        )
        for name in REPINNED_CONSTANT_NAMES
    }
    for name, value in normalized_target.items():
        _binding_source(name, value)
    _, _, observed = _module_assignments(raw, REPINNED_CONSTANT_NAMES)
    ordered_observed = {name: observed[name] for name in REPINNED_CONSTANT_NAMES}
    ordered_target = {name: normalized_target[name] for name in REPINNED_CONSTANT_NAMES}
    if ordered_observed == ordered_target:
        restored_prior = _rewrite_binding_literals(raw, FROZEN_R2_PRIOR_BINDINGS)
        if _sha256(restored_prior) != FROZEN_R3_PRE_REPIN_CONSTANTS_RAW_SHA256:
            raise EvaluatorRepinError(
                "R3 target constants do not restore the exact policy-bound pre-repin bytes"
            )
        return raw, "already_r3_target", ordered_observed
    if ordered_observed != FROZEN_R2_PRIOR_BINDINGS:
        raise EvaluatorRepinError(
            "evaluator bindings are neither the exact frozen R2 prior nor R3 target"
        )
    if _sha256(raw) != FROZEN_R3_PRE_REPIN_CONSTANTS_RAW_SHA256:
        raise EvaluatorRepinError("frozen R3 pre-repin constants raw SHA-256 differs")
    planned = _rewrite_binding_literals(raw, ordered_target)
    _, _, planned_values = _module_assignments(planned, REPINNED_CONSTANT_NAMES)
    if {name: planned_values[name] for name in REPINNED_CONSTANT_NAMES} != ordered_target:
        raise EvaluatorRepinError("planned evaluator bindings differ")
    if _normalized_ast(raw) != _normalized_ast(planned):
        raise EvaluatorRepinError("planned constants changed non-binding semantics")
    return planned, "frozen_r2_prior", ordered_observed


def _launcher_pins(raw: bytes) -> dict[str, str]:
    try:
        tree = ast.parse(raw.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise EvaluatorRepinError("heldout evaluator launcher source differs") from exc
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "PINNED_SOURCE_SHA256"
        and node.value is not None
    ]
    if len(matches) != 1:
        raise EvaluatorRepinError("launcher pin assignment count differs")
    try:
        value = ast.literal_eval(matches[0].value)
    except (ValueError, SyntaxError) as exc:
        raise EvaluatorRepinError("launcher pin assignment is not literal") from exc
    if (
        type(value) is not dict
        or len(value) != EXPECTED_LAUNCHER_SOURCE_COUNT
        or any(
            type(relative) is not str or type(digest) is not str or HEX64.fullmatch(digest) is None
            for relative, digest in value.items()
        )
    ):
        raise EvaluatorRepinError("launcher pin assignment differs")
    return dict(value)


def _validate_current_launcher_state(
    *, project_root: Path, launcher_raw: bytes, binding_state: str
) -> tuple[dict[str, str], tuple[int, ...]]:
    """Authenticate the prior R2 map or require a complete R3 no-op state."""

    live_pins, package_counts = _r2.build_launcher_pins(project_root, overlays={})
    existing = _launcher_pins(launcher_raw)
    if set(existing) != set(live_pins):
        raise EvaluatorRepinError("launcher pin universe differs from live evaluator")
    if binding_state == "already_r3_target":
        if existing != live_pins:
            raise EvaluatorRepinError("R3 target launcher pins do not match live state")
        restored_pins = dict(live_pins)
        restored_pins[CONSTANTS_RELATIVE] = FROZEN_R2_CONSTANTS_RAW_SHA256
        restored_pins[SOURCE_LOCK_RELATIVE] = FROZEN_R2_SOURCE_LOCK_RAW_SHA256
        restored_launcher = _r2.replace_launcher_pin_assignment(launcher_raw, restored_pins)
        if _sha256(restored_launcher) != FROZEN_R2_RUN_ONCE_RAW_SHA256:
            raise EvaluatorRepinError(
                "R3 target launcher does not restore the exact frozen prior bytes"
            )
        return existing, package_counts
    if binding_state != "frozen_r2_prior":
        raise EvaluatorRepinError("evaluator binding transition state differs")
    if _sha256(launcher_raw) != FROZEN_R2_RUN_ONCE_RAW_SHA256:
        raise EvaluatorRepinError("prior R2 launcher raw SHA-256 differs")
    if existing[CONSTANTS_RELATIVE] != FROZEN_R2_CONSTANTS_RAW_SHA256:
        raise EvaluatorRepinError("prior R2 constants launcher pin differs")
    if (
        existing[SOURCE_LOCK_RELATIVE] != FROZEN_R2_SOURCE_LOCK_RAW_SHA256
        or existing[SOURCE_LOCK_RELATIVE] != live_pins[SOURCE_LOCK_RELATIVE]
    ):
        raise EvaluatorRepinError("prior R2 source-lock launcher pin differs")
    for relative, live_digest in live_pins.items():
        if relative in {CONSTANTS_RELATIVE, SOURCE_LOCK_RELATIVE}:
            continue
        if existing[relative] != live_digest:
            raise EvaluatorRepinError(
                f"prior launcher pin does not match live evaluator: {relative}"
            )
    return existing, package_counts


def build_repin_plan(
    *,
    project_root: Path,
    execution_authority: Path,
    execution_authority_raw_sha256: str,
) -> RepinPlan:
    """Validate the R3 authority and build all three future files without writing."""

    project = project_root.resolve(strict=True)
    if project != PROJECT_ROOT:
        raise EvaluatorRepinError("repository root differs from helper-owned project")
    authority = _load_validated_execution_authority(
        project_root=project,
        authority_path=execution_authority,
        expected_raw_sha256=execution_authority_raw_sha256,
    )
    authority_path = execution_authority
    if not authority_path.is_absolute():
        authority_path = project / authority_path
    authority_path = authority_path.resolve(strict=True)
    groups, runtime = _r2._validate_source_manifest(project, authority.get("source_manifest"))
    source_manifest = authority.get("source_manifest")
    if type(source_manifest) is not dict or authority.get(
        "source_manifest_semantic_sha256"
    ) != source_manifest.get("source_manifest_semantic_sha256"):
        raise EvaluatorRepinError("authority/source-manifest binding differs")
    target_bindings = _target_bindings_from_authority(authority)

    constants_path = _r2._project_file(project, CONSTANTS_RELATIVE)
    source_lock_path = _r2._project_file(project, SOURCE_LOCK_RELATIVE)
    run_once_path = _r2._project_file(project, RUN_ONCE_RELATIVE)
    constants_raw, _ = _r2._read_exact_utf8(constants_path, label="evaluator constants")
    source_lock_raw, _ = _r2._read_exact_utf8(source_lock_path, label="evaluator source lock")
    run_once_raw, _ = _r2._read_exact_utf8(run_once_path, label="evaluator launcher")
    planned_constants, binding_state, observed_bindings = replace_evaluator_bindings(
        constants_raw,
        target_bindings=target_bindings,
    )
    _, package_counts = _validate_current_launcher_state(
        project_root=project,
        launcher_raw=run_once_raw,
        binding_state=binding_state,
    )
    planned_source_lock = _r2.render_source_lock(groups, runtime)
    if binding_state == "already_r3_target" and source_lock_raw != planned_source_lock:
        raise EvaluatorRepinError(
            "R3 target source lock differs from the computed authority closure"
        )
    planned_pins, planned_package_counts = _r2.build_launcher_pins(
        project,
        overlays={
            CONSTANTS_RELATIVE: planned_constants,
            SOURCE_LOCK_RELATIVE: planned_source_lock,
        },
    )
    if planned_package_counts != package_counts:
        raise EvaluatorRepinError("launcher package universe changed during planning")
    planned_run_once = _r2.replace_launcher_pin_assignment(run_once_raw, planned_pins)

    current = {
        CONSTANTS_RELATIVE: constants_raw,
        SOURCE_LOCK_RELATIVE: source_lock_raw,
        RUN_ONCE_RELATIVE: run_once_raw,
    }
    planned = {
        CONSTANTS_RELATIVE: planned_constants,
        SOURCE_LOCK_RELATIVE: planned_source_lock,
        RUN_ONCE_RELATIVE: planned_run_once,
    }
    _require_complete_target_no_op(
        binding_state=binding_state,
        current=current,
        planned=planned,
    )
    write_set = [
        relative
        for relative in (CONSTANTS_RELATIVE, SOURCE_LOCK_RELATIVE, RUN_ONCE_RELATIVE)
        if current[relative] != planned[relative]
    ]
    group_lists = [[dict(row) for row in group] for group in groups]
    report: dict[str, object] = {
        "schema_version": "expected_pe.r3.evaluator_repin_plan.v1",
        "status": "VALIDATED_R3_EVALUATOR_REPIN_PLAN",
        "transition_state": binding_state,
        "execution_authority_ref": {
            "relative_path": authority_path.relative_to(project).as_posix(),
            "raw_sha256": execution_authority_raw_sha256,
            "execution_authority_semantic_sha256": authority["execution_authority_semantic_sha256"],
        },
        "legacy_protocol_wire_binding": {
            "raw_constant_name": PROTOCOL_CONSTANT_NAMES[0],
            "semantic_constant_name": PROTOCOL_CONSTANT_NAMES[1],
            "r3_lock_raw_sha256": target_bindings[PROTOCOL_CONSTANT_NAMES[0]],
            "r3_binding_semantic_sha256": target_bindings[PROTOCOL_CONSTANT_NAMES[1]],
        },
        "generation_binding": {
            "heldout_seeds_in_order": list(target_bindings[SEED_CONSTANT_NAME]),
            "heldout_seed_count": 5,
            "generation_plan_semantic_sha256": target_bindings[PLAN_CONSTANT_NAME],
        },
        "source_lock": {
            "relative_path": SOURCE_LOCK_RELATIVE,
            "source_record_groups": group_lists,
            "source_group_counts": list(EXPECTED_SOURCE_GROUP_COUNTS),
            "source_group_semantic_sha256": [_r2._semantic_sha256(group) for group in group_lists],
            "source_record_count": EXPECTED_SOURCE_RECORD_COUNT,
            "source_records_semantic_sha256": source_manifest["source_records_semantic_sha256"],
            "runtime_versions": runtime,
            "runtime_semantic_sha256": source_manifest["runtime_semantic_sha256"],
            "current_raw_sha256": _sha256(source_lock_raw),
            "planned_raw_sha256": _sha256(planned_source_lock),
        },
        "constants": {
            "relative_path": CONSTANTS_RELATIVE,
            "replaced_names": list(REPINNED_CONSTANT_NAMES),
            "observed_prior_bindings": observed_bindings,
            "allowed_prior_states": [
                "exact_frozen_r2_four_binding_state",
                "exact_validated_r3_target_four_binding_state",
            ],
            "all_other_constants_bytes_preserved": True,
            "current_raw_sha256": _sha256(constants_raw),
            "planned_raw_sha256": _sha256(planned_constants),
        },
        "launcher": {
            "relative_path": RUN_ONCE_RELATIVE,
            "package_roots": list(EVALUATOR_PACKAGE_RELATIVES),
            "package_file_counts": list(package_counts),
            "source_pin_count": len(planned_pins),
            "source_pin_universe": [
                {"relative_path": relative, "raw_sha256": digest}
                for relative, digest in planned_pins.items()
            ],
            "current_raw_sha256": _sha256(run_once_raw),
            "planned_raw_sha256": _sha256(planned_run_once),
        },
        "write_set": write_set,
        "schema_runner_gate_formula_bootstrap_changes": 0,
    }
    return RepinPlan(
        project_root=project,
        authority_path=authority_path,
        authority_raw_sha256=execution_authority_raw_sha256,
        current_bytes=current,
        planned_bytes=planned,
        report=report,
    )


def _atomic_replace(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}.r3-repin-{os.getpid()}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise EvaluatorRepinError("staged evaluator write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if temporary.read_bytes() != raw:
            raise EvaluatorRepinError("staged evaluator bytes differ")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _require_complete_target_no_op(
    *,
    binding_state: str,
    current: Mapping[str, bytes],
    planned: Mapping[str, bytes],
) -> None:
    """Reject a claimed R3 target that would still rewrite any evaluator byte."""

    if binding_state == "already_r3_target" and dict(current) != dict(planned):
        changed = sorted(
            relative for relative in current if current.get(relative) != planned.get(relative)
        )
        raise EvaluatorRepinError(
            "R3 target state is not a complete byte-identical no-op: " + ",".join(changed)
        )


def apply_repin_plan(plan: RepinPlan) -> None:
    """Apply the three-file plan, then require a complete no-op revalidation."""

    expected_targets = (
        CONSTANTS_RELATIVE,
        SOURCE_LOCK_RELATIVE,
        RUN_ONCE_RELATIVE,
    )
    if (
        tuple(plan.current_bytes) != expected_targets
        or tuple(plan.planned_bytes) != expected_targets
    ):
        raise EvaluatorRepinError("repin write-set differs")
    fresh = build_repin_plan(
        project_root=plan.project_root,
        execution_authority=plan.authority_path,
        execution_authority_raw_sha256=plan.authority_raw_sha256,
    )
    if (
        fresh.current_bytes != plan.current_bytes
        or fresh.planned_bytes != plan.planned_bytes
        or fresh.report != plan.report
    ):
        raise EvaluatorRepinError("repin plan drifted during final apply validation")
    for relative in expected_targets:
        path = _r2._project_file(plan.project_root, relative)
        if path.read_bytes() != plan.current_bytes[relative]:
            raise EvaluatorRepinError(f"repin target drifted before apply: {relative}")
    for relative in expected_targets:
        if plan.planned_bytes[relative] != plan.current_bytes[relative]:
            _atomic_replace(
                plan.project_root.joinpath(*PurePosixPath(relative).parts),
                plan.planned_bytes[relative],
            )
    for relative in expected_targets:
        path = _r2._project_file(plan.project_root, relative)
        if path.read_bytes() != plan.planned_bytes[relative]:
            raise EvaluatorRepinError(f"repin target differs after apply: {relative}")
    no_op = build_repin_plan(
        project_root=plan.project_root,
        execution_authority=plan.authority_path,
        execution_authority_raw_sha256=plan.authority_raw_sha256,
    )
    if (
        no_op.current_bytes != plan.planned_bytes
        or no_op.planned_bytes != plan.planned_bytes
        or no_op.report.get("transition_state") != "already_r3_target"
    ):
        raise EvaluatorRepinError("applied repin did not revalidate as an R3 no-op")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Dry-run or apply the deterministic R3 heldout evaluator repin"
    )
    result.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    result.add_argument("--execution-authority", type=Path, required=True)
    result.add_argument("--execution-authority-raw-sha256", required=True)
    result.add_argument(
        "--apply",
        action="store_true",
        help="rewrite the exact three evaluator files; default is read-only dry-run",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        plan = build_repin_plan(
            project_root=arguments.repository_root,
            execution_authority=arguments.execution_authority,
            execution_authority_raw_sha256=(arguments.execution_authority_raw_sha256),
        )
        if arguments.apply:
            apply_repin_plan(plan)
        report = {
            **plan.report,
            "mode": "apply" if arguments.apply else "dry-run",
            "writes_performed": arguments.apply and bool(plan.report["write_set"]),
            "post_apply_no_op_revalidation": arguments.apply,
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except EvaluatorRepinError as exc:
        raise SystemExit(f"R3 evaluator repin rejected: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
