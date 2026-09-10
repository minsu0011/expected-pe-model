"""Deterministically repin the detached heldout evaluator to an R2 authority.

The default mode is a read-only dry run.  ``--apply`` is deliberately required
before the three evaluator files may be rewritten.  This helper lives outside
both the producer and evaluator source closures so its own bytes do not create
a source-lock fixed point.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Final, Mapping, Sequence


sys.dont_write_bytecode = True

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
ZERO_SHA256: Final = "0" * 64
EXPECTED_SOURCE_GROUP_COUNTS: Final = (74, 26, 34, 3)
EXPECTED_SOURCE_RECORD_COUNT: Final = 137
EXPECTED_LAUNCHER_SOURCE_COUNT: Final = 37

CONSTANTS_RELATIVE: Final = (
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/constants.py"
)
SOURCE_LOCK_RELATIVE: Final = (
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/source_lock.py"
)
RUN_ONCE_RELATIVE: Final = (
    "scripts/model_lab/pe_model_portfolio_heldout_certification_evaluator_v1/run_once.py"
)
PROTOCOL_CONSTANT_NAMES: Final = (
    "R2_PROTOCOL_LOCK_RAW_SHA256",
    "R2_PROTOCOL_BINDING_SEMANTIC_SHA256",
)
EVALUATOR_PACKAGE_RELATIVES: Final = (
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1",
)
EXPECTED_EVALUATOR_PACKAGE_FILE_COUNTS: Final = (11, 3, 11, 12)
SOURCE_MANIFEST_GROUP_FIELDS: Final = (
    "adapter_source_records",
    "c2_c3_frozen_numeric_source_records",
    "c4_source_tree_records",
    "c4_source_file_records",
)
SOURCE_MANIFEST_FIELDS: Final = {
    "schema_version",
    "status",
    "qualification_result_raw_sha256",
    "public_replay_design_lock_raw_sha256",
    *SOURCE_MANIFEST_GROUP_FIELDS,
    "c4_source_model_version",
    "runtime_versions",
    "runtime_semantic_sha256",
    "source_record_count",
    "source_records_semantic_sha256",
    "source_manifest_semantic_sha256",
}
SOURCE_MANIFEST_SCHEMA: Final = "expected_pe.four_model.heldout_prediction_source_manifest.v1"
SOURCE_MANIFEST_STATUS: Final = "FROZEN_EXECUTED_NUMERIC_SOURCE_CLOSURE_PRETRUTH"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvaluatorRepinError(RuntimeError):
    """Fail-closed R2 evaluator repin error."""


@dataclass(frozen=True)
class RepinPlan:
    """Fully validated future bytes and their audit report."""

    project_root: Path
    authority_path: Path
    authority_raw_sha256: str
    current_bytes: Mapping[str, bytes]
    planned_bytes: Mapping[str, bytes]
    report: Mapping[str, object]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _semantic_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return _sha256(raw)


def _require_nonzero_hash(value: object, *, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None or value == ZERO_SHA256:
        raise EvaluatorRepinError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def _require_relative(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise EvaluatorRepinError(f"{label} is not a POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
    ):
        raise EvaluatorRepinError(f"{label} normalization differs")
    return value


def _project_file(project: Path, relative: str) -> Path:
    normalized = _require_relative(relative, label="project file")
    lexical = project.joinpath(*PurePosixPath(normalized).parts)
    resolved = lexical.resolve(strict=True)
    if (
        project not in resolved.parents
        or not resolved.is_file()
        or lexical.is_symlink()
        or resolved.is_symlink()
    ):
        raise EvaluatorRepinError(f"project file escaped or is not regular: {relative}")
    return resolved


def _read_exact_utf8(path: Path, *, label: str) -> tuple[bytes, str]:
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after or before.st_size != len(raw):
        raise EvaluatorRepinError(f"{label} changed while being read")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluatorRepinError(f"{label} is not UTF-8") from exc
    if text.startswith("\ufeff") or "\r" in text or not text.endswith("\n"):
        raise EvaluatorRepinError(f"{label} text framing differs")
    return raw, text


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EvaluatorRepinError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvaluatorRepinError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluatorRepinError(f"{label} JSON differs") from exc
    if type(value) is not dict:
        raise EvaluatorRepinError(f"{label} is not a JSON object")
    return value


def _canonical_pretty_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _load_validated_execution_authority(
    *,
    project_root: Path,
    authority_path: Path,
    expected_raw_sha256: str,
) -> dict[str, Any]:
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
    raw, _ = _read_exact_utf8(candidate, label="execution authority")
    if _sha256(raw) != expected_raw:
        raise EvaluatorRepinError("execution authority raw SHA-256 differs")
    parsed = _strict_json_object(raw, label="execution authority")
    if _canonical_pretty_bytes(parsed) != raw:
        raise EvaluatorRepinError("execution authority canonical bytes differ")
    run_id = parsed.get("run_id")
    if type(run_id) is not str or not run_id.startswith("r2_"):
        raise EvaluatorRepinError("execution authority is not a new R2 authority")
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
        label="R2 protocol lock raw SHA-256",
    )
    protocol_semantic = _require_nonzero_hash(
        validated.get("r2_protocol_binding_semantic_sha256"),
        label="R2 protocol binding semantic SHA-256",
    )
    protocol = validated.get("r2_protocol_lock")
    if (
        type(protocol) is not dict
        or protocol.get("r2_protocol_binding_semantic_sha256") != protocol_semantic
        or _sha256(_canonical_pretty_bytes(protocol)) != protocol_raw
    ):
        raise EvaluatorRepinError("R2 protocol authority binding differs")
    return validated


def _validate_source_manifest(
    project_root: Path, value: object
) -> tuple[tuple[tuple[dict[str, object], ...], ...], dict[str, str]]:
    if type(value) is not dict or set(value) != SOURCE_MANIFEST_FIELDS:
        raise EvaluatorRepinError("authority source manifest key universe differs")
    if (
        value.get("schema_version") != SOURCE_MANIFEST_SCHEMA
        or value.get("status") != SOURCE_MANIFEST_STATUS
    ):
        raise EvaluatorRepinError("authority source manifest identity differs")

    groups: list[tuple[dict[str, object], ...]] = []
    seen: set[str] = set()
    for field, expected_count in zip(
        SOURCE_MANIFEST_GROUP_FIELDS, EXPECTED_SOURCE_GROUP_COUNTS, strict=True
    ):
        candidate = value.get(field)
        if type(candidate) is not list or len(candidate) != expected_count:
            raise EvaluatorRepinError(f"{field} count differs")
        records: list[dict[str, object]] = []
        for row in candidate:
            if type(row) is not dict or set(row) != {
                "relative_path",
                "raw_sha256",
                "size_bytes",
            }:
                raise EvaluatorRepinError(f"{field} record shape differs")
            relative = _require_relative(row["relative_path"], label=f"{field} relative path")
            digest = _require_nonzero_hash(row["raw_sha256"], label=f"{field} source SHA-256")
            size = row["size_bytes"]
            if type(size) is not int or size <= 0 or relative in seen:
                raise EvaluatorRepinError(f"{field} source record differs")
            seen.add(relative)
            path = _project_file(project_root, relative)
            raw = path.read_bytes()
            if len(raw) != size or _sha256(raw) != digest:
                raise EvaluatorRepinError(f"live source closure drifted: {relative}")
            records.append(
                {
                    "relative_path": relative,
                    "raw_sha256": digest,
                    "size_bytes": size,
                }
            )
        if [record["relative_path"] for record in records] != sorted(
            str(record["relative_path"]) for record in records
        ):
            raise EvaluatorRepinError(f"{field} order differs")
        groups.append(tuple(records))

    flattened = [record for group in groups for record in group]
    if (
        len(flattened) != EXPECTED_SOURCE_RECORD_COUNT
        or value.get("source_record_count") != EXPECTED_SOURCE_RECORD_COUNT
        or value.get("source_records_semantic_sha256") != _semantic_sha256(flattened)
    ):
        raise EvaluatorRepinError("authority source-record semantic closure differs")

    runtime = value.get("runtime_versions")
    if (
        type(runtime) is not dict
        or not runtime
        or any(type(key) is not str or type(item) is not str for key, item in runtime.items())
    ):
        raise EvaluatorRepinError("authority runtime inventory differs")
    runtime_exact = dict(runtime)
    runtime_semantic = _semantic_sha256(runtime_exact)
    if value.get("runtime_semantic_sha256") != runtime_semantic:
        raise EvaluatorRepinError("authority runtime semantic SHA-256 differs")

    project_text = str(project_root)
    if project_text not in sys.path:
        sys.path.insert(0, project_text)
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.source_inventory import (  # noqa: E501
        runtime_versions,
    )

    if runtime_versions() != runtime_exact:
        raise EvaluatorRepinError("live runtime differs from execution authority")
    unsigned = dict(value)
    stored_manifest_semantic = unsigned.pop("source_manifest_semantic_sha256", None)
    if stored_manifest_semantic != _semantic_sha256(unsigned):
        raise EvaluatorRepinError("authority source manifest self-seal differs")
    return tuple(groups), runtime_exact


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_source_lock(
    groups: Sequence[Sequence[Mapping[str, object]]],
    runtime_versions: Mapping[str, str],
) -> bytes:
    """Render the evaluator lock from the authority manifest, deterministically."""

    if tuple(len(group) for group in groups) != EXPECTED_SOURCE_GROUP_COUNTS:
        raise EvaluatorRepinError("rendered source group counts differ")
    normalized_groups: list[list[dict[str, object]]] = []
    for group in groups:
        normalized_group: list[dict[str, object]] = []
        for row in group:
            if set(row) != {"relative_path", "raw_sha256", "size_bytes"}:
                raise EvaluatorRepinError("rendered source record shape differs")
            relative = _require_relative(
                row["relative_path"], label="rendered source relative path"
            )
            digest = _require_nonzero_hash(row["raw_sha256"], label="rendered source SHA-256")
            size = row["size_bytes"]
            if type(size) is not int or size <= 0:
                raise EvaluatorRepinError("rendered source size differs")
            normalized_group.append(
                {
                    "relative_path": relative,
                    "raw_sha256": digest,
                    "size_bytes": size,
                }
            )
        normalized_groups.append(normalized_group)
    flattened = [row for group in normalized_groups for row in group]
    if len(flattened) != EXPECTED_SOURCE_RECORD_COUNT:
        raise EvaluatorRepinError("rendered source record count differs")
    runtime = dict(runtime_versions)
    if not runtime or any(
        type(key) is not str or type(value) is not str for key, value in runtime.items()
    ):
        raise EvaluatorRepinError("rendered runtime inventory differs")

    lines = [
        '"""Independent exact source/runtime lock for the frozen heldout prediction authority."""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
        "",
        "SourceRecordTriple = tuple[str, str, int]",
        "EXPECTED_SOURCE_RECORD_GROUPS: Final[",
        "    tuple[tuple[SourceRecordTriple, ...], ...]",
        "] = (",
    ]
    for group in normalized_groups:
        lines.append("    (")
        for row in group:
            lines.extend(
                (
                    "        (",
                    f"            {_quote(str(row['relative_path']))},",
                    f"            {_quote(str(row['raw_sha256']))},",
                    f"            {int(row['size_bytes'])},",
                    "        ),",
                )
            )
        lines.append("    ),")
    lines.extend(
        (
            ")",
            f"EXPECTED_SOURCE_GROUP_COUNTS: Final = {EXPECTED_SOURCE_GROUP_COUNTS!r}",
            "EXPECTED_SOURCE_GROUP_SEMANTIC_SHA256: Final = (",
        )
    )
    for group in normalized_groups:
        lines.append(f"    {_quote(_semantic_sha256(group))},")
    lines.extend(
        (
            ")",
            f"EXPECTED_SOURCE_RECORD_COUNT: Final = {EXPECTED_SOURCE_RECORD_COUNT}",
            "EXPECTED_SOURCE_RECORDS_SEMANTIC_SHA256: Final = (",
            f"    {_quote(_semantic_sha256(flattened))}",
            ")",
            "EXPECTED_RUNTIME_VERSIONS: Final = (",
        )
    )
    for key, value in sorted(runtime.items()):
        lines.append(f"    ({_quote(key)}, {_quote(value)}),")
    lines.extend(
        (
            ")",
            "EXPECTED_RUNTIME_SEMANTIC_SHA256: Final = (",
            f"    {_quote(_semantic_sha256(runtime))}",
            ")",
            "",
            "",
            "__all__ = [",
            '    "EXPECTED_RUNTIME_SEMANTIC_SHA256",',
            '    "EXPECTED_RUNTIME_VERSIONS",',
            '    "EXPECTED_SOURCE_GROUP_COUNTS",',
            '    "EXPECTED_SOURCE_GROUP_SEMANTIC_SHA256",',
            '    "EXPECTED_SOURCE_RECORD_COUNT",',
            '    "EXPECTED_SOURCE_RECORD_GROUPS",',
            '    "EXPECTED_SOURCE_RECORDS_SEMANTIC_SHA256",',
            "]",
        )
    )
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    try:
        ast.parse(raw.decode("utf-8"))
    except SyntaxError as exc:
        raise EvaluatorRepinError("planned source lock is not valid Python") from exc
    return raw


def replace_protocol_placeholders(
    raw: bytes, *, protocol_raw_sha256: str, protocol_semantic_sha256: str
) -> bytes:
    """Replace the two zero literals, or verify an exact prior protocol repin."""

    raw_digest = _require_nonzero_hash(protocol_raw_sha256, label="R2 protocol lock raw SHA-256")
    semantic_digest = _require_nonzero_hash(
        protocol_semantic_sha256,
        label="R2 protocol binding semantic SHA-256",
    )
    try:
        text = raw.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise EvaluatorRepinError("evaluator constants source differs") from exc
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in PROTOCOL_CONSTANT_NAMES:
                if node.target.id in assignments:
                    raise EvaluatorRepinError("duplicate protocol constant assignment")
                assignments[node.target.id] = node.value
    if set(assignments) != set(PROTOCOL_CONSTANT_NAMES):
        raise EvaluatorRepinError("protocol constant assignment universe differs")
    observed = tuple(ast.literal_eval(assignments[name]) for name in PROTOCOL_CONSTANT_NAMES)
    expected = (raw_digest, semantic_digest)
    if observed == expected:
        return raw
    if observed != (ZERO_SHA256, ZERO_SHA256):
        raise EvaluatorRepinError(
            "protocol constants are neither zero placeholders nor the exact authority"
        )

    result = text
    for name, digest in zip(PROTOCOL_CONSTANT_NAMES, (raw_digest, semantic_digest), strict=True):
        pattern = re.compile(rf'(?m)^({name}: Final = \(\n    "){ZERO_SHA256}("\n\))$')
        result, count = pattern.subn(rf"\g<1>{digest}\g<2>", result)
        if count != 1:
            raise EvaluatorRepinError(f"{name} placeholder text differs")
    planned = result.encode("utf-8")
    if len(planned) != len(raw):
        raise EvaluatorRepinError("protocol constant replacement changed file size")
    return planned


def discover_launcher_source_universe(
    project_root: Path,
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    """Return every .py file in the exact four evaluator package roots."""

    project = project_root.resolve(strict=True)
    groups: list[tuple[str, ...]] = []
    for relative_root, expected_count in zip(
        EVALUATOR_PACKAGE_RELATIVES,
        EXPECTED_EVALUATOR_PACKAGE_FILE_COUNTS,
        strict=True,
    ):
        root = project.joinpath(*PurePosixPath(relative_root).parts)
        resolved_root = root.resolve(strict=True)
        if (
            project not in resolved_root.parents
            or not resolved_root.is_dir()
            or root.is_symlink()
            or resolved_root.is_symlink()
        ):
            raise EvaluatorRepinError("evaluator package root escaped or differs")
        relatives: list[str] = []
        for path in resolved_root.rglob("*.py"):
            resolved = path.resolve(strict=True)
            if (
                resolved_root not in resolved.parents
                or not resolved.is_file()
                or path.is_symlink()
                or resolved.is_symlink()
            ):
                raise EvaluatorRepinError("evaluator package member escaped or differs")
            relatives.append(resolved.relative_to(project).as_posix())
        group = tuple(sorted(relatives))
        if len(group) != expected_count or len(group) != len(set(group)):
            raise EvaluatorRepinError(f"evaluator package file universe differs: {relative_root}")
        groups.append(group)
    flattened = tuple(relative for group in groups for relative in group)
    if (
        len(groups) != 4
        or len(flattened) != EXPECTED_LAUNCHER_SOURCE_COUNT
        or len(flattened) != len(set(flattened))
    ):
        raise EvaluatorRepinError("four-package launcher source universe differs")
    return flattened, tuple(len(group) for group in groups)


def build_launcher_pins(
    project_root: Path,
    *,
    overlays: Mapping[str, bytes],
) -> tuple[dict[str, str], tuple[int, ...]]:
    universe, package_counts = discover_launcher_source_universe(project_root)
    if not set(overlays).issubset(universe):
        raise EvaluatorRepinError("launcher hash overlay escaped its source universe")
    result: dict[str, str] = {}
    for relative in universe:
        raw = overlays.get(relative)
        if raw is None:
            raw = _project_file(project_root, relative).read_bytes()
        if type(raw) is not bytes or not raw:
            raise EvaluatorRepinError(f"launcher source bytes differ: {relative}")
        result[relative] = _sha256(raw)
    if len(result) != EXPECTED_LAUNCHER_SOURCE_COUNT:
        raise EvaluatorRepinError("launcher source pin count differs")
    return result, package_counts


def _render_launcher_assignment(pins: Mapping[str, str]) -> str:
    if len(pins) != EXPECTED_LAUNCHER_SOURCE_COUNT:
        raise EvaluatorRepinError("launcher assignment pin count differs")
    lines = ["PINNED_SOURCE_SHA256: dict[str, str] = {"]
    for relative, digest in pins.items():
        _require_relative(relative, label="launcher pin path")
        _require_nonzero_hash(digest, label="launcher source pin")
        lines.append(f"    {_quote(relative)}: {_quote(digest)},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def replace_launcher_pin_assignment(raw: bytes, pins: Mapping[str, str]) -> bytes:
    """Replace only the module-level PINNED_SOURCE_SHA256 assignment."""

    try:
        text = raw.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise EvaluatorRepinError("heldout evaluator launcher source differs") from exc
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "PINNED_SOURCE_SHA256"
    ]
    if len(matches) != 1:
        raise EvaluatorRepinError("launcher pin assignment count differs")
    node = matches[0]
    if (
        node.value is None
        or node.col_offset != 0
        or node.end_lineno is None
        or node.end_col_offset is None
    ):
        raise EvaluatorRepinError("launcher pin assignment location differs")
    try:
        existing = ast.literal_eval(node.value)
    except (ValueError, SyntaxError) as exc:
        raise EvaluatorRepinError("launcher pin assignment is not literal") from exc
    if (
        type(existing) is not dict
        or set(existing) != set(pins)
        or any(
            type(key) is not str or type(value) is not str or HEX64.fullmatch(value) is None
            for key, value in existing.items()
        )
    ):
        raise EvaluatorRepinError("existing launcher pin universe differs")

    lines = text.splitlines(keepends=True)
    start = sum(len(line) for line in lines[: node.lineno - 1])
    end = sum(len(line) for line in lines[: node.end_lineno])
    planned_text = text[:start] + _render_launcher_assignment(pins) + text[end:]
    try:
        planned_tree = ast.parse(planned_text)
    except SyntaxError as exc:
        raise EvaluatorRepinError("planned launcher source is not valid Python") from exc
    planned_nodes = [
        candidate
        for candidate in planned_tree.body
        if isinstance(candidate, ast.AnnAssign)
        and isinstance(candidate.target, ast.Name)
        and candidate.target.id == "PINNED_SOURCE_SHA256"
    ]
    if len(planned_nodes) != 1 or ast.literal_eval(planned_nodes[0].value) != dict(pins):
        raise EvaluatorRepinError("planned launcher pin assignment differs")
    return planned_text.encode("utf-8")


def build_repin_plan(
    *,
    project_root: Path,
    execution_authority: Path,
    execution_authority_raw_sha256: str,
) -> RepinPlan:
    """Validate all inputs and build all three future files without writing."""

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
    groups, runtime = _validate_source_manifest(project, authority.get("source_manifest"))
    if (
        authority.get("source_manifest_semantic_sha256")
        != authority["source_manifest"]["source_manifest_semantic_sha256"]
    ):
        raise EvaluatorRepinError("authority/source-manifest binding differs")

    protocol_raw = _require_nonzero_hash(
        authority.get("r2_protocol_lock_raw_sha256"),
        label="R2 protocol lock raw SHA-256",
    )
    protocol_semantic = _require_nonzero_hash(
        authority.get("r2_protocol_binding_semantic_sha256"),
        label="R2 protocol binding semantic SHA-256",
    )
    constants_path = _project_file(project, CONSTANTS_RELATIVE)
    source_lock_path = _project_file(project, SOURCE_LOCK_RELATIVE)
    run_once_path = _project_file(project, RUN_ONCE_RELATIVE)
    constants_raw, _ = _read_exact_utf8(constants_path, label="evaluator constants")
    source_lock_raw, _ = _read_exact_utf8(source_lock_path, label="evaluator source lock")
    run_once_raw, _ = _read_exact_utf8(run_once_path, label="evaluator launcher")
    planned_constants = replace_protocol_placeholders(
        constants_raw,
        protocol_raw_sha256=protocol_raw,
        protocol_semantic_sha256=protocol_semantic,
    )
    planned_source_lock = render_source_lock(groups, runtime)
    pins, package_counts = build_launcher_pins(
        project,
        overlays={
            CONSTANTS_RELATIVE: planned_constants,
            SOURCE_LOCK_RELATIVE: planned_source_lock,
        },
    )
    planned_run_once = replace_launcher_pin_assignment(run_once_raw, pins)

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
    group_lists = [[dict(row) for row in group] for group in groups]
    report: dict[str, object] = {
        "schema_version": "expected_pe.r2.evaluator_repin_plan.v1",
        "status": "VALIDATED_R2_EVALUATOR_REPIN_PLAN",
        "execution_authority_ref": {
            "relative_path": authority_path.relative_to(project).as_posix(),
            "raw_sha256": execution_authority_raw_sha256,
            "execution_authority_semantic_sha256": authority["execution_authority_semantic_sha256"],
        },
        "r2_protocol_lock_raw_sha256": protocol_raw,
        "r2_protocol_binding_semantic_sha256": protocol_semantic,
        "source_lock": {
            "relative_path": SOURCE_LOCK_RELATIVE,
            "source_record_groups": group_lists,
            "source_group_counts": list(EXPECTED_SOURCE_GROUP_COUNTS),
            "source_group_semantic_sha256": [_semantic_sha256(group) for group in group_lists],
            "source_record_count": EXPECTED_SOURCE_RECORD_COUNT,
            "source_records_semantic_sha256": authority["source_manifest"][
                "source_records_semantic_sha256"
            ],
            "runtime_versions": runtime,
            "runtime_semantic_sha256": authority["source_manifest"]["runtime_semantic_sha256"],
            "current_raw_sha256": _sha256(source_lock_raw),
            "planned_raw_sha256": _sha256(planned_source_lock),
        },
        "constants": {
            "relative_path": CONSTANTS_RELATIVE,
            "replaced_names": list(PROTOCOL_CONSTANT_NAMES),
            "allowed_prior_states": [
                "both_exact_zero_placeholders",
                "both_already_equal_validated_authority",
            ],
            "current_raw_sha256": _sha256(constants_raw),
            "planned_raw_sha256": _sha256(planned_constants),
        },
        "launcher": {
            "relative_path": RUN_ONCE_RELATIVE,
            "package_roots": list(EVALUATOR_PACKAGE_RELATIVES),
            "package_file_counts": list(package_counts),
            "source_pin_count": len(pins),
            "source_pin_universe": [
                {"relative_path": relative, "raw_sha256": digest}
                for relative, digest in pins.items()
            ],
            "current_raw_sha256": _sha256(run_once_raw),
            "planned_raw_sha256": _sha256(planned_run_once),
        },
        "write_set": [CONSTANTS_RELATIVE, SOURCE_LOCK_RELATIVE, RUN_ONCE_RELATIVE],
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
    temporary = path.with_name(f".{path.name}.r2-repin-{os.getpid()}.tmp")
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


def apply_repin_plan(plan: RepinPlan) -> None:
    """Apply only the already validated three-file mechanical rewrite."""

    expected_targets = (CONSTANTS_RELATIVE, SOURCE_LOCK_RELATIVE, RUN_ONCE_RELATIVE)
    if tuple(plan.current_bytes) != expected_targets or tuple(plan.planned_bytes) != (
        *expected_targets,
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
        path = _project_file(plan.project_root, relative)
        if path.read_bytes() != plan.current_bytes[relative]:
            raise EvaluatorRepinError(f"repin target drifted before apply: {relative}")
    for relative in expected_targets:
        if plan.planned_bytes[relative] != plan.current_bytes[relative]:
            _atomic_replace(
                plan.project_root.joinpath(*PurePosixPath(relative).parts),
                plan.planned_bytes[relative],
            )
    for relative in expected_targets:
        path = _project_file(plan.project_root, relative)
        if path.read_bytes() != plan.planned_bytes[relative]:
            raise EvaluatorRepinError(f"repin target differs after apply: {relative}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Dry-run or apply the deterministic R2 heldout evaluator repin"
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
            execution_authority_raw_sha256=arguments.execution_authority_raw_sha256,
        )
        if arguments.apply:
            apply_repin_plan(plan)
        report = {
            **plan.report,
            "mode": "apply" if arguments.apply else "dry-run",
            "writes_performed": arguments.apply,
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except EvaluatorRepinError as exc:
        raise SystemExit(f"R2 evaluator repin rejected: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
