"""Complete the one missing R3 protocol leaf without touching the registry.

The R3 reservation append is already valid and consumed.  Its original helper
stopped after Windows translated the planned LF registry serialization to CRLF,
before publishing the protocol leaf.  This closure-external tool accepts only a
separately frozen completion authority and can create only the missing
``promotion_policy.lock.json`` leaf.  It never reserves seeds, writes or locks
the registry, opens truth, generates heldout data, or scores predictions.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Final, Mapping, Sequence


sys.dont_write_bytecode = True

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SITE_PACKAGES: Final = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
HEX64: Final = re.compile(r"^[0-9a-f]{64}$")

AUTHORITY_SCHEMA: Final = "expected_pe.four_model.r3_protocol_leaf_completion_authority.v1"
AUTHORITY_STATUS: Final = "GO_CREATE_MISSING_R3_PROTOCOL_LEAF_ONLY_NO_REGISTRY_WRITE"
AUTHORITY_SCOPE: Final = "CREATE_ONLY_MISSING_PROTOCOL_LEAF_FOR_VALID_CONSUMED_RESERVATION"
DRY_RUN_STATUS: Final = "PASS_R3_PROTOCOL_LEAF_COMPLETION_DRY_RUN_NO_MUTATION"
COMPLETE_STATUS: Final = "PASS_R3_PROTOCOL_LEAF_COMPLETED_NO_REGISTRY_MUTATION"
CHILD_STATUS: Final = "PASS_R3_PROTOCOL_LEAF_FRESH_SUBPROCESS_VALIDATION"
CHILD_REPORT_FIELDS: Final = {
    "schema_version",
    "status",
    "run_id",
    "completion_authority_raw_sha256",
    "registry_raw_sha256",
    "registry_entry_count",
    "protocol_lock_raw_sha256",
    "protocol_leaf_count",
    "additional_seed_reservation_count",
    "formal_generation_count",
    "generation_count",
    "helper_apply_count",
    "original_helper_apply_count",
    "registry_append_count",
    "registry_write_count",
    "registry_lock_count",
    "reservation_count",
    "seed_value_change_count",
    "truth_open_count",
    "score_open_count",
    "heldout_content_open_count",
}


class R3ProtocolLeafCompletionError(RuntimeError):
    """Fail-closed leaf-only R3 completion error."""


@dataclass(frozen=True)
class ExpectedState:
    """Exact formal state; tests may supply an equally strict synthetic state."""

    run_id: str
    authority_relative_path: str
    tool_relative_path: str
    test_relative_path: str
    execution_gate_relative_path: str
    execution_gate_raw_sha256: str
    execution_gate_schema: str
    execution_gate_status: str
    apply_forensic_relative_path: str
    apply_forensic_raw_sha256: str
    apply_forensic_schema: str
    apply_forensic_status: str
    independent_audit_relative_path: str
    independent_audit_raw_sha256: str
    independent_audit_schema: str
    independent_audit_status: str
    independent_audit_semantic_sha256: str
    precommit_relative_path: str
    precommit_raw_sha256: str
    terminal_relative_path: str
    terminal_raw_sha256: str
    rehearsal_relative_path: str
    rehearsal_raw_sha256: str
    rehearsal_status: str
    registry_relative_path: str
    registry_raw_sha256: str
    registry_size_bytes: int
    registry_self_sha256: str
    registry_entry_count: int
    globally_spent_seed_count: int
    maximum_reserved_seed: int
    registry_lf_raw_sha256: str
    registry_lf_size_bytes: int
    registry_crlf_count: int
    registry_bare_lf_count: int
    registry_lock_relative_path: str
    registry_temp_glob: str
    predecessor_raw_sha256: str
    predecessor_self_sha256: str
    predecessor_entry_count: int
    predecessor_last_entry_sha256: str
    reservation_sequence: int
    reservation_entry_sha256: str
    reservation_id: str
    reservation_created_at_utc: str
    source_config_sha256: str
    candidate_config_sha256: str
    reservation_policy_config_sha256: str
    quarantine_seeds: tuple[int, ...]
    heldout_seeds: tuple[int, ...]
    heldout_seed_commitment_sha256: str
    output_root_relative_path: str
    protocol_leaf: str
    protocol_schema: str
    protocol_status: str
    protocol_raw_sha256: str
    protocol_size_bytes: int
    protocol_binding_semantic_sha256: str
    protocol_policy_lock_sha256: str

    @property
    def protocol_relative_path(self) -> str:
        return f"{self.output_root_relative_path}/{self.protocol_leaf}"


FORMAL: Final = ExpectedState(
    run_id="r3_20260824T134417",
    authority_relative_path=(
        "build/pe_four_model_heldout_r3_protocol_leaf_completion_authority_r3_20260824T134417.json"
    ),
    tool_relative_path=("scripts/model_lab/pe_four_model_heldout_r3_complete_protocol_leaf.py"),
    test_relative_path=("tests/model_lab/test_pe_four_model_heldout_r3_complete_protocol_leaf.py"),
    execution_gate_relative_path=(
        "build/pe_four_model_heldout_r3_reservation_execution_gate_r3_20260824T134417.json"
    ),
    execution_gate_raw_sha256=("4dcc8a6e5379f0b1dbe54db8eb84de132090f870a31f307ec0f39f024fb7a1eb"),
    execution_gate_schema=("expected_pe.four_model.r3_reservation_execution_gate.v1"),
    execution_gate_status="GO_APPLY_EXACTLY_ONE_R3_RESERVATION_PRETRUTH",
    apply_forensic_relative_path=(
        "build/pe_four_model_heldout_r3_reservation_apply_forensic_r3_20260824T134417.json"
    ),
    apply_forensic_raw_sha256=("aa4ff937b30079d5c443a1ae769d547ce709225a228df647d92d06744c7c86d1"),
    apply_forensic_schema="expected_pe.four_model.r3_reservation_apply_forensic.v1",
    apply_forensic_status=(
        "CONFIRMED_VALID_SINGLE_APPEND_PROTOCOL_UNPUBLISHED_LF_CRLF_FALSE_NEGATIVE"
    ),
    independent_audit_relative_path=(
        "build/pe_four_model_heldout_seed_precommit_independent_audit_r3_20260824T134417.json"
    ),
    independent_audit_raw_sha256=(
        "1346dab6e1db469a5b20f18d19ef2fd6789f2c189daa9b6dcd4df4f88dfef017"
    ),
    independent_audit_schema=("expected_pe.four_model.r3_seed_precommit_independent_audit.v1"),
    independent_audit_status="GO_R3_SINGLE_RESERVATION_PRETRUTH",
    independent_audit_semantic_sha256=(
        "14fce16cdf51238e5bf25fcc6729fd9982ab0740edae09f386492c781f7d9f1d"
    ),
    precommit_relative_path=("build/pe_four_model_heldout_seed_precommit_r3_20260824T134417.json"),
    precommit_raw_sha256=("1655629b3399bf767e76e4ba44796b03dc2b66874101507497ed96042c308540"),
    terminal_relative_path=(
        "outputs/model_zoo_pe_four_model_heldout_prediction_terminal_failure_"
        "r2_20260824T000005/TERMINAL_FAILURE.json"
    ),
    terminal_raw_sha256=("f7eff53b76d71325a79d7fca75ea29f1b825afcf3632b39c45720adb6f114079"),
    rehearsal_relative_path=("build/pe_r3r_r3full_20260824T1235/R3_REHEARSAL_RESULT.json"),
    rehearsal_raw_sha256=("ff2ca9f00fea06d1d10b9929b7ac3074fb112cddb320806418a89fde39742c85"),
    rehearsal_status="GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE",
    registry_relative_path="outputs/v04_spent_seed_registry.json",
    registry_raw_sha256=("f584a3f8cad803b319f535be14d5ac11d87ff851ac91f9ce670b112d0c3569dd"),
    registry_size_bytes=16_553,
    registry_self_sha256=("359388362e090e10674ce70d70722f7309b1e1463c9e2e203f825ac64029b141"),
    registry_entry_count=12,
    globally_spent_seed_count=146,
    maximum_reserved_seed=7829,
    registry_lf_raw_sha256=("75f458ec52ab7c4d57cb7e57fffb59eaba240258e86f1ff154a481d99043ea41"),
    registry_lf_size_bytes=16_047,
    registry_crlf_count=506,
    registry_bare_lf_count=0,
    registry_lock_relative_path="outputs/v04_spent_seed_registry.json.lock",
    registry_temp_glob=".v04_spent_seed_registry.json.*.tmp",
    predecessor_raw_sha256=("a8658fd084c8786212e4560459df4c83f6f2ed44f8365670c290dfe4fcfb20ec"),
    predecessor_self_sha256=("2678b6de5be0779079e11cdfc69a3c0ffc6b9fc68b312b97d5c490c3ea6aa533"),
    predecessor_entry_count=11,
    predecessor_last_entry_sha256=(
        "b369ddf802b08927501e218843f37677dfedfc7299b576e146ceae3242cd5c94"
    ),
    reservation_sequence=12,
    reservation_entry_sha256=("b70de4f15079bc657aa8ac00f37363f645ed6cadf74e554c5b54e277a5f8a973"),
    reservation_id=("be2a7e8a410d134ca9b7a94388d44908d72cedbf2282de44d3b31e1236816104"),
    reservation_created_at_utc="2026-08-24T06:18:08.372969+00:00",
    source_config_sha256=("00940a2bba079eeaccb8f62ab43f6985ed797fb0becfea90a876d7af5ca5ba8b"),
    candidate_config_sha256=("1c869f120339cc2ddf13d27c26a968294d059ad21e6bc62f675fb5ffcdaeab27"),
    reservation_policy_config_sha256=(
        "260081abb8f8a1557437049a46b141fc0f76d537b7758a0773f93c0b27f9b2cd"
    ),
    quarantine_seeds=(7727, 7741, 7753, 7757, 7759),
    heldout_seeds=(7789, 7793, 7817, 7823, 7829),
    heldout_seed_commitment_sha256=(
        "517acd3b8e033dc10087a1ae8ff8ef237a00b8c193ab758796860ff2dc575ede"
    ),
    output_root_relative_path=(
        "outputs/model_zoo_pe_four_model_heldout_r3_reservation_r3_20260824T134417"
    ),
    protocol_leaf="promotion_policy.lock.json",
    protocol_schema="expected_pe.four_model.r3_protocol_lock.v1",
    protocol_status="FROZEN_R3_SEEDS_RESERVED_ONCE_PRETRUTH",
    protocol_raw_sha256=("da0208d19265f06606a75ef1f7cf6037d6bf56ee07974b1b64516335775aff49"),
    protocol_size_bytes=4_388,
    protocol_binding_semantic_sha256=(
        "880fd56c06312dff4745381690446df0fd14be45b32b4f7a540eef4cadfb2667"
    ),
    protocol_policy_lock_sha256=(
        "faee33bbb3c07a0c8b57dcb5a602cda30246971b1987d4107c323c7bc4f6c2fc"
    ),
)


@dataclass(frozen=True)
class RuntimeBindings:
    canonical_pretty_bytes: Callable[[object], bytes]
    semantic_sha256: Callable[[object], str]
    safe_run_id: Callable[[object], str]
    build_protocol_lock: Callable[..., Mapping[str, object]]
    validate_protocol_lock: Callable[..., Mapping[str, object]]
    read_protocol_lock: Callable[..., Mapping[str, object]]
    verify_live_protocol_evidence: Callable[[Path, Mapping[str, Any]], None]
    read_registry: Callable[[Path], Mapping[str, Any]]
    verify_registry: Callable[[Mapping[str, Any]], None]
    reservation_contract_from_entry: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    reservation_id: Callable[[Mapping[str, Any]], str]
    canonical_output_root: Callable[[Path], str]
    registry_jsonable: Callable[[object], object]
    baseline_spent_seeds: tuple[int, ...]
    registry_format_version: int
    registry_id: str
    heldout_seeds: tuple[int, ...]
    quarantine_seeds: tuple[int, ...]
    heldout_seed_commitment_sha256: str
    precommit_relative_path: str
    precommit_raw_sha256: str
    terminal_relative_path: str
    terminal_raw_sha256: str
    rehearsal_relative_path: str
    rehearsal_raw_sha256: str
    independent_audit_relative_path: str
    independent_audit_raw_sha256: str
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


@dataclass(frozen=True)
class PinnedJson:
    relative_path: str
    raw_sha256: str
    raw: bytes
    value: Mapping[str, Any]


@dataclass(frozen=True)
class CompletionPlan:
    project_root: Path
    expected: ExpectedState
    runtime: RuntimeBindings
    authority: PinnedJson
    registry_path: Path
    registry_raw: bytes
    registry: Mapping[str, Any]
    reservation_entry: Mapping[str, Any]
    protocol_path: Path
    protocol: Mapping[str, object]
    protocol_raw: bytes
    source_manifest: Mapping[str, object]
    report: Mapping[str, object]


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R3ProtocolLeafCompletionError("R3 protocol leaf completion requires -I -B")
    if sys.pycache_prefix is None:
        raise R3ProtocolLeafCompletionError("R3 protocol leaf completion pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise R3ProtocolLeafCompletionError(
            "R3 protocol leaf completion pycache prefix is not empty"
        )
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _semantic_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise R3ProtocolLeafCompletionError("semantic JSON encoding failed") from exc
    return _sha256(raw)


def _canonical_pretty_bytes(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError) as exc:
        raise R3ProtocolLeafCompletionError("canonical JSON encoding failed") from exc


def _hash(value: object, *, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None or value == "0" * 64:
        raise R3ProtocolLeafCompletionError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def _relative(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise R3ProtocolLeafCompletionError(f"{label} is not a POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
    ):
        raise R3ProtocolLeafCompletionError(f"{label} normalization differs")
    return value


def _project_file(project: Path, relative: str, *, must_exist: bool = True) -> Path:
    clean = _relative(relative, label="project file")
    candidate = (project / clean).resolve(strict=must_exist)
    try:
        observed = candidate.relative_to(project).as_posix()
    except ValueError as exc:
        raise R3ProtocolLeafCompletionError("project file escaped repository") from exc
    if observed != clean:
        raise R3ProtocolLeafCompletionError("project file path normalization differs")
    if must_exist and (not candidate.is_file() or candidate.is_symlink()):
        raise R3ProtocolLeafCompletionError("project evidence file type differs")
    return candidate


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise R3ProtocolLeafCompletionError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                R3ProtocolLeafCompletionError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3ProtocolLeafCompletionError(f"{label} JSON differs") from exc
    if type(value) is not dict:
        raise R3ProtocolLeafCompletionError(f"{label} is not an object")
    return value


def _stable_read(path: Path, *, label: str) -> bytes:
    first = path.read_bytes()
    second = path.read_bytes()
    if first != second:
        raise R3ProtocolLeafCompletionError(f"{label} changed across stable read")
    return first


def _read_pinned_json(
    project: Path,
    relative: str,
    raw_sha256: str,
    *,
    label: str,
    require_canonical: bool = True,
) -> PinnedJson:
    path = _project_file(project, relative)
    raw = _stable_read(path, label=label)
    expected_raw = _hash(raw_sha256, label=f"{label} raw SHA-256")
    if _sha256(raw) != expected_raw:
        raise R3ProtocolLeafCompletionError(f"{label} live raw SHA-256 differs")
    value = _strict_json_object(raw, label=label)
    if require_canonical and _canonical_pretty_bytes(value) != raw:
        raise R3ProtocolLeafCompletionError(f"{label} canonical bytes differ")
    return PinnedJson(relative, expected_raw, raw, value)


def completion_authority_unsigned_template(
    *,
    completion_tool_raw_sha256: str,
    completion_test_raw_sha256: str,
    expected: ExpectedState = FORMAL,
) -> dict[str, object]:
    """Return the exact receipt body to seal after source/test hashes stabilize."""

    tool_hash = _hash(completion_tool_raw_sha256, label="completion tool raw SHA-256")
    test_hash = _hash(completion_test_raw_sha256, label="completion test raw SHA-256")
    return {
        "schema_version": AUTHORITY_SCHEMA,
        "status": AUTHORITY_STATUS,
        "run_id": expected.run_id,
        "access_counts": {
            "formal_generation_count": 0,
            "heldout_content_open_count": 0,
            "performance_content_consulted_count": 0,
            "score_open_count": 0,
            "truth_open_count": 0,
            "vault_open_count": 0,
        },
        "authority_scope": {
            "append_already_performed": True,
            "completion_failure_is_terminal_no_retry": True,
            "completion_retry_allowed": False,
            "formal_generation_allowed": False,
            "heldout_content_open_allowed": False,
            "new_seed_reservation_allowed": False,
            "original_helper_apply_retry_allowed": False,
            "protocol_leaf_create_count_authorized": 1,
            "protocol_leaf_overwrite_allowed": False,
            "registry_lock_allowed": False,
            "registry_write_allowed": False,
            "score_open_allowed": False,
            "seed_value_change_allowed": False,
            "separate_validator_subprocess_required": True,
            "scope": AUTHORITY_SCOPE,
            "truth_open_allowed": False,
        },
        "completion_action_counts": {
            "additional_seed_reservation_count": 0,
            "formal_generation_count": 0,
            "generation_count": 0,
            "helper_apply_count": 0,
            "heldout_content_open_count": 0,
            "original_helper_apply_count": 0,
            "protocol_leaf_create_count": 1,
            "registry_append_count": 0,
            "registry_lock_count": 0,
            "reservation_count": 0,
            "registry_write_count": 0,
            "score_open_count": 0,
            "seed_value_change_count": 0,
            "truth_open_count": 0,
        },
        "implementation_bindings": {
            "completion_tool": {
                "relative_path": expected.tool_relative_path,
                "raw_sha256": tool_hash,
            },
            "completion_test": {
                "relative_path": expected.test_relative_path,
                "raw_sha256": test_hash,
            },
        },
        "evidence_bindings": {
            "reservation_execution_gate": {
                "relative_path": expected.execution_gate_relative_path,
                "raw_sha256": expected.execution_gate_raw_sha256,
                "schema_version": expected.execution_gate_schema,
                "status": expected.execution_gate_status,
            },
            "reservation_apply_forensic": {
                "relative_path": expected.apply_forensic_relative_path,
                "raw_sha256": expected.apply_forensic_raw_sha256,
                "schema_version": expected.apply_forensic_schema,
                "status": expected.apply_forensic_status,
            },
            "independent_seed_precommit_audit": {
                "relative_path": expected.independent_audit_relative_path,
                "raw_sha256": expected.independent_audit_raw_sha256,
                "schema_version": expected.independent_audit_schema,
                "status": expected.independent_audit_status,
                "audit_semantic_sha256": (expected.independent_audit_semantic_sha256),
            },
        },
        "registry_expectation": {
            "relative_path": expected.registry_relative_path,
            "actual_raw_sha256": expected.registry_raw_sha256,
            "actual_size_bytes": expected.registry_size_bytes,
            "registry_self_sha256": expected.registry_self_sha256,
            "entry_count": expected.registry_entry_count,
            "globally_spent_seed_count": expected.globally_spent_seed_count,
            "maximum_reserved_seed": expected.maximum_reserved_seed,
            "expected_lf_raw_sha256": expected.registry_lf_raw_sha256,
            "expected_lf_size_bytes": expected.registry_lf_size_bytes,
            "actual_crlf_count": expected.registry_crlf_count,
            "actual_bare_lf_count": expected.registry_bare_lf_count,
            "actual_is_exact_crlf_expansion_of_expected_lf": True,
            "actual_and_lf_raw_sha256_differ": True,
            "registry_lock_relative_path": expected.registry_lock_relative_path,
            "registry_temp_glob": expected.registry_temp_glob,
            "predecessor": {
                "raw_sha256": expected.predecessor_raw_sha256,
                "registry_self_sha256": expected.predecessor_self_sha256,
                "entry_count": expected.predecessor_entry_count,
                "last_entry_sha256": expected.predecessor_last_entry_sha256,
            },
        },
        "reservation_expectation": {
            "sequence": expected.reservation_sequence,
            "entry_sha256": expected.reservation_entry_sha256,
            "reservation_id": expected.reservation_id,
            "previous_entry_sha256": expected.predecessor_last_entry_sha256,
            "created_at_utc": expected.reservation_created_at_utc,
            "source_config_sha256": expected.source_config_sha256,
            "candidate_config_sha256": expected.candidate_config_sha256,
            "policy_config_sha256": expected.reservation_policy_config_sha256,
            "quarantine_seeds_never_generate_or_score": list(expected.quarantine_seeds),
            "heldout_seeds_in_order": list(expected.heldout_seeds),
            "heldout_seed_commitment_sha256": (expected.heldout_seed_commitment_sha256),
            "reserved_seeds_in_order": sorted(
                (*expected.quarantine_seeds, *expected.heldout_seeds)
            ),
            "owner_output_root_relative_path": (expected.output_root_relative_path),
        },
        "protocol_expectation": {
            "relative_path": expected.protocol_relative_path,
            "schema_version": expected.protocol_schema,
            "status": expected.protocol_status,
            "raw_sha256": expected.protocol_raw_sha256,
            "size_bytes": expected.protocol_size_bytes,
            "r2_protocol_binding_semantic_sha256": (expected.protocol_binding_semantic_sha256),
            "policy_lock_sha256": expected.protocol_policy_lock_sha256,
        },
    }


def seal_completion_authority(
    unsigned: Mapping[str, object],
) -> dict[str, object]:
    """Seal a template without introducing a self-hash/raw-hash cycle."""

    core = dict(unsigned)
    if "completion_authority_semantic_sha256" in core:
        raise R3ProtocolLeafCompletionError("completion authority is already sealed")
    return {
        **core,
        "completion_authority_semantic_sha256": _semantic_sha256(core),
    }


def _read_completion_authority(
    *,
    project: Path,
    authority_path: Path,
    authority_raw_sha256: str,
    expected: ExpectedState,
) -> PinnedJson:
    candidate = authority_path
    if not candidate.is_absolute():
        candidate = project / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise R3ProtocolLeafCompletionError("completion authority is absent or unreadable") from exc
    try:
        relative = resolved.relative_to(project).as_posix()
    except ValueError as exc:
        raise R3ProtocolLeafCompletionError("completion authority escaped repository") from exc
    if relative != expected.authority_relative_path:
        raise R3ProtocolLeafCompletionError("completion authority canonical relative path differs")
    executing_tool = Path(__file__).resolve(strict=True)
    expected_tool = _project_file(project, expected.tool_relative_path)
    if executing_tool != expected_tool:
        raise R3ProtocolLeafCompletionError(
            "executing completion tool is not the authority-pinned project source"
        )
    pinned = _read_pinned_json(
        project,
        relative,
        authority_raw_sha256,
        label="R3 protocol leaf completion authority",
    )
    tool_raw = _stable_read(
        expected_tool,
        label="completion tool source",
    )
    test_raw = _stable_read(
        _project_file(project, expected.test_relative_path),
        label="completion test source",
    )
    expected_unsigned = completion_authority_unsigned_template(
        completion_tool_raw_sha256=_sha256(tool_raw),
        completion_test_raw_sha256=_sha256(test_raw),
        expected=expected,
    )
    expected_value = seal_completion_authority(expected_unsigned)
    if pinned.value != expected_value:
        raise R3ProtocolLeafCompletionError("completion authority exact content/source pins differ")
    return pinned


def _validate_evidence(project: Path, expected: ExpectedState) -> None:
    gate = _read_pinned_json(
        project,
        expected.execution_gate_relative_path,
        expected.execution_gate_raw_sha256,
        label="R3 reservation execution gate",
    ).value
    authorization = gate.get("authorization")
    allocation = gate.get("formal_seed_allocation")
    access = gate.get("access_state")
    if (
        gate.get("schema_version") != expected.execution_gate_schema
        or gate.get("status") != expected.execution_gate_status
        or gate.get("run_id") != expected.run_id
        or type(authorization) is not dict
        or authorization.get("additional_reservation_allowed") is not False
        or authorization.get("apply_call_count_authorized") != 1
        or authorization.get("automatic_retry_allowed") is not False
        or type(allocation) is not dict
        or allocation.get("quarantine_seeds_never_generate_or_score")
        != list(expected.quarantine_seeds)
        or allocation.get("heldout_seeds_in_order") != list(expected.heldout_seeds)
        or allocation.get("heldout_seed_commitment_sha256")
        != expected.heldout_seed_commitment_sha256
        or type(access) is not dict
        or any(value != 0 for value in access.values())
    ):
        raise R3ProtocolLeafCompletionError("R3 reservation execution gate content differs")

    forensic = _read_pinned_json(
        project,
        expected.apply_forensic_relative_path,
        expected.apply_forensic_raw_sha256,
        label="R3 reservation apply forensic",
    ).value
    serialization = forensic.get("serialization_forensics")
    registry_after = forensic.get("registry_after")
    registry_before = forensic.get("registry_before")
    entry = forensic.get("reservation_entry")
    root = forensic.get("reservation_root_state")
    reconstruction = forensic.get("in_memory_protocol_reconstruction")
    verdict = forensic.get("verdict")
    access_counts = forensic.get("access_counts")
    if (
        forensic.get("schema_version") != expected.apply_forensic_schema
        or forensic.get("status") != expected.apply_forensic_status
        or forensic.get("run_id") != expected.run_id
        or type(serialization) is not dict
        or serialization.get("actual_raw_sha256") != expected.registry_raw_sha256
        or serialization.get("expected_lf_raw_sha256") != expected.registry_lf_raw_sha256
        or serialization.get("actual_was_exact_crlf_expansion_of_expected_lf") is not True
        or serialization.get("semantic_or_hash_chain_corruption") is not False
        or type(registry_after) is not dict
        or registry_after.get("raw_sha256") != expected.registry_raw_sha256
        or registry_after.get("registry_self_sha256") != expected.registry_self_sha256
        or registry_after.get("entry_count") != expected.registry_entry_count
        or registry_after.get("last_entry_sha256") != expected.reservation_entry_sha256
        or type(registry_before) is not dict
        or registry_before.get("raw_sha256") != expected.predecessor_raw_sha256
        or registry_before.get("registry_self_sha256") != expected.predecessor_self_sha256
        or registry_before.get("entry_count") != expected.predecessor_entry_count
        or registry_before.get("last_entry_sha256") != expected.predecessor_last_entry_sha256
        or type(entry) is not dict
        or entry.get("entry_sha256") != expected.reservation_entry_sha256
        or entry.get("reservation_id") != expected.reservation_id
        or entry.get("source_config_sha256") != expected.source_config_sha256
        or entry.get("candidate_config_sha256") != expected.candidate_config_sha256
        or entry.get("policy_config_sha256") != expected.reservation_policy_config_sha256
        or type(root) is not dict
        or root.get("child_count") != 0
        or root.get("protocol_lock_exists") is not False
        or root.get("active_registry_lock_exists") is not False
        or root.get("temporary_registry_file_exists") is not False
        or type(reconstruction) is not dict
        or reconstruction.get("protocol_raw_sha256") != expected.protocol_raw_sha256
        or reconstruction.get("protocol_binding_semantic_sha256")
        != expected.protocol_binding_semantic_sha256
        or reconstruction.get("policy_lock_sha256") != expected.protocol_policy_lock_sha256
        or reconstruction.get("source_manifest_matches_reservation_entry") is not True
        or type(verdict) is not dict
        or verdict.get("registry_append_is_valid_and_consumed") is not True
        or verdict.get("helper_apply_retry_allowed") is not False
        or verdict.get("additional_seed_or_registry_reservation_allowed") is not False
        or verdict.get("protocol_leaf_only_completion_requires_separate_frozen_authority")
        is not True
        or type(access_counts) is not dict
        or any(value != 0 for value in access_counts.values())
    ):
        raise R3ProtocolLeafCompletionError("R3 reservation apply forensic content differs")

    audit = _read_pinned_json(
        project,
        expected.independent_audit_relative_path,
        expected.independent_audit_raw_sha256,
        label="R3 independent seed precommit audit",
    ).value
    unsigned_audit = dict(audit)
    stored_audit = unsigned_audit.pop("audit_semantic_sha256", None)
    if (
        audit.get("schema_version") != expected.independent_audit_schema
        or audit.get("status") != expected.independent_audit_status
        or audit.get("run_id") != expected.run_id
        or audit.get("append_performed") is not False
        or stored_audit != expected.independent_audit_semantic_sha256
        or stored_audit != _semantic_sha256(unsigned_audit)
    ):
        raise R3ProtocolLeafCompletionError("R3 independent seed precommit audit content differs")


def _assert_sidecars_absent(project: Path, expected: ExpectedState) -> None:
    lock_path = _project_file(project, expected.registry_lock_relative_path, must_exist=False)
    if lock_path.exists():
        raise R3ProtocolLeafCompletionError("registry lock exists")
    registry_parent = _project_file(project, expected.registry_relative_path).parent
    if list(registry_parent.glob(expected.registry_temp_glob)):
        raise R3ProtocolLeafCompletionError("registry temporary file exists")


def _assert_output_root(
    project: Path, expected: ExpectedState, *, leaf_state: str
) -> tuple[Path, Path]:
    root = (project / expected.output_root_relative_path).resolve(strict=True)
    try:
        relative = root.relative_to(project).as_posix()
    except ValueError as exc:
        raise R3ProtocolLeafCompletionError("completion output root escaped") from exc
    if relative != expected.output_root_relative_path or not root.is_dir() or root.is_symlink():
        raise R3ProtocolLeafCompletionError("completion output root type differs")
    children = list(root.iterdir())
    leaf = root / expected.protocol_leaf
    if leaf_state == "absent":
        if children or leaf.exists():
            raise R3ProtocolLeafCompletionError("completion target root is not exactly empty")
    elif leaf_state == "sole":
        if (
            len(children) != 1
            or children[0].name != expected.protocol_leaf
            or not leaf.is_file()
            or leaf.is_symlink()
        ):
            raise R3ProtocolLeafCompletionError(
                "completed output root is not the exact sole protocol leaf"
            )
    else:
        raise AssertionError(f"unsupported leaf state: {leaf_state}")
    return root, leaf


def _registry_lf_bytes(runtime: RuntimeBindings, registry: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                runtime.registry_jsonable(registry),
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise R3ProtocolLeafCompletionError("registry LF serialization failed") from exc


def _read_registry_exact(
    project: Path, expected: ExpectedState, runtime: RuntimeBindings
) -> tuple[Path, bytes, Mapping[str, Any], Mapping[str, Any]]:
    registry_path = _project_file(project, expected.registry_relative_path)
    raw_before = _stable_read(registry_path, label="spent-seed registry")
    if (
        _sha256(raw_before) != expected.registry_raw_sha256
        or len(raw_before) != expected.registry_size_bytes
    ):
        raise R3ProtocolLeafCompletionError("actual registry raw bytes differ")
    try:
        registry = runtime.read_registry(registry_path)
        runtime.verify_registry(registry)
    except Exception as exc:
        raise R3ProtocolLeafCompletionError("authoritative registry validation failed") from exc
    raw_after = _stable_read(registry_path, label="spent-seed registry")
    if raw_after != raw_before:
        raise R3ProtocolLeafCompletionError("spent-seed registry changed during validation")
    lf = _registry_lf_bytes(runtime, registry)
    crlf = lf.replace(b"\n", b"\r\n")
    bare_lf_count = raw_before.count(b"\n") - raw_before.count(b"\r\n")
    if (
        _sha256(lf) != expected.registry_lf_raw_sha256
        or len(lf) != expected.registry_lf_size_bytes
        or _sha256(lf) == expected.registry_raw_sha256
        or raw_before != crlf
        or raw_before.count(b"\r\n") != expected.registry_crlf_count
        or bare_lf_count != expected.registry_bare_lf_count
    ):
        raise R3ProtocolLeafCompletionError("registry LF/CRLF forensic proof differs")
    entries = registry.get("entries")
    if (
        registry.get("registry_sha256") != expected.registry_self_sha256
        or type(entries) is not list
        or len(entries) != expected.registry_entry_count
        or not entries
        or type(entries[-1]) is not dict
    ):
        raise R3ProtocolLeafCompletionError("registry exact sealed state differs")
    entry = entries[-1]
    try:
        contract = runtime.reservation_contract_from_entry(entry)
        derived_reservation_id = runtime.reservation_id(contract)
    except Exception as exc:
        raise R3ProtocolLeafCompletionError("last reservation contract validation failed") from exc
    owner = runtime.canonical_output_root(project / expected.output_root_relative_path)
    expected_reserved = sorted((*expected.quarantine_seeds, *expected.heldout_seeds))
    if (
        entry.get("sequence") != expected.reservation_sequence
        or entry.get("entry_sha256") != expected.reservation_entry_sha256
        or entry.get("reservation_id") != expected.reservation_id
        or derived_reservation_id != expected.reservation_id
        or entry.get("previous_entry_sha256") != expected.predecessor_last_entry_sha256
        or entry.get("created_at_utc") != expected.reservation_created_at_utc
        or entry.get("source_config_sha256") != expected.source_config_sha256
        or entry.get("candidates_sha256") != expected.candidate_config_sha256
        or entry.get("policy_config_sha256") != expected.reservation_policy_config_sha256
        or entry.get("tuning_seeds") != list(expected.quarantine_seeds)
        or entry.get("locked_seeds") != list(expected.heldout_seeds)
        or entry.get("reserved_seeds") != expected_reserved
        or entry.get("owner_output_root") != owner
        or contract.get("source_config_sha256") != expected.source_config_sha256
        or contract.get("candidates_sha256") != expected.candidate_config_sha256
        or contract.get("policy_config_sha256") != expected.reservation_policy_config_sha256
    ):
        raise R3ProtocolLeafCompletionError("consumed R3 reservation entry differs")
    spent = set(runtime.baseline_spent_seeds)
    for row in entries:
        if type(row) is not dict or type(row.get("reserved_seeds")) is not list:
            raise R3ProtocolLeafCompletionError("registry seed accounting differs")
        spent.update(row["reserved_seeds"])
    if (
        len(spent) != expected.globally_spent_seed_count
        or max(spent) != expected.maximum_reserved_seed
    ):
        raise R3ProtocolLeafCompletionError("registry global spent-seed accounting differs")
    return registry_path, raw_before, registry, entry


def _protocol_binding(
    *,
    project: Path,
    expected: ExpectedState,
    runtime: RuntimeBindings,
    registry: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> dict[str, object]:
    contract = runtime.reservation_contract_from_entry(entry)
    receipt = {
        "format_version": runtime.registry_format_version,
        "registry_id": runtime.registry_id,
        "registry_path": str((project / expected.registry_relative_path).resolve(strict=True)),
        "genesis_sha256": registry["genesis_sha256"],
        "reservation_id": expected.reservation_id,
        "reservation_sequence": expected.reservation_sequence,
        "reservation_entry_sha256": expected.reservation_entry_sha256,
    }
    transition = {
        "registry_relative_path": expected.registry_relative_path,
        "registry_before_raw_sha256": expected.predecessor_raw_sha256,
        "registry_after_raw_sha256": expected.registry_raw_sha256,
        "entry_count_before": expected.predecessor_entry_count,
        "entry_count_after": expected.registry_entry_count,
        "append_count": 1,
        "previous_entry_sha256": expected.predecessor_last_entry_sha256,
        "reservation_entry_sha256": expected.reservation_entry_sha256,
        "reservation_created_at_utc": expected.reservation_created_at_utc,
    }
    return {
        # These R2-named fields are the intentionally preserved R3 wire schema.
        "r1_terminal_failure": {
            "relative_path": expected.terminal_relative_path,
            "raw_sha256": expected.terminal_raw_sha256,
        },
        "replacement_seed_precommit": {
            "relative_path": expected.precommit_relative_path,
            "raw_sha256": expected.precommit_raw_sha256,
        },
        "final_nonreserved_preflight": {
            "relative_path": expected.rehearsal_relative_path,
            "raw_sha256": expected.rehearsal_raw_sha256,
            "status": expected.rehearsal_status,
            "reserved_generator_invocation_count": 0,
            "truth_leakage_count": 0,
            "heldout_access_count": 0,
            "score_open_count": 0,
            "registry_mutation_count": 0,
        },
        "quarantine_seeds_never_generate_or_score": list(expected.quarantine_seeds),
        "heldout_seeds_in_order": list(expected.heldout_seeds),
        "heldout_seed_commitment_sha256": (expected.heldout_seed_commitment_sha256),
        "reservation_contract": dict(contract),
        "spent_seed_reservation": receipt,
        "registry_transition": transition,
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


def _build_protocol_exact(
    *,
    project: Path,
    expected: ExpectedState,
    runtime: RuntimeBindings,
    registry: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> tuple[Mapping[str, object], bytes]:
    binding = _protocol_binding(
        project=project,
        expected=expected,
        runtime=runtime,
        registry=registry,
        entry=entry,
    )
    try:
        protocol = runtime.build_protocol_lock(
            run_id=expected.run_id,
            r2_protocol_binding=binding,
        )
        validated = runtime.validate_protocol_lock(
            protocol,
            expected_run_id=expected.run_id,
            project_root=project,
            expected_lock_relative_path=expected.protocol_relative_path,
        )
        raw = runtime.canonical_pretty_bytes(protocol)
        runtime.verify_live_protocol_evidence(project, protocol)
    except Exception as exc:
        raise R3ProtocolLeafCompletionError(
            "existing-wire R3 protocol reconstruction failed"
        ) from exc
    if (
        validated != protocol
        or protocol.get("schema_version") != expected.protocol_schema
        or protocol.get("status") != expected.protocol_status
        or protocol.get("run_id") != expected.run_id
        or protocol.get("r2_protocol_binding") != binding
        or protocol.get("r2_protocol_binding_semantic_sha256")
        != expected.protocol_binding_semantic_sha256
        or protocol.get("policy_lock_sha256") != expected.protocol_policy_lock_sha256
        or _sha256(raw) != expected.protocol_raw_sha256
        or len(raw) != expected.protocol_size_bytes
        or raw != _canonical_pretty_bytes(protocol)
    ):
        raise R3ProtocolLeafCompletionError("existing-wire R3 protocol exact hashes/content differ")
    return protocol, raw


def _validate_source_candidate_closure(
    *,
    project: Path,
    expected: ExpectedState,
    runtime: RuntimeBindings,
    entry: Mapping[str, Any],
) -> Mapping[str, object]:
    if (
        runtime.safe_run_id(expected.run_id) != expected.run_id
        or tuple(runtime.heldout_seeds) != expected.heldout_seeds
        or tuple(runtime.quarantine_seeds) != expected.quarantine_seeds
        or runtime.heldout_seed_commitment_sha256 != expected.heldout_seed_commitment_sha256
        or runtime.precommit_relative_path != expected.precommit_relative_path
        or runtime.precommit_raw_sha256 != expected.precommit_raw_sha256
        or runtime.terminal_relative_path != expected.terminal_relative_path
        or runtime.terminal_raw_sha256 != expected.terminal_raw_sha256
        or runtime.rehearsal_relative_path != expected.rehearsal_relative_path
        or runtime.rehearsal_raw_sha256 != expected.rehearsal_raw_sha256
        or runtime.independent_audit_relative_path != expected.independent_audit_relative_path
        or runtime.independent_audit_raw_sha256 != expected.independent_audit_raw_sha256
        or runtime.protocol_schema != expected.protocol_schema
        or runtime.protocol_status != expected.protocol_status
        or runtime.protocol_leaf != expected.protocol_leaf
        or not expected.output_root_relative_path.endswith(
            f"{runtime.protocol_root_prefix}{expected.run_id}"
        )
    ):
        raise R3ProtocolLeafCompletionError(
            "live producer R3 constants differ from completion authority"
        )
    try:
        source = runtime.build_source_manifest(**runtime.source_manifest_inputs(project))
        generation = runtime.generation_plan()
    except Exception as exc:
        raise R3ProtocolLeafCompletionError(
            "live producer source/generation closure failed"
        ) from exc
    candidate_config = {
        "model_ids_in_order": list(runtime.model_ids_in_order),
        "survivor_ids_in_qualification_rank_order": list(runtime.survivor_ids_in_order),
        "source_model_versions": dict(runtime.source_model_versions),
        "formula_lock": dict(runtime.formula_lock),
        "formula_lock_semantic_sha256": runtime.semantic_sha256(runtime.formula_lock),
        "generation_plan": dict(generation),
    }
    if (
        source.get("source_manifest_semantic_sha256") != expected.source_config_sha256
        or entry.get("source_config_sha256") != source.get("source_manifest_semantic_sha256")
        or runtime.semantic_sha256(candidate_config) != expected.candidate_config_sha256
        or entry.get("candidates_sha256") != expected.candidate_config_sha256
        or generation.get("heldout_seeds_in_order") != list(expected.heldout_seeds)
        or generation.get("estimator_rng_seeds_in_order") != list(expected.heldout_seeds)
        or generation.get("task_count") != 50
        or generation.get("identity_count") != 64_800
        or generation.get("prediction_row_count") != 259_200
    ):
        raise R3ProtocolLeafCompletionError("reservation-time source/candidate closure differs")
    return source


def build_completion_plan(
    *,
    project_root: Path,
    completion_authority: Path,
    completion_authority_raw_sha256: str,
    runtime: RuntimeBindings,
    expected: ExpectedState = FORMAL,
) -> CompletionPlan:
    """Build a read-only exact plan; the target must still be an empty root."""

    project = Path(project_root).resolve(strict=True)
    authority = _read_completion_authority(
        project=project,
        authority_path=completion_authority,
        authority_raw_sha256=completion_authority_raw_sha256,
        expected=expected,
    )
    _validate_evidence(project, expected)
    _assert_sidecars_absent(project, expected)
    _, protocol_path = _assert_output_root(project, expected, leaf_state="absent")
    registry_path, registry_raw, registry, entry = _read_registry_exact(project, expected, runtime)
    protocol, protocol_raw = _build_protocol_exact(
        project=project,
        expected=expected,
        runtime=runtime,
        registry=registry,
        entry=entry,
    )
    source = _validate_source_candidate_closure(
        project=project,
        expected=expected,
        runtime=runtime,
        entry=entry,
    )
    if _stable_read(registry_path, label="spent-seed registry") != registry_raw:
        raise R3ProtocolLeafCompletionError("registry changed across completion planning")
    _assert_sidecars_absent(project, expected)
    _assert_output_root(project, expected, leaf_state="absent")
    report = {
        "schema_version": "expected_pe.four_model.r3_protocol_leaf_completion.v1",
        "status": DRY_RUN_STATUS,
        "run_id": expected.run_id,
        "completion_authority_ref": {
            "relative_path": authority.relative_path,
            "raw_sha256": authority.raw_sha256,
            "completion_authority_semantic_sha256": authority.value[
                "completion_authority_semantic_sha256"
            ],
        },
        "registry_raw_sha256": expected.registry_raw_sha256,
        "registry_self_sha256": expected.registry_self_sha256,
        "registry_entry_count": expected.registry_entry_count,
        "reservation_entry_sha256": expected.reservation_entry_sha256,
        "reservation_id": expected.reservation_id,
        "protocol_lock_relative_path": expected.protocol_relative_path,
        "protocol_lock_raw_sha256": expected.protocol_raw_sha256,
        "protocol_binding_semantic_sha256": (expected.protocol_binding_semantic_sha256),
        "protocol_leaf_create_count": 0,
        "additional_seed_reservation_count": 0,
        "formal_generation_count": 0,
        "generation_count": 0,
        "helper_apply_count": 0,
        "seed_value_change_count": 0,
        "registry_append_count": 0,
        "registry_write_count": 0,
        "registry_lock_count": 0,
        "reservation_count": 0,
        "original_helper_apply_count": 0,
        "original_helper_retry_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    return CompletionPlan(
        project_root=project,
        expected=expected,
        runtime=runtime,
        authority=authority,
        registry_path=registry_path,
        registry_raw=registry_raw,
        registry=registry,
        reservation_entry=entry,
        protocol_path=protocol_path,
        protocol=protocol,
        protocol_raw=protocol_raw,
        source_manifest=source,
        report=report,
    )


def _write_new_leaf(path: Path, raw: bytes) -> None:
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
                raise R3ProtocolLeafCompletionError("protocol leaf write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_completed_state(
    *,
    project_root: Path,
    completion_authority: Path,
    completion_authority_raw_sha256: str,
    runtime: RuntimeBindings,
    expected: ExpectedState = FORMAL,
) -> Mapping[str, object]:
    """Fresh-process validation of the sole leaf and unchanged live closure."""

    project = Path(project_root).resolve(strict=True)
    authority = _read_completion_authority(
        project=project,
        authority_path=completion_authority,
        authority_raw_sha256=completion_authority_raw_sha256,
        expected=expected,
    )
    _validate_evidence(project, expected)
    _assert_sidecars_absent(project, expected)
    _, protocol_path = _assert_output_root(project, expected, leaf_state="sole")
    registry_path, registry_raw, registry, entry = _read_registry_exact(project, expected, runtime)
    protocol, protocol_raw = _build_protocol_exact(
        project=project,
        expected=expected,
        runtime=runtime,
        registry=registry,
        entry=entry,
    )
    observed_raw = _stable_read(protocol_path, label="completed protocol leaf")
    if observed_raw != protocol_raw:
        raise R3ProtocolLeafCompletionError("completed protocol leaf raw bytes differ")
    try:
        reread = runtime.read_protocol_lock(
            protocol_path,
            project_root=project,
            expected_run_id=expected.run_id,
            expected_raw_sha256=expected.protocol_raw_sha256,
        )
    except Exception as exc:
        raise R3ProtocolLeafCompletionError(
            "fresh live protocol/evidence validation failed"
        ) from exc
    if reread != protocol:
        raise R3ProtocolLeafCompletionError("fresh protocol reconstruction round-trip differs")
    _validate_source_candidate_closure(
        project=project,
        expected=expected,
        runtime=runtime,
        entry=entry,
    )
    if _stable_read(registry_path, label="spent-seed registry") != registry_raw:
        raise R3ProtocolLeafCompletionError("registry changed across fresh validator")
    _assert_sidecars_absent(project, expected)
    _assert_output_root(project, expected, leaf_state="sole")
    return {
        "schema_version": ("expected_pe.four_model.r3_protocol_leaf_completion_validator.v1"),
        "status": CHILD_STATUS,
        "run_id": expected.run_id,
        "completion_authority_raw_sha256": authority.raw_sha256,
        "registry_raw_sha256": expected.registry_raw_sha256,
        "registry_entry_count": expected.registry_entry_count,
        "protocol_lock_raw_sha256": expected.protocol_raw_sha256,
        "protocol_leaf_count": 1,
        "additional_seed_reservation_count": 0,
        "formal_generation_count": 0,
        "generation_count": 0,
        "helper_apply_count": 0,
        "original_helper_apply_count": 0,
        "registry_append_count": 0,
        "registry_write_count": 0,
        "registry_lock_count": 0,
        "reservation_count": 0,
        "seed_value_change_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }


def _launch_fresh_validator(plan: CompletionPlan) -> Mapping[str, object]:
    with tempfile.TemporaryDirectory(prefix="r3_protocol_leaf_validator_") as prefix_text:
        prefix = Path(prefix_text).resolve(strict=True)
        if any(prefix.iterdir()):
            raise R3ProtocolLeafCompletionError("fresh validator pycache prefix is not empty")
        environment = dict(os.environ)
        for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONPYCACHEPREFIX"):
            environment.pop(name, None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [
            sys.executable,
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={prefix}",
            str(Path(__file__).resolve(strict=True)),
            "--_validate-child",
            "--repository-root",
            str(plan.project_root),
            "--completion-authority",
            plan.authority.relative_path,
            "--completion-authority-raw-sha256",
            plan.authority.raw_sha256,
        ]
        completed = subprocess.run(
            command,
            cwd=plan.project_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise R3ProtocolLeafCompletionError(
                f"fresh validator subprocess rejected completion: {detail}"
            )
        try:
            report = _strict_json_object(
                completed.stdout.strip().encode("utf-8"),
                label="fresh validator report",
            )
        except R3ProtocolLeafCompletionError as exc:
            raise R3ProtocolLeafCompletionError("fresh validator report JSON differs") from exc
        if (
            set(report) != CHILD_REPORT_FIELDS
            or report.get("schema_version")
            != "expected_pe.four_model.r3_protocol_leaf_completion_validator.v1"
            or report.get("status") != CHILD_STATUS
            or report.get("run_id") != plan.expected.run_id
            or report.get("completion_authority_raw_sha256") != plan.authority.raw_sha256
            or report.get("registry_raw_sha256") != plan.expected.registry_raw_sha256
            or report.get("registry_entry_count") != plan.expected.registry_entry_count
            or report.get("protocol_lock_raw_sha256") != plan.expected.protocol_raw_sha256
            or report.get("protocol_leaf_count") != 1
            or report.get("additional_seed_reservation_count") != 0
            or report.get("formal_generation_count") != 0
            or report.get("generation_count") != 0
            or report.get("helper_apply_count") != 0
            or report.get("original_helper_apply_count") != 0
            or report.get("registry_append_count") != 0
            or report.get("registry_write_count") != 0
            or report.get("registry_lock_count") != 0
            or report.get("reservation_count") != 0
            or report.get("seed_value_change_count") != 0
            or report.get("truth_open_count") != 0
            or report.get("score_open_count") != 0
            or report.get("heldout_content_open_count") != 0
        ):
            raise R3ProtocolLeafCompletionError("fresh validator report content differs")
        return report


def apply_completion_plan(plan: CompletionPlan) -> Mapping[str, object]:
    """Create exactly one leaf, then require a separate fresh validator."""

    fresh = build_completion_plan(
        project_root=plan.project_root,
        completion_authority=Path(plan.authority.relative_path),
        completion_authority_raw_sha256=plan.authority.raw_sha256,
        runtime=plan.runtime,
        expected=plan.expected,
    )
    if (
        fresh.registry_raw != plan.registry_raw
        or fresh.reservation_entry != plan.reservation_entry
        or fresh.protocol != plan.protocol
        or fresh.protocol_raw != plan.protocol_raw
        or fresh.source_manifest != plan.source_manifest
        or fresh.authority != plan.authority
        or fresh.report != plan.report
    ):
        raise R3ProtocolLeafCompletionError("completion plan drifted before leaf creation")
    # All mutation targets and bytes below come only from the independently
    # rebuilt plan.  Caller-supplied dataclass paths are never dereferenced.
    plan = fresh
    _assert_sidecars_absent(plan.project_root, plan.expected)
    _assert_output_root(plan.project_root, plan.expected, leaf_state="absent")
    if _stable_read(plan.registry_path, label="spent-seed registry") != plan.registry_raw:
        raise R3ProtocolLeafCompletionError("registry changed immediately before leaf creation")
    _read_completion_authority(
        project=plan.project_root,
        authority_path=Path(plan.authority.relative_path),
        authority_raw_sha256=plan.authority.raw_sha256,
        expected=plan.expected,
    )
    # O_EXCL is the only durable repository mutation in this tool.  A partial
    # write or any later failure deliberately leaves a no-retry forensic state.
    _write_new_leaf(plan.protocol_path, plan.protocol_raw)
    if _stable_read(plan.registry_path, label="spent-seed registry") != plan.registry_raw:
        raise R3ProtocolLeafCompletionError("registry changed after protocol leaf creation")
    child_report = _launch_fresh_validator(plan)
    if _stable_read(plan.registry_path, label="spent-seed registry") != plan.registry_raw:
        raise R3ProtocolLeafCompletionError("registry changed after fresh validator")
    _assert_sidecars_absent(plan.project_root, plan.expected)
    _assert_output_root(plan.project_root, plan.expected, leaf_state="sole")
    return {
        **plan.report,
        "status": COMPLETE_STATUS,
        "protocol_leaf_create_count": 1,
        "fresh_validator_status": child_report["status"],
    }


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
        build_protocol_lock=r2_protocol_lock.build_r2_protocol_lock,
        validate_protocol_lock=r2_protocol_lock.validate_r2_protocol_lock,
        read_protocol_lock=r2_protocol_lock.read_r2_protocol_lock,
        verify_live_protocol_evidence=r2_protocol_lock._verify_live_evidence,
        read_registry=registry._read_spent_seed_registry,
        verify_registry=registry._verify_spent_seed_registry,
        reservation_contract_from_entry=registry._reservation_contract_from_entry,
        reservation_id=registry._reservation_id,
        canonical_output_root=registry._canonical_output_root,
        registry_jsonable=registry._jsonable,
        baseline_spent_seeds=tuple(registry.SPENT_EVIDENCE_SEEDS),
        registry_format_version=registry.SPENT_SEED_REGISTRY_FORMAT_VERSION,
        registry_id=registry.SPENT_SEED_REGISTRY_ID,
        heldout_seeds=tuple(contracts.HELDOUT_SEEDS),
        quarantine_seeds=tuple(contracts.R2_QUARANTINE_SEEDS),
        heldout_seed_commitment_sha256=contracts.R2_HELDOUT_SEED_COMMITMENT_SHA256,
        precommit_relative_path=contracts.R2_REPLACEMENT_SEED_PRECOMMIT_RELATIVE_PATH,
        precommit_raw_sha256=contracts.R2_REPLACEMENT_SEED_PRECOMMIT_RAW_SHA256,
        terminal_relative_path=contracts.R2_R1_TERMINAL_FAILURE_RELATIVE_PATH,
        terminal_raw_sha256=contracts.R2_R1_TERMINAL_FAILURE_RAW_SHA256,
        rehearsal_relative_path=contracts.R2_FINAL_NONRESERVED_PREFLIGHT_RELATIVE_PATH,
        rehearsal_raw_sha256=contracts.R2_FINAL_NONRESERVED_PREFLIGHT_RAW_SHA256,
        independent_audit_relative_path=contracts.R3_INDEPENDENT_AUDIT_RELATIVE_PATH,
        independent_audit_raw_sha256=contracts.R3_INDEPENDENT_AUDIT_RAW_SHA256,
        protocol_schema=contracts.R2_PROTOCOL_LOCK_SCHEMA,
        protocol_status=contracts.R2_PROTOCOL_LOCK_STATUS,
        protocol_root_prefix=contracts.R2_PROTOCOL_LOCK_ROOT_PREFIX,
        protocol_leaf=contracts.R2_PROTOCOL_LOCK_LEAF,
        model_ids_in_order=tuple(contracts.MODEL_IDS_IN_ORDER),
        survivor_ids_in_order=tuple(contracts.SURVIVOR_IDS_IN_QUALIFICATION_RANK_ORDER),
        source_model_versions=dict(contracts.SOURCE_MODEL_VERSIONS),
        formula_lock=dict(contracts.FORMULA_LOCK),
        build_source_manifest=build_source_manifest,
        source_manifest_inputs=source_manifest_inputs,
        generation_plan=generation_plan,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Dry-run or create only the missing R3 protocol leaf"
    )
    result.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    result.add_argument("--completion-authority", type=Path, required=True)
    result.add_argument("--completion-authority-raw-sha256", required=True)
    result.add_argument(
        "--apply",
        action="store_true",
        help="create only the missing promotion_policy.lock.json leaf once",
    )
    result.add_argument(
        "--_validate-child",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    _bootstrap()
    try:
        runtime = _load_runtime()
        if arguments._validate_child:
            if arguments.apply:
                raise R3ProtocolLeafCompletionError("fresh validator cannot receive --apply")
            report = validate_completed_state(
                project_root=arguments.repository_root,
                completion_authority=arguments.completion_authority,
                completion_authority_raw_sha256=(arguments.completion_authority_raw_sha256),
                runtime=runtime,
            )
        else:
            plan = build_completion_plan(
                project_root=arguments.repository_root,
                completion_authority=arguments.completion_authority,
                completion_authority_raw_sha256=(arguments.completion_authority_raw_sha256),
                runtime=runtime,
            )
            report = apply_completion_plan(plan) if arguments.apply else plan.report
        print(
            json.dumps(
                report,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except R3ProtocolLeafCompletionError as exc:
        raise SystemExit(f"R3 protocol leaf completion rejected: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTHORITY_SCHEMA",
    "AUTHORITY_STATUS",
    "CHILD_STATUS",
    "COMPLETE_STATUS",
    "DRY_RUN_STATUS",
    "ExpectedState",
    "FORMAL",
    "R3ProtocolLeafCompletionError",
    "RuntimeBindings",
    "apply_completion_plan",
    "build_completion_plan",
    "completion_authority_unsigned_template",
    "seal_completion_authority",
    "validate_completed_state",
]
