"""One-time metadata-only recovery for the R3 vault-manifest serializer mismatch.

This tool is intentionally outside the frozen R3 source closure.  It may read
only public authority/evidence files and the vault manifest metadata leaf.  It
never resolves, stats, enumerates, or opens a truth/latent payload path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
AUTHORITY_SCHEMA = "expected_pe.four_model.r3_vault_manifest_recovery_authority.v1"
AUTHORITY_STATUS = (
    "GO_EXACT_ONE_TIME_METADATA_SERIALIZATION_NORMALIZATION_NO_TRUTH_OPEN"
)
RECEIPT_SCHEMA = "expected_pe.four_model.r3_vault_manifest_recovery_receipt.v1"
RECEIPT_STATUS = (
    "PASS_EXACT_ONE_TIME_METADATA_SERIALIZATION_NORMALIZATION_NO_TRUTH_OPEN"
)
CLAIM_SCHEMA = "expected_pe.four_model.r3_vault_manifest_recovery_invocation_claim.v1"
CLAIM_STATUS = "CLAIMED_EXACT_ONE_TIME_VAULT_MANIFEST_NORMALIZATION"
RUN_ID = "r3_20260824T134417"
EVIDENCE_ROOT_RELATIVE = (
    "build/pe_four_model_heldout_r3_activation_recovery_r3_20260824T134417"
)
AUTHORITY_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/R3_VAULT_MANIFEST_RECOVERY_AUTHORITY.json"
BACKUP_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/VAULT_MANIFEST_PRE_NORMALIZATION.json"
CLAIM_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/NORMALIZATION_INVOCATION_CLAIM.json"
RECEIPT_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/NORMALIZATION_RECEIPT.json"
TARGET_RELATIVE = (
    "outputs/.model_zoo_pe_four_model_heldout_vault_r3_20260824T134417/"
    "VAULT_MANIFEST.json"
)
TEMPORARY_RELATIVE = (
    "outputs/.model_zoo_pe_four_model_heldout_vault_r3_20260824T134417/"
    ".VAULT_MANIFEST.r3_recovery_r3_20260824T134417.tmp"
)
PREDICTION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_predictions_r3_20260824T134417"
)
ACTIVATION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_model_portfolio_heldout_activation_r3_20260824T134417"
)
CERTIFICATION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_model_portfolio_heldout_certification_result_"
    "r3_20260824T134417"
)
OLD_RAW_SHA256 = "731efc61fe7469bb6b9efd9ab517bbc7ea6699d2896234d4a1ca9373c755dc87"
OLD_SIZE_BYTES = 16_720
NEW_RAW_SHA256 = "d0a3ac148f153c7c726c132012045b9837f3390a7bccd4ba634bf2a9c3df2d4e"
NEW_SIZE_BYTES = 19_308
MANIFEST_SEMANTIC_SHA256 = (
    "877be05224a3b8c85020a56a2ad80afba4d18c9976194199c2690db36da33893"
)
SOURCE_MANIFEST_RAW_SHA256 = (
    "cc1fa28b2a8f5544745d165e363fed5e6a214971225150d368899d5b79db3d12"
)
PREDICTION_SEAL_RAW_SHA256 = (
    "93e2697e289acf8496061be7f0d3ea1fdc1e84c177459550443c17b62d25e9fb"
)
TERMINAL_RAW_SHA256 = (
    "59376b65a2c39322818ad1ccda97bbb0fb876fca3e265168e67259659fa7e387"
)
IMMUTABLE_ANCHOR_RAW_SHA256 = {
    "fda61ea7d041020dff30e62eb90730f681062d132f946a2ca840d226bc868cfe",
    "2102ed765a33790f492f1e9a30e1c892504ff11f0ac2c581c9f80fcef1e1bbd0",
    "0b607b8f163b42452ecaf927bb696994755b565f0e846a8e0e4a63dccd518889",
}
PREDICTION_OUTPUT_FILE_UNIVERSE = (
    "AUDIT_SEAL.json",
    "CHECKSUMS.sha256",
    "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
    "PREDICTIONS.csv",
    "PREDICTION_MANIFEST.json",
    "SOURCE_MANIFEST.json",
)
AUTHORITY_FIELDS = {
    "activation_root_relative_path",
    "authority_semantic_sha256",
    "authorized_activation_retry_count",
    "authorized_normalizer_invocation_count",
    "authorized_scorer_invocation_count",
    "authorized_vault_mutation_count",
    "backup_relative_path",
    "certification_root_relative_path",
    "claim_relative_path",
    "created_at_utc",
    "historical_native_adjudication_ref",
    "historical_raw_binding_policy",
    "immutable_anchor_refs",
    "max_target_raw_transition_count",
    "normalizer_source_ref",
    "normalizer_test_ref",
    "prediction_audit_seal_ref",
    "prediction_output_file_universe",
    "prediction_root_relative_path",
    "prepublication_failure_terminal_ref",
    "protected_payload_directory_enumeration_allowed",
    "receipt_relative_path",
    "recovery_constraints",
    "recovery_evidence_root_relative_path",
    "retry_allowed",
    "run_id",
    "schema_version",
    "scope",
    "score_open_count_at_authority",
    "source_manifest_ref",
    "status",
    "temporary_relative_path",
    "truth_open_count_at_authority",
    "truth_ref_resolution_allowed",
    "validate_only_allowed",
    "vault_manifest_after_raw_sha256",
    "vault_manifest_after_size_bytes",
    "vault_manifest_before_ref",
    "vault_manifest_semantic_sha256",
}


class R3VaultManifestRecoveryError(RuntimeError):
    """Fail-closed error for the exact recovery identity."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R3VaultManifestRecoveryError("normalizer requires -I -B")
    if sys.pycache_prefix is None:
        raise R3VaultManifestRecoveryError("normalizer pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise R3VaultManifestRecoveryError("normalizer pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _semantic(value: object) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    )


def _pretty(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _r7_compact(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise R3VaultManifestRecoveryError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                R3VaultManifestRecoveryError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3VaultManifestRecoveryError(f"invalid JSON in {label}") from exc
    if type(value) is not dict:
        raise R3VaultManifestRecoveryError(f"{label} is not an object")
    return value


def _relative(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise R3VaultManifestRecoveryError(f"{label} is not a POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
    ):
        raise R3VaultManifestRecoveryError(f"{label} normalization differs")
    return value


def _project_path(relative: object, *, label: str, must_exist: bool) -> Path:
    normalized = _relative(relative, label=label)
    candidate = PROJECT_ROOT.joinpath(*PurePosixPath(normalized).parts)
    if candidate.is_symlink():
        raise R3VaultManifestRecoveryError(f"{label} is a reparse/symlink path")
    if must_exist:
        resolved = candidate.resolve(strict=True)
        if PROJECT_ROOT not in resolved.parents or not resolved.is_file():
            raise R3VaultManifestRecoveryError(f"{label} escaped or is not a file")
        return resolved
    parent = candidate.parent.resolve(strict=True)
    if PROJECT_ROOT not in parent.parents and parent != PROJECT_ROOT:
        raise R3VaultManifestRecoveryError(f"{label} parent escaped project")
    return candidate


def _ref_matches(observed: Mapping[str, object], expected: object) -> bool:
    return type(expected) is dict and dict(observed) == expected


def _activation_artifact_ref(record: object) -> dict[str, object]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
    )

    payload = record.payload()
    payload["volume_serial_number"] = int(str(payload["volume_serial_number"]), 16)
    return ArtifactRef.from_mapping(payload).payload()


def _source_records(manifest: Mapping[str, object]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if type(value) is dict:
            if "relative_path" in value and "raw_sha256" in value:
                records.append(dict(value))
            for item in value.values():
                visit(item)
        elif type(value) is list:
            for item in value:
                visit(item)

    visit(manifest)
    return records


def _validate_authority(
    raw: bytes,
    *,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    if _sha256(raw) != expected_raw_sha256 or _pretty(_strict_object(raw, label="authority")) != raw:
        raise R3VaultManifestRecoveryError("recovery authority raw/canonical bytes differ")
    value = _strict_object(raw, label="authority")
    unsigned = dict(value)
    stored = unsigned.pop("authority_semantic_sha256", None)
    old_ref = value.get("vault_manifest_before_ref")
    terminal_ref = value.get("prepublication_failure_terminal_ref")
    source_ref = value.get("source_manifest_ref")
    seal_ref = value.get("prediction_audit_seal_ref")
    anchors = value.get("immutable_anchor_refs")
    constraints = value.get("recovery_constraints")
    historical = value.get("historical_raw_binding_policy")
    if (
        set(value) != AUTHORITY_FIELDS
        or
        value.get("schema_version") != AUTHORITY_SCHEMA
        or value.get("status") != AUTHORITY_STATUS
        or type(stored) is not str
        or stored != _semantic(unsigned)
        or value.get("run_id") != RUN_ID
        or value.get("truth_open_count_at_authority") != 0
        or value.get("score_open_count_at_authority") != 0
        or value.get("authorized_vault_mutation_count") != 1
        or value.get("authorized_normalizer_invocation_count") != 1
        or value.get("authorized_activation_retry_count") != 1
        or value.get("authorized_scorer_invocation_count") != 1
        or value.get("max_target_raw_transition_count") != 1
        or value.get("retry_allowed") is not False
        or value.get("protected_payload_directory_enumeration_allowed") is not False
        or value.get("truth_ref_resolution_allowed") is not False
        or value.get("validate_only_allowed") is not True
        or value.get("activation_root_relative_path") != ACTIVATION_ROOT_RELATIVE
        or value.get("certification_root_relative_path") != CERTIFICATION_ROOT_RELATIVE
        or value.get("prediction_root_relative_path") != PREDICTION_ROOT_RELATIVE
        or value.get("recovery_evidence_root_relative_path") != EVIDENCE_ROOT_RELATIVE
        or value.get("backup_relative_path") != BACKUP_RELATIVE
        or value.get("claim_relative_path") != CLAIM_RELATIVE
        or value.get("receipt_relative_path") != RECEIPT_RELATIVE
        or value.get("temporary_relative_path") != TEMPORARY_RELATIVE
        or value.get("prediction_output_file_universe")
        != list(PREDICTION_OUTPUT_FILE_UNIVERSE)
        or type(old_ref) is not dict
        or old_ref.get("relative_path") != TARGET_RELATIVE
        or old_ref.get("raw_sha256") != OLD_RAW_SHA256
        or old_ref.get("size_bytes") != OLD_SIZE_BYTES
        or value.get("vault_manifest_after_raw_sha256") != NEW_RAW_SHA256
        or value.get("vault_manifest_after_size_bytes") != NEW_SIZE_BYTES
        or value.get("vault_manifest_semantic_sha256")
        != MANIFEST_SEMANTIC_SHA256
        or type(terminal_ref) is not dict
        or terminal_ref.get("raw_sha256") != TERMINAL_RAW_SHA256
        or type(source_ref) is not dict
        or source_ref.get("raw_sha256") != SOURCE_MANIFEST_RAW_SHA256
        or type(seal_ref) is not dict
        or seal_ref.get("raw_sha256") != PREDICTION_SEAL_RAW_SHA256
        or type(anchors) is not list
        or len(anchors) != 3
        or {
            item.get("raw_sha256")
            for item in anchors
            if type(item) is dict
        }
        != IMMUTABLE_ANCHOR_RAW_SHA256
        or type(constraints) is not dict
        or not constraints
        or any(item is not False for item in constraints.values())
        or type(historical) is not dict
        or historical.get("historical_adjudication_remains_immutable") is not True
        or historical.get("historical_vault_manifest_raw_sha256")
        != OLD_RAW_SHA256
        or historical.get("live_binding_must_be_superseded_by_post_normalization_bridge")
        is not True
        or historical.get("other_historical_findings_remain_authoritative") is not True
    ):
        raise R3VaultManifestRecoveryError("recovery authority contract differs")
    return value


def _write_temporary(*, temporary: Path, raw: bytes) -> None:
    if temporary.exists() or temporary.is_symlink():
        raise R3VaultManifestRecoveryError("recovery temporary path already exists")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise R3VaultManifestRecoveryError("recovery temporary short write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace(*, target: Path, temporary: Path) -> None:
    try:
        os.replace(temporary, target)
    except BaseException as exc:
        raise R3VaultManifestRecoveryError(
            "atomic replace raised; claim is spent and manual reconciliation is required"
        ) from exc
    if temporary.exists():
        raise R3VaultManifestRecoveryError("recovery temporary path survived replace")


def normalize(
    *,
    authority_path: Path,
    authority_raw_sha256: str,
    validate_only: bool = False,
) -> dict[str, object]:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        capture_identity,
        exact_root,
        stable_read,
    )

    if HEX64.fullmatch(authority_raw_sha256) is None:
        raise R3VaultManifestRecoveryError("authority raw SHA-256 differs")
    authority_file = Path(authority_path).resolve(strict=True)
    if authority_file.relative_to(PROJECT_ROOT).as_posix() != AUTHORITY_RELATIVE:
        raise R3VaultManifestRecoveryError("recovery authority path differs")
    authority_raw, _ = stable_read(
        authority_file,
        relative_path=authority_file.relative_to(PROJECT_ROOT).as_posix(),
    )
    authority = _validate_authority(
        authority_raw,
        expected_raw_sha256=authority_raw_sha256,
    )

    tool_ref = authority.get("normalizer_source_ref")
    tool_raw, observed_tool = stable_read(
        Path(__file__).resolve(strict=True),
        relative_path=Path(__file__).resolve(strict=True).relative_to(PROJECT_ROOT).as_posix(),
    )
    if not _ref_matches(observed_tool.payload(), tool_ref) or _sha256(tool_raw) != tool_ref.get("raw_sha256"):
        raise R3VaultManifestRecoveryError("normalizer source binding differs")

    terminal_ref = authority.get("prepublication_failure_terminal_ref")
    terminal_path = _project_path(
        terminal_ref.get("relative_path") if type(terminal_ref) is dict else None,
        label="prepublication terminal",
        must_exist=True,
    )
    _, observed_terminal = stable_read(
        terminal_path,
        relative_path=terminal_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    if not _ref_matches(observed_terminal.payload(), terminal_ref):
        raise R3VaultManifestRecoveryError("prepublication terminal binding differs")

    anchor_refs = authority.get("immutable_anchor_refs")
    if type(anchor_refs) is not list or len(anchor_refs) != 3:
        raise R3VaultManifestRecoveryError("immutable anchor universe differs")
    observed_anchors: list[dict[str, object]] = []
    for anchor_ref in anchor_refs:
        anchor_path = _project_path(
            anchor_ref.get("relative_path") if type(anchor_ref) is dict else None,
            label="immutable anchor",
            must_exist=True,
        )
        _, observed_anchor = stable_read(
            anchor_path,
            relative_path=anchor_path.relative_to(PROJECT_ROOT).as_posix(),
        )
        if not _ref_matches(observed_anchor.payload(), anchor_ref):
            raise R3VaultManifestRecoveryError("immutable anchor binding differs")
        observed_anchors.append(observed_anchor.payload())

    source_ref = authority.get("source_manifest_ref")
    source_path = _project_path(
        source_ref.get("relative_path") if type(source_ref) is dict else None,
        label="source manifest",
        must_exist=True,
    )
    source_raw, observed_source = stable_read(
        source_path,
        relative_path=source_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    if not _ref_matches(observed_source.payload(), source_ref):
        raise R3VaultManifestRecoveryError("source manifest binding differs")
    source_manifest = _strict_object(source_raw, label="source manifest")
    records = _source_records(source_manifest)
    paths = [record.get("relative_path") for record in records]
    if len(records) != 137 or len(set(paths)) != 137:
        raise R3VaultManifestRecoveryError("frozen source record universe differs")
    for record in records:
        source_file = _project_path(
            record.get("relative_path"), label="frozen source", must_exist=True
        )
        raw, observed_record = stable_read(
            source_file,
            relative_path=source_file.relative_to(PROJECT_ROOT).as_posix(),
        )
        if (
            _sha256(raw) != record.get("raw_sha256")
            or len(raw) != record.get("size_bytes")
            or observed_record.raw_sha256 != record.get("raw_sha256")
        ):
            raise R3VaultManifestRecoveryError("frozen source closure drifted")

    prediction_root = PROJECT_ROOT / _relative(
        authority.get("prediction_root_relative_path"), label="prediction root"
    )
    _, _ = exact_root(
        prediction_root,
        expected_files=tuple(authority.get("prediction_output_file_universe", [])),
    )
    seal_ref = authority.get("prediction_audit_seal_ref")
    seal_path = _project_path(
        seal_ref.get("relative_path") if type(seal_ref) is dict else None,
        label="prediction seal",
        must_exist=True,
    )
    _, observed_seal = stable_read(
        seal_path,
        relative_path=seal_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    if not _ref_matches(observed_seal.payload(), seal_ref):
        raise R3VaultManifestRecoveryError("prediction seal binding differs")

    for field in ("activation_root_relative_path", "certification_root_relative_path"):
        root = PROJECT_ROOT / _relative(authority.get(field), label=field)
        if root.exists() or root.is_symlink():
            raise R3VaultManifestRecoveryError(f"{field} already exists")

    old_ref = authority.get("vault_manifest_before_ref")
    target = _project_path(
        old_ref.get("relative_path") if type(old_ref) is dict else None,
        label="vault manifest",
        must_exist=True,
    )
    if target.relative_to(PROJECT_ROOT).as_posix() != TARGET_RELATIVE:
        raise R3VaultManifestRecoveryError("vault manifest target path differs")
    old_raw, observed_old = stable_read(
        target,
        relative_path=target.relative_to(PROJECT_ROOT).as_posix(),
    )
    if not _ref_matches(observed_old.payload(), old_ref):
        raise R3VaultManifestRecoveryError("vault manifest pre-normalization ref differs")
    old_object = _strict_object(old_raw, label="vault manifest before")
    if _r7_compact(old_object) != old_raw:
        raise R3VaultManifestRecoveryError("vault manifest is not exact R7 compact canonical")
    unsigned = dict(old_object)
    stored_semantic = unsigned.pop("vault_manifest_semantic_sha256", None)
    new_raw = _pretty(old_object)
    if (
        stored_semantic != authority.get("vault_manifest_semantic_sha256")
        or stored_semantic != _semantic(unsigned)
        or _sha256(new_raw) != authority.get("vault_manifest_after_raw_sha256")
        or len(new_raw) != authority.get("vault_manifest_after_size_bytes")
        or _strict_object(new_raw, label="vault manifest after expected") != old_object
    ):
        raise R3VaultManifestRecoveryError("vault manifest deterministic transformation differs")

    backup = _project_path(
        authority.get("backup_relative_path"), label="backup", must_exist=False
    )
    claim_path = _project_path(
        authority.get("claim_relative_path"), label="claim", must_exist=False
    )
    receipt_path = _project_path(
        authority.get("receipt_relative_path"), label="receipt", must_exist=False
    )
    temporary = _project_path(
        authority.get("temporary_relative_path"), label="temporary", must_exist=False
    )
    evidence_root = PROJECT_ROOT / _relative(
        authority.get("recovery_evidence_root_relative_path"),
        label="recovery evidence root",
    )
    evidence_root = evidence_root.resolve(strict=True)
    if (
        evidence_root.parent != (PROJECT_ROOT / "build").resolve(strict=True)
        or not evidence_root.is_dir()
        or any(path.parent != evidence_root for path in (backup, claim_path, receipt_path))
    ):
        raise R3VaultManifestRecoveryError("recovery evidence root geometry differs")
    if temporary.parent != target.parent:
        raise R3VaultManifestRecoveryError("temporary is not in the target directory")
    if any(
        path.exists() or path.is_symlink()
        for path in (backup, claim_path, receipt_path, temporary)
    ):
        raise R3VaultManifestRecoveryError("recovery output already exists")

    if validate_only:
        return {
            "status": "PASS_R3_VAULT_MANIFEST_NORMALIZATION_PREUSE_NO_MUTATION",
            "authority_raw_sha256": authority_raw_sha256,
            "normalizer_source_raw_sha256": observed_tool.raw_sha256,
            "vault_manifest_before_raw_sha256": observed_old.raw_sha256,
            "vault_manifest_after_raw_sha256": _sha256(new_raw),
            "decoded_json_exact_equal": (
                _strict_object(new_raw, label="validate-only after") == old_object
            ),
            "vault_mutation_count": 0,
            "claim_publication_count": 0,
            "truth_payload_open_count": 0,
            "score_open_count": 0,
        }

    vault_parent_identity_before = capture_identity(target.parent, directory=True)

    claim: dict[str, object] = {
        "schema_version": CLAIM_SCHEMA,
        "status": CLAIM_STATUS,
        "run_id": authority["run_id"],
        "authority_relative_path": authority_file.relative_to(PROJECT_ROOT).as_posix(),
        "authority_raw_sha256": authority_raw_sha256,
        "normalizer_source_ref": observed_tool.payload(),
        "vault_manifest_before_ref": observed_old.payload(),
        "expected_vault_manifest_after_raw_sha256": authority[
            "vault_manifest_after_raw_sha256"
        ],
        "expected_vault_manifest_after_size_bytes": authority[
            "vault_manifest_after_size_bytes"
        ],
        "exact_argv": [
            "--authority",
            authority_file.relative_to(PROJECT_ROOT).as_posix(),
            "--authority-raw-sha256",
            authority_raw_sha256,
        ],
        "normalizer_invocation_count": 1,
        "authorized_vault_mutation_count": 1,
        "truth_payload_open_count": 0,
        "score_open_count": 0,
        "retry_allowed": False,
    }
    claim["claim_semantic_sha256"] = _semantic(claim)
    claim_raw = _pretty(claim)
    atomic_write_new(claim_path, claim_raw)
    os.chmod(claim_path, stat.S_IREAD)
    _, claim_record = stable_read(
        claim_path,
        relative_path=claim_path.relative_to(PROJECT_ROOT).as_posix(),
    )

    atomic_write_new(backup, old_raw)
    backup_raw, backup_record = stable_read(
        backup,
        relative_path=backup.relative_to(PROJECT_ROOT).as_posix(),
    )
    if backup_raw != old_raw:
        raise R3VaultManifestRecoveryError("pre-normalization backup differs")

    old_raw_again, observed_old_again = stable_read(
        target,
        relative_path=target.relative_to(PROJECT_ROOT).as_posix(),
    )
    if old_raw_again != old_raw or observed_old_again.payload() != observed_old.payload():
        raise R3VaultManifestRecoveryError("vault manifest changed before replacement")

    _write_temporary(temporary=temporary, raw=new_raw)
    temporary_raw, temporary_record = stable_read(
        temporary,
        relative_path=temporary.relative_to(PROJECT_ROOT).as_posix(),
    )
    if temporary_raw != new_raw:
        raise R3VaultManifestRecoveryError("recovery temporary bytes differ")
    _replace(target=target, temporary=temporary)
    observed_raw, observed_after = stable_read(
        target,
        relative_path=target.relative_to(PROJECT_ROOT).as_posix(),
    )
    after_object = _strict_object(observed_raw, label="vault manifest after")
    if (
        observed_raw != new_raw
        or after_object != old_object
        or _pretty(after_object) != observed_raw
        or _semantic({k: v for k, v in after_object.items() if k != "vault_manifest_semantic_sha256"})
        != stored_semantic
    ):
        raise R3VaultManifestRecoveryError("post-normalization vault manifest differs")
    vault_parent_identity_after = capture_identity(target.parent, directory=True)
    if (
        vault_parent_identity_after != vault_parent_identity_before
        or observed_after.volume_serial_number != temporary_record.volume_serial_number
        or observed_after.file_id_128 != temporary_record.file_id_128
        or observed_after.file_id_128 == observed_old.file_id_128
    ):
        raise R3VaultManifestRecoveryError("atomic replacement identity continuity differs")

    receipt: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA,
        "status": RECEIPT_STATUS,
        "run_id": authority["run_id"],
        "authority_raw_sha256": authority_raw_sha256,
        "invocation_claim_ref": claim_record.payload(),
        "normalizer_source_ref": observed_tool.payload(),
        "immutable_anchor_refs": observed_anchors,
        "prepublication_failure_terminal_ref": observed_terminal.payload(),
        "vault_manifest_before_ref": observed_old.payload(),
        "vault_manifest_before_activation_artifact_ref": _activation_artifact_ref(
            observed_old
        ),
        "vault_manifest_backup_ref": backup_record.payload(),
        "vault_manifest_temporary_ref": temporary_record.payload(),
        "vault_manifest_after_ref": observed_after.payload(),
        "vault_manifest_after_activation_artifact_ref": _activation_artifact_ref(
            observed_after
        ),
        "vault_parent_identity_before": vault_parent_identity_before,
        "vault_parent_identity_after": vault_parent_identity_after,
        "vault_manifest_semantic_sha256_before": stored_semantic,
        "vault_manifest_semantic_sha256_after": stored_semantic,
        "decoded_json_exact_equal": after_object == old_object,
        "truth_ref_inventory_exact_equal": (
            after_object.get("truth_refs") == old_object.get("truth_refs")
        ),
        "vault_manifest_mutation_count": 1,
        "normalizer_invocation_count": 1,
        "vault_temporary_create_count": 1,
        "vault_atomic_replace_count": 1,
        "vault_write_handle_fsync_count": 1,
        "vault_write_handle_close_count": 1,
        "vault_target_pre_replace_revalidation_count": 1,
        "temporary_to_final_file_id_continuity": True,
        "vault_temporary_residual_count": 0,
        "other_vault_mutation_count": 0,
        "public_generation_mutation_count": 0,
        "prediction_mutation_count": 0,
        "frozen_source_mutation_count": 0,
        "registry_or_seed_mutation_count": 0,
        "candidate_or_model_mutation_count": 0,
        "truth_payload_open_count": 0,
        "latent_payload_open_count": 0,
        "score_open_count": 0,
        "vault_manifest_metadata_open_count": 3,
        "truth_ref_resolve_or_stat_count": 0,
        "protected_payload_directory_enumeration_count": 0,
        "activation_output_claim_count": 0,
        "certification_output_claim_count": 0,
        "metadata_only_recovery": True,
        "receipt_published_commit_last": True,
        "activation_retry_authority_remaining": 1,
        "scorer_invocation_authority_remaining": 1,
    }
    receipt["receipt_semantic_sha256"] = _semantic(receipt)
    receipt_raw = _pretty(receipt)
    atomic_write_new(receipt_path, receipt_raw)
    os.chmod(backup, stat.S_IREAD)
    os.chmod(receipt_path, stat.S_IREAD)
    return {
        "status": RECEIPT_STATUS,
        "receipt_relative_path": receipt_path.relative_to(PROJECT_ROOT).as_posix(),
        "receipt_raw_sha256": _sha256(receipt_raw),
        "receipt_semantic_sha256": receipt["receipt_semantic_sha256"],
        "invocation_claim_raw_sha256": claim_record.raw_sha256,
        "vault_manifest_after_raw_sha256": observed_after.raw_sha256,
        "truth_payload_open_count": 0,
        "score_open_count": 0,
        "activation_output_claim_count": 0,
        "scorer_invocation_count": 0,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--authority", required=True)
    result.add_argument("--authority-raw-sha256", required=True)
    result.add_argument("--validate-only", action="store_true")
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    result = normalize(
        authority_path=Path(arguments.authority),
        authority_raw_sha256=arguments.authority_raw_sha256,
        validate_only=arguments.validate_only,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
