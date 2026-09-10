"""Bind the R3 serialization-recovery bridge to one unchanged activation call."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
RUN_ID = "r3_20260824T134417"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PREUSE_SCHEMA = "expected_pe.four_model.r3_recovery_activation_preuse_authority.v1"
PREUSE_STATUS = "GO_EXACT_ONE_RECOVERY_BOUND_ACTIVATION_ATTEMPT_NO_TRUTH_OPEN"
CLAIM_SCHEMA = "expected_pe.four_model.r3_recovery_activation_invocation_claim.v1"
CLAIM_STATUS = "CLAIMED_EXACT_SECOND_AND_FINAL_R3_ACTIVATION_ATTEMPT"
SUCCESS_SCHEMA = "expected_pe.four_model.r3_recovery_activation_success_receipt.v1"
SUCCESS_STATUS = "PASS_RECOVERY_BOUND_R3_ACTIVATION_PUBLISHED_NO_TRUTH_OPEN"
TERMINAL_SCHEMA = "expected_pe.four_model.r3_recovery_activation_terminal.v1"
TERMINAL_STATUS = "TERMINAL_RECOVERY_ACTIVATION_FAILED_NO_THIRD_ATTEMPT"
EVIDENCE_ROOT_RELATIVE = (
    "build/pe_four_model_heldout_r3_activation_recovery_r3_20260824T134417"
)
PREUSE_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/R3_RECOVERY_ACTIVATION_PREUSE_AUTHORITY.json"
BRIDGE_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/R3_RECOVERY_SUPERSESSION_BRIDGE.json"
BRIDGE_RAW_SHA256 = "ec105ff2cee6d95b86d3063c38cfd0135ec48fe682fed6117577a0e293f03346"
RECOVERY_RECEIPT_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/NORMALIZATION_RECEIPT.json"
RECOVERY_RECEIPT_RAW_SHA256 = (
    "05dfd9f8a975cd8e23458026e4d128bf0c7c83f9ce1d1d950ae8fdc64363f419"
)
CLAIM_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/ACTIVATION_INVOCATION_CLAIM.json"
SUCCESS_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/ACTIVATION_SUCCESS_RECEIPT.json"
TERMINAL_RELATIVE = f"{EVIDENCE_ROOT_RELATIVE}/ACTIVATION_RECOVERY_TERMINAL.json"
MANIFEST_RELATIVE = (
    "outputs/.model_zoo_pe_four_model_heldout_vault_r3_20260824T134417/"
    "VAULT_MANIFEST.json"
)
MANIFEST_RAW_SHA256 = "d0a3ac148f153c7c726c132012045b9837f3390a7bccd4ba634bf2a9c3df2d4e"
MANIFEST_SEMANTIC_SHA256 = (
    "877be05224a3b8c85020a56a2ad80afba4d18c9976194199c2690db36da33893"
)
EXECUTION_AUTHORITY_RELATIVE = (
    "build/pe_four_model_heldout_execution_authority_r3_20260824T134417.json"
)
EXECUTION_AUTHORITY_RAW_SHA256 = (
    "fda61ea7d041020dff30e62eb90730f681062d132f946a2ca840d226bc868cfe"
)
MINT_RELATIVE = (
    "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1/"
    "mint_heldout_activation.py"
)
MINT_RAW_SHA256 = "aa85851b2116429e16f8df555aa2678c8bef53349f1beeff20a2f2a94a53436a"
SOURCE_MANIFEST_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_predictions_r3_20260824T134417/"
    "SOURCE_MANIFEST.json"
)
SOURCE_MANIFEST_RAW_SHA256 = (
    "cc1fa28b2a8f5544745d165e363fed5e6a214971225150d368899d5b79db3d12"
)
PREDICTION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_predictions_r3_20260824T134417"
)
PREDICTION_SEAL_RELATIVE = f"{PREDICTION_ROOT_RELATIVE}/AUDIT_SEAL.json"
PREDICTION_SEAL_RAW_SHA256 = (
    "93e2697e289acf8496061be7f0d3ea1fdc1e84c177459550443c17b62d25e9fb"
)
PREDICTION_OUTPUT_FILE_UNIVERSE = (
    "AUDIT_SEAL.json",
    "CHECKSUMS.sha256",
    "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
    "PREDICTIONS.csv",
    "PREDICTION_MANIFEST.json",
    "SOURCE_MANIFEST.json",
)
ACTIVATION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_model_portfolio_heldout_activation_r3_20260824T134417"
)
ACTIVATION_LEAF_RELATIVE = (
    f"{ACTIVATION_ROOT_RELATIVE}/HELDOUT_EVALUATION_ACTIVATION.json"
)
CERTIFICATION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_model_portfolio_heldout_certification_result_"
    "r3_20260824T134417"
)
CHILD_PYCACHE_RELATIVE = (
    "build/pe_four_model_heldout_r3_recovery_activation_child_pycache_"
    "r3_20260824T134417"
)
VAULT_MANIFEST_ARGUMENT = MANIFEST_RELATIVE
PYTHON_RAW_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"


class R3RecoveryActivationError(RuntimeError):
    """Fail-closed exact recovery activation error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R3RecoveryActivationError("recovery activation launcher requires -I -B")
    if sys.pycache_prefix is None:
        raise R3RecoveryActivationError("launcher pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise R3RecoveryActivationError("launcher pycache prefix is not empty")
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


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise R3RecoveryActivationError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                R3RecoveryActivationError(f"nonfinite JSON in {label}: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3RecoveryActivationError(f"invalid JSON in {label}") from exc
    if type(value) is not dict:
        raise R3RecoveryActivationError(f"{label} is not an object")
    return value


def _relative(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise R3RecoveryActivationError(f"{label} is not a POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
    ):
        raise R3RecoveryActivationError(f"{label} normalization differs")
    return value


def _path(relative: str, *, must_exist: bool) -> Path:
    candidate = PROJECT_ROOT.joinpath(*PurePosixPath(_relative(relative, label="path")).parts)
    if candidate.is_symlink():
        raise R3RecoveryActivationError("reparse/symlink path rejected")
    if must_exist:
        resolved = candidate.resolve(strict=True)
        if PROJECT_ROOT not in resolved.parents or not resolved.is_file():
            raise R3RecoveryActivationError("existing project file differs")
        return resolved
    parent = candidate.parent.resolve(strict=True)
    if PROJECT_ROOT not in parent.parents and parent != PROJECT_ROOT:
        raise R3RecoveryActivationError("new project file parent escaped")
    return candidate


def _native_ref(record: object) -> dict[str, object]:
    return record.payload()


def _activation_ref(record: object) -> dict[str, object]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
    )

    value = record.payload()
    value["volume_serial_number"] = int(str(value["volume_serial_number"]), 16)
    return ArtifactRef.from_mapping(value).payload()


def _verify_semantic(value: Mapping[str, Any], field: str, *, label: str) -> str:
    unsigned = dict(value)
    stored = unsigned.pop(field, None)
    if type(stored) is not str or stored != _semantic(unsigned):
        raise R3RecoveryActivationError(f"{label} self-seal differs")
    return stored


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


def _load_exact_json(
    relative: str,
    expected_raw_sha256: str,
    *,
    stable_read: object,
    label: str,
) -> tuple[dict[str, Any], object]:
    path = _path(relative, must_exist=True)
    raw, record = stable_read(path, relative_path=relative)
    value = _strict_object(raw, label=label)
    if record.raw_sha256 != expected_raw_sha256 or _pretty(value) != raw:
        raise R3RecoveryActivationError(f"{label} raw/canonical bytes differ")
    return value, record


def launch(
    *,
    preuse_path: Path,
    preuse_raw_sha256: str,
    validate_only: bool = False,
) -> dict[str, object]:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        exact_root,
        stable_read,
    )

    if HEX64.fullmatch(preuse_raw_sha256) is None:
        raise R3RecoveryActivationError("preuse raw SHA-256 differs")
    preuse_file = Path(preuse_path).resolve(strict=True)
    if preuse_file.relative_to(PROJECT_ROOT).as_posix() != PREUSE_RELATIVE:
        raise R3RecoveryActivationError("preuse authority path differs")
    preuse_raw, preuse_record = stable_read(
        preuse_file,
        relative_path=PREUSE_RELATIVE,
    )
    preuse = _strict_object(preuse_raw, label="preuse authority")
    _verify_semantic(preuse, "authority_semantic_sha256", label="preuse authority")
    if (
        _sha256(preuse_raw) != preuse_raw_sha256
        or _pretty(preuse) != preuse_raw
        or preuse.get("schema_version") != PREUSE_SCHEMA
        or preuse.get("status") != PREUSE_STATUS
        or preuse.get("run_id") != RUN_ID
        or preuse.get("activation_attempt_ordinal") != 2
        or preuse.get("activation_attempt_count_authorized") != 1
        or preuse.get("scorer_invocation_count_authorized_after_success") != 1
        or preuse.get("truth_open_count_at_authority") != 0
        or preuse.get("score_open_count_at_authority") != 0
        or preuse.get("retry_allowed_after_this_attempt") is not False
        or preuse.get("validate_only_allowed") is not True
    ):
        raise R3RecoveryActivationError("preuse authority contract differs")

    launcher_raw, launcher_record = stable_read(
        Path(__file__).resolve(strict=True),
        relative_path=Path(__file__).resolve(strict=True).relative_to(PROJECT_ROOT).as_posix(),
    )
    if preuse.get("launcher_source_ref") != _native_ref(launcher_record):
        raise R3RecoveryActivationError("launcher source binding differs")
    if _sha256(launcher_raw) != launcher_record.raw_sha256:
        raise R3RecoveryActivationError("launcher source digest differs")

    bridge, bridge_record = _load_exact_json(
        BRIDGE_RELATIVE,
        BRIDGE_RAW_SHA256,
        stable_read=stable_read,
        label="recovery bridge",
    )
    _verify_semantic(bridge, "bridge_semantic_sha256", label="recovery bridge")
    access = bridge.get("access")
    next_authority = bridge.get("next_authority")
    if (
        preuse.get("bridge_ref") != _native_ref(bridge_record)
        or bridge.get("status")
        != "GO_SERIALIZATION_RECOVERED_R3_EXACT_ONE_ACTIVATION_RETRY_P0_0_P1_0_P2_1"
        or bridge.get("run_id") != RUN_ID
        or type(access) is not dict
        or any(access.values())
        or type(next_authority) is not dict
        or next_authority.get("activation_attempt_ordinal") != 2
        or next_authority.get("activation_retry_count_remaining") != 1
        or next_authority.get("scorer_invocation_count_remaining") != 1
    ):
        raise R3RecoveryActivationError("recovery bridge authority differs")

    recovery, recovery_record = _load_exact_json(
        RECOVERY_RECEIPT_RELATIVE,
        RECOVERY_RECEIPT_RAW_SHA256,
        stable_read=stable_read,
        label="normalization receipt",
    )
    _verify_semantic(recovery, "receipt_semantic_sha256", label="normalization receipt")
    if (
        preuse.get("normalization_receipt_ref") != _native_ref(recovery_record)
        or recovery.get("status")
        != "PASS_EXACT_ONE_TIME_METADATA_SERIALIZATION_NORMALIZATION_NO_TRUTH_OPEN"
        or recovery.get("vault_manifest_mutation_count") != 1
        or recovery.get("decoded_json_exact_equal") is not True
        or recovery.get("truth_ref_inventory_exact_equal") is not True
        or recovery.get("truth_payload_open_count") != 0
        or recovery.get("latent_payload_open_count") != 0
        or recovery.get("score_open_count") != 0
    ):
        raise R3RecoveryActivationError("normalization receipt differs")

    manifest, manifest_record = _load_exact_json(
        MANIFEST_RELATIVE,
        MANIFEST_RAW_SHA256,
        stable_read=stable_read,
        label="normalized vault manifest",
    )
    manifest_semantic = _verify_semantic(
        manifest,
        "vault_manifest_semantic_sha256",
        label="normalized vault manifest",
    )
    if (
        manifest_semantic != MANIFEST_SEMANTIC_SHA256
        or preuse.get("normalized_vault_manifest_ref") != _native_ref(manifest_record)
        or recovery.get("vault_manifest_after_ref") != _native_ref(manifest_record)
    ):
        raise R3RecoveryActivationError("normalized vault manifest binding differs")

    for relative, expected_hash, preuse_field in (
        (EXECUTION_AUTHORITY_RELATIVE, EXECUTION_AUTHORITY_RAW_SHA256, "execution_authority_ref"),
        (MINT_RELATIVE, MINT_RAW_SHA256, "mint_activation_source_ref"),
        (PREDICTION_SEAL_RELATIVE, PREDICTION_SEAL_RAW_SHA256, "prediction_seal_ref"),
    ):
        path = _path(relative, must_exist=True)
        _, record = stable_read(path, relative_path=relative)
        if record.raw_sha256 != expected_hash or preuse.get(preuse_field) != _native_ref(record):
            raise R3RecoveryActivationError(f"{preuse_field} differs")

    source, source_record = _load_exact_json(
        SOURCE_MANIFEST_RELATIVE,
        SOURCE_MANIFEST_RAW_SHA256,
        stable_read=stable_read,
        label="source manifest",
    )
    if preuse.get("source_manifest_ref") != _native_ref(source_record):
        raise R3RecoveryActivationError("source manifest ref differs")
    records = _source_records(source)
    if len(records) != 137 or len({item.get("relative_path") for item in records}) != 137:
        raise R3RecoveryActivationError("source closure universe differs")
    for item in records:
        relative = _relative(item.get("relative_path"), label="frozen source")
        raw, observed = stable_read(_path(relative, must_exist=True), relative_path=relative)
        if (
            observed.raw_sha256 != item.get("raw_sha256")
            or observed.size_bytes != item.get("size_bytes")
            or _sha256(raw) != item.get("raw_sha256")
        ):
            raise R3RecoveryActivationError("frozen source closure drifted")

    exact_root(
        PROJECT_ROOT / PREDICTION_ROOT_RELATIVE,
        expected_files=PREDICTION_OUTPUT_FILE_UNIVERSE,
    )
    for relative in (
        ACTIVATION_ROOT_RELATIVE,
        CERTIFICATION_ROOT_RELATIVE,
        CLAIM_RELATIVE,
        SUCCESS_RELATIVE,
        TERMINAL_RELATIVE,
    ):
        candidate = PROJECT_ROOT / relative
        if candidate.exists() or candidate.is_symlink():
            raise R3RecoveryActivationError(f"pre-activation path exists: {relative}")

    child_pycache = (PROJECT_ROOT / CHILD_PYCACHE_RELATIVE).resolve(strict=True)
    if any(child_pycache.iterdir()):
        raise R3RecoveryActivationError("child activation pycache is not empty")
    python_path = Path(sys.executable).resolve(strict=True)
    if _sha256(python_path.read_bytes()) != PYTHON_RAW_SHA256:
        raise R3RecoveryActivationError("Python runtime raw hash differs")
    child_argv = [
        str(python_path),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={child_pycache}",
        MINT_RELATIVE,
        "--run-id",
        RUN_ID,
        "--execution-authority",
        EXECUTION_AUTHORITY_RELATIVE,
        "--execution-authority-raw-sha256",
        EXECUTION_AUTHORITY_RAW_SHA256,
        "--vault-manifest",
        VAULT_MANIFEST_ARGUMENT,
        "--prediction-root",
        PREDICTION_ROOT_RELATIVE,
    ]
    if validate_only:
        return {
            "status": "PASS_R3_RECOVERY_ACTIVATION_PREUSE_NO_CLAIM_NO_MUTATION",
            "preuse_authority_raw_sha256": preuse_raw_sha256,
            "launcher_source_raw_sha256": launcher_record.raw_sha256,
            "bridge_raw_sha256": bridge_record.raw_sha256,
            "normalization_receipt_raw_sha256": recovery_record.raw_sha256,
            "normalized_vault_manifest_raw_sha256": manifest_record.raw_sha256,
            "planned_child_argv": child_argv,
            "activation_claim_publication_count": 0,
            "activation_output_claim_count": 0,
            "truth_payload_open_count": 0,
            "score_open_count": 0,
        }
    claim: dict[str, object] = {
        "schema_version": CLAIM_SCHEMA,
        "status": CLAIM_STATUS,
        "run_id": RUN_ID,
        "activation_attempt_ordinal": 2,
        "preuse_authority_ref": _native_ref(preuse_record),
        "launcher_source_ref": _native_ref(launcher_record),
        "bridge_ref": _native_ref(bridge_record),
        "normalization_receipt_ref": _native_ref(recovery_record),
        "normalized_vault_manifest_ref": _native_ref(manifest_record),
        "exact_child_argv": child_argv,
        "activation_output_claim_count_before_child": 0,
        "certification_output_claim_count_before_child": 0,
        "truth_payload_open_count_before_child": 0,
        "score_open_count_before_child": 0,
        "retry_allowed": False,
    }
    claim["claim_semantic_sha256"] = _semantic(claim)
    claim_raw = _pretty(claim)
    claim_path = _path(CLAIM_RELATIVE, must_exist=False)
    atomic_write_new(claim_path, claim_raw)
    os.chmod(claim_path, stat.S_IREAD)
    _, claim_record = stable_read(claim_path, relative_path=CLAIM_RELATIVE)

    completed = subprocess.run(
        child_argv,
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    if completed.returncode != 0:
        terminal: dict[str, object] = {
            "schema_version": TERMINAL_SCHEMA,
            "status": TERMINAL_STATUS,
            "run_id": RUN_ID,
            "activation_attempt_ordinal": 2,
            "invocation_claim_ref": _native_ref(claim_record),
            "child_return_code": completed.returncode,
            "child_stdout": completed.stdout,
            "child_stderr": completed.stderr,
            "third_activation_attempt_allowed": False,
            "scorer_invocation_allowed": False,
            "truth_payload_open_count": 0,
            "score_open_count": 0,
        }
        terminal["terminal_semantic_sha256"] = _semantic(terminal)
        terminal_raw = _pretty(terminal)
        terminal_path = _path(TERMINAL_RELATIVE, must_exist=False)
        atomic_write_new(terminal_path, terminal_raw)
        os.chmod(terminal_path, stat.S_IREAD)
        raise R3RecoveryActivationError("recovery activation child failed terminally")

    child_result = _strict_object(completed.stdout.encode("utf-8"), label="activation stdout")
    activation_root, _ = exact_root(
        PROJECT_ROOT / ACTIVATION_ROOT_RELATIVE,
        expected_files=("HELDOUT_EVALUATION_ACTIVATION.json",),
    )
    activation_path = activation_root / "HELDOUT_EVALUATION_ACTIVATION.json"
    _, activation_record = stable_read(
        activation_path,
        relative_path=ACTIVATION_LEAF_RELATIVE,
    )
    activation_ref = _activation_ref(activation_record)
    if (
        child_result.get("status") != "PUBLISHED_ONE_LEAF_HELDOUT_EVALUATION_ACTIVATION"
        or child_result.get("activation_ref") != activation_ref
        or child_result.get("activation_raw_sha256") != activation_record.raw_sha256
        or child_result.get("truth_open_count") != 0
        or child_result.get("score_open_count") != 0
        or child_result.get("retry_allowed") is not False
        or (PROJECT_ROOT / CERTIFICATION_ROOT_RELATIVE).exists()
    ):
        raise R3RecoveryActivationError("published activation result differs")

    success: dict[str, object] = {
        "schema_version": SUCCESS_SCHEMA,
        "status": SUCCESS_STATUS,
        "run_id": RUN_ID,
        "activation_attempt_ordinal": 2,
        "prepublication_failed_attempt_count": 1,
        "successful_activation_publication_count": 1,
        "invocation_claim_ref": _native_ref(claim_record),
        "bridge_ref": _native_ref(bridge_record),
        "normalization_receipt_ref": _native_ref(recovery_record),
        "normalized_vault_manifest_ref": _native_ref(manifest_record),
        "activation_ref": activation_ref,
        "activation_raw_sha256": activation_record.raw_sha256,
        "activation_root_exact_leaf_count": 1,
        "certification_output_claim_count": 0,
        "truth_payload_open_count": 0,
        "latent_payload_open_count": 0,
        "score_open_count": 0,
        "third_activation_attempt_allowed": False,
        "detached_scorer_invocation_count_remaining": 1,
        "production_promotion_authority": False,
    }
    success["receipt_semantic_sha256"] = _semantic(success)
    success_raw = _pretty(success)
    success_path = _path(SUCCESS_RELATIVE, must_exist=False)
    atomic_write_new(success_path, success_raw)
    os.chmod(success_path, stat.S_IREAD)
    return {
        "status": SUCCESS_STATUS,
        "activation_relative_path": ACTIVATION_LEAF_RELATIVE,
        "activation_raw_sha256": activation_record.raw_sha256,
        "success_receipt_relative_path": SUCCESS_RELATIVE,
        "success_receipt_raw_sha256": _sha256(success_raw),
        "truth_payload_open_count": 0,
        "score_open_count": 0,
        "detached_scorer_invocation_count_remaining": 1,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--preuse-authority", required=True)
    result.add_argument("--preuse-authority-raw-sha256", required=True)
    result.add_argument("--validate-only", action="store_true")
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    result = launch(
        preuse_path=Path(arguments.preuse_authority),
        preuse_raw_sha256=arguments.preuse_authority_raw_sha256,
        validate_only=arguments.validate_only,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
