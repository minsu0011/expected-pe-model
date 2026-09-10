"""Externally anchored, stdlib-only R8 activation/child launcher."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ANCHOR = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_r4_20260821.json"
)
CAPABILITY_ENV = "EXPECTED_PE_R8_INHERITED_CAPABILITY_HANDLE"
BYTECODE_BLACKHOLE = (PROJECT_ROOT / "outputs/.expected_pe_r8_bytecode_blackhole_DO_NOT_CREATE").resolve()
EXPECTED_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r4_20260821"
)
EXPECTED_LAUNCHER_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation/external_launcher.py"
)
EXPECTED_R7_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation_design_20260821"
)
EXPECTED_R7_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "d0cd9c9f90a56f0eed37cf5c4d9ef742eefca682155561ae5a10ea52ed3ec20a"
)
EXPECTED_AUDITOR_PUBLIC_KEY_HEX = (
    "97ea5e43a65fba73d1e0e23050e42eb3902d2ae23aaf9063aaa8014a852f2a99"
)
EXPECTED_AUDITOR_KEY_ID = (
    "2c1a6ed36404ed3bf4221cbd4c2d569b1c1c5206c1a6d99c39cc941c9ee67087"
)
FAILURE_STAGE = "BOOTSTRAP_BEFORE_EXTERNAL_ANCHOR"


class LauncherError(RuntimeError):
    pass


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical(value: Any) -> bytes:
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


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _load_anchor() -> Mapping[str, Any]:
    raw = ANCHOR.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or _canonical(payload) != raw:
        raise LauncherError("external R8 anchor is not exact canonical JSON")
    expected_keys = {
        "auditor_key_id",
        "auditor_public_key_hex",
        "design_checksums_raw_sha256",
        "design_root_relative",
        "launcher_raw_sha256",
        "launcher_relative",
        "runtime_tcb_raw_sha256",
        "runtime_tcb_relative",
        "r7_design_checksums_raw_sha256",
        "r7_design_root_relative",
        "scheduler_worker_cap",
        "schema_version",
        "source_archive_raw_sha256",
        "source_archive_relative",
        "source_lock_raw_sha256",
        "source_lock_relative",
        "status",
    }
    if set(payload) != expected_keys:
        raise LauncherError("external R8 anchor exact-key schema drifted")
    if (
        payload["schema_version"] != "expected_pe.r8.r4.external_launcher_anchor.v1"
        or payload["status"] != "FROZEN_EXTERNAL_PIN_REPORT_HASH_OUT_OF_BAND"
        or payload["design_root_relative"] != EXPECTED_DESIGN_ROOT_RELATIVE
        or payload["launcher_relative"] != EXPECTED_LAUNCHER_RELATIVE
        or payload["r7_design_root_relative"] != EXPECTED_R7_DESIGN_ROOT_RELATIVE
        or payload["r7_design_checksums_raw_sha256"]
        != EXPECTED_R7_DESIGN_CHECKSUMS_RAW_SHA256
        or payload["auditor_public_key_hex"] != EXPECTED_AUDITOR_PUBLIC_KEY_HEX
        or payload["auditor_key_id"] != EXPECTED_AUDITOR_KEY_ID
        or payload["scheduler_worker_cap"] not in {4, 8, 12, 16}
    ):
        raise LauncherError("external R8-r4 anchor identity binding drifted")
    launcher = (PROJECT_ROOT / payload["launcher_relative"]).resolve(strict=True)
    if (
        launcher != Path(__file__).resolve(strict=True)
        or _is_reparse(launcher)
        or _sha256(launcher.read_bytes()) != payload["launcher_raw_sha256"]
    ):
        raise LauncherError("external R8 launcher self-byte binding drifted")
    return payload


def _load_source(anchor: Mapping[str, Any]) -> tuple[Mapping[str, Any], bytes]:
    lock_path = (PROJECT_ROOT / anchor["source_lock_relative"]).resolve(strict=True)
    archive_path = (PROJECT_ROOT / anchor["source_archive_relative"]).resolve(strict=True)
    lock_raw = lock_path.read_bytes()
    archive_raw = archive_path.read_bytes()
    if (
        _sha256(lock_raw) != anchor["source_lock_raw_sha256"]
        or _sha256(archive_raw) != anchor["source_archive_raw_sha256"]
    ):
        raise LauncherError("recoverable source lock/archive external pin drifted")
    lock = json.loads(lock_raw)
    stored = lock.pop("source_lock_semantic_sha256", None)
    if stored != _sha256(_canonical(lock)):
        raise LauncherError("recoverable source lock logical seal drifted")
    lock["source_lock_semantic_sha256"] = stored
    for record in lock["records"]:
        path = (PROJECT_ROOT / record["relative_path"]).resolve(strict=True)
        raw = path.read_bytes()
        if (
            path.as_posix() != record["absolute_path"]
            or len(raw) != record["size_bytes"]
            or _sha256(raw) != record["raw_sha256"]
            or "__pycache__" in path.parts
            or path.suffix.casefold() in {".pyc", ".pyo"}
            or _is_reparse(path)
        ):
            raise LauncherError(f"governed recoverable source drifted: {path}")
    return lock, archive_raw


def _load_runtime(anchor: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (PROJECT_ROOT / anchor["runtime_tcb_relative"]).resolve(strict=True)
    raw = path.read_bytes()
    if _sha256(raw) != anchor["runtime_tcb_raw_sha256"]:
        raise LauncherError("complete runtime TCB raw pin drifted")
    payload = json.loads(raw)
    stored = payload.pop("runtime_tcb_semantic_sha256", None)
    if stored != _sha256(_canonical(payload)):
        raise LauncherError("complete runtime TCB logical seal drifted")
    payload["runtime_tcb_semantic_sha256"] = stored
    executable = Path(str(payload.get("python_executable", {}).get("path", ""))).resolve(
        strict=True
    )
    site_root = Path(str(payload.get("site_packages_root", ""))).resolve(strict=True)
    if (
        payload.get("schema_version") != "expected_pe.r8.complete_runtime_tcb.v2"
        or payload.get("child_flags") != ["-I", "-S", "-B", "-E"]
        or payload.get("site_import_enabled") is not False
        or payload.get("every_record_member_sealed") is not True
        or payload.get("stdlib_complete_tree_sealed") is not True
        or payload.get("python_native_complete_trees_sealed") is not True
        or payload.get("unsealed_native_module_origins_forbidden") is not True
        or not isinstance(payload.get("python_native_inventory"), dict)
        or payload.get("pycache_or_pyc_member_count") != 0
        or executable != Path(sys.executable).resolve(strict=True)
        or not site_root.is_dir()
        or _is_reparse(site_root)
        or site_root.as_posix() != payload["site_packages_root"]
    ):
        raise LauncherError("complete runtime TCB exact bootstrap binding drifted")
    return payload


def _verify_frozen_design(
    *,
    root_relative: str,
    checksums_raw_sha256: str,
) -> None:
    root = (PROJECT_ROOT / root_relative).resolve(strict=True)
    if not root.is_dir() or _is_reparse(root):
        raise LauncherError("frozen R8 design root is invalid")
    checksum_raw = (root / "CHECKSUMS.sha256").read_bytes()
    if _sha256(checksum_raw) != checksums_raw_sha256:
        raise LauncherError("frozen design checksum pin drifted")
    expected: dict[str, str] = {}
    for line in checksum_raw.decode("ascii").splitlines():
        digest, relative = line.split("  ", 1)
        if relative in expected:
            raise LauncherError("frozen R8 design checksum duplicates a path")
        expected[relative] = digest
    actual: dict[str, str] = {}
    for path in root.rglob("*"):
        if _is_reparse(path):
            raise LauncherError("frozen R8 design contains reparse entry")
        if path.is_file() and path.name != "CHECKSUMS.sha256":
            relative = path.relative_to(root).as_posix()
            actual[relative] = _sha256(path.read_bytes())
        elif not path.is_file() and not path.is_dir():
            raise LauncherError("frozen R8 design contains special entry")
    if actual != expected:
        raise LauncherError("frozen design exact checksum universe drifted")


def _load_design(anchor: Mapping[str, Any]) -> None:
    _verify_frozen_design(
        root_relative=str(anchor["design_root_relative"]),
        checksums_raw_sha256=str(anchor["design_checksums_raw_sha256"]),
    )
    _verify_frozen_design(
        root_relative=str(anchor["r7_design_root_relative"]),
        checksums_raw_sha256=str(anchor["r7_design_checksums_raw_sha256"]),
    )


def _configure_imports(runtime: Mapping[str, Any]) -> None:
    expected = [
        PROJECT_ROOT.resolve(strict=True).as_posix(),
        (PROJECT_ROOT / "src").resolve(strict=True).as_posix(),
        str(runtime["site_packages_root"]),
    ]
    for value in expected:
        path = Path(value).resolve(strict=True)
        if _is_reparse(path):
            raise LauncherError("R8 import root is a reparse point")
        sys.path.append(str(path))


def _bindings(anchor: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "design_checksums_raw_sha256": str(anchor["design_checksums_raw_sha256"]),
        "source_lock_raw_sha256": str(anchor["source_lock_raw_sha256"]),
        "runtime_tcb_raw_sha256": str(anchor["runtime_tcb_raw_sha256"]),
        "scheduler_worker_cap": int(anchor["scheduler_worker_cap"]),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="One authenticated R8 qualification activation; token is read from stdin.",
        allow_abbrev=False,
    )
    root.add_argument("--authority", type=Path, required=True)
    root.add_argument("--run-id", required=True)
    return root


def main() -> int:
    global FAILURE_STAGE

    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or Path(str(sys.pycache_prefix)).resolve(strict=False) != BYTECODE_BLACKHOLE
        or BYTECODE_BLACKHOLE.exists()
    ):
        raise LauncherError("external R8 launcher requires -I -S -B -E and absent pycache blackhole")
    anchor = _load_anchor()
    FAILURE_STAGE = "BOOTSTRAP_SOURCE_RUNTIME_DESIGN_REOPEN"
    source_lock, source_archive_raw = _load_source(anchor)
    if _sha256(source_archive_raw) != anchor["source_archive_raw_sha256"]:
        raise LauncherError("recoverable source archive changed")
    runtime = _load_runtime(anchor)
    _load_design(anchor)
    _configure_imports(runtime)

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_qualification_generation.runtime_tcb import (
        require_isolated_child,
        verify_complete_runtime_tcb,
        verify_loaded_origin_closure,
        verify_startup_runtime_tcb,
    )

    require_isolated_child()
    bindings = _bindings(anchor)
    internal = CAPABILITY_ENV in os.environ
    if internal:
        if len(sys.argv) != 1:
            raise LauncherError("inherited child accepts no caller arguments")
        FAILURE_STAGE = "INTERNAL_STARTUP_TCB_REOPEN"
        startup = verify_startup_runtime_tcb(
            runtime,
            local_source_records=source_lock["records"],
        )
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_qualification_generation.activation import (
            _internal_child_dispatch,
        )

        FAILURE_STAGE = "INHERITED_CAPABILITY_VALIDATION"
        role, receipt = _internal_child_dispatch(bindings=bindings)
        loaded = verify_loaded_origin_closure(
            runtime,
            local_source_records=source_lock["records"],
        )
        if receipt is not None:
            output = {**dict(receipt), "r8_role": role, "startup_tcb": startup, "loaded_tcb": loaded}
            print(json.dumps(output, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0

    FAILURE_STAGE = "TOP_LEVEL_ARGUMENT_VALIDATION"
    arguments = parser().parse_args()
    verify_complete_runtime_tcb(runtime)
    token_line = sys.stdin.buffer.readline(66)
    if (
        len(token_line) != 65
        or token_line[-1:] != b"\n"
        or any(character not in b"0123456789abcdef" for character in token_line[:64])
    ):
        raise LauncherError("activation token stdin must be exactly 64 lowercase hex characters")
    if sys.stdin.buffer.read(1) != b"":
        raise LauncherError("activation token stdin contains trailing material")
    token = token_line[:64].decode("ascii")
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_qualification_generation.activation import (
        activate_once,
    )

    FAILURE_STAGE = "TOP_LEVEL_AUTHORITY_AND_ACTIVATION"
    receipt = activate_once(
        authority_path=arguments.authority,
        activation_token=token,
        run_id=arguments.run_id,
        bindings=bindings,
    )
    loaded = verify_loaded_origin_closure(runtime, local_source_records=source_lock["records"])
    print(
        json.dumps(
            {**dict(receipt), "top_level_loaded_tcb": loaded},
            ensure_ascii=True,
            sort_keys=True,
            allow_nan=False,
        ),
        flush=True,
    )
    return 0


def guarded_main() -> int:
    try:
        return main()
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        forbidden = sorted(
            name
            for name in sys.modules
            if name.endswith(".protected_role")
            or name == "research.model_zoo.dgp_exploration_v2.generator"
        )
        receipt = {
            "status": "FAIL_CLOSED_BEFORE_GENERATION",
            "failure_class": type(exc).__name__,
            "failure_stage": FAILURE_STAGE,
            "protected_generator_imported": bool(forbidden),
            "protected_import_names": forbidden,
            "payload_generated": False,
            "truth_vault_latent_opened": False,
        }
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True), file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(guarded_main())
