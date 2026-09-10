"""Verified-bytes outer bootstrap for all R7 process roles.

This file imports only the standard library until the frozen source lock,
runtime members, path topology, and optional design bundle have been verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation"
)
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
SOURCE_LOCK_PATH = DESIGN_ROOT / "SOURCE_LOCK.json"
PINNED_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_BASE_PYTHON = Path(
    r"C:\Users\minsu\anaconda3\envs\myenv\python.exe"
)
PINNED_SOURCE_LOCK_RAW_SHA256 = "3a7ce804da20c1acfad5812acd5789693a291fbf8eb45e7cd42958500fbc53b6"
EXPECTED_DESIGN_FILES = (
    "ACCESS_RECEIPT.json",
    "AUTHORITY_STATE.json",
    "CHECKSUMS.sha256",
    "CONTROL_CLOSURE.json",
    "DESIGN_LOCK.json",
    "EXECUTABLE_TCB.json",
    "INDEPENDENT_AUDIT_PLAN.json",
    "MANIFEST.json",
    "ONE_SHOT_PROTOCOL.json",
    "PATH_RESOURCE_RECEIPT.json",
    "PROCESS_ISOLATION_CONTRACT.json",
    "PUBLIC_LANE_CONTRACT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "RUNTIME_LOCK.json",
    "SEAL_RECEIPT.json",
    "SOURCE_LOCK.json",
    "SOURCE_TCB_CLOSURE.json",
    "VAULT_METADATA_CONTRACT.json",
)
REQUIRED_ENVIRONMENT = {
    "CUDA_VISIBLE_DEVICES": "-1",
    "MKL_NUM_THREADS": "1",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "NUMEXPR_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
}
EXPECTED_PYCACHE_PREFIX = PROJECT_ROOT / "build" / (
    "pc_r8r8_qualification_generation_actual_once_20260822"
)
EXACT_INTERPRETER_ARGUMENTS = (
    "-I",
    "-S",
    "-B",
    "-E",
    "-X",
    f"pycache_prefix={EXPECTED_PYCACHE_PREFIX}",
)
LIVE_EXECUTION_COMMANDS_DENIED_IN_THIS_REVISION = frozenset(
    {
        "execute",
        "role-protected-generate",
        "role-public-run",
        "role-public-finalize",
    }
)
FORBIDDEN_ENVIRONMENT = (
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONUSERBASE",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
)


class BootstrapError(RuntimeError):
    pass


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _require_plain(path: Path, *, root: Path) -> Path:
    root_resolved = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise BootstrapError("verified path escaped project root") from exc
    cursor = root_resolved
    if _is_reparse(cursor):
        raise BootstrapError("project root is a reparse point")
    for part in relative.parts:
        cursor = cursor / part
        if _is_reparse(cursor):
            raise BootstrapError("verified path contains a reparse component")
    return resolved


def _verify_file_record(path: Path, expected: Mapping[str, Any]) -> None:
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    if (
        resolved.as_posix() != expected.get("path")
        or len(raw) != expected.get("size_bytes")
        or _sha256(raw) != expected.get("raw_sha256")
    ):
        raise BootstrapError("runtime file record drifted")


def _verify_runtime_preimport(runtime: Mapping[str, Any]) -> None:
    _verify_file_record(Path(sys.executable), runtime["python_executable"])
    _verify_file_record(
        Path(getattr(sys, "_base_executable", sys.executable)),
        runtime["python_base_executable"],
    )
    for record in runtime["python_native_dlls"].values():
        _verify_file_record(Path(record["path"]), record)
    for distribution in runtime["distributions"].values():
        _verify_file_record(Path(distribution["record"]["path"]), distribution["record"])
        site_root = Path(runtime["site_packages_root"]).resolve(strict=True)
        for relative, record in distribution["native_members"].items():
            path = (site_root / relative).resolve(strict=True)
            raw = path.read_bytes()
            if len(raw) != record["size_bytes"] or _sha256(raw) != record["raw_sha256"]:
                raise BootstrapError("native distribution member drifted")


def _verify_runtime_module_origins(runtime: Mapping[str, Any]) -> None:
    import importlib

    expected_names = tuple(runtime["critical_module_names"])
    origins = runtime["critical_module_origins"]
    if set(origins) != set(expected_names):
        raise BootstrapError("critical runtime module universe drifted")
    for name in expected_names:
        module = importlib.import_module(name)
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise BootstrapError(f"critical runtime module lacks an origin: {name}")
        _verify_file_record(Path(origin), origins[name])


def _exact_application_arguments(arguments: argparse.Namespace) -> tuple[str, ...]:
    command = arguments.command
    if not isinstance(command, str):
        raise BootstrapError("bootstrap command is not an exact string")
    if command in {
        "role-protected-check",
        "role-public-check",
        "role-public-finalize-check",
    }:
        nonce = arguments.nonce
        if not isinstance(nonce, str):
            raise BootstrapError("bootstrap nonce is not an exact string")
        return (command, "--nonce", nonce)
    return (command,)


def _verify_isolated_flags(
    application_arguments: tuple[str, ...],
) -> Mapping[str, Any]:
    entry = str(Path(__file__).resolve())
    expected_orig_argv = (
        str(PINNED_BASE_PYTHON),
        *EXACT_INTERPRETER_ARGUMENTS,
        entry,
        *application_arguments,
    )
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or getattr(sys.flags, "safe_path", None) not in {None, 1}
    ):
        raise BootstrapError("bootstrap requires exact -I -S -B -E isolation")
    if (
        tuple(sys.orig_argv) != expected_orig_argv
        or sys.argv != [entry, *application_arguments]
        or sys.executable != str(PINNED_PYTHON)
    ):
        raise BootstrapError("bootstrap full executable/flags/entry/app argv drifted")
    for name, expected in REQUIRED_ENVIRONMENT.items():
        if os.environ.get(name) != expected:
            raise BootstrapError(f"required resource environment drifted: {name}")
    for name in FORBIDDEN_ENVIRONMENT:
        if os.environ.get(name):
            raise BootstrapError(f"forbidden import/plugin environment is set: {name}")
    python_environment = sorted(
        name for name in os.environ if name.upper().startswith("PYTHON")
    )
    if python_environment:
        raise BootstrapError(
            f"Python environment controls are forbidden under -E: {python_environment}"
        )
    if sys.pycache_prefix != str(EXPECTED_PYCACHE_PREFIX):
        raise BootstrapError("effective -X pycache prefix drifted")
    prefix = _require_plain(EXPECTED_PYCACHE_PREFIX, root=PROJECT_ROOT)
    if not prefix.is_dir() or any(prefix.iterdir()):
        raise BootstrapError("held pycache prefix is not empty at bootstrap entry")
    return {
        "status": "PASS_EXACT_FULL_COMMAND_AND_PYTHON_ENVIRONMENT_COUNT_ZERO",
        "orig_argv": list(expected_orig_argv),
        "orig_argv_exact_full_equality": True,
        "venv_executable": str(PINNED_PYTHON),
        "base_executable_orig_argv_zero": str(PINNED_BASE_PYTHON),
        "environment_entry_count_inspected": len(os.environ),
        "python_environment_control_names": [],
        "python_environment_control_count": 0,
    }


def _verify_directory_universe(lock: Mapping[str, Any]) -> None:
    for relative_root, expected_records in lock["governed_directory_files"].items():
        root = _require_plain(PROJECT_ROOT / relative_root, root=PROJECT_ROOT)
        actual: dict[str, Any] = {}

        def visit(directory: Path) -> None:
            with os.scandir(directory) as stream:
                children = sorted(stream, key=lambda item: item.name.casefold())
            if directory != root and not children:
                raise BootstrapError("governed directory contains an unbound empty directory")
            for child in children:
                path = Path(child.path)
                metadata = os.lstat(path)
                if _is_reparse(path):
                    raise BootstrapError("governed directory contains a reparse entry")
                if stat.S_ISREG(metadata.st_mode):
                    relative = path.relative_to(root).as_posix()
                    raw = path.read_bytes()
                    actual[relative] = {
                        "raw_sha256": _sha256(raw),
                        "size_bytes": len(raw),
                    }
                elif stat.S_ISDIR(metadata.st_mode):
                    visit(path)
                else:
                    raise BootstrapError("governed directory contains a special entry")

        visit(root)
        if actual != expected_records:
            raise BootstrapError(f"governed exact directory universe drifted: {relative_root}")


def _load_and_verify_source_lock(
    application_arguments: tuple[str, ...],
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    launch_preflight = _verify_isolated_flags(application_arguments)
    path = _require_plain(SOURCE_LOCK_PATH, root=PROJECT_ROOT)
    raw = path.read_bytes()
    if _sha256(raw) != PINNED_SOURCE_LOCK_RAW_SHA256:
        raise BootstrapError("externally pinned source lock drifted")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("source lock cannot be decoded") from exc
    stored = payload.pop("manifest_sha256", None)
    if stored != _sha256(_canonical(payload)):
        raise BootstrapError("source lock logical seal drifted")
    payload["manifest_sha256"] = stored
    script_root = _require_plain(PROJECT_ROOT / SCRIPT_RELATIVE, root=PROJECT_ROOT)
    script_children = tuple(sorted(path.name for path in script_root.iterdir()))
    if script_children != tuple(payload["script_exact_universe"]) or any(
        not path.is_file() or _is_reparse(path) for path in script_root.iterdir()
    ):
        raise BootstrapError("launcher script exact universe drifted")
    expected_paths = set()
    for relative, digest, size in payload["source_sha256"]:
        if relative in expected_paths:
            raise BootstrapError("source lock contains a duplicate path")
        expected_paths.add(relative)
        source = _require_plain(PROJECT_ROOT / relative, root=PROJECT_ROOT)
        raw_source = source.read_bytes()
        if len(raw_source) != size or _sha256(raw_source) != digest:
            raise BootstrapError(f"governed source bytes drifted: {relative}")
    _verify_directory_universe(payload)
    _verify_runtime_preimport(payload["runtime_lock"])
    current = [Path(item).resolve(strict=False).as_posix() for item in sys.path]
    if current != payload["runtime_lock"]["isolated_base_sys_path"]:
        raise BootstrapError("isolated base sys.path topology drifted")
    for item in payload["runtime_lock"]["expected_added_sys_path"]:
        resolved = Path(item).resolve(strict=True)
        if _is_reparse(resolved):
            raise BootstrapError("added sys.path entry is a reparse point")
        sys.path.append(str(resolved))
    expected_full = (
        payload["runtime_lock"]["isolated_base_sys_path"]
        + payload["runtime_lock"]["expected_added_sys_path"]
    )
    if [Path(item).resolve(strict=False).as_posix() for item in sys.path] != expected_full:
        raise BootstrapError("configured sys.path topology drifted")
    _verify_runtime_module_origins(payload["runtime_lock"])
    return payload, launch_preflight


def _read_exact_design(*, required: bool) -> dict[str, bytes] | None:
    if not DESIGN_ROOT.exists():
        if required:
            raise BootstrapError("frozen R8-r8 design is absent")
        return None
    root = _require_plain(DESIGN_ROOT, root=PROJECT_ROOT)
    children = tuple(root.iterdir())
    names = tuple(sorted(path.name for path in children))
    if names != EXPECTED_DESIGN_FILES or any(
        not path.is_file() or _is_reparse(path) for path in children
    ):
        raise BootstrapError("frozen R8-r8 design exact universe drifted")
    raw = {name: (root / name).read_bytes() for name in names}
    ledger: dict[str, str] = {}
    for line in raw["CHECKSUMS.sha256"].decode("ascii").splitlines():
        digest, name = line.split("  ", 1)
        if name in ledger or name not in raw or _sha256(raw[name]) != digest:
            raise BootstrapError("frozen R8-r8 design checksum ledger drifted")
        ledger[name] = digest
    if set(ledger) != set(raw).difference({"CHECKSUMS.sha256"}):
        raise BootstrapError("frozen R8-r8 design checksum universe drifted")
    for name, content in raw.items():
        if not name.endswith(".json"):
            continue
        payload = json.loads(content)
        stored = payload.pop("manifest_sha256", None)
        if stored != _sha256(_canonical(payload)):
            raise BootstrapError(f"frozen R8-r8 design self-seal drifted: {name}")
    return raw


def _verify_lock_design_binding(
    lock: Mapping[str, Any], design: Mapping[str, bytes] | None
) -> None:
    if design is None:
        return
    executable = json.loads(design["EXECUTABLE_TCB.json"])
    runtime = json.loads(design["RUNTIME_LOCK.json"])
    if (
        executable.get("source_lock_raw_sha256") != PINNED_SOURCE_LOCK_RAW_SHA256
        or executable.get("source_sha256") != lock["source_sha256"]
        or runtime.get("runtime_lock") != lock["runtime_lock"]
    ):
        raise BootstrapError("source/runtime lock and frozen design binding drifted")


class PublicFilesystemGuard:
    """Deny output-tree access outside the explicit public staging/design roots."""

    def __init__(self, *, public_root: Path) -> None:
        self.public_root = public_root.resolve(strict=False)
        self.outputs = (PROJECT_ROOT / "outputs").resolve(strict=True)
        self.design = DESIGN_ROOT.resolve(strict=False)
        self.temp = Path(tempfile.gettempdir()).resolve(strict=True)
        self.system_roots = tuple(
            {
                Path(sys.prefix).resolve(strict=True),
                Path(sys.base_prefix).resolve(strict=True),
                PROJECT_ROOT.resolve(strict=True),
                self.temp,
                *(Path(item).resolve(strict=False) for item in sys.path if item),
            }
        )

    def _allowed(self, candidate: Path, *, write: bool) -> bool:
        resolved = candidate.resolve(strict=False)
        if resolved.is_relative_to(self.public_root):
            return True
        if resolved.is_relative_to(self.design):
            return not write
        if resolved.is_relative_to(self.outputs):
            return False
        if write:
            return resolved.is_relative_to(self.temp)
        return any(resolved.is_relative_to(root) for root in self.system_roots)

    def __call__(self, event: str, arguments: tuple[Any, ...]) -> None:
        if event not in {"open", "os.listdir", "os.scandir"}:
            return
        if not arguments or isinstance(arguments[0], int):
            return
        value = arguments[0]
        if not isinstance(value, (str, bytes, os.PathLike)):
            return
        path = Path(os.fsdecode(value))
        mode = arguments[1] if event == "open" and len(arguments) > 1 else "r"
        write = isinstance(mode, str) and any(token in mode for token in ("w", "a", "x", "+"))
        if not self._allowed(path, write=write):
            raise PermissionError("R7 public role filesystem guard denied path")


def _verify_loaded_local_origins(lock: Mapping[str, Any]) -> None:
    expected = {str(relative): digest for relative, digest, _size in lock["source_sha256"]}
    for name, module in tuple(sys.modules.items()):
        if not (name.startswith("research.model_zoo") or name.startswith("pe_regime_v04")):
            continue
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            continue
        path = Path(origin).resolve(strict=True)
        if path.suffix.casefold() == ".pyc":
            raise BootstrapError("governed local module loaded from bytecode")
        try:
            relative = path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            continue
        if relative not in expected or _sha256(path.read_bytes()) != expected[relative]:
            raise BootstrapError(f"loaded local module origin is ungoverned: {name}")


def _verify_public_namespace_separation() -> None:
    forbidden = sorted(
        name
        for name in sys.modules
        if name.startswith(
            (
                "research.model_zoo.dgp_exploration_v2",
                "research.model_zoo.dgp_suite",
            )
        )
        or name.endswith(".protected_role")
    )
    if forbidden:
        raise BootstrapError("public process imported a protected namespace")


def dispatch(
    arguments: argparse.Namespace,
    lock: Mapping[str, Any],
    _design: Mapping[str, bytes] | None,
    launch_preflight: Mapping[str, Any] | None = None,
) -> int:
    command = arguments.command
    if command in LIVE_EXECUTION_COMMANDS_DENIED_IN_THIS_REVISION:
        raise BootstrapError(
            "DENIED_PENDING_SEPARATE_AUDITED_MEMORY_ONLY_CHILD_CAPABILITY_REVISION"
        )
    if command in {"check-only", "check-only-preflight"}:
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.custodian import (
            check_only,
        )

        receipt = check_only()
        if launch_preflight is not None:
            receipt = {**receipt, "launch_preflight": dict(launch_preflight)}
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "role-protected-check":
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.protected_role import (
            check_only,
        )

        check_only(nonce=arguments.nonce)
        _verify_loaded_local_origins(lock)
        return 0
    if command == "role-public-check":
        planned_public = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r8_"
            "qualification_generation_check_only_probe"
        )
        sys.addaudithook(PublicFilesystemGuard(public_root=planned_public))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.public_role import (
            check_only,
        )

        receipt = check_only(nonce=arguments.nonce)
        if launch_preflight is not None:
            receipt = {**receipt, "launch_preflight": dict(launch_preflight)}
        _verify_public_namespace_separation()
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "role-public-finalize-check":
        planned_public = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r8_"
            "qualification_generation_check_only_probe"
        )
        sys.addaudithook(PublicFilesystemGuard(public_root=planned_public))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.controller import (
            validate_planned_public_path,
        )

        if len(arguments.nonce) != 64 or any(
            character not in "0123456789abcdef" for character in arguments.nonce
        ):
            raise BootstrapError("public finalizer check nonce is invalid")
        path_receipt = validate_planned_public_path(
            planned_public, outputs_root=PROJECT_ROOT / "outputs"
        )
        _verify_public_namespace_separation()
        _verify_loaded_local_origins(lock)
        receipt = {
            "status": "PASS_PUBLIC_FINALIZER_IMPORTED_NO_PAYLOAD",
            "nonce_sha256": _sha256(arguments.nonce.encode("ascii")),
            "planned_public": path_receipt,
            "artifact_open_count": 0,
            "protected_import_present": False,
        }
        if launch_preflight is not None:
            receipt["launch_preflight"] = dict(launch_preflight)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    raise BootstrapError("unsupported R8-r8 bootstrap command")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("check-only")
    sub.add_parser("check-only-preflight")
    sub.add_parser("execute")
    protected_check = sub.add_parser("role-protected-check")
    protected_check.add_argument("--nonce", required=True)
    public_check = sub.add_parser("role-public-check")
    public_check.add_argument("--nonce", required=True)
    finalizer_check = sub.add_parser("role-public-finalize-check")
    finalizer_check.add_argument("--nonce", required=True)
    sub.add_parser("role-protected-generate")
    sub.add_parser("role-public-run")
    sub.add_parser("role-public-finalize")
    return root


def main() -> int:
    arguments = parser().parse_args()
    application_arguments = _exact_application_arguments(arguments)
    lock, launch_preflight = _load_and_verify_source_lock(application_arguments)
    design_required = arguments.command not in {
        "check-only-preflight",
        "role-protected-check",
        "role-public-check",
        "role-public-finalize-check",
        *LIVE_EXECUTION_COMMANDS_DENIED_IN_THIS_REVISION,
    }
    design = _read_exact_design(required=design_required)
    _verify_lock_design_binding(lock, design)
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.custodian import (
        bind_held_no_bytecode_window,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.no_bytecode import (
        HeldExistingNoBytecodeWindow,
    )

    with HeldExistingNoBytecodeWindow(
        path=Path(sys.pycache_prefix),
        ancestry_root=Path(Path(sys.pycache_prefix).anchor),
    ) as no_bytecode_window:
        with bind_held_no_bytecode_window(no_bytecode_window):
            return dispatch(arguments, lock, design, launch_preflight)


if __name__ == "__main__":
    raise SystemExit(main())
