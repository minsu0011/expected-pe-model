"""Verified-bytes outer bootstrap for all R7 process roles.

This file imports only the standard library until the frozen source lock,
runtime members, path topology, and optional design bundle have been verified.
"""

from __future__ import annotations

import argparse
import base64
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
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r7_qualification_generation"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_qualification_generation"
)
SOURCE_LOCK_PATH = PROJECT_ROOT / SCRIPT_RELATIVE / "SOURCE_LOCK.json"
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation_design_20260821"
)
PINNED_SOURCE_LOCK_RAW_SHA256 = "9a23b46c5c8ec0c0f7eaf2b1a8300f96486675473f02432d146a5f1190036e5e"
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


def _verify_isolated_flags() -> None:
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or getattr(sys.flags, "safe_path", None) not in {None, 1}
    ):
        raise BootstrapError("bootstrap requires -I -S -B -E")
    for name, expected in REQUIRED_ENVIRONMENT.items():
        if os.environ.get(name) != expected:
            raise BootstrapError(f"required resource environment drifted: {name}")
    for name in FORBIDDEN_ENVIRONMENT:
        if os.environ.get(name):
            raise BootstrapError(f"forbidden import/plugin environment is set: {name}")


def _verify_directory_universe(lock: Mapping[str, Any]) -> None:
    for relative_root, expected_records in lock["governed_directory_files"].items():
        root = _require_plain(PROJECT_ROOT / relative_root, root=PROJECT_ROOT)
        actual: dict[str, Any] = {}
        for path in root.rglob("*"):
            if _is_reparse(path):
                raise BootstrapError("governed directory contains a reparse entry")
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                raw = path.read_bytes()
                actual[relative] = {"raw_sha256": _sha256(raw), "size_bytes": len(raw)}
            elif not path.is_dir():
                raise BootstrapError("governed directory contains a special entry")
        if actual != expected_records:
            raise BootstrapError(f"governed exact directory universe drifted: {relative_root}")


def _load_and_verify_source_lock() -> dict[str, Any]:
    _verify_isolated_flags()
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
    return payload


def _read_exact_design(*, required: bool) -> dict[str, bytes] | None:
    if not DESIGN_ROOT.exists():
        if required:
            raise BootstrapError("frozen R7 design is absent")
        return None
    root = _require_plain(DESIGN_ROOT, root=PROJECT_ROOT)
    children = tuple(root.iterdir())
    names = tuple(sorted(path.name for path in children))
    if names != EXPECTED_DESIGN_FILES or any(
        not path.is_file() or _is_reparse(path) for path in children
    ):
        raise BootstrapError("frozen R7 design exact universe drifted")
    raw = {name: (root / name).read_bytes() for name in names}
    ledger: dict[str, str] = {}
    for line in raw["CHECKSUMS.sha256"].decode("ascii").splitlines():
        digest, name = line.split("  ", 1)
        if name in ledger or name not in raw or _sha256(raw[name]) != digest:
            raise BootstrapError("frozen R7 design checksum ledger drifted")
        ledger[name] = digest
    if set(ledger) != set(raw).difference({"CHECKSUMS.sha256"}):
        raise BootstrapError("frozen R7 design checksum universe drifted")
    for name, content in raw.items():
        if not name.endswith(".json"):
            continue
        payload = json.loads(content)
        stored = payload.pop("manifest_sha256", None)
        if stored != _sha256(_canonical(payload)):
            raise BootstrapError(f"frozen R7 design self-seal drifted: {name}")
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


def _decode_mapping(value: str, *, label: str) -> dict[str, Any]:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"{label} is invalid") from exc
    if not isinstance(payload, dict):
        raise BootstrapError(f"{label} is not an object")
    return payload


def _design_runtime(design: Mapping[str, bytes]) -> tuple[dict[str, Any], dict[str, Any], str]:
    lock = json.loads(design["DESIGN_LOCK.json"])
    checksums = _sha256(design["CHECKSUMS.sha256"])
    return lock["replay_inventory"], lock["child_runtime_reference"], checksums


def dispatch(
    arguments: argparse.Namespace, lock: Mapping[str, Any], design: Mapping[str, bytes] | None
) -> int:
    command = arguments.command
    if command in {"check-only", "check-only-preflight"}:
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.custodian import (
            check_only,
        )

        receipt = check_only()
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "execute":
        if design is None:
            raise BootstrapError("qualification execution requires frozen design")
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.custodian import (
            run_qualification,
        )

        authority = _decode_mapping(arguments.authority_base64, label="activation authority")
        token_raw = sys.stdin.buffer.read()
        try:
            activation_token = token_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BootstrapError("activation token stdin is not ASCII") from exc
        if len(activation_token) != 64 or any(
            character not in "0123456789abcdef" for character in activation_token
        ):
            raise BootstrapError("activation token stdin must be exactly 64 lowercase hex bytes")
        _inventory, _child_runtime, design_checksums = _design_runtime(design)
        runtime_semantic = lock["runtime_lock"]["runtime_semantic_sha256"]
        receipt = run_qualification(
            authority=authority,
            activation_token=activation_token,
            public_run_id=arguments.public_run_id,
            design_checksums_raw_sha256=design_checksums,
            source_lock_raw_sha256=PINNED_SOURCE_LOCK_RAW_SHA256,
            runtime_lock_semantic_sha256=runtime_semantic,
        )
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
        sys.addaudithook(PublicFilesystemGuard(public_root=Path(arguments.public_root)))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.public_role import (
            check_only,
        )

        receipt = check_only(nonce=arguments.nonce)
        _verify_public_namespace_separation()
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "role-public-finalize-check":
        sys.addaudithook(PublicFilesystemGuard(public_root=Path(arguments.public_root)))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.controller import (
            validate_planned_public_path,
        )

        if len(arguments.nonce) != 64 or any(
            character not in "0123456789abcdef" for character in arguments.nonce
        ):
            raise BootstrapError("public finalizer check nonce is invalid")
        path_receipt = validate_planned_public_path(
            Path(arguments.public_root), outputs_root=PROJECT_ROOT / "outputs"
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
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "role-protected-generate":
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.protected_role import (
            generate_task,
        )

        first = (
            None
            if arguments.first_protected_hashes_base64 is None
            else _decode_mapping(
                arguments.first_protected_hashes_base64,
                label="first protected hashes",
            )
        )
        generate_task(
            seed=arguments.seed,
            dgp=arguments.dgp,
            replay_pass=arguments.replay_pass,
            vault_pass_root=Path(arguments.vault_pass_root),
            expected_first_protected_hashes=first,
        )
        _verify_loaded_local_origins(lock)
        return 0
    if command == "role-public-run":
        if design is None:
            raise BootstrapError("public generation role requires frozen design")
        sys.addaudithook(PublicFilesystemGuard(public_root=Path(arguments.public_task_root)))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.public_role import (
            run_task,
        )

        inventory, child_runtime, design_checksums = _design_runtime(design)
        if arguments.design_checksums_raw_sha256 != design_checksums:
            raise BootstrapError("public role design checksum drifted")
        receipt = run_task(
            seed=arguments.seed,
            dgp=arguments.dgp,
            replay_pass=arguments.replay_pass,
            task_root=Path(arguments.public_task_root),
            expected_inventory=inventory,
            expected_child_runtime=child_runtime,
        )
        _verify_public_namespace_separation()
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    if command == "role-public-finalize":
        if design is None:
            raise BootstrapError("public finalizer requires frozen design")
        sys.addaudithook(PublicFilesystemGuard(public_root=Path(arguments.public_staging)))
        _verify_public_namespace_separation()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.controller import (
            finalize_public_staging,
        )

        metadata = _decode_mapping(arguments.opaque_metadata_base64, label="opaque metadata")
        receipt = finalize_public_staging(
            staging=Path(arguments.public_staging),
            protected_metadata=metadata,
            design_checksums_raw_sha256=arguments.design_checksums_raw_sha256,
            source_lock_raw_sha256=arguments.source_lock_raw_sha256,
            runtime_lock_semantic_sha256=arguments.runtime_lock_semantic_sha256,
        )
        _verify_public_namespace_separation()
        _verify_loaded_local_origins(lock)
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
        return 0
    raise BootstrapError("unsupported R7 bootstrap command")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("check-only")
    sub.add_parser("check-only-preflight")
    execute = sub.add_parser("execute")
    execute.add_argument("--authority-base64", required=True)
    execute.add_argument("--public-run-id", required=True)
    protected_check = sub.add_parser("role-protected-check")
    protected_check.add_argument("--nonce", required=True)
    public_check = sub.add_parser("role-public-check")
    public_check.add_argument("--nonce", required=True)
    public_check.add_argument("--public-root", required=True)
    finalizer_check = sub.add_parser("role-public-finalize-check")
    finalizer_check.add_argument("--nonce", required=True)
    finalizer_check.add_argument("--public-root", required=True)
    protected_generate = sub.add_parser("role-protected-generate")
    protected_generate.add_argument("--seed", type=int, required=True)
    protected_generate.add_argument("--dgp", required=True)
    protected_generate.add_argument("--replay-pass", type=int, required=True)
    protected_generate.add_argument("--vault-pass-root", required=True)
    protected_generate.add_argument("--first-protected-hashes-base64")
    public_run = sub.add_parser("role-public-run")
    public_run.add_argument("--seed", type=int, required=True)
    public_run.add_argument("--dgp", required=True)
    public_run.add_argument("--replay-pass", type=int, required=True)
    public_run.add_argument("--public-task-root", required=True)
    public_run.add_argument("--design-checksums-raw-sha256", required=True)
    public_finalize = sub.add_parser("role-public-finalize")
    public_finalize.add_argument("--public-staging", required=True)
    public_finalize.add_argument("--opaque-metadata-base64", required=True)
    public_finalize.add_argument("--design-checksums-raw-sha256", required=True)
    public_finalize.add_argument("--source-lock-raw-sha256", required=True)
    public_finalize.add_argument("--runtime-lock-semantic-sha256", required=True)
    return root


def main() -> int:
    arguments = parser().parse_args()
    lock = _load_and_verify_source_lock()
    design_required = arguments.command not in {
        "check-only-preflight",
        "role-protected-check",
        "role-public-check",
        "role-public-finalize-check",
    }
    design = _read_exact_design(required=design_required)
    _verify_lock_design_binding(lock, design)
    return dispatch(arguments, lock, design)


if __name__ == "__main__":
    raise SystemExit(main())
