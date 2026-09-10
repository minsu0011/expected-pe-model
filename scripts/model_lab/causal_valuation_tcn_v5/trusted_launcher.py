"""Externally pinned, stdlib-only launcher for the score-free V5 preflight.

The launcher treats its own externally anchored bytes plus two fixed-path lock
files as the trust root.  No caller-supplied path, manifest, module, or source
digest participates in attestation.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import types
from typing import Any, Mapping


PROJECT_ROOT_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
PINNED_PYTHON_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_torch_py310\\Scripts\\python.exe"
)
TORCH_SITE_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_torch_py310\\Lib\\site-packages"
)
PANDAS_SITE_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_py310\\Lib\\site-packages"
)
SOURCE_LOCK_TEXT = PROJECT_ROOT_TEXT + (
    "\\scripts\\model_lab\\causal_valuation_tcn_v5\\V5_SOURCE_LOCK.json"
)
RUNTIME_LOCK_TEXT = PROJECT_ROOT_TEXT + (
    "\\scripts\\model_lab\\causal_valuation_tcn_v5\\V5_RUNTIME_LOCK.json"
)
LAUNCHER_TEXT = PROJECT_ROOT_TEXT + (
    "\\scripts\\model_lab\\causal_valuation_tcn_v5\\trusted_launcher.py"
)
STAGE_TEXT = PROJECT_ROOT_TEXT + "\\outputs\\.causal_valuation_tcn_v5_verified_stage"

# These literals are patched only by the isolated lock-preparation build step.
# The final external anchor pins this launcher, both lock files, and the bundle.
PINNED_SOURCE_LOCK_SHA256 = "ba62b1e86d42f78c9db507c2c784378459ff646087d6e703440ef8affdbc6d85"
PINNED_RUNTIME_LOCK_SHA256 = "ddce6212e26a8bdafeb83b12e1da03f85aef18d6ca5e1cb2033388912fce160d"

SOURCE_SCHEMA = "expected_pe.causal_valuation_tcn_v5.source_lock.v1"
RUNTIME_SCHEMA = "expected_pe.causal_valuation_tcn_v5.runtime_lock.v1"
PREIMPORT_SCHEMA = "expected_pe.causal_valuation_tcn_v5.preimport_attestation.v2"
SOURCE_PACKAGE_PREFIX = "research.model_zoo.causal_valuation_tcn_v5"
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
AUTHORITY_ZERO = {
    "real_fit": False,
    "real_prediction": False,
    "evaluation": False,
    "truth_or_vault": False,
    "heldout": False,
    "score": False,
    "registry_or_champion": False,
    "seed_derivation_or_reservation": False,
    "promotion": False,
}


class PreimportError(RuntimeError):
    """Raised before any governed or numeric source is imported."""


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(8 * 1024 * 1024)
            if not block:
                return hasher.hexdigest()
            hasher.update(block)


def _require_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PreimportError(f"{label} is not lowercase SHA-256")
    return value


def _ordinary(path: Path, *, directory: bool | None, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise PreimportError(f"{label} is absent") from error
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise PreimportError(f"{label} contains a reparse/symlink component")
    metadata = os.lstat(absolute)
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise PreimportError(f"{label} is not an ordinary directory")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise PreimportError(f"{label} is not an ordinary file")
    return absolute


def _strict_object(content: bytes, *, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in values:
            if type(key) is not str or key in output:
                raise PreimportError(f"{label} duplicate/invalid JSON key")
            output[key] = value
        return output

    try:
        text = content.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PreimportError(f"{label} non-finite JSON token: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreimportError(f"{label} is not strict UTF-8 JSON") from error
    if type(payload) is not dict:
        raise PreimportError(f"{label} root is not an object")
    return payload


def _read_pinned_lock(path_text: str, digest: str, *, label: str) -> dict[str, Any]:
    _require_sha256(digest, f"pinned {label} hash")
    if digest.startswith("__"):
        raise PreimportError(f"{label} hash was not finalized")
    path = _ordinary(Path(path_text), directory=False, label=label)
    content = path.read_bytes()
    if _sha256_bytes(content) != digest:
        raise PreimportError(f"{label} raw bytes differ from launcher trust root")
    return _strict_object(content, label=label)


def _exact_direct_children(root: Path, expected: Mapping[str, str], *, label: str) -> None:
    root = _ordinary(root, directory=True, label=label)
    actual: dict[str, str] = {}
    for child in root.iterdir():
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise PreimportError(f"{label} contains a reparse/symlink child")
        if stat.S_ISREG(metadata.st_mode):
            kind = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        else:
            kind = "other"
        actual[child.name] = kind
        if child.suffix.casefold() in {".pyc", ".pyo", ".pyd", ".dll"}:
            raise PreimportError(f"{label} contains forbidden executable/bytecode content")
    if actual != dict(expected):
        raise PreimportError(f"{label} exact direct-child universe drifted")


def _verify_source_lock() -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
    project = _ordinary(Path(PROJECT_ROOT_TEXT), directory=True, label="project root")
    lock = _read_pinned_lock(
        SOURCE_LOCK_TEXT, PINNED_SOURCE_LOCK_SHA256, label="V5 source lock"
    )
    required = {
        "schema_version",
        "status",
        "project_root",
        "source_records",
        "exact_roots",
        "stage_paths",
        "source_manifest_sha256",
        "authority",
    }
    if set(lock) != required:
        raise PreimportError("source lock exact schema drifted")
    if (
        lock["schema_version"] != SOURCE_SCHEMA
        or lock["status"] != "EXTERNALLY_PINNED_VERIFIED_SOURCE_BYTES"
        or lock["project_root"] != PROJECT_ROOT_TEXT
        or lock["authority"] != AUTHORITY_ZERO
    ):
        raise PreimportError("source lock identity/policy drifted")
    roots = lock["exact_roots"]
    if type(roots) is not dict or sorted(roots) != list(roots):
        raise PreimportError("source lock root universe/order drifted")
    for relative, children in roots.items():
        if type(relative) is not str or type(children) is not dict:
            raise PreimportError("source lock root record drifted")
        if sorted(children) != list(children) or any(
            type(name) is not str or kind not in {"file", "directory"}
            for name, kind in children.items()
        ):
            raise PreimportError("source lock root child record drifted")
        _exact_direct_children(project / relative, children, label=relative)
    records = lock["source_records"]
    if type(records) is not list:
        raise PreimportError("source record universe is not a list")
    paths = [record.get("path") if type(record) is dict else None for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PreimportError("source record universe/order is not exact")
    captured: dict[str, bytes] = {}
    normalized_records: list[dict[str, Any]] = []
    for record in records:
        if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
            raise PreimportError("source record schema drifted")
        relative = record["path"]
        if type(relative) is not str or "\\" in relative or relative.startswith("/"):
            raise PreimportError("source record path is not canonical relative POSIX")
        path = _ordinary(project / relative, directory=False, label=relative)
        if path.suffix.casefold() in {".pyc", ".pyo", ".pyd", ".dll"}:
            raise PreimportError("source lock contains forbidden executable/bytecode")
        content = path.read_bytes()
        digest = _sha256_bytes(content)
        if record["bytes"] != len(content) or record["raw_sha256"] != digest:
            raise PreimportError(f"verified source bytes drifted: {relative}")
        captured[relative] = content
        normalized_records.append(dict(record))
    manifest = _sha256_bytes(_canonical(normalized_records))
    if lock["source_manifest_sha256"] != manifest:
        raise PreimportError("source lock semantic manifest drifted")
    stage_paths = lock["stage_paths"]
    expected_stage = sorted(
        [*paths, Path(LAUNCHER_TEXT).relative_to(project).as_posix(),
         Path(SOURCE_LOCK_TEXT).relative_to(project).as_posix(),
         Path(RUNTIME_LOCK_TEXT).relative_to(project).as_posix()]
    )
    if stage_paths != expected_stage:
        raise PreimportError("source lock stage universe drifted")
    launcher = _ordinary(Path(LAUNCHER_TEXT), directory=False, label="trusted launcher")
    captured[launcher.relative_to(project).as_posix()] = launcher.read_bytes()
    for lock_path in (Path(SOURCE_LOCK_TEXT), Path(RUNTIME_LOCK_TEXT)):
        ordinary = _ordinary(lock_path, directory=False, label="fixed lock")
        captured[ordinary.relative_to(project).as_posix()] = ordinary.read_bytes()
    return lock, captured, {
        "source_lock_sha256": PINNED_SOURCE_LOCK_SHA256,
        "source_manifest_sha256": manifest,
        "source_record_count": len(records),
        "stage_exact_file_universe": stage_paths,
    }


def _decode_record_hash(value: str, label: str) -> str:
    if not value.startswith("sha256="):
        raise PreimportError(f"{label} RECORD hash algorithm drifted")
    try:
        raw = base64.urlsafe_b64decode(value[7:] + "=" * (-len(value[7:]) % 4))
    except Exception as error:
        raise PreimportError(f"{label} RECORD hash is malformed") from error
    if len(raw) != 32:
        raise PreimportError(f"{label} RECORD hash length drifted")
    return raw.hex()


def _distribution_receipt(
    distribution: importlib.metadata.Distribution, *, name: str
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    text = distribution.read_text("RECORD")
    if type(text) is not str:
        raise PreimportError(f"RECORD absent: {name}")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    seen: set[str] = set()
    duplicate_paths = 0
    members = hashlib.sha256(b"expected_pe.causal_valuation_tcn_v5.record_members.v1\0")
    file_map: dict[str, dict[str, Any]] = {}
    counts = {"hashed": 0, "unhashed": 0, "present_unhashed": 0, "pyc": 0, "pyc_mismatch": 0}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise PreimportError(f"RECORD exact row universe drifted: {name}")
        relative, encoded_hash, encoded_size = row
        if relative in seen:
            duplicate_paths += 1
        seen.add(relative)
        path = Path(os.path.abspath(distribution.locate_file(relative)))
        exists = path.exists()
        actual_hash = ""
        actual_size = -1
        matches: bool | None = None
        is_pyc = Path(relative).suffix.casefold() in {".pyc", ".pyo"}
        if is_pyc:
            counts["pyc"] += 1
        if encoded_hash:
            expected_hash = _decode_record_hash(encoded_hash, f"{name}:{relative}")
            ordinary = _ordinary(path, directory=False, label=f"{name}:{relative}")
            actual_size = ordinary.stat().st_size
            try:
                expected_size = int(encoded_size)
            except ValueError as error:
                raise PreimportError(f"RECORD size malformed: {name}:{relative}") from error
            actual_hash = _sha256_file(ordinary)
            matches = expected_size == actual_size and expected_hash == actual_hash
            if not matches and not is_pyc:
                raise PreimportError(f"RECORD member bytes drifted: {name}:{relative}")
            if not matches:
                counts["pyc_mismatch"] += 1
            counts["hashed"] += 1
            if matches and not is_pyc:
                file_map[ordinary.as_posix().casefold()] = {
                    "path": ordinary.as_posix(),
                    "bytes": actual_size,
                    "raw_sha256": actual_hash,
                }
        else:
            if encoded_size:
                raise PreimportError(f"unhashed RECORD size drifted: {name}:{relative}")
            counts["unhashed"] += 1
            if exists:
                ordinary = _ordinary(path, directory=False, label=f"{name}:{relative}")
                actual_size = ordinary.stat().st_size
                actual_hash = _sha256_file(ordinary)
                counts["present_unhashed"] += 1
        members.update(_canonical({
            "path": relative.replace("\\", "/"),
            "record_hash": encoded_hash,
            "record_size": encoded_size,
            "present": exists,
            "actual_size": actual_size,
            "actual_sha256": actual_hash,
            "record_content_matches": matches,
            "dependency_bytecode_executable": False,
        }))
    receipt = {
        "version": distribution.version,
        "record_raw_sha256": _sha256_bytes(text.encode("utf-8")),
        "record_row_count": len(rows),
        "hashed_member_count": counts["hashed"],
        "unhashed_member_count": counts["unhashed"],
        "present_unhashed_member_count": counts["present_unhashed"],
        "duplicate_record_path_count": duplicate_paths,
        "nonexecuted_pyc_member_count": counts["pyc"],
        "nonexecuted_pyc_mismatch_count": counts["pyc_mismatch"],
        "exact_member_universe_sha256": members.hexdigest(),
    }
    return receipt, file_map


def _verify_site(
    site_text: str,
    expected_versions: Mapping[str, str],
    expected_receipts: Mapping[str, Any],
    *,
    exact_distribution_universe: bool,
    label: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    _ordinary(Path(site_text), directory=True, label=label)
    distributions = tuple(importlib.metadata.distributions(path=[site_text]))
    by_name: dict[str, importlib.metadata.Distribution] = {}
    for distribution in distributions:
        name = distribution.metadata.get("Name")
        if type(name) is not str or name in by_name:
            raise PreimportError(f"{label} distribution universe is ambiguous")
        by_name[name] = distribution
    if exact_distribution_universe and set(by_name) != set(expected_versions):
        raise PreimportError(f"{label} exact distribution universe drifted")
    if not set(expected_versions).issubset(by_name):
        raise PreimportError(f"{label} required distribution is absent")
    if set(expected_receipts) != set(expected_versions):
        raise PreimportError(f"{label} receipt universe drifted")
    receipts: dict[str, Any] = {}
    file_map: dict[str, dict[str, Any]] = {}
    for name in sorted(expected_versions):
        distribution = by_name[name]
        if distribution.version != expected_versions[name]:
            raise PreimportError(f"{label} version drifted: {name}")
        receipt, members = _distribution_receipt(distribution, name=name)
        if receipt != expected_receipts[name]:
            raise PreimportError(f"{label} RECORD closure drifted: {name}")
        receipts[name] = receipt
        for key, value in members.items():
            if key in file_map and file_map[key] != value:
                raise PreimportError(f"{label} RECORD member origin is ambiguous")
            file_map[key] = value
    closure = hashlib.sha256(b"expected_pe.causal_valuation_tcn_v5.record_closure.v1\0")
    for name, receipt in receipts.items():
        closure.update(_canonical({"name": name, **receipt}))
    binaries = sorted(
        (
            record
            for record in file_map.values()
            if Path(record["path"]).suffix.casefold() in {".dll", ".pyd"}
        ),
        key=lambda record: record["path"],
    )
    return {
        "site_packages": site_text,
        "distribution_universe": dict(expected_versions),
        "distributions": receipts,
        "distribution_count": len(receipts),
        "record_member_closure_sha256": closure.hexdigest(),
        "binary_member_count": len(binaries),
        "binary_member_closure_sha256": _sha256_bytes(_canonical(binaries)),
    }, file_map


def _topology() -> dict[str, Any]:
    return {
        "sys_path": list(sys.path),
        "meta_path": [f"{type(value).__module__}.{type(value).__qualname__}" for value in sys.meta_path],
        "path_hooks": [
            f"{getattr(value, '__module__', '')}.{getattr(value, '__qualname__', type(value).__qualname__)}"
            for value in sys.path_hooks
        ],
        "plugins": [
            name for name in sorted(sys.modules)
            if name == "pytest" or name.startswith("_pytest")
        ],
    }


def _verify_runtime_lock() -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any]]:
    lock = _read_pinned_lock(
        RUNTIME_LOCK_TEXT, PINNED_RUNTIME_LOCK_SHA256, label="V5 runtime lock"
    )
    required = {
        "schema_version", "status", "python_executable", "interpreter_files",
        "driver_row", "torch_site", "pandas_site", "stdlib_records",
        "preimport_topology", "worker_topology", "native_allowlist", "authority",
    }
    if set(lock) != required:
        raise PreimportError("runtime lock exact schema drifted")
    if (
        lock["schema_version"] != RUNTIME_SCHEMA
        or lock["status"] != "EXTERNALLY_PINNED_PREIMPORT_RUNTIME_CLOSURE"
        or lock["python_executable"] != PINNED_PYTHON_TEXT
        or lock["authority"] != AUTHORITY_ZERO
    ):
        raise PreimportError("runtime lock identity/policy drifted")
    if Path(sys.executable) != Path(PINNED_PYTHON_TEXT):
        raise PreimportError("launcher used the wrong Python executable")
    interpreter: dict[str, Any] = {}
    for record in lock["interpreter_files"]:
        if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
            raise PreimportError("interpreter file record drifted")
        path = _ordinary(Path(record["path"]), directory=False, label="interpreter file")
        if path.stat().st_size != record["bytes"] or _sha256_file(path) != record["raw_sha256"]:
            raise PreimportError(f"interpreter/runtime file bytes drifted: {path}")
        interpreter[path.as_posix()] = {"bytes": record["bytes"], "raw_sha256": record["raw_sha256"]}
    if _topology() != lock["preimport_topology"]:
        raise PreimportError("pre-import sys.path/meta/path-hook/plugin topology drifted")
    torch_config = lock["torch_site"]
    pandas_config = lock["pandas_site"]
    for config, expected_path in ((torch_config, TORCH_SITE_TEXT), (pandas_config, PANDAS_SITE_TEXT)):
        if type(config) is not dict or set(config) != {
            "site_packages", "versions", "receipts", "exact_distribution_universe"
        } or config["site_packages"] != expected_path:
            raise PreimportError("numeric site lock schema/path drifted")
    torch_receipt, torch_members = _verify_site(
        TORCH_SITE_TEXT, torch_config["versions"], torch_config["receipts"],
        exact_distribution_universe=torch_config["exact_distribution_universe"],
        label="torch/numpy site",
    )
    pandas_receipt, pandas_members = _verify_site(
        PANDAS_SITE_TEXT, pandas_config["versions"], pandas_config["receipts"],
        exact_distribution_universe=pandas_config["exact_distribution_universe"],
        label="pandas site",
    )
    trusted_files: dict[str, dict[str, Any]] = {}
    for record in [*lock["stdlib_records"], *lock["native_allowlist"]]:
        if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
            raise PreimportError("runtime allowlist record drifted")
        path = _ordinary(Path(record["path"]), directory=False, label="runtime allowlist")
        observed = {"path": path.as_posix(), "bytes": path.stat().st_size, "raw_sha256": _sha256_file(path)}
        if observed != record:
            raise PreimportError(f"runtime allowlist bytes drifted: {path}")
        key = path.as_posix().casefold()
        if key in trusted_files and trusted_files[key] != record:
            raise PreimportError("runtime allowlist origin is ambiguous")
        trusted_files[key] = record
    for members in (torch_members, pandas_members):
        for key, record in members.items():
            if key in trusted_files and trusted_files[key] != record:
                raise PreimportError("RECORD/runtime origin is ambiguous")
            trusted_files[key] = record
    nvidia_smi = next(
        (Path(record["path"]) for record in lock["interpreter_files"]
         if Path(record["path"]).name.casefold() == "nvidia-smi.exe"),
        None,
    )
    if nvidia_smi is None:
        raise PreimportError("nvidia-smi is absent from interpreter closure")
    process = subprocess.run(
        [str(nvidia_smi), "--query-gpu=driver_version,name,compute_cap", "--format=csv,noheader,nounits"],
        check=False, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    rows = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    if process.returncode != 0 or rows != [lock["driver_row"]]:
        raise PreimportError("pinned driver/GPU/SM identity drifted")
    return lock, trusted_files, {
        "runtime_lock_sha256": PINNED_RUNTIME_LOCK_SHA256,
        "interpreter_driver_closure": {"files": interpreter, "nvidia_smi_row": rows[0]},
        "distribution_record_closure": torch_receipt,
        "pandas_record_closure": pandas_receipt,
        "preimport_topology": lock["preimport_topology"],
        "worker_topology": lock["worker_topology"],
        "stdlib_record_count": len(lock["stdlib_records"]),
        "native_allowlist_count": len(lock["native_allowlist"]),
    }


class VerifiedBytesLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, content: bytes, origin: str, is_package: bool) -> None:
        self.fullname = fullname
        self.content = content
        self.origin = origin
        self.is_package = is_package

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType | None:
        return None

    def exec_module(self, module: types.ModuleType) -> None:
        module.__file__ = self.origin
        module.__cached__ = None
        module.__loader__ = self
        if self.is_package:
            module.__package__ = self.fullname
            module.__path__ = []
        code = compile(self.content, self.origin, "exec", dont_inherit=True)
        exec(code, module.__dict__)


class VerifiedBytesFinder(importlib.abc.MetaPathFinder):
    """Only loader authorized to create governed V5 Python modules."""

    def __init__(self, source_bytes: Mapping[str, bytes]) -> None:
        self.modules: dict[str, tuple[bytes, str, bool]] = {}
        prefix = "research/model_zoo/causal_valuation_tcn_v5/"
        for relative, content in source_bytes.items():
            if not relative.startswith(prefix) or not relative.endswith(".py"):
                continue
            leaf = relative[len(prefix):]
            if "/" in leaf:
                raise PreimportError("governed source contains an unexpected package directory")
            is_package = leaf == "__init__.py"
            fullname = SOURCE_PACKAGE_PREFIX if is_package else f"{SOURCE_PACKAGE_PREFIX}.{leaf[:-3]}"
            digest = _sha256_bytes(content)
            origin = f"verified-bytes://{relative}#{digest}"
            self.modules[fullname] = (content, origin, is_package)

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: types.ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if fullname in {"research", "research.model_zoo"}:
            spec = importlib.machinery.ModuleSpec(fullname, loader=None, is_package=True)
            spec.submodule_search_locations = []
            return spec
        if fullname in self.modules:
            content, origin, is_package = self.modules[fullname]
            loader = VerifiedBytesLoader(fullname, content, origin, is_package)
            return importlib.machinery.ModuleSpec(
                fullname, loader, origin=origin, is_package=is_package
            )
        if fullname == SOURCE_PACKAGE_PREFIX or fullname.startswith(SOURCE_PACKAGE_PREFIX + "."):
            raise ModuleNotFoundError(f"governed module is absent from verified bytes: {fullname}")
        return None

    def origin_records(self) -> dict[str, dict[str, Any]]:
        return {
            name: {"origin": origin, "bytes": len(content), "raw_sha256": _sha256_bytes(content)}
            for name, (content, origin, _) in sorted(self.modules.items())
        }


def _assert_no_governed_imports() -> None:
    forbidden = [
        name for name in sys.modules
        if name == "research" or name.startswith("research.")
        or name in {"torch", "numpy", "pandas", "pytest"}
        or name.startswith(("torch.", "numpy.", "pandas.", "_pytest"))
    ]
    if forbidden:
        raise PreimportError("governed/numeric/plugin module loaded before attestation")


def _write_stage(captured: Mapping[str, bytes]) -> None:
    stage = Path(STAGE_TEXT)
    outputs = Path(PROJECT_ROOT_TEXT) / "outputs"
    if stage.parent != outputs or stage.name != ".causal_valuation_tcn_v5_verified_stage":
        raise PreimportError("fixed source stage identity drifted")
    if stage.exists():
        raise PreimportError("fixed source stage already exists")
    stage.mkdir()
    for relative, content in captured.items():
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    _verify_stage(captured)


def _verify_stage(captured: Mapping[str, bytes]) -> None:
    stage = _ordinary(Path(STAGE_TEXT), directory=True, label="verified source stage")
    actual: dict[str, bytes] = {}
    for path in stage.rglob("*"):
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise PreimportError("verified stage contains a reparse/symlink component")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(stage).as_posix()
            if path.suffix.casefold() in {".pyc", ".pyo", ".pyd", ".dll"}:
                raise PreimportError("verified stage contains executable/bytecode content")
            actual[relative] = path.read_bytes()
        elif not stat.S_ISDIR(metadata.st_mode):
            raise PreimportError("verified stage contains a non-file/non-directory member")
    if set(actual) != set(captured) or any(actual[key] != captured[key] for key in captured):
        raise PreimportError("verified stage exact byte universe drifted")


def _remove_stage() -> None:
    stage = Path(os.path.abspath(STAGE_TEXT))
    outputs = Path(os.path.abspath(PROJECT_ROOT_TEXT)) / "outputs"
    if stage.parent != outputs or stage.name != ".causal_valuation_tcn_v5_verified_stage":
        raise PreimportError("refused unsafe stage cleanup target")
    if stage.exists():
        _ordinary(stage, directory=True, label="verified stage cleanup target")
        shutil.rmtree(stage)


def _attest(*, make_stage: bool) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
    _assert_no_governed_imports()
    if not sys.dont_write_bytecode or sys.pycache_prefix is None:
        raise PreimportError("source-only bytecode quarantine is not active")
    if Path(sys.pycache_prefix).exists():
        raise PreimportError("bytecode quarantine is not empty/absent")
    _, captured, source_receipt = _verify_source_lock()
    runtime_lock, trusted_files, runtime_receipt = _verify_runtime_lock()
    if make_stage:
        _write_stage(captured)
    else:
        _verify_stage(captured)
    receipt = {
        "schema_version": PREIMPORT_SCHEMA,
        "status": "PASS_VERIFIED_BYTES_BEFORE_ANY_GOVERNED_IMPORT",
        **source_receipt,
        **runtime_receipt,
        "stage": STAGE_TEXT,
        "bytecode_allowed": False,
        "reparse_allowed": False,
        "pytest_plugin_universe": [],
        "authority": AUTHORITY_ZERO,
    }
    return captured, receipt, {"runtime_lock": runtime_lock, "trusted_files": trusted_files}


def _controlled_environment(
    *, receipt: Mapping[str, Any], finder: VerifiedBytesFinder
) -> dict[str, str]:
    keep = (
        "ALLUSERSPROFILE", "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH",
        "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROGRAMDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "SYSTEMDRIVE", "SYSTEMROOT",
        "TEMP", "TMP", "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR",
    )
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    receipt_text = _canonical(receipt).decode("ascii")
    environment.update({
        "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "2026082108",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "CVTCN_V5_LIVE_PROJECT_ROOT": PROJECT_ROOT_TEXT,
        "CVTCN_V5_SOURCE_STAGE": STAGE_TEXT,
        "CVTCN_V5_PREIMPORT_ATTESTATION_SHA256": _sha256_bytes(receipt_text.encode("ascii")),
        "CVTCN_V5_PREIMPORT_RECEIPT_JSON": receipt_text,
        "CVTCN_V5_VERIFIED_MODULE_ORIGINS_JSON": _canonical(finder.origin_records()).decode("ascii"),
    })
    if "CVTCN_V5_TEST_OUTPUT_CONTAINER" in os.environ:
        environment["CVTCN_V5_TEST_OUTPUT_CONTAINER"] = os.environ["CVTCN_V5_TEST_OUTPUT_CONTAINER"]
    return environment


def _install_finder(captured: Mapping[str, bytes], runtime_lock: Mapping[str, Any]) -> VerifiedBytesFinder:
    finder = VerifiedBytesFinder(captured)
    sys.path[:] = list(runtime_lock["worker_topology"]["sys_path"])
    sys.meta_path.insert(0, finder)
    expected = dict(runtime_lock["worker_topology"])
    expected["meta_path"] = [
        "__main__.VerifiedBytesFinder" if value == "VERIFIED_BYTES_FINDER" else value
        for value in expected["meta_path"]
    ]
    if _topology() != expected:
        raise PreimportError("verified worker sys.path/meta/path-hook/plugin topology drifted")
    return finder


def _verify_loaded_origins(
    *, finder: VerifiedBytesFinder, trusted_files: Mapping[str, Mapping[str, Any]]
) -> None:
    expected_governed = finder.origin_records()
    for name, module in sorted(sys.modules.items()):
        namespace = getattr(module, "__dict__", {})
        origin = namespace.get("__file__") if type(namespace) is dict else None
        if type(origin) is not str:
            continue
        if name == SOURCE_PACKAGE_PREFIX or name.startswith(SOURCE_PACKAGE_PREFIX + "."):
            record = expected_governed.get(name)
            if record is None or origin != record["origin"]:
                raise PreimportError(f"governed module origin drifted: {name}")
            continue
        if origin.startswith("verified-bytes://"):
            raise PreimportError("non-governed module used the verified-bytes authority")
        path = _ordinary(Path(origin), directory=False, label=f"loaded module {name}")
        if name in {"__main__", "__mp_main__"} and path == Path(LAUNCHER_TEXT):
            # The launcher's bytes are the externally anchored root, so they
            # cannot also be placed inside a lock whose hash the launcher pins.
            continue
        if path.suffix.casefold() in {".pyc", ".pyo"}:
            raise PreimportError(f"loaded module originated from bytecode: {name}")
        record = trusted_files.get(path.as_posix().casefold())
        if record is None:
            raise PreimportError(f"loaded module origin is outside pinned runtime closure: {name}")
        if path.stat().st_size != record["bytes"] or _sha256_file(path) != record["raw_sha256"]:
            raise PreimportError(f"loaded module bytes drifted after import: {name}")


def _verify_smoke_runtime_payload(
    payload: Mapping[str, Any],
    *,
    finder: VerifiedBytesFinder,
    runtime_lock: Mapping[str, Any],
) -> None:
    runtime = payload.get("runtime_receipt")
    if type(runtime) is not dict:
        raise PreimportError("smoke runtime receipt is absent")
    current = _topology()
    if (
        runtime.get("exact_sys_path") != current["sys_path"]
        or runtime.get("meta_path_universe") != current["meta_path"]
        or runtime.get("path_hook_universe") != current["path_hooks"]
        or runtime.get("pytest_plugin_universe") != []
    ):
        raise PreimportError("post-import sys.path/import-hook/plugin topology drifted")
    native_records = runtime.get("loaded_native_module_records")
    if type(native_records) not in {list, tuple}:
        raise PreimportError("loaded native DLL receipt is not a fixed sequence")
    observed_native: dict[str, Mapping[str, Any]] = {}
    expected_native: dict[str, Mapping[str, Any]] = {}
    for label, records, output in (
        ("observed", native_records, observed_native),
        ("expected", runtime_lock["native_allowlist"], expected_native),
    ):
        for record in records:
            if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
                raise PreimportError(f"{label} native DLL record schema drifted")
            key = record["path"].casefold()
            if key in output:
                raise PreimportError(f"{label} native DLL universe is ambiguous")
            output[key] = {
                "path": key,
                "bytes": record["bytes"],
                "raw_sha256": record["raw_sha256"],
            }
    if observed_native != expected_native:
        missing = sorted(set(expected_native) - set(observed_native))
        extra = sorted(set(observed_native) - set(expected_native))
        changed = sorted(
            key
            for key in set(observed_native).intersection(expected_native)
            if observed_native[key] != expected_native[key]
        )
        raise PreimportError(
            "loaded native DLL exact universe/bytes drifted: "
            f"missing={missing[:3]!r}, extra={extra[:3]!r}, changed={changed[:3]!r}"
        )
    if runtime.get("loaded_native_module_count") != len(native_records):
        raise PreimportError("loaded native DLL count drifted")
    governed_expected = finder.origin_records()
    governed_observed = {
        record["module"]: {
            "origin": record["origin"],
            "bytes": record["bytes"],
            "raw_sha256": record["raw_sha256"],
        }
        for record in runtime.get("module_origin_records", [])
        if type(record) is dict
        and type(record.get("origin")) is str
        and record["origin"].startswith("verified-bytes://")
    }
    loaded_governed = {
        name: record
        for name, record in governed_expected.items()
        if name in sys.modules
    }
    if governed_observed != loaded_governed:
        raise PreimportError("governed module origin/hash receipt drifted")


def _worker(task: str, device: str | None) -> int:
    captured, receipt, private = _attest(make_stage=False)
    receipt_text = _canonical(receipt).decode("ascii")
    receipt_sha = _sha256_bytes(receipt_text.encode("ascii"))
    if os.environ.get("CVTCN_V5_PREIMPORT_ATTESTATION_SHA256") != receipt_sha:
        raise PreimportError("parent/worker pre-import attestation differs")
    if os.environ.get("CVTCN_V5_PREIMPORT_RECEIPT_JSON") != receipt_text:
        raise PreimportError("parent/worker pre-import receipt bytes differ")
    finder = _install_finder(captured, private["runtime_lock"])
    expected_origins = _canonical(finder.origin_records()).decode("ascii")
    if os.environ.get("CVTCN_V5_VERIFIED_MODULE_ORIGINS_JSON") != expected_origins:
        raise PreimportError("parent/worker verified module authority differs")
    if task == "smoke":
        if device not in {"cpu", "cuda"}:
            raise PreimportError("smoke worker device drifted")
        module = __import__(f"{SOURCE_PACKAGE_PREFIX}.smoke_worker", fromlist=["_run"])
        payload = module._run(device)
        _verify_loaded_origins(finder=finder, trusted_files=private["trusted_files"])
        _verify_smoke_runtime_payload(
            payload, finder=finder, runtime_lock=private["runtime_lock"]
        )
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    if task == "tests":
        if device is not None:
            raise PreimportError("test worker unexpectedly received a device")
        relative = "tests/model_lab/causal_valuation_tcn_v5/torch_checks.py"
        namespace = {
            "__name__": "__main__",
            "__file__": f"verified-bytes://{relative}#{_sha256_bytes(captured[relative])}",
            "__package__": None,
            "__cached__": None,
        }
        exec(compile(captured[relative], namespace["__file__"], "exec", dont_inherit=True), namespace)
        _verify_loaded_origins(finder=finder, trusted_files=private["trusted_files"])
        return 0
    raise PreimportError("unknown isolated worker task")


def _run_child(
    *, task: str, device: str | None, receipt: Mapping[str, Any], finder: VerifiedBytesFinder
) -> dict[str, Any]:
    command = [
        PINNED_PYTHON_TEXT, "-I", "-B", "-S", "-X",
        f"pycache_prefix={Path(STAGE_TEXT) / 'forbidden_bytecode_sink'}",
        LAUNCHER_TEXT, "--worker-task", task,
    ]
    if device is not None:
        command.extend(("--worker-device", device))
    process = subprocess.run(
        command,
        cwd=STAGE_TEXT,
        env=_controlled_environment(receipt=receipt, finder=finder),
        check=False,
        capture_output=True,
        timeout=1800,
    )
    stdout = process.stdout or b""
    stderr = process.stderr or b""
    try:
        stdout_text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PreimportError("isolated worker stdout is not strict UTF-8") from error
    result = {
        "command": command,
        "return_code": process.returncode,
        "stdout": stdout_text,
        "stdout_sha256": _sha256_bytes(stdout),
        "stderr_sha256": _sha256_bytes(stderr),
        "stderr_tail": stderr[-6000:].decode("utf-8", errors="backslashreplace"),
    }
    if process.returncode != 0:
        raise PreimportError(
            f"isolated {task}/{device or 'none'} worker failed: {result['stderr_tail']}"
        )
    return result


def _parent(*, preflight: bool) -> int:
    captured, receipt, private = _attest(make_stage=True)
    finder = VerifiedBytesFinder(captured)
    try:
        test = _run_child(task="tests", device=None, receipt=receipt, finder=finder)
        if not preflight:
            output = {
                "schema_version": "expected_pe.causal_valuation_tcn_v5.trusted_tests.v1",
                "status": "PASS_TRUSTED_VERIFIED_BYTES_TESTS",
                "preimport_attestation": receipt,
                "test": {key: value for key, value in test.items() if key != "stdout"},
                "test_stdout": test["stdout"],
                "authority": AUTHORITY_ZERO,
            }
            sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
            return 0
        cpu = _run_child(task="smoke", device="cpu", receipt=receipt, finder=finder)
        gpu_one = _run_child(task="smoke", device="cuda", receipt=receipt, finder=finder)
        gpu_two = _run_child(task="smoke", device="cuda", receipt=receipt, finder=finder)
        workers = {
            "cpu": json.loads(cpu["stdout"]),
            "gpu_process_1": json.loads(gpu_one["stdout"]),
            "gpu_process_2": json.loads(gpu_two["stdout"]),
        }
        output = {
            "schema_version": "expected_pe.causal_valuation_tcn_v5.trusted_preflight.v1",
            "status": "PASS_TRUSTED_TEST_CPU_TWO_INDEPENDENT_GPU_PREFLIGHT",
            "preimport_attestation": receipt,
            "test": {key: value for key, value in test.items() if key != "stdout"},
            "test_stdout": test["stdout"],
            "worker_process_receipts": {
                "cpu": {key: value for key, value in cpu.items() if key != "stdout"},
                "gpu_process_1": {key: value for key, value in gpu_one.items() if key != "stdout"},
                "gpu_process_2": {key: value for key, value in gpu_two.items() if key != "stdout"},
            },
            "workers": workers,
            "authority": AUTHORITY_ZERO,
        }
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    finally:
        _remove_stage()


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--tests-only", action="store_true")
    mode.add_argument("--worker-task", choices=("tests", "smoke"))
    parser.add_argument("--worker-device", choices=("cpu", "cuda"))
    args = parser.parse_args()
    if args.worker_task is not None:
        return _worker(args.worker_task, args.worker_device)
    if args.worker_device is not None:
        raise PreimportError("parent launcher does not accept a worker device")
    return _parent(preflight=bool(args.preflight))


if __name__ == "__main__":
    raise SystemExit(main())
