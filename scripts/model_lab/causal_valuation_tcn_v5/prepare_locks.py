"""One-time deterministic preparation of the externally pinned V5 lock files.

This script is not part of the trusted launch path.  It inventories only code
and environment metadata already authorized for the score-free V5 repair.
The resulting raw hashes must be patched into ``trusted_launcher.py`` with a
reviewed source edit before the launcher can run.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


PROJECT_ROOT = Path(
    "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
SCRIPT_ROOT = PROJECT_ROOT / "scripts/model_lab/causal_valuation_tcn_v5"
PACKAGE_ROOT = PROJECT_ROOT / "research/model_zoo/causal_valuation_tcn_v5"
TEST_ROOT = PROJECT_ROOT / "tests/model_lab/causal_valuation_tcn_v5"
SOURCE_LOCK = SCRIPT_ROOT / "V5_SOURCE_LOCK.json"
RUNTIME_LOCK = SCRIPT_ROOT / "V5_RUNTIME_LOCK.json"
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
TORCH_SITE = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Lib/site-packages"
)
PANDAS_SITE = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Lib/site-packages"
)
V2_ENVIRONMENT = PROJECT_ROOT / (
    "outputs/model_zoo_causal_valuation_tcn_v2_score_free_"
    "design_environment_preflight_20260821/bundle/ENVIRONMENT_DEPENDENCY_CLOSURE.json"
)
INTERPRETER_PATHS = (
    PINNED_PYTHON,
    Path("C:/Users/minsu/anaconda3/envs/myenv/python.exe"),
    Path("C:/Users/minsu/anaconda3/envs/myenv/python310.dll"),
    Path("C:/Windows/System32/nvidia-smi.exe"),
)
DRIVER_ROW = "596.49, NVIDIA GeForce RTX 5080, 12.0"
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
PACKAGE_FILES = (
    "DESIGN.md",
    "MODEL_HYPOTHESIS.md",
    "REFERENCE_LICENSE_REGISTRY.json",
    "__init__.py",
    "artifacts.py",
    "contracts.py",
    "custody.py",
    "models.py",
    "path_guard.py",
    "runtime.py",
    "safe_json.py",
    "smoke.py",
    "smoke_worker.py",
    "source_audit.py",
    "training.py",
)


class LockPreparationError(RuntimeError):
    pass


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(8 * 1024 * 1024)
            if not block:
                return hasher.hexdigest()
            hasher.update(block)


def _ordinary(path: Path, *, directory: bool, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise LockPreparationError(f"{label} contains a reparse/symlink component")
    metadata = os.lstat(absolute)
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise LockPreparationError(f"{label} is not an ordinary directory")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise LockPreparationError(f"{label} is not an ordinary file")
    return absolute


def _file_record(path: Path) -> dict[str, Any]:
    ordinary = _ordinary(path, directory=False, label=str(path))
    return {
        "path": ordinary.as_posix(),
        "bytes": ordinary.stat().st_size,
        "raw_sha256": _sha256(ordinary),
    }


def _source_record(relative: str) -> dict[str, Any]:
    path = _ordinary(PROJECT_ROOT / relative, directory=False, label=relative)
    return {
        "path": relative,
        "bytes": path.stat().st_size,
        "raw_sha256": _sha256(path),
    }


def _decode_record_hash(value: str, label: str) -> str:
    if not value.startswith("sha256="):
        raise LockPreparationError(f"{label} RECORD hash algorithm drifted")
    raw = base64.urlsafe_b64decode(value[7:] + "=" * (-len(value[7:]) % 4))
    if len(raw) != 32:
        raise LockPreparationError(f"{label} RECORD hash length drifted")
    return raw.hex()


def _distribution_receipt(
    distribution: importlib.metadata.Distribution, *, name: str
) -> dict[str, Any]:
    text = distribution.read_text("RECORD")
    if type(text) is not str:
        raise LockPreparationError(f"RECORD absent: {name}")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    seen: set[str] = set()
    duplicate_paths = 0
    members = hashlib.sha256(b"expected_pe.causal_valuation_tcn_v5.record_members.v1\0")
    counts = {"hashed": 0, "unhashed": 0, "present_unhashed": 0, "pyc": 0, "pyc_mismatch": 0}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise LockPreparationError(f"RECORD exact row universe drifted: {name}")
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
            expected_size = int(encoded_size)
            actual_hash = _sha256(ordinary)
            matches = expected_size == actual_size and expected_hash == actual_hash
            if not matches and not is_pyc:
                raise LockPreparationError(f"RECORD member bytes drifted: {name}:{relative}")
            if not matches:
                counts["pyc_mismatch"] += 1
            counts["hashed"] += 1
        else:
            if encoded_size:
                raise LockPreparationError(f"unhashed RECORD size drifted: {name}:{relative}")
            counts["unhashed"] += 1
            if exists:
                ordinary = _ordinary(path, directory=False, label=f"{name}:{relative}")
                actual_size = ordinary.stat().st_size
                actual_hash = _sha256(ordinary)
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
    return {
        "version": distribution.version,
        "record_raw_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "record_row_count": len(rows),
        "hashed_member_count": counts["hashed"],
        "unhashed_member_count": counts["unhashed"],
        "present_unhashed_member_count": counts["present_unhashed"],
        "duplicate_record_path_count": duplicate_paths,
        "nonexecuted_pyc_member_count": counts["pyc"],
        "nonexecuted_pyc_mismatch_count": counts["pyc_mismatch"],
        "exact_member_universe_sha256": members.hexdigest(),
    }


def _site_config(site: Path, names: set[str] | None) -> dict[str, Any]:
    distributions = tuple(importlib.metadata.distributions(path=[str(site)]))
    by_name: dict[str, importlib.metadata.Distribution] = {}
    for distribution in distributions:
        name = distribution.metadata.get("Name")
        if type(name) is not str or name in by_name:
            raise LockPreparationError("distribution universe is ambiguous")
        by_name[name] = distribution
    selected = set(by_name) if names is None else names
    if not selected.issubset(by_name):
        raise LockPreparationError("required distribution is absent")
    versions = {name: by_name[name].version for name in sorted(selected)}
    receipts = {
        name: _distribution_receipt(by_name[name], name=name) for name in sorted(selected)
    }
    return {
        "site_packages": str(site).replace("/", "\\"),
        "versions": versions,
        "receipts": receipts,
        "exact_distribution_universe": names is None,
    }


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


def _reference_runtime_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = json.loads(_ordinary(V2_ENVIRONMENT, directory=False, label="V2 environment closure").read_text(encoding="utf-8"))
    receipts = [
        payload["cpu_runtime_receipt"],
        payload["gpu_process_1_runtime_receipt"],
        payload["gpu_process_2_runtime_receipt"],
    ]
    site_prefix = TORCH_SITE.as_posix().casefold().rstrip("/") + "/"
    project_prefix = PROJECT_ROOT.as_posix().casefold().rstrip("/") + "/"
    stdlib: dict[str, dict[str, Any]] = {}
    native: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        for record in receipt["module_origin_records"]:
            origin = str(record["origin"])
            folded = origin.casefold()
            if folded.startswith(site_prefix) or folded.startswith(project_prefix):
                continue
            path = Path(origin)
            candidate = _file_record(path)
            if candidate["bytes"] != record["bytes"] or candidate["raw_sha256"] != record["raw_sha256"]:
                raise LockPreparationError("V2 stdlib evidence is no longer byte-stable")
            stdlib[candidate["path"].casefold()] = candidate
        for record in receipt["loaded_native_module_records"]:
            candidate = _file_record(Path(record["path"]))
            if candidate != record:
                raise LockPreparationError("V2 native evidence is no longer byte-stable")
            native[candidate["path"].casefold()] = candidate
    return (
        [stdlib[key] for key in sorted(stdlib)],
        [native[key] for key in sorted(native)],
    )


def _runtime_lock() -> dict[str, Any]:
    if Path(sys.executable) != PINNED_PYTHON:
        raise LockPreparationError("lock preparation used the wrong Python executable")
    preimport = _topology()
    if preimport["plugins"]:
        raise LockPreparationError("plugin modules leaked into lock preparation")
    worker = {
        "sys_path": [str(TORCH_SITE).replace("/", "\\"), *preimport["sys_path"]],
        "meta_path": ["VERIFIED_BYTES_FINDER", *preimport["meta_path"]],
        "path_hooks": preimport["path_hooks"],
        "plugins": [],
    }
    stdlib, native = _reference_runtime_records()
    return {
        "schema_version": "expected_pe.causal_valuation_tcn_v5.runtime_lock.v1",
        "status": "EXTERNALLY_PINNED_PREIMPORT_RUNTIME_CLOSURE",
        "python_executable": str(PINNED_PYTHON).replace("/", "\\"),
        "interpreter_files": [_file_record(path) for path in INTERPRETER_PATHS],
        "driver_row": DRIVER_ROW,
        "torch_site": _site_config(TORCH_SITE, None),
        "pandas_site": _site_config(PANDAS_SITE, {"pandas"}),
        "stdlib_records": stdlib,
        "preimport_topology": preimport,
        "worker_topology": worker,
        "native_allowlist": native,
        "authority": AUTHORITY_ZERO,
    }


def _source_lock() -> dict[str, Any]:
    source_paths = sorted([
        *(f"research/model_zoo/causal_valuation_tcn_v5/{name}" for name in PACKAGE_FILES),
        "scripts/model_lab/causal_valuation_tcn_v5/build_preflight.py",
        "scripts/model_lab/causal_valuation_tcn_v5/prepare_locks.py",
        "tests/model_lab/causal_valuation_tcn_v5/torch_checks.py",
    ])
    records = [_source_record(relative) for relative in source_paths]
    stage_paths = sorted([
        *source_paths,
        "scripts/model_lab/causal_valuation_tcn_v5/trusted_launcher.py",
        "scripts/model_lab/causal_valuation_tcn_v5/V5_SOURCE_LOCK.json",
        "scripts/model_lab/causal_valuation_tcn_v5/V5_RUNTIME_LOCK.json",
    ])
    return {
        "schema_version": "expected_pe.causal_valuation_tcn_v5.source_lock.v1",
        "status": "EXTERNALLY_PINNED_VERIFIED_SOURCE_BYTES",
        "project_root": str(PROJECT_ROOT).replace("/", "\\"),
        "source_records": records,
        "exact_roots": {
            "research/model_zoo/causal_valuation_tcn_v5": {
                name: "file" for name in sorted(PACKAGE_FILES)
            },
            "scripts/model_lab/causal_valuation_tcn_v5": {
                name: "file" for name in (
                    "V5_RUNTIME_LOCK.json", "V5_SOURCE_LOCK.json", "build_preflight.py",
                    "prepare_locks.py", "trusted_launcher.py",
                )
            },
            "tests/model_lab/causal_valuation_tcn_v5": {"torch_checks.py": "file"},
        },
        "stage_paths": stage_paths,
        "source_manifest_sha256": hashlib.sha256(_canonical(records)).hexdigest(),
        "authority": AUTHORITY_ZERO,
    }


def main() -> int:
    for path in (SOURCE_LOCK, RUNTIME_LOCK):
        if path.exists():
            raise LockPreparationError(f"refusing to overwrite existing lock: {path}")
    runtime_content = _canonical(_runtime_lock()) + b"\n"
    RUNTIME_LOCK.write_bytes(runtime_content)
    source_content = _canonical(_source_lock()) + b"\n"
    SOURCE_LOCK.write_bytes(source_content)
    output = {
        "source_lock": SOURCE_LOCK.as_posix(),
        "source_lock_sha256": hashlib.sha256(source_content).hexdigest(),
        "runtime_lock": RUNTIME_LOCK.as_posix(),
        "runtime_lock_sha256": hashlib.sha256(runtime_content).hexdigest(),
    }
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
