"""Seal the complete Structural V6 CPython/package runtime inventory."""

from __future__ import annotations

import ctypes
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import sysconfig
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
)


OUTPUT = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/RUNTIME_ENVIRONMENT_V6.json"
)
PINNED_LAUNCHER = (ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)
EXPECTED_LAUNCHER_RAW = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
EXPECTED_PROCESS_IMAGE = Path("C:/Users/minsu/anaconda3/envs/myenv/python.exe")
EXPECTED_PROCESS_IMAGE_RAW = "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
EXPECTED_VERSION = (3, 10, 19)
BRANCH_CRITICAL_PACKAGES = {
    "catboost": "1.2.10",
    "lightgbm": "4.6.0",
    "pyyaml": "6.0.2",
    "statsmodels": "0.14.6",
    "xgboost": "3.2.0",
}


def _actual_process_image() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer))
    if not length:
        raise OSError(ctypes.get_last_error(), "GetModuleFileNameW failed")
    return Path(buffer.value).resolve(strict=True)


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _metadata_package_map() -> dict[str, str]:
    packages: dict[str, str] = {}
    installed_roots = sorted(
        {
            str(Path(value).resolve())
            for key in ("purelib", "platlib")
            if (value := sysconfig.get_path(key))
        }
    )
    for distribution in metadata.distributions(path=installed_roots):
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise RuntimeError("installed distribution lacks a Name field")
        name = _normalize_distribution(str(raw_name))
        if name in packages:
            raise RuntimeError(f"duplicate installed distribution: {name}")
        packages[name] = str(distribution.version)
    return dict(sorted(packages.items()))


def _freeze_package_map(lines: tuple[str, ...]) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in lines:
        if line.count("==") != 1:
            raise RuntimeError(f"non-exact pip freeze entry: {line}")
        raw_name, version = line.split("==", 1)
        name = _normalize_distribution(raw_name)
        if not name or not version or name in packages:
            raise RuntimeError(f"invalid/duplicate pip freeze entry: {line}")
        packages[name] = version
    return dict(sorted(packages.items()))


def _pip_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    return environment


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable V6 environment already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    executable = Path(sys.executable).resolve(strict=True)
    if executable != PINNED_LAUNCHER or sha256_file(executable) != EXPECTED_LAUNCHER_RAW:
        raise RuntimeError("must run with the exact pinned Model Lab CPython launcher")
    if sys.version_info[:3] != EXPECTED_VERSION or platform.python_implementation() != "CPython":
        raise RuntimeError("must run under exact CPython 3.10.19")
    image = _actual_process_image()
    if image != EXPECTED_PROCESS_IMAGE or sha256_file(image) != EXPECTED_PROCESS_IMAGE_RAW:
        raise RuntimeError("actual CPython process image changed")
    freeze = subprocess.run(
        [str(executable), "-m", "pip", "freeze", "--all"],
        check=True,
        capture_output=True,
        env=_pip_environment(),
    )
    freeze_lines = tuple(
        line.strip()
        for line in freeze.stdout.decode("utf-8", errors="strict").splitlines()
        if line.strip()
    )
    freeze_packages = _freeze_package_map(freeze_lines)
    metadata_packages = _metadata_package_map()
    if freeze_packages != metadata_packages:
        raise RuntimeError("pip freeze and importlib.metadata package maps differ")
    if any(
        metadata_packages.get(name) != version for name, version in BRANCH_CRITICAL_PACKAGES.items()
    ):
        raise RuntimeError("branch-critical Structural runtime package changed")
    check = subprocess.run(
        [str(executable), "-m", "pip", "check"],
        check=True,
        capture_output=True,
        env=_pip_environment(),
    )
    payload = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v6_complete_exact_runtime_environment",
            "launcher": {
                "path": executable.as_posix(),
                "bytes": executable.stat().st_size,
                "raw_sha256": sha256_file(executable),
            },
            "actual_process_image": {
                "path": image.as_posix(),
                "bytes": image.stat().st_size,
                "raw_sha256": sha256_file(image),
            },
            "runtime": {
                "implementation": platform.python_implementation(),
                "version_info": list(sys.version_info[:3]),
                "version": sys.version,
                "sys_prefix": Path(sys.prefix).resolve().as_posix(),
                "sys_base_prefix": Path(sys.base_prefix).resolve().as_posix(),
                "stdlib": Path(sysconfig.get_path("stdlib")).resolve().as_posix(),
            },
            "branch_critical_packages": BRANCH_CRITICAL_PACKAGES,
            "package_versions_all": metadata_packages,
            "package_versions_all_sha256": sha256_bytes(canonical_json_bytes(metadata_packages)),
            "pip_freeze_all": list(freeze_lines),
            "pip_freeze_all_sha256": sha256_bytes(canonical_json_bytes(freeze_lines)),
            "freeze_stdout_bytes": len(freeze.stdout),
            "freeze_stdout_raw_sha256": hashlib.sha256(freeze.stdout).hexdigest(),
            "pip_check_stdout": check.stdout.decode("utf-8", errors="strict").strip(),
            "pip_check_stderr": check.stderr.decode("utf-8", errors="strict").strip(),
            "pip_check_returncode": check.returncode,
            "thread_gpu_policy": {
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "VECLIB_MAXIMUM_THREADS": "1",
                "NUMEXPR_NUM_THREADS": "1",
                "CUDA_VISIBLE_DEVICES": "-1",
                "NVIDIA_VISIBLE_DEVICES": "void",
            },
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
                "package_count": len(metadata_packages),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
