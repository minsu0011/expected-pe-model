"""Seal the exact CPython 3.10 runtime required by Structural V5."""

from __future__ import annotations

import ctypes
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
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
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/RUNTIME_ENVIRONMENT_V5.json"
)
PINNED_LAUNCHER = (ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)
EXPECTED_LAUNCHER_RAW = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
EXPECTED_VERSION = (3, 10, 19)
REQUIRED_DISTRIBUTIONS = (
    "joblib",
    "numpy",
    "pandas",
    "pyarrow",
    "scikit-learn",
    "scipy",
    "threadpoolctl",
    "xgboost",
)


def _actual_process_image() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer))
    if not length:
        raise OSError(ctypes.get_last_error(), "GetModuleFileNameW failed")
    return Path(buffer.value).resolve(strict=True)


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable V5 environment already exists: {path}")
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
    freeze = subprocess.run(
        [str(executable), "-m", "pip", "freeze", "--all"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    freeze_lines = tuple(line.strip() for line in freeze.stdout.splitlines() if line.strip())
    check = subprocess.run(
        [str(executable), "-m", "pip", "check"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    packages = {name: metadata.version(name) for name in REQUIRED_DISTRIBUTIONS}
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v5_exact_runtime_environment",
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
            "required_distribution_versions": packages,
            "pip_freeze_all": list(freeze_lines),
            "pip_freeze_all_sha256": sha256_bytes(canonical_json_bytes(freeze_lines)),
            "pip_check_stdout": check.stdout.strip(),
            "pip_check_stderr": check.stderr.strip(),
            "thread_gpu_policy": {
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "VECLIB_MAXIMUM_THREADS": "1",
                "NUMEXPR_NUM_THREADS": "1",
                "CUDA_VISIBLE_DEVICES": "-1",
                "NVIDIA_VISIBLE_DEVICES": "void",
            },
            "freeze_stdout_raw_sha256": hashlib.sha256(freeze.stdout.encode("utf-8")).hexdigest(),
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
