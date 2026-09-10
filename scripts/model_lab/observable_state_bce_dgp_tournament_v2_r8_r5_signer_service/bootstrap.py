"""Launch or ping the fixed R8-r5 in-memory signer service."""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SERVICE_PATH = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_signer_service/custody_service.py"
)
READINESS_PATH = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r5_signer_service_20260821/READINESS.json"
)
PYTHON_PATH = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310" / "Scripts" / "python.exe"
)


def _load_service() -> Any:
    spec = importlib.util.spec_from_file_location("expected_pe_r8_r5_custody_service", SERVICE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("service source could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _windows_random_seed() -> bytearray:
    if os.name != "nt":
        raise RuntimeError("production bootstrap is Windows-only")
    seed = bytearray(32)
    buffer = (ctypes.c_ubyte * len(seed)).from_buffer(seed)
    bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
    bcrypt.BCryptGenRandom.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    bcrypt.BCryptGenRandom.restype = ctypes.c_long
    use_system_preferred_rng = 0x00000002
    status = bcrypt.BCryptGenRandom(
        None,
        ctypes.cast(buffer, ctypes.c_void_p),
        len(seed),
        use_system_preferred_rng,
    )
    if status != 0:
        ctypes.memset(ctypes.addressof(buffer), 0, len(seed))
        raise RuntimeError("BCryptGenRandom failed")
    return seed


def _zeroize(seed: bytearray) -> None:
    buffer = (ctypes.c_ubyte * len(seed)).from_buffer(seed)
    ctypes.memset(ctypes.addressof(buffer), 0, len(seed))


def _pid_is_alive(process_id: object) -> bool:
    if type(process_id) is not int or process_id <= 0:
        return False
    process_query_limited_information = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(process_query_limited_information, 0, process_id)
    if not handle:
        return False
    kernel32.CloseHandle(handle)
    return True


def _launch() -> dict[str, Any]:
    if READINESS_PATH.exists() or READINESS_PATH.parent.exists():
        raise RuntimeError("fixed production readiness root already exists")
    if not PYTHON_PATH.is_file() or not SERVICE_PATH.is_file():
        raise RuntimeError("pinned Python or signer source is absent")
    seed = _windows_random_seed()
    creationflags = (
        subprocess.CREATE_NO_WINDOW
        | subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NEW_PROCESS_GROUP
    )
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                str(PYTHON_PATH),
                "-I",
                "-S",
                "-B",
                "-E",
                str(SERVICE_PATH),
                "--serve-production",
            ],
            close_fds=True,
            creationflags=creationflags,
            cwd=str(PROJECT_ROOT),
            env={
                "PATH": str(PYTHON_PATH.parent),
                "PYTHONDONTWRITEBYTECODE": "1",
                "SYSTEMROOT": os.environ["SYSTEMROOT"],
                "WINDIR": os.environ["WINDIR"],
            },
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
        )
        if process.stdin is None:
            raise RuntimeError("anonymous stdin was not created")
        written = 0
        while written < len(seed):
            count = os.write(process.stdin.fileno(), memoryview(seed)[written:])
            if count <= 0:
                raise RuntimeError("anonymous seed transfer failed")
            written += count
        process.stdin.close()
    finally:
        _zeroize(seed)
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if READINESS_PATH.is_file():
            raw = READINESS_PATH.read_bytes()
            payload = json.loads(raw)
            service_process_id = payload.get("process_id")
            if not _pid_is_alive(service_process_id):
                raise RuntimeError("readiness service PID is not alive")
            module = _load_service()
            if module.canonical_json_bytes(payload) != raw:
                raise RuntimeError("readiness receipt is non-canonical")
            status = module.ping_service(READINESS_PATH)
            return {
                "bootstrap_process_id": process.pid,
                "expires_at_utc": payload["expires_at_utc"],
                "key_id": payload["key_id"],
                "process_id": service_process_id,
                "readiness_raw_sha256": module.sha256_bytes(raw),
                "service_status": status,
                "status": "PASS_PRODUCTION_SERVICE_LAUNCHED_AND_PINGED",
            }
        if process.poll() is not None:
            raise RuntimeError(f"signer exited before readiness: {process.returncode}")
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for signer readiness")


def _status() -> dict[str, Any]:
    module = _load_service()
    raw, receipt = module.load_readiness(READINESS_PATH)
    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "key_id": receipt["key_id"],
        "readiness_raw_sha256": module.sha256_bytes(raw),
        "service_status": module.ping_service(READINESS_PATH),
        "status": "PASS_READ_ONLY_STATUS",
    }


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"launch", "status"}:
        return 64
    result = _launch() if sys.argv[1] == "launch" else _status()
    print(json.dumps(result, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
