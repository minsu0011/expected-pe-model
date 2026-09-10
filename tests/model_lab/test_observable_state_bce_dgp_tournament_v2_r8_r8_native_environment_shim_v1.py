from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3.native_prebootstrap_contract import (  # noqa: E402
    CHILD_PYCACHE_PREFIX_RELATIVE,
    DESIGN_OUTPUT_RELATIVE,
    NATIVE_AUDIT_ARGUMENT,
    NATIVE_SHIM_EXECUTABLE_FILE_ID_128,
    NATIVE_SHIM_EXECUTABLE_RELATIVE,
    NATIVE_SHIM_EXECUTABLE_SHA256,
    NATIVE_SHIM_EXECUTABLE_SIZE_BYTES,
    NATIVE_SHIM_EXECUTABLE_VOLUME_SERIAL_NUMBER,
    NATIVE_SHIM_SEAL_RECEIPT_RELATIVE,
    NATIVE_SHIM_SEAL_RECEIPT_SHA256,
    NATIVE_SHIM_SEAL_RECEIPT_SIZE_BYTES,
    NATIVE_SHIM_SEALER_RELATIVE,
    NATIVE_SHIM_SEALER_SHA256,
    NATIVE_SHIM_SEALER_SIZE_BYTES,
    NATIVE_SHIM_SOURCE_FILE_ID_128,
    NATIVE_SHIM_SOURCE_RELATIVE,
    NATIVE_SHIM_SOURCE_SHA256,
    NATIVE_SHIM_SOURCE_SIZE_BYTES,
    NATIVE_SHIM_SOURCE_VOLUME_SERIAL_NUMBER,
    SUPERVISOR_CLAIM_RELATIVE,
    ZERO_COUNTS,
    ZIG_ARCHIVE_SHA256,
    ZIG_ARCHIVE_SIZE_BYTES,
    ZIG_FILE_ID_128,
    ZIG_PATH,
    ZIG_SHA256,
    ZIG_SIZE_BYTES,
    ZIG_VOLUME_SERIAL_NUMBER,
)

V3_SUPERVISOR = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/trusted_supervisor.py"
)
ZIG_ARCHIVE = Path(r"C:\Users\minsu\Documents\EPS\zig-x86_64-windows-0.16.0.zip")
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_WRITE = 0x40000000
WRITE_DAC = 0x00040000
FILE_SHARE_READ = 0x00000001
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL32.CreateFileW.argtypes = (
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
)
KERNEL32.CreateFileW.restype = wintypes.HANDLE
KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
KERNEL32.CloseHandle.restype = wintypes.BOOL


def _raw(path: Path) -> tuple[str, int]:
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest(), len(content)


def _identity(path: Path) -> tuple[int, str]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("shim_v1_identity_helper", V3_SUPERVISOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handle = module._open_no_share_write_delete(path, directory=False)
    try:
        return module._identity(handle)
    finally:
        module._close_checked(handle)


def _pe_imports(raw: bytes) -> tuple[str, ...]:
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    assert raw[pe : pe + 4] == b"PE\0\0"
    section_count = struct.unpack_from("<H", raw, pe + 6)[0]
    optional_size = struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", raw, optional)[0] == 0x20B
    data_directories = optional + 112
    import_rva, _import_size = struct.unpack_from("<II", raw, data_directories + 8)
    section_table = optional + optional_size
    sections: list[tuple[int, int, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", raw, offset + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))

    def file_offset(rva: int) -> int:
        for virtual_address, size, raw_offset in sections:
            if virtual_address <= rva < virtual_address + size:
                return raw_offset + rva - virtual_address
        raise AssertionError(f"PE RVA is outside sections: {rva:#x}")

    descriptor = file_offset(import_rva)
    names: list[str] = []
    while any(struct.unpack_from("<IIIII", raw, descriptor)):
        name_rva = struct.unpack_from("<IIIII", raw, descriptor)[3]
        name_offset = file_offset(name_rva)
        end = raw.index(0, name_offset)
        names.append(raw[name_offset:end].decode("ascii"))
        descriptor += 20
    com_descriptor_rva, com_descriptor_size = struct.unpack_from(
        "<II", raw, data_directories + 14 * 8
    )
    assert (com_descriptor_rva, com_descriptor_size) == (0, 0)
    return tuple(names)


def test_native_shim_source_toolchain_executable_and_seal_are_pinned() -> None:
    cases = (
        (
            PROJECT_ROOT / NATIVE_SHIM_SOURCE_RELATIVE,
            NATIVE_SHIM_SOURCE_SHA256,
            NATIVE_SHIM_SOURCE_SIZE_BYTES,
            NATIVE_SHIM_SOURCE_VOLUME_SERIAL_NUMBER,
            NATIVE_SHIM_SOURCE_FILE_ID_128,
        ),
        (
            ZIG_PATH,
            ZIG_SHA256,
            ZIG_SIZE_BYTES,
            ZIG_VOLUME_SERIAL_NUMBER,
            ZIG_FILE_ID_128,
        ),
        (
            PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE,
            NATIVE_SHIM_EXECUTABLE_SHA256,
            NATIVE_SHIM_EXECUTABLE_SIZE_BYTES,
            NATIVE_SHIM_EXECUTABLE_VOLUME_SERIAL_NUMBER,
            NATIVE_SHIM_EXECUTABLE_FILE_ID_128,
        ),
    )
    for path, digest, size, volume, file_id in cases:
        assert _raw(path) == (digest, size)
        assert _identity(path) == (volume, file_id)
    assert _raw(ZIG_ARCHIVE) == (ZIG_ARCHIVE_SHA256, ZIG_ARCHIVE_SIZE_BYTES)
    assert _raw(PROJECT_ROOT / NATIVE_SHIM_SEALER_RELATIVE) == (
        NATIVE_SHIM_SEALER_SHA256,
        NATIVE_SHIM_SEALER_SIZE_BYTES,
    )
    assert _raw(PROJECT_ROOT / NATIVE_SHIM_SEAL_RECEIPT_RELATIVE) == (
        NATIVE_SHIM_SEAL_RECEIPT_SHA256,
        NATIVE_SHIM_SEAL_RECEIPT_SIZE_BYTES,
    )


def test_native_shim_rebuild_is_byte_for_byte_reproducible() -> None:
    source = PROJECT_ROOT / NATIVE_SHIM_SOURCE_RELATIVE
    with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / "build") as temporary:
        output = Path(temporary) / "reproduced.exe"
        completed = subprocess.run(
            (
                str(ZIG_PATH),
                "cc",
                "-target",
                "x86_64-windows-gnu",
                "-O2",
                "-s",
                "-municode",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(output),
                "-lbcrypt",
            ),
            cwd=PROJECT_ROOT,
            env={
                "PATH": r"C:\Windows\System32;C:\Windows",
                "SYSTEMROOT": r"C:\Windows",
                "WINDIR": r"C:\Windows",
                "LOCALAPPDATA": temporary,
                "APPDATA": temporary,
                "USERPROFILE": temporary,
                "TEMP": temporary,
                "TMP": temporary,
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=120,
        )
        assert completed.returncode == 0 and completed.stdout == completed.stderr == b""
        assert output.read_bytes() == (PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE).read_bytes()


def test_native_shim_is_x64_native_and_imports_only_windows_components() -> None:
    raw = (PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE).read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    assert struct.unpack_from("<H", raw, pe + 4)[0] == 0x8664
    assert set(_pe_imports(raw)) == {
        "KERNEL32.dll",
        "bcrypt.dll",
        "api-ms-win-crt-environment-l1-1-0.dll",
        "api-ms-win-crt-heap-l1-1-0.dll",
        "api-ms-win-crt-math-l1-1-0.dll",
        "api-ms-win-crt-private-l1-1-0.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll",
        "api-ms-win-crt-string-l1-1-0.dll",
    }


def test_native_shim_source_has_fixed_environment_hash_identity_and_job_boundary() -> None:
    source = (PROJECT_ROOT / NATIVE_SHIM_SOURCE_RELATIVE).read_text(encoding="utf-8")
    for required in (
        'L"PATH=C:\\\\Windows\\\\System32;C:\\\\Windows\\0"',
        'L"SYSTEMROOT=C:\\\\Windows\\0"',
        'L"WINDIR=C:\\\\Windows\\0\\0"',
        "BCryptFinishHash",
        "GetFileInformationByHandleEx",
        "GetFinalPathNameByHandleW",
        "FILE_SHARE_READ",
        "CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "AssignProcessToJobObject",
        "TerminateProcess",
        "0x8a, 0xdd, 0xe3, 0xb9, 0x85, 0x52, 0x3b, 0xdd",
    ):
        assert required in source
    for forbidden in ("GetEnvironmentVariable", "getenv(", "_wenviron", "system(", "ShellExecute"):
        assert forbidden not in source


def test_native_shim_filters_hostile_clr_environment_and_consumes_no_identity() -> None:
    governed = tuple(
        PROJECT_ROOT / relative
        for relative in (
            SUPERVISOR_CLAIM_RELATIVE,
            CHILD_PYCACHE_PREFIX_RELATIVE,
            DESIGN_OUTPUT_RELATIVE,
        )
    )
    before = tuple(path.exists() for path in governed)
    assert before == (False, False, False)
    environment = {
        "PATH": r"C:\definitely_absent;C:\Windows\System32;C:\Windows",
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "COR_ENABLE_PROFILING": "1",
        "COR_PROFILER": "{11111111-1111-1111-1111-111111111111}",
        "COR_PROFILER_PATH": r"C:\definitely_absent\hostile.dll",
        "COR_PROFILER_PATH_64": r"C:\definitely_absent\hostile64.dll",
        "CORECLR_ENABLE_PROFILING": "1",
        "CORECLR_PROFILER": "{11111111-1111-1111-1111-111111111111}",
        "CORECLR_PROFILER_PATH": r"C:\definitely_absent\corehostile.dll",
        "DOTNET_STARTUP_HOOKS": r"C:\definitely_absent\hook.dll",
        "COMPLUS_ProfAPI_ProfilerCompatibilitySetting": "EnableV2Profiler",
    }
    completed = subprocess.run(
        (str(PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE), NATIVE_AUDIT_ARGUMENT),
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0 and completed.stderr == b""
    receipt = json.loads(completed.stdout)
    assert receipt["status"] == "PASS_PREPYTHON_CUSTODY_AUDIT_NO_PYTHON_NO_IDENTITY"
    assert receipt["authority_generation_fresh_truth_heldout_signer_counts"] == ZERO_COUNTS
    assert tuple(path.exists() for path in governed) == before


def test_native_shim_and_directory_are_same_user_immutable() -> None:
    executable = PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE
    directory = executable.parent
    probe = directory / "__pytest_write_probe__.tmp"
    assert not probe.exists()
    attempts = (
        (str(executable), GENERIC_WRITE, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT),
        (str(executable), WRITE_DAC, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT),
        (str(directory), WRITE_DAC, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS),
        (str(probe), GENERIC_WRITE, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT),
    )
    for path, access, disposition, flags in attempts:
        handle = KERNEL32.CreateFileW(
            path,
            access,
            FILE_SHARE_READ,
            None,
            disposition,
            flags,
            None,
        )
        if handle != INVALID_HANDLE_VALUE:
            KERNEL32.CloseHandle(handle)
        assert handle == INVALID_HANDLE_VALUE
        assert ctypes.get_last_error() == 5
    assert not probe.exists()


def test_native_shim_invalid_modes_fail_before_any_identity_consumption() -> None:
    before = tuple(
        (PROJECT_ROOT / relative).exists()
        for relative in (
            SUPERVISOR_CLAIM_RELATIVE,
            CHILD_PYCACHE_PREFIX_RELATIVE,
            DESIGN_OUTPUT_RELATIVE,
        )
    )
    for arguments in ((), ("--not-a-contract-mode",)):
        completed = subprocess.run(
            (str(PROJECT_ROOT / NATIVE_SHIM_EXECUTABLE_RELATIVE), *arguments),
            cwd=PROJECT_ROOT,
            env={
                "PATH": r"C:\Windows\System32;C:\Windows",
                "SYSTEMROOT": r"C:\Windows",
                "WINDIR": r"C:\Windows",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert completed.returncode == 111
        assert b"NATIVE_ENVIRONMENT_SHIM_FAIL_CLOSED" in completed.stderr
    assert (
        tuple(
            (PROJECT_ROOT / relative).exists()
            for relative in (
                SUPERVISOR_CLAIM_RELATIVE,
                CHILD_PYCACHE_PREFIX_RELATIVE,
                DESIGN_OUTPUT_RELATIVE,
            )
        )
        == before
    )
