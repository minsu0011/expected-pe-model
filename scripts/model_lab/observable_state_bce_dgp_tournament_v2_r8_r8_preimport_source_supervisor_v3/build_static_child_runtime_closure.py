"""Build the fixed full CPython child-runtime closure without project imports."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import sys
from collections.abc import Iterable
from ctypes import wintypes
from pathlib import Path
from typing import Any, Final

PROJECT_ROOT: Final = Path(
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
BASE_ROOT: Final = Path(r"C:\Users\minsu\anaconda3\envs\myenv")
VENV_ROOT: Final = Path(r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310")
BASE_LIB: Final = BASE_ROOT / "Lib"
BASE_SITE_PACKAGES: Final = BASE_LIB / "site-packages"
BASE_DLLS: Final = BASE_ROOT / "DLLs"
BASE_LIBRARY_BIN: Final = BASE_ROOT / "Library/bin"
SYSTEM32: Final = Path(r"C:\Windows\System32")
BUILD_ARGUMENT: Final = "--emit-full-static-child-runtime-closure-v3-no-execution"
ZERO_COUNTS: Final = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "heldout": 0,
    "signer": 0,
    "truth": 0,
}
FIXED_CHILD_ENVIRONMENT: Final = {
    "PATH": (
        r"C:\Users\minsu\anaconda3\envs\myenv;"
        r"C:\Users\minsu\anaconda3\envs\myenv\DLLs;"
        r"C:\Users\minsu\anaconda3\envs\myenv\Library\bin;"
        r"C:\Windows\System32;C:\Windows"
    ),
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
}
SYSTEM_IMAGE_NAMES: Final = (
    "advapi32.dll",
    "bcryptprimitives.dll",
    "combase.dll",
    "conhost.exe",
    "crypt32.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "imm32.dll",
    "kernel32.dll",
    "KernelBase.dll",
    "msvcp_win.dll",
    "msvcrt.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "rsaenh.dll",
    "sechost.dll",
    "ucrtbase.dll",
    "user32.dll",
    "version.dll",
    "win32u.dll",
    "ws2_32.dll",
)
PROJECT_IMPORT_DIRECTORIES: Final = (
    PROJECT_ROOT,
    PROJECT_ROOT / "src",
    PROJECT_ROOT / "research",
    PROJECT_ROOT / "research/model_zoo",
    PROJECT_ROOT
    / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1",
    PROJECT_ROOT
    / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation",
    PROJECT_ROOT / "scripts",
    PROJECT_ROOT / "scripts/model_lab",
    PROJECT_ROOT
    / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation",
)

GENERIC_READ = 0x80000000
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_ID_INFO_CLASS = 18
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class RuntimeClosureBuildError(RuntimeError):
    """Raised when the fixed source-built runtime evidence is unsafe."""


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    ]


class _FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", _FILE_ID_128),
    ]


def _configure_kernel32() -> Any:
    if sys.platform != "win32":
        raise RuntimeClosureBuildError("runtime closure source-build requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.GetFileSizeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_longlong),
    ]
    kernel32.GetFileSizeEx.restype = wintypes.BOOL
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    return kernel32


_KERNEL32 = _configure_kernel32()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _close_checked(handle: int) -> None:
    if not _KERNEL32.CloseHandle(wintypes.HANDLE(handle)):
        raise RuntimeClosureBuildError(f"CloseHandle failed: {ctypes.get_last_error()}")


def _identity(handle: int) -> tuple[int, str]:
    info = _FILE_ID_INFO()
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        FILE_ID_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise RuntimeClosureBuildError(f"FileIdInfo query failed: {ctypes.get_last_error()}")
    return int(info.VolumeSerialNumber), bytes(info.FileId.Identifier).hex()


def _attributes(handle: int) -> tuple[int, int]:
    info = _FILE_ATTRIBUTE_TAG_INFO()
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise RuntimeClosureBuildError(
            f"FileAttributeTagInfo query failed: {ctypes.get_last_error()}"
        )
    return int(info.FileAttributes), int(info.ReparseTag)


def _final_path(handle: int) -> Path:
    required = _KERNEL32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0)
    if required == 0:
        raise RuntimeClosureBuildError("GetFinalPathName size query failed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = _KERNEL32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise RuntimeClosureBuildError("GetFinalPathName query failed")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _open(path: Path, *, directory: bool) -> int:
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    handle = _KERNEL32.CreateFileW(
        str(path),
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise RuntimeClosureBuildError(
            f"runtime custody open failed: {path}: {ctypes.get_last_error()}"
        )
    return int(handle)


def _read_handle(handle: int) -> bytes:
    size = ctypes.c_longlong()
    if not _KERNEL32.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
        raise RuntimeClosureBuildError("GetFileSizeEx failed")
    if size.value < 0 or not _KERNEL32.SetFilePointerEx(
        wintypes.HANDLE(handle), 0, None, FILE_BEGIN
    ):
        raise RuntimeClosureBuildError("SetFilePointerEx failed")
    digest_input: list[bytes] = []
    remaining = int(size.value)
    while remaining:
        requested = min(remaining, 1024 * 1024)
        buffer = ctypes.create_string_buffer(requested)
        read = wintypes.DWORD()
        if (
            not _KERNEL32.ReadFile(
                wintypes.HANDLE(handle),
                buffer,
                requested,
                ctypes.byref(read),
                None,
            )
            or read.value == 0
        ):
            raise RuntimeClosureBuildError("ReadFile failed or returned premature EOF")
        digest_input.append(buffer.raw[: read.value])
        remaining -= int(read.value)
    return b"".join(digest_input)


def _require_plain_exact(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        metadata = os.lstat(cursor)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise RuntimeClosureBuildError(f"runtime ancestry is reparse: {cursor}")
        with os.scandir(cursor) as stream:
            matches = [entry.name for entry in stream if entry.name.casefold() == part.casefold()]
        if matches != [part]:
            raise RuntimeClosureBuildError(f"runtime path case drifted: {path}")
        cursor /= part
    metadata = os.lstat(absolute)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)
        or (directory and not stat.S_ISDIR(metadata.st_mode))
        or (not directory and not stat.S_ISREG(metadata.st_mode))
    ):
        raise RuntimeClosureBuildError(f"runtime target kind is unsafe: {path}")
    return absolute


def _observe_file(path: Path, role: str) -> dict[str, Any]:
    absolute = _require_plain_exact(path, directory=False)
    handle = _open(absolute, directory=False)
    try:
        raw = _read_handle(handle)
        attributes, tag = _attributes(handle)
        volume, file_id = _identity(handle)
        final = _final_path(handle)
        if (
            attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            or tag != 0
            or volume <= 0
            or len(file_id) != 32
            or file_id == "0" * 32
            or os.path.normcase(str(final)) != os.path.normcase(str(absolute))
        ):
            raise RuntimeClosureBuildError(f"runtime file identity drifted: {path}")
        return {
            "file_id_128": file_id,
            "final_path": str(final),
            "raw_sha256": _sha256(raw),
            "reparse_ancestor_count": 0,
            "role": role,
            "size_bytes": len(raw),
            "volume_serial_number": volume,
        }
    finally:
        _close_checked(handle)


def _child_entry(path: Path) -> list[Any]:
    metadata = os.lstat(path)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = stat.S_ISLNK(metadata.st_mode) or bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    kind = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "other"
    )
    handle = _open(path, directory=kind == "directory")
    try:
        volume, file_id = _identity(handle)
    finally:
        _close_checked(handle)
    return [path.name, kind, reparse, volume, file_id]


def _observe_directory(path: Path, *, protection_required: bool) -> dict[str, Any]:
    absolute = _require_plain_exact(path, directory=True)
    handle = _open(absolute, directory=True)
    try:
        attributes, tag = _attributes(handle)
        volume, file_id = _identity(handle)
        final = _final_path(handle)
        if (
            not attributes & FILE_ATTRIBUTE_DIRECTORY
            or attributes & FILE_ATTRIBUTE_REPARSE_POINT
            or tag != 0
            or volume <= 0
            or len(file_id) != 32
            or file_id == "0" * 32
            or os.path.normcase(str(final)) != os.path.normcase(str(absolute))
        ):
            raise RuntimeClosureBuildError(f"runtime directory identity drifted: {path}")
    finally:
        _close_checked(handle)
    if protection_required:
        with os.scandir(absolute) as stream:
            children = sorted(
                (_child_entry(Path(entry.path)) for entry in stream),
                key=lambda row: (str(row[0]).casefold(), str(row[0])),
            )
    else:
        children = []
    return {
        "child_entries_semantic_sha256": _sha256(_canonical(children)),
        "child_entry_count": len(children),
        "file_id_128": file_id,
        "final_path": str(final),
        "protection_required": protection_required,
        "reparse_ancestor_count": 0,
        "volume_serial_number": volume,
    }


def _iter_files(root: Path) -> Iterable[Path]:
    for directory, directory_names, file_names in os.walk(root):
        current = Path(directory)
        if current == BASE_LIB:
            directory_names[:] = [
                name for name in directory_names if name.casefold() != "site-packages"
            ]
        directory_names.sort(key=lambda value: (value.casefold(), value))
        file_names.sort(key=lambda value: (value.casefold(), value))
        for name in file_names:
            yield current / name


def _iter_directories(root: Path) -> Iterable[Path]:
    yield root
    for directory, directory_names, _file_names in os.walk(root):
        current = Path(directory)
        if current == BASE_LIB:
            directory_names[:] = [
                name for name in directory_names if name.casefold() != "site-packages"
            ]
        directory_names.sort(key=lambda value: (value.casefold(), value))
        for name in directory_names:
            yield current / name


def _file_candidates() -> list[tuple[Path, str]]:
    values: list[tuple[Path, str]] = []
    for path in sorted(
        (item for item in BASE_ROOT.iterdir() if item.is_file()),
        key=lambda item: (item.name.casefold(), item.name),
    ):
        values.append((path, "BASE_ROOT_FILE"))
    for root, role in (
        (BASE_DLLS, "BASE_DLL_TREE_FILE"),
        (BASE_LIB, "BASE_STDLIB_TREE_FILE"),
        (BASE_LIBRARY_BIN, "BASE_LIBRARY_BIN_TREE_FILE"),
        (VENV_ROOT / "Scripts", "VENV_SCRIPTS_TREE_FILE"),
    ):
        values.extend((path, role) for path in _iter_files(root))
    values.extend(
        (path, "VENV_ROOT_FILE")
        for path in sorted(
            (item for item in VENV_ROOT.iterdir() if item.is_file()),
            key=lambda item: (item.name.casefold(), item.name),
        )
    )
    for directory in PROJECT_IMPORT_DIRECTORIES:
        values.extend(
            (path, "PROJECT_IMPORT_DIRECTORY_DIRECT_FILE")
            for path in sorted(
                (item for item in directory.iterdir() if item.is_file()),
                key=lambda item: (item.name.casefold(), item.name),
            )
        )
    values.extend((SYSTEM32 / name, "PINNED_SYSTEM_IMAGE") for name in SYSTEM_IMAGE_NAMES)
    return values


def _protected_directories() -> list[Path]:
    values = {
        BASE_ROOT,
        VENV_ROOT,
        VENV_ROOT / "Scripts",
        *PROJECT_IMPORT_DIRECTORIES,
    }
    for root in (BASE_DLLS, BASE_LIB, BASE_LIBRARY_BIN):
        values.update(_iter_directories(root))
    return sorted(values, key=lambda path: (str(path).casefold(), str(path)))


def build_payload() -> dict[str, Any]:
    file_rows_by_key: dict[str, dict[str, Any]] = {}
    for path, role in _file_candidates():
        absolute = Path(os.path.abspath(path))
        key = os.path.normcase(str(absolute))
        if key in file_rows_by_key:
            raise RuntimeClosureBuildError(f"runtime file candidate duplicated: {path}")
        file_rows_by_key[key] = _observe_file(absolute, role)
    file_rows = sorted(
        file_rows_by_key.values(),
        key=lambda row: (str(row["final_path"]).casefold(), str(row["final_path"])),
    )

    directory_rows_by_key: dict[str, dict[str, Any]] = {}
    for path in _protected_directories():
        absolute = Path(os.path.abspath(path))
        key = os.path.normcase(str(absolute))
        if key in directory_rows_by_key:
            continue
        directory_rows_by_key[key] = _observe_directory(absolute, protection_required=True)
    system32_key = os.path.normcase(str(SYSTEM32))
    if system32_key not in directory_rows_by_key:
        directory_rows_by_key[system32_key] = _observe_directory(
            SYSTEM32, protection_required=False
        )
    directory_rows = sorted(
        directory_rows_by_key.values(),
        key=lambda row: (str(row["final_path"]).casefold(), str(row["final_path"])),
    )
    absent_paths = [str(BASE_ROOT / "python310.zip")]
    if any(Path(path).exists() for path in absent_paths):
        raise RuntimeClosureBuildError("fixed absent runtime path unexpectedly exists")
    return {
        "absent_path_count": len(absent_paths),
        "absent_paths": absent_paths,
        "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
        "directory_record_count": len(directory_rows),
        "directory_records": directory_rows,
        "directory_records_semantic_sha256": _sha256(_canonical(directory_rows)),
        "fixed_child_environment": FIXED_CHILD_ENVIRONMENT,
        "path_discovery": {
            "caller_selected_path_count": 0,
            "dynamic_production_discovery": False,
            "source": (
                "PINNED_BASE_ROOT_PLUS_FULL_STDLIB_DLL_LIBRARY_BIN_"
                "VENV_CONFIG_AND_PINNED_SYSTEM_IMAGES"
            ),
        },
        "runtime_record_count": len(file_rows),
        "runtime_records": file_rows,
        "runtime_records_semantic_sha256": _sha256(_canonical(file_rows)),
        "schema_version": (
            "expected_pe.r8.r8.preimport_source_supervisor.full_static_child_runtime_closure.v3"
        ),
        "status": "PASS_SOURCE_BUILT_FULL_FIXED_CHILD_RUNTIME_CLOSURE_NO_EXECUTION",
    }


def main() -> int:
    if sys.argv != [str(Path(__file__).resolve()), BUILD_ARGUMENT]:
        raise RuntimeClosureBuildError("exact source-build argument is required")
    controls = sorted(name for name in os.environ if name.upper().startswith("PYTHON"))
    if controls:
        raise RuntimeClosureBuildError(f"Python environment controls are forbidden: {controls}")
    sys.stdout.buffer.write(_canonical(build_payload()) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
