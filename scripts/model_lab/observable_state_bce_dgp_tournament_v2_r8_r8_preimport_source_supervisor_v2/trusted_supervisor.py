"""Stdlib-only pre-import source supervisor for the fixed R8-r8 freezer.

This source must be compiled from bytes already held by the separately audited
``python -c`` stub.  Direct path execution fails before a manifest, project
source, output, or pycache identity is touched.  No project module is imported
at all; the exact 119-record closure and child prefix use only stdlib/ctypes.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping


PROJECT_ROOT = Path(
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
SCRIPT_ROOT = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v2"
)
SUPERVISOR_PATH = SCRIPT_ROOT / "trusted_supervisor.py"
MANIFEST_PATH = SCRIPT_ROOT / "SOURCE_CLOSURE_MANIFEST.json"
STUB_TEMPLATE_PATH = SCRIPT_ROOT / "STDLIB_LAUNCH_STUB_TEMPLATE.txt"
RUNTIME_CLOSURE_PATH = SCRIPT_ROOT / "STATIC_CHILD_RUNTIME_CLOSURE.json"
MANIFEST_RAW_SHA256 = "cde4fa3513b4b6fe51b2376235a7111c4004d8be09cd3635a26adadcde2c03e7"
MANIFEST_SIZE_BYTES = 6489
STUB_TEMPLATE_RAW_SHA256 = (
    "2d684150f011152f768ae70209da3a6bf9c2c6d08d56c0ff7ffc45dab372178b"
)
STUB_TEMPLATE_SIZE_BYTES = 8089
STUB_TEMPLATE_VOLUME_SERIAL_NUMBER = 13325047249941796650
STUB_TEMPLATE_FILE_ID_128 = "5c92060000000a000000000000000000"
RUNTIME_CLOSURE_RAW_SHA256 = (
    "09e11bb2f2d8e6aff7e865e4e15aaee80a11c14109233f45039e6df66d331836"
)
RUNTIME_CLOSURE_SIZE_BYTES = 136853
RUNTIME_CLOSURE_VOLUME_SERIAL_NUMBER = 13325047249941796650
RUNTIME_CLOSURE_FILE_ID_128 = "2ac40400000031000000000000000000"
RUNTIME_RECORD_COUNT = 298
RUNTIME_RECORDS_SEMANTIC_SHA256 = (
    "cd91799cf28af21808255c921d02ef41a44ee42863081d053c15bcae79f73d20"
)
R8_SOURCE_LOCK_RAW_SHA256 = "3a7ce804da20c1acfad5812acd5789693a291fbf8eb45e7cd42958500fbc53b6"
RECORDS_119_SEMANTIC_SHA256 = (
    "192788eff7e396bce7226e94748a4f7313fc7cb8965434a45d51067ed2ebc442"
)
PINNED_VENV_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_BASE_PYTHON = Path(r"C:\Users\minsu\anaconda3\envs\myenv\python.exe")
SUPERVISOR_CLAIM_PREFIX = PROJECT_ROOT / "build" / (
    "pc_r8r8_preimport_source_supervisor_v2_actual_once_20260823"
)
CHILD_PYCACHE_PREFIX = PROJECT_ROOT / "build" / (
    "pc_r8r8_static_freeze_actual_once_20260822"
)
FREEZER_PATH = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "qualification_generation/freeze_static_evidence.py"
)
FREEZER_ARGUMENT = "--freeze-r8-r8-static-source-no-authority-no-generation-no-fresh"
EXACT_CHILD_COMMAND = (
    str(PINNED_VENV_PYTHON),
    "-I",
    "-S",
    "-B",
    "-E",
    "-X",
    f"pycache_prefix={CHILD_PYCACHE_PREFIX}",
    str(FREEZER_PATH),
    FREEZER_ARGUMENT,
)
ZERO_COUNTS = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "heldout": 0,
    "signer": 0,
    "truth": 0,
}
CHILD_TIMEOUT_SECONDS = 900
CHILD_CLEANUP_TIMEOUT_SECONDS = 30
CHILD_STREAM_CAPTURE_LIMIT_BYTES = 8 * 1024 * 1024

GENERIC_READ = 0x80000000
FILE_LIST_DIRECTORY = 0x0001
FILE_ADD_SUBDIRECTORY = 0x0004
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_BEGIN = 0
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_ID_INFO_CLASS = 18
FILE_CREATE = 2
FILE_CREATED = 2
FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_OPEN_REPARSE_POINT = 0x00200000
OBJ_DONT_REPARSE = 0x00001000
WRITE_DAC = 0x00040000
READ_CONTROL = 0x00020000
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1
SDDL_REVISION_1 = 1
SE_DACL_PROTECTED = 0x1000
SE_DACL_PRESENT = 0x0004
PROTECTED_READ_ONLY_SDDL = (
    "D:P(A;OICI;GRGX;;;OW)(A;OICI;GRGX;;;SY)(A;OICI;GRGX;;;BA)"
)
TEST_RESTORE_SDDL = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class SupervisorError(RuntimeError):
    """Fail-closed static-supervisor error."""


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


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_void_p),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IOSB_UNION(ctypes.Union):
    _fields_ = [("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p)]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("u", _IOSB_UNION), ("Information", ctypes.c_size_t)]


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


def _kernel32() -> Any:
    if sys.platform != "win32":
        raise SupervisorError("pre-import supervisor requires Windows")
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _configure_win32() -> Any:
    kernel32 = _kernel32()
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
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    return kernel32


_KERNEL32 = _configure_win32()


def _configure_ntdll() -> Any:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    ntdll.NtCreateFile.restype = ctypes.c_long
    return ntdll


_NTDLL = _configure_ntdll()


def _configure_advapi32() -> Any:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetKernelObjectSecurity.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    advapi32.SetKernelObjectSecurity.restype = wintypes.BOOL
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorLength.argtypes = [ctypes.c_void_p]
    advapi32.GetSecurityDescriptorLength.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    return advapi32


_ADVAPI32 = _configure_advapi32()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _close_checked(handle: int) -> None:
    if not _KERNEL32.CloseHandle(wintypes.HANDLE(handle)):
        raise SupervisorError(f"CloseHandle failed: {ctypes.get_last_error()}")


def _identity(handle: int) -> tuple[int, str]:
    info = _FILE_ID_INFO()
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        FILE_ID_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise SupervisorError(f"FileIdInfo query failed: {ctypes.get_last_error()}")
    return int(info.VolumeSerialNumber), bytes(info.FileId.Identifier).hex()


def _attributes(handle: int) -> tuple[int, int]:
    info = _FILE_ATTRIBUTE_TAG_INFO()
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise SupervisorError(
            f"FileAttributeTagInfo query failed: {ctypes.get_last_error()}"
        )
    return int(info.FileAttributes), int(info.ReparseTag)


def _final_path(handle: int) -> Path:
    required = _KERNEL32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), None, 0, 0
    )
    if required == 0:
        raise SupervisorError(f"GetFinalPathName size failed: {ctypes.get_last_error()}")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = _KERNEL32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buffer, len(buffer), 0
    )
    if written == 0 or written >= len(buffer):
        raise SupervisorError(f"GetFinalPathName failed: {ctypes.get_last_error()}")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _read_handle(handle: int) -> bytes:
    size = ctypes.c_longlong()
    if not _KERNEL32.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
        raise SupervisorError(f"GetFileSizeEx failed: {ctypes.get_last_error()}")
    if size.value < 0 or not _KERNEL32.SetFilePointerEx(
        wintypes.HANDLE(handle), 0, None, FILE_BEGIN
    ):
        raise SupervisorError(f"SetFilePointerEx failed: {ctypes.get_last_error()}")
    chunks: list[bytes] = []
    remaining = int(size.value)
    while remaining:
        requested = min(remaining, 1024 * 1024)
        buffer = ctypes.create_string_buffer(requested)
        read = wintypes.DWORD()
        if not _KERNEL32.ReadFile(
            wintypes.HANDLE(handle),
            buffer,
            requested,
            ctypes.byref(read),
            None,
        ):
            raise SupervisorError(f"ReadFile failed: {ctypes.get_last_error()}")
        if read.value == 0:
            raise SupervisorError("held file returned premature EOF")
        chunks.append(buffer.raw[: read.value])
        remaining -= int(read.value)
    return b"".join(chunks)


def _open_no_share_write_delete(
    path: Path, *, directory: bool, create_child: bool = False
) -> int:
    access = FILE_READ_ATTRIBUTES
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        access |= FILE_LIST_DIRECTORY | FILE_TRAVERSE
        if create_child:
            access |= FILE_ADD_SUBDIRECTORY
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    elif create_child:
        raise SupervisorError("file handle cannot receive create-child access")
    else:
        access |= GENERIC_READ
    handle = _KERNEL32.CreateFileW(
        str(path), access, FILE_SHARE_READ, None, OPEN_EXISTING, flags, None
    )
    if handle == INVALID_HANDLE_VALUE:
        raise SupervisorError(
            f"no-share-write/delete open failed for {path}: {ctypes.get_last_error()}"
        )
    return int(handle)


def _absolute_directory_chain(file_path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(file_path))
    anchor = Path(absolute.anchor)
    chain: list[Path] = [anchor]
    cursor = anchor
    for part in absolute.parent.parts[1:]:
        cursor /= part
        chain.append(cursor)
    return tuple(chain)


def _require_exact_case(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        with os.scandir(cursor) as stream:
            matches = [entry.name for entry in stream if entry.name.casefold() == part.casefold()]
        if matches != [part]:
            raise SupervisorError(f"exact lexical path case drifted: {path}")
        cursor /= part


def _apply_exact_dacl(handle: int, sddl: str) -> None:
    security_descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.ULONG()
    if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(security_descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise SupervisorError(
            f"SDDL conversion failed: {ctypes.get_last_error()}"
        )
    primary: BaseException | None = None
    try:
        dacl_present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        dacl_defaulted = wintypes.BOOL()
        if not _ADVAPI32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ) or not dacl_present.value or not dacl.value:
            raise SupervisorError("converted protected DACL is absent")
        if not _ADVAPI32.SetKernelObjectSecurity(
            wintypes.HANDLE(handle),
            DACL_SECURITY_INFORMATION,
            security_descriptor,
        ):
            raise SupervisorError(
                f"SetKernelObjectSecurity protected DACL failed: "
                f"{ctypes.get_last_error()}"
            )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if _KERNEL32.LocalFree(security_descriptor):
            error = SupervisorError("LocalFree for converted DACL failed")
            if primary is not None:
                raise error from primary
            raise error


def _security_snapshot(handle: int) -> Mapping[str, Any]:
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = _ADVAPI32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0 or not dacl.value or not security_descriptor.value:
        raise SupervisorError(f"GetSecurityInfo protected DACL failed: {result}")
    primary: BaseException | None = None
    try:
        control = ctypes.c_ushort()
        revision = wintypes.DWORD()
        if not _ADVAPI32.GetSecurityDescriptorControl(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise SupervisorError("GetSecurityDescriptorControl failed")
        size = int(_ADVAPI32.GetSecurityDescriptorLength(security_descriptor))
        if (
            size <= 0
            or control.value & (SE_DACL_PRESENT | SE_DACL_PROTECTED)
            != (SE_DACL_PRESENT | SE_DACL_PROTECTED)
        ):
            raise SupervisorError("protected DACL control flags drifted")
        raw = ctypes.string_at(security_descriptor, size)
        return {
            "security_descriptor_raw_sha256": _sha256(raw),
            "security_descriptor_size_bytes": size,
            "security_descriptor_control": int(control.value),
            "security_descriptor_revision": int(revision.value),
            "dacl_present": True,
            "dacl_protected": True,
            "source_sddl": PROTECTED_READ_ONLY_SDDL,
        }
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if _KERNEL32.LocalFree(security_descriptor):
            error = SupervisorError("LocalFree for queried DACL failed")
            if primary is not None:
                raise error from primary
            raise error


def _filetime_100ns(value: _FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


class _HeldFile:
    """Hold full reparse-free ancestry and one exact file against replacement."""

    def __init__(self, *, path: Path, expected_sha256: str, expected_size: int) -> None:
        self.path = Path(os.path.abspath(path))
        self.expected_sha256 = expected_sha256
        self.expected_size = expected_size
        self._handles: list[int] = []
        self._ancestry_identities: tuple[tuple[int, str], ...] = ()
        self.handle: int | None = None
        self.raw = b""
        self.volume_serial_number = 0
        self.file_id_128 = ""
        try:
            _require_exact_case(self.path)
            ancestry: list[tuple[int, str]] = []
            for directory in _absolute_directory_chain(self.path):
                metadata = os.lstat(directory)
                if stat.S_ISLNK(metadata.st_mode) or bool(
                    int(getattr(metadata, "st_file_attributes", 0))
                    & FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise SupervisorError(f"reparse ancestry rejected: {directory}")
                held = _open_no_share_write_delete(directory, directory=True)
                self._handles.append(held)
                attributes, tag = _attributes(held)
                if not attributes & FILE_ATTRIBUTE_DIRECTORY or (
                    attributes & FILE_ATTRIBUTE_REPARSE_POINT or tag != 0
                ):
                    raise SupervisorError(f"unsafe held ancestry: {directory}")
                ancestry.append(_identity(held))
            metadata = os.lstat(self.path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise SupervisorError(f"held target is not a plain file: {self.path}")
            target = _open_no_share_write_delete(self.path, directory=False)
            self._handles.append(target)
            self.handle = target
            attributes, tag = _attributes(target)
            if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) or tag:
                raise SupervisorError(f"held target is unsafe: {self.path}")
            if os.path.normcase(str(_final_path(target))) != os.path.normcase(str(self.path)):
                raise SupervisorError(f"held target final path drifted: {self.path}")
            self.raw = _read_handle(target)
            self.volume_serial_number, self.file_id_128 = _identity(target)
            self._ancestry_identities = tuple(ancestry)
            self.verify()
        except BaseException as primary:
            try:
                self.close()
            except BaseException:
                raise SupervisorError("held file construction and cleanup failed") from primary
            raise

    def verify(self) -> Mapping[str, Any]:
        if self.handle is None:
            raise SupervisorError("held file is closed")
        for handle, expected in zip(self._handles[:-1], self._ancestry_identities):
            attributes, tag = _attributes(handle)
            if (
                _identity(handle) != expected
                or not attributes & FILE_ATTRIBUTE_DIRECTORY
                or attributes & FILE_ATTRIBUTE_REPARSE_POINT
                or tag != 0
            ):
                raise SupervisorError(f"held ancestry identity drifted: {self.path}")
        raw = _read_handle(self.handle)
        identity = _identity(self.handle)
        attributes, tag = _attributes(self.handle)
        if (
            len(raw) != self.expected_size
            or _sha256(raw) != self.expected_sha256
            or identity != (self.volume_serial_number, self.file_id_128)
            or attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
            or tag != 0
            or os.path.normcase(str(_final_path(self.handle)))
            != os.path.normcase(str(self.path))
        ):
            raise SupervisorError(f"held file identity/hash changed: {self.path}")
        try:
            receipt_path = self.path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            receipt_path = str(self.path)
        return {
            "relative_path": receipt_path,
            "raw_sha256": self.expected_sha256,
            "size_bytes": self.expected_size,
            "volume_serial_number": self.volume_serial_number,
            "file_id_128": self.file_id_128,
            "reparse_ancestor_count": 0,
            "share_mode": "FILE_SHARE_READ_ONLY",
            "write_share_allowed": False,
            "delete_share_allowed": False,
            "handle_still_open": True,
        }

    def close(self) -> None:
        failures: list[BaseException] = []
        for handle in reversed(self._handles):
            try:
                _close_checked(handle)
            except BaseException as exc:
                failures.append(exc)
        self._handles.clear()
        self.handle = None
        if failures:
            raise SupervisorError(
                f"{len(failures)} held-file handle close operation(s) failed"
            ) from failures[0]


class _HeldCreatedDirectory:
    """Atomically create-new and hold one exact empty direct-child directory."""

    def __init__(self, *, parent: Path, child_name: str) -> None:
        if (
            type(child_name) is not str
            or not child_name
            or Path(child_name).name != child_name
            or child_name in {".", ".."}
            or "/" in child_name
            or "\\" in child_name
        ):
            raise SupervisorError("child directory name is not one exact leaf")
        self.parent = Path(os.path.abspath(parent))
        self.path = self.parent / child_name
        self.child_name = child_name
        self._handles: list[int] = []
        self._ancestry_identities: tuple[tuple[int, str], ...] = ()
        self.handle: int | None = None
        self.volume_serial_number = 0
        self.file_id_128 = ""
        self._dacl_before: Mapping[str, Any] | None = None
        try:
            _require_exact_case(self.parent)
            ancestry: list[tuple[int, str]] = []
            chain = _absolute_directory_chain(self.path)
            for index, directory in enumerate(chain):
                metadata = os.lstat(directory)
                if stat.S_ISLNK(metadata.st_mode) or bool(
                    int(getattr(metadata, "st_file_attributes", 0))
                    & FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise SupervisorError(
                        f"child-prefix reparse ancestry rejected: {directory}"
                    )
                held = _open_no_share_write_delete(
                    directory,
                    directory=True,
                    create_child=index == len(chain) - 1,
                )
                self._handles.append(held)
                attributes, tag = _attributes(held)
                if (
                    not attributes & FILE_ATTRIBUTE_DIRECTORY
                    or attributes & FILE_ATTRIBUTE_REPARSE_POINT
                    or tag != 0
                    or os.path.normcase(str(_final_path(held)))
                    != os.path.normcase(str(directory))
                ):
                    raise SupervisorError(
                        f"unsafe held child-prefix ancestry: {directory}"
                    )
                ancestry.append(_identity(held))

            name_buffer = ctypes.create_unicode_buffer(child_name)
            encoded_name = child_name.encode("utf-16-le")
            unicode_name = _UNICODE_STRING(
                len(encoded_name),
                len(encoded_name) + 2,
                ctypes.cast(name_buffer, ctypes.c_void_p),
            )
            object_attributes = _OBJECT_ATTRIBUTES(
                ctypes.sizeof(_OBJECT_ATTRIBUTES),
                wintypes.HANDLE(self._handles[-1]),
                ctypes.pointer(unicode_name),
                OBJ_DONT_REPARSE,
                None,
                None,
            )
            io_status = _IO_STATUS_BLOCK()
            target = wintypes.HANDLE()
            status = _NTDLL.NtCreateFile(
                ctypes.byref(target),
                FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | WRITE_DAC
                | READ_CONTROL,
                ctypes.byref(object_attributes),
                ctypes.byref(io_status),
                None,
                0,
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT,
                None,
                0,
            )
            if status != 0 or int(io_status.Information) != FILE_CREATED:
                raise SupervisorError(
                    "child pycache prefix create-new failed; identity consumed or unsafe"
                )
            if target.value is None:
                raise SupervisorError("child pycache prefix returned a null handle")
            self.handle = int(target.value)
            self._handles.append(self.handle)
            self._ancestry_identities = tuple(ancestry)
            self.volume_serial_number, self.file_id_128 = _identity(self.handle)
            _apply_exact_dacl(self.handle, PROTECTED_READ_ONLY_SDDL)
            self._dacl_before = dict(_security_snapshot(self.handle))
            self.verify()
        except BaseException as primary:
            try:
                self.close()
            except BaseException:
                raise SupervisorError(
                    "child-prefix construction and cleanup failed"
                ) from primary
            raise

    def verify(self) -> Mapping[str, Any]:
        if self.handle is None:
            raise SupervisorError("held child pycache prefix is closed")
        if self._dacl_before is None:
            raise SupervisorError("held child pycache prefix DACL is absent")
        for handle, expected in zip(self._handles[:-1], self._ancestry_identities):
            attributes, tag = _attributes(handle)
            if (
                _identity(handle) != expected
                or not attributes & FILE_ATTRIBUTE_DIRECTORY
                or attributes & FILE_ATTRIBUTE_REPARSE_POINT
                or tag != 0
            ):
                raise SupervisorError("held child-prefix ancestry identity drifted")
        attributes, tag = _attributes(self.handle)
        if (
            _identity(self.handle)
            != (self.volume_serial_number, self.file_id_128)
            or not attributes & FILE_ATTRIBUTE_DIRECTORY
            or attributes & FILE_ATTRIBUTE_REPARSE_POINT
            or tag != 0
            or os.path.normcase(str(_final_path(self.handle)))
            != os.path.normcase(str(self.path))
        ):
            raise SupervisorError("held child pycache prefix identity drifted")
        with os.scandir(self.path) as entries:
            direct_children = tuple(entry.name for entry in entries)
        if direct_children:
            raise SupervisorError(
                f"held child pycache prefix is not empty: {list(direct_children)}"
            )
        dacl_after = dict(_security_snapshot(self.handle))
        if dacl_after != self._dacl_before:
            raise SupervisorError("held child pycache prefix DACL drifted")
        return {
            "path": str(self.path),
            "volume_serial_number": self.volume_serial_number,
            "file_id_128": self.file_id_128,
            "reparse_tag": 0,
            "direct_child_entry_count": 0,
            "create_disposition": "FILE_CREATE",
            "create_information": "FILE_CREATED",
            "share_mode": "FILE_SHARE_READ_ONLY",
            "write_share_allowed": False,
            "delete_share_allowed": False,
            "handle_still_open": True,
            "identity_consumed_no_retry": True,
            "protected_read_list_only_dacl": self._dacl_before,
            "dacl_continuity": True,
        }

    def restore_test_cleanup_dacl(self) -> None:
        if self.handle is None:
            raise SupervisorError("held child pycache prefix is closed")
        try:
            self.path.relative_to(PROJECT_ROOT / "build")
        except ValueError:
            _apply_exact_dacl(self.handle, TEST_RESTORE_SDDL)
            return
        raise SupervisorError("production child prefix DACL cannot be restored")

    def close(self) -> None:
        failures: list[BaseException] = []
        for handle in reversed(self._handles):
            try:
                _close_checked(handle)
            except BaseException as exc:
                failures.append(exc)
        self._handles.clear()
        self.handle = None
        if failures:
            raise SupervisorError(
                f"{len(failures)} child-prefix handle close operation(s) failed"
            ) from failures[0]


class _CheckedOwners:
    def __init__(self) -> None:
        self._items: list[tuple[str, Any]] = []
        self.closed_labels: tuple[str, ...] = ()

    def own(self, label: str, value: Any) -> Any:
        self._items.append((label, value))
        return value

    def close(self, primary: BaseException | None = None) -> None:
        failures: list[tuple[str, BaseException]] = []
        closed: list[str] = []
        for label, value in reversed(self._items):
            try:
                value.close()
                closed.append(label)
            except BaseException as exc:
                failures.append((label, exc))
        self._items.clear()
        self.closed_labels = tuple(closed)
        if failures:
            error = SupervisorError(
                f"{len(failures)} cleanup operation(s) failed: "
                + ",".join(label for label, _exc in failures)
            )
            if primary is not None:
                raise error from primary
            raise error from failures[0][1]
        if primary is not None:
            raise primary


def _exact_record(value: object) -> list[Any]:
    if (
        type(value) is not list
        or len(value) != 3
        or type(value[0]) is not str
        or type(value[1]) is not str
        or type(value[2]) is not int
    ):
        raise SupervisorError("source closure record shape drifted")
    relative, digest, size = value
    pure = PurePosixPath(relative)
    if (
        not relative
        or pure.is_absolute()
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or size < 0
    ):
        raise SupervisorError("source closure record value drifted")
    return [relative, digest, size]


def _exact_identity_record(value: object) -> list[Any]:
    if type(value) is not list or len(value) != 5:
        raise SupervisorError("identity-bound artifact record shape drifted")
    relative, digest, size, volume, file_id = value
    base = _exact_record([relative, digest, size])
    if (
        type(volume) is not int
        or volume <= 0
        or type(file_id) is not str
        or len(file_id) != 32
        or file_id == "0" * 32
        or any(character not in "0123456789abcdef" for character in file_id)
    ):
        raise SupervisorError("identity-bound artifact record value drifted")
    return [*base, volume, file_id]


def _derive_records(manifest: Mapping[str, Any], r7_raw: bytes) -> tuple[list[Any], ...]:
    r7_record = _exact_record(manifest.get("r7_source_lock_record"))
    if len(r7_raw) != r7_record[2] or _sha256(r7_raw) != r7_record[1]:
        raise SupervisorError("R7 SOURCE_LOCK raw bytes drifted")
    try:
        r7_payload = json.loads(r7_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("R7 SOURCE_LOCK cannot be decoded") from exc
    r7_rows = tuple(_exact_record(row) for row in r7_payload.get("source_sha256", ()))
    delta = tuple(_exact_record(row) for row in manifest.get("r8_delta_rows", ()))
    source_rows = tuple(sorted((*r7_rows, *delta), key=lambda row: row[0]))
    if (
        len(r7_rows) != 95
        or len(delta) != 22
        or len(source_rows) != 117
        or len({row[0] for row in source_rows}) != 117
        or _sha256(_canonical(list(source_rows)))
        != manifest.get("r8_source_rows_semantic_sha256")
    ):
        raise SupervisorError("derived 117-row source closure drifted")
    outer = _exact_record(manifest.get("outer_bootstrap_record"))
    rows = tuple(sorted((*source_rows, outer, r7_record), key=lambda row: row[0]))
    if (
        len(rows) != 119
        or len({row[0] for row in rows}) != 119
        or _sha256(_canonical(list(rows))) != RECORDS_119_SEMANTIC_SHA256
    ):
        raise SupervisorError("derived 119-row closure drifted")
    return rows


def _require_no_python_environment() -> Mapping[str, Any]:
    names = tuple(
        sorted(
            (name for name in os.environ if name.upper().startswith("PYTHON")),
            key=lambda item: (item.casefold(), item),
        )
    )
    if names:
        raise SupervisorError(f"Python environment controls are forbidden: {list(names)}")
    return {
        "environment_entry_count_inspected": len(os.environ),
        "python_environment_control_count": 0,
        "python_environment_control_names": [],
    }


def _render_stub_template(
    template_raw: bytes,
    *,
    supervisor_raw_sha256: str,
    supervisor_size_bytes: int,
    supervisor_volume_serial_number: int,
    supervisor_file_id_128: str,
) -> bytes:
    replacements = {
        "__SUPERVISOR_RAW_SHA256_64__": supervisor_raw_sha256,
        "__SUPERVISOR_SIZE_BYTES_DECIMAL__": str(supervisor_size_bytes),
        "__SUPERVISOR_VOLUME_SERIAL_NUMBER_DECIMAL__": str(
            supervisor_volume_serial_number
        ),
        "__SUPERVISOR_FILE_ID_128_HEX__": supervisor_file_id_128,
    }
    if (
        len(supervisor_raw_sha256) != 64
        or any(character not in "0123456789abcdef" for character in supervisor_raw_sha256)
        or type(supervisor_size_bytes) is not int
        or supervisor_size_bytes <= 0
        or type(supervisor_volume_serial_number) is not int
        or supervisor_volume_serial_number <= 0
        or len(supervisor_file_id_128) != 32
        or any(character not in "0123456789abcdef" for character in supervisor_file_id_128)
    ):
        raise SupervisorError("supervisor identity cannot render the fixed stub template")
    try:
        rendered = template_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SupervisorError("stub template is not exact ASCII") from exc
    for placeholder, value in replacements.items():
        if rendered.count(placeholder) != 1:
            raise SupervisorError(f"stub template placeholder drifted: {placeholder}")
        rendered = rendered.replace(placeholder, value)
    if "__SUPERVISOR_" in rendered:
        raise SupervisorError("stub template contains an unbound dynamic placeholder")
    return rendered.encode("ascii")


def _require_stub_activation(owner: _CheckedOwners) -> Mapping[str, Any]:
    source_handle = globals().get("_STUB_SOURCE_HANDLE")
    claim_handle = globals().get("_STUB_CLAIM_HANDLE")
    if (
        type(source_handle) is not int
        or type(claim_handle) is not int
        or sys.argv != [str(SUPERVISOR_PATH)]
        or len(sys.orig_argv) != 7
        or tuple(sys.orig_argv[:6])
        != (str(PINNED_BASE_PYTHON), "-I", "-S", "-B", "-E", "-c")
        or sys.executable != str(PINNED_VENV_PYTHON)
    ):
        raise SupervisorError("direct path invocation or unaudited stub activation denied")
    stub_raw = sys.orig_argv[6].encode("utf-8")
    source_raw = _read_handle(source_handle)
    source_identity = _identity(source_handle)
    source_attributes, source_tag = _attributes(source_handle)
    claim_identity = _identity(claim_handle)
    claim_attributes, claim_tag = _attributes(claim_handle)
    template_hold = owner.own(
        "stub_template",
        _HeldFile(
            path=STUB_TEMPLATE_PATH,
            expected_sha256=STUB_TEMPLATE_RAW_SHA256,
            expected_size=STUB_TEMPLATE_SIZE_BYTES,
        ),
    )
    if (
        template_hold.volume_serial_number != STUB_TEMPLATE_VOLUME_SERIAL_NUMBER
        or template_hold.file_id_128 != STUB_TEMPLATE_FILE_ID_128
    ):
        raise SupervisorError("held stub template FileId drifted")
    expected_stub_raw = _render_stub_template(
        template_hold.raw,
        supervisor_raw_sha256=_sha256(source_raw),
        supervisor_size_bytes=len(source_raw),
        supervisor_volume_serial_number=source_identity[0],
        supervisor_file_id_128=source_identity[1],
    )
    if (
        stub_raw != expected_stub_raw
        or os.path.normcase(str(_final_path(source_handle)))
        != os.path.normcase(str(SUPERVISOR_PATH))
        or source_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
        or source_tag != 0
        or claim_identity[0] <= 0
        or len(claim_identity[1]) != 32
        or claim_identity[1] == "0" * 32
        or not claim_attributes & FILE_ATTRIBUTE_DIRECTORY
        or claim_attributes & FILE_ATTRIBUTE_REPARSE_POINT
        or claim_tag != 0
        or os.path.normcase(str(_final_path(claim_handle)))
        != os.path.normcase(str(SUPERVISOR_CLAIM_PREFIX))
    ):
        raise SupervisorError("held stub/supervisor/claim activation identity drifted")
    return {
        "rendered_stub_raw_sha256": _sha256(stub_raw),
        "rendered_stub_size_bytes": len(stub_raw),
        "stub_template": template_hold.verify(),
        "stub_template_full_reconstruction_match": True,
        "self_reported_stub_identity_count": 0,
        "supervisor_raw_sha256": _sha256(source_raw),
        "supervisor_size_bytes": len(source_raw),
        "supervisor_volume_serial_number": source_identity[0],
        "supervisor_file_id_128": source_identity[1],
        "supervisor_final_path": str(SUPERVISOR_PATH),
        "supervisor_claim_volume_serial_number": claim_identity[0],
        "supervisor_claim_file_id_128": claim_identity[1],
        "direct_path_invocation_allowed": False,
        "base_orig_argv_executable": str(PINNED_BASE_PYTHON),
        "venv_sys_executable": str(PINNED_VENV_PYTHON),
    }


def _hold_fixed_closure(owner: _CheckedOwners) -> tuple[tuple[_HeldFile, ...], Mapping[str, Any]]:
    manifest_hold = owner.own(
        "closure_manifest",
        _HeldFile(
            path=MANIFEST_PATH,
            expected_sha256=MANIFEST_RAW_SHA256,
            expected_size=MANIFEST_SIZE_BYTES,
        ),
    )
    try:
        manifest = json.loads(manifest_hold.raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("held closure manifest cannot be decoded") from exc
    if (
        manifest.get("schema_version")
        != "expected_pe.r8.r8.preimport_source_supervisor.closure_manifest.v2"
        or manifest.get("status")
        != (
            "FIXED_119_SOURCE_RECORDS_PLUS_TEMPLATE_AND_RUNTIME_"
            "NO_EXECUTION_AUTHORITY"
        )
        or manifest.get("r8_source_lock_raw_sha256") != R8_SOURCE_LOCK_RAW_SHA256
        or manifest.get("records_119_semantic_sha256")
        != RECORDS_119_SEMANTIC_SHA256
        or manifest.get("authority_generation_fresh_truth_heldout_signer_counts")
        != ZERO_COUNTS
    ):
        raise SupervisorError("held closure manifest semantic drifted")
    expected_template_record = [
        STUB_TEMPLATE_PATH.relative_to(PROJECT_ROOT).as_posix(),
        STUB_TEMPLATE_RAW_SHA256,
        STUB_TEMPLATE_SIZE_BYTES,
        STUB_TEMPLATE_VOLUME_SERIAL_NUMBER,
        STUB_TEMPLATE_FILE_ID_128,
    ]
    expected_runtime_record = [
        RUNTIME_CLOSURE_PATH.relative_to(PROJECT_ROOT).as_posix(),
        RUNTIME_CLOSURE_RAW_SHA256,
        RUNTIME_CLOSURE_SIZE_BYTES,
        RUNTIME_CLOSURE_VOLUME_SERIAL_NUMBER,
        RUNTIME_CLOSURE_FILE_ID_128,
    ]
    if (
        _exact_identity_record(manifest.get("stub_template_record"))
        != expected_template_record
        or _exact_identity_record(manifest.get("runtime_closure_record"))
        != expected_runtime_record
    ):
        raise SupervisorError("manifest template/runtime identity record drifted")
    r7_record = _exact_record(manifest.get("r7_source_lock_record"))
    r7_hold = owner.own(
        "source=r7_source_lock",
        _HeldFile(
            path=PROJECT_ROOT / r7_record[0],
            expected_sha256=r7_record[1],
            expected_size=r7_record[2],
        ),
    )
    rows = _derive_records(manifest, r7_hold.raw)
    held_by_relative: dict[str, _HeldFile] = {r7_record[0]: r7_hold}
    for index, row in enumerate(rows):
        if row[0] in held_by_relative:
            continue
        held_by_relative[row[0]] = owner.own(
            f"source[{index}]={row[0]}",
            _HeldFile(
                path=PROJECT_ROOT / row[0],
                expected_sha256=row[1],
                expected_size=row[2],
            ),
        )
    held = tuple(held_by_relative[row[0]] for row in rows)
    receipts = [item.verify() for item in held]
    return held, {
        "status": "PASS_119_SOURCES_HELD_BEFORE_PROJECT_IMPORT",
        "source_record_count": len(receipts),
        "records_semantic_sha256": _sha256(
            _canonical([[r["relative_path"], r["raw_sha256"], r["size_bytes"]] for r in receipts])
        ),
        "records": receipts,
        "manifest_raw_sha256": MANIFEST_RAW_SHA256,
        "all_handles_still_open": True,
        "project_import_count_before_hold": 0,
    }


def _runtime_row(value: object) -> Mapping[str, Any]:
    expected_keys = {
        "file_id_128",
        "final_path",
        "raw_sha256",
        "reparse_ancestor_count",
        "roles",
        "size_bytes",
        "volume_serial_number",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise SupervisorError("runtime closure row key set drifted")
    final_path = value["final_path"]
    digest = value["raw_sha256"]
    size = value["size_bytes"]
    volume = value["volume_serial_number"]
    file_id = value["file_id_128"]
    roles = value["roles"]
    if (
        type(final_path) is not str
        or not Path(final_path).is_absolute()
        or type(digest) is not str
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or type(size) is not int
        or size <= 0
        or type(volume) is not int
        or volume <= 0
        or type(file_id) is not str
        or len(file_id) != 32
        or file_id == "0" * 32
        or any(character not in "0123456789abcdef" for character in file_id)
        or value["reparse_ancestor_count"] != 0
        or type(roles) is not list
        or not roles
        or roles != sorted(set(roles))
        or any(type(role) is not str or not role for role in roles)
    ):
        raise SupervisorError("runtime closure row value drifted")
    return value


def _hold_runtime_closure(
    owner: _CheckedOwners,
) -> tuple[tuple[_HeldFile, ...], _HeldFile, Mapping[str, Any]]:
    manifest_hold = owner.own(
        "runtime_closure_manifest",
        _HeldFile(
            path=RUNTIME_CLOSURE_PATH,
            expected_sha256=RUNTIME_CLOSURE_RAW_SHA256,
            expected_size=RUNTIME_CLOSURE_SIZE_BYTES,
        ),
    )
    if (
        manifest_hold.volume_serial_number
        != RUNTIME_CLOSURE_VOLUME_SERIAL_NUMBER
        or manifest_hold.file_id_128 != RUNTIME_CLOSURE_FILE_ID_128
    ):
        raise SupervisorError("runtime closure manifest FileId drifted")
    try:
        payload = json.loads(manifest_hold.raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("runtime closure manifest cannot be decoded") from exc
    rows = payload.get("runtime_records") if type(payload) is dict else None
    if (
        type(rows) is not list
        or payload.get("schema_version")
        != (
            "expected_pe.r8.r8.preimport_source_supervisor.static_child_"
            "runtime_closure.v2"
        )
        or payload.get("status")
        != "PASS_SOURCE_BUILT_FIXED_CHILD_RUNTIME_CLOSURE_NO_EXECUTION"
        or payload.get("runtime_record_count") != RUNTIME_RECORD_COUNT
        or len(rows) != RUNTIME_RECORD_COUNT
        or payload.get("runtime_records_semantic_sha256")
        != RUNTIME_RECORDS_SEMANTIC_SHA256
        or _sha256(_canonical(rows)) != RUNTIME_RECORDS_SEMANTIC_SHA256
        or payload.get("authority_generation_fresh_truth_heldout_signer_counts")
        != ZERO_COUNTS
        or payload.get("runtime_lock", {}).get("runtime_semantic_sha256")
        != "67eee77eb0991533cb0cfff7b1ed060db25e9fa568d49db9aa1a30e10f39f8c3"
        or payload.get("path_discovery", {}).get("dynamic_production_discovery")
        is not False
        or payload.get("path_discovery", {}).get("caller_selected_path_count") != 0
    ):
        raise SupervisorError("runtime closure manifest semantic drifted")
    held: list[_HeldFile] = []
    seen_paths: set[str] = set()
    executable: _HeldFile | None = None
    for index, raw_row in enumerate(rows):
        row = _runtime_row(raw_row)
        path = Path(str(row["final_path"]))
        key = os.path.normcase(str(path))
        if key in seen_paths:
            raise SupervisorError("runtime closure contains a duplicate final path")
        seen_paths.add(key)
        custody = owner.own(
            f"runtime[{index}]={path}",
            _HeldFile(
                path=path,
                expected_sha256=str(row["raw_sha256"]),
                expected_size=int(row["size_bytes"]),
            ),
        )
        if (
            custody.volume_serial_number != row["volume_serial_number"]
            or custody.file_id_128 != row["file_id_128"]
        ):
            raise SupervisorError(f"runtime closure FileId drifted: {path}")
        held.append(custody)
        if key == os.path.normcase(str(PINNED_VENV_PYTHON)):
            if executable is not None:
                raise SupervisorError("runtime closure venv executable is duplicated")
            executable = custody
    if executable is None:
        raise SupervisorError("runtime closure lacks the pinned venv executable")
    receipts = [item.verify() for item in held]
    return tuple(held), executable, {
        "status": "PASS_298_RUNTIME_FILES_HELD_BEFORE_CHILD_SPAWN",
        "runtime_record_count": len(held),
        "runtime_records_semantic_sha256": RUNTIME_RECORDS_SEMANTIC_SHA256,
        "runtime_manifest": manifest_hold.verify(),
        "runtime_receipts": receipts,
        "all_handles_still_open": True,
        "dynamic_production_discovery": False,
    }


class _StreamDigest:
    def __init__(self, stream: Any, label: str) -> None:
        self.stream = stream
        self.label = label
        self.digest = hashlib.sha256()
        self.size = 0
        self.captured = bytearray()
        self.capture_overflow = False
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, name=f"r8r8-{label}-drain")

    def _run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                self.digest.update(chunk)
                self.size += len(chunk)
                if len(self.captured) + len(chunk) <= CHILD_STREAM_CAPTURE_LIMIT_BYTES:
                    self.captured.extend(chunk)
                else:
                    self.capture_overflow = True
        except BaseException as exc:
            self.error = exc

    def start(self) -> None:
        self.thread.start()

    def finish(self, timeout: float) -> tuple[Mapping[str, Any], bytes]:
        self.thread.join(timeout)
        if (
            self.thread.is_alive()
            or self.error is not None
            or self.capture_overflow
        ):
            raise SupervisorError(f"bounded {self.label} drain failed") from self.error
        raw = bytes(self.captured)
        return (
            {
                "raw_sha256": self.digest.hexdigest(),
                "size_bytes": self.size,
                "capture_limit_bytes": CHILD_STREAM_CAPTURE_LIMIT_BYTES,
                "capture_overflow": False,
                "nonempty": bool(raw),
                "drain_thread_joined": True,
            },
            raw,
        )


def _parse_freezer_stdout(raw: bytes) -> Mapping[str, Any]:
    if (
        not raw
        or len(raw) > CHILD_STREAM_CAPTURE_LIMIT_BYTES
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\n" in raw[:-1]
    ):
        raise SupervisorError("freezer stdout is not one bounded canonical JSON line")
    try:
        payload = json.loads(raw[:-1])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("freezer stdout canonical receipt cannot be decoded") from exc
    if (
        type(payload) is not dict
        or _canonical(payload) + b"\n" != raw
        or payload.get("schema_version")
        != "expected_pe.r8.r8.static_one_shot_freeze_receipt.v2"
        or payload.get("status")
        != "FROZEN_NO_GO_PENDING_DIFFERENT_INDEPENDENT_POST_FREEZE_AUDIT"
        or payload.get("source_lock_raw_sha256") != R8_SOURCE_LOCK_RAW_SHA256
        or payload.get("held_source_record_count") != 119
        or payload.get("production_execution_authorized") is not False
        or payload.get("authority_generation_fresh_truth_signer_counts") != ZERO_COUNTS
    ):
        raise SupervisorError("freezer canonical receipt semantics drifted")
    return payload


def _capture_process_evidence(
    process: subprocess.Popen[bytes], held_executable: _HeldFile
) -> Mapping[str, Any]:
    raw_handle = getattr(process, "_handle", None)
    try:
        process_handle = int(raw_handle)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("Popen did not retain a held native process handle") from exc
    observed_pid = int(_KERNEL32.GetProcessId(wintypes.HANDLE(process_handle)))
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel_time = _FILETIME()
    user_time = _FILETIME()
    if observed_pid <= 0 or not _KERNEL32.GetProcessTimes(
        wintypes.HANDLE(process_handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise SupervisorError("held child process identity query failed")
    capacity = 32768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = wintypes.DWORD(capacity)
    if not _KERNEL32.QueryFullProcessImageNameW(
        wintypes.HANDLE(process_handle),
        0,
        buffer,
        ctypes.byref(length),
    ):
        raise SupervisorError(
            f"held child image path query failed: {ctypes.get_last_error()}"
        )
    image_path = Path(buffer.value[: length.value])
    executable_receipt = held_executable.verify()
    if (
        observed_pid != process.pid
        or _filetime_100ns(creation) <= 0
        or os.path.normcase(str(image_path))
        != os.path.normcase(str(PINNED_VENV_PYTHON))
        or os.path.normcase(str(_final_path(held_executable.handle)))
        != os.path.normcase(str(image_path))
    ):
        raise SupervisorError("held child process/image identity drifted")
    return {
        "pid": observed_pid,
        "creation_time_100ns": _filetime_100ns(creation),
        "image_final_path": str(image_path),
        "image_volume_serial_number": executable_receipt["volume_serial_number"],
        "image_file_id_128": executable_receipt["file_id_128"],
        "image_raw_sha256": executable_receipt["raw_sha256"],
        "image_size_bytes": executable_receipt["size_bytes"],
        "held_process_handle": True,
        "same_as_held_venv_executable": True,
    }


def _verify_process_evidence_after_exit(
    process: subprocess.Popen[bytes],
    before: Mapping[str, Any],
    held_executable: _HeldFile,
) -> Mapping[str, Any]:
    raw_handle = getattr(process, "_handle", None)
    try:
        process_handle = int(raw_handle)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("Popen process handle disappeared after exit") from exc
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel_time = _FILETIME()
    user_time = _FILETIME()
    observed_pid = int(_KERNEL32.GetProcessId(wintypes.HANDLE(process_handle)))
    if not _KERNEL32.GetProcessTimes(
        wintypes.HANDLE(process_handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise SupervisorError("held child process post-exit identity query failed")
    executable_receipt = held_executable.verify()
    if (
        process.poll() is None
        or observed_pid != before["pid"]
        or _filetime_100ns(creation) != before["creation_time_100ns"]
        or executable_receipt["volume_serial_number"]
        != before["image_volume_serial_number"]
        or executable_receipt["file_id_128"] != before["image_file_id_128"]
        or executable_receipt["raw_sha256"] != before["image_raw_sha256"]
    ):
        raise SupervisorError("held child process/image post-exit evidence drifted")
    return {
        "pid": observed_pid,
        "creation_time_100ns": _filetime_100ns(creation),
        "exit_time_100ns": _filetime_100ns(exit_time),
        "process_exited": True,
        "held_process_handle_still_queryable": True,
        "held_executable_identity_unchanged": True,
    }


def _run_child(
    command: tuple[str, ...],
    environment: Mapping[str, str],
    held_executable: _HeldFile,
) -> Mapping[str, Any]:
    if command != EXACT_CHILD_COMMAND:
        raise SupervisorError("child command is caller-controlled or drifted")
    process: subprocess.Popen[bytes] | None = None
    stdout_digest: _StreamDigest | None = None
    stderr_digest: _StreamDigest | None = None
    cleanup_failures: list[BaseException] = []
    started = time.monotonic_ns()
    timed_out = False
    try:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        if process.stdout is None or process.stderr is None:
            raise SupervisorError("child pipes were not created")
        process_evidence_before = _capture_process_evidence(
            process, held_executable
        )
        stdout_digest = _StreamDigest(process.stdout, "stdout")
        stderr_digest = _StreamDigest(process.stderr, "stderr")
        stdout_digest.start()
        stderr_digest.start()
        try:
            exit_code = process.wait(timeout=CHILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                process.wait(timeout=CHILD_CLEANUP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=CHILD_CLEANUP_TIMEOUT_SECONDS)
            raise SupervisorError("fixed freezer child exceeded its global deadline")
        stdout_receipt, stdout_raw = stdout_digest.finish(
            CHILD_CLEANUP_TIMEOUT_SECONDS
        )
        stderr_receipt, _stderr_raw = stderr_digest.finish(
            CHILD_CLEANUP_TIMEOUT_SECONDS
        )
        completed = time.monotonic_ns()
        if exit_code != 0:
            raise SupervisorError(f"fixed freezer child exited nonzero: {exit_code}")
        child_freezer_receipt = _parse_freezer_stdout(stdout_raw)
        process_evidence_after = _verify_process_evidence_after_exit(
            process,
            process_evidence_before,
            held_executable,
        )
        return {
            "status": "PASS_FIXED_FREEZER_CHILD_EXIT_ZERO",
            "exact_command": list(command),
            "close_fds": True,
            "global_deadline_seconds": CHILD_TIMEOUT_SECONDS,
            "timed_out": False,
            "exit_code": exit_code,
            "pid": process.pid,
            "started_monotonic_ns": started,
            "completed_monotonic_ns": completed,
            "stdout": stdout_receipt,
            "stderr": stderr_receipt,
            "stderr_nonempty": stderr_receipt["nonempty"],
            "child_freezer_receipt": child_freezer_receipt,
            "held_process_evidence": process_evidence_before,
            "held_process_evidence_after_exit": process_evidence_after,
            "held_process_evidence_after_exit_match": True,
        }
    finally:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=CHILD_CLEANUP_TIMEOUT_SECONDS)
            except BaseException as exc:
                cleanup_failures.append(exc)
        for stream in (
            None if process is None else process.stdout,
            None if process is None else process.stderr,
        ):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as exc:
                    cleanup_failures.append(exc)
        if cleanup_failures:
            raise SupervisorError(
                f"{len(cleanup_failures)} child cleanup operation(s) failed"
            ) from cleanup_failures[0]
        if timed_out and process is not None and process.poll() is None:
            raise SupervisorError("timed-out child remained active")


def main() -> int:
    owners = _CheckedOwners()
    primary: BaseException | None = None
    receipt: dict[str, Any] | None = None
    try:
        activation = _require_stub_activation(owners)
        environment_receipt = _require_no_python_environment()
        held_sources, source_before = _hold_fixed_closure(owners)
        held_runtime, held_executable, runtime_before = _hold_runtime_closure(
            owners
        )
        child_prefix = owners.own(
            "child_pycache_prefix",
            _HeldCreatedDirectory(
                parent=PROJECT_ROOT / "build",
                child_name=CHILD_PYCACHE_PREFIX.name,
            ),
        )
        if child_prefix.path != CHILD_PYCACHE_PREFIX:
            raise SupervisorError("fixed child pycache prefix identity drifted")
        clean_environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("PYTHON")
        }
        child = _run_child(
            EXACT_CHILD_COMMAND,
            clean_environment,
            held_executable,
        )
        prefix_receipt = dict(child_prefix.verify())
        source_after = [item.verify() for item in held_sources]
        if source_after != source_before["records"]:
            raise SupervisorError("119 held source receipts changed after child exit")
        runtime_after = [item.verify() for item in held_runtime]
        if runtime_after != runtime_before["runtime_receipts"]:
            raise SupervisorError("298 held runtime receipts changed after child exit")
        receipt = {
            "schema_version": "expected_pe.r8.r8.preimport_source_supervisor.receipt.v2",
            "status": (
                "PASS_FIXED_FREEZER_EXIT_SOURCE_RUNTIME_DACL_PROCESS_"
                "CONTINUITY_NO_AUTHORITY"
            ),
            "activation": activation,
            "source_before": source_before,
            "source_after_records_semantic_sha256": _sha256(
                _canonical(
                    [
                        [row["relative_path"], row["raw_sha256"], row["size_bytes"]]
                        for row in source_after
                    ]
                )
            ),
            "source_before_after_file_id_hash_continuity": True,
            "runtime_before": runtime_before,
            "runtime_after_records_semantic_sha256": (
                RUNTIME_RECORDS_SEMANTIC_SHA256
            ),
            "runtime_before_after_file_id_hash_continuity": True,
            "child_pycache_prefix": prefix_receipt,
            "child": child,
            "environment": environment_receipt,
            "supervisor_claim_identity_consumed_no_retry": True,
            "child_prefix_identity_consumed_no_retry": True,
            "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
            "authority_minted": False,
        }
    except BaseException as exc:
        primary = exc
    owners.close(primary)
    if receipt is None:
        raise SupervisorError("supervisor ended without a terminal receipt")
    receipt["cleanup"] = {
        "status": "PASS_ALL_SOURCE_HANDLE_CLOSES_ATTEMPTED",
        "closed_owner_count": len(owners.closed_labels),
        "close_failure_count": 0,
    }
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    if "_STUB_SOURCE_HANDLE" not in globals():
        raise SystemExit("DENIED_DIRECT_PATH_INVOCATION_REQUIRES_AUDITED_STDLIB_C_STUB")
    raise SystemExit(main())
