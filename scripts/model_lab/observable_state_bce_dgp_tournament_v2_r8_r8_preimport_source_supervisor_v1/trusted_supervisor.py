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
    "preimport_source_supervisor_v1"
)
SUPERVISOR_PATH = SCRIPT_ROOT / "trusted_supervisor.py"
MANIFEST_PATH = SCRIPT_ROOT / "SOURCE_CLOSURE_MANIFEST.json"
MANIFEST_RAW_SHA256 = "b2d51e5885f6ef1e48c35dcd3b890edab21a1fc9c3bd9d8968a81416bacf6f0a"
MANIFEST_SIZE_BYTES = 5805
R8_SOURCE_LOCK_RAW_SHA256 = "3a7ce804da20c1acfad5812acd5789693a291fbf8eb45e7cd42958500fbc53b6"
RECORDS_119_SEMANTIC_SHA256 = (
    "192788eff7e396bce7226e94748a4f7313fc7cb8965434a45d51067ed2ebc442"
)
PINNED_VENV_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_BASE_PYTHON = Path(r"C:\Users\minsu\anaconda3\envs\myenv\python.exe")
SUPERVISOR_CLAIM_PREFIX = PROJECT_ROOT / "build" / (
    "pc_r8r8_preimport_source_supervisor_actual_once_20260823"
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
                | SYNCHRONIZE,
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


def _require_stub_activation() -> Mapping[str, Any]:
    source_handle = globals().get("_STUB_SOURCE_HANDLE")
    claim_handle = globals().get("_STUB_CLAIM_HANDLE")
    stub_sha = globals().get("_STUB_RAW_SHA256")
    expected_source_sha = globals().get("_STUB_SOURCE_RAW_SHA256")
    expected_source_volume = globals().get("_STUB_SOURCE_VOLUME_SERIAL_NUMBER")
    expected_source_file_id = globals().get("_STUB_SOURCE_FILE_ID_128")
    expected_claim_volume = globals().get("_STUB_CLAIM_VOLUME_SERIAL_NUMBER")
    expected_claim_file_id = globals().get("_STUB_CLAIM_FILE_ID_128")
    if (
        type(source_handle) is not int
        or type(claim_handle) is not int
        or type(stub_sha) is not str
        or type(expected_source_sha) is not str
        or type(expected_source_volume) is not int
        or type(expected_source_file_id) is not str
        or type(expected_claim_volume) is not int
        or type(expected_claim_file_id) is not str
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
    if (
        _sha256(stub_raw) != stub_sha
        or _sha256(source_raw) != expected_source_sha
        or source_identity != (expected_source_volume, expected_source_file_id)
        or os.path.normcase(str(_final_path(source_handle)))
        != os.path.normcase(str(SUPERVISOR_PATH))
        or source_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
        or source_tag != 0
        or claim_identity != (expected_claim_volume, expected_claim_file_id)
        or not claim_attributes & FILE_ATTRIBUTE_DIRECTORY
        or claim_attributes & FILE_ATTRIBUTE_REPARSE_POINT
        or claim_tag != 0
        or os.path.normcase(str(_final_path(claim_handle)))
        != os.path.normcase(str(SUPERVISOR_CLAIM_PREFIX))
    ):
        raise SupervisorError("held stub/supervisor/claim activation identity drifted")
    return {
        "stub_raw_sha256": stub_sha,
        "supervisor_raw_sha256": expected_source_sha,
        "supervisor_volume_serial_number": expected_source_volume,
        "supervisor_file_id_128": expected_source_file_id,
        "supervisor_final_path": str(SUPERVISOR_PATH),
        "supervisor_claim_volume_serial_number": expected_claim_volume,
        "supervisor_claim_file_id_128": expected_claim_file_id,
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
        != "expected_pe.r8.r8.preimport_source_supervisor.closure_manifest.v1"
        or manifest.get("r8_source_lock_raw_sha256") != R8_SOURCE_LOCK_RAW_SHA256
        or manifest.get("records_119_semantic_sha256")
        != RECORDS_119_SEMANTIC_SHA256
        or manifest.get("authority_generation_fresh_truth_signer_counts") != ZERO_COUNTS
    ):
        raise SupervisorError("held closure manifest semantic drifted")
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


def _run_child(command: tuple[str, ...], environment: Mapping[str, str]) -> Mapping[str, Any]:
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
    activation = _require_stub_activation()
    environment_receipt = _require_no_python_environment()
    owners = _CheckedOwners()
    primary: BaseException | None = None
    receipt: dict[str, Any] | None = None
    try:
        held_sources, source_before = _hold_fixed_closure(owners)
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
        child = _run_child(EXACT_CHILD_COMMAND, clean_environment)
        prefix_receipt = dict(child_prefix.verify())
        source_after = [item.verify() for item in held_sources]
        if source_after != source_before["records"]:
            raise SupervisorError("119 held source receipts changed after child exit")
        receipt = {
            "schema_version": "expected_pe.r8.r8.preimport_source_supervisor.receipt.v1",
            "status": "PASS_FIXED_FREEZER_EXIT_SOURCE_CONTINUITY_NO_AUTHORITY",
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
            "child_pycache_prefix": prefix_receipt,
            "child": child,
            "environment": environment_receipt,
            "supervisor_claim_identity_consumed_no_retry": True,
            "child_prefix_identity_consumed_no_retry": True,
            "authority_generation_fresh_truth_signer_counts": ZERO_COUNTS,
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
