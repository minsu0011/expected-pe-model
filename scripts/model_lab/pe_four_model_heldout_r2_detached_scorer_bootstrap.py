"""Stdlib-only external held-byte bootstrap for the R2 heldout scorer.

This file deliberately remains outside the scorer's pinned source closure.  It opens
the caller-selected scorer launcher with Windows sharing that permits reads only,
verifies the exact bytes through that still-open handle, and executes those bytes in
the same process.  It never opens the activation, vault, or truth artifacts.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import sys
from typing import Any


_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_LAUNCHER_BYTES = 16 * 1024 * 1024


class DetachedScorerBootstrapError(RuntimeError):
    """Raised before scorer execution when the external trust boundary differs."""


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    )


def _kernel32() -> Any:
    if os.name != "nt":
        raise DetachedScorerBootstrapError("held-byte bootstrap requires Windows")
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    library.CreateFileW.restype = wintypes.HANDLE
    library.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    library.GetFileInformationByHandleEx.restype = wintypes.BOOL
    library.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    library.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    library.GetFileSizeEx.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_longlong),
    )
    library.GetFileSizeEx.restype = wintypes.BOOL
    library.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    library.ReadFile.restype = wintypes.BOOL
    library.CloseHandle.argtypes = (wintypes.HANDLE,)
    library.CloseHandle.restype = wintypes.BOOL
    return library


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DetachedScorerBootstrapError(f"{label} is not lowercase SHA-256")
    return value


def _path_key(value: str | Path) -> str:
    normalized = os.path.normcase(os.path.abspath(os.fspath(value)))
    if normalized.startswith("\\\\?\\UNC\\"):
        normalized = "\\\\" + normalized[8:]
    elif normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return normalized


def _final_path(handle: int) -> str:
    library = _kernel32()
    size = library.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0)
    if size <= 0:
        raise DetachedScorerBootstrapError(
            f"launcher final-path query failed: {ctypes.get_last_error()}"
        )
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = library.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buffer, len(buffer), 0
    )
    if written <= 0 or written >= len(buffer):
        raise DetachedScorerBootstrapError(
            f"launcher final-path read failed: {ctypes.get_last_error()}"
        )
    return buffer.value


def _read_held_bytes(handle: int) -> bytes:
    library = _kernel32()
    size = ctypes.c_longlong()
    if not library.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
        raise DetachedScorerBootstrapError(
            f"launcher size query failed: {ctypes.get_last_error()}"
        )
    if size.value <= 0 or size.value > _MAX_LAUNCHER_BYTES:
        raise DetachedScorerBootstrapError("launcher byte size is outside the trust bound")
    remaining = int(size.value)
    chunks: list[bytes] = []
    while remaining:
        requested = min(remaining, _READ_CHUNK_BYTES)
        buffer = ctypes.create_string_buffer(requested)
        received = wintypes.DWORD()
        if not library.ReadFile(
            wintypes.HANDLE(handle),
            buffer,
            requested,
            ctypes.byref(received),
            None,
        ):
            raise DetachedScorerBootstrapError(
                f"launcher held-byte read failed: {ctypes.get_last_error()}"
            )
        if received.value <= 0 or received.value > requested:
            raise DetachedScorerBootstrapError("launcher held-byte read was truncated")
        chunks.append(buffer.raw[: received.value])
        remaining -= received.value
    raw = b"".join(chunks)
    if len(raw) != size.value:
        raise DetachedScorerBootstrapError("launcher held-byte size drifted")
    return raw


def _close_handle(handle: int) -> None:
    if not _kernel32().CloseHandle(wintypes.HANDLE(handle)):
        raise DetachedScorerBootstrapError(
            f"launcher held handle cleanup failed: {ctypes.get_last_error()}"
        )


def _hold_launcher(path: Path, *, expected_sha256: str) -> tuple[int, bytes, Path]:
    expected = _sha256(expected_sha256, label="launcher raw hash")
    absolute = Path(os.path.abspath(os.fspath(path)))
    library = _kernel32()
    handle_value = library.CreateFileW(
        str(absolute),
        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        # Omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE blocks writes, deletes, and
        # renames until execution has ended and this handle is closed.
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    handle = int(handle_value or 0)
    if handle in (0, _INVALID_HANDLE_VALUE):
        raise DetachedScorerBootstrapError(
            f"launcher held-open failed: {absolute}: {ctypes.get_last_error()}"
        )
    try:
        attributes = _FileAttributeTagInfo()
        if not library.GetFileInformationByHandleEx(
            wintypes.HANDLE(handle),
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
        ):
            raise DetachedScorerBootstrapError(
                f"launcher attribute query failed: {ctypes.get_last_error()}"
            )
        if (
            attributes.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
            or attributes.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or attributes.reparse_tag != 0
        ):
            raise DetachedScorerBootstrapError(
                "launcher is a directory or reparse point"
            )
        if _path_key(_final_path(handle)) != _path_key(absolute):
            raise DetachedScorerBootstrapError("launcher final path drifted")
        raw = _read_held_bytes(handle)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise DetachedScorerBootstrapError("launcher held-byte hash drifted")
        # Recheck the name after reading.  The restrictive share mode makes a successful
        # rename impossible, but this keeps the invariant explicit and fail-closed.
        if _path_key(_final_path(handle)) != _path_key(absolute):
            raise DetachedScorerBootstrapError("launcher final path drifted after read")
        return handle, raw, absolute
    except BaseException:
        _close_handle(handle)
        raise


def _require_runtime() -> Path:
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or not sys.dont_write_bytecode
    ):
        raise DetachedScorerBootstrapError(
            "bootstrap requires exact python -I -S -B -E invocation"
        )
    prefix_value = sys.pycache_prefix
    xoption = getattr(sys, "_xoptions", {}).get("pycache_prefix")
    if (
        type(prefix_value) is not str
        or type(xoption) is not str
        or not os.path.isabs(prefix_value)
        or _path_key(prefix_value) != _path_key(xoption)
        or "heldout_eval_pycache_absent_" not in Path(prefix_value).name
        or os.path.lexists(prefix_value)
    ):
        raise DetachedScorerBootstrapError(
            "bootstrap requires one caller-supplied new absent pycache prefix"
        )
    return Path(prefix_value)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="External held-byte bootstrap for one-shot R2 heldout scoring"
    )
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--launcher-raw-sha256", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--activation", required=True)
    parser.add_argument("--activation-raw-sha256", required=True)
    return parser


def _scorer_argv(
    *, launcher: Path, repository_root: str, activation: str, activation_raw_sha256: str
) -> list[str]:
    if not repository_root or not activation:
        raise DetachedScorerBootstrapError(
            "repository root and activation arguments must be nonempty"
        )
    return [
        str(launcher),
        "--repository-root",
        repository_root,
        "--activation",
        activation,
        "--activation-raw-sha256",
        _sha256(activation_raw_sha256, label="activation raw hash"),
    ]


def _launch_held(
    *,
    launcher: Path,
    launcher_raw_sha256: str,
    repository_root: str,
    activation: str,
    activation_raw_sha256: str,
) -> dict[str, object]:
    handle, held_raw, absolute = _hold_launcher(
        launcher, expected_sha256=launcher_raw_sha256
    )
    original_argv = sys.argv
    namespace: dict[str, object] = {
        "__file__": str(absolute),
        "__name__": "__main__",
        "__package__": None,
        "__cached__": None,
        "__spec__": None,
        "_HELDOUT_VERIFIED_LAUNCHER_RAW_SHA256": launcher_raw_sha256,
        "_HELDOUT_VERIFIED_LAUNCHER_HANDLE": handle,
    }
    try:
        sys.argv = _scorer_argv(
            launcher=absolute,
            repository_root=repository_root,
            activation=activation,
            activation_raw_sha256=activation_raw_sha256,
        )
        exec(compile(held_raw, str(absolute), "exec"), namespace, namespace)
        return namespace
    finally:
        sys.argv = original_argv
        _close_handle(handle)


def main() -> int:
    _require_runtime()
    arguments = _argument_parser().parse_args()
    _launch_held(
        launcher=arguments.launcher,
        launcher_raw_sha256=_sha256(
            arguments.launcher_raw_sha256, label="launcher raw hash"
        ),
        repository_root=arguments.repository_root,
        activation=arguments.activation,
        activation_raw_sha256=_sha256(
            arguments.activation_raw_sha256, label="activation raw hash"
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
