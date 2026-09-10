"""Build the fixed child-runtime closure without importing project code."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any, Final, Mapping


PROJECT_ROOT: Final = Path(
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
R7_SOURCE_LOCK: Final = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)
R7_SOURCE_LOCK_RAW_SHA256: Final = (
    "9a23b46c5c8ec0c0f7eaf2b1a8300f96486675473f02432d146a5f1190036e5e"
)
R7_SOURCE_LOCK_SIZE_BYTES: Final = 172140
RUNTIME_SEMANTIC_SHA256: Final = (
    "67eee77eb0991533cb0cfff7b1ed060db25e9fa568d49db9aa1a30e10f39f8c3"
)
BUILD_ARGUMENT: Final = "--emit-static-child-runtime-closure-no-execution"
ZERO_COUNTS: Final = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "heldout": 0,
    "signer": 0,
    "truth": 0,
}

GENERIC_READ = 0x80000000
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_ID_INFO_CLASS = 18
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class RuntimeClosureBuildError(RuntimeError):
    """Raised when fixed source-build runtime evidence drifts."""


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
        raise RuntimeClosureBuildError(
            f"CloseHandle failed: {ctypes.get_last_error()}"
        )


def _identity(handle: int) -> tuple[int, str]:
    info = _FILE_ID_INFO()
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        FILE_ID_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise RuntimeClosureBuildError(
            f"FileIdInfo query failed: {ctypes.get_last_error()}"
        )
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
    required = _KERNEL32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), None, 0, 0
    )
    if required == 0:
        raise RuntimeClosureBuildError("GetFinalPathName size query failed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = _KERNEL32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buffer, len(buffer), 0
    )
    if written == 0 or written >= len(buffer):
        raise RuntimeClosureBuildError("GetFinalPathName query failed")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _read_handle(handle: int) -> bytes:
    size = ctypes.c_longlong()
    if not _KERNEL32.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
        raise RuntimeClosureBuildError("GetFileSizeEx failed")
    if size.value < 0 or not _KERNEL32.SetFilePointerEx(
        wintypes.HANDLE(handle), 0, None, FILE_BEGIN
    ):
        raise RuntimeClosureBuildError("SetFilePointerEx failed")
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
        ) or read.value == 0:
            raise RuntimeClosureBuildError("ReadFile failed or returned premature EOF")
        chunks.append(buffer.raw[: read.value])
        remaining -= int(read.value)
    return b"".join(chunks)


def _exact_case_and_reparse_free(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        metadata = os.lstat(cursor)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0))
            & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise RuntimeClosureBuildError(f"runtime ancestry is reparse: {cursor}")
        with os.scandir(cursor) as stream:
            matches = [
                entry.name
                for entry in stream
                if entry.name.casefold() == part.casefold()
            ]
        if matches != [part]:
            raise RuntimeClosureBuildError(f"runtime path case drifted: {path}")
        cursor /= part
    metadata = os.lstat(absolute)
    if stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RuntimeClosureBuildError(f"runtime target is reparse: {path}")


def _observe(
    *, path: Path, expected_sha256: str, expected_size: int, roles: set[str]
) -> dict[str, Any]:
    _exact_case_and_reparse_free(path)
    handle = _KERNEL32.CreateFileW(
        str(path),
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise RuntimeClosureBuildError(
            f"runtime file custody open failed: {path}: {ctypes.get_last_error()}"
        )
    held = int(handle)
    primary: BaseException | None = None
    try:
        raw = _read_handle(held)
        attributes, tag = _attributes(held)
        volume, file_id = _identity(held)
        final = _final_path(held)
        if (
            len(raw) != expected_size
            or _sha256(raw) != expected_sha256
            or attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            or tag != 0
            or volume <= 0
            or len(file_id) != 32
            or file_id == "0" * 32
            or os.path.normcase(str(final)) != os.path.normcase(str(path))
        ):
            raise RuntimeClosureBuildError(f"runtime file identity drifted: {path}")
        return {
            "final_path": str(final),
            "file_id_128": file_id,
            "raw_sha256": expected_sha256,
            "reparse_ancestor_count": 0,
            "roles": sorted(roles),
            "size_bytes": expected_size,
            "volume_serial_number": volume,
        }
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            _close_checked(held)
        except BaseException as close_error:
            if primary is None:
                raise
            raise RuntimeClosureBuildError(
                "runtime observation failed and its handle close also failed"
            ) from close_error


def _candidate_rows(runtime: Mapping[str, Any]) -> list[tuple[Path, str, int, str]]:
    candidates: list[tuple[Path, str, int, str]] = []

    def add(spec: Mapping[str, Any], role: str, path: Path | None = None) -> None:
        target = Path(str(spec["path"])) if path is None else path
        digest = spec.get("raw_sha256")
        size = spec.get("size_bytes")
        if (
            type(digest) is not str
            or len(digest) != 64
            or type(size) is not int
            or size <= 0
        ):
            raise RuntimeClosureBuildError(f"runtime lock row malformed: {role}")
        candidates.append((target, digest, size, role))

    add(runtime["python_executable"], "VENV_EXECUTABLE")
    add(runtime["python_base_executable"], "BASE_EXECUTABLE")
    for name, spec in sorted(runtime["python_native_dlls"].items()):
        add(spec, f"PYTHON_NATIVE_DLL:{name}")
    site_packages = Path(str(runtime["site_packages_root"]))
    for distribution, spec in sorted(runtime["distributions"].items()):
        add(spec["record"], f"DISTRIBUTION_RECORD:{distribution}")
        for relative, native in sorted(spec["native_members"].items()):
            pure = PurePosixPath(relative)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise RuntimeClosureBuildError(
                    f"unsafe native-member relative path: {relative}"
                )
            add(
                native,
                f"DISTRIBUTION_NATIVE:{distribution}:{relative}",
                site_packages.joinpath(*pure.parts),
            )
    for module, spec in sorted(runtime["critical_module_origins"].items()):
        add(spec, f"CRITICAL_ORIGIN:{module}")
    return candidates


def build_payload() -> dict[str, Any]:
    source_raw = R7_SOURCE_LOCK.read_bytes()
    if (
        len(source_raw) != R7_SOURCE_LOCK_SIZE_BYTES
        or _sha256(source_raw) != R7_SOURCE_LOCK_RAW_SHA256
    ):
        raise RuntimeClosureBuildError("R7 SOURCE_LOCK raw bytes drifted")
    try:
        source_lock = json.loads(source_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeClosureBuildError("R7 SOURCE_LOCK cannot be decoded") from exc
    runtime = source_lock.get("runtime_lock")
    if (
        type(runtime) is not dict
        or runtime.get("schema_version")
        != "expected_pe.r7.qualification.runtime_lock.v1"
        or runtime.get("runtime_semantic_sha256") != RUNTIME_SEMANTIC_SHA256
        or tuple(sorted(runtime.get("distributions", ())))
        != (
            "joblib",
            "lightgbm",
            "numpy",
            "pandas",
            "pyyaml",
            "scikit-learn",
            "scipy",
            "statsmodels",
            "threadpoolctl",
        )
    ):
        raise RuntimeClosureBuildError("R7 runtime lock semantic drifted")
    deduped: dict[str, dict[str, Any]] = {}
    expected_by_key: dict[str, tuple[str, int]] = {}
    roles_by_key: dict[str, set[str]] = {}
    path_by_key: dict[str, Path] = {}
    for path, digest, size, role in _candidate_rows(runtime):
        absolute = Path(os.path.abspath(path))
        key = os.path.normcase(str(absolute))
        previous = expected_by_key.setdefault(key, (digest, size))
        if previous != (digest, size):
            raise RuntimeClosureBuildError(f"deduped runtime row disagrees: {path}")
        path_by_key[key] = absolute
        roles_by_key.setdefault(key, set()).add(role)
    for key in sorted(path_by_key):
        digest, size = expected_by_key[key]
        deduped[key] = _observe(
            path=path_by_key[key],
            expected_sha256=digest,
            expected_size=size,
            roles=roles_by_key[key],
        )
    rows = sorted(deduped.values(), key=lambda row: str(row["final_path"]).casefold())
    return {
        "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
        "path_discovery": {
            "caller_selected_path_count": 0,
            "dedupe_key": "NORMCASE_EXACT_FINAL_PATH",
            "dynamic_production_discovery": False,
            "source": "PINNED_R7_SOURCE_LOCK_RUNTIME_LOCK_ONLY",
        },
        "runtime_lock": {
            "distribution_count": 9,
            "runtime_semantic_sha256": RUNTIME_SEMANTIC_SHA256,
            "schema_version": "expected_pe.r7.qualification.runtime_lock.v1",
            "source_lock_raw_sha256": R7_SOURCE_LOCK_RAW_SHA256,
            "source_lock_size_bytes": R7_SOURCE_LOCK_SIZE_BYTES,
        },
        "runtime_record_count": len(rows),
        "runtime_records": rows,
        "runtime_records_semantic_sha256": _sha256(_canonical(rows)),
        "schema_version": (
            "expected_pe.r8.r8.preimport_source_supervisor.static_child_"
            "runtime_closure.v2"
        ),
        "status": "PASS_SOURCE_BUILT_FIXED_CHILD_RUNTIME_CLOSURE_NO_EXECUTION",
    }


def main() -> int:
    if sys.argv != [str(Path(__file__).resolve()), BUILD_ARGUMENT]:
        raise RuntimeClosureBuildError("exact source-build argument is required")
    python_controls = sorted(
        name for name in os.environ if name.upper().startswith("PYTHON")
    )
    if python_controls:
        raise RuntimeClosureBuildError(
            f"Python environment controls are forbidden: {python_controls}"
        )
    print(_canonical(build_payload()).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
