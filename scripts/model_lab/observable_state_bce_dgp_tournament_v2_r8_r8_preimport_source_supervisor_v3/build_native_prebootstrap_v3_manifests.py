"""Derive deterministic line manifests for the managed pre-Python bootstrap.

This is a build-time tool only.  It does not mint authority, execute the
freezer, or read fresh/truth/heldout data.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from ctypes import wintypes
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
V5_ROOT = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3"
)
SOURCE_MANIFEST = V5_ROOT / "SOURCE_CLOSURE_MANIFEST_V5.json"
RUNTIME_MANIFEST = V5_ROOT / "STATIC_CHILD_RUNTIME_CLOSURE.json"
R7_SOURCE_LOCK = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)
FILE_OUTPUT = Path(__file__).resolve().parent / "NATIVE_FILE_CLOSURE_V3.tsv"
DIRECTORY_OUTPUT = Path(__file__).resolve().parent / "NATIVE_DIRECTORY_CLOSURE_V3.tsv"

SOURCE_MANIFEST_SHA256 = "9c082d0247e19b1dd9e865765a2907e3171ae2aebc74ea9dd05d34167595f9c4"
RUNTIME_MANIFEST_SHA256 = "2aa3ff6edd53d8ebfdcb6a55b63a3a16d25e185e71acd2a3b9b8c86e6a1aeec2"
R7_SOURCE_LOCK_SHA256 = "9a23b46c5c8ec0c0f7eaf2b1a8300f96486675473f02432d146a5f1190036e5e"
ZERO_COUNTS = {
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
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ID_INFO_CLASS = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", _FILE_ID_128),
    ]


_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.CreateFileW.argtypes = (
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
)
_KERNEL32.CreateFileW.restype = wintypes.HANDLE
_KERNEL32.GetFileInformationByHandleEx.argtypes = (
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
)
_KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
_KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
_KERNEL32.CloseHandle.restype = wintypes.BOOL


class BuildError(RuntimeError):
    """Raised when the pinned upstream closure drifts."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_exact(path: Path, digest: str) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    if _sha256(raw) != digest:
        raise BuildError(f"pinned upstream bytes drifted: {path}")
    payload = json.loads(raw)
    if type(payload) is not dict:
        raise BuildError(f"upstream JSON root drifted: {path}")
    return raw, payload


def _file_identity(path: Path) -> tuple[int, str]:
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
        raise BuildError(f"file identity open failed for {path}: {ctypes.get_last_error()}")
    try:
        information = _FILE_ID_INFO()
        if not _KERNEL32.GetFileInformationByHandleEx(
            handle,
            FILE_ID_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise BuildError(f"file identity query failed for {path}: {ctypes.get_last_error()}")
        return int(information.VolumeSerialNumber), bytes(information.FileId.Identifier).hex()
    finally:
        if not _KERNEL32.CloseHandle(handle):
            raise BuildError(f"file identity handle close failed: {ctypes.get_last_error()}")


def _source_rows() -> list[list[Any]]:
    _, source = _load_exact(SOURCE_MANIFEST, SOURCE_MANIFEST_SHA256)
    r7_raw, r7 = _load_exact(R7_SOURCE_LOCK, R7_SOURCE_LOCK_SHA256)
    if source.get("authority_generation_fresh_truth_heldout_signer_counts") != ZERO_COUNTS:
        raise BuildError("source closure sensitive counters drifted")
    r7_record = source.get("r7_source_lock_record")
    if (
        type(r7_record) is not list
        or r7_record[1:] != [R7_SOURCE_LOCK_SHA256, len(r7_raw)]
        or r7.get("source_sha256") is None
    ):
        raise BuildError("R7 source-lock bridge drifted")
    rows = [*r7["source_sha256"], *source["r8_delta_rows"]]
    rows.extend((source["outer_bootstrap_record"], r7_record))
    rows = sorted(rows, key=lambda row: row[0])
    if len(rows) != 119 or len({row[0] for row in rows}) != 119:
        raise BuildError("fixed 119-source universe drifted")
    return rows


def _file_bytes() -> bytes:
    _, runtime = _load_exact(RUNTIME_MANIFEST, RUNTIME_MANIFEST_SHA256)
    if runtime.get("authority_generation_fresh_truth_heldout_signer_counts") != ZERO_COUNTS:
        raise BuildError("runtime closure sensitive counters drifted")
    records: dict[str, tuple[str, str, int, int, str, str]] = {}
    for relative, digest, size in _source_rows():
        path = str((PROJECT_ROOT / relative).resolve(strict=True))
        volume, file_id = _file_identity(Path(path))
        records[path.casefold()] = (
            "SOURCE_119",
            path,
            size,
            volume,
            file_id,
            digest,
        )
    for row in runtime.get("runtime_records", ()):
        path = str(Path(row["final_path"]).resolve(strict=True))
        key = path.casefold()
        value = (
            "RUNTIME_2265",
            path,
            int(row["size_bytes"]),
            int(row["volume_serial_number"]),
            row["file_id_128"],
            row["raw_sha256"],
        )
        prior = records.get(key)
        if prior is not None:
            prior_digest = prior[-1]
            prior_size = prior[2]
            if prior_digest != value[-1] or prior_size != value[2]:
                raise BuildError(f"overlapping file record conflicts: {path}")
            continue
        records[key] = value
    support = (
        ("V5_SOURCE_MANIFEST", SOURCE_MANIFEST),
        ("V5_RUNTIME_MANIFEST", RUNTIME_MANIFEST),
        ("V5_STUB_TEMPLATE", V5_ROOT / "STDLIB_LAUNCH_STUB_TEMPLATE_V5.txt"),
        ("V5_SUPERVISOR", V5_ROOT / "trusted_supervisor_v5.py"),
    )
    for role, target in support:
        path = str(target.resolve(strict=True))
        raw = target.read_bytes()
        volume, file_id = _file_identity(target)
        key = path.casefold()
        value = (role, path, len(raw), volume, file_id, _sha256(raw))
        prior = records.get(key)
        if prior is not None and (prior[-1], prior[2]) != (value[-1], value[2]):
            raise BuildError(f"support file record conflicts: {path}")
        records[key] = value
    rows: list[str] = ["EXPECTED_PE_NATIVE_FILE_CLOSURE_V3"]
    for value in sorted(records.values(), key=lambda row: (row[1].casefold(), row[1])):
        role, path, size, volume, file_id, digest = value
        if any(character in path for character in "\t\r\n"):
            raise BuildError(f"path is not TSV-safe: {path}")
        rows.append(f"{role}\t{path}\t{digest}\t{size}\t{volume}\t{file_id}")
    return ("\n".join(rows) + "\n").encode("utf-8")


def _directory_bytes() -> bytes:
    _, runtime = _load_exact(RUNTIME_MANIFEST, RUNTIME_MANIFEST_SHA256)
    records = [
        row for row in runtime.get("directory_records", ()) if row["protection_required"] is True
    ]
    if len(records) != 129:
        raise BuildError("fixed protected-directory universe drifted")
    rows = ["EXPECTED_PE_NATIVE_DIRECTORY_CLOSURE_V3"]
    for row in sorted(
        records,
        key=lambda item: (item["final_path"].casefold(), item["final_path"]),
    ):
        path = row["final_path"]
        if any(character in path for character in "\t\r\n"):
            raise BuildError(f"path is not TSV-safe: {path}")
        rows.append(
            "\t".join(
                (
                    path,
                    str(row["volume_serial_number"]),
                    row["file_id_128"],
                    str(row["child_entry_count"]),
                    row["child_entries_semantic_sha256"],
                )
            )
        )
    return ("\n".join(rows) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-fixed-native-closure-v3-no-execution",
        action="store_true",
        required=True,
    )
    arguments = parser.parse_args()
    if arguments.write_fixed_native_closure_v3_no_execution is not True:
        raise BuildError("exact no-execution build flag is required")
    file_raw = _file_bytes()
    directory_raw = _directory_bytes()
    FILE_OUTPUT.write_bytes(file_raw)
    DIRECTORY_OUTPUT.write_bytes(directory_raw)
    print(
        json.dumps(
            {
                "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
                "directory_manifest": {
                    "path": str(DIRECTORY_OUTPUT),
                    "raw_sha256": _sha256(directory_raw),
                    "size_bytes": len(directory_raw),
                    "record_count": directory_raw.count(b"\n") - 1,
                },
                "file_manifest": {
                    "path": str(FILE_OUTPUT),
                    "raw_sha256": _sha256(file_raw),
                    "size_bytes": len(file_raw),
                    "record_count": file_raw.count(b"\n") - 1,
                },
                "status": "PASS_NATIVE_LINE_CLOSURES_BUILT_NO_EXECUTION_NO_AUTHORITY",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
