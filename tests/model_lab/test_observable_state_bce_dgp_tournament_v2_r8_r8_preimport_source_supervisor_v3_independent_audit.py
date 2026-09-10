from __future__ import annotations

import ast
import ctypes
import hashlib
import json
import os
import stat
from ctypes import wintypes
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3"
)
SUPERVISOR = SCRIPT_ROOT / "trusted_supervisor.py"
MANIFEST = SCRIPT_ROOT / "SOURCE_CLOSURE_MANIFEST.json"
RUNTIME = SCRIPT_ROOT / "STATIC_CHILD_RUNTIME_CLOSURE.json"
TEMPLATE = SCRIPT_ROOT / "STDLIB_LAUNCH_STUB_TEMPLATE.txt"
R7_LOCK = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)
CLAIM = PROJECT_ROOT / "build/pc_r8r8_preimport_source_supervisor_v3_actual_once_20260823"
PYCACHE = PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822"
FINAL = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
EXPECTED = {
    "manifest": (
        "09848b168eb261fd0b6e3de8944ef2c96cb314e33f2b0ae92b26066e533215c9",
        5612,
    ),
    "runtime": (
        "2aa3ff6edd53d8ebfdcb6a55b63a3a16d25e185e71acd2a3b9b8c86e6a1aeec2",
        842184,
    ),
    "supervisor": (
        "e8f656ae4fb0d883f38c4ff4428cf1d58a0f4e596974229955cb05134fb81f2f",
        100124,
    ),
    "template": (
        "c1be8402881be09fa4365016983c6253da9d77e93cd4a35db53a4d7bc0dd49c1",
        8092,
    ),
}

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
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


def _kernel32() -> ctypes.WinDLL:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


KERNEL32 = _kernel32()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json(raw: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise AssertionError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def _identity(path: Path, *, directory: bool) -> tuple[int, str]:
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    handle = KERNEL32.CreateFileW(str(path), 0x80, 1, None, 3, flags, None)
    assert handle != INVALID_HANDLE_VALUE, (path, ctypes.get_last_error())
    held = int(handle)
    try:
        info = _FILE_ID_INFO()
        assert KERNEL32.GetFileInformationByHandleEx(
            wintypes.HANDLE(held),
            FILE_ID_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        return (
            int(info.VolumeSerialNumber),
            bytes(info.FileId.Identifier).hex(),
        )
    finally:
        assert KERNEL32.CloseHandle(wintypes.HANDLE(held))


def _child_inventory(path: Path) -> list[list[object]]:
    rows: list[list[object]] = []
    for child in sorted(
        path.iterdir(),
        key=lambda item: (item.name.casefold(), item.name),
    ):
        metadata = os.lstat(child)
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse = stat.S_ISLNK(metadata.st_mode) or bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)
        kind = (
            "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "file"
            if stat.S_ISREG(metadata.st_mode)
            else "other"
        )
        volume, file_id = _identity(child, directory=kind == "directory")
        rows.append([child.name, kind, reparse, volume, file_id])
    return rows


def test_independent_raw_pins_and_all_actual_identities_are_unspent() -> None:
    for name, path in (
        ("manifest", MANIFEST),
        ("runtime", RUNTIME),
        ("supervisor", SUPERVISOR),
        ("template", TEMPLATE),
    ):
        raw = path.read_bytes()
        assert (_sha(raw), len(raw)) == EXPECTED[name]
    assert not CLAIM.exists()
    assert not PYCACHE.exists()
    assert not FINAL.exists()
    assert not Path(f"{FINAL}.staging").exists()


def test_independent_119_source_closure_is_live_and_exact() -> None:
    manifest = _strict_json(MANIFEST.read_bytes())
    r7_raw = R7_LOCK.read_bytes()
    r7 = _strict_json(r7_raw)
    assert isinstance(manifest, dict) and isinstance(r7, dict)
    r7_record = manifest["r7_source_lock_record"]
    assert r7_record == [
        str(R7_LOCK.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        _sha(r7_raw),
        len(r7_raw),
    ]
    rows = sorted(
        [
            *r7["source_sha256"],
            *manifest["r8_delta_rows"],
            manifest["outer_bootstrap_record"],
            r7_record,
        ]
    )
    assert len(rows) == 119
    assert len({row[0] for row in rows}) == 119
    assert _sha(_canonical(rows)) == manifest["records_119_semantic_sha256"]
    for relative, digest, size in rows:
        raw = (PROJECT_ROOT / relative).read_bytes()
        assert (_sha(raw), len(raw)) == (digest, size)


def test_independent_2265_file_and_130_directory_closure_is_live() -> None:
    payload = _strict_json(RUNTIME.read_bytes())
    assert isinstance(payload, dict)
    files = payload["runtime_records"]
    directories = payload["directory_records"]
    assert len(files) == payload["runtime_record_count"] == 2265
    assert len(directories) == payload["directory_record_count"] == 130
    assert _sha(_canonical(files)) == payload["runtime_records_semantic_sha256"]
    assert _sha(_canonical(directories)) == payload["directory_records_semantic_sha256"]
    paths: set[str] = set()
    identities: set[tuple[int, str]] = set()
    for row in files:
        path = Path(row["final_path"])
        key = os.path.normcase(str(path))
        assert key not in paths
        paths.add(key)
        raw = path.read_bytes()
        assert (_sha(raw), len(raw)) == (row["raw_sha256"], row["size_bytes"])
        identity = _identity(path, directory=False)
        assert identity == (row["volume_serial_number"], row["file_id_128"])
        assert identity not in identities
        identities.add(identity)
    for row in directories:
        path = Path(row["final_path"])
        assert _identity(path, directory=True) == (
            row["volume_serial_number"],
            row["file_id_128"],
        )
        if row["protection_required"]:
            children = _child_inventory(path)
            assert len(children) == row["child_entry_count"]
            assert _sha(_canonical(children)) == row["child_entries_semantic_sha256"]
            assert {
                os.path.normcase(str(path / child[0])) for child in children if child[1] == "file"
            } <= paths
    assert payload["absent_paths"] == [r"C:\Users\minsu\anaconda3\envs\myenv\python310.zip"]
    assert not Path(payload["absent_paths"][0]).exists()


def test_independent_supervisor_ast_and_boundary_claims_are_consistent() -> None:
    source = SUPERVISOR.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "research" not in imported
    assert "sys.path" not in source
    for required in (
        "D:P(A;;0x1200a9;;;OW)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)",
        "CREATE_SUSPENDED",
        "AssignProcessToJobObject",
        "NtResumeProcess",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "EXPECTED_JOB_TOTAL_PROCESSES = 3",
        "FIXED_CHILD_ENVIRONMENT",
        '"authority_minted": False',
    ):
        assert required in source
    assert "dynamic_production_discovery" in source
    assert "caller_selected_path_count" in source


def test_independent_system32_write_and_dacl_access_is_denied() -> None:
    target = Path(r"C:\Windows\System32\conhost.exe")
    for requested in (0x40000000, 0x00040000, 0x00010000):
        handle = KERNEL32.CreateFileW(
            str(target),
            requested,
            1,
            None,
            3,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        assert handle == INVALID_HANDLE_VALUE
        assert ctypes.get_last_error() in {5, 32}
