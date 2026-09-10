"""One-shot R3 post-generation adjudication using native Win32 file identity.

The frozen R3 auditor remains byte-immutable.  This program verifies and loads
that exact source, then replaces only its file-read and public-identity hooks.
All schema, geometry, order, hash, public/private-boundary, and vault-manifest
checks continue to execute in the frozen auditor.  The replacement reader gets
bytes, uint64 volume serial number, and the 128-bit file identifier from one
held Win32 handle that denies share-write and share-delete.

This is deliberately a create-new, one-invocation adjudication.  The output
root is claimed before any formal generation artifact is read.  A crash,
finding, or publication failure consumes the invocation and permits no retry.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import ntpath
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any


FORMAL_RUN_ID = "r3_20260824T134417"
ADJUDICATION_ID = "r3_native_fileidinfo_v1_20260824T134417"
PREUSE_AUTHORITY_RELATIVE = (
    f"build/pe_four_model_heldout_r3_native_identity_adjudication_authority_{FORMAL_RUN_ID}.json"
)
PREUSE_REVIEW_RELATIVE = (
    f"build/pe_four_model_heldout_r3_native_identity_adjudication_review_{FORMAL_RUN_ID}.json"
)
ADJUDICATION_OUTPUT_RELATIVE = (
    f"build/pe_four_model_heldout_r3_post_generation_native_identity_adjudication_{FORMAL_RUN_ID}"
)
CORRECTED_TEST_RELATIVE = (
    "tests/model_lab/test_pe_four_model_heldout_r3_post_generation_native_identity_adjudicator.py"
)
CORRECTED_AUDITOR_RELATIVE = (
    "scripts/model_lab/pe_four_model_heldout_r3_post_generation_native_identity_adjudicator.py"
)
EXECUTION_AUTHORITY_RELATIVE = (
    f"build/pe_four_model_heldout_execution_authority_{FORMAL_RUN_ID}.json"
)
PUBLIC_REPLAY_RELATIVE = f"outputs/model_zoo_pe_four_model_heldout_public_replay_{FORMAL_RUN_ID}"
VAULT_MANIFEST_RELATIVE = (
    f"outputs/.model_zoo_pe_four_model_heldout_vault_{FORMAL_RUN_ID}/VAULT_MANIFEST.json"
)
ORIGINAL_AUDITOR_RELATIVE = "scripts/model_lab/pe_four_model_heldout_r3_post_generation_audit.py"
ORIGINAL_AUDITOR_RAW_SHA256 = "479a82da82ced5a180624b4b4b403824b394d42bb87624dc8da90bbe7fd7cc10"
ORIGINAL_TEST_RELATIVE = "tests/model_lab/test_pe_four_model_heldout_r3_post_generation_audit.py"
ORIGINAL_TEST_RAW_SHA256 = "53d5a8cd3275d6c76ffc2a1bcb1680c92a904ed6ee070287bf70ce9ab5f5615e"
ORIGINAL_NO_GO_RELATIVE = (
    "build/pe_four_model_heldout_r3_post_generation_audit_"
    f"{FORMAL_RUN_ID}/R3_POST_GENERATION_AUDIT.json"
)
ORIGINAL_NO_GO_RAW_SHA256 = "bee089a842b8f09d316d6155d06f64d5eb5ebff61c40d9fc1b10d0fe801e5103"
ORIGINAL_NO_GO_SEMANTIC_SHA256 = "3a85aed4e3f0f478232111a3839b3f1557aa18a9c894b0d82699e1b67b1af7b5"
EXPECTED_EXECUTION_AUTHORITY_RAW_SHA256 = (
    "fda61ea7d041020dff30e62eb90730f681062d132f946a2ca840d226bc868cfe"
)
EXPECTED_EXECUTION_AUTHORITY_SEMANTIC_SHA256 = (
    "f0d79e7435a78f26171a43e2c46a038c2fd33907011e674d51bac29b72822bd9"
)
EXPECTED_GENERATION_PLAN_SEMANTIC_SHA256 = (
    "2390b49ec02cc330345c107f78b512fc2ee182fe4eee329e41d171d688d984f0"
)
EXPECTED_GENERATION_RECEIPT_RAW_SHA256 = (
    "2102ed765a33790f492f1e9a30e1c892504ff11f0ac2c581c9f80fcef1e1bbd0"
)
STORED_WIN32_VOLUME_SERIAL_NUMBER = 13325047249941796650
OBSERVED_PYTHON310_ST_DEV = 3960706858

AUTHORITY_SCHEMA = "expected_pe.four_model.r3_native_identity_adjudication_authority.v1"
AUTHORITY_STATUS = "GO_ONE_CORRECTED_POSTGEN_ADJUDICATION_ONLY"
REVIEW_SCHEMA = "expected_pe.four_model.r3_native_identity_adjudication_review.v1"
REVIEW_STATUS = "GO_PREUSE_INDEPENDENT_REVIEW_NO_BLOCKERS"
REPORT_SCHEMA = "expected_pe.four_model.r3_post_generation_native_identity_adjudication.v1"
GO_STATUS = "GO_R3_NATIVE_IDENTITY_ADJUDICATION_P0_0_P1_0_P2_0"
NO_GO_STATUS = "NO_GO_R3_NATIVE_IDENTITY_ADJUDICATION_TERMINAL_NO_RETRY"
CLAIM_SCHEMA = "expected_pe.four_model.r3_adjudication_invocation_claim.v1"
CLAIM_STATUS = "CONSUMED_SINGLE_ADJUDICATION_INVOCATION_BEFORE_FORMAL_READ"
REPORT_NAME = "R3_POST_GENERATION_NATIVE_IDENTITY_ADJUDICATION.json"
CLAIM_NAME = "ADJUDICATION_INVOCATION_CLAIM.json"
MAX_PATH_CHARS = 240

_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_BEGIN = 0
_FILE_BASIC_INFO_CLASS = 0
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ID_INFO_CLASS = 18
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class NativeIdentityError(RuntimeError):
    """A native identity operation failed closed."""


class _FileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FileIdInfo(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_ulonglong),
        ("file_id", _FileId128),
    )


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    )


class _FileBasicInfo(ctypes.Structure):
    _fields_ = (
        ("creation_time", ctypes.c_longlong),
        ("last_access_time", ctypes.c_longlong),
        ("last_write_time", ctypes.c_longlong),
        ("change_time", ctypes.c_longlong),
        ("file_attributes", wintypes.DWORD),
    )


class _FileStandardInfo(ctypes.Structure):
    _fields_ = (
        ("allocation_size", ctypes.c_longlong),
        ("end_of_file", ctypes.c_longlong),
        ("number_of_links", wintypes.DWORD),
        ("delete_pending", wintypes.BOOLEAN),
        ("directory", wintypes.BOOLEAN),
    )


class NativeFileInfo:
    """The exact identity and stability fields observed on one held handle."""

    __slots__ = (
        "volume_serial_number",
        "file_id_128",
        "size_bytes",
        "last_write_time",
        "change_time",
        "file_attributes",
        "number_of_links",
    )

    def __init__(
        self,
        *,
        volume_serial_number: int,
        file_id_128: bytes,
        size_bytes: int,
        last_write_time: int,
        change_time: int,
        file_attributes: int,
        number_of_links: int,
    ) -> None:
        self.volume_serial_number = volume_serial_number
        self.file_id_128 = file_id_128
        self.size_bytes = size_bytes
        self.last_write_time = last_write_time
        self.change_time = change_time
        self.file_attributes = file_attributes
        self.number_of_links = number_of_links

    def stability_tuple(self) -> tuple[int, bytes, int, int, int, int]:
        return (
            self.volume_serial_number,
            self.file_id_128,
            self.size_bytes,
            self.last_write_time,
            self.change_time,
            self.file_attributes,
        )


class ReadTelemetry:
    """Allowlist and aggregate counters; protected payload paths are never stored."""

    def __init__(
        self,
        *,
        authority_path: Path,
        public_root: Path,
        vault_manifest_path: Path,
    ) -> None:
        self.authority_path = _absolute(authority_path)
        self.public_root = _absolute(public_root)
        self.vault_manifest_path = _absolute(vault_manifest_path)
        self.authority_read_count = 0
        self.public_read_count = 0
        self.vault_manifest_read_count = 0
        self.other_read_count = 0
        self.unauthorized_read_attempt_count = 0
        self.public_paths: set[str] = set()
        self.all_identity_observations: set[tuple[int, bytes]] = set()

    def classify(self, path: Path) -> str:
        absolute = _absolute(path)
        if _path_key(absolute) == _path_key(self.authority_path):
            return "authority"
        if _path_key(absolute) == _path_key(self.vault_manifest_path):
            return "vault_manifest"
        try:
            common = os.path.commonpath((absolute, self.public_root))
        except ValueError:
            common = ""
        if _path_key(common) == _path_key(self.public_root):
            return "public"
        return "other"

    def authorize(self, path: Path) -> str:
        kind = self.classify(path)
        if kind == "other":
            self.unauthorized_read_attempt_count += 1
            raise NativeIdentityError("read path is outside the adjudication allowlist")
        return kind

    def record(self, path: Path, info: NativeFileInfo, *, kind: str) -> None:
        if kind != self.classify(path) or kind == "other":
            raise NativeIdentityError("read authorization classification changed")
        if kind == "authority":
            self.authority_read_count += 1
        elif kind == "public":
            self.public_read_count += 1
            self.public_paths.add(_path_key(_absolute(path)))
        elif kind == "vault_manifest":
            self.vault_manifest_read_count += 1
        else:
            self.other_read_count += 1
            raise NativeIdentityError("read path is outside the adjudication allowlist")
        self.all_identity_observations.add((info.volume_serial_number, info.file_id_128))

    def evidence(self) -> dict[str, Any]:
        return {
            "authority_native_read_count": self.authority_read_count,
            "public_native_read_count": self.public_read_count,
            "unique_public_path_count": len(self.public_paths),
            "vault_manifest_native_read_count": self.vault_manifest_read_count,
            "other_native_read_count": self.other_read_count,
            "unauthorized_read_attempt_count": (self.unauthorized_read_attempt_count),
            "allowlist_authorization_preceded_native_open": True,
            "protected_payload_directories_enumerated": False,
            "protected_payload_refs_resolved_or_statted": 0,
            "protected_payload_leaves_opened": 0,
            "truth_open_count": 0,
            "score_open_count": 0,
        }


def compact_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def semantic_sha256(value: Any) -> str:
    return sha256(compact_bytes(value))


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(path))


def _path_key(path: str | Path) -> str:
    text = str(path)
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return ntpath.normcase(ntpath.normpath(text))


def _kernel32() -> Any:
    if os.name != "nt":
        raise NativeIdentityError("native identity adjudication requires Windows")
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
    library.SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    library.SetFilePointerEx.restype = wintypes.BOOL
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


def _native_failure(operation: str) -> NativeIdentityError:
    return NativeIdentityError(f"{operation} failed closed: win32={ctypes.get_last_error()}")


def _query_identity(library: Any, handle: int) -> tuple[int, bytes]:
    information = _FileIdInfo()
    if not library.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _native_failure("FileIdInfo query")
    return (
        int(information.volume_serial_number),
        bytes(information.file_id.identifier),
    )


def _query_attributes(library: Any, handle: int) -> tuple[int, int]:
    information = _FileAttributeTagInfo()
    if not library.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _native_failure("FileAttributeTagInfo query")
    return int(information.file_attributes), int(information.reparse_tag)


def _query_basic(library: Any, handle: int) -> tuple[int, int, int]:
    information = _FileBasicInfo()
    if not library.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_BASIC_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _native_failure("FileBasicInfo query")
    return (
        int(information.last_write_time),
        int(information.change_time),
        int(information.file_attributes),
    )


def _query_standard(library: Any, handle: int) -> tuple[int, int, bool, bool]:
    information = _FileStandardInfo()
    if not library.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_STANDARD_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _native_failure("FileStandardInfo query")
    return (
        int(information.end_of_file),
        int(information.number_of_links),
        bool(information.delete_pending),
        bool(information.directory),
    )


def _final_path(library: Any, handle: int) -> str:
    required = int(library.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0))
    if required <= 0:
        raise _native_failure("final path size query")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        library.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), buffer, len(buffer), 0)
    )
    if written <= 0 or written >= len(buffer):
        raise _native_failure("final path query")
    return buffer.value


def _read_exact(library: Any, handle: int, expected_size: int) -> bytes:
    if expected_size < 0:
        raise NativeIdentityError("negative native file size")
    if not library.SetFilePointerEx(
        wintypes.HANDLE(handle), ctypes.c_longlong(0), None, _FILE_BEGIN
    ):
        raise _native_failure("held file seek")
    remaining = expected_size
    chunks: list[bytes] = []
    while remaining:
        requested = min(remaining, 1024 * 1024)
        buffer = ctypes.create_string_buffer(requested)
        count = wintypes.DWORD()
        if not library.ReadFile(
            wintypes.HANDLE(handle),
            buffer,
            requested,
            ctypes.byref(count),
            None,
        ):
            raise _native_failure("held file read")
        if count.value <= 0:
            raise NativeIdentityError("held file returned premature EOF")
        chunks.append(buffer.raw[: count.value])
        remaining -= int(count.value)
    probe = ctypes.create_string_buffer(1)
    count = wintypes.DWORD()
    if not library.ReadFile(wintypes.HANDLE(handle), probe, 1, ctypes.byref(count), None):
        raise _native_failure("held EOF probe")
    if count.value != 0:
        raise NativeIdentityError("held file grew during exact read")
    return b"".join(chunks)


def _snapshot(library: Any, handle: int) -> NativeFileInfo:
    volume, file_id = _query_identity(library, handle)
    attributes, reparse_tag = _query_attributes(library, handle)
    last_write, change_time, basic_attributes = _query_basic(library, handle)
    size, links, delete_pending, directory = _query_standard(library, handle)
    if attributes != basic_attributes:
        raise NativeIdentityError("native attribute queries disagree")
    if (
        directory
        or bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)
        or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
        or reparse_tag != 0
        or delete_pending
    ):
        raise NativeIdentityError("native handle is not an ordinary stable file")
    if len(file_id) != 16:
        raise NativeIdentityError("native FileId is not 128 bits")
    return NativeFileInfo(
        volume_serial_number=volume,
        file_id_128=file_id,
        size_bytes=size,
        last_write_time=last_write,
        change_time=change_time,
        file_attributes=attributes,
        number_of_links=links,
    )


def native_read(path: Path) -> tuple[bytes, NativeFileInfo]:
    """Read bytes and full identity from one handle held against writes/deletes."""

    absolute = _absolute(path)
    if len(str(absolute)) >= MAX_PATH_CHARS:
        raise NativeIdentityError("audited path is 240 characters or longer")
    library = _kernel32()
    handle = library.CreateFileW(
        str(absolute),
        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    numeric = int(handle or 0)
    if numeric in (0, _INVALID_HANDLE_VALUE):
        raise _native_failure("same-handle file open")
    primary_error: BaseException | None = None
    try:
        before = _snapshot(library, numeric)
        before_path = _final_path(library, numeric)
        if _path_key(before_path) != _path_key(absolute):
            raise NativeIdentityError("held final path differs from requested path")
        raw = _read_exact(library, numeric, before.size_bytes)
        after = _snapshot(library, numeric)
        after_path = _final_path(library, numeric)
        if before.stability_tuple() != after.stability_tuple():
            raise NativeIdentityError("file changed during same-handle audit read")
        if _path_key(after_path) != _path_key(absolute):
            raise NativeIdentityError("held final path changed during audit read")
        if len(raw) != after.size_bytes:
            raise NativeIdentityError("native read size differs from file size")
        return raw, after
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if not library.CloseHandle(wintypes.HANDLE(numeric)) and primary_error is None:
            raise _native_failure("same-handle close")


def producer_artifact_ref(path: Path, project: Path) -> dict[str, Any]:
    """Test/support helper matching the producer's FileIdInfo wire contract."""

    raw, info = native_read(path)
    return {
        "file_id_128": info.file_id_128.hex(),
        "raw_sha256": sha256(raw),
        "relative_path": path.relative_to(project).as_posix(),
        "size_bytes": len(raw),
        "volume_serial_number": info.volume_serial_number,
    }


def _load_frozen_auditor(project: Path) -> Any:
    source = project / ORIGINAL_AUDITOR_RELATIVE
    raw = source.read_bytes()
    if sha256(raw) != ORIGINAL_AUDITOR_RAW_SHA256:
        raise NativeIdentityError("frozen original auditor source hash drifted")
    name = "_r3_frozen_post_generation_auditor_479a82"
    module = type(sys)(name)
    module.__file__ = str(source)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = None
    sys.modules[name] = module
    try:
        code = compile(raw, str(source), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _patched_hooks(base: Any, telemetry: ReadTelemetry) -> tuple[Any, Any, Any]:
    def stable_read(path: Path, *, state: Any) -> tuple[bytes, NativeFileInfo]:
        absolute = _absolute(path)
        state.max_path_chars = max(state.max_path_chars, len(str(absolute)))
        state.require(
            len(str(absolute)) < MAX_PATH_CHARS,
            "PATH_LENGTH",
            "audited path is 240 characters or longer",
            "P1",
        )
        try:
            kind = telemetry.authorize(absolute)
            raw, info = native_read(absolute)
            telemetry.record(absolute, info, kind=kind)
        except NativeIdentityError as exc:
            raise base.AuditFailure("P0", "NATIVE_SAME_HANDLE_READ", str(exc)) from exc
        state.require(
            len(raw) == info.size_bytes,
            "FILE_SIZE",
            "file read size differs",
            "P1",
        )
        return raw, info

    def register_public(info: NativeFileInfo, *, state: Any) -> None:
        identity = (info.volume_serial_number, info.file_id_128)
        state.require(
            identity not in state.public_file_identities,
            "PUBLIC_HARDLINK",
            "public file identity alias detected",
        )
        state.public_file_identities.add(identity)

    def validate_ref(
        ref: Any,
        *,
        expected_relative_path: str,
        raw: bytes,
        info: NativeFileInfo,
        state: Any,
    ) -> None:
        state.require(
            type(ref) is dict and set(ref) == base.ARTIFACT_REF_FIELDS,
            "ARTIFACT_REF_SCHEMA",
            "public ArtifactRef schema differs",
            "P1",
        )
        state.require(
            ref["relative_path"] == expected_relative_path,
            "ARTIFACT_PATH",
            "public ArtifactRef path differs",
        )
        state.require(
            base._hex_sha(ref["raw_sha256"]),
            "ARTIFACT_SHA_FORMAT",
            "public ArtifactRef hash malformed",
            "P1",
        )
        state.require(
            ref["raw_sha256"] == base.sha256(raw),
            "ARTIFACT_SHA",
            "public ArtifactRef hash differs",
        )
        state.require(
            ref["size_bytes"] == len(raw),
            "ARTIFACT_SIZE",
            "public ArtifactRef size differs",
            "P1",
        )
        state.require(
            type(ref["volume_serial_number"]) is int
            and ref["volume_serial_number"] == info.volume_serial_number,
            "ARTIFACT_VOLUME",
            "public ArtifactRef native uint64 volume identity differs",
        )
        file_id = ref["file_id_128"]
        state.require(
            type(file_id) is str and base.FILE_ID_RE.fullmatch(file_id) is not None,
            "ARTIFACT_FILE_ID_FORMAT",
            "public ArtifactRef FileId malformed",
            "P1",
        )
        state.require(
            bytes.fromhex(file_id) == info.file_id_128,
            "ARTIFACT_FILE_ID",
            "public ArtifactRef native 128-bit FileId differs",
        )
        register_public(info, state=state)

    return stable_read, register_public, validate_ref


def run_corrected_base_audit(
    project: Path,
    *,
    run_id: str,
    execution_authority: Path,
    authority_semantic_sha256: str,
    authority_raw_sha256: str,
    public_replay_root: Path,
    vault_manifest_path: Path,
    telemetry: ReadTelemetry | None = None,
) -> tuple[dict[str, Any], ReadTelemetry]:
    """Execute every frozen check with only the three identity hooks replaced."""

    project = _absolute(project)
    base = _load_frozen_auditor(project)
    if telemetry is None:
        telemetry = ReadTelemetry(
            authority_path=execution_authority,
            public_root=public_replay_root,
            vault_manifest_path=vault_manifest_path,
        )
    replacements = _patched_hooks(base, telemetry)
    originals = (base.stable_read, base._register_public, base.validate_ref)
    base.stable_read, base._register_public, base.validate_ref = replacements
    try:
        report = base.run_audit(
            project,
            run_id=run_id,
            execution_authority=execution_authority,
            authority_semantic_sha256=authority_semantic_sha256,
            authority_raw_sha256=authority_raw_sha256,
            public_replay_root=public_replay_root,
            vault_manifest_path=vault_manifest_path,
        )
    finally:
        base.stable_read, base._register_public, base.validate_ref = originals
    if report.get("auditor_source_raw_sha256") != ORIGINAL_AUDITOR_RAW_SHA256:
        raise NativeIdentityError("frozen base-audit provenance differs")
    return report, telemetry


def _parse_pretty_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise NativeIdentityError(f"{label} is invalid JSON") from exc
    if type(value) is not dict or raw != pretty_bytes(value):
        raise NativeIdentityError(f"{label} is not canonical pretty JSON")
    return value


def _relative(path: Path, project: Path) -> str:
    try:
        return _absolute(path).relative_to(_absolute(project)).as_posix()
    except ValueError as exc:
        raise NativeIdentityError("adjudication path is outside project") from exc


def _read_exact_project_file(
    *,
    project: Path,
    supplied_path: Path,
    expected_relative: str,
    label: str,
) -> bytes:
    """Authorize one exact project-relative path before its native open/read."""

    if Path(expected_relative).is_absolute() or ".." in Path(expected_relative).parts:
        raise NativeIdentityError(f"{label} expected path contract is unsafe")
    expected = _absolute(project / Path(*expected_relative.split("/")))
    supplied = _absolute(supplied_path)
    if _path_key(supplied) != _path_key(expected):
        raise NativeIdentityError(f"{label} path differs from its exact scope")
    try:
        raw, _ = native_read(expected)
    except NativeIdentityError as exc:
        raise NativeIdentityError(f"{label} native read failed closed") from exc
    return raw


def _validate_review(
    review_raw: bytes,
    *,
    run_id: str,
    adjudication_id: str,
    source_hash: str,
    test_hash: str,
) -> dict[str, Any]:
    review = _parse_pretty_json(review_raw, label="independent review")
    keys = {
        "schema_version",
        "status",
        "run_id",
        "adjudication_id",
        "reviewed_source_raw_sha256",
        "reviewed_test_raw_sha256",
        "frozen_original_source_raw_sha256",
        "frozen_original_test_raw_sha256",
        "independent_reviewer_count",
        "reviews",
        "test_evidence",
        "preuse_access_evidence",
        "review_semantic_sha256",
    }
    if set(review) != keys:
        raise NativeIdentityError("independent review key universe differs")
    core = dict(review)
    seal = core.pop("review_semantic_sha256")
    if seal != semantic_sha256(core):
        raise NativeIdentityError("independent review semantic seal differs")
    if (
        review["schema_version"] != REVIEW_SCHEMA
        or review["status"] != REVIEW_STATUS
        or review["run_id"] != run_id
        or review["adjudication_id"] != adjudication_id
        or review["reviewed_source_raw_sha256"] != source_hash
        or review["reviewed_test_raw_sha256"] != test_hash
        or review["frozen_original_source_raw_sha256"] != ORIGINAL_AUDITOR_RAW_SHA256
        or review["frozen_original_test_raw_sha256"] != ORIGINAL_TEST_RAW_SHA256
        or review["independent_reviewer_count"] != 2
    ):
        raise NativeIdentityError("independent review binding differs")
    reviews = review["reviews"]
    expected_review_ids = {
        "r3_formal_migration_audit",
        "r3_reservation_redteam",
    }
    if (
        type(reviews) is not list
        or len(reviews) != 2
        or {item.get("review_id") for item in reviews if type(item) is dict} != expected_review_ids
        or any(
            type(item) is not dict
            or set(item) != {"review_id", "status", "blocking_findings"}
            or item["status"] != "GO"
            or item["blocking_findings"] != []
            for item in reviews
        )
    ):
        raise NativeIdentityError("independent reviewer decisions differ")
    tests = review["test_evidence"]
    if (
        type(tests) is not dict
        or set(tests)
        != {
            "focused_tests_status",
            "focused_pass_count",
            "focused_skip_count",
            "privilege_skip_scope",
            "full_synthetic_50_task_status",
            "full_synthetic_public_file_count",
            "ruff_check_status",
            "ruff_format_check_status",
        }
        or tests["focused_tests_status"] != "PASS"
        or type(tests["focused_pass_count"]) is not int
        or tests["focused_pass_count"] < 1
        or tests["focused_skip_count"] not in (0, 1)
        or tests["privilege_skip_scope"] not in ("none", "windows_symlink_privilege_only")
        or tests["full_synthetic_50_task_status"] != "PASS"
        or tests["full_synthetic_public_file_count"] != 201
        or tests["ruff_check_status"] != "PASS"
        or tests["ruff_format_check_status"] != "PASS"
    ):
        raise NativeIdentityError("independent review test evidence differs")
    if review["preuse_access_evidence"] != {
        "formal_public_root_access_count": 0,
        "vault_manifest_access_count": 0,
        "protected_payload_enumeration_count": 0,
        "protected_payload_stat_or_open_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "prediction_invocation_count": 0,
    }:
        raise NativeIdentityError("independent review pre-use access differs")
    return review


def verify_preuse_authority(
    *,
    project: Path,
    authority_path: Path,
    expected_raw_sha256: str,
    expected_semantic_sha256: str,
    run_id: str,
    adjudication_id: str,
    execution_authority: Path,
    execution_authority_raw_sha256: str,
    execution_authority_semantic_sha256: str,
    public_replay_root: Path,
    vault_manifest_path: Path,
    output_root: Path,
) -> tuple[dict[str, Any], bytes]:
    """Verify all pre-use pins without opening a formal generation artifact."""

    project = _absolute(project)
    exact_paths = {
        "pre-use authority": (authority_path, PREUSE_AUTHORITY_RELATIVE),
        "execution authority": (
            execution_authority,
            EXECUTION_AUTHORITY_RELATIVE,
        ),
        "public replay": (public_replay_root, PUBLIC_REPLAY_RELATIVE),
        "vault manifest": (vault_manifest_path, VAULT_MANIFEST_RELATIVE),
        "adjudication output": (output_root, ADJUDICATION_OUTPUT_RELATIVE),
    }
    for label, (supplied, expected_relative) in exact_paths.items():
        expected = _absolute(project / Path(*expected_relative.split("/")))
        if _path_key(_absolute(supplied)) != _path_key(expected):
            raise NativeIdentityError(f"{label} path differs from exact formal scope")
    authority_path = _absolute(authority_path)
    raw = _read_exact_project_file(
        project=project,
        supplied_path=authority_path,
        expected_relative=PREUSE_AUTHORITY_RELATIVE,
        label="pre-use authority",
    )
    if sha256(raw) != expected_raw_sha256:
        raise NativeIdentityError("pre-use authority raw hash differs")
    authority = _parse_pretty_json(raw, label="pre-use authority")
    top_keys = {
        "schema_version",
        "status",
        "run_id",
        "adjudication_id",
        "scope",
        "invocation_policy",
        "original_no_go_binding",
        "generation_binding",
        "identity_correction",
        "corrected_auditor_binding",
        "access_policy",
        "required_preuse_review",
        "adjudication_authority_semantic_sha256",
    }
    if set(authority) != top_keys:
        raise NativeIdentityError("pre-use authority key universe differs")
    core = dict(authority)
    seal = core.pop("adjudication_authority_semantic_sha256")
    if seal != expected_semantic_sha256 or seal != semantic_sha256(core):
        raise NativeIdentityError("pre-use authority semantic seal differs")
    if (
        authority["schema_version"] != AUTHORITY_SCHEMA
        or authority["status"] != AUTHORITY_STATUS
        or authority["run_id"] != run_id
        or authority["adjudication_id"] != adjudication_id
    ):
        raise NativeIdentityError("pre-use authority identity differs")
    if authority["scope"] != {
        "same_immutable_generation": True,
        "corrected_issue": "ARTIFACT_VOLUME_REPRESENTATION_ONLY",
        "full_audit_required": True,
        "waiver_allowed": False,
    }:
        raise NativeIdentityError("adjudication scope differs")
    invocation = authority["invocation_policy"]
    expected_output_relative = _relative(output_root, project)
    if expected_output_relative != ADJUDICATION_OUTPUT_RELATIVE:
        raise NativeIdentityError("adjudication output relative path differs")
    if invocation != {
        "authorized_invocation_count": 1,
        "prior_corrected_invocation_count": 0,
        "retry_allowed": False,
        "exact_create_new_output_root": expected_output_relative,
        "output_root_must_not_exist": True,
    }:
        raise NativeIdentityError("single-invocation policy differs")
    original = authority["original_no_go_binding"]
    expected_original = {
        "relative_path": ORIGINAL_NO_GO_RELATIVE,
        "raw_sha256": ORIGINAL_NO_GO_RAW_SHA256,
        "audit_semantic_sha256": ORIGINAL_NO_GO_SEMANTIC_SHA256,
        "status": "NO_GO_R3_POST_GENERATION_AUDIT",
        "auditor_source_raw_sha256": ORIGINAL_AUDITOR_RAW_SHA256,
        "finding_counts": {"P0": 1, "P1": 0, "P2": 0},
        "sole_finding": "ARTIFACT_VOLUME",
        "preserve_immutable": True,
    }
    if original != expected_original:
        raise NativeIdentityError("original NO_GO binding differs")
    original_raw = _read_exact_project_file(
        project=project,
        supplied_path=project / ORIGINAL_NO_GO_RELATIVE,
        expected_relative=ORIGINAL_NO_GO_RELATIVE,
        label="original NO_GO report",
    )
    if sha256(original_raw) != ORIGINAL_NO_GO_RAW_SHA256:
        raise NativeIdentityError("original NO_GO report drifted")
    original_report = _parse_pretty_json(original_raw, label="original NO_GO")
    if (
        original_report.get("audit_semantic_sha256") != ORIGINAL_NO_GO_SEMANTIC_SHA256
        or original_report.get("status") != "NO_GO_R3_POST_GENERATION_AUDIT"
        or original_report.get("finding_counts") != {"P0": 1, "P1": 0, "P2": 0}
        or [item.get("code") for item in original_report.get("findings", [])] != ["ARTIFACT_VOLUME"]
    ):
        raise NativeIdentityError("original NO_GO report content differs")
    generation = authority["generation_binding"]
    if generation != {
        "execution_authority_relative_path": _relative(execution_authority, project),
        "execution_authority_raw_sha256": execution_authority_raw_sha256,
        "execution_authority_semantic_sha256": (execution_authority_semantic_sha256),
        "generation_plan_semantic_sha256": (EXPECTED_GENERATION_PLAN_SEMANTIC_SHA256),
        "public_root_relative_path": _relative(public_replay_root, project),
        "generation_receipt_relative_path": (
            _relative(public_replay_root, project) + "/GENERATION_EXECUTION_RECEIPT.json"
        ),
        "generation_receipt_raw_sha256": (EXPECTED_GENERATION_RECEIPT_RAW_SHA256),
        "generation_status": ("PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH"),
        "vault_manifest_relative_path": _relative(vault_manifest_path, project),
        "task_count": 50,
        "seed_count": 5,
        "dgp_count": 10,
        "public_file_count": 201,
    }:
        raise NativeIdentityError("immutable generation binding differs")
    if (
        execution_authority_raw_sha256 != EXPECTED_EXECUTION_AUTHORITY_RAW_SHA256
        or execution_authority_semantic_sha256 != EXPECTED_EXECUTION_AUTHORITY_SEMANTIC_SHA256
    ):
        raise NativeIdentityError("execution authority pins differ")
    correction = authority["identity_correction"]
    if (
        correction
        != {
            "producer_api": "GetFileInformationByHandleEx(FileIdInfo)",
            "stored_volume_serial_number": STORED_WIN32_VOLUME_SERIAL_NUMBER,
            "observed_python_st_dev": OBSERVED_PYTHON310_ST_DEV,
            "low32_projection_exact": True,
            "authoritative_volume_rule": ("exact_uint64_FileIdInfo_VolumeSerialNumber"),
            "authoritative_file_id_rule": "exact_128bit_FileId",
            "st_dev_acceptance_or_fallback": False,
            "same_handle_bytes_size_identity": True,
            "share_write_or_delete_allowed": False,
        }
        or (STORED_WIN32_VOLUME_SERIAL_NUMBER & 0xFFFFFFFF) != OBSERVED_PYTHON310_ST_DEV
    ):
        raise NativeIdentityError("native identity correction contract differs")
    binding = authority["corrected_auditor_binding"]
    binding_keys = {
        "new_relative_path",
        "new_source_raw_sha256",
        "test_relative_path",
        "test_raw_sha256",
        "original_auditor_relative_path",
        "original_auditor_raw_sha256",
        "original_test_relative_path",
        "original_test_raw_sha256",
        "original_auditor_unchanged",
        "independent_from_frozen_producer",
        "implementation_mode",
    }
    if type(binding) is not dict or set(binding) != binding_keys:
        raise NativeIdentityError("corrected auditor binding key universe differs")
    source_raw = _read_exact_project_file(
        project=project,
        supplied_path=Path(__file__),
        expected_relative=CORRECTED_AUDITOR_RELATIVE,
        label="corrected adjudicator source",
    )
    test_raw = _read_exact_project_file(
        project=project,
        supplied_path=project / CORRECTED_TEST_RELATIVE,
        expected_relative=CORRECTED_TEST_RELATIVE,
        label="corrected adjudicator test",
    )
    original_source_raw = _read_exact_project_file(
        project=project,
        supplied_path=project / ORIGINAL_AUDITOR_RELATIVE,
        expected_relative=ORIGINAL_AUDITOR_RELATIVE,
        label="frozen original auditor source",
    )
    original_test_raw = _read_exact_project_file(
        project=project,
        supplied_path=project / ORIGINAL_TEST_RELATIVE,
        expected_relative=ORIGINAL_TEST_RELATIVE,
        label="frozen original auditor test",
    )
    if (
        binding["new_relative_path"] != CORRECTED_AUDITOR_RELATIVE
        or binding["new_source_raw_sha256"] != sha256(source_raw)
        or binding["test_relative_path"] != CORRECTED_TEST_RELATIVE
        or binding["test_raw_sha256"] != sha256(test_raw)
        or binding["original_auditor_relative_path"] != ORIGINAL_AUDITOR_RELATIVE
        or binding["original_auditor_raw_sha256"] != sha256(original_source_raw)
        or binding["original_auditor_raw_sha256"] != ORIGINAL_AUDITOR_RAW_SHA256
        or binding["original_test_relative_path"] != ORIGINAL_TEST_RELATIVE
        or binding["original_test_raw_sha256"] != sha256(original_test_raw)
        or binding["original_test_raw_sha256"] != ORIGINAL_TEST_RAW_SHA256
        or binding["original_auditor_unchanged"] is not True
        or binding["independent_from_frozen_producer"] is not True
        or binding["implementation_mode"]
        != "explicit_two_source_envelope_with_three_hook_replacement"
    ):
        raise NativeIdentityError("corrected auditor source/test binding differs")
    access = authority["access_policy"]
    if access != {
        "public_root_read_only": True,
        "exact_vault_manifest_only": True,
        "protected_payload_enumeration_allowed": False,
        "protected_payload_stat_or_open_allowed": False,
        "truth_open_allowed": False,
        "score_open_allowed": False,
        "prediction_allowed": False,
        "activation_allowed": False,
        "registry_or_seed_write_allowed": False,
        "generation_allowed": False,
    }:
        raise NativeIdentityError("adjudication access policy differs")
    review = authority["required_preuse_review"]
    review_keys = {
        "independent_review_status",
        "focused_tests_status",
        "full_synthetic_50_task_status",
        "independent_review_relative_path",
        "independent_review_raw_sha256",
    }
    if (
        type(review) is not dict
        or set(review) != review_keys
        or review["independent_review_status"] != "GO"
        or review["focused_tests_status"] != "PASS"
        or review["full_synthetic_50_task_status"] != "PASS"
        or review["independent_review_relative_path"] != PREUSE_REVIEW_RELATIVE
    ):
        raise NativeIdentityError("required pre-use review evidence differs")
    review_raw = _read_exact_project_file(
        project=project,
        supplied_path=project / PREUSE_REVIEW_RELATIVE,
        expected_relative=PREUSE_REVIEW_RELATIVE,
        label="independent pre-use review",
    )
    if review["independent_review_raw_sha256"] != sha256(review_raw):
        raise NativeIdentityError("independent pre-use review raw hash differs")
    _validate_review(
        review_raw,
        run_id=run_id,
        adjudication_id=adjudication_id,
        source_hash=sha256(source_raw),
        test_hash=sha256(test_raw),
    )
    if _absolute(output_root).exists():
        raise NativeIdentityError("create-new adjudication output root already exists")
    return authority, raw


def postuse_reverify(
    *,
    project: Path,
    authority: dict[str, Any],
    authority_raw: bytes,
    claim_path: Path,
    claim_raw: bytes,
) -> dict[str, Any]:
    """Rebind every mutable pathname input immediately before final reporting."""

    project = _absolute(project)
    expected: list[tuple[str, Path, str, str]] = [
        (
            "preuse_authority",
            project / PREUSE_AUTHORITY_RELATIVE,
            PREUSE_AUTHORITY_RELATIVE,
            sha256(authority_raw),
        ),
        (
            "original_no_go",
            project / ORIGINAL_NO_GO_RELATIVE,
            ORIGINAL_NO_GO_RELATIVE,
            ORIGINAL_NO_GO_RAW_SHA256,
        ),
        (
            "original_auditor_source",
            project / ORIGINAL_AUDITOR_RELATIVE,
            ORIGINAL_AUDITOR_RELATIVE,
            ORIGINAL_AUDITOR_RAW_SHA256,
        ),
        (
            "original_auditor_test",
            project / ORIGINAL_TEST_RELATIVE,
            ORIGINAL_TEST_RELATIVE,
            ORIGINAL_TEST_RAW_SHA256,
        ),
        (
            "corrected_adjudicator_source",
            project / CORRECTED_AUDITOR_RELATIVE,
            CORRECTED_AUDITOR_RELATIVE,
            authority["corrected_auditor_binding"]["new_source_raw_sha256"],
        ),
        (
            "corrected_adjudicator_test",
            project / CORRECTED_TEST_RELATIVE,
            CORRECTED_TEST_RELATIVE,
            authority["corrected_auditor_binding"]["test_raw_sha256"],
        ),
        (
            "independent_review",
            project / PREUSE_REVIEW_RELATIVE,
            PREUSE_REVIEW_RELATIVE,
            authority["required_preuse_review"]["independent_review_raw_sha256"],
        ),
        (
            "invocation_claim",
            claim_path,
            f"{ADJUDICATION_OUTPUT_RELATIVE}/{CLAIM_NAME}",
            sha256(claim_raw),
        ),
    ]
    refs: dict[str, Any] = {}
    for label, path, relative, expected_hash in expected:
        raw = _read_exact_project_file(
            project=project,
            supplied_path=path,
            expected_relative=relative,
            label=f"post-use {label}",
        )
        observed_hash = sha256(raw)
        if observed_hash != expected_hash:
            raise NativeIdentityError(f"post-use {label} hash drifted")
        refs[label] = {
            "relative_path": relative,
            "raw_sha256": observed_hash,
            "size_bytes": len(raw),
        }
    return {
        "status": "PASS_ALL_PREUSE_AND_CLAIM_BYTES_REVERIFIED_POST_AUDIT",
        "file_count": len(refs),
        "files": refs,
    }


def claim_invocation(
    *,
    project: Path,
    output_root: Path,
    run_id: str,
    adjudication_id: str,
    authority_relative: str,
    authority_raw_sha256: str,
    authority_semantic_sha256: str,
) -> tuple[Path, dict[str, Any], bytes]:
    project = _absolute(project)
    root = _absolute(output_root)
    build = project / "build"
    if (
        root.parent != build
        or _relative(root, project) != ADJUDICATION_OUTPUT_RELATIVE
        or root.exists()
    ):
        raise NativeIdentityError("adjudication output root is not create-new build child")
    root.mkdir()
    claim = {
        "schema_version": CLAIM_SCHEMA,
        "status": CLAIM_STATUS,
        "run_id": run_id,
        "adjudication_id": adjudication_id,
        "preuse_authority_relative_path": authority_relative,
        "preuse_authority_raw_sha256": authority_raw_sha256,
        "preuse_authority_semantic_sha256": authority_semantic_sha256,
        "authorized_invocation_count": 1,
        "consumed_invocation_count": 1,
        "retry_allowed": False,
        "formal_generation_read_count_at_claim": 0,
        "formal_generation_read_permitted_only_after_claim": True,
    }
    claim["claim_semantic_sha256"] = semantic_sha256(claim)
    raw = pretty_bytes(claim)
    with (root / CLAIM_NAME).open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    observed, _ = native_read(root / CLAIM_NAME)
    if observed != raw:
        raise NativeIdentityError("invocation claim changed after publication")
    return root, claim, raw


def build_report(
    *,
    authority: dict[str, Any],
    authority_relative: str,
    authority_raw_sha256: str,
    authority_semantic_sha256: str,
    claim: dict[str, Any],
    claim_raw: bytes,
    base_report: dict[str, Any] | None,
    telemetry: ReadTelemetry | None,
    findings: list[dict[str, str]],
    postuse_evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    base_completed = (
        base_report is not None
        and base_report.get("status") == "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"
    )
    postuse_pass = (
        postuse_evidence is not None
        and postuse_evidence.get("status")
        == "PASS_ALL_PREUSE_AND_CLAIM_BYTES_REVERIFIED_POST_AUDIT"
        and postuse_evidence.get("file_count") == 8
    )
    success = not findings and base_completed and postuse_pass and telemetry is not None
    counts = {"P0": 0, "P1": 0, "P2": 0}
    for finding in findings:
        severity = finding.get("severity", "P0")
        counts[severity if severity in counts else "P0"] += 1
    native_evidence = telemetry.evidence() if telemetry is not None else None
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "status": GO_STATUS if success else NO_GO_STATUS,
        "run_id": authority["run_id"],
        "adjudication_id": authority["adjudication_id"],
        "finding_counts": counts,
        "findings": findings,
        "preuse_authority": {
            "relative_path": authority_relative,
            "raw_sha256": authority_raw_sha256,
            "semantic_sha256": authority_semantic_sha256,
            "status": authority["status"],
        },
        "invocation_claim": {
            "relative_path": f"{ADJUDICATION_OUTPUT_RELATIVE}/{CLAIM_NAME}",
            "raw_sha256": sha256(claim_raw),
            "size_bytes": len(claim_raw),
            "status": claim["status"],
            "claim_semantic_sha256": claim["claim_semantic_sha256"],
            "consumed_invocation_count": 1,
            "retry_allowed": False,
            "published_before_formal_generation_read": True,
            "live_bytes_reverified_after_full_audit": postuse_pass,
        },
        "original_no_go_binding": authority["original_no_go_binding"],
        "immutable_generation_binding": authority["generation_binding"],
        "correction_basis": authority["identity_correction"],
        "corrected_auditor_binding": authority["corrected_auditor_binding"],
        "frozen_full_audit_report": base_report,
        "full_coverage": {
            "full_frozen_audit_completed": base_completed,
            "adjudication_all_gates_passed": success,
            "task_count": 50 if base_completed else None,
            "public_file_count": 201 if base_completed else None,
            "seed_count": 5 if base_completed else None,
            "dgp_count": 10 if base_completed else None,
            "schema_geometry_row_date_manifest_receipt_hash_checks": (base_completed),
            "native_uint64_volume_and_file_id_128_checks": base_completed,
            "hardlink_reparse_path_public_private_checks": base_completed,
        },
        "native_read_evidence": native_evidence,
        "protected_boundary": {
            "enforcement_evidence_retained": native_evidence is not None,
            "truth_open_count": (native_evidence["truth_open_count"] if native_evidence else None),
            "score_open_count": (native_evidence["score_open_count"] if native_evidence else None),
            "payload_directories_enumerated": (
                native_evidence["protected_payload_directories_enumerated"]
                if native_evidence
                else None
            ),
            "payload_refs_resolved_or_statted": (
                native_evidence["protected_payload_refs_resolved_or_statted"]
                if native_evidence
                else None
            ),
            "payload_leaves_opened": (
                native_evidence["protected_payload_leaves_opened"] if native_evidence else None
            ),
        },
        "postuse_integrity_reverification": postuse_evidence,
        "mutation_ledger": {
            "generation_invocation_count": 0,
            "seed_reservation_or_registry_write_count": 0,
            "prediction_invocation_count": 0,
            "activation_invocation_count": 0,
            "public_mutation_count": 0,
            "vault_mutation_count": 0,
            "frozen_source_mutation_count": 0,
            "original_audit_mutation_count": 0,
            "adjudication_output_root_create_count": 1,
            "invocation_claim_publication_count": 1,
            "adjudication_report_publication_count": 1,
        },
        "output_publication_contract": {
            "exact_leaf_names": [CLAIM_NAME, REPORT_NAME],
            "report_create_new": True,
            "exact_leaf_universe_verification_phase": ("post_report_fsync_before_GO_process_exit"),
        },
        "audit_check_count": (base_report.get("audit_check_count") if base_report else None),
        "base_audit_semantic_sha256": (
            base_report.get("audit_semantic_sha256") if base_report else None
        ),
    }
    report["audit_semantic_sha256"] = semantic_sha256(report)
    return report


def publish_report(root: Path, report: dict[str, Any]) -> str:
    raw = pretty_bytes(report)
    output = root / REPORT_NAME
    with output.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    observed, _ = native_read(output)
    if observed != raw:
        raise NativeIdentityError("adjudication report changed after publication")
    entries = {entry.name: entry for entry in os.scandir(root)}
    if set(entries) != {CLAIM_NAME, REPORT_NAME}:
        raise NativeIdentityError("adjudication output leaf universe differs")
    claim_raw, _ = native_read(Path(entries[CLAIM_NAME].path))
    claim_ref = report.get("invocation_claim")
    if (
        type(claim_ref) is not dict
        or claim_ref.get("raw_sha256") != sha256(claim_raw)
        or claim_ref.get("size_bytes") != len(claim_raw)
    ):
        raise NativeIdentityError("live invocation claim raw bytes differ")
    claim = _parse_pretty_json(claim_raw, label="live invocation claim")
    claim_keys = {
        "schema_version",
        "status",
        "run_id",
        "adjudication_id",
        "preuse_authority_relative_path",
        "preuse_authority_raw_sha256",
        "preuse_authority_semantic_sha256",
        "authorized_invocation_count",
        "consumed_invocation_count",
        "retry_allowed",
        "formal_generation_read_count_at_claim",
        "formal_generation_read_permitted_only_after_claim",
        "claim_semantic_sha256",
    }
    claim_core = dict(claim)
    claim_seal = claim_core.pop("claim_semantic_sha256", None)
    if (
        set(claim) != claim_keys
        or claim.get("schema_version") != CLAIM_SCHEMA
        or claim.get("status") != CLAIM_STATUS
        or claim.get("run_id") != report.get("run_id")
        or claim.get("adjudication_id") != report.get("adjudication_id")
        or claim.get("authorized_invocation_count") != 1
        or claim.get("consumed_invocation_count") != 1
        or claim.get("retry_allowed") is not False
        or claim.get("formal_generation_read_count_at_claim") != 0
        or claim.get("formal_generation_read_permitted_only_after_claim") is not True
        or claim_seal != semantic_sha256(claim_core)
        or claim_seal != claim_ref.get("claim_semantic_sha256")
    ):
        raise NativeIdentityError("live invocation claim contract differs")
    final_report_raw, _ = native_read(Path(entries[REPORT_NAME].path))
    if final_report_raw != raw:
        raise NativeIdentityError("live adjudication report raw bytes differ")
    return sha256(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--adjudication-id", required=True)
    parser.add_argument("--preuse-authority", type=Path, required=True)
    parser.add_argument("--preuse-authority-raw-sha256", required=True)
    parser.add_argument("--preuse-authority-semantic-sha256", required=True)
    parser.add_argument("--execution-authority", type=Path, required=True)
    parser.add_argument("--execution-authority-raw-sha256", required=True)
    parser.add_argument("--execution-authority-semantic-sha256", required=True)
    parser.add_argument("--public-replay-root", type=Path, required=True)
    parser.add_argument("--vault-manifest", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    project = _absolute(args.project_root)
    if args.run_id != FORMAL_RUN_ID or args.adjudication_id != ADJUDICATION_ID:
        print('{"status":"STOP_FORMAL_ADJUDICATION_IDENTITY"}')
        return 4
    try:
        authority, authority_raw = verify_preuse_authority(
            project=project,
            authority_path=args.preuse_authority,
            expected_raw_sha256=args.preuse_authority_raw_sha256,
            expected_semantic_sha256=args.preuse_authority_semantic_sha256,
            run_id=args.run_id,
            adjudication_id=args.adjudication_id,
            execution_authority=args.execution_authority,
            execution_authority_raw_sha256=args.execution_authority_raw_sha256,
            execution_authority_semantic_sha256=(args.execution_authority_semantic_sha256),
            public_replay_root=args.public_replay_root,
            vault_manifest_path=args.vault_manifest,
            output_root=args.output_root,
        )
        root, claim, claim_raw = claim_invocation(
            project=project,
            output_root=args.output_root,
            run_id=args.run_id,
            adjudication_id=args.adjudication_id,
            authority_relative=_relative(args.preuse_authority, project),
            authority_raw_sha256=args.preuse_authority_raw_sha256,
            authority_semantic_sha256=args.preuse_authority_semantic_sha256,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "STOP_PREUSE_OR_CLAIM", "code": type(exc).__name__},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 4

    base_report: dict[str, Any] | None = None
    telemetry = ReadTelemetry(
        authority_path=args.execution_authority,
        public_root=args.public_replay_root,
        vault_manifest_path=args.vault_manifest,
    )
    findings: list[dict[str, str]] = []
    try:
        base_report, _ = run_corrected_base_audit(
            project,
            run_id=args.run_id,
            execution_authority=args.execution_authority,
            authority_semantic_sha256=(args.execution_authority_semantic_sha256),
            authority_raw_sha256=args.execution_authority_raw_sha256,
            public_replay_root=args.public_replay_root,
            vault_manifest_path=args.vault_manifest,
            telemetry=telemetry,
        )
        evidence = telemetry.evidence()
        if (
            base_report.get("status") != "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"
            or base_report.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
            or base_report.get("public_evidence", {}).get("generation_receipt_raw_sha256")
            != EXPECTED_GENERATION_RECEIPT_RAW_SHA256
            or base_report.get("authority", {}).get("generation_plan_semantic_sha256")
            != EXPECTED_GENERATION_PLAN_SEMANTIC_SHA256
            or evidence["authority_native_read_count"] != 1
            or evidence["public_native_read_count"] != 201
            or evidence["unique_public_path_count"] != 201
            or evidence["vault_manifest_native_read_count"] != 1
            or evidence["other_native_read_count"] != 0
            or evidence["unauthorized_read_attempt_count"] != 0
        ):
            raise NativeIdentityError("full corrected audit coverage differs")
    except Exception as exc:
        findings.append(
            {
                "severity": "P0",
                "code": (
                    exc.code
                    if hasattr(exc, "code") and type(exc.code) is str
                    else "CORRECTED_AUDIT_FAILURE"
                ),
                "message": (
                    exc.safe_message
                    if hasattr(exc, "safe_message") and type(exc.safe_message) is str
                    else "corrected full audit failed closed"
                ),
            }
        )
    postuse_evidence: dict[str, Any] | None = None
    try:
        postuse_evidence = postuse_reverify(
            project=project,
            authority=authority,
            authority_raw=authority_raw,
            claim_path=root / CLAIM_NAME,
            claim_raw=claim_raw,
        )
    except Exception:
        findings.append(
            {
                "severity": "P0",
                "code": "POSTUSE_INTEGRITY_REVERIFICATION",
                "message": "post-use authority, source, test, review, or claim bytes drifted",
            }
        )
    report = build_report(
        authority=authority,
        authority_relative=_relative(args.preuse_authority, project),
        authority_raw_sha256=args.preuse_authority_raw_sha256,
        authority_semantic_sha256=args.preuse_authority_semantic_sha256,
        claim=claim,
        claim_raw=claim_raw,
        base_report=base_report,
        telemetry=telemetry,
        findings=findings,
        postuse_evidence=postuse_evidence,
    )
    try:
        raw_hash = publish_report(root, report)
    except Exception:
        print('{"status":"NO_GO_ADJUDICATION_PUBLICATION_TERMINAL"}')
        return 3
    print(
        json.dumps(
            {
                "status": report["status"],
                "audit_raw_sha256": raw_hash,
                "audit_semantic_sha256": report["audit_semantic_sha256"],
                "finding_counts": report["finding_counts"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
