from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3.native_prebootstrap_contract import (  # noqa: E402
    CHILD_PYCACHE_PREFIX_RELATIVE,
    CSC_FILE_ID_128,
    CSC_PATH,
    CSC_SHA256,
    CSC_SIZE_BYTES,
    CSC_VOLUME_SERIAL_NUMBER,
    DESIGN_OUTPUT_RELATIVE,
    EXTERNAL_HANDSHAKE_AUDIT_RELATIVE,
    EXTERNAL_HANDSHAKE_AUDIT_SHA256,
    EXTERNAL_HANDSHAKE_AUDIT_SIZE_BYTES,
    NATIVE_AUDIT_ARGUMENT,
    NATIVE_BUILDER_RELATIVE,
    NATIVE_BUILDER_SHA256,
    NATIVE_BUILDER_SIZE_BYTES,
    NATIVE_DIRECTORY_MANIFEST_FILE_ID_128,
    NATIVE_DIRECTORY_MANIFEST_RECORD_COUNT,
    NATIVE_DIRECTORY_MANIFEST_RELATIVE,
    NATIVE_DIRECTORY_MANIFEST_SHA256,
    NATIVE_DIRECTORY_MANIFEST_SIZE_BYTES,
    NATIVE_DIRECTORY_MANIFEST_VOLUME_SERIAL_NUMBER,
    NATIVE_EXECUTABLE_FILE_ID_128,
    NATIVE_EXECUTABLE_RELATIVE,
    NATIVE_EXECUTABLE_SHA256,
    NATIVE_EXECUTABLE_SIZE_BYTES,
    NATIVE_EXECUTABLE_VOLUME_SERIAL_NUMBER,
    NATIVE_FILE_MANIFEST_FILE_ID_128,
    NATIVE_FILE_MANIFEST_RECORD_COUNT,
    NATIVE_FILE_MANIFEST_RELATIVE,
    NATIVE_FILE_MANIFEST_SHA256,
    NATIVE_FILE_MANIFEST_SIZE_BYTES,
    NATIVE_FILE_MANIFEST_VOLUME_SERIAL_NUMBER,
    NATIVE_SEAL_RECEIPT_RELATIVE,
    NATIVE_SEAL_RECEIPT_SHA256,
    NATIVE_SEAL_RECEIPT_SIZE_BYTES,
    NATIVE_SEALER_RELATIVE,
    NATIVE_SEALER_SHA256,
    NATIVE_SEALER_SIZE_BYTES,
    NATIVE_SOURCE_FILE_ID_128,
    NATIVE_SOURCE_RELATIVE,
    NATIVE_SOURCE_SHA256,
    NATIVE_SOURCE_SIZE_BYTES,
    NATIVE_SOURCE_VOLUME_SERIAL_NUMBER,
    PROTECTED_DIRECTORY_SDDL,
    SUPERVISOR_CLAIM_RELATIVE,
    ZERO_COUNTS,
)

V3_SUPERVISOR = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/trusted_supervisor.py"
)
MINIMAL_WINDOWS_ENVIRONMENT = {
    "PATH": r"C:\Windows\System32;C:\Windows",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
}


def _raw(path: Path) -> tuple[str, int]:
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest(), len(content)


def _v3() -> Any:
    spec = importlib.util.spec_from_file_location("native_v1_identity_helper", V3_SUPERVISOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identity(path: Path) -> tuple[int, str]:
    module = _v3()
    handle = module._open_no_share_write_delete(path, directory=False)
    try:
        return module._identity(handle)
    finally:
        module._close_checked(handle)


def _line_records(path: Path, header: str) -> list[list[str]]:
    raw = path.read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    lines = raw.decode("utf-8").splitlines()
    assert lines[0] == header
    return [line.split("\t") for line in lines[1:]]


def test_native_source_compiler_manifests_and_executable_are_exactly_pinned() -> None:
    cases = (
        (
            PROJECT_ROOT / NATIVE_SOURCE_RELATIVE,
            NATIVE_SOURCE_SHA256,
            NATIVE_SOURCE_SIZE_BYTES,
            NATIVE_SOURCE_VOLUME_SERIAL_NUMBER,
            NATIVE_SOURCE_FILE_ID_128,
        ),
        (
            CSC_PATH,
            CSC_SHA256,
            CSC_SIZE_BYTES,
            CSC_VOLUME_SERIAL_NUMBER,
            CSC_FILE_ID_128,
        ),
        (
            PROJECT_ROOT / NATIVE_FILE_MANIFEST_RELATIVE,
            NATIVE_FILE_MANIFEST_SHA256,
            NATIVE_FILE_MANIFEST_SIZE_BYTES,
            NATIVE_FILE_MANIFEST_VOLUME_SERIAL_NUMBER,
            NATIVE_FILE_MANIFEST_FILE_ID_128,
        ),
        (
            PROJECT_ROOT / NATIVE_DIRECTORY_MANIFEST_RELATIVE,
            NATIVE_DIRECTORY_MANIFEST_SHA256,
            NATIVE_DIRECTORY_MANIFEST_SIZE_BYTES,
            NATIVE_DIRECTORY_MANIFEST_VOLUME_SERIAL_NUMBER,
            NATIVE_DIRECTORY_MANIFEST_FILE_ID_128,
        ),
        (
            PROJECT_ROOT / NATIVE_EXECUTABLE_RELATIVE,
            NATIVE_EXECUTABLE_SHA256,
            NATIVE_EXECUTABLE_SIZE_BYTES,
            NATIVE_EXECUTABLE_VOLUME_SERIAL_NUMBER,
            NATIVE_EXECUTABLE_FILE_ID_128,
        ),
    )
    for path, digest, size, volume, file_id in cases:
        assert _raw(path) == (digest, size)
        assert _identity(path) == (volume, file_id)

    builder = PROJECT_ROOT / NATIVE_BUILDER_RELATIVE
    handshake = PROJECT_ROOT / EXTERNAL_HANDSHAKE_AUDIT_RELATIVE
    assert _raw(builder) == (NATIVE_BUILDER_SHA256, NATIVE_BUILDER_SIZE_BYTES)
    assert _raw(handshake) == (
        EXTERNAL_HANDSHAKE_AUDIT_SHA256,
        EXTERNAL_HANDSHAKE_AUDIT_SIZE_BYTES,
    )
    assert _raw(PROJECT_ROOT / NATIVE_SEALER_RELATIVE) == (
        NATIVE_SEALER_SHA256,
        NATIVE_SEALER_SIZE_BYTES,
    )
    assert _raw(PROJECT_ROOT / NATIVE_SEAL_RECEIPT_RELATIVE) == (
        NATIVE_SEAL_RECEIPT_SHA256,
        NATIVE_SEAL_RECEIPT_SIZE_BYTES,
    )


def test_native_line_manifests_reproduce_from_the_pinned_v3_closure() -> None:
    builder_path = PROJECT_ROOT / NATIVE_BUILDER_RELATIVE
    spec = importlib.util.spec_from_file_location("native_v1_manifest_builder", builder_path)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    assert builder._file_bytes() == (PROJECT_ROOT / NATIVE_FILE_MANIFEST_RELATIVE).read_bytes()
    assert (
        builder._directory_bytes()
        == (PROJECT_ROOT / NATIVE_DIRECTORY_MANIFEST_RELATIVE).read_bytes()
    )


def test_native_line_manifest_shapes_counts_and_live_records_are_exact() -> None:
    file_records = _line_records(
        PROJECT_ROOT / NATIVE_FILE_MANIFEST_RELATIVE,
        "EXPECTED_PE_NATIVE_FILE_CLOSURE_V1",
    )
    directory_records = _line_records(
        PROJECT_ROOT / NATIVE_DIRECTORY_MANIFEST_RELATIVE,
        "EXPECTED_PE_NATIVE_DIRECTORY_CLOSURE_V1",
    )
    assert len(file_records) == NATIVE_FILE_MANIFEST_RECORD_COUNT == 2366
    assert len(directory_records) == NATIVE_DIRECTORY_MANIFEST_RECORD_COUNT == 129
    assert all(len(row) == 6 for row in file_records)
    assert all(len(row) == 5 for row in directory_records)
    assert len({os.path.normcase(row[1]) for row in file_records}) == len(file_records)
    assert len({os.path.normcase(row[0]) for row in directory_records}) == len(directory_records)
    roles = {row[0] for row in file_records}
    assert {
        "RUNTIME_2265",
        "SOURCE_119",
        "V3_RUNTIME_MANIFEST",
        "V3_SOURCE_MANIFEST",
        "V3_STUB_TEMPLATE",
        "V3_SUPERVISOR",
    } <= roles


def test_native_source_has_the_fixed_fail_closed_boundary() -> None:
    source = (PROJECT_ROOT / NATIVE_SOURCE_RELATIVE).read_text(encoding="utf-8")
    for required in (
        PROTECTED_DIRECTORY_SDDL,
        "FileShareRead",
        "FileFlagOpenReparsePoint",
        "GetFileInformationByHandleEx",
        "GetFinalPathNameByHandleW",
        "SetKernelObjectSecurity",
        "EnvironmentVariables.Clear()",
        "--execute-fixed-r8-r8-static-once-no-authority",
        "PASS_PREPYTHON_FILE_DACL_CUSTODY_AND_FIXED_V3_CHILD_NO_AUTHORITY",
    ):
        assert required in source
    for forbidden in ("System.Text.Json", "Newtonsoft", "UseShellExecute = true"):
        assert forbidden not in source


def test_final_native_executable_audit_is_clean_and_consumes_no_identity() -> None:
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
    completed = subprocess.run(
        (str(PROJECT_ROOT / NATIVE_EXECUTABLE_RELATIVE), NATIVE_AUDIT_ARGUMENT),
        cwd=PROJECT_ROOT,
        env=MINIMAL_WINDOWS_ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=60,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    receipt = json.loads(completed.stdout)
    assert receipt["status"] == "PASS_PREPYTHON_CUSTODY_AUDIT_NO_PYTHON_NO_IDENTITY"
    assert receipt["authority_generation_fresh_truth_heldout_signer_counts"] == ZERO_COUNTS
    assert receipt["file_record_count"] == NATIVE_FILE_MANIFEST_RECORD_COUNT
    assert receipt["directory_record_count"] == NATIVE_DIRECTORY_MANIFEST_RECORD_COUNT
    assert receipt["executable_raw_sha256"] == NATIVE_EXECUTABLE_SHA256
    assert tuple(path.exists() for path in governed) == before
