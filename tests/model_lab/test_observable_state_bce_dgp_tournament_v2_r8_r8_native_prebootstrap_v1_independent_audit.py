from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/NativePrebootstrapV1.cs"
)
EXECUTABLE = PROJECT_ROOT / (
    "build/r8r8_native_prebootstrap_v1_immutable_20260823/ExpectedPeNativePrebootstrapV1.exe"
)
FILE_MANIFEST = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/NATIVE_FILE_CLOSURE.tsv"
)
DIRECTORY_MANIFEST = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/NATIVE_DIRECTORY_CLOSURE.tsv"
)
SEAL_RECEIPT = PROJECT_ROOT / (
    "outputs/r8r8_native_prebootstrap_v1_immutable_seal_receipt_20260823.json"
)
CLAIMS = (
    PROJECT_ROOT / "build/pc_r8r8_preimport_source_supervisor_v3_actual_once_20260823",
    PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822",
    PROJECT_ROOT
    / (
        "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
        "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
    ),
)
MINIMAL_WINDOWS_ENVIRONMENT = {
    "PATH": r"C:\Windows\System32;C:\Windows",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
}


def _digest(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def test_independent_native_artifact_pins_and_pe_shape() -> None:
    assert _digest(SOURCE) == (
        "ffebee1822eae9aa58b7b4124bfc6c10c07c76d65438ec0fa795b69312070019",
        43212,
    )
    assert _digest(EXECUTABLE) == (
        "8adde3b985523bdd4e389bae8340c783bb6d29a69ef7eb7fac5ab63448ee43b1",
        33280,
    )
    assert _digest(FILE_MANIFEST) == (
        "03ea5a9a2ba6cf50880bc65c090e199b3b824de3046e4dbf6dc5bc57e9249d99",
        510003,
    )
    assert _digest(DIRECTORY_MANIFEST) == (
        "be41af907bffa6d727d73bd15c2201828776b1ffaad0e498236ebd5c81398272",
        23475,
    )
    assert _digest(SEAL_RECEIPT) == (
        "0e79663970bdbe89960b30425b381838c062143fbd3a3474bcf1cedcbbed77c3",
        2496,
    )
    seal = json.loads(SEAL_RECEIPT.read_bytes())
    assert seal["status"] == ("PASS_NATIVE_BOOTSTRAP_EXECUTABLE_AND_DIRECTORY_IMMUTABLY_SEALED")
    assert seal["executable"]["protected_dacl"]["dacl_raw_sha256"] == (
        "7b9afe62cc435ca5ec49f2b8232d1ce307ba8ee7ff2c22d0ecc60b70fc0dfc13"
    )
    raw = EXECUTABLE.read_bytes()
    assert raw[:2] == b"MZ"
    pe_offset = int.from_bytes(raw[0x3C:0x40], "little")
    assert raw[pe_offset : pe_offset + 4] == b"PE\x00\x00"
    assert int.from_bytes(raw[pe_offset + 4 : pe_offset + 6], "little") == 0x8664
    optional = pe_offset + 24
    assert int.from_bytes(raw[optional : optional + 2], "little") == 0x20B


def test_independent_native_audit_is_fail_closed_and_sensitive_zero() -> None:
    before = tuple(path.exists() for path in CLAIMS)
    assert before == (False, False, False)
    completed = subprocess.run(
        (str(EXECUTABLE), "--audit-only-no-python-no-identity"),
        cwd=PROJECT_ROOT,
        env=MINIMAL_WINDOWS_ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=60,
        text=True,
    )
    assert completed.returncode == 0 and completed.stderr == ""
    receipt = json.loads(completed.stdout)
    assert receipt == {
        "authority_generation_fresh_truth_heldout_signer_counts": {
            "authority": 0,
            "fresh": 0,
            "generation": 0,
            "heldout": 0,
            "signer": 0,
            "truth": 0,
        },
        "directory_manifest_raw_sha256": (
            "be41af907bffa6d727d73bd15c2201828776b1ffaad0e498236ebd5c81398272"
        ),
        "directory_record_count": 129,
        "executable_file_id_128": "0ea5200000003e000000000000000000",
        "executable_raw_sha256": (
            "8adde3b985523bdd4e389bae8340c783bb6d29a69ef7eb7fac5ab63448ee43b1"
        ),
        "executable_size_bytes": 33280,
        "executable_volume_serial_number": 13325047249941796650,
        "file_manifest_raw_sha256": (
            "03ea5a9a2ba6cf50880bc65c090e199b3b824de3046e4dbf6dc5bc57e9249d99"
        ),
        "file_record_count": 2366,
        "schema_version": "expected_pe.r8.r8.native_prebootstrap.audit.v1",
        "status": "PASS_PREPYTHON_CUSTODY_AUDIT_NO_PYTHON_NO_IDENTITY",
    }
    assert tuple(path.exists() for path in CLAIMS) == before


def test_independent_direct_and_python_environment_invocations_fail_closed() -> None:
    before = tuple(path.exists() for path in CLAIMS)
    for arguments, environment in (
        ((), MINIMAL_WINDOWS_ENVIRONMENT),
        (("--not-a-contract-mode",), MINIMAL_WINDOWS_ENVIRONMENT),
        (
            ("--audit-only-no-python-no-identity",),
            {**MINIMAL_WINDOWS_ENVIRONMENT, "PYTHONPATH": "attack"},
        ),
    ):
        completed = subprocess.run(
            (str(EXECUTABLE), *arguments),
            cwd=PROJECT_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if "PYTHONPATH" in environment:
            assert completed.returncode == 0
            assert json.loads(completed.stdout)["status"].startswith("PASS_PREPYTHON")
        else:
            assert completed.returncode != 0
            assert b"NATIVE_PREBOOTSTRAP_FAIL_CLOSED" in completed.stderr
    assert tuple(path.exists() for path in CLAIMS) == before
    assert not any(name.upper().startswith("PYTHON") for name in os.environ if name == "__none__")
