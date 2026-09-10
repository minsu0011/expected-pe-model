from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/NativeEnvironmentShimV1.c"
)
EXECUTABLE = PROJECT_ROOT / (
    "build/r8r8_native_environment_shim_v1_immutable_20260823/ExpectedPeNativeEnvironmentShimV1.exe"
)
SEAL_RECEIPT = PROJECT_ROOT / (
    "outputs/r8r8_native_environment_shim_v1_immutable_seal_receipt_20260823.json"
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


def _digest(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def test_independent_native_shim_pins_and_seal_receipt() -> None:
    assert _digest(SOURCE) == (
        "8ed491bb7e5af01e66803b96b3d8aa85abd7aa42bf5a72440f325f024d9101fa",
        9401,
    )
    assert _digest(EXECUTABLE) == (
        "c52956ac74ba6f09e20064349283d8f630d347e76062722ac841954e7dde14e2",
        80896,
    )
    assert _digest(SEAL_RECEIPT) == (
        "fe5d19653817d59b1d96f6f3290355a063891b8bf18674c09ed9626b4b532df0",
        2518,
    )
    receipt = json.loads(SEAL_RECEIPT.read_bytes())
    assert receipt["status"] == (
        "PASS_NATIVE_ENVIRONMENT_SHIM_EXECUTABLE_AND_DIRECTORY_IMMUTABLY_SEALED"
    )
    assert receipt["executable"]["protected_dacl"]["dacl_raw_sha256"] == (
        "7b9afe62cc435ca5ec49f2b8232d1ce307ba8ee7ff2c22d0ecc60b70fc0dfc13"
    )


def test_independent_hostile_environment_cannot_reach_managed_prebootstrap() -> None:
    before = tuple(path.exists() for path in CLAIMS)
    assert before == (False, False, False)
    environment = {
        "PATH": r"C:\attacker;C:\Windows\System32;C:\Windows",
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "COR_ENABLE_PROFILING": "1",
        "COR_PROFILER": "{22222222-2222-2222-2222-222222222222}",
        "COR_PROFILER_PATH": r"C:\attacker\profiler.dll",
        "COMPLUS_ProfAPI_ProfilerCompatibilitySetting": "EnableV2Profiler",
        "DOTNET_STARTUP_HOOKS": r"C:\attacker\hook.dll",
        "PYTHONPATH": r"C:\attacker\python",
        "PYTHONHOME": r"C:\attacker\home",
    }
    completed = subprocess.run(
        (str(EXECUTABLE), "--audit-only-no-python-no-identity"),
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0 and completed.stderr == b""
    receipt = json.loads(completed.stdout)
    assert receipt["status"] == "PASS_PREPYTHON_CUSTODY_AUDIT_NO_PYTHON_NO_IDENTITY"
    assert receipt["file_record_count"] == 2366
    assert receipt["directory_record_count"] == 129
    assert tuple(path.exists() for path in CLAIMS) == before
