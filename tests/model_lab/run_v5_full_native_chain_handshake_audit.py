"""Audit shim V3 -> managed V3 -> V5 custody without consuming identity."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay")
PYTHON = Path(r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe")
SHIM = PROJECT_ROOT / (
    "build/r8r8_native_environment_shim_v3_immutable_20260823/"
    "ExpectedPeNativeEnvironmentShimV3.exe"
)
EXTERNAL_AUDIT = PROJECT_ROOT / "tests/model_lab/run_v5_external_native_handshake_audit.py"
GOVERNED = (
    PROJECT_ROOT / "build/pc_r8r8_preimport_source_supervisor_v5_recovery_once_20260823",
    PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822",
    PROJECT_ROOT
    / (
        "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
        "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
    ),
)
MINIMAL_ENVIRONMENT = {
    "PATH": r"C:\Windows\System32;C:\Windows",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
}


def main() -> int:
    before = tuple(path.exists() for path in GOVERNED)
    if before != (False, False, False):
        raise RuntimeError("V5 governed identity existed before full-chain audit")
    hostile_environment = {
        **os.environ,
        "PYTHONPATH": r"C:\hostile\pythonpath",
        "PYTHONHOME": r"C:\hostile\pythonhome",
        "DOTNET_ROOT": r"C:\hostile\dotnet",
        "CORECLR_ENABLE_PROFILING": "1",
    }
    process = subprocess.Popen(
        (str(SHIM), "--audit-external-v5-handshake-window-no-python-no-identity"),
        cwd=PROJECT_ROOT,
        env=hostile_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    assert process.stdout is not None
    first_line = process.stdout.readline()
    try:
        ready = json.loads(first_line)
        if ready.get("status") != "READY_EXTERNAL_V5_HANDSHAKE_WINDOW_NO_PYTHON_NO_IDENTITY":
            raise RuntimeError(f"full-chain audit did not become ready: {first_line!r}")
        external = subprocess.run(
            (str(PYTHON), "-I", "-S", "-B", "-E", str(EXTERNAL_AUDIT)),
            cwd=PROJECT_ROOT,
            env=MINIMAL_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=45,
            text=True,
            encoding="utf-8",
        )
        remainder, stderr = process.communicate(timeout=75)
    except BaseException:
        process.kill()
        process.communicate(timeout=30)
        raise
    if process.returncode != 0 or stderr != "":
        raise RuntimeError(
            f"full native chain failed: exit={process.returncode} stderr={stderr!r}"
        )
    final_lines = remainder.splitlines()
    if len(final_lines) != 1:
        raise RuntimeError(f"full native chain final output drifted: {remainder!r}")
    final = json.loads(final_lines[0])
    external_receipt = json.loads(external.stdout)
    if (
        external.returncode != 0
        or external.stderr != ""
        or external_receipt.get("status")
        != "PASS_FULL_V5_EXTERNAL_NATIVE_HANDSHAKE_NO_EXECUTION_NO_IDENTITY"
        or final.get("status") != "PASS_EXTERNAL_V5_HANDSHAKE_WINDOW_NO_PYTHON_NO_IDENTITY"
        or tuple(path.exists() for path in GOVERNED) != before
    ):
        raise RuntimeError("full native chain handshake verdict drifted")
    print(
        json.dumps(
            {
                "authority_generation_fresh_truth_heldout_signer_counts": {
                    "authority": 0,
                    "fresh": 0,
                    "generation": 0,
                    "heldout": 0,
                    "signer": 0,
                    "truth": 0,
                },
                "external_v5_receipt": external_receipt,
                "hostile_environment_removed_before_managed_boundary": True,
                "managed_final_receipt": final,
                "one_shot_identity_before_after_absent": True,
                "status": "PASS_FULL_NATIVE_SHIM_V3_MANAGED_V3_V5_HANDSHAKE_NO_EXECUTION",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
