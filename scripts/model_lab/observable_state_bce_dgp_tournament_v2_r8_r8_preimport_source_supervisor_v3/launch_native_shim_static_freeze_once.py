"""Lossless one-shot launcher for the sealed native environment shim."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SHIM = PROJECT_ROOT / (
    "build/r8r8_native_environment_shim_v1_immutable_20260823/ExpectedPeNativeEnvironmentShimV1.exe"
)
SHIM_SHA256 = "c52956ac74ba6f09e20064349283d8f630d347e76062722ac841954e7dde14e2"
SHIM_SIZE = 80896
SHIM_ARGUMENT = "--execute-fixed-r8-r8-static-once-no-authority"
EXACT_ARGUMENT = "--launch-sealed-native-shim-static-freeze-once-lossless-capture"
STDOUT_CAPTURE = PROJECT_ROOT / "outputs/r8r8_native_chain_actual_stdout_20260823.jsonl"
STDERR_CAPTURE = PROJECT_ROOT / "outputs/r8r8_native_chain_actual_stderr_20260823.bin"
LAUNCH_RECEIPT = PROJECT_ROOT / "outputs/r8r8_native_chain_actual_launch_receipt_20260823.json"
SUPERVISOR_CLAIM = (
    PROJECT_ROOT / "build/pc_r8r8_preimport_source_supervisor_v3_actual_once_20260823"
)
CHILD_PREFIX = PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822"
DESIGN_OUTPUT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
ZERO_COUNTS = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "heldout": 0,
    "signer": 0,
    "truth": 0,
}
FIXED_LAUNCH_ENVIRONMENT = {
    "PATH": r"C:\Windows\System32;C:\Windows",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
}


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()


def main(arguments: list[str]) -> int:
    if arguments != [EXACT_ARGUMENT]:
        raise RuntimeError("exact lossless one-shot launch argument is required")
    shim_raw = SHIM.read_bytes()
    if len(shim_raw) != SHIM_SIZE or hashlib.sha256(shim_raw).hexdigest() != SHIM_SHA256:
        raise RuntimeError("sealed native shim bytes drifted")
    governed = (SUPERVISOR_CLAIM, CHILD_PREFIX, DESIGN_OUTPUT)
    if any(path.exists() for path in governed):
        raise RuntimeError("one-shot claim, child prefix, or design output already exists")
    if any(path.exists() for path in (STDOUT_CAPTURE, STDERR_CAPTURE, LAUNCH_RECEIPT)):
        raise RuntimeError("lossless launch evidence identity already exists")
    completed = subprocess.run(
        (str(SHIM), SHIM_ARGUMENT),
        cwd=PROJECT_ROOT,
        env=FIXED_LAUNCH_ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=1200,
    )
    _write_new(STDOUT_CAPTURE, completed.stdout)
    _write_new(STDERR_CAPTURE, completed.stderr)
    lines = [line for line in completed.stdout.splitlines() if line]
    parsed = [json.loads(line) for line in lines]
    after = tuple(path.exists() for path in governed)
    terminal = {
        "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
        "design_output_exists": after[2],
        "exit_code": completed.returncode,
        "managed_receipt_status": None if len(parsed) < 2 else parsed[1].get("status"),
        "schema_version": "expected_pe.r8.r8.native_chain.lossless_launch_receipt.v1",
        "shim_file_id_contract": "45042100000018000000000000000000",
        "shim_raw_sha256": SHIM_SHA256,
        "stderr_raw_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stderr_size_bytes": len(completed.stderr),
        "stdout_json_line_count": len(lines),
        "stdout_raw_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stdout_size_bytes": len(completed.stdout),
        "supervisor_claim_exists": after[0],
        "supervisor_receipt_status": None if not parsed else parsed[0].get("status"),
        "child_prefix_exists": after[1],
    }
    success = (
        completed.returncode == 0
        and completed.stderr == b""
        and len(parsed) == 2
        and parsed[0].get("status")
        == "PASS_FIXED_FREEZER_EXIT_SOURCE_RUNTIME_DACL_PROCESS_CONTINUITY_NO_AUTHORITY"
        and parsed[1].get("status")
        == "PASS_PREPYTHON_FILE_DACL_CUSTODY_AND_FIXED_V3_CHILD_NO_AUTHORITY"
        and parsed[0].get("authority_generation_fresh_truth_heldout_signer_counts") == ZERO_COUNTS
        and parsed[1].get("authority_generation_fresh_truth_heldout_signer_counts") == ZERO_COUNTS
        and after == (True, True, True)
    )
    terminal["status"] = (
        "PASS_SEALED_NATIVE_CHAIN_STATIC_FREEZE_ONCE_LOSSLESSLY_CAPTURED"
        if success
        else "FAIL_SEALED_NATIVE_CHAIN_STATIC_FREEZE_TERMINAL_NO_RETRY"
    )
    encoded = json.dumps(
        terminal,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    _write_new(LAUNCH_RECEIPT, encoded)
    print(encoded.decode("ascii"))
    if not success:
        raise RuntimeError("sealed native chain did not produce the exact terminal receipts")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
