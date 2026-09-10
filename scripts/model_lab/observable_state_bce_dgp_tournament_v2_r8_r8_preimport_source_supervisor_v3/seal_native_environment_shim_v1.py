"""One-shot DACL seal for the fixed native environment shim V1."""

from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SUPERVISOR = Path(__file__).resolve().parent / "trusted_supervisor.py"
EXECUTABLE = PROJECT_ROOT / (
    "build/r8r8_native_environment_shim_v1_immutable_20260823/ExpectedPeNativeEnvironmentShimV1.exe"
)
EXECUTABLE_SHA256 = "c52956ac74ba6f09e20064349283d8f630d347e76062722ac841954e7dde14e2"
EXECUTABLE_SIZE = 80896
EXECUTABLE_VOLUME = 13325047249941796650
EXECUTABLE_FILE_ID = "45042100000018000000000000000000"
RECEIPT = PROJECT_ROOT / (
    "outputs/r8r8_native_environment_shim_v1_immutable_seal_receipt_20260823.json"
)
EXACT_ARGUMENT = "--seal-fixed-native-environment-shim-v1-owner-rights-read-execute-once"
ZERO_COUNTS = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "heldout": 0,
    "signer": 0,
    "truth": 0,
}


def _load_supervisor() -> Any:
    raw = SUPERVISOR.read_bytes()
    if (
        len(raw) != 100124
        or hashlib.sha256(raw).hexdigest()
        != "e8f656ae4fb0d883f38c4ff4428cf1d58a0f4e596974229955cb05134fb81f2f"
    ):
        raise RuntimeError("V3 supervisor drifted before native shim seal")
    spec = importlib.util.spec_from_file_location("native_shim_v1_seal_v3", SUPERVISOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("V3 supervisor loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _open_file_for_dacl(module: Any, path: Path) -> int:
    handle = module._KERNEL32.CreateFileW(
        str(path),
        module.GENERIC_READ | module.FILE_READ_ATTRIBUTES | module.READ_CONTROL | module.WRITE_DAC,
        module.FILE_SHARE_READ,
        None,
        module.OPEN_EXISTING,
        module.FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == module.INVALID_HANDLE_VALUE:
        raise RuntimeError(f"native shim DACL open failed: {ctypes.get_last_error()}")
    return int(handle)


def main(arguments: list[str]) -> int:
    if arguments != [EXACT_ARGUMENT]:
        raise RuntimeError("exact native shim seal argument is required")
    if RECEIPT.exists():
        raise RuntimeError("native shim seal receipt identity already exists")
    raw = EXECUTABLE.read_bytes()
    if len(raw) != EXECUTABLE_SIZE or hashlib.sha256(raw).hexdigest() != EXECUTABLE_SHA256:
        raise RuntimeError("native shim bytes drifted before seal")
    module = _load_supervisor()
    directory = EXECUTABLE.parent
    file_handle = _open_file_for_dacl(module, EXECUTABLE)
    directory_handle = module._open_directory_for_dacl(directory)
    file_original = module._OwnedOriginalDacl(file_handle)
    directory_original = module._OwnedOriginalDacl(directory_handle)
    file_applied = False
    directory_applied = False
    committed = False
    try:
        if module._identity(file_handle) != (EXECUTABLE_VOLUME, EXECUTABLE_FILE_ID):
            raise RuntimeError("native shim identity drifted before seal")
        directory_volume, directory_file_id = module._identity(directory_handle)
        file_original_receipt = dict(file_original.receipt())
        directory_original_receipt = dict(directory_original.receipt())
        expected = dict(module._sddl_dacl_fingerprint(module.PROTECTED_DIRECTORY_READ_ONLY_SDDL))
        module._apply_exact_dacl(file_handle, module.PROTECTED_DIRECTORY_READ_ONLY_SDDL)
        file_applied = True
        file_protected = dict(module._security_snapshot_any(file_handle))
        module._apply_exact_dacl(directory_handle, module.PROTECTED_DIRECTORY_READ_ONLY_SDDL)
        directory_applied = True
        directory_protected = dict(module._security_snapshot_any(directory_handle))
        semantic_keys = ("dacl_raw_sha256", "dacl_size_bytes")
        if (
            any(file_protected[key] != expected[key] for key in semantic_keys)
            or any(directory_protected[key] != expected[key] for key in semantic_keys)
            or file_protected["dacl_protected"] is not True
            or directory_protected["dacl_protected"] is not True
        ):
            raise RuntimeError("native shim immutable DACL fingerprint drifted")
        receipt = {
            "authority_generation_fresh_truth_heldout_signer_counts": ZERO_COUNTS,
            "directory": {
                "file_id_128": directory_file_id,
                "final_path": str(directory),
                "original_dacl": directory_original_receipt,
                "protected_dacl": directory_protected,
                "volume_serial_number": directory_volume,
            },
            "executable": {
                "file_id_128": EXECUTABLE_FILE_ID,
                "final_path": str(EXECUTABLE),
                "original_dacl": file_original_receipt,
                "protected_dacl": file_protected,
                "raw_sha256": EXECUTABLE_SHA256,
                "size_bytes": EXECUTABLE_SIZE,
                "volume_serial_number": EXECUTABLE_VOLUME,
            },
            "protection_sddl": module.PROTECTED_DIRECTORY_READ_ONLY_SDDL,
            "schema_version": "expected_pe.r8.r8.native_environment_shim.immutable_seal.v1",
            "status": "PASS_NATIVE_ENVIRONMENT_SHIM_EXECUTABLE_AND_DIRECTORY_IMMUTABLY_SEALED",
        }
        encoded = json.dumps(
            receipt,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        with RECEIPT.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
        committed = True
        print(encoded.decode("ascii"))
    finally:
        if not committed:
            if directory_applied:
                directory_original.restore(directory_handle)
            if file_applied:
                file_original.restore(file_handle)
        directory_original.close()
        file_original.close()
        module._close_checked(directory_handle)
        module._close_checked(file_handle)
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
