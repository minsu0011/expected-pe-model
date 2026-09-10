"""Run frozen R8-r5 fail-closed probes without contacting the signer."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for value in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.capability import (  # noqa: E402
    CAPABILITY_ENV,
    SECURITY_ATTRIBUTES,
    _create_inheritable_pipe,
    _write_capability_handle,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.contracts import (  # noqa: E402
    AUDITOR_KEY_ID,
    AUTHORITY_DOMAIN_TEXT,
    BYTECODE_BLACKHOLE_RELATIVE,
    DESIGN_ROOT_RELATIVE,
    DGPS,
    EXTERNAL_ANCHOR_RELATIVE,
    HELDOUT_SEEDS,
    QUALIFICATION_SEEDS,
    REGISTRY_RAW_SHA256,
    SIGNER_READINESS_RAW_SHA256,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.publication import (  # noqa: E402
    durably_fsync_tree,
    fsync_directory,
)


RUNTIME_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
LAUNCHER = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/external_launcher.py"
)
RUNTIME_STARTUP_PROBE = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/runtime_startup_probe.py"
)
NEGATIVE_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_builder_frozen_negative_checks_r5_20260821"
)
TOKEN = "de" * 32


def _close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        raise RuntimeError("negative-probe parent handle close failed")


def _handle_flags(handle: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetHandleInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.GetHandleInformation.restype = wintypes.BOOL
    flags = wintypes.DWORD()
    if not kernel32.GetHandleInformation(wintypes.HANDLE(handle), ctypes.byref(flags)):
        raise RuntimeError("negative-probe handle flag readback failed")
    return int(flags.value)


def _isolated_command() -> list[str]:
    blackhole = (PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE).resolve()
    return [
        str(RUNTIME_PYTHON),
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={blackhole}",
        str(LAUNCHER),
    ]


def _child_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update(
        {
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_NUM_THREADS": "1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "NUMEXPR_NUM_THREADS": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
        }
    )
    return environment


def _failure_receipt(stderr: bytes) -> Mapping[str, Any]:
    for line in reversed(stderr.decode("utf-8", errors="replace").splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("status") == "FAIL_CLOSED_BEFORE_GENERATION":
            return payload
    raise RuntimeError("frozen negative check lacked a fail-closed receipt")


def _run_failure(
    name: str,
    command: list[str],
    *,
    environment: Mapping[str, str],
    expected_failure_stage: str,
    stdin: bytes = b"",
    startupinfo: subprocess.STARTUPINFO | None = None,
) -> Mapping[str, Any]:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=dict(environment),
        input=stdin,
        capture_output=True,
        check=False,
        timeout=600,
        close_fds=True,
        startupinfo=startupinfo,
    )
    receipt = _failure_receipt(completed.stderr)
    if (
        completed.returncode != 2
        or receipt.get("protected_generator_imported") is not False
        or receipt.get("payload_generated") is not False
        or receipt.get("truth_vault_latent_opened") is not False
        or receipt.get("failure_stage") != expected_failure_stage
        or completed.stdout
    ):
        raise RuntimeError(f"frozen negative check did not fail closed: {name}")
    return {
        "name": name,
        "command": command,
        "returncode": completed.returncode,
        "stdin_raw_sha256": sha256_bytes(stdin),
        "stdout_raw_sha256": sha256_bytes(completed.stdout),
        "stderr_raw_sha256": sha256_bytes(completed.stderr),
        "failure_receipt": receipt,
    }


def _os_handle_allowlist_probe() -> Mapping[str, Any]:
    frame = b"EPS-R8-R4-ALLOWLISTED-PIPE-OBJECT-MARKER-v1\n"
    unrelated_marker = b"EPS-R8-R4-UNRELATED-PIPE-OBJECT-MARKER-v1\n"
    read_handle, write_handle = _create_inheritable_pipe(frame)
    unrelated_read, unrelated_write = _create_inheritable_pipe(b"")
    read_flags = _handle_flags(read_handle)
    write_flags = _handle_flags(write_handle)
    unrelated_flags = _handle_flags(unrelated_read)
    _write_capability_handle(unrelated_write, unrelated_marker)
    environment = _child_environment()
    environment["R8_PROBE_READ_HANDLE"] = str(read_handle)
    environment["R8_PROBE_UNRELATED_HANDLE"] = str(unrelated_read)
    environment["R8_PROBE_FRAME_SIZE"] = str(len(frame))
    environment["R8_PROBE_UNRELATED_MARKER_HEX"] = unrelated_marker.hex()
    code = """
import ctypes,json,os
from ctypes import wintypes
read_handle=int(os.environ['R8_PROBE_READ_HANDLE'])
unrelated=int(os.environ['R8_PROBE_UNRELATED_HANDLE'])
frame_size=int(os.environ['R8_PROBE_FRAME_SIZE'])
marker=bytes.fromhex(os.environ['R8_PROBE_UNRELATED_MARKER_HEX'])
kernel32=ctypes.WinDLL('kernel32',use_last_error=True)
kernel32.GetHandleInformation.argtypes=(wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD))
kernel32.GetHandleInformation.restype=wintypes.BOOL
kernel32.ReadFile.argtypes=(wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p)
kernel32.ReadFile.restype=wintypes.BOOL
kernel32.PeekNamedPipe.argtypes=(wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD))
kernel32.PeekNamedPipe.restype=wintypes.BOOL

frame_buffer=ctypes.create_string_buffer(frame_size)
frame_read=wintypes.DWORD()
allowed_readfile_succeeded=bool(kernel32.ReadFile(wintypes.HANDLE(read_handle),frame_buffer,frame_size,ctypes.byref(frame_read),None))
frame=frame_buffer.raw[:frame_read.value]

flags=wintypes.DWORD()
numeric_alias_visible=bool(kernel32.GetHandleInformation(wintypes.HANDLE(unrelated),ctypes.byref(flags)))
peek_buffer=ctypes.create_string_buffer(len(marker))
peeked=wintypes.DWORD()
available=wintypes.DWORD()
left=wintypes.DWORD()
ctypes.set_last_error(0)
peek_succeeded=bool(kernel32.PeekNamedPipe(wintypes.HANDLE(unrelated),peek_buffer,len(marker),ctypes.byref(peeked),ctypes.byref(available),ctypes.byref(left)))
peek_last_error=ctypes.get_last_error()
peek_bytes=peek_buffer.raw[:peeked.value] if peek_succeeded else b''
marker_visible=peek_bytes==marker
marker_read_attempted=False
marker_read_confirmed=False
if marker_visible:
    marker_read_attempted=True
    read_buffer=ctypes.create_string_buffer(len(marker))
    marker_read=wintypes.DWORD()
    marker_read_ok=bool(kernel32.ReadFile(wintypes.HANDLE(unrelated),read_buffer,len(marker),ctypes.byref(marker_read),None))
    marker_read_confirmed=marker_read_ok and read_buffer.raw[:marker_read.value]==marker
print(json.dumps({
    'allowed_read_method':'WIN32_READFILE',
    'allowed_readfile_succeeded':allowed_readfile_succeeded,
    'frame_hex':frame.hex(),
    'unrelated_numeric_alias_visible':numeric_alias_visible,
    'unrelated_peek_succeeded':peek_succeeded,
    'unrelated_peek_last_error':peek_last_error,
    'unrelated_peek_bytes_hex':peek_bytes.hex(),
    'unrelated_marker_visible':marker_visible,
    'unrelated_marker_read_attempted':marker_read_attempted,
    'unrelated_marker_read_confirmed':marker_read_confirmed,
},sort_keys=True))
"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.lpAttributeList = {"handle_list": [read_handle]}
    process = subprocess.Popen(
        [str(RUNTIME_PYTHON), "-I", "-S", "-B", "-E", "-c", code],
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        startupinfo=startupinfo,
    )
    _close_handle(read_handle)
    _close_handle(unrelated_read)
    _write_capability_handle(write_handle, frame)
    stdout, stderr = process.communicate(timeout=60)
    if process.returncode != 0:
        raise RuntimeError(f"OS handle allowlist child failed: {stderr[-1000:]!r}")
    payload = json.loads(stdout)
    if (
        payload["allowed_read_method"] != "WIN32_READFILE"
        or payload["allowed_readfile_succeeded"] is not True
        or bytes.fromhex(payload["frame_hex"]) != frame
        or payload["unrelated_marker_visible"] is not False
        or payload["unrelated_marker_read_confirmed"] is not False
    ):
        raise RuntimeError("OS handle object-identity allowlist exclusion failed")
    if not (read_flags & 1) or write_flags & 1 or not (unrelated_flags & 1):
        raise RuntimeError("CreatePipe inherit-flag contract drifted")
    return {
        "name": "OS_HANDLE_ALLOWLIST_EXACT_PIPE_OBJECT_IDENTITY",
        "status": "PASS_EXACT_WIN32_ANONYMOUS_PIPE_OBJECT_ALLOWLIST",
        "security_attributes_size_bytes": ctypes.sizeof(SECURITY_ATTRIBUTES),
        "security_attributes_b_inherit_handle": True,
        "read_handle_inheritable_before_spawn": True,
        "write_handle_inheritable_before_spawn": False,
        "unrelated_handle_inheritable_but_not_allowlisted": True,
        "object_identity_check_method": (
            "PEEK_NAMED_PIPE_UNIQUE_MARKER_AND_CONDITIONAL_READFILE"
        ),
        "allowed_pipe_object_read_via_readfile": True,
        "unrelated_numeric_alias_visible": payload["unrelated_numeric_alias_visible"],
        "unrelated_peek_succeeded": payload["unrelated_peek_succeeded"],
        "unrelated_peek_last_error": payload["unrelated_peek_last_error"],
        "unrelated_object_marker_visible_in_child": False,
        "unrelated_marker_read_attempted": payload["unrelated_marker_read_attempted"],
        "unrelated_pipe_object_inherited": False,
        "allowlisted_handle_count": 1,
        "frame_raw_sha256": sha256_bytes(frame),
        "unrelated_marker_raw_sha256": sha256_bytes(unrelated_marker),
        "child_stdout_raw_sha256": sha256_bytes(stdout),
        "child_stderr_raw_sha256": sha256_bytes(stderr),
    }


def _frozen_runtime_startup_probe(anchor: Mapping[str, Any]) -> Mapping[str, Any]:
    command = [
        str(RUNTIME_PYTHON),
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={(PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE).resolve()}",
        str(RUNTIME_STARTUP_PROBE),
        "--runtime",
        str(PROJECT_ROOT / anchor["runtime_tcb_relative"]),
        "--runtime-sha256",
        anchor["runtime_tcb_raw_sha256"],
        "--source-lock",
        str(PROJECT_ROOT / anchor["source_lock_relative"]),
        "--source-lock-sha256",
        anchor["source_lock_raw_sha256"],
    ]
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=_child_environment(),
        capture_output=True,
        check=False,
        timeout=600,
        close_fds=True,
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError("frozen isolated runtime/startup probe failed")
    child = json.loads(completed.stdout)
    if (
        child.get("status") != "PASS_NO_UNSEALED_STARTUP_OR_NATIVE_MODULE_ORIGIN"
        or child.get("unsealed_loaded_origin_count") != 0
        or child.get("protected_generator_import_count") != 0
        or child.get("payload_generation_count") != 0
        or child.get("truth_vault_latent_open_count") != 0
        or child.get("registry_mutation_count") != 0
        or child.get("qualification_generation_authorized") is not False
    ):
        raise RuntimeError("frozen isolated runtime/startup receipt drifted")
    return {
        "name": "FROZEN_PYTHON310_COMPLETE_RUNTIME_STARTUP_REPLAY",
        "status": "PASS_NO_UNSEALED_STARTUP_OR_NATIVE_MODULE_ORIGIN",
        "command": command,
        "returncode": completed.returncode,
        "stdout_raw_sha256": sha256_bytes(completed.stdout),
        "stderr_raw_sha256": sha256_bytes(completed.stderr),
        "child_receipt": child,
    }


def _malformed_inherited_capability_probe() -> Mapping[str, Any]:
    malformed = b'\x00\x00\x00\x02{}'
    read_handle, write_handle = _create_inheritable_pipe(malformed)
    environment = _child_environment()
    environment[CAPABILITY_ENV] = str(read_handle)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.lpAttributeList = {"handle_list": [read_handle]}
    process = subprocess.Popen(
        _isolated_command(),
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        startupinfo=startupinfo,
    )
    _close_handle(read_handle)
    _write_capability_handle(write_handle, malformed)
    stdout, stderr = process.communicate(timeout=600)
    receipt = _failure_receipt(stderr)
    if (
        process.returncode != 2
        or receipt.get("protected_generator_imported") is not False
        or receipt.get("payload_generated") is not False
        or receipt.get("truth_vault_latent_opened") is not False
        or receipt.get("failure_stage") != "INHERITED_CAPABILITY_VALIDATION"
        or stdout
    ):
        raise RuntimeError("valid inherited pipe with malformed capability did not fail closed")
    return {
        "name": "VALID_INHERITED_PIPE_MALFORMED_CAPABILITY",
        "command": _isolated_command(),
        "returncode": process.returncode,
        "malformed_frame_raw_sha256": sha256_bytes(malformed),
        "stdout_raw_sha256": sha256_bytes(stdout),
        "stderr_raw_sha256": sha256_bytes(stderr),
        "failure_receipt": receipt,
    }


def _invalid_in_memory_authority(anchor: Mapping[str, Any], anchor_raw: bytes) -> Mapping[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "expected_pe.r8.r5.qualification.signed_authority.v1",
        "action": "ACTIVATE_ONCE",
        "stage": "QUALIFICATION",
        "activation_token_sha256": sha256_bytes(TOKEN.encode("ascii")),
        "audit_json_raw_sha256": "1" * 64,
        "audit_seal_raw_sha256": "2" * 64,
        "authority_domain": AUTHORITY_DOMAIN_TEXT,
        "custody_signer_key_id": AUDITOR_KEY_ID,
        "design_checksums_raw_sha256": anchor["design_checksums_raw_sha256"],
        "external_anchor_raw_sha256": sha256_bytes(anchor_raw),
        "source_lock_raw_sha256": anchor["source_lock_raw_sha256"],
        "source_archive_raw_sha256": anchor["source_archive_raw_sha256"],
        "runtime_tcb_raw_sha256": anchor["runtime_tcb_raw_sha256"],
        "signer_readiness_raw_sha256": SIGNER_READINESS_RAW_SHA256,
        "registry_raw_sha256": REGISTRY_RAW_SHA256,
        "qualification_seed_ids": list(QUALIFICATION_SEEDS),
        "heldout_seed_ids": list(HELDOUT_SEEDS),
        "dgp_ids": list(DGPS),
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "permissions": {
            "heldout_generation": False,
            "model_fit_prediction_evaluation_score": False,
            "production_promotion": False,
            "qualification_generation": True,
            "registry_mutation": False,
        },
        "issued_at_utc": (now - timedelta(minutes=1)).isoformat(),
        "expires_at_utc": (now + timedelta(minutes=10)).isoformat(),
        "signature_ed25519_hex": "0" * 128,
    }


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    staging = NEGATIVE_ROOT.parent / f".{NEGATIVE_ROOT.name}.staging"
    anchor_path = PROJECT_ROOT / EXTERNAL_ANCHOR_RELATIVE
    if any(path.exists() for path in (NEGATIVE_ROOT, staging)):
        raise RuntimeError("R8-r5 frozen negative-check root already exists")
    if not anchor_path.is_file() or not RUNTIME_PYTHON.is_file():
        raise RuntimeError("R8-r5 freeze/expected runtime is absent")
    anchor_raw = anchor_path.read_bytes()
    anchor = json.loads(anchor_raw)
    if canonical_json_bytes(anchor) != anchor_raw:
        raise RuntimeError("R8-r5 external anchor is not canonical")
    design_checksums = (PROJECT_ROOT / DESIGN_ROOT_RELATIVE / "CHECKSUMS.sha256").read_bytes()
    if sha256_bytes(design_checksums) != anchor["design_checksums_raw_sha256"]:
        raise RuntimeError("R8-r5 frozen design checksum anchor drifted")
    registry_before = (PROJECT_ROOT / "outputs/v04_spent_seed_registry.json").read_bytes()
    generation_before = sorted(
        path.name
        for path in PROJECT_ROOT.joinpath("outputs").glob(
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation_20*"
        )
    )
    staging.mkdir(exist_ok=False)
    environment = _child_environment()
    checks: list[Mapping[str, Any]] = [
        _os_handle_allowlist_probe(),
        _frozen_runtime_startup_probe(anchor),
    ]
    checks.append(
        _run_failure(
            "DIRECT_TOP_LEVEL_WITHOUT_AUTHORITY",
            _isolated_command(),
            environment=environment,
            expected_failure_stage="TOP_LEVEL_ARGUMENT_VALIDATION",
        )
    )
    forged_environment = dict(environment)
    forged_environment[CAPABILITY_ENV] = "18446744073709551615"
    checks.append(
        _run_failure(
            "FORGED_NONINHERITED_CHILD_HANDLE",
            _isolated_command(),
            environment=forged_environment,
            expected_failure_stage="INHERITED_CAPABILITY_VALIDATION",
        )
    )
    checks.append(_malformed_inherited_capability_probe())
    invalid_authority = _invalid_in_memory_authority(anchor, anchor_raw)
    invalid_envelope = canonical_json_bytes(
        {
            "activation_token": TOKEN,
            "authority": invalid_authority,
            "schema_version": "expected_pe.r8.r5.in_memory_activation_envelope.v1",
        }
    )
    checks.append(
        _run_failure(
            "INVALID_IN_MEMORY_EXACT_KEY_AUTHORITY",
            _isolated_command(),
            environment=environment,
            expected_failure_stage="TOP_LEVEL_IN_MEMORY_AUTHORITY_AND_ACTIVATION",
            stdin=invalid_envelope,
        )
    )
    registry_after = (PROJECT_ROOT / "outputs/v04_spent_seed_registry.json").read_bytes()
    generation_after = sorted(
        path.name
        for path in PROJECT_ROOT.joinpath("outputs").glob(
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation_20*"
        )
    )
    if registry_after != registry_before or generation_after != generation_before:
        raise RuntimeError("frozen negative probes changed registry/generation roots")
    protected = sorted(name for name in sys.modules if name.endswith(".protected_role"))
    if protected:
        raise RuntimeError("negative-probe builder imported protected generator role")
    payload = {
        "schema_version": "expected_pe.r8.r5.builder_frozen_negative_checks.v1",
        "status": "PASS_ALL_R8_R5_FROZEN_NEGATIVE_AND_OS_HANDLE_CHECKS",
        "design_checksums_raw_sha256": anchor["design_checksums_raw_sha256"],
        "external_anchor_raw_sha256": sha256_bytes(anchor_raw),
        "checks": checks,
        "check_count": len(checks),
        "protected_generator_import_count": 0,
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
        "heldout_access_count": 0,
        "fit_prediction_evaluation_score_count": 0,
        "registry_mutation_count": 0,
        "generation_output_roots_created": [],
        "qualification_generation_authorized": False,
        "signer_contact_count": 0,
        "activation_authority_file_created": False,
        "invalid_in_memory_envelope_raw_sha256": sha256_bytes(invalid_envelope),
    }
    _write(staging / "CHECKS.json", canonical_json_bytes(payload))
    report = (
        "# R8-r5 Frozen Negative and Win32 Handle Checks\n\n"
        "All direct/forged/malformed/unsigned paths failed before protected generator import. "
        "The OS probe read the allowlisted pipe through ReadFile and proved that the unique "
        "marker in an unrelated inheritable pipe object was unavailable through PeekNamedPipe, "
        "regardless of numeric-handle alias reuse. The frozen Python 3.10 runtime/startup "
        "preflight reopened every native tree and found zero unsealed loaded origins. No payload "
        "or authority file was created, and the production signer was never contacted.\n"
    ).encode("utf-8")
    _write(staging / "REPORT.md", report)
    checksum_lines = []
    for path in sorted(staging.iterdir(), key=lambda item: item.name):
        checksum_lines.append(f"{sha256_bytes(path.read_bytes())}  {path.name}\n")
    checksums = "".join(checksum_lines).encode("ascii")
    _write(staging / "CHECKSUMS.sha256", checksums)
    durably_fsync_tree(staging)
    os.replace(staging, NEGATIVE_ROOT)
    fsync_directory(NEGATIVE_ROOT.parent)
    print(
        json.dumps(
            {
                "status": payload["status"],
                "root": NEGATIVE_ROOT.relative_to(PROJECT_ROOT).as_posix(),
                "checksums_raw_sha256": sha256_bytes(checksums),
                "check_count": len(checks),
                "authority": False,
                "generation": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
