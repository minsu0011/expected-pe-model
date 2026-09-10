"""Create the R7 source lock or atomically freeze/check the design bundle."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in reversed((PROJECT_ROOT, PROJECT_ROOT / "src")):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (  # noqa: E402
    DESIGN_FILE_UNIVERSE,
    DESIGN_ROOT,
    EXACT_ENVIRONMENT,
    OUTPUTS_ROOT,
    R7QualificationGenerationError,
    SCRIPT_RELATIVE,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.preflight import (  # noqa: E402
    build_bundle_bytes,
    source_lock_bytes,
    verify_bundle_bytes,
)


SOURCE_LOCK = PROJECT_ROOT / SCRIPT_RELATIVE / "SOURCE_LOCK.json"
BOOTSTRAP = PROJECT_ROOT / SCRIPT_RELATIVE / "trusted_bootstrap.py"


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _flush_directory(path: Path) -> None:
    if os.name != "nt" or not path.is_dir() or _is_reparse(path):
        raise R7QualificationGenerationError("directory flush requires regular Windows directory")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    flush = kernel32.FlushFileBuffers
    flush.argtypes = (wintypes.HANDLE,)
    flush.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    handle = create_file(
        str(path.resolve()),
        0x40000000,
        0x00000007,
        None,
        3,
        0x02000000,
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise R7QualificationGenerationError("directory flush handle could not be opened")
    try:
        if not flush(handle):
            raise R7QualificationGenerationError("directory flush failed")
    finally:
        close(handle)


def _write_exclusive(path: Path, content: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _environment() -> dict[str, str]:
    allowed = {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    result = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    result.update(EXACT_ENVIRONMENT)
    return result


def _process_check(*, frozen_design_required: bool) -> dict[str, Any]:
    command = [
        str(Path(sys.executable).resolve()),
        "-I",
        "-S",
        "-B",
        "-E",
        str(BOOTSTRAP.resolve(strict=True)),
        "check-only" if frozen_design_required else "check-only-preflight",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=_environment(),
        timeout=300,
    )
    if completed.returncode != 0:
        raise R7QualificationGenerationError(
            f"trusted R7 process check failed: {completed.stderr[-4000:]!r}"
        )
    try:
        payload = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R7QualificationGenerationError("trusted R7 process check output is invalid") from exc
    if payload.get("status") != "PASS_ALL_PROCESS_ROLES_IMPORTED_CHANNELS_AND_PATHS_NO_GENERATION":
        raise R7QualificationGenerationError("trusted R7 process check status drifted")
    return payload


def build_source_lock() -> Mapping[str, Any]:
    if SOURCE_LOCK.exists():
        raise FileExistsError("immutable R7 source lock already exists")
    if not SOURCE_LOCK.parent.is_dir() or _is_reparse(SOURCE_LOCK.parent):
        raise R7QualificationGenerationError("R7 script root is invalid")
    content = source_lock_bytes()
    _write_exclusive(SOURCE_LOCK, content)
    _flush_directory(SOURCE_LOCK.parent)
    if SOURCE_LOCK.read_bytes() != content:
        raise R7QualificationGenerationError("published source lock changed")
    return {
        "status": "R7_SOURCE_LOCK_FROZEN_PATCH_BOOTSTRAP_ANCHOR_NEXT",
        "source_lock_relative": SOURCE_LOCK.relative_to(PROJECT_ROOT).as_posix(),
        "source_lock_raw_sha256": sha256_bytes(content),
        "source_lock_bytes": len(content),
    }


def _read_frozen_bundle() -> dict[str, bytes]:
    if not DESIGN_ROOT.is_dir() or _is_reparse(DESIGN_ROOT):
        raise R7QualificationGenerationError("frozen R7 design root is invalid")
    children = tuple(DESIGN_ROOT.iterdir())
    names = tuple(sorted(path.name for path in children))
    if names != DESIGN_FILE_UNIVERSE or any(
        not path.is_file() or _is_reparse(path) for path in children
    ):
        raise R7QualificationGenerationError("frozen R7 design exact universe drifted")
    return {name: (DESIGN_ROOT / name).read_bytes() for name in names}


def check_preflight() -> Mapping[str, Any]:
    process = _process_check(frozen_design_required=False)
    bundle = build_bundle_bytes(process)
    result = verify_bundle_bytes(bundle)
    return {
        **result,
        "status": "PASS_R7_DESIGN_PREFLIGHT_CHECK_NO_WRITE_NO_GENERATION",
        "target": DESIGN_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "process_check": process["status"],
    }


def freeze() -> Mapping[str, Any]:
    if DESIGN_ROOT.parent.resolve() != OUTPUTS_ROOT.resolve() or _is_reparse(OUTPUTS_ROOT):
        raise R7QualificationGenerationError("R7 design output parent custody drifted")
    staging = OUTPUTS_ROOT / f".{DESIGN_ROOT.name}.staging"
    if DESIGN_ROOT.exists() or staging.exists():
        raise FileExistsError("immutable R7 design target or staging already exists")
    process = _process_check(frozen_design_required=False)
    bundle = build_bundle_bytes(process)
    expected = verify_bundle_bytes(bundle)
    staging.mkdir(exist_ok=False)
    if _is_reparse(staging):
        raise R7QualificationGenerationError("created R7 design staging is reparse")
    for name in DESIGN_FILE_UNIVERSE:
        _write_exclusive(staging / name, bundle[name])
    _flush_directory(staging)
    staged = {name: (staging / name).read_bytes() for name in DESIGN_FILE_UNIVERSE}
    if verify_bundle_bytes(staged) != expected or staged != bundle:
        raise R7QualificationGenerationError("staged R7 design differs from memory")
    if DESIGN_ROOT.exists():
        raise FileExistsError("R7 design target appeared before publish")
    os.replace(staging, DESIGN_ROOT)
    _flush_directory(OUTPUTS_ROOT)
    published = _read_frozen_bundle()
    if verify_bundle_bytes(published) != expected or published != staged:
        raise R7QualificationGenerationError("published R7 design differs from staging")
    return {
        **expected,
        "status": "SEALED_R7_QUALIFICATION_GENERATION_REPAIR_STOP_FOR_INDEPENDENT_AUDIT",
        "target": DESIGN_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "generation_count": 0,
        "protected_payload_open_count": 0,
        "registry_mutation_count": 0,
        "qualification_activation_authorized": False,
        "heldout_activation_authorized": False,
    }


def check_frozen() -> Mapping[str, Any]:
    result = verify_bundle_bytes(_read_frozen_bundle())
    process = _process_check(frozen_design_required=True)
    return {
        **result,
        "status": "PASS_FROZEN_R7_DESIGN_AND_PROCESS_CHECK_NO_GENERATION",
        "target": DESIGN_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "process_check": process["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build-source-lock", action="store_true")
    mode.add_argument("--check-preflight", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--check-frozen", action="store_true")
    args = parser.parse_args()
    if args.build_source_lock:
        result = build_source_lock()
    elif args.check_preflight:
        result = check_preflight()
    elif args.freeze:
        result = freeze()
    else:
        result = check_frozen()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
