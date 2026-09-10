"""Check or atomically freeze the score-free R6 qualification-generation design."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.contracts import (  # noqa: E402
    DESIGN_FILE_UNIVERSE,
    DESIGN_OUTPUT_ROOT,
    OUTPUTS_ROOT,
    R6QualificationGenerationError,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.preflight import (  # noqa: E402
    build_bundle_bytes,
    verify_bundle_bytes,
)


def _is_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _fsync_directory(path: Path) -> None:
    if os.name != "nt" or not path.is_dir() or _is_reparse(path):
        raise R6QualificationGenerationError("directory flush requires regular Windows directory")
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
        raise R6QualificationGenerationError(
            f"CreateFileW directory flush failed: {ctypes.get_last_error()}"
        )
    flushed = bool(flush(handle))
    flush_error = ctypes.get_last_error() if not flushed else 0
    closed = bool(close(handle))
    close_error = ctypes.get_last_error() if not closed else 0
    if not flushed:
        raise R6QualificationGenerationError(
            f"FlushFileBuffers directory failed: {flush_error}"
        )
    if not closed:
        raise R6QualificationGenerationError(f"CloseHandle directory failed: {close_error}")


def _write_exclusive(path: Path, content: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _read_exact_bundle(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or _is_reparse(root):
        raise R6QualificationGenerationError("frozen design root is not a regular directory")
    children = tuple(root.iterdir())
    if any(not path.is_file() or _is_reparse(path) for path in children):
        raise R6QualificationGenerationError("frozen design contains a non-regular child")
    names = tuple(sorted(path.name for path in children))
    if names != DESIGN_FILE_UNIVERSE or len({name.casefold() for name in names}) != len(names):
        raise R6QualificationGenerationError("frozen design exact universe drifted")
    return {name: (root / name).read_bytes() for name in names}


def check_only() -> dict[str, Any]:
    bundle = build_bundle_bytes()
    result = verify_bundle_bytes(bundle)
    return {
        **result,
        "status": "PASS_R6_QUALIFICATION_GENERATION_DESIGN_CHECK_NO_WRITE",
        "target": DESIGN_OUTPUT_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "real_generation_count": 0,
        "protected_payload_open_count": 0,
        "live_registry_open_or_mutation_count": 0,
    }


def freeze() -> dict[str, Any]:
    if DESIGN_OUTPUT_ROOT.parent.resolve() != OUTPUTS_ROOT.resolve():
        raise R6QualificationGenerationError("design output escaped exact outputs parent")
    if not OUTPUTS_ROOT.is_dir() or _is_reparse(OUTPUTS_ROOT):
        raise R6QualificationGenerationError("outputs root custody drifted")
    staging = OUTPUTS_ROOT / f".{DESIGN_OUTPUT_ROOT.name}.staging"
    if DESIGN_OUTPUT_ROOT.exists() or staging.exists():
        raise FileExistsError("immutable design target or staging root already exists")
    bundle = build_bundle_bytes()
    expected = verify_bundle_bytes(bundle)
    staging.mkdir(exist_ok=False)
    if _is_reparse(staging):
        raise R6QualificationGenerationError("created staging root is a reparse point")
    for name in DESIGN_FILE_UNIVERSE:
        _write_exclusive(staging / name, bundle[name])
    _fsync_directory(staging)
    staged = verify_bundle_bytes(_read_exact_bundle(staging))
    if staged != expected:
        raise R6QualificationGenerationError("staging verification differs from in-memory design")
    if DESIGN_OUTPUT_ROOT.exists():
        raise FileExistsError("immutable design target appeared before publish")
    os.replace(staging, DESIGN_OUTPUT_ROOT)
    _fsync_directory(OUTPUTS_ROOT)
    if staging.exists() or not DESIGN_OUTPUT_ROOT.is_dir():
        raise R6QualificationGenerationError("atomic design publication failed")
    published = verify_bundle_bytes(_read_exact_bundle(DESIGN_OUTPUT_ROOT))
    if published != staged:
        raise R6QualificationGenerationError("post-publish verification differs")
    return {
        **published,
        "status": "SEALED_R6_QUALIFICATION_GENERATION_DESIGN_FROZEN_STOP_FOR_AUDIT",
        "target": DESIGN_OUTPUT_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "checksums_raw_sha256": sha256_bytes(bundle["CHECKSUMS.sha256"]),
        "real_generation_count": 0,
        "protected_payload_open_count": 0,
        "live_registry_open_or_mutation_count": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    args = parser.parse_args()
    result = check_only() if args.check else freeze()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
