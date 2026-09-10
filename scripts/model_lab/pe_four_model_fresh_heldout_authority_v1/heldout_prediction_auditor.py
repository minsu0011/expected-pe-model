"""Isolated public-only independent prediction audit entry point."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
_CPU_0_31_MASK = (1 << 32) - 1


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RuntimeError("independent auditor requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise RuntimeError("independent auditor forbids Python environment controls")
    if sys.pycache_prefix is None:
        raise RuntimeError("independent auditor pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RuntimeError("independent auditor pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(
        kernel32.GetCurrentProcess(), ctypes.c_size_t(_CPU_0_31_MASK)
    ):
        raise RuntimeError("independent auditor CPU0-31 affinity assignment failed")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--prediction-root", required=True)
    result.add_argument("--numeric-work-root", required=True)
    result.add_argument("--survivor-freeze-semantic-sha256", required=True)
    result.add_argument("--generation-plan-semantic-sha256", required=True)
    result.add_argument("--common-identity-semantic-sha256", required=True)
    return result


def main() -> int:
    _bootstrap()
    args = parser().parse_args()
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.independent_audit import (
        audit_published_prefix,
    )

    audit = audit_published_prefix(
        project_root=PROJECT_ROOT,
        prediction_root=Path(args.prediction_root),
        numeric_work_root=Path(args.numeric_work_root),
        qualification_survivor_freeze_semantic_sha256=(
            args.survivor_freeze_semantic_sha256
        ),
        generation_plan_semantic_sha256=args.generation_plan_semantic_sha256,
        common_identity_semantic_sha256=args.common_identity_semantic_sha256,
    )
    sys.stdout.buffer.write(canonical_pretty_bytes(audit))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
