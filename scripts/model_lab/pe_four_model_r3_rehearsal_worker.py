"""Cold production-role dispatcher for the non-reserved R3 rehearsal."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
_CPU_0_31_MASK = (1 << 32) - 1


class RehearsalWorkerError(RuntimeError):
    """Fail-closed cold-worker error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RehearsalWorkerError("R3 rehearsal worker requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise RehearsalWorkerError("Python environment controls are forbidden")
    if sys.pycache_prefix is None:
        raise RehearsalWorkerError("R3 rehearsal worker pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RehearsalWorkerError("R3 rehearsal worker pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = str(path.resolve(strict=True))
        if resolved not in sys.path:
            sys.path.append(resolved)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(
        kernel32.GetCurrentProcess(), ctypes.c_size_t(_CPU_0_31_MASK)
    ):
        raise RehearsalWorkerError("R3 rehearsal CPU0-31 assignment failed")
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )

    require_process_resources()


def main() -> int:
    _bootstrap()
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import rehearsal_task
    from scripts.model_lab.pe_four_model_fresh_heldout_authority_v1 import (
        heldout_role_worker,
    )

    # Infrastructure-only injection: every invoked role below is the production role.
    heldout_role_worker._task = rehearsal_task  # noqa: SLF001
    args = heldout_role_worker.parser().parse_args()
    if args.command == "protected-two-pass":
        return heldout_role_worker._protected_two_pass(args)  # noqa: SLF001
    if args.command == "public-two-pass":
        return heldout_role_worker._public_two_pass(args)  # noqa: SLF001
    if args.command == "numeric-bce":
        return heldout_role_worker._numeric_task(args, lane="bce")  # noqa: SLF001
    if args.command == "numeric-c4":
        return heldout_role_worker._numeric_task(args, lane="c4")  # noqa: SLF001
    raise RehearsalWorkerError("R3 rehearsal role is not allowed")


if __name__ == "__main__":
    raise SystemExit(main())
