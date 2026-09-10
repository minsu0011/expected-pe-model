"""Exact no-publish entry point for the R8-r8 in-memory static builder."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
EXACT_ARGUMENT = "--verify-two-in-memory-builds-no-publish-no-authority"
PINNED_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_BASE_PYTHON = Path(
    r"C:\Users\minsu\anaconda3\envs\myenv\python.exe"
)


def _python_environment_names() -> tuple[str, ...]:
    return tuple(
        sorted(
            (name for name in os.environ if name.upper().startswith("PYTHON")),
            key=lambda item: (item.casefold(), item),
        )
    )


def _require_exact_launch() -> dict[str, object]:
    prefix_value = sys.pycache_prefix
    if not isinstance(prefix_value, str):
        raise SystemExit("no-publish preflight requires source-owned -X pycache_prefix")
    expected_flags = (
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={prefix_value}",
    )
    entry = str(Path(__file__).resolve())
    expected_orig_argv = (
        str(PINNED_BASE_PYTHON),
        *expected_flags,
        entry,
        EXACT_ARGUMENT,
    )
    python_environment_names = _python_environment_names()
    if sys.argv != [entry, EXACT_ARGUMENT]:
        raise SystemExit("exact no-publish argument required")
    if (
        tuple(sys.orig_argv) != expected_orig_argv
        or sys.executable != str(PINNED_PYTHON)
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or python_environment_names
    ):
        raise SystemExit("no-publish exact command or isolation state drifted")
    return {
        "status": "PASS_EXACT_FULL_COMMAND_AND_PYTHON_ENVIRONMENT_COUNT_ZERO",
        "orig_argv": list(expected_orig_argv),
        "orig_argv_exact_full_equality": True,
        "venv_executable": str(PINNED_PYTHON),
        "base_executable_orig_argv_zero": str(PINNED_BASE_PYTHON),
        "environment_entry_count_inspected": len(os.environ),
        "python_environment_control_names": [],
        "python_environment_control_count": 0,
    }


def main() -> int:
    launch_preflight = _require_exact_launch()
    prefix_value = sys.pycache_prefix
    assert isinstance(prefix_value, str)
    sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "src")]
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.no_bytecode import (
        HeldExistingNoBytecodeWindow,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (
        build_in_memory_receipt,
    )

    with HeldExistingNoBytecodeWindow(
        path=Path(prefix_value), ancestry_root=Path(Path(prefix_value).anchor)
    ) as no_bytecode_window:
        receipt = build_in_memory_receipt()
        receipt["no_bytecode_custody"] = no_bytecode_window.receipt()
        receipt["launch_preflight"] = launch_preflight
    if receipt["future_source_lock_exists"]:
        raise SystemExit("future SOURCE_LOCK already exists; in-memory builder refuses overwrite")
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
