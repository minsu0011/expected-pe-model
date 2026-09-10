from __future__ import annotations

import ctypes
import importlib.util
import tempfile
from pathlib import Path
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR_PATH = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/trusted_supervisor_v4.py"
)


def _supervisor() -> Any:
    spec = importlib.util.spec_from_file_location(
        "r8r8_preimport_source_supervisor_v4_recovery_under_test",
        SUPERVISOR_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="requires x64 Windows")
def test_parent_inventory_accepts_existing_child_directory_write_handle() -> None:
    """Regress the exact error-32 collision that safely stopped the V3 run.

    A parent-custody holder can enumerate and create children in ``child`` and
    shares READ|WRITE but not DELETE.  Inventory must admit that existing write
    access while retaining its own no-delete share, so replacement stays
    blocked.  V3 used READ-only sharing for the second handle and failed here.
    """

    supervisor = _supervisor()
    with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / "build") as temporary:
        parent = Path(temporary)
        child = parent / "child"
        child.mkdir()
        existing_writer = supervisor._KERNEL32.CreateFileW(
            str(child),
            (
                supervisor.FILE_LIST_DIRECTORY
                | supervisor.FILE_ADD_SUBDIRECTORY
                | supervisor.FILE_TRAVERSE
                | supervisor.FILE_READ_ATTRIBUTES
            ),
            supervisor.FILE_SHARE_READ | supervisor.FILE_SHARE_WRITE,
            None,
            supervisor.OPEN_EXISTING,
            (
                supervisor.FILE_FLAG_OPEN_REPARSE_POINT
                | supervisor.FILE_FLAG_BACKUP_SEMANTICS
            ),
            None,
        )
        assert existing_writer != supervisor.INVALID_HANDLE_VALUE
        try:
            with pytest.raises(supervisor.SupervisorError, match="failed.*32"):
                supervisor._open_no_share_write_delete(child, directory=True)

            inventory = supervisor._directory_inventory(parent)
            assert len(inventory) == 1
            assert inventory[0][0:3] == ["child", "directory", False]
        finally:
            supervisor._close_checked(int(existing_writer))


def test_v4_recovery_paths_and_schema_are_distinct_from_consumed_v3() -> None:
    supervisor = _supervisor()
    assert supervisor.SUPERVISOR_PATH.name == "trusted_supervisor_v4.py"
    assert supervisor.MANIFEST_PATH.name == "SOURCE_CLOSURE_MANIFEST_V4.json"
    assert supervisor.STUB_TEMPLATE_PATH.name == "STDLIB_LAUNCH_STUB_TEMPLATE_V4.txt"
    assert "v4_recovery_once" in supervisor.SUPERVISOR_CLAIM_PREFIX.name
    assert supervisor.SUPERVISOR_CLAIM_PREFIX.name != (
        "pc_r8r8_preimport_source_supervisor_v3_actual_once_20260823"
    )
