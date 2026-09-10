from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR_PATH = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/trusted_supervisor_v5.py"
)


def _supervisor() -> Any:
    spec = importlib.util.spec_from_file_location(
        "r8r8_preimport_source_supervisor_v5_recovery_under_test",
        SUPERVISOR_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_created_child_accepts_existing_stub_parent_write_handle() -> None:
    """Regress the exact production-only error-32 branch missed by V4."""

    supervisor = _supervisor()
    with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / "build") as temporary:
        parent = Path(temporary)
        stub_parent = supervisor._KERNEL32.CreateFileW(
            str(parent),
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
        assert stub_parent != supervisor.INVALID_HANDLE_VALUE
        held = None
        try:
            with pytest.raises(supervisor.SupervisorError, match="failed.*32"):
                supervisor._open_no_share_write_delete(
                    parent,
                    directory=True,
                    create_child=True,
                )
            held = supervisor._HeldCreatedDirectory(
                parent=parent,
                child_name="v5_exact_child",
            )
            receipt = held.verify()
            assert receipt["direct_child_entry_count"] == 0
            assert receipt["path"] == str(parent / "v5_exact_child")
            supervisor._apply_exact_dacl(held.handle, supervisor.TEST_RESTORE_SDDL)
        finally:
            if held is not None:
                held.close()
            supervisor._close_checked(int(stub_parent))


def test_v5_recovery_paths_are_distinct_from_consumed_v3_and_v4() -> None:
    supervisor = _supervisor()
    assert supervisor.SUPERVISOR_PATH.name == "trusted_supervisor_v5.py"
    assert supervisor.MANIFEST_PATH.name == "SOURCE_CLOSURE_MANIFEST_V5.json"
    assert supervisor.STUB_TEMPLATE_PATH.name == "STDLIB_LAUNCH_STUB_TEMPLATE_V5.txt"
    assert supervisor.SUPERVISOR_CLAIM_PREFIX.name == (
        "pc_r8r8_preimport_source_supervisor_v5_recovery_once_20260823"
    )
