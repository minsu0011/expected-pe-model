from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from research.model_zoo.hofs_robustness_revision_r3.contracts import (
    HofsRobustnessContractError,
)
from research.model_zoo.hofs_robustness_revision_r3.final_freeze import (
    SELECTED_ID,
    SELECTED_WEIGHT,
    verify_checksum_ledger,
)


def _make_ledger(root: Path, payload: bytes) -> str:
    root.mkdir()
    (root / "PAYLOAD.bin").write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    ledger = f"{digest}  PAYLOAD.bin\n".encode("ascii")
    (root / "CHECKSUMS.sha256").write_bytes(ledger)
    return hashlib.sha256(ledger).hexdigest()


def test_final_identity_and_weight_are_exact() -> None:
    assert SELECTED_ID == "hofs_r3_global_log_shrink_w0500"
    assert SELECTED_WEIGHT == 0.5


def test_checksum_ledger_verifier_reopens_complete_universe(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    expected = _make_ledger(root, b"frozen")
    receipt = verify_checksum_ledger(root, expected)
    assert receipt["ledger_entry_count"] == 1
    assert receipt["failures"] == 0
    assert receipt["extra_files"] == 0


def test_checksum_ledger_verifier_rejects_mutation(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    expected = _make_ledger(root, b"frozen")
    (root / "PAYLOAD.bin").write_bytes(b"mutated")
    with pytest.raises(HofsRobustnessContractError):
        verify_checksum_ledger(root, expected)
