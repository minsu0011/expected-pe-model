"""Tests for the explicitly user-authorized full-host resource boundary."""

from __future__ import annotations

import pytest

from research.model_zoo.aggressive_lab.contracts import AggressiveLabContractError
from research.model_zoo.aggressive_lab.full_load_resources import (
    CPU_AFFINITY_MASK,
    CPU_IDS,
    EXPECTED_GPU_NAME,
    assert_full_load_process,
    seal_full_load_process,
)


def test_full_load_exact_host_receipt() -> None:
    receipt = seal_full_load_process(outer_workers=32)
    assert receipt.cpu_ids == CPU_IDS == tuple(range(32))
    assert receipt.affinity_mask_hex == f"0x{CPU_AFFINITY_MASK:08X}"
    assert receipt.outer_workers == 32
    assert receipt.cpu_inner_threads == 1
    assert receipt.total_physical_memory_gib >= 90.0
    assert receipt.available_physical_memory_gib >= receipt.ram_min_free_gib
    assert receipt.gpu.name == EXPECTED_GPU_NAME
    assert receipt.gpu.memory_total_mib >= 15_000
    assert receipt.gpu_enabled is True
    inherited = assert_full_load_process(outer_workers=32)
    assert inherited.affinity_mask_hex == receipt.affinity_mask_hex


@pytest.mark.parametrize("workers", [0, 33])
def test_full_load_rejects_worker_count_outside_host(workers: int) -> None:
    with pytest.raises(AggressiveLabContractError, match="between 1 and 32"):
        seal_full_load_process(outer_workers=workers)
