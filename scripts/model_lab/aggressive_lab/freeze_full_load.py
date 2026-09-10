"""Freeze the superseding full-load resource contract without changing V1 evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

# ruff: noqa: E402

ROOT = Path(__file__).resolve().parents[3]
for item in (ROOT, ROOT / "src"):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from research.model_zoo.aggressive_lab.contracts import canonical_json_bytes
from research.model_zoo.aggressive_lab.full_load_resources import (
    CPU_IDS,
    CPU_INNER_THREADS,
    EXPECTED_GPU_NAME,
    GPU_INDEX,
    MAX_OUTER_WORKERS,
    RAM_MIN_FREE_GIB,
    RAM_SOFT_BUDGET_GIB,
    seal_full_load_process,
)


OUTPUT = ROOT / "outputs/model_zoo_aggressive_full_load_20260820"
SOURCES = (
    "research/model_zoo/aggressive_lab/contracts.py",
    "research/model_zoo/aggressive_lab/full_load_resources.py",
    "scripts/model_lab/aggressive_lab/freeze_full_load.py",
    "tests/model_lab/test_aggressive_full_load.py",
)
PARENT_DESIGN = "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit("full-load design output already exists")
    receipt = seal_full_load_process(outer_workers=MAX_OUTER_WORKERS).as_dict()
    payload = {
        "schema_version": "expected_pe.aggressive_full_load.v1",
        "mode": "FULL_LOAD_7950X3D_RTX5080_96GB",
        "supersedes_resource_mode_only": "BATTLEGROUND_CPU_16_31_GPU_SEALED",
        "lane_labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "parent_design_raw_sha256": _sha(ROOT / PARENT_DESIGN),
        "cpu_ids": list(CPU_IDS),
        "max_outer_workers": MAX_OUTER_WORKERS,
        "cpu_inner_threads": CPU_INNER_THREADS,
        "ram_soft_budget_gib": RAM_SOFT_BUDGET_GIB,
        "ram_min_free_gib": RAM_MIN_FREE_GIB,
        "gpu": {
            "index": GPU_INDEX,
            "expected_name": EXPECTED_GPU_NAME,
            "enabled": True,
            "max_concurrent_gpu_candidates": 1,
            "cpu_only_candidates_must_not_select_gpu": True,
        },
        "launch_probe": receipt,
        "source_sha256": {name: _sha(ROOT / name) for name in SOURCES},
        "heavy_execution_authority": True,
        "fresh_or_heldout_authority": False,
        "production_promotion_authority": False,
    }
    raw = canonical_json_bytes(payload)
    OUTPUT.mkdir(parents=True)
    (OUTPUT / "DESIGN_LOCK.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (OUTPUT / "DESIGN_LOCK.sha256").write_text(
        f"{digest}  DESIGN_LOCK.json\n", encoding="utf-8", newline="\n"
    )
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
