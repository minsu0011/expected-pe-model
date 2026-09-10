"""Freeze practical runtime bytes without cyclic self-pinning."""

from __future__ import annotations

from importlib import metadata
import json
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_dependency_freeze_v2_20260820"


def main() -> int:
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    receipt = seal_battleground_process(outer_workers=1)
    from research.model_zoo.aggressive_lab.contracts import DESIGN_LOCK_RAW_SHA256
    from research.model_zoo.structural_v7.dependency_guard import (
        EXPECTED_DIRECT_DISTRIBUTIONS,
        EXPECTED_LOCAL_DEPENDENCY_PATHS,
        EXPECTED_SHARED_LANE_PATHS,
        POST_FREEZE_PIN_RELATIVE,
        _current_v7_source_paths,
        sha256_file,
    )

    if OUTPUT.exists():
        raise FileExistsError(f"immutable V7 dependency freeze exists: {OUTPUT}")

    def record(relative: str) -> dict[str, object]:
        path = (ROOT / relative).resolve(strict=True)
        path.relative_to(ROOT)
        return {
            "path": relative,
            "bytes": path.stat().st_size,
            "raw_sha256": sha256_file(path),
        }

    design_relative = (
        "outputs/model_zoo_structural_v7_design_v2_20260820/DESIGN_LOCK_V2.json"
    )
    design_path = (ROOT / design_relative).resolve(strict=True)
    executable = Path(sys.executable).resolve(strict=True)
    v7_sources = _current_v7_source_paths(ROOT)
    payload = {
        "format_version": 2,
        "mode": "structural_v7_practical_dependency_freeze",
        "status": "FROZEN_HEAVY_LAUNCH_STILL_BLOCKED",
        "parent_design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "v7_design_lock_v2": {
            "path": design_relative,
            "bytes": design_path.stat().st_size,
            "raw_sha256": sha256_file(design_path),
        },
        "interpreter": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable": str(executable),
            "executable_raw_sha256": sha256_file(executable),
        },
        "direct_distributions": {
            name: metadata.version(name) for name in EXPECTED_DIRECT_DISTRIBUTIONS
        },
        "local_runtime_dependencies": [
            record(relative) for relative in EXPECTED_LOCAL_DEPENDENCY_PATHS
        ],
        "shared_lane_dependencies": [
            record(relative) for relative in EXPECTED_SHARED_LANE_PATHS
        ],
        "v7_source_closure": [record(relative) for relative in v7_sources],
        "post_freeze_pin_exclusion": {
            "path": POST_FREEZE_PIN_RELATIVE.as_posix(),
            "reason": (
                "excluded_to_avoid_cyclic_self_pinning_and_separately_pinned_by_audit_v2"
            ),
        },
    }
    if len(payload["local_runtime_dependencies"]) != 16:
        raise RuntimeError("the practical local runtime dependency inventory is not 16")
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    manifest_path = OUTPUT / "DEPENDENCY_MANIFEST_V2.json"
    manifest_path.write_bytes(raw)
    receipt_raw = json.dumps(
        receipt.as_dict(), ensure_ascii=False, indent=2, allow_nan=False
    ).encode("utf-8") + b"\n"
    (OUTPUT / "RESOURCE_RECEIPT.json").write_bytes(receipt_raw)
    report = (
        "# Structural V7 Practical Dependency Freeze V2\n\n"
        f"- Local runtime dependencies: {len(EXPECTED_LOCAL_DEPENDENCY_PATHS)}\n"
        f"- Shared research-lane dependencies: {len(EXPECTED_SHARED_LANE_PATHS)}\n"
        f"- Structural V7 source closure: {len(v7_sources)}\n"
        f"- Python: {platform.python_implementation()} {platform.python_version()}\n"
        "- Post-freeze pin module: separately audited, excluded to prevent a hash cycle.\n"
        "- Heavy launch: blocked.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
