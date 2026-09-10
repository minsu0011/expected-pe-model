"""Freeze Structural V7 full-load transitive runtime bytes."""

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


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_full_load_dependency_20260820"


def main() -> int:
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        verify_dependency_freeze,
    )

    v2_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.structural_v7_full_load.contracts import (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        V7_V2_DEPENDENCY_RAW_SHA256,
        load_common_full_load_lock,
    )

    common_lock = load_common_full_load_lock(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    from research.model_zoo.structural_v7_full_load.dependency_guard import (
        COMMON_FULL_LOAD_LOCK_RELATIVE,
        COMMON_FULL_LOAD_RESOURCE_RELATIVE,
        EXPECTED_DIRECT_DISTRIBUTIONS,
        FULL_LOAD_DESIGN_RELATIVE,
        POST_FREEZE_PIN_RELATIVE,
        V7_V2_DEPENDENCY_RELATIVE,
        V7_V2_POST_PIN_RELATIVE,
        _current_source_paths,
        sha256_file,
    )

    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural full-load dependency freeze exists: {OUTPUT}")

    def record(relative: str) -> dict[str, object]:
        path = (ROOT / relative).resolve(strict=True)
        path.relative_to(ROOT)
        return {
            "path": relative,
            "bytes": path.stat().st_size,
            "raw_sha256": sha256_file(path),
        }

    executable = Path(sys.executable).resolve(strict=True)
    source_paths = _current_source_paths(ROOT)
    payload = {
        "format_version": 1,
        "mode": "structural_v7_full_load_transitive_dependency_freeze",
        "status": "FROZEN_ROOT_LAUNCH_APPROVAL_REQUIRED",
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "v7_v2_dependency_raw_sha256": V7_V2_DEPENDENCY_RAW_SHA256,
        "interpreter": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable": str(executable),
            "executable_raw_sha256": sha256_file(executable),
        },
        "direct_distributions": {
            name: metadata.version(name) for name in EXPECTED_DIRECT_DISTRIBUTIONS
        },
        "common_full_load_lock": record(COMMON_FULL_LOAD_LOCK_RELATIVE),
        "common_full_load_resource": record(COMMON_FULL_LOAD_RESOURCE_RELATIVE),
        "v7_v2_dependency_manifest": record(V7_V2_DEPENDENCY_RELATIVE),
        "v7_v2_post_freeze_pin": record(V7_V2_POST_PIN_RELATIVE),
        "full_load_design": record(FULL_LOAD_DESIGN_RELATIVE),
        "full_source_closure": [record(relative) for relative in source_paths],
        "post_freeze_pin_exclusion": {
            "path": POST_FREEZE_PIN_RELATIVE.as_posix(),
            "reason": "excluded_to_avoid_cyclic_self_pinning_and_separately_audited",
        },
    }
    if v2_receipt.manifest_raw_sha256 != V7_V2_DEPENDENCY_RAW_SHA256:
        raise RuntimeError("V2 transitive dependency receipt changed")
    if common_lock["source_sha256"][COMMON_FULL_LOAD_RESOURCE_RELATIVE] != (
        payload["common_full_load_resource"]["raw_sha256"]
    ):
        raise RuntimeError("common lock does not pin the full-load resource module")
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "DEPENDENCY_MANIFEST.json"
    path.write_bytes(raw)
    (OUTPUT / "RESOURCE_RECEIPT.json").write_text(
        json.dumps(resource_receipt.as_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report = (
        "# Structural V7 Full-Load Dependency Freeze\n\n"
        f"- New full-load source closure: {len(source_paths)} files.\n"
        "- Structural V7 V2 dependency freeze is verified transitively.\n"
        "- Common full-load lock and resource implementation are byte-pinned.\n"
        "- Python executable and six direct numerical distributions are pinned.\n"
        "- Heavy launch remains blocked pending root-session approval.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
