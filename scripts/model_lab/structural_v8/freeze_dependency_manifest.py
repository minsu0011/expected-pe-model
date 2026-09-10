"""Freeze Structural V8 transitive runtime bytes."""

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

OUTPUT = ROOT / "outputs/model_zoo_structural_v8_dependency_20260820"


def main() -> int:
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256 as V7_FULL_DEPENDENCY_RAW_SHA256,
        verify_full_dependency_freeze,
    )

    v7_receipt = verify_full_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    from research.model_zoo.structural_v8.contracts import (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        V7_PREDICTION_MANIFEST_RAW_SHA256,
        V7_TERMINAL_MANIFEST_RAW_SHA256,
        sha256_file,
    )
    from research.model_zoo.structural_v8.dependency_guard import (
        COMMON_LOCK_RELATIVE,
        COMMON_RESOURCE_RELATIVE,
        DESIGN_RELATIVE,
        EXPECTED_DIRECT_DISTRIBUTIONS,
        POST_FREEZE_PIN_RELATIVE,
        V7_FULL_DEPENDENCY_RELATIVE,
        V7_FULL_POST_PIN_RELATIVE,
        V7_PREDICTION_RELATIVE,
        V7_TERMINAL_RELATIVE,
        current_source_paths,
    )

    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V8 dependency exists: {OUTPUT}")

    def record(relative: str) -> dict[str, object]:
        path = (ROOT / relative).resolve(strict=True)
        path.relative_to(ROOT)
        return {
            "path": relative,
            "bytes": path.stat().st_size,
            "raw_sha256": sha256_file(path),
        }

    immutable_paths = (
        COMMON_LOCK_RELATIVE,
        COMMON_RESOURCE_RELATIVE,
        V7_FULL_DEPENDENCY_RELATIVE,
        V7_FULL_POST_PIN_RELATIVE,
        DESIGN_RELATIVE,
        f"{V7_PREDICTION_RELATIVE}/MANIFEST.json",
        f"{V7_PREDICTION_RELATIVE}/predictions.csv",
        f"{V7_PREDICTION_RELATIVE}/diagnostics.csv",
        f"{V7_PREDICTION_RELATIVE}/runtime.json",
        f"{V7_TERMINAL_RELATIVE}/MANIFEST.json",
        f"{V7_TERMINAL_RELATIVE}/TOURNAMENT_REGISTRY.json",
    )
    source_paths = current_source_paths(ROOT)
    executable = Path(sys.executable).resolve(strict=True)
    payload = {
        "format_version": 1,
        "mode": "structural_v8_transitive_dependency_freeze",
        "status": "FROZEN_HEAVY_PREDICTION_APPROVAL_REQUIRED",
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "v7_full_dependency_raw_sha256": V7_FULL_DEPENDENCY_RAW_SHA256,
        "v7_prediction_manifest_raw_sha256": V7_PREDICTION_MANIFEST_RAW_SHA256,
        "v7_terminal_manifest_raw_sha256": V7_TERMINAL_MANIFEST_RAW_SHA256,
        "interpreter": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable": str(executable),
            "executable_raw_sha256": sha256_file(executable),
        },
        "direct_distributions": {
            name: metadata.version(name) for name in EXPECTED_DIRECT_DISTRIBUTIONS
        },
        "immutable_dependencies": [record(relative) for relative in immutable_paths],
        "source_closure": [record(relative) for relative in source_paths],
        "post_freeze_pin_exclusion": {
            "path": POST_FREEZE_PIN_RELATIVE.as_posix(),
            "reason": "excluded_to_avoid_cyclic_self_pinning_and_separately_audited",
        },
    }
    if v7_receipt.manifest_raw_sha256 != V7_FULL_DEPENDENCY_RAW_SHA256:
        raise RuntimeError("V8 V7 dependency receipt changed")
    if payload["immutable_dependencies"][0]["raw_sha256"] != (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256
    ):
        raise RuntimeError("V8 common lock bytes changed")
    if payload["immutable_dependencies"][5]["raw_sha256"] != (
        V7_PREDICTION_MANIFEST_RAW_SHA256
    ):
        raise RuntimeError("V8 V7 prediction manifest bytes changed")
    if payload["immutable_dependencies"][9]["raw_sha256"] != (
        V7_TERMINAL_MANIFEST_RAW_SHA256
    ):
        raise RuntimeError("V8 terminal manifest bytes changed")
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
    (OUTPUT / "REPORT.md").write_text(
        "# Structural V8 Dependency Freeze\n\n"
        f"- V8 source closure: {len(source_paths)} files.\n"
        "- Common full-load, V7 execution dependency, V7 prediction components, "
        "and V7 terminal decision are byte-pinned.\n"
        "- Heavy prediction remains blocked.\n",
        encoding="utf-8",
        newline="\n",
    )
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
