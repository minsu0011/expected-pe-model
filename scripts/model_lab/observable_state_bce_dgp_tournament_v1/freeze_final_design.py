from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
from typing import Any

from research.model_zoo.observable_state_bce_dgp_tournament_v1.bindings_r4 import (
    INDEPENDENT_AUDIT_BINDING_R4,
    PUBLIC_INPUT_BINDING_R4,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.contracts import (
    EXPECTED_COMMON_IDENTITIES,
    EXPECTED_FOLD_BLOCKS,
    EXPECTED_STATE_MODEL_FITS,
    EXPECTED_TASK_COUNT,
    RESOURCE_POLICY,
    TOURNAMENT_CANDIDATE_IDS,
    canonical_json_bytes,
    design_preview_sha256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.runner import (
    EXPECTED_FINAL_DESIGN_ROOT,
    build_final_design_payload,
    ram_guard_receipt,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.source_audit import (
    audit_source_boundary,
)


ACTIVATION_LITERAL = "FREEZE_R4_OBSERVABLE_STATE_BCE_DGP_FINAL_DESIGN_SCORE_BLIND"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new(path: Path, payload: Any) -> str:
    raw = canonical_json_bytes(payload) + b"\n"
    if path.exists():
        raise RuntimeError(f"immutable design artifact already exists: {path.name}")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _source_paths(root: Path) -> tuple[Path, ...]:
    package = root / "research/model_zoo/observable_state_bce_dgp_tournament_v1"
    script_root = root / "scripts/model_lab/observable_state_bce_dgp_tournament_v1"
    paths = {
        *package.glob("*.py"),
        package / "DESIGN_PREVIEW.md",
        *script_root.glob("*.py"),
        root / "tests/model_lab/test_observable_state_bce_dgp_tournament_v1.py",
        root / "pyproject.toml",
    }
    if any(not path.is_file() for path in paths):
        raise RuntimeError("final-design source closure is incomplete")
    return tuple(sorted(paths))


def freeze(project_root: Path, *, activation: str) -> dict[str, Any]:
    if activation != ACTIVATION_LITERAL:
        raise RuntimeError("final-design freeze activation differs")
    root = project_root.resolve(strict=True)
    destination = (root / EXPECTED_FINAL_DESIGN_ROOT).resolve()
    outputs = (root / "outputs").resolve(strict=True)
    if destination.parent != outputs or destination.exists():
        raise RuntimeError("immutable final-design destination is unsafe or already exists")

    design = build_final_design_payload(
        project_root=root,
        public_binding=PUBLIC_INPUT_BINDING_R4,
        independent_audit_binding=INDEPENDENT_AUDIT_BINDING_R4,
    )
    source_audit = audit_source_boundary()
    source_records = [
        {
            "relative_path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "raw_sha256": _sha256_file(path),
        }
        for path in _source_paths(root)
    ]
    source_closure = {
        "schema_version": "expected_pe.observable_state_bce_dgp.source_closure.v1",
        "status": "PASS_EXACT_SCORE_BLIND_SOURCE_CLOSURE",
        "design_preview_sha256": design_preview_sha256(),
        "source_boundary_audit_semantic_sha256": source_audit["audit_semantic_sha256"],
        "records": source_records,
        "record_count": len(source_records),
        "truth_or_evaluator_source_included": False,
        "truth_payload_opened": False,
        "score_computed": False,
    }

    memory = ram_guard_receipt()
    total_gib = memory["total_physical_memory_gib"]
    available_gib = memory["available_physical_memory_gib_at_launch"]
    if (os.cpu_count() or 0) < 32:
        raise RuntimeError("preflight requires at least 32 logical CPUs")
    if total_gib < RESOURCE_POLICY.ram_soft_budget_gib + RESOURCE_POLICY.ram_min_free_gib:
        raise RuntimeError("preflight RAM cannot satisfy frozen budget and reserve")
    if available_gib < RESOURCE_POLICY.ram_min_free_gib:
        raise RuntimeError("preflight available RAM is below reserve")

    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging.", dir=outputs)
    ).resolve()
    published = False
    try:
        design_sha = _write_new(staging / "DESIGN_LOCK.json", design)
        source_closure_sha = _write_new(staging / "SOURCE_CLOSURE.json", source_closure)
        preflight = {
            "schema_version": "expected_pe.observable_state_bce_dgp.preflight.v1",
            "status": "PASS_FROZEN_READY_FOR_PREDICTION_ONLY",
            "design_lock_raw_sha256": design_sha,
            "source_closure_raw_sha256": source_closure_sha,
            "public_input_binding": {
                "relative_root": PUBLIC_INPUT_BINDING_R4.relative_root,
                "freeze_receipt_raw_sha256": (
                    PUBLIC_INPUT_BINDING_R4.freeze_receipt_raw_sha256
                ),
                "checksums_raw_sha256": PUBLIC_INPUT_BINDING_R4.checksums_raw_sha256,
            },
            "independent_audit_binding": {
                "relative_root": INDEPENDENT_AUDIT_BINDING_R4.relative_root,
                "audit_raw_sha256": INDEPENDENT_AUDIT_BINDING_R4.audit_raw_sha256,
                "audit_semantic_sha256": (
                    INDEPENDENT_AUDIT_BINDING_R4.audit_semantic_sha256
                ),
                "audit_sha256_file_raw_sha256": (
                    INDEPENDENT_AUDIT_BINDING_R4.audit_sha256_file_raw_sha256
                ),
                "seal_receipt_raw_sha256": (
                    INDEPENDENT_AUDIT_BINDING_R4.seal_receipt_raw_sha256
                ),
                "checksums_raw_sha256": (
                    INDEPENDENT_AUDIT_BINDING_R4.checksums_raw_sha256
                ),
            },
            "candidate_ids": list(TOURNAMENT_CANDIDATE_IDS),
            "no_parameter_sweep": True,
            "geometry": {
                "tasks": EXPECTED_TASK_COUNT,
                "folds": EXPECTED_FOLD_BLOCKS,
                "state_model_fits": EXPECTED_STATE_MODEL_FITS,
                "prediction_identities": EXPECTED_COMMON_IDENTITIES,
            },
            "resource": {
                "cpu_ids": list(RESOURCE_POLICY.cpu_ids),
                "outer_workers": RESOURCE_POLICY.maximum_outer_workers,
                "inner_threads": RESOURCE_POLICY.inner_threads,
                "gpu_enabled": RESOURCE_POLICY.gpu_enabled,
                "total_physical_memory_gib": total_gib,
                "available_physical_memory_gib": available_gib,
                "ram_soft_budget_gib": RESOURCE_POLICY.ram_soft_budget_gib,
                "ram_min_free_gib": RESOURCE_POLICY.ram_min_free_gib,
            },
            "runtime": {
                "python_executable": str(Path(os.sys.executable).resolve(strict=True)),
                "python_executable_raw_sha256": _sha256_file(
                    Path(os.sys.executable).resolve(strict=True)
                ),
                "python_version": platform.python_version(),
            },
            "focused_tests_required_before_launch": True,
            "ruff_required_before_launch": True,
            "truth_payload_opened": False,
            "score_computed": False,
            "registry_or_champion_mutated": False,
            "seed_changed_or_reserved": False,
        }
        preflight_sha = _write_new(staging / "PREFLIGHT.json", preflight)
        receipt = {
            "schema_version": "expected_pe.observable_state_bce_dgp.design_freeze.v1",
            "status": "PASS_FINAL_DESIGN_ATOMICALLY_FROZEN_PREDICTION_ONLY",
            "design_lock_raw_sha256": design_sha,
            "source_closure_raw_sha256": source_closure_sha,
            "preflight_raw_sha256": preflight_sha,
            "atomic_directory_rename": True,
            "destination_initially_absent": True,
            "prediction_executed": False,
            "truth_payload_opened": False,
            "score_computed": False,
        }
        receipt_sha = _write_new(staging / "FREEZE_RECEIPT.json", receipt)
        checksum_lines = [
            f"{design_sha}  DESIGN_LOCK.json",
            f"{receipt_sha}  FREEZE_RECEIPT.json",
            f"{preflight_sha}  PREFLIGHT.json",
            f"{source_closure_sha}  SOURCE_CLOSURE.json",
        ]
        checksums_raw = ("\n".join(checksum_lines) + "\n").encode("ascii")
        (staging / "CHECKSUMS.sha256").write_bytes(checksums_raw)
        checksums_sha = hashlib.sha256(checksums_raw).hexdigest()
        staging.replace(destination)
        published = True
        return {
            **receipt,
            "freeze_receipt_raw_sha256": receipt_sha,
            "checksums_raw_sha256": checksums_sha,
            "output": str(destination),
        }
    finally:
        if not published and staging.exists():
            import shutil

            shutil.rmtree(staging, ignore_errors=True)


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    result = freeze(root, activation=ACTIVATION_LITERAL)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
