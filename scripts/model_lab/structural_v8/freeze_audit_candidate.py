"""Freeze Structural V8 design/source/tests for independent audit."""

# ruff: noqa: E402 -- dependency verification precedes research imports.

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

OUTPUT = ROOT / "outputs/model_zoo_structural_v8_audit_20260820"
TEST_FILES = ("tests/model_lab/test_structural_v8.py",)


def _record(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _run(command: list[str]) -> dict[str, object]:
    environment = os.environ.copy()
    inherited = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(ROOT), str(SRC), inherited) if value
    )
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Freeze Structural V8 audit")
    parser.add_argument("--ruff", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from research.model_zoo.structural_v8.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        SMOKE_RAW_SHA256,
        load_design_lock,
        load_preflight,
        load_smoke,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    design = load_design_lock(ROOT)
    preflight = load_preflight(ROOT)
    smoke = load_smoke(ROOT)
    ruff = args.ruff
    if ruff is None:
        found = shutil.which("ruff")
        ruff = (
            Path(found)
            if found is not None
            else Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
        )
    if not ruff.is_file():
        raise FileNotFoundError("ruff executable not found")
    pytest_result = _run([sys.executable, "-m", "pytest", "-q", *TEST_FILES])
    ruff_result = _run(
        [
            str(ruff),
            "check",
            "research/model_zoo/structural_v8",
            "scripts/model_lab/structural_v8",
            *TEST_FILES,
        ]
    )
    if pytest_result["exit_code"] != 0 or ruff_result["exit_code"] != 0:
        raise RuntimeError("Structural V8 lightweight validation failed")
    if verify_dependency_freeze(ROOT) != dependency_receipt:
        raise RuntimeError("Structural V8 frozen bytes changed during validation")
    inventory_paths = [
        *sorted((ROOT / "research/model_zoo/structural_v8").glob("*.py")),
        *sorted((ROOT / "scripts/model_lab/structural_v8").glob("*.py")),
        *(ROOT / relative for relative in TEST_FILES),
    ]
    inventory = [_record(path) for path in inventory_paths]
    artifact_paths = {
        "design_record": ROOT
        / "outputs/model_zoo_structural_v8_design_v2_20260820/DESIGN_LOCK.json",
        "dependency_record": ROOT
        / "outputs/model_zoo_structural_v8_dependency_20260820/DEPENDENCY_MANIFEST.json",
        "preflight_record": ROOT
        / "outputs/model_zoo_structural_v8_preflight_20260820/PREFLIGHT.json",
        "smoke_record": ROOT
        / "outputs/model_zoo_structural_v8_smoke_20260820/SMOKE.json",
        "post_freeze_pin_record": ROOT
        / "research/model_zoo/structural_v8/post_freeze_pins.py",
    }
    payload = {
        "format_version": 1,
        "mode": "structural_v8_independent_audit_candidate",
        "status": "AUDIT_READY_HEAVY_PREDICTION_NOT_STARTED_ROOT_APPROVAL_REQUIRED",
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "fresh_or_heldout_allowed": False,
        "common_full_load_lock_raw_sha256": design[
            "common_full_load_lock_raw_sha256"
        ],
        "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
        "preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
        "smoke_raw_sha256": SMOKE_RAW_SHA256,
        "design_manifest_sha256": design["manifest_sha256"],
        "preflight_manifest_sha256": preflight["manifest_sha256"],
        "smoke_manifest_sha256": smoke["manifest_sha256"],
        **{key: _record(path) for key, path in artifact_paths.items()},
        "dependency_receipt": dependency_receipt.as_dict(),
        "resource_receipt": resource_receipt.as_dict(),
        "candidate_count": design["candidate_count"],
        "candidate_outer_edges": preflight["all_call_receipt"]["edge_count"],
        "expected_prediction_rows": preflight["expected_prediction_rows"],
        "fit_calls_executed_on_spent_data": 0,
        "prediction_rows_generated": 0,
        "evaluation_truth_opened": False,
        "scores_computed": False,
        "heavy_run_started": False,
        "targeted_pytest": pytest_result,
        "targeted_ruff": ruff_result,
        "source_and_test_inventory": inventory,
        "source_and_test_inventory_sha256": hashlib.sha256(
            json.dumps(
                inventory,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "estimated_prediction_runtime": {
            "basis": (
                "310 k32 local-linear, 310 joint partial-pooling, 310 m64 Nyström "
                "RBF fits, and 310 fixed-gate transforms at outer32/inner1"
            ),
            "planning_range_minutes": [2, 15],
            "uncertainty": "Windows spawn and per-worker sealed input loading",
        },
        "independent_audit_questions": [
            "Are all V8 parent and spawned worker imports behind the dependency guard?",
            "Is the task graph exactly 1,240 edges with no retry?",
            "Do all three fit families use only outer-fold training observed labels?",
            "Does the fixed gate consume only sealed V7 OOF predictions and causal probabilities?",
            "Is exact 32,400-row identity required before artifact publication and truth?",
            "Are GPU estimator selection, fresh data, promotion, and scoring still blocked?",
        ],
    }
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V8 audit exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    audit_raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    audit_path = OUTPUT / "AUDIT_CANDIDATE.json"
    audit_path.write_bytes(audit_raw)
    report_path = OUTPUT / "REPORT.md"
    report_path.write_text(
        "# Structural V8 Audit Candidate\n\n"
        "Four distinct-math families and 1,240 exact consumer edges are frozen. "
        "The only execution so far is a small synthetic score-free smoke. Heavy "
        "prediction and the separate evaluator both remain approval-gated.\n",
        encoding="utf-8",
        newline="\n",
    )
    checksum_paths = [*artifact_paths.values(), *inventory_paths, audit_path, report_path]
    rows = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}"
        for path in dict.fromkeys(checksum_paths)
    ]
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        "\n".join(rows) + "\n", encoding="utf-8", newline="\n"
    )
    print(hashlib.sha256(audit_raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
