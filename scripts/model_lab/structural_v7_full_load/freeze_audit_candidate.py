"""Freeze Structural V7 full-load source/tests for independent audit."""

# ruff: noqa: E402 -- dependency verification precedes research/numerical imports.

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


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_full_load_audit_20260820"
TEST_FILES = (
    "tests/model_lab/test_structural_v7_contracts.py",
    "tests/model_lab/test_structural_v7_folds_preflight.py",
    "tests/model_lab/test_structural_v7_models.py",
    "tests/model_lab/test_structural_v7_v2.py",
    "tests/model_lab/test_structural_v7_full_load.py",
)


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
    parser = argparse.ArgumentParser(description="Freeze Structural full-load audit")
    parser.add_argument("--ruff", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        load_design_lock,
        load_preflight,
        verify_full_dependency_freeze,
    )

    dependency_receipt = verify_full_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    design = load_design_lock(ROOT)
    preflight = load_preflight(ROOT)
    ruff = args.ruff
    if ruff is None:
        found = shutil.which("ruff")
        if found is None:
            fallback = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
            if not fallback.is_file():
                raise FileNotFoundError("ruff executable not found")
            ruff = fallback
        else:
            ruff = Path(found)
    pytest_result = _run([sys.executable, "-m", "pytest", "-q", *TEST_FILES])
    ruff_result = _run(
        [
            str(ruff),
            "check",
            "research/model_zoo/structural_v7_full_load",
            "scripts/model_lab/structural_v7_full_load",
            *TEST_FILES,
        ]
    )
    if pytest_result["exit_code"] != 0 or ruff_result["exit_code"] != 0:
        raise RuntimeError("Structural full-load lightweight validation failed")
    if verify_full_dependency_freeze(ROOT) != dependency_receipt:
        raise RuntimeError("Structural full-load dependency bytes changed during validation")

    inventory_paths = [
        *sorted((ROOT / "research/model_zoo/structural_v7_full_load").glob("*.py")),
        *sorted((ROOT / "scripts/model_lab/structural_v7_full_load").glob("*.py")),
        *(ROOT / relative for relative in TEST_FILES),
    ]
    inventory = [_record(path) for path in inventory_paths]
    design_path = (
        ROOT / "outputs/model_zoo_structural_v7_full_load_design_20260820/DESIGN_LOCK.json"
    )
    dependency_path = (
        ROOT
        / "outputs/model_zoo_structural_v7_full_load_dependency_20260820/"
        "DEPENDENCY_MANIFEST.json"
    )
    preflight_path = (
        ROOT / "outputs/model_zoo_structural_v7_full_load_preflight_20260820/PREFLIGHT.json"
    )
    post_pin_path = (
        ROOT / "research/model_zoo/structural_v7_full_load/post_freeze_pins.py"
    )
    payload = {
        "format_version": 1,
        "mode": "structural_v7_full_load_independent_audit_candidate",
        "status": "AUDIT_READY_HEAVY_RUN_NOT_STARTED_ROOT_APPROVAL_REQUIRED",
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "common_full_load_lock_raw_sha256": design[
            "common_full_load_lock_raw_sha256"
        ],
        "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
        "preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
        "design_manifest_sha256": design["manifest_sha256"],
        "preflight_manifest_sha256": preflight["manifest_sha256"],
        "design_record": _record(design_path),
        "dependency_record": _record(dependency_path),
        "preflight_record": _record(preflight_path),
        "post_freeze_pin_record": _record(post_pin_path),
        "dependency_receipt": dependency_receipt.as_dict(),
        "resource_receipt": resource_receipt.as_dict(),
        "lane_gpu_usage": design["lane_gpu_usage"],
        "candidate_count": design["candidate_count"],
        "base_task_count": preflight["base_task_count"],
        "candidate_task_count": preflight["candidate_task_count"],
        "expected_prediction_rows": preflight["expected_prediction_rows"],
        "fit_calls_executed": 0,
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
        "estimated_runtime": {
            "basis": (
                "740 CPU base fits plus 620 ExtraTrees, 620 spline residual, 310 "
                "state-space, 620 decomposition, and 930 blend/simplex outer calls; "
                "32 spawn workers, inner1"
            ),
            "planning_range_minutes": [10, 45],
            "uncertainty": "state-space optimizer and Windows spawn variability",
        },
        "independent_audit_questions": [
            "Does every parent and spawned worker verify frozen dependencies first?",
            "Are CPU0-31, outer<=32, inner1 and RAM80/free12 re-attested?",
            "Is GPU visible only because of the common lock and unused by all candidates?",
            "Is the two-stage task graph exactly 740 plus 3,100 with no retries?",
            "Does exact 71,280-row identity pass before artifact publication and truth?",
            "Are outputs exploration-only and the root launch token still required?",
        ],
    }
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural full-load audit exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    audit_raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    audit_path = OUTPUT / "AUDIT_CANDIDATE.json"
    audit_path.write_bytes(audit_raw)
    report = (
        "# Structural V7 Full-Load Audit Candidate\n\n"
        "Status: `AUDIT_READY_HEAVY_RUN_NOT_STARTED_ROOT_APPROVAL_REQUIRED`\n\n"
        "- Common full-load and transitive V7 V2 bytes are frozen.\n"
        "- Two-stage 32-process launcher: 740 base + 3,100 candidate tasks.\n"
        "- Exact expected identity: 71,280 prediction rows.\n"
        "- GPU visible under common lock, not selected by any Structural estimator.\n"
        "- No fit, prediction, truth, or score has run.\n"
        "- Planning runtime: 10-45 minutes; root approval still required.\n"
    )
    report_path = OUTPUT / "REPORT.md"
    report_path.write_text(report, encoding="utf-8", newline="\n")
    checksum_paths = [
        design_path,
        dependency_path,
        preflight_path,
        post_pin_path,
        *inventory_paths,
        audit_path,
        report_path,
    ]
    checksum_rows = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}"
        for path in dict.fromkeys(checksum_paths)
    ]
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        "\n".join(checksum_rows) + "\n", encoding="utf-8", newline="\n"
    )
    print(hashlib.sha256(audit_raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
