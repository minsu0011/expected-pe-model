"""Freeze the repaired Structural V7 package for independent read-only audit."""

# ruff: noqa: E402 -- dependency verification precedes all research/numerical imports.

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


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_audit_candidate_v2_20260820"
TEST_FILES = (
    "tests/model_lab/test_structural_v7_contracts.py",
    "tests/model_lab/test_structural_v7_folds_preflight.py",
    "tests/model_lab/test_structural_v7_models.py",
    "tests/model_lab/test_structural_v7_v2.py",
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
    parser = argparse.ArgumentParser(description="Freeze Structural V7 V2 audit candidate")
    parser.add_argument("--ruff", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        DEPENDENCY_MANIFEST_V2_RAW_SHA256,
        DESIGN_LOCK_V2_RAW_SHA256,
        PREFLIGHT_V2_RAW_SHA256,
        load_design_lock_v2,
        load_preflight_v2,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    resource_receipt = seal_battleground_process(outer_workers=1)
    from research.model_zoo.aggressive_lab.contracts import (
        DESIGN_LOCK_RAW_SHA256 as PARENT_LOCK_RAW_SHA256,
    )
    from research.model_zoo.structural_v7.contracts import CANDIDATES, sha256_file

    design = load_design_lock_v2(ROOT)
    preflight = load_preflight_v2(ROOT)
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
            "research/model_zoo/structural_v7",
            "scripts/model_lab/structural_v7",
            *TEST_FILES,
        ]
    )
    if pytest_result["exit_code"] != 0 or ruff_result["exit_code"] != 0:
        raise RuntimeError("Structural V7 V2 lightweight validation failed")
    final_dependency_receipt = verify_dependency_freeze(ROOT)
    if final_dependency_receipt != dependency_receipt:
        raise RuntimeError("dependency verification changed during lightweight validation")

    inventory_paths = [
        *sorted((ROOT / "research/model_zoo/structural_v7").glob("*.py")),
        *sorted((ROOT / "scripts/model_lab/structural_v7").glob("*.py")),
        *(ROOT / relative for relative in TEST_FILES),
    ]
    inventory = [_record(path) for path in inventory_paths]
    dependency_path = (
        ROOT
        / "outputs/model_zoo_structural_v7_dependency_freeze_v2_20260820/"
        "DEPENDENCY_MANIFEST_V2.json"
    )
    post_pin_path = ROOT / "research/model_zoo/structural_v7/post_freeze_pins_v2.py"
    payload = {
        "format_version": 2,
        "mode": "structural_v7_independent_audit_candidate_v2",
        "status": "READY_FOR_INDEPENDENT_READ_ONLY_AUDIT_HEAVY_LAUNCH_BLOCKED",
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "parent_design_lock_raw_sha256": PARENT_LOCK_RAW_SHA256,
        "v7_design_lock_v2_raw_sha256": DESIGN_LOCK_V2_RAW_SHA256,
        "v7_design_lock_v2_manifest_sha256": design["manifest_sha256"],
        "dependency_manifest_v2_raw_sha256": DEPENDENCY_MANIFEST_V2_RAW_SHA256,
        "v7_preflight_v2_raw_sha256": PREFLIGHT_V2_RAW_SHA256,
        "v7_preflight_v2_manifest_sha256": preflight["manifest_sha256"],
        "dependency_manifest_record": _record(dependency_path),
        "post_freeze_pin_record": _record(post_pin_path),
        "dependency_verification_receipt": dependency_receipt.as_dict(),
        "candidate_count": len(CANDIDATES),
        "base_fit_calls_inspected": preflight["base_fit_call_count"],
        "candidate_outer_edges_inspected": preflight[
            "candidate_outer_consumer_edge_count"
        ],
        "hard_preflight_failures": preflight["hard_failure_count"],
        "preferred_min_exceptions": preflight["preferred_min_exception_count"],
        "fit_calls_executed": preflight["fit_calls_executed"],
        "prediction_rows_generated": preflight["prediction_rows_generated"],
        "evaluation_truth_opened": preflight["evaluation_truth_opened"],
        "scores_computed": preflight["scores_computed"],
        "heavy_launch_authorized": False,
        "resource_receipt": resource_receipt.as_dict(),
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
        "protected_boundaries": {
            "production_source_modified": False,
            "registry_modified": False,
            "frozen_structural_source_modified": False,
            "final_dashboard_or_release_modified": False,
            "new_paths_only": [
                "research/model_zoo/structural_v7/**",
                "scripts/model_lab/structural_v7/**",
                "tests/model_lab/test_structural_v7*.py",
                "outputs/model_zoo_structural_v7_*",
            ],
        },
        "independent_audit_questions": [
            "Does the practical dependency manifest bind 16 local runtime files, shared "
            "lane files, the interpreter/distributions, and the V7 source closure?",
            "Do parent launcher, every worker, and evaluator verify dependency bytes "
            "before numerical imports, fit, or truth?",
            "Does the evaluator require exactly five spent seeds and 1,296 outer rows "
            "per model under the pinned outer schedule hash?",
            "Does the hard-min rationale avoid a false parameter/sample sufficiency claim?",
            "Are all results permanently exploration-only and heavy launch still blocked?",
        ],
    }
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V7 V2 audit candidate exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    audit_raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    audit_path = OUTPUT / "AUDIT_CANDIDATE_V2.json"
    audit_path.write_bytes(audit_raw)
    report = (
        "# Structural V7 Independent Audit Candidate V2\n\n"
        "Status: `READY_FOR_INDEPENDENT_READ_ONLY_AUDIT_HEAVY_LAUNCH_BLOCKED`\n\n"
        "- Practical dependency bytes and V7 source closure are frozen.\n"
        "- Parent, worker, evaluator, and V2 preflight verify dependencies first.\n"
        "- Evaluator identity is exact: 5 spent seeds x 1,296 rows/model plus outer hash.\n"
        "- Hard floor 200 is described only as executability; observed support is 250/252/502.\n"
        "- Fit, prediction, truth and score counts remain zero.\n"
        "- Heavy launch remains blocked pending root approval.\n"
    )
    report_path = OUTPUT / "REPORT.md"
    report_path.write_text(report, encoding="utf-8", newline="\n")
    checksum_paths = [
        ROOT / "outputs/model_zoo_structural_v7_design_v2_20260820/DESIGN_LOCK_V2.json",
        dependency_path,
        ROOT / "outputs/model_zoo_structural_v7_preflight_v2_20260820/PREFLIGHT_V2.json",
        post_pin_path,
        *inventory_paths,
        audit_path,
        report_path,
    ]
    unique_paths = list(dict.fromkeys(checksum_paths))
    checksum_rows = [
        f"{sha256_file(path)}  {path.relative_to(ROOT).as_posix()}" for path in unique_paths
    ]
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        "\n".join(checksum_rows) + "\n", encoding="utf-8", newline="\n"
    )
    print(sha256_file(audit_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
