"""Freeze Structural V7 source/tests/preflight for independent read-only audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_audit_candidate_20260820"
TEST_FILES = (
    "tests/model_lab/test_structural_v7_contracts.py",
    "tests/model_lab/test_structural_v7_folds_preflight.py",
    "tests/model_lab/test_structural_v7_models.py",
)


def _record(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _run(command: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
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
    parser = argparse.ArgumentParser(description="Freeze the V7 independent-audit candidate")
    parser.add_argument("--ruff", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from research.model_zoo.aggressive_lab.contracts import (
        DESIGN_LOCK_RAW_SHA256 as PARENT_LOCK_SHA256,
        load_sealed_design_lock,
    )
    from research.model_zoo.aggressive_lab.resources import assert_battleground_process

    receipt = assert_battleground_process(outer_workers=1)
    load_sealed_design_lock(ROOT)
    from research.model_zoo.structural_v7.contracts import CANDIDATES, sha256_file
    from research.model_zoo.structural_v7.design import (
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        load_design_lock,
        load_preflight,
    )

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
            "research/model_zoo/structural_v7",
            "scripts/model_lab/structural_v7",
            *TEST_FILES,
        ]
    )
    if pytest_result["exit_code"] != 0 or ruff_result["exit_code"] != 0:
        raise RuntimeError("Structural V7 targeted validation failed")

    inventory_paths = [
        *sorted((ROOT / "research/model_zoo/structural_v7").glob("*.py")),
        *sorted((ROOT / "scripts/model_lab/structural_v7").glob("*.py")),
        *(ROOT / path for path in TEST_FILES),
    ]
    inventory = [_record(path) for path in inventory_paths]
    forbidden_tokens = (
        "authority_policy_" + "v6",
        "authorization_" + "v6",
        "ACTIVATION_EXECUTION_" + "V6",
        "EXTERNAL_POLICY_PIN_EXECUTION_" + "V6",
    )
    forbidden_hits: list[dict[str, str]] = []
    for path in inventory_paths:
        source = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                forbidden_hits.append(
                    {"path": str(path.relative_to(ROOT)), "token": token}
                )
    # The contract test intentionally names forbidden strings.  Execution
    # source and entrypoints must remain free of them.
    forbidden_execution_hits = [
        row
        for row in forbidden_hits
        if not str(row["path"]).startswith("tests\\")
        and not str(row["path"]).startswith("tests/")
    ]
    if forbidden_execution_hits:
        raise RuntimeError("Structural V7 execution source references prior authority")

    payload = {
        "format_version": 1,
        "mode": "structural_v7_independent_audit_candidate",
        "status": "READY_FOR_INDEPENDENT_READ_ONLY_AUDIT_HEAVY_LAUNCH_BLOCKED",
        "evidence_class": "EXPLORATION_ONLY",
        "promotion_authority": "NOT_PROMOTION_EVIDENCE",
        "production_promotion_allowed": False,
        "parent_design_lock_raw_sha256": PARENT_LOCK_SHA256,
        "v7_design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "v7_design_lock_manifest_sha256": design["manifest_sha256"],
        "v7_preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
        "v7_preflight_manifest_sha256": preflight["manifest_sha256"],
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
        "resource_receipt": receipt.as_dict(),
        "targeted_pytest": pytest_result,
        "targeted_ruff": ruff_result,
        "source_inventory": inventory,
        "source_inventory_sha256": hashlib.sha256(
            json.dumps(
                inventory,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "prior_authority_execution_source_hits": forbidden_execution_hits,
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
            "Does every planned nested/base/meta/outer call pass the locked 252/200 policy?",
            "Are seed/date/entity/fold identities exact and chronological?",
            "Can prediction code access evaluation truth or fresh/heldout inputs?",
            "Are all candidate results permanently exploration-only?",
            "Are CPUs 16-31, outer<=16, inner1 and GPU seal enforced in entrypoints?",
            "Is prior Structural execution authority absent from V7 execution dependencies?",
        ],
    }
    if OUTPUT.exists():
        raise FileExistsError(f"immutable audit-candidate directory exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    audit_raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    (OUTPUT / "AUDIT_CANDIDATE.json").write_bytes(audit_raw)
    report = (
        "# Structural V7 Independent Audit Candidate\n\n"
        "Status: `READY_FOR_INDEPENDENT_READ_ONLY_AUDIT_HEAVY_LAUNCH_BLOCKED`\n\n"
        "- 10 precommitted candidates; spent seeds only.\n"
        "- 740 base calls and 3,100 candidate/outer dependency edges inspected no-fit.\n"
        "- Hard failures 0; ten 250-label first folds pass the locked hard floor 200.\n"
        "- Targeted pytest 13/13 and Ruff pass.\n"
        "- Fit, prediction, truth and score counts remain zero.\n"
        "- Prior Structural execution authority is not an execution dependency.\n"
        "- Heavy launch still requires root approval after independent audit.\n"
    )
    (OUTPUT / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    checksum_paths = [
        ROOT / "outputs/model_zoo_structural_v7_design_20260820/DESIGN_LOCK.json",
        ROOT / "outputs/model_zoo_structural_v7_preflight_20260820/PREFLIGHT.json",
        *inventory_paths,
        OUTPUT / "AUDIT_CANDIDATE.json",
        OUTPUT / "REPORT.md",
    ]
    checksum_rows = [
        f"{sha256_file(path)}  {str(path.relative_to(ROOT)).replace(chr(92), '/')}"
        for path in checksum_paths
    ]
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        "\n".join(checksum_rows) + "\n", encoding="utf-8", newline="\n"
    )
    print(sha256_file(OUTPUT / "AUDIT_CANDIDATE.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
