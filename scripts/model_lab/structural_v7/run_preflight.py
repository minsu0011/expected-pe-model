"""Run Structural V7 all-call preflight without fitting or scoring."""

# ruff: noqa: E402 -- resource sealing intentionally precedes numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_preflight_20260820"


def main() -> int:
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    receipt = seal_battleground_process(outer_workers=1)
    from research.model_zoo.structural_v7.contracts import sha256_file

    design_path = ROOT / "outputs/model_zoo_structural_v7_design_20260820/DESIGN_LOCK.json"
    design_hash = sha256_file(design_path)
    from research.model_zoo.structural_v7.preflight import run_no_fit_preflight

    report = run_no_fit_preflight(ROOT, v7_design_lock_raw_sha256=design_hash)
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V7 preflight directory exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(report.payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    (OUTPUT / "PREFLIGHT.json").write_bytes(raw)
    receipt_raw = json.dumps(
        receipt.as_dict(), ensure_ascii=False, indent=2, allow_nan=False
    ).encode("utf-8") + b"\n"
    (OUTPUT / "RESOURCE_RECEIPT.json").write_bytes(receipt_raw)
    summary = report.payload
    text = (
        "# Structural V7 All-Nested-Call No-Fit Preflight\n\n"
        f"- Status: `{summary['status']}`\n"
        f"- Base fit calls inspected: {summary['base_fit_call_count']}\n"
        f"- Candidate/outer dependency edges: {summary['candidate_outer_consumer_edge_count']}\n"
        f"- Hard failures: {summary['hard_failure_count']}\n"
        f"- Preferred-min exceptions: {summary['preferred_min_exception_count']}\n"
        f"- Minimum base/meta/structural labels: "
        f"250/{summary['minimum_meta_usable_label_rows']}/"
        f"{summary['minimum_structural_usable_label_rows']}\n"
        "- Fit/prediction/truth/score calls: 0/0/0/0\n"
        "- Heavy launch: blocked pending root approval\n"
    )
    (OUTPUT / "REPORT.md").write_text(text, encoding="utf-8", newline="\n")
    print(sha256_file(OUTPUT / "PREFLIGHT.json"))
    return 0 if report.status.startswith("GO_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
