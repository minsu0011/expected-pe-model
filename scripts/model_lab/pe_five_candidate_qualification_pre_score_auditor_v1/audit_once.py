#!/usr/bin/env python
"""Isolated CLI for the independent R8-r14 pre-score audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1 import (  # noqa: E402
    audit_once,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None or not any(character != "0" for character in value):
        raise argparse.ArgumentTypeError("expected nonzero lowercase SHA-256 hex")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit one frozen scorer target and prediction/public chain before the "
            "qualification scorer may publish a marker or open truth."
        )
    )
    parser.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--target-binding", type=Path, required=True)
    parser.add_argument("--target-binding-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    output = audit_once(
        project_root=arguments.repository_root,
        target_binding_path=arguments.target_binding,
        expected_target_binding_raw_sha256=arguments.target_binding_raw_sha256,
        output_root=arguments.output_root,
    )
    report = json.loads((output / "PRE_SCORE_AUDIT.json").read_text(encoding="ascii"))
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if str(report.get("status", "")).startswith("GO_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
