#!/usr/bin/env python
"""Isolated CLI for the independent five-model prediction-freeze audit."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1 import (
    publish_prediction_freeze_audit,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")


def _sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected 64 lowercase SHA-256 hex digits")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit the frozen five-model qualification predictions without truth access."
    )
    parser.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--combined-root", type=Path, required=True)
    parser.add_argument("--c1-c3-binding-root", type=Path, required=True)
    parser.add_argument("--c1-c3-prediction-root", type=Path, required=True)
    parser.add_argument("--c4-surface-root", type=Path, required=True)
    parser.add_argument("--common-root", type=Path, required=True)
    parser.add_argument("--postgen-audit", type=Path, required=True)
    parser.add_argument("--postgen-audit-seal", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--expected-combined-root-name", required=True)
    parser.add_argument("--expected-combined-checksums-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--expected-common-checksums-raw-sha256", type=_sha256, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    report = publish_prediction_freeze_audit(
        repository_root=arguments.repository_root,
        output_root=arguments.output_root,
        combined_root=arguments.combined_root,
        c1_c3_binding_root=arguments.c1_c3_binding_root,
        c1_c3_prediction_root=arguments.c1_c3_prediction_root,
        c4_surface_root=arguments.c4_surface_root,
        common_root=arguments.common_root,
        postgen_audit_path=arguments.postgen_audit,
        postgen_seal_path=arguments.postgen_audit_seal,
        expected_combined_root_name=arguments.expected_combined_root_name,
        expected_combined_checksums_raw_sha256=(
            arguments.expected_combined_checksums_raw_sha256
        ),
        expected_common_checksums_raw_sha256=arguments.expected_common_checksums_raw_sha256,
    )
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"].startswith("GO_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
