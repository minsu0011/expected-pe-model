#!/usr/bin/env python
"""Hash-pinned, truth-free mint CLI for one pre-score target binding."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.target_mint import (  # noqa: E402
    mint_target_once,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None or not any(character != "0" for character in value):
        raise argparse.ArgumentTypeError("expected nonzero lowercase SHA-256 hex")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mint the exact pre-score target from a frozen base-14 activation core."
    )
    parser.add_argument("--repository-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--activation-core", type=Path, required=True)
    parser.add_argument("--activation-core-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    arguments = parser.parse_args()
    receipt = mint_target_once(
        project_root=arguments.repository_root,
        activation_core_path=arguments.activation_core,
        expected_activation_core_raw_sha256=arguments.activation_core_raw_sha256,
        output_root=arguments.output_root,
    )
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
