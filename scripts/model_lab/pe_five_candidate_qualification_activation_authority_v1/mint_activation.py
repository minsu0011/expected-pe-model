"""Mint the exact public scorer activation after independent pre-score GO+seal."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY))
sys.path.insert(0, str(REPOSITORY / "src"))

from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1 import (  # noqa: E402
    mint_final_activation_once,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.canonical import (  # noqa: E402
    compact_ascii_json_bytes,
)


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("must be lowercase SHA-256 hex")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish the one-file scorer activation after exact pre-score GO+seal"
    )
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY)
    parser.add_argument("--activation-core-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--pre-score-target-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--pre-score-audit-raw-sha256", type=_sha256, required=True)
    parser.add_argument("--pre-score-audit-seal-raw-sha256", type=_sha256, required=True)
    args = parser.parse_args()
    receipt = mint_final_activation_once(
        project_root=args.repository_root,
        expected_activation_core_raw_sha256=args.activation_core_raw_sha256,
        expected_pre_score_target_raw_sha256=args.pre_score_target_raw_sha256,
        expected_pre_score_audit_raw_sha256=args.pre_score_audit_raw_sha256,
        expected_pre_score_audit_seal_raw_sha256=args.pre_score_audit_seal_raw_sha256,
    )
    sys.stdout.buffer.write(compact_ascii_json_bytes(receipt, terminal_lf=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
