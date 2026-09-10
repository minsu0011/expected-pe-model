"""Mint the exact fixed R8-r14 activation core; never read truth.csv bytes."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY))
sys.path.insert(0, str(REPOSITORY / "src"))

from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1 import (  # noqa: E402
    mint_activation_core_once,
)
from research.model_zoo.pe_five_candidate_qualification_activation_authority_v1.canonical import (  # noqa: E402
    compact_ascii_json_bytes,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mint one fixed 14-field qualification activation core without truth content"
    )
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY)
    args = parser.parse_args()
    receipt = mint_activation_core_once(project_root=args.repository_root)
    sys.stdout.buffer.write(compact_ascii_json_bytes(receipt, terminal_lf=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
