"""Print the evaluator V2 source-only denial receipt without filesystem discovery."""

from __future__ import annotations

import sys

from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2 import (
    source_only_receipt_bytes,
)


def main() -> int:
    sys.stdout.buffer.write(source_only_receipt_bytes())
    return 78


if __name__ == "__main__":
    raise SystemExit(main())

