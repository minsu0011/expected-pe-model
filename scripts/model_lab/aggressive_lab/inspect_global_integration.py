"""Verify the unfrozen global integrator plan and print a read-only JSON receipt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.aggressive_lab.global_integration.contract import (
    inspect_terminal_contract,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser.parse_args()


def main() -> int:
    receipt = inspect_terminal_contract(parse_args().root.resolve())
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
