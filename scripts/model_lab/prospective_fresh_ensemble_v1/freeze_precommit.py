"""Freeze the prospective fresh-ensemble source/design/preflight artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
SOURCE = PROJECT_ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from research.model_zoo.prospective_fresh_ensemble_v1.precommit import (  # noqa: E402
    DEFAULT_OUTPUT_NAME,
    freeze_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME)
    args = parser.parse_args()
    manifest = freeze_precommit(PROJECT_ROOT, args.output_root)
    print(f"PRECOMMIT_FROZEN {manifest['manifest_sha256']}")
    print(f"OUTPUT_ROOT {Path(args.output_root).resolve()}")
    print("LAUNCH_AUTHORIZED False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
