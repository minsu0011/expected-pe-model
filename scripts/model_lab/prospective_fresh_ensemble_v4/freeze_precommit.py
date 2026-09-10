"""Freeze the V4 redirector-safe precommit; never reserve seeds or run models."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE = PROJECT_ROOT / "src"
for value in (PROJECT_ROOT, SOURCE):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.prospective_fresh_ensemble_v4.precommit import (  # noqa: E402
    DEFAULT_OUTPUT_NAME,
    freeze_precommit,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root", type=Path, default=PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME
    )
    parser.add_argument(
        "--smoke-receipt",
        type=Path,
        required=True,
        help="completed sealed V4 short-path generator smoke receipt",
    )
    args = parser.parse_args()
    manifest = freeze_precommit(
        PROJECT_ROOT,
        args.output_root,
        smoke_receipt_path=args.smoke_receipt,
    )
    print(f"V4_PRECOMMIT_FROZEN {manifest['manifest_sha256']}")
    print(f"OUTPUT_ROOT {Path(args.output_root).resolve()}")
    print("NEW_SEED_RESERVATION False")
    print("SPENT_SEED_GENERATOR_SMOKE_BOUND True")
    print("FREEZE_COMMAND_DATA_OR_MODEL_RUN False")
    print("CANDIDATE_FIT_OR_SCORE False")
    print("LAUNCH_AUTHORIZED False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
