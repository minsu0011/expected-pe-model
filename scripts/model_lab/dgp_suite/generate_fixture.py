"""Generate immutable non-evidence A--J fixtures; never run or score a model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.model_zoo.dgp_suite import (
    FIXTURE_MASTER_SEED,
    FixtureSeed,
    generate_dgp,
    write_dgp_artifacts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--dgp", choices=[*"ABCDEFGHIJ", "ALL"], default="ALL")
    parser.add_argument(
        "--fixture-seed",
        type=int,
        default=FIXTURE_MASTER_SEED,
        help="Explicitly non-evidence fixture seed; this command never reserves evidence seeds.",
    )
    parser.add_argument(
        "--acknowledge-fixture-only",
        action="store_true",
        help="Required acknowledgement that outputs cannot be used as tuning/validation evidence.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.acknowledge_fixture_only:
        raise SystemExit("--acknowledge-fixture-only is required")
    seed = FixtureSeed(args.fixture_seed)
    ids = tuple("ABCDEFGHIJ") if args.dgp == "ALL" else (args.dgp,)
    result: dict[str, object] = {
        "fixture_only": True,
        "model_executed": False,
        "candidate_score_computed": False,
        "dgps": {},
    }
    for dgp_id in ids:
        generated = generate_dgp(dgp_id, fixture_seed=seed)
        hashes = write_dgp_artifacts(generated, args.output_root / f"DGP_{dgp_id}")
        result["dgps"][dgp_id] = hashes  # type: ignore[index]
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
