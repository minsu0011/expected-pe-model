"""CLI for the independent atomic R8-r14 public-root post-generation audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PROJECT_ROOT / "src"
for entry in (PROJECT_ROOT, SRC_ROOT):
    value = str(entry)
    if value not in sys.path:
        sys.path.insert(0, value)

from research.model_zoo.expected_pe_public_root_post_generation_auditor_v1 import (  # noqa: E402
    publish_atomic_audit,
)
from research.model_zoo.expected_pe_public_root_post_generation_auditor_v1.contracts import (  # noqa: E402
    GO_STATUS,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--expected-public-root-name", required=True)
    parser.add_argument("--expected-checksums-raw-sha256", required=True)
    parser.add_argument("--expected-manifest-raw-sha256")
    parser.add_argument("--expected-public-tree-semantic-sha256")
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = publish_atomic_audit(
        args.public_root,
        output_root=args.output_root,
        expected_public_root_name=args.expected_public_root_name,
        expected_checksums_raw_sha256=args.expected_checksums_raw_sha256,
        expected_manifest_raw_sha256=args.expected_manifest_raw_sha256,
        expected_public_tree_semantic_sha256=args.expected_public_tree_semantic_sha256,
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "output_root": args.output_root.resolve(strict=True).as_posix(),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == GO_STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
