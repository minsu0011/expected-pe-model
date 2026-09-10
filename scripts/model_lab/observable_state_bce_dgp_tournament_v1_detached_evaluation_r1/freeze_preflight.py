"""Freeze metadata-only capability for one detached DGP evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.contract import (  # noqa: E501
        PREFLIGHT_ROOT,
        RESULT_ROOT,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v1_detached_evaluation_r1.custody import (  # noqa: E501
        freeze_preflight,
        preflight_source_paths,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=root)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    test_path = repo_root / (
        "tests/model_lab/test_observable_state_bce_dgp_tournament_v1_"
        "detached_evaluation_r1.py"
    )
    destination = freeze_preflight(
        repo_root,
        source_paths=preflight_source_paths(repo_root),
        destination=repo_root / PREFLIGHT_ROOT,
        result_destination=repo_root / RESULT_ROOT,
        test_path=test_path,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
