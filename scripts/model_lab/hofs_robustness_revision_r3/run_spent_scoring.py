"""Run and publish the separate spent-only H-OFS R3 score."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hofs_robustness_revision_r3.contracts import (  # noqa: E402
    SCORING_OUTPUT_ROOT,
)
from research.model_zoo.hofs_robustness_revision_r3.publisher import (  # noqa: E402
    publish_atomic,
)
from research.model_zoo.hofs_robustness_revision_r3.scoring import (  # noqa: E402
    build_scoring_files,
    evaluate_spent_robustness_revision,
)


def main() -> int:
    result = evaluate_spent_robustness_revision(PROJECT_ROOT)
    print(publish_atomic(SCORING_OUTPUT_ROOT, build_scoring_files(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
