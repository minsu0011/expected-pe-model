"""Publish truth-free H-OFS R3 derived predictions."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hofs_robustness_revision_r3.contracts import (  # noqa: E402
    PREDICTION_OUTPUT_ROOT,
)
from research.model_zoo.hofs_robustness_revision_r3.prediction import (  # noqa: E402
    build_prediction_files,
)
from research.model_zoo.hofs_robustness_revision_r3.publisher import (  # noqa: E402
    publish_atomic,
)


def main() -> int:
    print(publish_atomic(PREDICTION_OUTPUT_ROOT, build_prediction_files()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
