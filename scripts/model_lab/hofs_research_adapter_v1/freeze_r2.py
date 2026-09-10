"""Atomically freeze the tested H-OFS research full-r2 preflight."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hofs_research_adapter_v1.artifacts import (  # noqa: E402
    build_r2_preflight_files,
)
from research.model_zoo.hofs_research_adapter_v1.contracts import (  # noqa: E402
    R2_PREFLIGHT_ROOT,
)
from research.model_zoo.hofs_research_adapter_v1.inputs import (  # noqa: E402
    build_public_task_plan,
)
from research.model_zoo.hofs_research_adapter_v1.publisher import (  # noqa: E402
    publish_atomic,
)


def main() -> int:
    tasks = build_public_task_plan()
    receipt = publish_atomic(R2_PREFLIGHT_ROOT, build_r2_preflight_files(tasks))
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
