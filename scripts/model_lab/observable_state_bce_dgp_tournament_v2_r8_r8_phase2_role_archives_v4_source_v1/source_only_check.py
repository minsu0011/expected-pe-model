"""Run the six-role temp-only double build and remain source-only denied."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_phase2_role_archives_v4_source_v1.contracts import (  # noqa: E402, E501
    SOURCE_ONLY_DENY_EXIT,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_phase2_role_archives_v4_source_v1.freezer import (  # noqa: E402, E501
    canonical_json_bytes,
    run_tmp_only_double_build,
)


def main() -> int:
    if len(sys.argv) != 1:
        return 64
    receipt = run_tmp_only_double_build()
    sys.stdout.buffer.write(canonical_json_bytes(receipt) + b"\n")
    sys.stdout.buffer.flush()
    return SOURCE_ONLY_DENY_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
