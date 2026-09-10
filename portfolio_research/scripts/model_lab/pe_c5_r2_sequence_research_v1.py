"""Run the dedicated C5-R2 causal sequence research wave."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from research.model_zoo.pe_c5_r2_sequence_research_v1.orchestrator import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
