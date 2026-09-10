"""CLI for the fixed, score-free H-OFS research adapter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hofs_research_adapter_v1.artifacts import (  # noqa: E402
    build_benchmark_files,
    build_full_files,
    build_smoke_files,
)
from research.model_zoo.hofs_research_adapter_v1.contracts import (  # noqa: E402
    BENCHMARK_OUTPUT_ROOT,
    FULL_OUTPUT_ROOT,
    SMOKE_OUTPUT_ROOT,
    design_sha256,
)
from research.model_zoo.hofs_research_adapter_v1.inputs import (  # noqa: E402
    build_public_task_plan,
    verify_numeric_source_closure,
)
from research.model_zoo.hofs_research_adapter_v1.publisher import publish_atomic  # noqa: E402
from research.model_zoo.hofs_research_adapter_v1.runner import (  # noqa: E402
    run_full_prediction,
    run_one_task_smoke,
    run_worker_microbenchmark,
)


FULL_COORDINATION_TOKEN = "FULL_RUN_R2_RESOURCE_COORDINATED"


def run(mode: str, *, coordination_token: str | None = None) -> dict[str, Any]:
    if mode == "preflight":
        tasks = build_public_task_plan()
        source = verify_numeric_source_closure()
        return {
            "mode": mode,
            "design_sha256": design_sha256(),
            "task_count": len(tasks),
            "numeric_source_closure_semantic_sha256": source["semantic_sha256"],
            "fit_or_prediction_count": 0,
            "status": "PASS_RESEARCH_ONLY_HOFS_ADAPTER_PREFLIGHT",
        }
    if coordination_token is not None and mode != "full":
        raise RuntimeError("coordination token is accepted only for the full mode")
    if mode == "smoke":
        result = run_one_task_smoke()
        publication = publish_atomic(SMOKE_OUTPUT_ROOT, build_smoke_files(result))
    elif mode == "benchmark":
        result = run_worker_microbenchmark()
        publication = publish_atomic(BENCHMARK_OUTPUT_ROOT, build_benchmark_files(result))
    elif mode == "full":
        if coordination_token != FULL_COORDINATION_TOKEN:
            raise RuntimeError("full run requires explicit resource-coordination token")
        result = run_full_prediction()
        publication = publish_atomic(FULL_OUTPUT_ROOT, build_full_files(result))
    else:
        raise RuntimeError("unknown adapter mode")
    return {
        "mode": mode,
        "status": result["status"],
        "publication": publication,
        "fit_count": result.get("fit_count"),
        "prediction_row_count": result.get("prediction_row_count"),
        "full_run_started": mode == "full",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("preflight", "smoke", "benchmark", "full"),
        default="preflight",
    )
    parser.add_argument("--coordination-token")
    return parser


def main() -> int:
    args = _parser().parse_args()
    receipt = run(args.mode, coordination_token=args.coordination_token)
    print(json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
