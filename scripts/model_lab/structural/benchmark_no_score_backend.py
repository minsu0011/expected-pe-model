"""Run and seal the 8/16/24/32 spawn-only synthetic backend benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", type=int, default=64)
    parser.add_argument("--rounds", type=int, default=12000)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "outputs/model_zoo_structural_wave_screen_20260819/NO_SCORE_BACKEND_BENCHMARK.json"
        ),
    )
    args = parser.parse_args()
    root = _project_root()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.structural.contracts import canonical_json_bytes
    from pe_regime_v04.model_lab.structural.runner import benchmark_no_score_backend

    output = (root / args.output).resolve() if not args.output.is_absolute() else args.output
    if output.exists():
        raise FileExistsError(f"refusing to overwrite sealed benchmark: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = benchmark_no_score_backend(
        task_count=args.tasks, rounds=args.rounds, repeats=args.repeats
    )
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(canonical_json_bytes(payload) + b"\n")
    temporary.replace(output)
    print(
        json.dumps(
            {
                "path": output.relative_to(root).as_posix(),
                "selected_worker_count": payload["selected_worker_count"],
                "manifest_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
