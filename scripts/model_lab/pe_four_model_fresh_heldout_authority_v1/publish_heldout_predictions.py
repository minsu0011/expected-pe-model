"""Separate public-only numeric prediction, fresh audit, and seal stage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RuntimeError("heldout prediction publication requires -I -B")
    if sys.pycache_prefix is None:
        raise RuntimeError("heldout prediction pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RuntimeError("heldout prediction pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    result.add_argument("--execution-authority", required=True)
    result.add_argument("--execution-authority-raw-sha256", required=True)
    result.add_argument("--public-replay-root", required=True)
    result.add_argument("--worker-pycache-prefix", required=True)
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        read_execution_authority,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.publisher import (
        publish_prediction_freeze,
    )

    require_process_resources()
    authority = read_execution_authority(
        Path(arguments.execution_authority),
        project_root=PROJECT_ROOT,
        expected_run_id=arguments.run_id,
        expected_raw_sha256=arguments.execution_authority_raw_sha256,
    )
    result = publish_prediction_freeze(
        project_root=PROJECT_ROOT,
        public_replay_root=Path(arguments.public_replay_root),
        execution_authority=authority,
        run_id=arguments.run_id,
        pycache_prefix=Path(arguments.worker_pycache_prefix),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
