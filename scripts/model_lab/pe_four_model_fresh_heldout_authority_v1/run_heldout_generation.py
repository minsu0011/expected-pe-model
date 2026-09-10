"""Isolated 16-lane protected/public heldout generation stage."""

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
        raise RuntimeError("heldout generation requires -I -B")
    if sys.pycache_prefix is None:
        raise RuntimeError("heldout generation pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RuntimeError("heldout generation pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    result.add_argument("--execution-authority", required=True)
    result.add_argument("--execution-authority-raw-sha256", required=True)
    result.add_argument("--worker-pycache-prefix", required=True)
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        read_execution_authority,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation_execution import (
        run_heldout_generation,
    )

    authority = read_execution_authority(
        Path(arguments.execution_authority),
        project_root=PROJECT_ROOT,
        expected_run_id=arguments.run_id,
        expected_raw_sha256=arguments.execution_authority_raw_sha256,
    )
    result = run_heldout_generation(
        project_root=PROJECT_ROOT,
        run_id=arguments.run_id,
        pycache_prefix=Path(arguments.worker_pycache_prefix),
        execution_authority=authority,
    )
    vault_relative = str(result.vault_manifest["vault_relative_path"])
    print(
        json.dumps(
            {
                "status": result.public_receipt["status"],
                "public_replay_root_relative_path": result.public_root.relative_to(
                    PROJECT_ROOT
                ).as_posix(),
                "vault_manifest_relative_path": (
                    f"{vault_relative}/VAULT_MANIFEST.json"
                ),
                "execution_authority_semantic_sha256": authority[
                    "execution_authority_semantic_sha256"
                ],
                "truth_ref_count": result.vault_manifest["truth_ref_count"],
                "truth_open_count": 0,
                "score_open_count": 0,
                "prediction_executed_in_generation_process": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
