"""Mint the one-leaf evaluator activation without opening any truth leaf."""

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
        raise RuntimeError("heldout activation authority requires -I -B")
    if sys.pycache_prefix is None:
        raise RuntimeError("heldout activation pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RuntimeError("heldout activation pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    result.add_argument("--execution-authority", required=True)
    result.add_argument("--execution-authority-raw-sha256", required=True)
    result.add_argument("--vault-manifest", required=True)
    result.add_argument("--prediction-root", required=True)
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.activation import (
        publish_activation,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        read_execution_authority,
    )

    authority = read_execution_authority(
        Path(arguments.execution_authority),
        project_root=PROJECT_ROOT,
        expected_run_id=arguments.run_id,
        expected_raw_sha256=arguments.execution_authority_raw_sha256,
    )
    result = publish_activation(
        project_root=PROJECT_ROOT,
        run_id=arguments.run_id,
        execution_authority=authority,
        vault_manifest_path=Path(arguments.vault_manifest),
        prediction_root=Path(arguments.prediction_root),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
