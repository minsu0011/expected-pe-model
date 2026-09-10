"""Freeze source/runtime/plan authority before reserved heldout generation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RuntimeError("execution authority requires -I -B")
    if sys.pycache_prefix is None:
        raise RuntimeError("execution authority pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RuntimeError("execution authority pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    result.add_argument("--survivor-freeze", required=True)
    result.add_argument("--survivor-freeze-raw-sha256", required=True)
    result.add_argument("--r2-protocol-lock", required=True)
    result.add_argument("--r2-protocol-lock-raw-sha256", required=True)
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        build_execution_authority,
        safe_run_id,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.r2_protocol_lock import (
        read_r2_protocol_lock,
    )

    require_process_resources()
    run_id = safe_run_id(arguments.run_id)
    survivor_path = Path(arguments.survivor_freeze).resolve(strict=True)
    raw = survivor_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != arguments.survivor_freeze_raw_sha256:
        raise RuntimeError("survivor freeze raw SHA-256 differs")
    try:
        survivor = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("survivor freeze JSON differs") from exc
    protocol_path = Path(arguments.r2_protocol_lock).resolve(strict=True)
    try:
        protocol_relative = protocol_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise RuntimeError("R2 protocol lock escaped project") from exc
    protocol = read_r2_protocol_lock(
        protocol_path,
        project_root=PROJECT_ROOT,
        expected_run_id=run_id,
        expected_raw_sha256=arguments.r2_protocol_lock_raw_sha256,
    )
    authority = build_execution_authority(
        project_root=PROJECT_ROOT,
        run_id=run_id,
        survivor_freeze=survivor,
        r2_protocol_lock=protocol,
        r2_protocol_lock_relative_path=protocol_relative,
        r2_protocol_lock_raw_sha256=arguments.r2_protocol_lock_raw_sha256,
    )
    output = (
        PROJECT_ROOT
        / "build"
        / f"pe_four_model_heldout_execution_authority_{run_id}.json"
    )
    output_raw = canonical_pretty_bytes(authority)
    atomic_write_new(output, output_raw)
    print(
        json.dumps(
            {
                "status": "FROZEN_PRETRUTH_EXECUTION_AUTHORITY",
                "relative_path": output.relative_to(PROJECT_ROOT).as_posix(),
                "raw_sha256": hashlib.sha256(output_raw).hexdigest(),
                "execution_authority_semantic_sha256": authority[
                    "execution_authority_semantic_sha256"
                ],
                "source_record_count": authority["source_manifest"][
                    "source_record_count"
                ],
                "r2_protocol_lock_raw_sha256": authority[
                    "r2_protocol_lock_raw_sha256"
                ],
                "r2_protocol_binding_semantic_sha256": authority[
                    "r2_protocol_binding_semantic_sha256"
                ],
                "truth_open_count": 0,
                "score_open_count": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
