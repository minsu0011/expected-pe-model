from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.runtime import (  # noqa: E402
    resource_receipt,
    validate_runtime,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring import (  # noqa: E402
    build_capability_payload,
    file_record,
    seal_capability,
    sha256_file,
)


DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_observable_state_r2_detached_scoring_capability_20260820"
)
SOURCE_PATHS = (
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_scoring/__init__.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_scoring/contracts.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_scoring/capability.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_scoring/evaluator.py",
    "research/model_zoo/bounded_consensus_v1/contracts.py",
    "research/model_zoo/bounded_consensus_v1/tail_evaluator.py",
    "research/model_zoo/bounded_consensus_v1/deterministic.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/contracts.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/runtime.py",
    "scripts/model_lab/bounded_consensus_v1_observable_state_r2_scoring/freeze_capability.py",
    "scripts/model_lab/bounded_consensus_v1_observable_state_r2_scoring/score_detached.py",
    "tests/model_lab/test_bounded_consensus_v1_observable_state_r2_scoring.py",
)


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    return {
        **unsigned,
        "manifest_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_source_manifest(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("relative_path", "bytes", "sha256"))
        writer.writeheader()
        for relative in SOURCE_PATHS:
            source = (PROJECT_ROOT / relative).resolve(strict=True)
            writer.writerow(
                {
                    "relative_path": relative,
                    "bytes": source.stat().st_size,
                    "sha256": sha256_file(source),
                }
            )


def freeze(output: Path) -> dict[str, Any]:
    validate_runtime()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_path = output / "SOURCE_MANIFEST.csv"
    _write_source_manifest(source_path)
    payload = build_capability_payload(PROJECT_ROOT)
    payload["source_manifest"] = file_record(source_path).__dict__
    payload["freeze_runtime"] = resource_receipt(stage="detached_scoring_capability_freeze")
    capability = seal_capability(payload)
    capability_path = output / "EVALUATION_CAPABILITY.json"
    _write_json(capability_path, capability)
    preflight = _seal(
        {
            "format_version": 1,
            "status": "AUTHORIZED_DETACHED_STATE_R2_SCORING_READY",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": capability["capability_sha256"],
            "source_manifest": file_record(source_path).__dict__,
            "truth_seed_count": capability["truth_seed_count"],
            "truth_csv_values_opened": False,
            "truth_csv_bytes_hashed": False,
            "heldout_opened": False,
            "registry_or_champion_mutated": False,
            "score_computation_executed": False,
            "freeze_runtime": payload["freeze_runtime"],
        }
    )
    preflight_path = output / "CAPABILITY_PREFLIGHT.json"
    _write_json(preflight_path, preflight)
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(
            f"{sha256_file(path)}  {path.name}\n"
            for path in (source_path, capability_path, preflight_path)
        ),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output),
        "capability_sha256": capability["capability_sha256"],
        "capability_raw_sha256": sha256_file(capability_path),
        "preflight_sha256": preflight["manifest_sha256"],
        "source_manifest_raw_sha256": sha256_file(source_path),
        "checksums_raw_sha256": sha256_file(checksum_path),
        "truth_csv_values_opened": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(freeze(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
