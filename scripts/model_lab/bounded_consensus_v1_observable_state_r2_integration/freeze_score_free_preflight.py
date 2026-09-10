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
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration import (  # noqa: E402
    disabled_evaluation_gate_template,
    integration_design_payload,
    run_score_free_preflight,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.runtime import (  # noqa: E402
    resource_receipt,
    validate_runtime,
)


DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_observable_state_r2_score_free_preflight_py310_20260820"
)
SOURCE_RELATIVE_PATHS = (
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/__init__.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/contracts.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/custody.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/assembler.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/source_audit.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/evaluation_gate.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/preflight.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/runtime.py",
    "research/model_zoo/bounded_consensus_v1_observable_state_r2_integration/INTEGRATION_DESIGN.md",
    "research/model_zoo/bounded_consensus_v1/__init__.py",
    "research/model_zoo/bounded_consensus_v1/contracts.py",
    "research/model_zoo/bounded_consensus_v1/adapter.py",
    "research/model_zoo/bounded_consensus_v1/confidence.py",
    "research/model_zoo/bounded_consensus_v1/variants.py",
    "research/model_zoo/bounded_consensus_v1/deterministic.py",
    "research/model_zoo/observable_fair_value_state_v1/__init__.py",
    "research/model_zoo/observable_fair_value_state_v1/contracts.py",
    "research/model_zoo/observable_fair_value_state_v1/features.py",
    "scripts/model_lab/bounded_consensus_v1_observable_state_r2_integration/"
    "freeze_score_free_preflight.py",
    "scripts/model_lab/bounded_consensus_v1_observable_state_r2_integration/"
    "assemble_predictions.py",
    "tests/model_lab/test_bounded_consensus_v1_observable_state_r2_integration.py",
)


def _seal(payload: dict[str, Any], *, field: str = "manifest_sha256") -> dict[str, Any]:
    sealed = dict(payload)
    sealed.pop(field, None)
    sealed[field] = hashlib.sha256(canonical_json_bytes(sealed)).hexdigest()
    return sealed


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_source_manifest(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("relative_path", "bytes", "sha256"))
        writer.writeheader()
        for relative in SOURCE_RELATIVE_PATHS:
            source = (PROJECT_ROOT / relative).resolve(strict=True)
            writer.writerow(
                {
                    "relative_path": relative.replace("\\", "/"),
                    "bytes": source.stat().st_size,
                    "sha256": sha256_file(source),
                }
            )


def freeze(output: Path) -> dict[str, Any]:
    validate_runtime()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    closure, preflight = run_score_free_preflight(PROJECT_ROOT)

    design_path = output / "INTEGRATION_DESIGN_LOCK.json"
    closure_path = output / "INPUT_CLOSURE.json"
    gate_path = output / "EVALUATION_GATE_TEMPLATE.json"
    source_path = output / "SOURCE_MANIFEST.csv"
    preflight_path = output / "PREFLIGHT.json"
    design = _seal(integration_design_payload())
    input_closure = _seal(closure.to_payload(), field="closure_sha256")
    gate = _seal(disabled_evaluation_gate_template(), field="template_sha256")
    _write_json(design_path, design)
    _write_json(closure_path, input_closure)
    _write_json(gate_path, gate)
    _write_source_manifest(source_path)
    preflight.update(
        {
            "integration_design_lock": file_record(design_path).__dict__,
            "integration_design_manifest_sha256": design["manifest_sha256"],
            "input_closure": file_record(closure_path).__dict__,
            "input_closure_sha256": input_closure["closure_sha256"],
            "source_manifest": file_record(source_path).__dict__,
            "evaluation_gate_template": file_record(gate_path).__dict__,
            "evaluation_gate_template_sha256": gate["template_sha256"],
            "resource_receipt": resource_receipt(stage="score_free_preflight"),
        }
    )
    sealed_preflight = _seal(preflight)
    _write_json(preflight_path, sealed_preflight)
    checksum_paths = (design_path, closure_path, gate_path, source_path, preflight_path)
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output),
        "design_sha256": design["manifest_sha256"],
        "input_closure_sha256": input_closure["closure_sha256"],
        "preflight_sha256": sealed_preflight["manifest_sha256"],
        "source_manifest_raw_sha256": sha256_file(source_path),
        "checksums_raw_sha256": sha256_file(checksum_path),
        "status": sealed_preflight["status"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(freeze(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
