from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_qualification_integration import (  # noqa: E402
    disabled_evaluation_gate_template,
    integration_design_payload,
    run_score_free_preflight,
)
from research.model_zoo.bounded_consensus_v1_qualification_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)


DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_qualification_integration_score_free_preflight_r3_py310_20260820"
)
PINNED_LAUNCHER = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_LAUNCHER_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_BASE_PYTHON = Path(r"C:\Users\minsu\anaconda3\envs\myenv\python.exe")
PINNED_BASE_PYTHON_SHA256 = (
    "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
)
THREAD_VARIABLES = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)
SOURCE_RELATIVE_PATHS = (
    "research/model_zoo/bounded_consensus_v1_qualification_integration/__init__.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/contracts.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/custody.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/assembler.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/evaluation_gate.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/preflight.py",
    "research/model_zoo/bounded_consensus_v1_qualification_integration/INTEGRATION_DESIGN.md",
    "research/model_zoo/bounded_consensus_v1/__init__.py",
    "research/model_zoo/bounded_consensus_v1/contracts.py",
    "research/model_zoo/bounded_consensus_v1/adapter.py",
    "research/model_zoo/bounded_consensus_v1/confidence.py",
    "research/model_zoo/bounded_consensus_v1/variants.py",
    "research/model_zoo/bounded_consensus_v1/tail_evaluator.py",
    "research/model_zoo/bounded_consensus_v1/deterministic.py",
    "research/model_zoo/observable_fair_value_state_v1/__init__.py",
    "research/model_zoo/observable_fair_value_state_v1/contracts.py",
    "research/model_zoo/observable_fair_value_state_v1/features.py",
    "scripts/model_lab/bounded_consensus_v1_qualification_integration/"
    "freeze_score_free_preflight.py",
    "scripts/model_lab/bounded_consensus_v1_qualification_integration/"
    "assemble_predictions.py",
)


def _seal(payload: dict[str, Any], field: str = "manifest_sha256") -> dict[str, Any]:
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


def _require_score_free_runtime() -> None:
    launcher = Path(sys.executable).resolve(strict=True)
    base = Path(sys._base_executable).resolve(strict=True)
    if launcher != PINNED_LAUNCHER.resolve(strict=True):
        raise RuntimeError(f"preflight requires pinned V5 worker launcher: {PINNED_LAUNCHER}")
    if base != PINNED_BASE_PYTHON.resolve(strict=True):
        raise RuntimeError(f"preflight requires pinned py310 base: {PINNED_BASE_PYTHON}")
    if (
        sys.version_info[:3] != (3, 10, 19)
        or sha256_file(launcher) != PINNED_LAUNCHER_SHA256
        or sha256_file(base) != PINNED_BASE_PYTHON_SHA256
    ):
        raise RuntimeError("pinned V5 launcher/base version or executable hash drifted")
    wrong = {name: os.environ.get(name) for name in THREAD_VARIABLES if os.environ.get(name) != "1"}
    if wrong:
        raise RuntimeError(f"native thread variables must all equal 1: {wrong}")
    cuda = os.environ.get("CUDA_VISIBLE_DEVICES", "")
    if cuda not in {"-1", ""}:
        raise RuntimeError("CUDA_VISIBLE_DEVICES must be -1 or empty for preflight")


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
    _require_score_free_runtime()
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
            "runtime_policy": {
                **preflight["runtime_policy"],
                "pinned_worker_launcher": str(PINNED_LAUNCHER.resolve(strict=True)),
                "pinned_worker_launcher_raw_sha256": PINNED_LAUNCHER_SHA256,
                "pinned_base_python_executable": str(PINNED_BASE_PYTHON.resolve(strict=True)),
                "pinned_base_python_raw_sha256": PINNED_BASE_PYTHON_SHA256,
                "pinned_python_version": "3.10.19",
            },
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
        "output": str(output.resolve()),
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
