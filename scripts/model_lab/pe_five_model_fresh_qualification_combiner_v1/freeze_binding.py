"""Freeze the exact three-artifact input binding; never combine, fit, or score."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.artifacts import (  # noqa: E402
    atomic_publish_directory,
    canonical_json_bytes,
    checksum_bytes,
    seal_payload,
    semantic_sha256,
    write_bytes_new,
    write_json_new,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.binding import (  # noqa: E402
    capture_artifact_binding,
    capture_source_records,
    open_bound_inputs,
    validate_binding_payload,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.contracts import (  # noqa: E402
    BINDING_SCHEMA,
    BINDING_STATUS,
    C1_C3_BINDING_FILES,
    C1_C3_PREDICTION_FILES,
    C4_SURFACE_FILES,
    MODEL_IDS,
)


def _direct_output(relative: str, *, must_exist: bool) -> Path:
    candidate = Path(relative.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts or len(candidate.parts) != 2:
        raise RuntimeError("root must be a direct project outputs child")
    if candidate.parts[0] != "outputs" or ".staging" in candidate.parts[1].casefold():
        raise RuntimeError("root must be a final project outputs child")
    path = (PROJECT_ROOT / candidate).resolve(strict=must_exist)
    if path.parent != (PROJECT_ROOT / "outputs").resolve(strict=True):
        raise RuntimeError("root escaped project outputs")
    return path


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if type(payload) is not dict:
        raise RuntimeError("expected JSON object")
    return payload


def _build(args: argparse.Namespace) -> dict[str, object]:
    c1_binding_root = _direct_output(args.c1_c3_binding_root_relative, must_exist=True)
    c1_prediction_root = _direct_output(
        args.c1_c3_prediction_root_relative, must_exist=True
    )
    c4_root = _direct_output(args.c4_surface_root_relative, must_exist=True)
    prediction_output = _direct_output(
        args.prediction_output_relative, must_exist=False
    )
    if prediction_output.exists():
        raise RuntimeError("five-model prediction destination already exists")

    c1_binding_artifact = capture_artifact_binding(
        root=c1_binding_root,
        root_relative=Path(args.c1_c3_binding_root_relative).as_posix(),
        role="c1_c3_binding",
        expected_files=C1_C3_BINDING_FILES,
    )
    c1_prediction_artifact = capture_artifact_binding(
        root=c1_prediction_root,
        root_relative=Path(args.c1_c3_prediction_root_relative).as_posix(),
        role="c1_c3_predictions",
        expected_files=C1_C3_PREDICTION_FILES,
    )
    c4_surface_artifact = capture_artifact_binding(
        root=c4_root,
        root_relative=Path(args.c4_surface_root_relative).as_posix(),
        role="c4_surfaces",
        expected_files=C4_SURFACE_FILES,
    )
    c1_manifest = _json(c1_prediction_root / "PREDICTION_MANIFEST.json")
    c4_manifest = _json(c4_root / "MANIFEST.json")
    prefix_versions = c1_manifest.get("source_model_versions")
    c4_version = c4_manifest.get("source_model_version")
    if type(prefix_versions) is not list or len(prefix_versions) != 4:
        raise RuntimeError("C1--C3 manifest source versions are absent")
    source_model_versions = [
        *prefix_versions,
        {"model_id": MODEL_IDS[-1], "source_model_version": c4_version},
    ]
    source_records = capture_source_records(PROJECT_ROOT)
    unsigned = {
        "schema_version": BINDING_SCHEMA,
        "status": BINDING_STATUS,
        "c1_c3_binding_artifact": c1_binding_artifact,
        "c1_c3_prediction_artifact": c1_prediction_artifact,
        "c4_surface_artifact": c4_surface_artifact,
        "source_records": source_records,
        "source_records_semantic_sha256": semantic_sha256(source_records),
        "source_model_versions": source_model_versions,
        "prediction_output_relative": Path(
            args.prediction_output_relative
        ).as_posix(),
        "activation_marker_relative": (
            f"{Path(args.prediction_output_relative).as_posix()}_activation"
        ),
    }
    binding = seal_payload(unsigned, "binding_semantic_sha256")
    validate_binding_payload(binding)
    with open_bound_inputs(PROJECT_ROOT, binding) as closure:
        closure.revalidate()
    return binding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c1-c3-binding-root-relative", required=True)
    parser.add_argument("--c1-c3-prediction-root-relative", required=True)
    parser.add_argument("--c4-surface-root-relative", required=True)
    parser.add_argument("--prediction-output-relative", required=True)
    parser.add_argument("--binding-output-root-relative", required=True)
    args = parser.parse_args()
    output = _direct_output(args.binding_output_root_relative, must_exist=False)
    staging = output.with_name(f".{output.name}.staging")
    if output.exists() or staging.exists():
        raise RuntimeError("binding output or staging already exists")
    binding = _build(args)
    os.mkdir(staging)
    binding_sha = write_json_new(staging / "BINDING.json", binding)
    source_manifest = {
        "schema_version": "expected_pe.five_model.binding_source_manifest.v1",
        "status": "PASS_EXACT_COMBINER_SOURCE_CLOSURE",
        "source_records": binding["source_records"],
        "source_records_semantic_sha256": binding[
            "source_records_semantic_sha256"
        ],
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    source_sha = write_json_new(staging / "SOURCE_MANIFEST.json", source_manifest)
    checksums_sha = write_bytes_new(
        staging / "CHECKSUMS.sha256",
        checksum_bytes(
            {"BINDING.json": binding_sha, "SOURCE_MANIFEST.json": source_sha}
        ),
    )
    atomic_publish_directory(staging, output)
    sys.stdout.write(
        canonical_json_bytes(
            {
                "status": "FROZEN_EXACT_PRETRUTH_INPUT_ARTIFACT_BINDING",
                "binding_output": str(output),
                "binding_raw_sha256": binding_sha,
                "binding_semantic_sha256": binding["binding_semantic_sha256"],
                "checksums_raw_sha256": checksums_sha,
            }
        ).decode("ascii")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
