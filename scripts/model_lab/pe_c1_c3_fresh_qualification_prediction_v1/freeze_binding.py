"""Freeze explicit post-generation public/audit FileId bindings; never fit or score."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.artifacts import (  # noqa: E402, RUF100
    atomic_publish_directory,
    canonical_json_bytes,
    checksum_bytes,
    seal_payload,
    semantic_sha256,
    write_bytes_new,
    write_json_new,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.contracts import (  # noqa: E402, RUF100
    AUDIT_EVIDENCE_FILENAMES,
    BINDING_SCHEMA,
    BINDING_STATUS,
    DGP_IDS,
    GENERATION_EVIDENCE_FILENAMES,
    MODEL_IDS,
    QUALIFICATION_SEEDS,
    SEED_ALIASES,
    SOURCE_CLOSURE_RELATIVES,
    is_sha256,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.custody import (  # noqa: E402, RUF100
    open_bound_inputs,
    snapshot_record,
    snapshot_root_identity,
    validate_binding_payload,
)


def _direct_output(relative: str, *, must_exist: bool) -> Path:
    candidate = Path(relative.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts or len(candidate.parts) != 2:
        raise RuntimeError("root must be a direct project outputs child")
    if candidate.parts[0] != "outputs" or ".staging" in candidate.parts[1].casefold():
        raise RuntimeError("root must be a final project outputs child")
    path = PROJECT_ROOT / candidate
    resolved = path.resolve(strict=must_exist)
    if resolved.parent != (PROJECT_ROOT / "outputs").resolve(strict=True):
        raise RuntimeError("root escaped project outputs")
    return resolved


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if type(payload) is not dict:
        raise RuntimeError("expected JSON object")
    return payload


def _build(args: argparse.Namespace) -> dict[str, object]:
    public_root = _direct_output(args.public_root_relative, must_exist=True)
    audit_root = _direct_output(args.audit_root_relative, must_exist=True)
    prediction_output = _direct_output(args.prediction_output_relative, must_exist=False)
    if prediction_output.exists():
        raise RuntimeError("prediction destination already exists")

    audit_payload = _json(audit_root / "POSTGEN_AUDIT.json")
    public_tree_sha256 = audit_payload.get("public_tree_semantic_sha256")
    if not is_sha256(public_tree_sha256):
        raise RuntimeError("post-generation audit tree hash is absent")

    generation_evidence = {
        filename: snapshot_record(public_root / filename, relative_path=filename)
        for filename in GENERATION_EVIDENCE_FILENAMES
    }
    tasks = []
    task_index = 0
    for seed_alias, seed in zip(SEED_ALIASES, QUALIFICATION_SEEDS, strict=True):
        for dgp in DGP_IDS:
            prefix = f"replays/pass_1/seed_{seed}/dgp_{dgp}"
            tasks.append(
                {
                    "task_index": task_index,
                    "seed_alias": seed_alias,
                    "estimator_seed": seed,
                    "dgp_id": dgp,
                    "canonical": snapshot_record(
                        public_root / prefix / "canonical150.csv",
                        relative_path=f"{prefix}/canonical150.csv",
                    ),
                    "overlay": snapshot_record(
                        public_root / prefix / "v04_overlay.csv",
                        relative_path=f"{prefix}/v04_overlay.csv",
                    ),
                }
            )
            task_index += 1
    audit_evidence = {
        filename: snapshot_record(audit_root / filename, relative_path=filename)
        for filename in AUDIT_EVIDENCE_FILENAMES
    }
    source_records = [
        snapshot_record(PROJECT_ROOT / relative, relative_path=relative)
        for relative in SOURCE_CLOSURE_RELATIVES
    ]
    source_semantic = semantic_sha256(source_records)
    versions = [
        {
            "model_id": MODEL_IDS[0],
            "source_model_version": f"sha256:{public_tree_sha256}",
        },
        *[
            {
                "model_id": model_id,
                "source_model_version": f"sha256:{source_semantic}",
            }
            for model_id in MODEL_IDS[1:]
        ],
    ]
    unsigned = {
        "schema_version": BINDING_SCHEMA,
        "status": BINDING_STATUS,
        "public_root_relative": Path(args.public_root_relative).as_posix(),
        "public_root_identity": snapshot_root_identity(public_root),
        "public_tree_sha256": public_tree_sha256,
        "generation_evidence": generation_evidence,
        "tasks": tasks,
        "audit_root_relative": Path(args.audit_root_relative).as_posix(),
        "audit_root_identity": snapshot_root_identity(audit_root),
        "audit_evidence": audit_evidence,
        "source_records": source_records,
        "source_records_semantic_sha256": source_semantic,
        "source_model_versions": versions,
        "prediction_output_relative": Path(args.prediction_output_relative).as_posix(),
        "activation_marker_relative": (
            f"{Path(args.prediction_output_relative).as_posix()}_activation"
        ),
    }
    binding = seal_payload(unsigned, "binding_semantic_sha256")
    validate_binding_payload(binding)
    # Reopen every exact byte and hold it under the finished binding once before
    # publication. This is still public-only and performs no numerical import.
    with open_bound_inputs(PROJECT_ROOT, binding) as closure:
        closure.revalidate()
    return binding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root-relative", required=True)
    parser.add_argument("--audit-root-relative", required=True)
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
        "schema_version": "expected_pe.pe_c1_c3.binding_source_manifest.v1",
        "source_records": binding["source_records"],
        "source_records_semantic_sha256": binding[
            "source_records_semantic_sha256"
        ],
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    source_sha = write_json_new(staging / "SOURCE_MANIFEST.json", source_manifest)
    checksums = checksum_bytes(
        {"BINDING.json": binding_sha, "SOURCE_MANIFEST.json": source_sha}
    )
    checksums_sha = write_bytes_new(staging / "CHECKSUMS.sha256", checksums)
    # Any exception above leaves staging in place as immutable failure evidence.
    atomic_publish_directory(staging, output)
    sys.stdout.write(
        canonical_json_bytes(
            {
                "status": "FROZEN_POSTGEN_AUDITED_PREDICTION_ONLY_BINDING",
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
