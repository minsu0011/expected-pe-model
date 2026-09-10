from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration import (  # noqa: E402
    assemble_bound_state_r2_predictions,
    bind_state_r2_inputs,
    integration_design_sha256,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.contracts import (  # noqa: E402
    BASE_PREDICTION_COLUMN,
    CHALLENGER_A_COLUMN,
    CHALLENGER_B_COLUMN,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.custody import (  # noqa: E402
    file_record,
    sha256_file,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.runtime import (  # noqa: E402
    resource_receipt,
    validate_runtime,
)


DEFAULT_PREFLIGHT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_observable_state_r2_score_free_preflight_py310_20260820"
    / "PREFLIGHT.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_observable_state_r2_prediction_only_py310_20260820"
)


def _seal(payload: dict[str, Any], *, field: str = "manifest_sha256") -> dict[str, Any]:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return {
        **unsigned,
        field: hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _load_preflight(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("preflight root must be an object")
    seal = str(payload.get("manifest_sha256", ""))
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != seal:
        raise RuntimeError("preflight self-seal changed")
    if payload.get("status") != "READY_PREDICTION_ONLY":
        raise RuntimeError("preflight is not prediction-ready")
    if payload.get("integration_design_sha256") != integration_design_sha256():
        raise RuntimeError("preflight integration design changed")
    actions = payload.get("actions", {})
    blocked = (
        "truth_files_opened",
        "score_files_opened",
        "metric_files_opened",
        "decision_files_opened",
        "heldout_files_opened",
        "registry_files_opened",
        "score_computation_executed",
    )
    if any(actions.get(key) is not False for key in blocked):
        raise RuntimeError("preflight score-free action boundary changed")
    return payload, hashlib.sha256(raw).hexdigest()


def _verify_source_manifest(preflight: dict[str, Any]) -> tuple[Path, str]:
    record = preflight.get("source_manifest", {})
    source_path = Path(str(record.get("path", ""))).resolve(strict=True)
    if source_path.stat().st_size != int(record.get("bytes", -1)):
        raise RuntimeError("source manifest byte count changed")
    source_hash = sha256_file(source_path)
    if source_hash != record.get("sha256"):
        raise RuntimeError("source manifest hash changed")
    with source_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError("source manifest is empty")
    for row in rows:
        relative = Path(row["relative_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("source manifest contains an unsafe path")
        source = (PROJECT_ROOT / relative).resolve(strict=True)
        try:
            source.relative_to(PROJECT_ROOT.resolve(strict=True))
        except ValueError as exc:
            raise RuntimeError("source manifest path escapes the project root") from exc
        if source.stat().st_size != int(row["bytes"]) or sha256_file(source) != row["sha256"]:
            raise RuntimeError(f"source closure changed: {row['relative_path']}")
    return source_path, source_hash


def _prediction_csv_sha256(frame: Any) -> str:
    buffer = io.StringIO(newline="")
    frame.to_csv(
        buffer,
        index=False,
        lineterminator="\n",
        na_rep="NaN",
        float_format="%.17g",
    )
    return hashlib.sha256(buffer.getvalue().encode("utf-8")).hexdigest()


def _validate_output_path(output: Path) -> Path:
    resolved = output.resolve()
    lowered = resolved.as_posix().casefold()
    if any(token in lowered for token in ("heldout", "truth", "evaluation", "score")):
        raise RuntimeError("prediction output path crosses a blocked custody boundary")
    if resolved.exists():
        raise FileExistsError("immutable prediction-only output already exists")
    return resolved


def assemble(preflight_path: Path, output: Path) -> dict[str, Any]:
    validate_runtime()
    output = _validate_output_path(output)
    preflight, preflight_raw_sha256 = _load_preflight(preflight_path.resolve(strict=True))
    source_path, source_manifest_raw_sha256 = _verify_source_manifest(preflight)
    closure = bind_state_r2_inputs(PROJECT_ROOT)
    closure_payload = closure.to_payload()
    closure_sha256 = hashlib.sha256(canonical_json_bytes(closure_payload)).hexdigest()
    if closure_sha256 != preflight.get("input_closure_sha256"):
        raise RuntimeError("live input closure differs from the frozen preflight")

    primary = assemble_bound_state_r2_predictions(closure)
    replay = assemble_bound_state_r2_predictions(closure)
    primary_csv_sha = _prediction_csv_sha256(primary.predictions)
    replay_csv_sha = _prediction_csv_sha256(replay.predictions)
    if primary_csv_sha != replay_csv_sha or not primary.predictions.equals(replay.predictions):
        raise RuntimeError("fixed-order prediction replay is not byte-exact")

    output.mkdir(parents=True, exist_ok=False)
    prediction_path = output / "PREDICTIONS.csv"
    primary.predictions.to_csv(
        prediction_path,
        index=False,
        lineterminator="\n",
        na_rep="NaN",
        float_format="%.17g",
    )
    if sha256_file(prediction_path) != primary_csv_sha:
        raise RuntimeError("written prediction bytes differ from in-memory freeze")

    geometry_path = output / "SEED_GEOMETRY.json"
    geometry = _seal(
        {
            "format_version": 1,
            "integration_design_sha256": integration_design_sha256(),
            "seeds": [audit.__dict__ for audit in primary.seed_audits],
            "total_canonical_rows": sum(audit.canonical_rows for audit in primary.seed_audits),
            "total_source_prediction_rows": sum(
                audit.prediction_rows for audit in primary.seed_audits
            ),
            "total_fold_blocks": sum(audit.fold_count for audit in primary.seed_audits),
        }
    )
    _write_json(geometry_path, geometry)

    receipt_path = output / "RUNTIME_RECEIPT.json"
    receipt = _seal(
        {
            "format_version": 1,
            "status": "PINNED_PREDICTION_RUNTIME_VERIFIED",
            "integration_design_sha256": integration_design_sha256(),
            "input_closure_sha256": closure_sha256,
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "preflight_raw_sha256": preflight_raw_sha256,
            "source_manifest": file_record(source_path).__dict__,
            "source_manifest_raw_sha256": source_manifest_raw_sha256,
            "resource": resource_receipt(stage="prediction_only_assembly"),
            "deterministic_replay": {
                "executed": True,
                "dataframe_exact": True,
                "prediction_csv_sha256": primary_csv_sha,
            },
            "prediction_artifact": file_record(prediction_path).__dict__,
            "seed_geometry_artifact": file_record(geometry_path).__dict__,
            "truth_files_opened": False,
            "score_files_opened": False,
            "metric_files_opened": False,
            "decision_files_opened": False,
            "heldout_files_opened": False,
            "registry_files_opened": False,
            "independent_audit_structured_content_read": False,
            "evaluation_executed": False,
            "scores_computed": False,
        }
    )
    _write_json(receipt_path, receipt)

    manifest_path = output / "PREDICTION_MANIFEST.json"
    manifest = _seal(
        {
            "format_version": 1,
            "status": "PREDICTION_ONLY_COMPLETE",
            "integration_design_sha256": integration_design_sha256(),
            "input_closure_sha256": closure_sha256,
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "preflight_raw_sha256": preflight_raw_sha256,
            "state_design_lock": closure.state_design_lock.__dict__,
            "state_design_semantic_sha256": closure.state_design_semantic_sha256,
            "state_prediction_manifest": closure.state_prediction_manifest.__dict__,
            "state_prediction_manifest_semantic_sha256": (
                closure.state_prediction_manifest_semantic_sha256
            ),
            "state_prediction_freeze": closure.state_prediction_freeze.__dict__,
            "state_prediction_freeze_semantic_sha256": (
                closure.state_prediction_freeze_semantic_sha256
            ),
            "independent_audit_provenance": [
                {**record.__dict__, "interpretation": "OPAQUE_RAW_HASH_ONLY"}
                for record in closure.independent_audit_provenance
            ],
            "source_manifest": file_record(source_path).__dict__,
            "prediction_artifact": file_record(prediction_path).__dict__,
            "seed_geometry_artifact": file_record(geometry_path).__dict__,
            "runtime_receipt": file_record(receipt_path).__dict__,
            "runtime_receipt_manifest_sha256": receipt["manifest_sha256"],
            "rows": len(primary.predictions),
            "seed_count": len(primary.seed_audits),
            "fold_blocks": sum(audit.fold_count for audit in primary.seed_audits),
            "variant_ids": list(primary.variant_ids),
            "base_prediction_column": BASE_PREDICTION_COLUMN,
            "challenger_a_column": CHALLENGER_A_COLUMN,
            "challenger_b_column": CHALLENGER_B_COLUMN,
            "deterministic_replay_prediction_csv_sha256": primary_csv_sha,
            "truth_files_opened": False,
            "score_files_opened": False,
            "metric_files_opened": False,
            "decision_files_opened": False,
            "heldout_files_opened": False,
            "registry_files_opened": False,
            "independent_audit_structured_content_read": False,
            "scores_computed": False,
            "promotion_authority": False,
        }
    )
    _write_json(manifest_path, manifest)

    freeze_path = output / "PREDICTION_FREEZE.json"
    freeze = _seal(
        {
            "format_version": 1,
            "status": "PREDICTION_ARTIFACTS_FROZEN_BEFORE_SCORE",
            "integration_design_sha256": integration_design_sha256(),
            "prediction_manifest": file_record(manifest_path).__dict__,
            "prediction_manifest_semantic_sha256": manifest["manifest_sha256"],
            "prediction_artifact": file_record(prediction_path).__dict__,
            "seed_geometry_artifact": file_record(geometry_path).__dict__,
            "runtime_receipt": file_record(receipt_path).__dict__,
            "truth_files_opened": False,
            "score_files_opened": False,
            "evaluation_executed": False,
            "scores_computed": False,
        },
        field="freeze_sha256",
    )
    _write_json(freeze_path, freeze)

    checksum_paths = (
        prediction_path,
        geometry_path,
        receipt_path,
        manifest_path,
        freeze_path,
    )
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output),
        "prediction_raw_sha256": sha256_file(prediction_path),
        "prediction_manifest_sha256": manifest["manifest_sha256"],
        "prediction_freeze_sha256": freeze["freeze_sha256"],
        "checksums_raw_sha256": sha256_file(checksum_path),
        "rows": len(primary.predictions),
        "scores_computed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", type=Path, default=DEFAULT_PREFLIGHT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(assemble(args.preflight, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
