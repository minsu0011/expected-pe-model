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

from research.model_zoo.bounded_consensus_v1 import design_lock_sha256  # noqa: E402
from research.model_zoo.bounded_consensus_v1.contracts import canonical_json_bytes  # noqa: E402
from research.model_zoo.bounded_consensus_v1_observable_state_r2_integration.runtime import (  # noqa: E402
    resource_receipt,
    validate_runtime,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring import (  # noqa: E402
    file_record,
    load_and_verify_capability,
    score_from_capability,
    sha256_file,
)
from research.model_zoo.bounded_consensus_v1_observable_state_r2_scoring.contracts import (  # noqa: E402
    PREDICTION_RAW_SHA256,
)


DEFAULT_CAPABILITY = (
    PROJECT_ROOT
    / "outputs"
    / "bounded_consensus_v1_observable_state_r2_detached_scoring_capability_20260820"
    / "EVALUATION_CAPABILITY.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "outputs" / "bounded_consensus_v1_observable_state_r2_detached_scoring_20260820"
)
TABLES = (
    ("POOLED_METRICS.csv", "pooled_metrics"),
    ("SEED_METRICS.csv", "seed_metrics"),
    ("LANE_METRICS.csv", "lane_metrics"),
    ("SEED_LANE_METRICS.csv", "seed_lane_metrics"),
    ("CORRELATION_DIAGNOSTICS.csv", "correlation_diagnostics"),
    ("ORACLE_DIAGNOSTICS.csv", "oracle_diagnostics"),
    ("DECISIONS.csv", "decisions"),
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


def _verify_source_manifest(capability: dict[str, Any]) -> None:
    record = capability["source_manifest"]
    path = Path(record["path"]).resolve(strict=True)
    if path.stat().st_size != int(record["bytes"]) or sha256_file(path) != record["sha256"]:
        raise RuntimeError("capability source manifest changed")
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError("capability source manifest is empty")
    for row in rows:
        relative = Path(row["relative_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("capability source manifest contains unsafe path")
        source = (PROJECT_ROOT / relative).resolve(strict=True)
        try:
            source.relative_to(PROJECT_ROOT.resolve(strict=True))
        except ValueError as exc:
            raise RuntimeError("scoring source escapes the project root") from exc
        if source.stat().st_size != int(row["bytes"]) or sha256_file(source) != row["sha256"]:
            raise RuntimeError(f"scoring source changed after capability freeze: {source}")


def score(capability_path: Path, output: Path) -> dict[str, Any]:
    validate_runtime()
    output = output.resolve()
    if any(
        blocked in tuple(part.casefold() for part in output.parts)
        for blocked in ("heldout", "registry", "champion")
    ):
        raise RuntimeError("scoring output crosses a blocked path boundary")
    if output.exists():
        raise FileExistsError("immutable scoring output already exists")
    capability_path = capability_path.resolve(strict=True)
    capability = load_and_verify_capability(capability_path)
    _verify_source_manifest(capability)
    prediction_path = Path(capability["prediction_artifact"]["path"]).resolve(strict=True)
    prediction_hash_before = sha256_file(prediction_path)
    if prediction_hash_before != PREDICTION_RAW_SHA256:
        raise RuntimeError("prediction bytes differ before scoring")
    result = score_from_capability(capability_path)
    prediction_hash_after = sha256_file(prediction_path)
    if prediction_hash_after != prediction_hash_before:
        raise RuntimeError("prediction bytes changed during scoring")
    output.mkdir(parents=True, exist_ok=False)

    artifact_records: dict[str, dict[str, Any]] = {}
    for filename, attribute in TABLES:
        path = output / filename
        getattr(result, attribute).to_csv(
            path,
            index=False,
            lineterminator="\n",
            na_rep="NaN",
            float_format="%.17g",
        )
        artifact_records[filename] = file_record(path).__dict__
    decisions = {
        str(row["bce_v1_variant_id"]): str(row["research_gate_status"])
        for row in result.decisions.to_dict(orient="records")
    }
    diagnostic_geometry = {
        "pooled_metric_rows": len(result.pooled_metrics),
        "seed_metric_rows": len(result.seed_metrics),
        "lane_metric_rows": len(result.lane_metrics),
        "seed_lane_metric_rows": len(result.seed_lane_metrics),
        "correlation_diagnostic_rows": len(result.correlation_diagnostics),
        "oracle_diagnostic_rows": len(result.oracle_diagnostics),
        "decision_rows": len(result.decisions),
    }
    receipt = _seal(
        {
            "format_version": 1,
            "status": "DETACHED_STATE_R2_QUALIFICATION_SCORING_COMPLETE",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": result.capability_sha256,
            "bounded_consensus_design_lock_sha256": design_lock_sha256(),
            "prediction_artifact": capability["prediction_artifact"],
            "prediction_raw_sha256_before_scoring": prediction_hash_before,
            "prediction_raw_sha256_after_scoring": prediction_hash_after,
            "prediction_bytes_preserved": True,
            "date_normalization_before_join": "pandas_datetime64_ns",
            "join_validation": "variant_by_variant_exact_one_to_one",
            "truth_files_opened": [record.__dict__ for record in result.truth_file_records],
            "truth_file_count": len(result.truth_file_records),
            "heldout_files_opened": False,
            "registry_mutated": False,
            "champion_mutated": False,
            "oracle_diagnostics_used_by_gate": False,
            "decisions": decisions,
            "diagnostic_geometry": diagnostic_geometry,
            "artifacts": artifact_records,
            "runtime": resource_receipt(stage="detached_state_r2_qualification_scoring"),
        }
    )
    receipt_path = output / "SCORING_RECEIPT.json"
    _write_json(receipt_path, receipt)
    manifest = _seal(
        {
            "format_version": 1,
            "status": "SEALED_STATE_R2_RESEARCH_RESULTS_ONLY",
            "capability": file_record(capability_path).__dict__,
            "capability_sha256": result.capability_sha256,
            "scoring_receipt": file_record(receipt_path).__dict__,
            "scoring_receipt_manifest_sha256": receipt["manifest_sha256"],
            "artifacts": artifact_records,
            "decisions": decisions,
            "diagnostic_geometry": diagnostic_geometry,
            "prediction_bytes_preserved": True,
            "promotion_authority": False,
            "registry_or_champion_mutation": False,
            "heldout_access": False,
        }
    )
    manifest_path = output / "SCORING_MANIFEST.json"
    _write_json(manifest_path, manifest)
    checksum_paths = [output / filename for filename, _ in TABLES]
    checksum_paths.extend((receipt_path, manifest_path))
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
        newline="\n",
    )
    return {
        "output": str(output),
        "capability_sha256": result.capability_sha256,
        "scoring_receipt_sha256": receipt["manifest_sha256"],
        "scoring_manifest_sha256": manifest["manifest_sha256"],
        "checksums_raw_sha256": sha256_file(checksum_path),
        "prediction_bytes_preserved": True,
        "decisions": decisions,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability", type=Path, default=DEFAULT_CAPABILITY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(score(args.capability, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
