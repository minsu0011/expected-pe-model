"""Publish the isolated spent-only H-OFS extension of the research tournament."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.pre_certification_research_tournament_v1.contracts import (  # noqa: E402
    BCE_CHECKSUMS_SHA256,
    BCE_MANIFEST_SHA256,
    BCE_PREDICTIONS_SHA256,
    RESEARCH_EVIDENCE_CLASS,
    TRUTH_CHECKSUMS_SHA256,
    TRUTH_RECEIPT_SHA256,
    canonical_json_bytes,
)
from research.model_zoo.pre_certification_research_tournament_v1.hofs_extension import (  # noqa: E402
    EXTENDED_MODEL_IDS,
    EXTENSION_OUTPUT_ROOT,
    HOFS_CHECKSUMS_SHA256,
    HOFS_MANIFEST_SHA256,
    HOFS_MODEL_ID,
    HOFS_STANDARDIZED_SHA256,
    evaluate_spent_hofs_extension,
)


PRIOR_BCE_TOURNAMENT_ROOT = (
    "outputs/model_zoo_pre_certification_research_tournament_v1_bce_spent_r4_20260822"
)
PRIOR_BCE_TOURNAMENT_MANIFEST_SHA256 = (
    "c02c3234decce63a605171bb57b2794d362db8576b499512a148e41adf0d874d"
)
PRIOR_BCE_TOURNAMENT_CHECKSUMS_SHA256 = (
    "2c4176e6ac4ca87354931ee64eabec26a004f5ccd3927ccaed0830de8bccbc88"
)
SOURCE_PATHS = (
    "research/model_zoo/pre_certification_research_tournament_v1/contracts.py",
    "research/model_zoo/pre_certification_research_tournament_v1/adapters.py",
    "research/model_zoo/pre_certification_research_tournament_v1/evaluator.py",
    "research/model_zoo/pre_certification_research_tournament_v1/hofs_extension.py",
    "scripts/model_lab/pre_certification_research_tournament_v1/run_hofs_extension.py",
    "tests/model_lab/test_hofs_tournament_extension.py",
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")


def _csv_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    if not rows:
        raise RuntimeError("cannot serialize empty metric rows")
    columns = tuple(rows[0])
    if any(tuple(row) != columns for row in rows):
        raise RuntimeError("metric row schema/order drifted")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(columns), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _prior_bce_hashes() -> dict[str, str]:
    paths = {
        "manifest": PROJECT_ROOT / PRIOR_BCE_TOURNAMENT_ROOT / "MANIFEST.json",
        "checksums": PROJECT_ROOT / PRIOR_BCE_TOURNAMENT_ROOT / "CHECKSUMS.sha256",
    }
    observed = {name: _sha256(path.read_bytes()) for name, path in paths.items()}
    if observed != {
        "manifest": PRIOR_BCE_TOURNAMENT_MANIFEST_SHA256,
        "checksums": PRIOR_BCE_TOURNAMENT_CHECKSUMS_SHA256,
    }:
        raise RuntimeError("prior BCE tournament output drifted")
    return observed


def _source_manifest() -> dict[str, Any]:
    rows = []
    for relative in SOURCE_PATHS:
        content = (PROJECT_ROOT / relative).read_bytes()
        rows.append(
            {"relative_path": relative, "raw_sha256": _sha256(content), "bytes": len(content)}
        )
    return {
        "files": rows,
        "file_count": len(rows),
        "semantic_sha256": _sha256(canonical_json_bytes(rows)),
    }


def _report(result: Any) -> bytes:
    ranking = sorted(result.pooled_metrics, key=lambda row: float(row["model_mae"]))
    lines = [
        "# Spent Research Tournament — H-OFS r2 extension",
        "",
        "Evidence: **RESEARCH_ONLY**. This extension has no certification, promotion, or registry authority.",
        "",
        "| rank | model | MAE | RMSE | MAE gain vs v04 |",
        "|---:|---|---:|---:|---:|",
    ]
    for rank, row in enumerate(ranking, start=1):
        lines.append(
            f"| {rank} | {row['model_id']} | {float(row['model_mae']):.8f} | "
            f"{float(row['model_rmse']):.8f} | "
            f"{float(row['mae_relative_gain_vs_v04']):+.4%} |"
        )
    lines.extend(
        [
            "",
            "The exact common mask contains 64,800 rows. H-OFS was read from its immutable r2 "
            "standardized prediction artifact. The prior BCE tournament bundle was hash-checked "
            "before and after scoring and was not modified.",
            "",
            "Pairwise oracle metrics are unattainable descriptive upper bounds only.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _publish(files: Mapping[str, bytes]) -> dict[str, Any]:
    output = (PROJECT_ROOT / EXTENSION_OUTPUT_ROOT).resolve()
    outputs = (PROJECT_ROOT / "outputs").resolve()
    if output.parent != outputs or output.exists():
        raise RuntimeError("extension output root exists or escaped outputs")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=outputs))
    published = False
    try:
        for name in sorted(files):
            path = staging / name
            with path.open("xb") as handle:
                handle.write(files[name])
                handle.flush()
                os.fsync(handle.fileno())
        ledger = b"".join(
            f"{_sha256(files[name])}  {name}\n".encode("ascii") for name in sorted(files)
        )
        with (staging / "CHECKSUMS.sha256").open("xb") as handle:
            handle.write(ledger)
            handle.flush()
            os.fsync(handle.fileno())
        expected = set(files) | {"CHECKSUMS.sha256"}
        observed = {path.name for path in staging.iterdir() if path.is_file()}
        if expected != observed:
            raise RuntimeError("extension staging universe drifted")
        os.replace(staging, output)
        published = True
        return {
            "output_relative": EXTENSION_OUTPUT_ROOT,
            "file_count": len(expected),
            "checksums_raw_sha256": _sha256(ledger),
            "status": "PASS_ATOMIC_RESEARCH_ONLY_HOFS_EXTENSION_PUBLICATION",
        }
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)


def run() -> dict[str, Any]:
    prior_before = _prior_bce_hashes()
    result = evaluate_spent_hofs_extension(PROJECT_ROOT)
    prior_after = _prior_bce_hashes()
    if prior_before != prior_after:
        raise RuntimeError("prior BCE tournament changed during extension scoring")
    source_manifest = _source_manifest()
    summary = list(result.candidate_summary)
    hofs_summary = next(row for row in summary if row["candidate_id"] == HOFS_MODEL_ID)
    input_manifest = {
        "schema_version": "expected_pe.pre_cert_research.hofs_extension_inputs.v1",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "bce_predictions_raw_sha256": BCE_PREDICTIONS_SHA256,
        "bce_manifest_raw_sha256": BCE_MANIFEST_SHA256,
        "bce_checksums_raw_sha256": BCE_CHECKSUMS_SHA256,
        "hofs_manifest_raw_sha256": HOFS_MANIFEST_SHA256,
        "hofs_checksums_raw_sha256": HOFS_CHECKSUMS_SHA256,
        "hofs_standardized_raw_sha256": HOFS_STANDARDIZED_SHA256,
        "spent_truth_receipt_raw_sha256": TRUTH_RECEIPT_SHA256,
        "spent_truth_checksums_raw_sha256": TRUTH_CHECKSUMS_SHA256,
        "prior_bce_tournament_before": prior_before,
        "prior_bce_tournament_after": prior_after,
        "prior_bce_tournament_mutated": False,
    }
    manifest = {
        "schema_version": "expected_pe.pre_cert_research.hofs_extension_manifest.v1",
        "status": "PASS_HOFS_R2_SPENT_RESEARCH_TOURNAMENT_EXTENSION_COMPLETE",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "output_root": EXTENSION_OUTPUT_ROOT,
        "scored_models": list(EXTENDED_MODEL_IDS),
        "common_rows": 64800,
        "hofs_model_id": HOFS_MODEL_ID,
        "hofs_pooled_mae": hofs_summary["pooled_mae"],
        "hofs_pooled_rmse": hofs_summary["pooled_rmse"],
        "hofs_mae_gain_vs_v04": hofs_summary["mae_gain_vs_v04"],
        "source_manifest_semantic_sha256": source_manifest["semantic_sha256"],
        "input_manifest_semantic_sha256": _sha256(canonical_json_bytes(input_manifest)),
        "prior_bce_tournament_mutated": False,
        "model_fits_during_scoring": 0,
        "certification_or_promotion_authority": False,
    }
    files = {
        "ACCESS_RECEIPT.json": _json_bytes(dict(result.access_receipt)),
        "BOOTSTRAP_METRICS.csv": _csv_bytes(list(result.bootstrap_metrics)),
        "CANDIDATE_SUMMARY.csv": _csv_bytes(summary),
        "COMPLEMENTARITY.csv": _csv_bytes(list(result.complementarity)),
        "DGP_METRICS.csv": _csv_bytes(list(result.dgp_metrics)),
        "FOLD_METRICS.csv": _csv_bytes(list(result.fold_metrics)),
        "INPUT_MANIFEST.json": _json_bytes(input_manifest),
        "MANIFEST.json": _json_bytes(manifest),
        "POOLED_METRICS.csv": _csv_bytes(list(result.pooled_metrics)),
        "REPORT.md": _report(result),
        "RUNTIME_RECEIPT.json": _json_bytes(dict(result.runtime_receipt)),
        "SEED_DGP_METRICS.csv": _csv_bytes(list(result.seed_dgp_metrics)),
        "SEED_METRICS.csv": _csv_bytes(list(result.seed_metrics)),
        "SOURCE_MANIFEST.json": _json_bytes(source_manifest),
        "TAIL_METRICS.csv": _csv_bytes(list(result.tail_metrics)),
    }
    publication = _publish(files)
    return {"publication": publication, "hofs_summary": hofs_summary, "status": manifest["status"]}


def main() -> int:
    print(json.dumps(run(), sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
