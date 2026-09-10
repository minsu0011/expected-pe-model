"""Publish the exact spent-only BCE pre-certification research tournament."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Mapping, Sequence
import uuid


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.pre_certification_research_tournament_v1.contracts import (  # noqa: E402
    BCE_PREDICTION_ROOT,
    CHAMPION_ID,
    DETAILED_EVIDENCE_CLASS,
    FIVE_CANDIDATE_SLOTS,
    OUTPUT_ROOT,
    RESEARCH_EVIDENCE_CLASS,
    SCORED_CANDIDATE_IDS,
    design_lock_payload,
    semantic_sha256,
)
from research.model_zoo.pre_certification_research_tournament_v1.evaluator import (  # noqa: E402
    TournamentResult,
    evaluate_spent_bce_surface,
)
from research.model_zoo.pre_certification_research_tournament_v1.inventory import (  # noqa: E402
    build_inventory,
)


FOLD_DIAGNOSTICS_RELATIVE = f"{BCE_PREDICTION_ROOT}/FOLD_DIAGNOSTICS.json"
FOLD_DIAGNOSTICS_SHA256 = (
    "b5dc9d37f81736e91e512594fa002d79ae47bbbc9ac7e72b20d07084ec62b814"
)
SOURCE_PATHS = (
    "research/model_zoo/pre_certification_research_tournament_v1/__init__.py",
    "research/model_zoo/pre_certification_research_tournament_v1/contracts.py",
    "research/model_zoo/pre_certification_research_tournament_v1/adapters.py",
    "research/model_zoo/pre_certification_research_tournament_v1/inventory.py",
    "research/model_zoo/pre_certification_research_tournament_v1/evaluator.py",
    "research/model_zoo/pre_certification_research_tournament_v1/DESIGN.md",
    "scripts/model_lab/pre_certification_research_tournament_v1/run_research_tournament.py",
    "tests/model_lab/test_pre_certification_research_tournament_v1.py",
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _pretty_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _csv_bytes(records: Sequence[Mapping[str, Any]]) -> bytes:
    if not records:
        raise RuntimeError("research tournament CSV records cannot be empty")
    fieldnames = list(records[0])
    expected = set(fieldnames)
    if any(set(record) != expected for record in records):
        raise RuntimeError("research tournament CSV records have inconsistent fields")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue().encode("utf-8")


def _write_new(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return _sha256(content)


def _source_manifest() -> tuple[list[dict[str, Any]], bytes]:
    rows: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        path = (PROJECT_ROOT / relative).resolve()
        if path.relative_to(PROJECT_ROOT.resolve()).as_posix() != relative:
            raise RuntimeError(f"source path identity drifted: {relative}")
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"source file missing or nonordinary: {relative}")
        content = path.read_bytes()
        rows.append(
            {
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "relative_path": relative,
                "bytes": len(content),
                "raw_sha256": _sha256(content),
            }
        )
    return rows, _csv_bytes(rows)


def _prediction_cost_receipt() -> dict[str, Any]:
    path = (PROJECT_ROOT / FOLD_DIAGNOSTICS_RELATIVE).resolve()
    content = path.read_bytes()
    if _sha256(content) != FOLD_DIAGNOSTICS_SHA256:
        raise RuntimeError("BCE fold diagnostics hash drifted")
    diagnostics = json.loads(content.decode("utf-8"))
    if type(diagnostics) is not list or len(diagnostics) != 3_100:
        raise RuntimeError("BCE fold diagnostics geometry drifted")
    fit_seconds_by_model: dict[str, list[float]] = {}
    for fold in diagnostics:
        if type(fold) is not dict or type(fold.get("models")) is not list:
            raise RuntimeError("BCE fold diagnostics schema drifted")
        for model in fold["models"]:
            fit_seconds_by_model.setdefault(str(model["model_id"]), []).append(
                float(model["fit_wall_seconds"])
            )
    if sorted(len(values) for values in fit_seconds_by_model.values()) != [3_100, 3_100]:
        raise RuntimeError("BCE constituent fit counts drifted")
    total = sum(sum(values) for values in fit_seconds_by_model.values())
    return {
        "schema_version": "expected_pe.pre_cert_research.prior_prediction_cost.v1",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "source_relative_path": FOLD_DIAGNOSTICS_RELATIVE,
        "source_raw_sha256": FOLD_DIAGNOSTICS_SHA256,
        "fold_blocks": 3_100,
        "constituent_fit_count": 6_200,
        "fit_wall_seconds_sum": total,
        "outer_workers": 32,
        "inner_threads": 1,
        "gpu_used": False,
        "model_fit_cost": {
            model_id: {
                "fits": len(values),
                "fit_wall_seconds_sum": sum(values),
                "fit_wall_seconds_median": sorted(values)[len(values) // 2],
                "fit_wall_seconds_max": max(values),
            }
            for model_id, values in sorted(fit_seconds_by_model.items())
        },
        "candidate_transform_incremental_fit_count": 0,
    }


def _scorecard(result: TournamentResult) -> list[dict[str, Any]]:
    metrics = {row["candidate_id"]: row for row in result.candidate_summary}
    rows: list[dict[str, Any]] = []
    for slot in FIVE_CANDIDATE_SLOTS:
        score = metrics.get(slot.scored_model_id or "")
        scored = score is not None
        rows.append(
            {
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "candidate": slot.display_name,
                "slot_id": slot.slot_id,
                "family": slot.family,
                "version": slot.current_version,
                "research_readiness": slot.research_readiness,
                "research_score_status": (
                    score["research_score_status"] if scored else "BLOCKED_IMPLEMENTATION"
                ),
                "fresh_qualification_status": "NOT_ACCESSED",
                "mae": score["pooled_mae"] if scored else None,
                "rmse": score["pooled_rmse"] if scored else None,
                "gain_vs_v04_mae": score["mae_gain_vs_v04"] if scored else None,
                "gain_vs_v04_rmse": score["rmse_gain_vs_v04"] if scored else None,
                "seed_wins": score["seed_wins"] if scored else None,
                "dgp_wins": score["dgp_wins"] if scored else None,
                "worst_seed_harm": score["worst_seed_harm"] if scored else None,
                "worst_dgp_harm": score["worst_dgp_harm"] if scored else None,
                "worst_seed_dgp_harm": score["worst_seed_dgp_harm"] if scored else None,
                "p95": score["p95_absolute_error"] if scored else None,
                "p99": score["p99_absolute_error"] if scored else None,
                "extreme_count": score["extreme_error_count"] if scored else None,
                "systematic_joint_tail_failures": (
                    score["systematic_dgp_joint_tail_failures"] if scored else None
                ),
                "error_corr_v04": score["signed_error_corr_v04"] if scored else None,
                "abs_error_corr_v04": score["abs_error_corr_v04"] if scored else None,
                "oracle_pair_mae_gain_vs_v04": (
                    score["oracle_pair_mae_gain_vs_v04"] if scored else None
                ),
                "bootstrap_mae_gain_lower_5pct": (
                    score["bootstrap_mae_gain_lower_5pct"] if scored else None
                ),
                "deployable": False,
                "pit_safe": "PASS_RESEARCH_PATH" if scored else "PENDING_NEW_RUNNER_AUDIT",
                "causal_safe": "PASS_RESEARCH_PATH" if scored else "PENDING_NEW_RUNNER_AUDIT",
                "portfolio_role": (
                    "RESEARCH_CANDIDATE_PENDING_FORMAL_CERTIFICATION"
                    if scored
                    else "BLOCKED_IMPLEMENTATION"
                ),
                "certification_status": "RESEARCH_ONLY_NOT_CERTIFIED",
            }
        )
    return rows


def _report(scorecard: Sequence[Mapping[str, Any]], result: TournamentResult) -> str:
    lines = [
        "# Five-candidate pre-certification research tournament V1",
        "",
        "Evidence: **RESEARCH_ONLY**. This is spent outcome-exposed research evidence, not fresh ",
        "qualification, heldout, certification, promotion, or portfolio-admission evidence.",
        "",
        "| slot | candidate | research score | MAE gain vs v04 | RMSE gain vs v04 | seed wins | DGP wins | worst seed-DGP harm |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in scorecard:
        if row["mae"] is None:
            lines.append(
                f"| {row['slot_id']} | {row['candidate']} | BLOCKED_IMPLEMENTATION |  |  |  |  |  |"
            )
        else:
            lines.append(
                "| {slot_id} | {candidate} | SCORED_SPENT_R4 | {mae:+.4%} | {rmse:+.4%} | "
                "{seed_wins}/5 | {dgp_wins}/10 | {worst:.4%} |".format(
                    slot_id=row["slot_id"],
                    candidate=row["candidate"],
                    mae=float(row["gain_vs_v04_mae"]),
                    rmse=float(row["gain_vs_v04_rmse"]),
                    seed_wins=int(row["seed_wins"]),
                    dgp_wins=int(row["dgp_wins"]),
                    worst=float(row["worst_seed_dgp_harm"]),
                )
            )
    lines.extend(
        [
            "",
            "The exact common comparison uses 64,800 identities. Champion and all three BCE ",
            "predictions are valid on every row; model-specific row drops are zero. H-OFS has no ",
            "usable prediction because V11 is execution-inert. Causal TCN has no full R4 runner or ",
            "prediction because V7 is terminal `NO_GO 0/1/0`. Neither missing model is assigned a ",
            "synthetic or zero score.",
            "",
            f"Spent truth files opened: {result.access_receipt['truth_payload_files_opened']}.",
            "Latent files opened: 0. Fresh files opened: 0. Heldout files opened: 0.",
            "Registry/Champion mutations: 0.",
            "",
            "Pairwise oracle metrics in `COMPLEMENTARITY.csv` are unattainable diagnostics only.",
        ]
    )
    return "\n".join(lines) + "\n"


def run() -> dict[str, Any]:
    started = time.perf_counter()
    inventory = build_inventory(PROJECT_ROOT)
    design = design_lock_payload()
    result = evaluate_spent_bce_surface(PROJECT_ROOT)
    prediction_cost = _prediction_cost_receipt()
    scorecard = _scorecard(result)
    source_rows, source_bytes = _source_manifest()

    final_root = (PROJECT_ROOT / OUTPUT_ROOT).resolve()
    outputs = (PROJECT_ROOT / "outputs").resolve()
    if final_root.parent != outputs or final_root.exists():
        raise FileExistsError("unique research tournament output root already exists or escaped")
    staging = outputs / f".{final_root.name}.staging.{uuid.uuid4().hex}"
    staging.mkdir(parents=False, exist_ok=False)
    published = False
    try:
        artifacts: dict[str, bytes] = {
            "DESIGN_LOCK.json": _pretty_json_bytes(design),
            "INVENTORY.json": _pretty_json_bytes(inventory),
            "POOLED_METRICS.csv": _csv_bytes(result.pooled_metrics),
            "SEED_METRICS.csv": _csv_bytes(result.seed_metrics),
            "DGP_METRICS.csv": _csv_bytes(result.dgp_metrics),
            "SEED_DGP_METRICS.csv": _csv_bytes(result.seed_dgp_metrics),
            "FOLD_METRICS.csv": _csv_bytes(result.fold_metrics),
            "TAIL_METRICS.csv": _csv_bytes(result.tail_metrics),
            "COMPLEMENTARITY.csv": _csv_bytes(result.complementarity),
            "BOOTSTRAP_METRICS.csv": _csv_bytes(result.bootstrap_metrics),
            "CANDIDATE_SUMMARY.csv": _csv_bytes(result.candidate_summary),
            "PE_FIVE_CANDIDATE_SCORECARD.csv": _csv_bytes(scorecard),
            "ACCESS_RECEIPT.json": _pretty_json_bytes(dict(result.access_receipt)),
            "RUNTIME_RECEIPT.json": _pretty_json_bytes(
                {
                    **dict(result.runtime_receipt),
                    "prior_bce_prediction_cost": prediction_cost,
                    "publisher_elapsed_seconds_before_manifest": time.perf_counter() - started,
                    "python": platform.python_version(),
                    "python_executable": sys.executable.replace("\\", "/"),
                    "platform": platform.platform(),
                }
            ),
            "SOURCE_MANIFEST.csv": source_bytes,
            "REPORT.md": _report(scorecard, result).encode("utf-8"),
        }
        hashes: dict[str, str] = {}
        for name, content in artifacts.items():
            hashes[name] = _write_new(staging / name, content)

        manifest: dict[str, Any] = {
            "schema_version": "expected_pe.pre_cert_research.manifest.v1",
            "status": "PASS_BCE_3_OF_5_SPENT_RESEARCH_TOURNAMENT_COMPLETE",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "evidence_class": RESEARCH_EVIDENCE_CLASS,
            "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
            "design_semantic_sha256": design["design_semantic_sha256"],
            "inventory_semantic_sha256": semantic_sha256(inventory),
            "candidate_slots": [slot.slot_id for slot in FIVE_CANDIDATE_SLOTS],
            "scored_candidates": list(SCORED_CANDIDATE_IDS),
            "champion_comparator": CHAMPION_ID,
            "blocked_candidates": ["PE-C4", "PE-C5"],
            "blocked_status": "BLOCKED_IMPLEMENTATION_NOT_SCORED_NOT_ZERO_FILLED",
            "common_identity_rows": 64_800,
            "truth_payload_files_opened": 50,
            "latent_payload_files_opened": 0,
            "fresh_payload_files_opened": 0,
            "heldout_payload_files_opened": 0,
            "model_fits_during_scoring": 0,
            "parameter_or_alpha_sweeps": 0,
            "registry_or_champion_mutations": 0,
            "certification_or_promotion_authority": False,
            "artifacts": {
                name: {"bytes": len(artifacts[name]), "raw_sha256": digest}
                for name, digest in sorted(hashes.items())
            },
            "source_file_count": len(source_rows),
        }
        manifest["manifest_semantic_sha256"] = semantic_sha256(manifest)
        manifest_bytes = _pretty_json_bytes(manifest)
        hashes["MANIFEST.json"] = _write_new(staging / "MANIFEST.json", manifest_bytes)
        checksum_bytes = "".join(
            f"{digest}  {name}\n" for name, digest in sorted(hashes.items())
        ).encode("ascii")
        checksums_sha256 = _write_new(staging / "CHECKSUMS.sha256", checksum_bytes)

        expected_files = set(hashes) | {"CHECKSUMS.sha256"}
        if {path.name for path in staging.iterdir()} != expected_files:
            raise RuntimeError("research tournament output file universe drifted")
        for name, digest in hashes.items():
            if _sha256((staging / name).read_bytes()) != digest:
                raise RuntimeError(f"staged output hash drifted: {name}")
        if final_root.exists():
            raise FileExistsError("research tournament destination appeared before publish")
        os.replace(staging, final_root)
        published = True
        return {
            **manifest,
            "output": final_root.relative_to(PROJECT_ROOT).as_posix(),
            "manifest_raw_sha256": hashes["MANIFEST.json"],
            "checksums_raw_sha256": checksums_sha256,
        }
    finally:
        if not published and staging.exists():
            # Preserve failure evidence. The random staging identity prevents accidental retry.
            failure = {
                "status": "PRESERVED_FAILED_RESEARCH_TOURNAMENT_STAGING",
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
            }
            try:
                _write_new(staging / "FAILURE_STATUS.json", _pretty_json_bytes(failure))
            except FileExistsError:
                pass


def main() -> int:
    result = run()
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
