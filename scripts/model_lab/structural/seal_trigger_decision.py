"""Seal the authorized Structural-Wave trigger decision; run no model."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SRC = REPOSITORY_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    STRUCTURAL_DESIGN_SHA256,
    seal_payload,
    sha256_file,
    verify_structural_design,
)
from pe_regime_v04.model_lab.structural.triggers import (  # noqa: E402
    FINAL_AUDIT_MANIFEST_FILE_SHA256,
    FINAL_AUDIT_MANIFEST_LOGICAL_SHA256,
    FINAL_AUDIT_REPORT_FILE_SHA256,
    FINAL_TERMINAL_FILE_SHA256,
    FINAL_TERMINAL_LOGICAL_SHA256,
    FINAL_TRIGGER_INPUT_FILE_SHA256,
    FINAL_TRIGGER_INPUT_LOGICAL_SHA256,
    load_authorized_final_wave1_evidence,
    resolve_structural_triggers,
)


def _record(path: Path, *, logical_sha256: str | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "relative_path": path.resolve(strict=True).relative_to(REPOSITORY_ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if logical_sha256 is not None:
        record["logical_sha256"] = logical_sha256
    return record


def _write_immutable(path: Path, payload: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable trigger decision already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    data = (
        json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_decision() -> dict[str, object]:
    design = REPOSITORY_ROOT / "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json"
    terminal = REPOSITORY_ROOT / "outputs/model_zoo_wave1_screen_20260819/TERMINAL_MANIFEST.json"
    audit_dir = REPOSITORY_ROOT / "outputs/model_zoo_wave1_terminal_audit_20260819"
    audit_manifest = audit_dir / "AUDIT_MANIFEST.json"
    audit_report = audit_dir / "REPORT.json"
    trigger_inputs = audit_dir / "STRUCTURAL_TRIGGER_INPUTS.json"
    verify_structural_design(design)
    evidence = load_authorized_final_wave1_evidence(
        terminal_path=terminal,
        audit_manifest_path=audit_manifest,
        audit_report_path=audit_report,
        trigger_inputs_path=trigger_inputs,
    )
    resolution = resolve_structural_triggers(evidence)
    expected_triggers = {
        "T_A_TRACK_GAP": True,
        "T_DIRECT_PLATEAU_OR_TAIL": True,
        "T_COMPLEMENTARITY": True,
        "T_STABLE_BIAS": False,
        "T_SERIAL_RESIDUAL": True,
    }
    expected_enabled = [
        "decomp_block_ridge_ar1_lag1",
        "decomp_block_ridge_ar1_current",
        "residual_ar1_nested_oof",
        "stack_geometric_equal_pair",
        "stack_simplex_pair_frozen",
    ]
    if dict(resolution.triggers) != expected_triggers:
        raise RuntimeError("final trigger resolution differs from authorized tuple")
    if list(resolution.enabled_candidates) != expected_enabled:
        raise RuntimeError("final enabled candidate set differs from authorization")
    if resolution.disabled_candidates != ("residual_huber_nested_oof",):
        raise RuntimeError("final disabled candidate set differs from authorization")
    if resolution.selected_pair != ("xgboost_cpu_common", "spline_ridge_common"):
        raise RuntimeError("final selected complementary pair differs from authorization")
    if resolution.selected_residual_base_model_id != "v04_expected_pe":
        raise RuntimeError("final residual base differs from authorization")
    payload: dict[str, object] = {
        "format_version": 1,
        "mode": "model_zoo_structural_wave_trigger_decision",
        "state": "SEALED_SCORE_FREE_BEFORE_STRUCTURAL_EXECUTION",
        "decision_time_source": "independent_audit_report.audited_at",
        "decision_time": "2026-08-19T07:24:53+09:00",
        "structural_design": _record(design),
        "wave1_terminal": _record(terminal, logical_sha256=FINAL_TERMINAL_LOGICAL_SHA256),
        "independent_audit_manifest": _record(
            audit_manifest, logical_sha256=FINAL_AUDIT_MANIFEST_LOGICAL_SHA256
        ),
        "independent_audit_report": _record(audit_report),
        "structural_trigger_inputs": _record(
            trigger_inputs, logical_sha256=FINAL_TRIGGER_INPUT_LOGICAL_SHA256
        ),
        "required_authority_hashes": {
            "structural_design_sha256": STRUCTURAL_DESIGN_SHA256,
            "wave1_terminal_file_sha256": FINAL_TERMINAL_FILE_SHA256,
            "wave1_terminal_logical_sha256": FINAL_TERMINAL_LOGICAL_SHA256,
            "audit_manifest_file_sha256": FINAL_AUDIT_MANIFEST_FILE_SHA256,
            "audit_manifest_logical_sha256": FINAL_AUDIT_MANIFEST_LOGICAL_SHA256,
            "audit_report_file_sha256": FINAL_AUDIT_REPORT_FILE_SHA256,
            "trigger_inputs_file_sha256": FINAL_TRIGGER_INPUT_FILE_SHA256,
            "trigger_inputs_logical_sha256": FINAL_TRIGGER_INPUT_LOGICAL_SHA256,
        },
        "wave1_terminal_decision": "PASS_TERMINAL_REJECT_ALL",
        "triggers": expected_triggers,
        "selected_residual_base_model_id": resolution.selected_residual_base_model_id,
        "selected_complementary_pair": {
            "primary_model_id": resolution.selected_pair[0],
            "secondary_model_id": resolution.selected_pair[1],
            "selection_role": "READ_ONLY_SPENT_SURFACE_TRIGGER_ONLY",
        },
        "enabled_candidates": expected_enabled,
        "disabled_candidates": ["residual_huber_nested_oof"],
        "enabled_candidate_count": 5,
        "global_candidate_ceiling": 6,
        "hierarchical_status": "DATA_INSUFFICIENT",
        "attestations": {
            "candidate_predictions_generated": False,
            "candidate_scores_computed": False,
            "candidate_models_run": False,
            "fresh_seed_selected_or_reserved": False,
            "heldout_opened": False,
            "registry_modified": False,
            "phase1_wave1_or_dgp_source_modified": False,
            "oracle_pair_used_as_model_feature_or_weight_target": False,
        },
    }
    return seal_payload(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT
        / "outputs/model_zoo_structural_wave_screen_20260819/TRIGGER_DECISION.json",
    )
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    payload = build_decision()
    if args.verify_only:
        print(payload["manifest_sha256"])
        return 0
    _write_immutable(args.output, payload)
    print(args.output.resolve())
    print(payload["manifest_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
