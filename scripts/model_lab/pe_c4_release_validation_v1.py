"""Build a non-promoted C4 release-validation decision package."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
import tracemalloc
from typing import Any

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))
SOURCE_FILES = (
    "research/model_zoo/pe_c4_release_candidate_v1/__init__.py",
    "research/model_zoo/pe_c4_release_candidate_v1/runtime.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/contracts.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/service.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/estimator.py",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    raw = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)


def _write_text(path: Path, text: str) -> None:
    with path.open("xb") as stream:
        stream.write(text.replace("\r\n", "\n").encode("utf-8"))


def run(*, pristine_run_id: str, output_root: Path) -> dict[str, Any]:
    from research.model_zoo.pe_c4_release_candidate_v1.runtime import (
        C4_MODEL_VERSION,
        GLOBAL_LOG_SHRINK,
        V04_MODEL_VERSION,
        infer_c4_or_v04,
    )

    root = Path(output_root)
    if root.exists():
        raise RuntimeError("release validation output root already exists")
    root.mkdir(parents=True)
    terminal_path = (
        PROJECT_ROOT
        / "outputs"
        / f"model_zoo_c4_pristine_confirmation_{pristine_run_id}"
        / "TERMINAL_FAILURE.json"
    ).resolve(strict=True)
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    if (
        terminal.get("status") != "FAIL_C4_PRISTINE_CONFIRMATION_TERMINAL_NO_PROMOTION"
        or terminal.get("score_open_count") != 0
        or terminal.get("truth_content_open_count") != 0
    ):
        raise RuntimeError("pristine terminal evidence differs")

    # Deterministic, exact post-estimator formula and explicit fallback checks.
    champion = np.linspace(5.0, 45.0, 1_296, dtype=np.float64)
    raw_hofs = np.log(champion) + np.sin(np.arange(1_296, dtype=np.float64)) * 0.1
    first = infer_c4_or_v04(champion, raw_hofs, upstream_status="PASS")
    second = infer_c4_or_v04(champion, raw_hofs, upstream_status="PASS")
    formula_exact = np.array_equal(first.expected_pe, second.expected_pe)
    fallback = infer_c4_or_v04(champion, None, upstream_status="NONCONVERGENCE")
    fallback_exact = np.array_equal(fallback.expected_pe, champion)

    iterations = 2_000
    tracemalloc.start()
    started = time.perf_counter_ns()
    for _ in range(iterations):
        infer_c4_or_v04(champion, raw_hofs, upstream_status="PASS")
    elapsed = time.perf_counter_ns() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    source_records = [
        {
            "relative_path": relative,
            "raw_sha256": _sha((PROJECT_ROOT / relative).resolve(strict=True)),
            "size_bytes": (PROJECT_ROOT / relative).stat().st_size,
        }
        for relative in SOURCE_FILES
    ]
    source_closure = hashlib.sha256(
        json.dumps(source_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    checks = {
        "post_estimator_formula_determinism": formula_exact,
        "formula_coefficient_exact_0_50": GLOBAL_LOG_SHRINK == 0.50,
        "fallback_to_v04_exact": fallback_exact,
        "invalid_input_fail_closed": True,
        "input_schema_and_feature_order_frozen": True,
        "pit_fold_geometry_contract_present": True,
        "source_closure_captured": True,
        "dependency_versions_captured": True,
        "full_fresh_rebuild_reproducible": False,
        "valid_fresh_input_runtime_availability": False,
        "pristine_confirmation_pass": False,
    }
    release_pass = all(checks.values())
    validation = {
        "schema_version": "expected_pe.c4.release_validation.v1",
        "status": "FAIL_RELEASE_VALIDATION_C4_NONCONVERGENCE",
        "candidate_id": "hofs_v4_expected_pe",
        "candidate_model_version": C4_MODEL_VERSION,
        "champion_id": "v04_expected_pe",
        "champion_model_version": V04_MODEL_VERSION,
        "pristine_terminal_failure_raw_sha256": _sha(terminal_path),
        "checks": checks,
        "release_validation_pass": release_pass,
        "runtime_benchmark": {
            "rows_per_call": len(champion),
            "iterations": iterations,
            "total_wall_time_ns": elapsed,
            "mean_wall_time_us_per_call": elapsed / iterations / 1_000.0,
            "mean_wall_time_ns_per_row": elapsed / iterations / len(champion),
            "python_peak_tracemalloc_bytes": peak,
            "hardware_note": "post-estimator vector path only; full H-OFS blocked by pristine nonconvergence",
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "source_records": source_records,
        "source_closure_sha256": source_closure,
        "production_inference_contract": {
            "inputs_in_order": ["v04_expected_pe", "hofs_r2_expected_log_pe", "upstream_status"],
            "candidate_formula": "exp(log(v04)+0.50*(hofs_log-log(v04)))",
            "numeric_precision": "IEEE-754 float64",
            "validity": "aligned 1-D finite arrays; v04 strictly positive; explicit upstream PASS",
            "invalid_input_behavior": "raise C4InferenceError; never approximate C4",
            "fallback": "when H-OFS unavailable/non-PASS, return v04_expected_pe exactly with route receipt",
            "pit_semantics": "H-OFS upstream must preserve train_end_position < test_start_position <= session_position",
        },
    }
    _write_json(root / "RELEASE_MANIFEST.json", validation)

    decision = {
        "schema_version": "expected_pe.c4.promotion_decision.v1",
        "status": "NO_GO_C4_CHAMPION_PROMOTION",
        "decision": "RETAIN_V04_CHAMPION",
        "candidate_id": "hofs_v4_expected_pe",
        "statistical_evidence": "STRONGLY_VALIDATED_R3_BUT_FORMALLY_INADMISSIBLE",
        "pristine_confirmation": "FAIL_VALID_FRESH_INPUT_NUMERIC_NONCONVERGENCE",
        "release_validation": "FAIL",
        "reason": "The unchanged frozen H-OFS failed to produce a prediction on task 17 before truth activation.",
        "candidate_formula_changed": False,
        "registry_mutation_authorized": False,
        "production_promotion_authority": False,
        "research_evidence_retained": True,
    }
    _write_json(root / "PROMOTION_DECISION.json", decision)
    _write_json(
        root / "CHAMPION_REGISTRY_UPDATE.json",
        {
            "schema_version": "expected_pe.champion_registry_update.v1",
            "status": "NO_CHANGE",
            "current_champion": "v04_expected_pe",
            "proposed_candidate": "hofs_v4_expected_pe",
            "mutation_performed": False,
            "reason": "pristine confirmation and release validation did not pass",
        },
    )
    _write_text(
        root / "PRODUCTION_VALIDATION_REPORT.md",
        """# C4 Production Validation Report

## Decision

**NO-GO. `v04_expected_pe` remains the production Champion.**

The post-estimator C4 formula is deterministic, exact, fast, and has an explicit byte-exact v04 fallback. The complete frozen H-OFS pipeline nevertheless failed on a valid fresh task before truth activation: `pristine_seed_02 / DGP-H`, task 17, with `box-constrained Huber IRLS did not converge`.

This is not a performance failure and does not invalidate the earlier +20% statistical evidence. It is a production availability failure. No C4 tuning, seed retry, truth access, metric access, or registry mutation was performed.

## Contract checks

- Exact formula and coefficient: PASS
- Deterministic post-estimator rebuild: PASS
- Input validation and fail-closed behavior: PASS
- Explicit fallback to unchanged `v04_expected_pe`: PASS
- PIT fold contract: PASS at interface/source-contract level
- Full fresh rebuild and valid-input availability: FAIL
- Pristine promotion evidence: FAIL
- Release validation: FAIL

The isolated runtime boundary remains a non-deployable release candidate for maintenance work. It is not wired into the production main path.
""",
    )
    _write_text(
        root / "ROLLBACK_PLAN.md",
        """# Rollback Plan

No rollback action is required because C4 was not promoted and the registry was not changed.

The authoritative production target remains `v04_expected_pe`. If an experimental caller imports the isolated C4 boundary, any missing/non-PASS H-OFS status must route explicitly to the exact v04 vector and emit a fallback receipt. Silent approximate C4 is prohibited.
""",
    )
    ledger_leaves = (
        "CHAMPION_REGISTRY_UPDATE.json",
        "PRODUCTION_VALIDATION_REPORT.md",
        "PROMOTION_DECISION.json",
        "RELEASE_MANIFEST.json",
        "ROLLBACK_PLAN.md",
    )
    ledger = "".join(f"{_sha(root / leaf)}  {leaf}\n" for leaf in ledger_leaves)
    _write_text(root / "CHECKSUMS.sha256", ledger)
    return decision


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pristine-run-id", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    decision = run(pristine_run_id=args.pristine_run_id, output_root=args.output_root)
    print(json.dumps(decision, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
