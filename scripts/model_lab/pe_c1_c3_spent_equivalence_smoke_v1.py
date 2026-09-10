"""One-task spent-only numeric equivalence smoke for the PE-C1--C3 service."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

SPENT_ROOT = (
    PROJECT_ROOT
    / "outputs"
    / "model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
)
SPENT_TASK = SPENT_ROOT / "replays" / "pass_1" / "seed_2026082001" / "dgp_A"
SPENT_PREDICTIONS = (
    PROJECT_ROOT
    / "outputs"
    / "model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_20260821"
    / "PREDICTIONS.csv"
)
PINNED_FILES = {
    SPENT_ROOT / "CHECKSUMS.sha256": (
        148_903,
        "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7",
    ),
    SPENT_TASK / "canonical150.csv": (
        3_655_561,
        "aa6bb2f3e63b4423c79a578c3ed2fb8353050dd5ed7dc2d117931abfde1bb384",
    ),
    SPENT_TASK / "v04_overlay.csv": (
        5_835_358,
        "a8d195a023ad11b5fc91014fe843ae5ca6201340dd7004bebac1d5b524df81a0",
    ),
    SPENT_PREDICTIONS: (
        17_216_008,
        "f2d38f9de31aa89d502050babb5df185fd35a30851701eb3a90e8c50fe64064b",
    ),
}
PUBLISH_FLAG = "--publish-fixed-spent-equivalence-evidence"
OUTPUT_ROOT = (
    PROJECT_ROOT
    / "outputs"
    / "model_zoo_pe_c1_c3_fresh_qualification_service_v1_spent_equivalence_r3_20260822"
)
SOURCE_RELATIVES = (
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/__init__.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/contracts.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/core.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/resource.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/runtime.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/DESIGN.md",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/__init__.py",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/contracts.py",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/prediction.py",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/DESIGN.md",
    "scripts/model_lab/pe_c1_c3_spent_equivalence_smoke_v1.py",
    "tests/model_lab/test_pe_c1_c3_fresh_qualification_service_v1.py",
    "tests/model_lab/test_pe_c1_c4_fresh_qualification_prediction_v2.py",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _f64_sha256(values: object) -> str:
    import numpy as np

    return hashlib.sha256(np.asarray(values, dtype="<f8").tobytes()).hexdigest()


def _pretty_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _publish_evidence(payload: dict[str, object]) -> None:
    staging = OUTPUT_ROOT.with_name(f".{OUTPUT_ROOT.name}.staging")
    if OUTPUT_ROOT.exists() or staging.exists():
        raise RuntimeError("fixed spent-equivalence evidence destination already exists")
    staging.mkdir(parents=False, exist_ok=False)
    sources = []
    for relative in SOURCE_RELATIVES:
        path = PROJECT_ROOT / relative
        sources.append(
            {
                "relative_path": relative,
                "size_bytes": path.stat().st_size,
                "raw_sha256": _sha256(path),
            }
        )
    source_manifest = {
        "schema_version": "expected_pe.pe_c1_c3.spent_equivalence_sources.v1",
        "evidence_class": "SPENT_RESEARCH_ONLY_NOT_FRESH_CERTIFICATION",
        "sources": sources,
        "truth_source_count": 0,
        "fresh_source_count": 0,
        "heldout_source_count": 0,
    }
    report = (
        b"# PE-C1--C3 Spent Numeric Equivalence\n\n"
        b"Status: `PASS / SPENT_RESEARCH_ONLY / NOT_FRESH_CERTIFICATION`.\n\n"
        b"One pinned public research task (seed 2026082001, DGP A) was refit through "
        b"the isolated V1 service on two affined logical CPUs with inner-thread count "
        b"one and GPU disabled. The v04, LightGBM, HistGB, PE-C1, PE-C2, and PE-C3 "
        b"float64 vectors were bitwise identical to the frozen predecessor output. "
        b"The production raw-byte parser consumed the pinned CRLF public files and "
        b"validated the BOM-preserving header-content hashes before fitting. "
        b"The service and predecessor use different explicit spent-cohort alias labels; "
        b"all remaining row identities match and both bind estimator seed 2026082001. "
        b"For formula-only comparison, copies of both task surfaces were projected to "
        b"qualification_seed_01 so the strict production formula contract stayed unchanged; "
        b"the explicit research builder marked all projected rows prediction/PIT-invalid and "
        b"that projection was not treated as full-identity evidence. "
        b"No truth, fresh qualification, heldout, score, selection, or promotion input "
        b"was read.\n"
    )
    artifacts = {
        "RESULT.json": _pretty_json_bytes(payload),
        "SOURCE_MANIFEST.json": _pretty_json_bytes(source_manifest),
        "REPORT.md": report,
    }
    for filename, raw in artifacts.items():
        _write_new(staging / filename, raw)
    checksum_lines = [
        f"{_sha256(staging / filename)}  {filename}\n" for filename in sorted(artifacts)
    ]
    _write_new(staging / "CHECKSUMS.sha256", "".join(checksum_lines).encode("ascii"))
    os.replace(staging, OUTPUT_ROOT)


def main() -> int:
    if sys.argv[1:] not in ([], [PUBLISH_FLAG]):
        raise RuntimeError("caller-controlled smoke arguments are forbidden")
    for path, (expected_size, expected_sha256) in PINNED_FILES.items():
        if path.stat().st_size != expected_size or _sha256(path) != expected_sha256:
            raise RuntimeError(f"spent-only pinned input drifted: {path.name}")

    # Resource policy is sealed before importing any numerical/model stack.
    from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.resource import (
        apply_exact_spawn_environment,
        seal_worker_runtime,
    )

    apply_exact_spawn_environment()
    runtime = seal_worker_runtime(0)

    import numpy as np
    import pandas as pd

    from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.contracts import (
        SPENT_EQUIVALENCE_ALIAS,
        SPENT_EQUIVALENCE_ESTIMATOR_SEED,
        TaskIdentity,
    )
    from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.core import (
        compute_task_surface_from_bytes,
    )
    from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
        C1_ID,
        C2_ID,
        C3_ID,
        HOFS_TASK_SURFACE_COLUMNS,
    )
    from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.prediction import (
        build_research_task_formula_rows,
        merge_bound_task_surfaces,
    )

    canonical_raw = (SPENT_TASK / "canonical150.csv").read_bytes()
    overlay_raw = (SPENT_TASK / "v04_overlay.csv").read_bytes()
    started = time.perf_counter()
    computed = compute_task_surface_from_bytes(
        canonical_raw,
        overlay_raw,
        identity=TaskIdentity(
            seed_alias=SPENT_EQUIVALENCE_ALIAS,
            dgp_id="A",
            estimator_seed=SPENT_EQUIVALENCE_ESTIMATOR_SEED,
        ),
    )
    elapsed = time.perf_counter() - started
    service = computed.surface
    # The frozen output is float17g; round-trip parsing recovers its in-memory f64 values.
    legacy = pd.read_csv(
        SPENT_PREDICTIONS,
        low_memory=False,
        float_precision="round_trip",
    )
    legacy = legacy.loc[
        legacy["seed_alias"].eq("research_seed_01") & legacy["dgp_id"].eq("A")
    ].reset_index(drop=True)
    if len(legacy) != len(service):
        raise RuntimeError("spent legacy task geometry differs")

    identity_columns = (
        "dgp_id",
        "date",
        "symbol",
        "session_position",
        "fold_id",
        "train_end_position",
        "test_start_position",
    )
    identity_equal_excluding_seed_alias = all(
        np.array_equal(service[column].to_numpy(), legacy[column].to_numpy())
        for column in identity_columns
    )
    constituent_pairs = {
        "v04": ("v04_expected_pe", "incumbent__v04_expected_pe"),
        "lgbm": ("lgbm_full_state_expected_pe", "challenger__lgbm_full_state"),
        "histgb": ("histgb_full_state_expected_pe", "challenger__histgb_full_state"),
    }
    comparisons = {}
    for label, (new_column, legacy_column) in constituent_pairs.items():
        left = service[new_column].to_numpy(dtype=np.float64)
        right = legacy[legacy_column].to_numpy(dtype=np.float64)
        comparisons[label] = {
            "bitwise_equal": bool(np.array_equal(left, right)),
            "max_abs_difference": float(np.max(np.abs(left - right))),
            "new_f64_sha256": _f64_sha256(left),
            "legacy_f64_sha256": _f64_sha256(right),
        }

    hofs = service.loc[:, list(HOFS_TASK_SURFACE_COLUMNS[:8])].copy()
    hofs["hofs_r2_expected_log_pe"] = np.log(
        service["v04_expected_pe"].to_numpy(dtype=np.float64)
    )
    hofs["hofs_v7_tail_guard_weight"] = 0.5
    hofs["hofs_v7_log_scale"] = 0.0
    hofs = hofs.loc[:, list(HOFS_TASK_SURFACE_COLUMNS)]
    # Keep the explicit spent identity above as the identity evidence.  The clean
    # production formula deliberately accepts only qualification aliases, so use
    # detached copies with one valid alias solely to compare numeric vectors.  Do
    # not weaken the production validator or claim this projection is identity
    # equivalence.
    formula_alias = "qualification_seed_01"
    service_formula = service.copy()
    hofs_formula = hofs.copy()
    service_formula.loc[:, "seed_alias"] = formula_alias
    hofs_formula.loc[:, "seed_alias"] = formula_alias
    clean_rows = build_research_task_formula_rows(
        merge_bound_task_surfaces(service_formula, hofs_formula)
    )
    if (
        not clean_rows["prediction_valid"].eq(False).all()
        or not clean_rows["pit_valid"].eq(False).all()
    ):
        raise RuntimeError("formula-only research projection claimed prediction readiness")
    candidate_pairs = {
        C1_ID: "candidate__bce_b",
        C2_ID: "candidate__bce_d",
        C3_ID: "candidate__fixed_alpha_040",
    }
    for model_id, legacy_column in candidate_pairs.items():
        left = clean_rows.loc[
            clean_rows["pe_model_id"].eq(model_id), "expected_pe"
        ].to_numpy(dtype=np.float64)
        right = legacy[legacy_column].to_numpy(dtype=np.float64)
        comparisons[model_id] = {
            "bitwise_equal": bool(np.array_equal(left, right)),
            "max_abs_difference": float(np.max(np.abs(left - right))),
            "new_f64_sha256": _f64_sha256(left),
            "legacy_f64_sha256": _f64_sha256(right),
        }

    verdict = identity_equal_excluding_seed_alias and all(
        row["bitwise_equal"] for row in comparisons.values()
    )
    payload = {
        "schema_version": "expected_pe.pe_c1_c3.spent_equivalence_smoke.v2",
        "status": "PASS" if verdict else "FAIL",
        "evidence_class": "SPENT_RESEARCH_ONLY_NOT_FRESH_CERTIFICATION",
        "supersedes_evidence_root": (
            "outputs/model_zoo_pe_c1_c3_fresh_qualification_service_v1_"
            "spent_equivalence_r2_20260822"
        ),
        "full_identity_equal": False,
        "identity_equal_excluding_seed_alias": identity_equal_excluding_seed_alias,
        "identity_alias_receipt": {
            "service_seed_alias": SPENT_EQUIVALENCE_ALIAS,
            "legacy_seed_alias": "research_seed_01",
            "estimator_seed": SPENT_EQUIVALENCE_ESTIMATOR_SEED,
            "alias_difference_reason": "EXPLICIT_SPENT_EQUIVALENCE_COHORT_LABEL",
        },
        "formula_only_alias_projection": {
            "applied": True,
            "projected_alias": formula_alias,
            "scope": "DETACHED_COPIES_FOR_NUMERIC_FORMULA_COMPARISON_ONLY",
            "identity_evidence_eligible": False,
            "production_contract_modified": False,
            "projected_rows_prediction_valid": False,
            "projected_rows_pit_valid": False,
        },
        "comparisons": comparisons,
        "raw_input_parser": {
            "production_raw_byte_entry_exercised": True,
            "canonical_raw_sha256": hashlib.sha256(canonical_raw).hexdigest(),
            "overlay_raw_sha256": hashlib.sha256(overlay_raw).hexdigest(),
            "canonical_header_terminator": (
                "CRLF"
                if canonical_raw[canonical_raw.index(b"\n") - 1] == 13
                else "LF"
            ),
            "overlay_header_terminator": (
                "CRLF" if overlay_raw[overlay_raw.index(b"\n") - 1] == 13 else "LF"
            ),
            "header_hash_excludes_terminator": True,
            "bom_preserved": True,
        },
        "elapsed_seconds": elapsed,
        "resource": {
            "slot": runtime.slot,
            "cpu_ids": list(runtime.cpu_ids),
            "affinity_mask": runtime.affinity_mask,
            "inner_threads": 1,
            "gpu_enabled": False,
        },
        "truth_read": False,
        "score_computed": False,
        "fresh_seed_read": False,
        "heldout_read": False,
    }
    if verdict and sys.argv[1:] == [PUBLISH_FLAG]:
        _publish_evidence(payload)
    sys.stdout.write(json.dumps(payload, sort_keys=True, allow_nan=False) + "\n")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
