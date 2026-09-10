"""Atomically seal the independently approved Structural V4 spent activation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.folds import generate_pit_folds  # noqa: E402
from pe_regime_v04.model_lab.structural.authorization import (  # noqa: E402
    EXPECTED_ENABLED,
    _load_authority_policy,
    _verify_snapshot,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    STRUCTURAL_DESIGN_SHA256,
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.structural.nested import (  # noqa: E402
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_FOLD_COUNT,
    FORMAL_OUTER_FOLD_SPEC,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
    FORMAL_OUTER_STARTS,
)


SCREEN = ROOT / "outputs/model_zoo_structural_wave_screen_20260819"
AUDIT_DIR = ROOT / "outputs/model_zoo_structural_wave_fourth_independent_audit_20260819"
SPENT = ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819"
OUTPUT = SPENT / "ACTIVATION_BINDING.json"
OLD_POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py"
OLD_POLICY_RAW = "ca874545c461d60cdfd71569472c743943e0f74db5080aeb8e1443e6d41aef2e"
OLD_POLICY_LOGICAL = "f4a97d7d701867e3e84f20f2a6e4735be9f7014c404dd28f9f35617b295b147d"
AUDIT_RAW = "d59656aeea97a568f52fb17c95d114a4a28a0ac15d23208fe98aa9e90dfba5c9"
AUDIT_LOGICAL = "efe869aa58ac89b7c5c5a82f86ff8533f2d66f551ef1f9620abb05664ad9102f"
REQUEST_RAW = "93d0985e2f6ff479577ebfc235caee886a7b3deafee9b57e95de48d73918ff6b"
REQUEST_LOGICAL = "274ba5316bc300385fd70fa38805ef7378cc981eb7803ad107c377a06b86614e"
MANIFEST_RAW = "9be2956cf283ae51fd117181fa7d13d604e09c1863823a671482d411b1ddb4e5"
MANIFEST_LOGICAL = "dc7e08c8dc9402a2a46dd4db2e4ef8ad7176d28353a014c9b812c6359cb031bd"
SNAPSHOT_RAW = "b1996943814339ca3b9b9aa4b1d92c13bfe569783e9a174b9440bff54705dec2"
SNAPSHOT_LOGICAL = "f42c7569fd362fddc843d0b81dc34323a819db99f591662a405f651818befd0c"
BASE_RAW = "b60ca510b4cad411c29dded212df934e327b948c24f0a932060e1bdff26a81a4"
BASE_LOGICAL = "23f10ffdbbf4f81157997baf54a770d47d764eb7196bed4bee6b945b2293bf47"
PREDICT_INPUTS_RAW = "f8f30ab74d812909b644984ba9ee3c4a8f509dfabb2ab566c7048313245d500c"
PREDICT_INPUTS_LOGICAL = "b08dd0a63c9b02ef14f06b3fd48764ac44c954100be5f360d03df7390aa494e8"
SEEDS = (6301, 6421, 6521, 6607, 6701)


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, raw: str, logical: str) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if sha256_file(resolved) != raw:
        raise RuntimeError(f"raw binding mismatch: {resolved}")
    value = _read(resolved)
    if value["manifest_sha256"] != logical:
        raise RuntimeError(f"logical binding mismatch: {resolved}")
    return {
        "path": resolved.relative_to(ROOT).as_posix(),
        "bytes": resolved.stat().st_size,
        "raw_sha256": raw,
        "logical_sha256": logical,
    }


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable activation already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    encoded = canonical_json_bytes(payload) + b"\n"
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    audit = _read(AUDIT_DIR / "AUDIT.json")
    if (
        sha256_file(AUDIT_DIR / "AUDIT.json") != AUDIT_RAW
        or audit["manifest_sha256"] != AUDIT_LOGICAL
    ):
        raise RuntimeError("independent GO audit binding mismatch")
    decision = audit.get("decision")
    if not isinstance(decision, Mapping) or (
        decision.get("spent_seed_screen"),
        decision.get("open_p0"),
        decision.get("open_p1"),
        decision.get("structural_prediction_or_scoring_authorized"),
    ) != ("GO", 0, 0, True):
        raise RuntimeError("independent audit is not an exact zero-P0/P1 spent GO")
    evidence = audit.get("evidence_bindings")
    expected_evidence = {
        "reaudit_request_v4_sha256": REQUEST_RAW,
        "reaudit_request_v4_logical_sha256": REQUEST_LOGICAL,
        "external_authority_policy_sha256": OLD_POLICY_RAW,
        "external_authority_policy_logical_sha256": OLD_POLICY_LOGICAL,
        "implementation_manifest_v4_sha256": MANIFEST_RAW,
        "implementation_manifest_v4_logical_sha256": MANIFEST_LOGICAL,
        "base_binding_lock_v4_sha256": BASE_RAW,
        "base_binding_lock_v4_logical_sha256": BASE_LOGICAL,
        "execution_snapshot_v4_sha256": SNAPSHOT_RAW,
        "execution_snapshot_v4_logical_sha256": SNAPSHOT_LOGICAL,
        "checksums_v4_sha256": "e14fe827036687e66ce30d7cd9dbf521044498d9b7ef50f1921fd110fbccd4cf",
    }
    if evidence != expected_evidence:
        raise RuntimeError("independent audit evidence bindings changed")

    checksums = SCREEN / "CHECKSUMS_V4.sha256"
    for line in checksums.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        if sha256_file(ROOT / relative) != expected:
            raise RuntimeError(f"V4 checksum drift: {relative}")
    policy = _load_authority_policy(OLD_POLICY, expected_raw_sha256=OLD_POLICY_RAW)
    if policy.get("manifest_sha256") != OLD_POLICY_LOGICAL:
        raise RuntimeError("audited pre-activation policy logical seal changed")
    snapshot_path = SCREEN / "EXECUTION_SNAPSHOT_V4.json"
    snapshot = _read(snapshot_path)
    _verify_snapshot(snapshot, ROOT)

    predict_inputs_path = ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
    predict_inputs = _read(predict_inputs_path)
    if (
        sha256_file(predict_inputs_path) != PREDICT_INPUTS_RAW
        or predict_inputs["manifest_sha256"] != PREDICT_INPUTS_LOGICAL
    ):
        raise RuntimeError("spent predict input binding changed")
    if tuple(int(row["seed"]) for row in predict_inputs["seeds"]) != SEEDS:
        raise RuntimeError("spent seed universe changed")

    identity = pd.DataFrame({"date": pd.date_range("2000-01-03", periods=1800, freq="B")})
    folds = generate_pit_folds(identity, FORMAL_OUTER_FOLD_SPEC, date_column="date")
    rows = [
        {
            "fold_id": fold.fold_id,
            "train_positions": list(fold.train_positions),
            "test_positions": list(fold.test_positions),
        }
        for fold in folds
    ]
    coverage = [position for fold in folds for position in fold.test_positions]
    if (
        len(folds) != FORMAL_OUTER_FOLD_COUNT
        or tuple(fold.test_positions[0] for fold in folds) != FORMAL_OUTER_STARTS
        or len(folds[-1].test_positions) != 15
        or sha256_bytes(canonical_json_bytes(rows)) != FORMAL_OUTER_POSITION_SCHEDULE_SHA256
        or sha256_bytes(canonical_json_bytes(coverage)) != FORMAL_OUTER_COVERAGE_SHA256
    ):
        raise RuntimeError("formal 74-fold schedule binding changed")

    benchmark = _read(SCREEN / "NO_SCORE_BACKEND_BENCHMARK.json")
    if (
        benchmark.get("selected_worker_count") != 8
        or benchmark.get("parity", {}).get("all_8_16_24_32_repeats_exact") is not True
    ):
        raise RuntimeError("selected ProcessPool8 policy changed")

    bindings = {
        "independent_go_audit": _record(
            AUDIT_DIR / "AUDIT.json", raw=AUDIT_RAW, logical=AUDIT_LOGICAL
        ),
        "v4_reaudit_request": _record(
            SCREEN / "INDEPENDENT_REAUDIT_REQUEST_V4.json", raw=REQUEST_RAW, logical=REQUEST_LOGICAL
        ),
        "audited_pre_activation_policy": {
            "path": OLD_POLICY.relative_to(ROOT).as_posix(),
            "bytes": OLD_POLICY.stat().st_size,
            "raw_sha256": OLD_POLICY_RAW,
            "logical_sha256": OLD_POLICY_LOGICAL,
        },
        "v4_implementation_manifest": _record(
            SCREEN / "IMPLEMENTATION_MANIFEST_V4.json", raw=MANIFEST_RAW, logical=MANIFEST_LOGICAL
        ),
        "v4_base_binding_lock": _record(
            SCREEN / "BASE_BINDING_LOCK_V4.json", raw=BASE_RAW, logical=BASE_LOGICAL
        ),
        "v4_execution_snapshot": _record(snapshot_path, raw=SNAPSHOT_RAW, logical=SNAPSHOT_LOGICAL),
        "predict_inputs": _record(
            predict_inputs_path, raw=PREDICT_INPUTS_RAW, logical=PREDICT_INPUTS_LOGICAL
        ),
    }
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v4_atomic_spent_activation_binding",
            "state": "ACTIVE_EXACT_SPENT_SCREEN_ONLY",
            "design_sha256": STRUCTURAL_DESIGN_SHA256,
            "exact_bindings": bindings,
            "source_closure": {
                "inventory_count": len(snapshot["source_inventory"]),
                "source_inventory_sha256": snapshot["source_inventory_sha256"],
                "all_current_raw_bytes_reverified": True,
            },
            "fold_contract": {
                "fold_count": FORMAL_OUTER_FOLD_COUNT,
                "starts": list(FORMAL_OUTER_STARTS),
                "terminal_test_rows": 15,
                "full_membership_schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
                "coverage_sha256": FORMAL_OUTER_COVERAGE_SHA256,
                "coverage": "range(252,1800)",
                "required_evaluation_fold_ids": [f"fold_{index:03d}" for index in range(12, 74)],
                "required_evaluation_positions": "range(504,1800)",
                "required_rows_per_seed": 1296,
            },
            "execution_contract": {
                "candidate_ids": list(EXPECTED_ENABLED),
                "seeds": list(SEEDS),
                "seed_role": "ALREADY_SPENT_WAVE1_ONLY",
                "outer_backend": "ProcessPoolExecutor",
                "start_method": "spawn",
                "outer_workers": 8,
                "inner_threads": 1,
                "gpu": "OFF",
                "max_total_rss_bytes": 64 * 1024**3,
                "minimum_free_ram_bytes": 16 * 1024**3,
            },
            "decision": dict(decision),
            "attestations": {
                "fresh_or_heldout_seed_selected_or_reserved": False,
                "candidate_parameters_changed": False,
                "prediction_started_before_this_activation": False,
                "evaluation_truth_opened_before_terminal_prediction_custody": False,
            },
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
