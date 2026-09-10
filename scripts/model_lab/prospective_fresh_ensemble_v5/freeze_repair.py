"""Freeze the V5 descriptor repair before any new seed reservation or execution."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.prospective_fresh_ensemble_v5.contracts import (  # noqa: E402
    LANE_ID,
    V5ContractError,
    file_record,
    read_json_object,
    seal_payload,
    sha256_file,
    verify_sealed_payload,
    write_json_exclusive,
)


OUTPUT_NAME = "model_zoo_prospective_fresh_ensemble_v5_repair_freeze_20260820"
OFFICIAL_FUTURE_OUTPUT_NAME = "model_zoo_prospective_fresh_ensemble_v5_20260820"
V4_FAILURE_AUDIT_RELATIVE = (
    "outputs/model_zoo_prospective_fresh_ensemble_v4_"
    "heldout_terminal_failure_audit_20260820"
)
V4_FAILURE_AUDIT_EXPECTED = {
    "AUDIT.json": "755716e85c5de75cf14afd6037534ea18bf6de4c0f9397162cc716dd1bc67a8b",
    "HELDOUT_TERMINAL_FAILURE_AUDIT.md": (
        "ea679f66398f29e36cd7459957be572b9bb750beea7fdafc5e598ab5d9d3175c"
    ),
    "CHECKSUMS.sha256": "e4253fb29dd76a3a627d698345b8cec16da3efd99d77183386ceffd825b04695",
}
V4_FAILURE_AUDIT_SELF_SHA256 = (
    "9f1d28ed99b48963689f369d62bb0e27eefcbadc34fea9d3e8acfbf8a81518c4"
)
V4_FAILURE_VERDICT = "TERMINAL_HELDOUT_PRESPAWN_CONTRACT_FAILURE_NO_RETRY"

V5_SOURCE_RELATIVE = (
    "research/model_zoo/prospective_fresh_ensemble_v5/__init__.py",
    "research/model_zoo/prospective_fresh_ensemble_v5/contracts.py",
    "research/model_zoo/prospective_fresh_ensemble_v5/descriptor.py",
    "research/model_zoo/prospective_fresh_ensemble_v5/pid_handshake.py",
    "scripts/model_lab/prospective_fresh_ensemble_v5/handshake_probe.py",
    "scripts/model_lab/prospective_fresh_ensemble_v5/freeze_repair.py",
    "tests/model_lab/test_prospective_fresh_ensemble_v5_repair.py",
)
V4_DESCRIPTOR_RELATIVE = (
    "outputs/model_zoo_prospective_fresh_ensemble_v4_20260820/"
    "runtime/heldout/HELDOUT_STAGE_DESCRIPTOR.json"
)
V4_DESCRIPTOR_RAW_SHA256 = (
    "d34e20be4174fe00fa943678694819e8846d5107fc454d606e6c6dd82dc0539a"
)
V4_DESCRIPTOR_SELF_SHA256 = (
    "aa0b180b1d752c330c2e81a41649cfd0fb5e39db6236d7709a36db808ff03175"
)
CANDIDATE_ID = "pointwise_level_median3__5c65a5a85e727116ebe8"
CANDIDATE_MEMBERS = (
    "s4_decomposition_ridge_ar1_with_regime_v7",
    "v04_expected_pe",
    "v04_ml_expected_pe_no_regime",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_checked(command: list[str], environment: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise V5ContractError(
            "verification command failed: "
            + " ".join(command)
            + "\n"
            + completed.stdout
            + completed.stderr
        )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _verify_v4_failure_audit() -> dict[str, Any]:
    audit_root = (PROJECT_ROOT / V4_FAILURE_AUDIT_RELATIVE).resolve(strict=True)
    for name, expected_hash in V4_FAILURE_AUDIT_EXPECTED.items():
        path = (audit_root / name).resolve(strict=True)
        if sha256_file(path) != expected_hash:
            raise V5ContractError(f"V4 terminal audit changed: {name}")
    audit = read_json_object(audit_root / "AUDIT.json")
    verify_sealed_payload(audit, "audit_sha256")
    if (
        audit.get("audit_sha256") != V4_FAILURE_AUDIT_SELF_SHA256
        or audit.get("verdict") != V4_FAILURE_VERDICT
        or audit.get("heldout_retry_authorized") is not False
        or audit.get("new_lane_and_fresh_reservation_required") is not True
        or audit.get("heldout_evidence_exists") is not False
        or audit.get("production_promotion_authority") is not False
        or audit.get("failure_summary", {}).get("invocation_id_created") is not False
        or audit.get("failure_summary", {}).get(
            "launcher_or_actual_child_subprocess_spawned_by_failed_call"
        )
        is not False
    ):
        raise V5ContractError("V4 terminal failure disposition changed")
    descriptor_path = (PROJECT_ROOT / V4_DESCRIPTOR_RELATIVE).resolve(strict=True)
    descriptor = read_json_object(descriptor_path)
    verify_sealed_payload(descriptor, "descriptor_sha256")
    if (
        sha256_file(descriptor_path) != V4_DESCRIPTOR_RAW_SHA256
        or descriptor.get("descriptor_sha256") != V4_DESCRIPTOR_SELF_SHA256
        or Path(str(descriptor["runtime_root"])).resolve()
        != descriptor_path.parent.resolve()
    ):
        raise V5ContractError("V4 failed descriptor evidence changed")
    for relative, expected_hash in audit["failure_path_source_hashes"].items():
        if sha256_file(PROJECT_ROOT / relative) != expected_hash:
            raise V5ContractError(f"V4 failure-path source changed: {relative}")
    return {
        "directory": V4_FAILURE_AUDIT_RELATIVE,
        "files": {
            name: file_record(audit_root / name)
            for name in sorted(V4_FAILURE_AUDIT_EXPECTED)
        },
        "audit_self_sha256": audit["audit_sha256"],
        "verdict": audit["verdict"],
        "classification": audit["classification"],
        "v4_failed_descriptor": file_record(descriptor_path),
        "v4_failed_descriptor_self_sha256": descriptor["descriptor_sha256"],
        "heldout_identifiers_repeated": False,
    }


def _verify_pre_reservation_state() -> dict[str, Any]:
    registry_path = (PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json").resolve(
        strict=True
    )
    registry = read_json_object(registry_path)
    entries = registry.get("entries")
    if not isinstance(entries, list):
        raise V5ContractError("spent-seed registry schema changed")
    future_output = str(
        (PROJECT_ROOT / "outputs" / OFFICIAL_FUTURE_OUTPUT_NAME).resolve()
    )
    v5_matches = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and (
            str(entry.get("reservation_id", "")).startswith("prospective-fresh-v5")
            or str(entry.get("owner_output_root", "")) == future_output
        )
    ]
    if v5_matches:
        raise V5ContractError("V5 reservation already exists; repair freeze must precede it")
    future_root = PROJECT_ROOT / "outputs" / OFFICIAL_FUTURE_OUTPUT_NAME
    if future_root.exists():
        raise V5ContractError("future V5 execution root existed before repair freeze")
    return {
        "registry": file_record(registry_path),
        "registry_self_sha256": registry.get("registry_sha256"),
        "registry_entry_count": len(entries),
        "v5_matching_reservation_count": 0,
        "future_execution_root_present": False,
        "seed_identifiers_serialized_into_freeze": False,
    }


def _source_records() -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for relative in V5_SOURCE_RELATIVE:
        path = (PROJECT_ROOT / relative).resolve(strict=True)
        source = path.read_text(encoding="utf-8")
        compile(source, str(path), "exec")
        records[relative] = file_record(path)
    return records


def _verification_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": "src",
            "PYTHONDONTWRITEBYTECODE": "1",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
            "CUDA_VISIBLE_DEVICES": "-1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "HIP_VISIBLE_DEVICES": "-1",
            "ROCR_VISIBLE_DEVICES": "-1",
        }
    )
    return environment


def main() -> int:
    output = (PROJECT_ROOT / "outputs" / OUTPUT_NAME).resolve()
    if output.exists():
        raise V5ContractError(f"immutable repair freeze already exists: {output}")
    registry_before = sha256_file(PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json")
    v4_binding = _verify_v4_failure_audit()
    pre_reservation = _verify_pre_reservation_state()
    sources = _source_records()

    pinned_python = (
        PROJECT_ROOT.parent / ".venv_pe_model_lab_py310" / "Scripts" / "python.exe"
    ).resolve(strict=True)
    ruff = shutil.which("ruff")
    if ruff is None:
        raise V5ContractError("ruff executable is unavailable")
    environment = _verification_environment()
    pytest_result = _run_checked(
        [
            str(pinned_python),
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/model_lab/test_prospective_fresh_ensemble_v5_repair.py",
        ],
        environment,
    )
    ruff_result = _run_checked(
        [
            str(Path(ruff).resolve(strict=True)),
            "check",
            "research/model_zoo/prospective_fresh_ensemble_v5",
            "scripts/model_lab/prospective_fresh_ensemble_v5",
            "tests/model_lab/test_prospective_fresh_ensemble_v5_repair.py",
        ],
        environment,
    )
    registry_after_checks = sha256_file(
        PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json"
    )
    if registry_after_checks != registry_before:
        raise V5ContractError("spent-seed registry changed during V5 repair verification")

    output.mkdir(parents=True, exist_ok=False)
    source_freeze = seal_payload(
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "frozen_at_utc": _utc_now(),
            "state": "PRE_RESERVATION_REPAIR_SOURCE_FREEZE",
            "source_files": sources,
            "source_file_count": len(sources),
            "all_sources_compile_in_memory": True,
            "v4_failure_path_sources_rehashed_exact": True,
            "v1_v4_source_or_artifact_mutation_authorized": False,
        },
        "source_freeze_sha256",
    )
    source_path = output / "V5_REPAIR_SOURCE_FREEZE.json"
    write_json_exclusive(source_path, source_freeze)

    test_evidence = seal_payload(
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "verified_at_utc": _utc_now(),
            "state": "NO_MODEL_REPAIR_VERIFIED",
            "source_freeze": file_record(source_path),
            "source_freeze_self_sha256": source_freeze["source_freeze_sha256"],
            "pinned_python": file_record(pinned_python),
            "pytest": pytest_result,
            "pytest_expected": "8 passed",
            "real_pinned_windows_descriptor_to_handshake_roundtrip": "PASS",
            "launcher_pid_differs_from_actual_child_pid": True,
            "adversarial_fail_closed_cases": 7,
            "ruff": ruff_result,
            "in_memory_compile": "PASS",
            "seed_reservation_performed": False,
            "data_generation_performed": False,
            "model_fit_or_prediction_performed": False,
            "truth_opened": False,
            "scoring_performed": False,
        },
        "test_evidence_sha256",
    )
    test_path = output / "V5_REPAIR_TEST_EVIDENCE.json"
    write_json_exclusive(test_path, test_evidence)

    design = seal_payload(
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "frozen_at_utc": _utc_now(),
            "state": "AUDIT_READY_PRE_RESERVATION_NO_EXECUTION",
            "supersedes_terminal_lane": "prospective_fresh_ensemble_v4",
            "v4_terminal_failure_audit": v4_binding,
            "repair": {
                "root_cause": "V4_DESCRIPTOR_PARENT_EQUALLED_RUNTIME_ROOT",
                "heldout_descriptor_relative": "HELDOUT_STAGE_DESCRIPTOR.json",
                "heldout_runtime_relative": "runtime/heldout",
                "descriptor_outside_runtime_root_required": True,
                "descriptor_and_runtime_root_exact_absolute_binding_required": True,
                "all_handshake_artifacts_below_runtime_root": True,
                "actual_child_pid_and_launcher_parent_pid_exact": True,
            },
            "candidate": {
                "candidate_id": CANDIDATE_ID,
                "candidate_count": 1,
                "members": list(CANDIDATE_MEMBERS),
                "aggregation": "rowwise_level_median3",
                "runner_up_or_substitution_allowed": False,
            },
            "frozen_gates": {
                "qualification": {
                    "pooled_fair_log_mae_relative_gain": ">0",
                    "pooled_fair_log_rmse_relative_gain": ">=0",
                    "minimum_seed_mae_wins": "3/5",
                    "maximum_worst_seed_mae_relative_harm": 0.03,
                    "full_coverage_and_pit_required": True,
                },
                "heldout": {
                    "pooled_fair_log_mae_relative_gain": ">0",
                    "pooled_fair_log_rmse_relative_gain": ">=0",
                    "minimum_seed_mae_wins": "3/5",
                    "maximum_worst_seed_mae_relative_harm": 0.03,
                    "full_coverage_and_pit_required": True,
                },
                "gate_change_from_v4": False,
            },
            "evidence_class": {
                "classification": "RESEARCH_FRESH_SYNTHETIC_ONLY",
                "same_generator_only": True,
                "real_market_validation": False,
                "production_promotion_authority": False,
            },
            "fresh_reservation_plan_after_audit_only": {
                "registry": "outputs/v04_spent_seed_registry.json",
                "append_only": True,
                "qualification_seed_count": 5,
                "heldout_seed_count": 5,
                "v1_v4_reserved_or_spent_ids_available": False,
                "v4_heldout_ids_reusable": False,
                "seed_identifiers_selected_or_disclosed_now": False,
                "reservation_allowed_before_independent_repair_audit": False,
                "reservation_allowed_before_separate_root_approval": False,
                "reservation_retry_or_reuse_allowed": False,
            },
            "post_freeze_sequence": [
                "independent_read_only_V5_repair_audit",
                "separate_root_approval_for_fresh_5_plus_5_reservation",
                "atomic_append_only_reservation_and_commitment",
                "full_V5_execution_source_closure_and_precommit_freeze",
                "independent_prelaunch_audit",
                "separate_qualification_root_launch_approval",
                "qualification_generate_predict_evaluate_once",
                "if_and_only_if_qualification_passes_separate_heldout_unlock_audit",
                "separate_heldout_root_launch_approval",
                "heldout_generate_predict_evaluate_once",
            ],
            "forbidden_at_this_freeze": {
                "seed_reservation": True,
                "seed_resolution": True,
                "generation": True,
                "model_fit": True,
                "prediction": True,
                "truth_open": True,
                "scoring": True,
                "V4_retry_or_reuse": True,
            },
            "source_freeze": file_record(source_path),
            "source_freeze_self_sha256": source_freeze["source_freeze_sha256"],
            "test_evidence": file_record(test_path),
            "test_evidence_self_sha256": test_evidence["test_evidence_sha256"],
            "pre_reservation_verification": pre_reservation,
        },
        "design_lock_sha256",
    )
    design_path = output / "V5_REPAIR_DESIGN_LOCK.json"
    write_json_exclusive(design_path, design)

    registry_final = sha256_file(PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json")
    if registry_final != registry_before:
        raise V5ContractError("spent-seed registry changed while sealing V5 repair")
    status = seal_payload(
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "sealed_at_utc": _utc_now(),
            "state": "AWAITING_INDEPENDENT_REPAIR_AUDIT_BEFORE_RESERVATION",
            "design_lock": file_record(design_path),
            "design_lock_self_sha256": design["design_lock_sha256"],
            "source_freeze": file_record(source_path),
            "source_freeze_self_sha256": source_freeze["source_freeze_sha256"],
            "test_evidence": file_record(test_path),
            "test_evidence_self_sha256": test_evidence["test_evidence_sha256"],
            "registry_raw_sha256_before_and_after_exact": registry_final,
            "V5_seed_reservation_exists": False,
            "V5_runtime_root_exists": False,
            "V4_retry_or_mutation_performed": False,
            "model_or_data_operation_performed": False,
            "next_permitted_action": "INDEPENDENT_READ_ONLY_V5_REPAIR_AUDIT",
        },
        "status_sha256",
    )
    status_path = output / "PRE_RESERVATION_STATUS.json"
    write_json_exclusive(status_path, status)

    artifacts = [design_path, source_path, test_path, status_path]
    checksums_path = output / "CHECKSUMS.sha256"
    with checksums_path.open("xb") as stream:
        for path in sorted(artifacts, key=lambda item: item.name):
            stream.write(f"{sha256_file(path)}  {path.name}\n".encode("ascii"))
        stream.flush()

    print(f"V5_REPAIR_FREEZE {output}")
    print(f"DESIGN_RAW {sha256_file(design_path)}")
    print(f"DESIGN_SELF {design['design_lock_sha256']}")
    print(f"SOURCE_RAW {sha256_file(source_path)}")
    print(f"SOURCE_SELF {source_freeze['source_freeze_sha256']}")
    print(f"TEST_RAW {sha256_file(test_path)}")
    print(f"TEST_SELF {test_evidence['test_evidence_sha256']}")
    print(f"STATUS_RAW {sha256_file(status_path)}")
    print(f"STATUS_SELF {status['status_sha256']}")
    print(f"CHECKSUMS_RAW {sha256_file(checksums_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
