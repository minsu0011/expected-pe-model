"""Run exact score-free probes and atomically freeze the R5 precommit."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.artifacts import (
    sha256_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.contracts import (
    REQUIRED_NAMED_PROBES,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.precommit import (
    freeze_score_free_precommit,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.transaction import (
    verify_live_registry_read_only,
)


ROOT = Path(
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
SELF = ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r5/"
    "freeze_r5_precommit.py"
)
PINNED = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
RUFF = Path(r"C:\Users\minsu\anaconda3\Scripts\ruff.exe")
RUFF_SHA256 = "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
TEST_MAIN = "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r5.py"
TEST_TRANSACTION = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r5_transaction.py"
)
PROBE_NODEIDS = {
    "bootstrap_rejects_pyc_pyd_dll_and_extra_file": [
        f"{TEST_MAIN}::test_bootstrap_rejects_pyc_pyd_dll_and_extra_file"
    ],
    "bootstrap_rejects_extra_directory_and_reparse": [
        f"{TEST_MAIN}::test_bootstrap_rejects_extra_directory_and_reparse"
    ],
    "bootstrap_binds_all_initializers_origins_hashes_loaders": [
        f"{TEST_MAIN}::test_bootstrap_binds_all_initializers_origins_hashes_loaders",
        (
            f"{TEST_MAIN}::"
            "test_bootstrap_verified_bytes_import_attestation_executes_before_action"
        ),
    ],
    "bootstrap_isolated_flags_path_cwd_site_environment_exact": [
        f"{TEST_MAIN}::test_bootstrap_isolated_flags_path_cwd_site_environment_exact"
    ],
    "lexical_case_alias_rejected_before_resolve": [
        f"{TEST_MAIN}::test_lexical_case_alias_rejected_before_resolve"
    ],
    "lexical_dotdot_forward_slash_UNC_device_ADS_8dot3_rejected": [
        f"{TEST_MAIN}::test_lexical_dotdot_forward_slash_UNC_device_ADS_8dot3_rejected"
    ],
    "component_symlink_junction_reparse_rejected": [
        f"{TEST_MAIN}::test_component_symlink_junction_reparse_rejected"
    ],
    "R4_NO_GO_full_bundle_supersession_exact": [
        f"{TEST_MAIN}::test_R4_NO_GO_full_bundle_supersession_exact"
    ],
    "candidate_gate_geometry_schema_and_zero_states_exact": [
        f"{TEST_MAIN}::test_candidate_gate_geometry_schema_and_zero_states_exact"
    ],
    "transaction_lock_is_process_lifetime_OS_lock": [
        f"{TEST_MAIN}::test_transaction_lock_is_process_lifetime_OS_lock"
    ],
    "transaction_lock_spans_verify_read_derive_append_reread_receipt": [
        f"{TEST_MAIN}::test_transaction_lock_spans_verify_read_derive_append_reread_receipt"
    ],
    "fault_after_each_durable_phase_recovers_exactly_once": [
        f"{TEST_TRANSACTION}::test_fault_after_each_durable_phase_recovers_exactly_once"
    ],
    "same_transaction_concurrency_returns_one_entry_one_receipt": [
        f"{TEST_TRANSACTION}::test_same_transaction_32_processes_return_one_entry_one_receipt"
    ],
    "distinct_lane_race_one_success_one_clean_fail_no_orphan": [
        f"{TEST_TRANSACTION}::test_distinct_lane_same_snapshot_one_success_one_clean_fail_no_orphan"
    ],
    "legacy_old_writer_race_lost_update_zero": [
        f"{TEST_TRANSACTION}::test_legacy_old_writer_race_lost_update_zero"
    ],
    "corrupt_truncated_swapped_journal_receipt_rejected": [
        f"{TEST_TRANSACTION}::test_corrupt_truncated_swapped_journal_receipt_rejected"
    ],
    "journal_before_after_exact_one_append_cross_bound": [
        f"{TEST_TRANSACTION}::test_journal_before_after_exact_one_append_cross_bound"
    ],
    "hash_equal_recovery_membership_receipt_exact": [
        f"{TEST_TRANSACTION}::test_hash_equal_recovery_membership_receipt_exact"
    ],
    "forged_unrelated_prepositioned_journal_receipt_rejected": [
        (
            f"{TEST_TRANSACTION}::"
            "test_forged_unrelated_prepositioned_journal_receipt_rejected"
        )
    ],
    "later_unrelated_append_and_stale_lock_recover": [
        f"{TEST_TRANSACTION}::test_later_unrelated_append_keeps_first_retry_idempotent",
        f"{TEST_TRANSACTION}::test_fault_after_each_durable_phase_recovers_exactly_once",
    ],
    "named_test_results_and_raw_logs_bound": [
        f"{TEST_MAIN}::test_named_test_results_and_raw_logs_bound"
    ],
    "approver_token_identity_authenticated": [
        f"{TEST_MAIN}::test_approver_token_identity_authenticated"
    ],
    "audit_before_approval_and_freshness_enforced": [
        f"{TEST_MAIN}::test_audit_before_approval_and_freshness_enforced"
    ],
    "minimal_unbound_extra_missing_wrong_hash_audit_approval_rejected": [
        f"{TEST_MAIN}::test_minimal_unbound_extra_missing_wrong_hash_audit_approval_rejected",
        (
            f"{TEST_MAIN}::"
            "test_audit_minimal_unbound_extra_missing_wrong_hash_resealed_attacks_reject"
        ),
        (
            f"{TEST_MAIN}::"
            "test_approval_minimal_unbound_extra_missing_wrong_hash_resealed_attacks_reject"
        ),
    ],
}


def _raw_record(raw: bytes, returncode: int, **extra: object) -> dict[str, object]:
    return {
        "returncode": returncode,
        "raw_log_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_log_base64": base64.b64encode(raw).decode("ascii"),
        **extra,
    }


def main() -> int:
    if str(Path(sys.argv[0])) != str(SELF) or str(Path(__file__)) != str(SELF):
        raise RuntimeError("R5 freeze must be invoked by its exact absolute path")
    if (
        sys.version.split()[0] != "3.10.19"
        or str(Path(sys.executable)) != str(PINNED)
        or sha256_file(PINNED) != PINNED_SHA256
        or sha256_file(RUFF) != RUFF_SHA256
        or set(PROBE_NODEIDS) != set(REQUIRED_NAMED_PROBES)
    ):
        raise RuntimeError("R5 freeze interpreter/tool/probe universe differs")
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT), str(ROOT / "src")))
    environment.pop("R5_TEST_CRASH_AT", None)
    environment.pop("R5_TEST_HOLD_AFTER_LEGACY_MARKER_SECONDS", None)
    pytest_command = [
        str(PINNED),
        "-B",
        "-m",
        "pytest",
        "-vv",
        "--tb=short",
        "-p",
        "no:cacheprovider",
        TEST_MAIN,
        TEST_TRANSACTION,
    ]
    pytest_result = subprocess.run(
        pytest_command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
    )
    pytest_raw = pytest_result.stdout + pytest_result.stderr
    if pytest_result.returncode != 0:
        raise RuntimeError(pytest_raw.decode("utf-8", errors="replace")[-12000:])
    match = re.search(rb"(\d+) passed", pytest_raw)
    passed = int(match.group(1)) if match else 0
    ruff_targets = [
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r5",
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r5",
        TEST_MAIN,
        TEST_TRANSACTION,
    ]
    ruff_command = [str(RUFF), "check", *ruff_targets]
    ruff_result = subprocess.run(
        ruff_command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
    )
    ruff_raw = ruff_result.stdout + ruff_result.stderr
    if ruff_result.returncode != 0:
        raise RuntimeError(ruff_raw.decode("utf-8", errors="replace")[-12000:])
    generated_at = datetime.now(timezone.utc).isoformat()
    pytest_hash = hashlib.sha256(pytest_raw).hexdigest()
    evidence = {
        "commands": {"pytest": pytest_command, "ruff": ruff_command},
        "environment": {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": environment["PYTHONPATH"],
            "R5_TEST_CRASH_AT": None,
        },
        "generated_at_utc": generated_at,
        "interpreter": {
            "version": "3.10.19",
            "launcher": str(PINNED),
            "launcher_raw_sha256": PINNED_SHA256,
        },
        "named_probe_results": {
            name: {
                "status": "PASS",
                "nodeids": nodeids,
                "raw_log_sha256": pytest_hash,
            }
            for name, nodeids in sorted(PROBE_NODEIDS.items())
        },
        "pytest": _raw_record(
            pytest_raw,
            pytest_result.returncode,
            passed_count=passed,
            nodeids=sorted({nodeid for values in PROBE_NODEIDS.values() for nodeid in values}),
        ),
        "ruff": _raw_record(
            ruff_raw,
            ruff_result.returncode,
            executable=str(RUFF),
            executable_raw_sha256=RUFF_SHA256,
        ),
        "side_effects": {
            "fresh_seed_ids_derived": False,
            "fresh_seed_ids_reserved": False,
            "registry_mutated": False,
            "runtime_root_created": False,
            "truth_opened": False,
            "score_computed": False,
        },
    }
    registry = ROOT / "outputs/v04_spent_seed_registry.json"
    registry_before = verify_live_registry_read_only(registry)
    result = freeze_score_free_precommit(
        quality_evidence=evidence, generated_at_utc=generated_at
    )
    registry_after = verify_live_registry_read_only(registry)
    if registry_after != registry_before:
        raise RuntimeError("registry invariant changed during score-free R5 freeze")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
