from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = (
    ROOT
    / "research"
    / "model_zoo"
    / "portfolio_governance_v1"
    / "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _lock() -> dict[str, object]:
    return json.loads(LOCK_PATH.read_bytes())


def test_hofs_v12_lock_has_no_execution_or_data_authority() -> None:
    lock = _lock()
    assert lock["schema_version"] == (
        "expected_pe.portfolio.hofs_v12_resource_resolution_lock.v1"
    )
    assert lock["status"] == "DESIGN_LOCK_NO_EXECUTION_AUTHORITY"
    assert lock["scope"] == "ISOLATED_PE_C4_HOFS_QUALIFICATION_PREDICTION_LANE_ONLY"
    assert lock["authority"] == {
        "actual_numeric_launch": False,
        "fresh_or_heldout_discovery": False,
        "publication": False,
        "score_or_truth_access": False,
    }
    assert lock["current_verdict"] == (
        "RESOURCE_CONFLICT_RESOLVED_IN_DESIGN_ONLY_NUMERIC_LAUNCH_STILL_FORBIDDEN"
    )


def test_hofs_v12_lock_resolves_affinity_without_changing_v7() -> None:
    lock = _lock()
    conflict = lock["conflict_closed"]
    assert conflict["id"] == "P0_V7_32CPU_VS_V12_2CPU_AFFINITY_CONFLICT"
    assert conflict["prohibited_resolutions"] == [
        "MONKEYPATCH_V7_RUNTIME_CAPTURE",
        "SHIM_OR_COPY_V7_RECEIPT",
        "WEAKEN_V7_VALIDATION",
        "RUN_V7_NUMERIC_INSIDE_A_TWO_CPU_AFFINITY_PROCESS",
    ]

    resource = lock["resource_contract"]
    assert resource["actual_controller_worker_count"] == 16
    assert resource["process_start_method"] == "spawn"
    assert resource["worker_affinity_mask_hex"] == "0xFFFFFFFF"
    assert resource["worker_cpu_ids"] == list(range(32))
    assert resource["logical_cpus_visible_per_worker"] == 32
    assert resource["inner_threads"] == 1
    assert resource["required_environment"] == {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
    }
    assert resource["gpu_used"] is False
    assert resource["v7_resource_receipt_outer_workers_field"] == 32
    assert resource["isolated_c4_runtime_receipt_records_actual_worker_count"] == 16

    lineage = lock["numeric_lineage"]
    assert lineage["numeric_source_change_allowed"] is False
    assert lineage["service_or_custody_change_only"] is True
    assert lineage["same_fresh_tuning_or_retest_allowed"] is False
    assert HEX64.fullmatch(lineage["v7_contract_sha256"])
    assert HEX64.fullmatch(lineage["v7_fit_config_sha256"])


def test_hofs_v12_lock_evidence_pins_are_current() -> None:
    lock = _lock()
    pins = lock["evidence_pins"]
    assert len(pins) == 10
    assert len({row["relative_path"] for row in pins}) == len(pins)
    for row in pins:
        assert set(row) >= {"relative_path", "size_bytes", "raw_sha256"}
        path = ROOT / row["relative_path"]
        assert path.is_file()
        assert path.stat().st_size == row["size_bytes"]
        assert HEX64.fullmatch(row["raw_sha256"])
        assert _sha256(path) == row["raw_sha256"]


def test_hofs_v12_lock_requires_all_pretruth_gates() -> None:
    lock = _lock()
    assert lock["required_before_fresh_numeric_launch"] == [
        "HOFS_V12_SERVICE_SOURCE_FREEZE",
        "SPENT_PUBLIC_ONE_TASK_62_FOLD_BITWISE_EQUIVALENCE_TO_FROZEN_HOFS_R2",
        "NATIVE_16_WORKER_FULL_AFFINITY_RESOURCE_PREFLIGHT",
        "INDEPENDENT_PRETRUTH_SOURCE_AND_RUNTIME_AUDIT_GO_P0_0_P1_0_P2_0",
        "EXTERNAL_ACTUAL_COMMON_TASK_HASH_AND_FILE_ID_BINDING",
    ]
