"""Fixed-identity exclusive publisher for approved spent resource evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    EXPECTED_CPU_IDS,
    GPU_OFF_ENVIRONMENT,
    INNER_THREADS,
    NUMERIC_RESOURCE_GATE_STATUS,
    OUTER_WORKERS,
    PROCESS_START_METHOD,
    RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
    SPENT_EVIDENCE_OUTPUT_ROOT,
    SPENT_EVIDENCE_STAGING_ROOT,
    WORKER_AFFINITY_MASK,
    WORKER_AFFINITY_POLICY,
    HofsV12QualificationServiceError,
    canonical_json_bytes,
    validate_exact_json_primitives,
)
from .runtime import expected_process_exit_records


_RESOURCE_STATUS = "PASS_NATIVE_16_SPAWNED_FULL_AFFINITY_RESOURCE_PREFLIGHT"
_SPENT_STATUS = "PASS_SPENT_PUBLIC_ONE_TASK_62_FOLD_BITWISE_EQUIVALENCE"
_EXPECTED_PREDICTION_ROWS_SHA256 = (
    "b9ddd3fc9b397a825da4ae3a5abb35370df19f3db64b5a89c61b4e0f40edb58e"
)
_APPROVAL_RELATIVE = (
    "research/model_zoo/portfolio_governance_v1/"
    "HOFS_V12_SPENT_EVIDENCE_PUBLICATION_APPROVAL_V1.json"
)
_APPROVAL_SCHEMA_VERSION = "expected_pe.hofs_v12.spent_evidence_publication_approval.v1"
_APPROVAL_STATUS = "ROOT_APPROVED_ONE_SHOT_SPENT_EVIDENCE_PUBLICATION"
_APPROVAL_FIELDS = (
    "schema_version",
    "status",
    "output_relative",
    "resource_receipt_raw_sha256",
    "spent_receipt_raw_sha256",
    "source_records_semantic_sha256",
    "approval_nonce_sha256",
    "one_shot",
    "publication_count_before",
)
_SOURCE_RELATIVES = (
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/__init__.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/contracts.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/publisher.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/runtime.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/service.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/RUNTIME_BINDING_REPORT.md",
    "research/model_zoo/hofs_research_adapter_v1/inputs.py",
    "research/model_zoo/portfolio_governance_v1/HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/contracts.py",
    "scripts/model_lab/hofs_v12_fresh_qualification_service_v1/run_spent_public_smoke.py",
    "tests/model_lab/test_hofs_v12_fresh_qualification_service_v1.py",
)
_PINNED_DEPENDENCY_RAW_SHA256 = {
    "research/model_zoo/hofs_research_adapter_v1/inputs.py": (
        "627ac3a73fcfee88b10b6229b1043b79cc98c8b5425e693b108d844126586551"
    ),
    "research/model_zoo/portfolio_governance_v1/"
    "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json": RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/contracts.py": (
        "ab5d80a58236472f9536dfe4cce73084e8d47f97e6da3490aa5d99b0e0099d32"
    ),
}
_HEX64 = frozenset("0123456789abcdef")
_HEX32 = frozenset("0123456789abcdef")
_RESOURCE_RECEIPT_FIELDS = (
    "schema_version",
    "status",
    "resource_resolution_lock_raw_sha256",
    "process_start_method",
    "actual_controller_worker_count",
    "simultaneous_ready_worker_count",
    "controller_observation",
    "worker_observations",
    "process_exit_records",
    "elapsed_ns",
    "worker_peak_rss_max_bytes",
    "worker_peak_rss_sum_bytes",
    "qualification_access_count",
    "fresh_access_count",
    "truth_access_count",
    "heldout_access_count",
    "score_access_count",
    "publication_count",
    "receipt_raw_sha256",
)
_OBSERVATION_FIELDS = (
    "logical_cpu_count",
    "logical_cpu_ids",
    "affinity_mask",
    "affinity_policy",
    "inner_threads",
    "environment",
    "process_start_method",
    "status",
    "worker_ordinal",
    "pid",
)
_MEMORY_FIELDS = ("rss_bytes", "peak_rss_bytes", "private_bytes", "peak_pagefile_bytes")
_SPENT_RECEIPT_FIELDS = (
    "schema_version",
    "status",
    "resource_resolution_lock_raw_sha256",
    "spent_seed",
    "spent_dgp",
    "fold_count",
    "prediction_row_count",
    "bitwise_numeric_comparison_count",
    "bitwise_numeric_mismatch_count",
    "identity_or_hash_mismatch_count",
    "surface_log_bitwise_mismatch_count",
    "current_prediction_rows_sha256",
    "frozen_r2_prediction_rows_sha256",
    "resource_envelope",
    "fixed_file_records",
    "elapsed_ns",
    "peak_process_rss_bytes",
    "publication_count",
    "qualification_access_count",
    "fresh_access_count",
    "truth_artifact_access_count",
    "heldout_access_count",
    "score_artifact_access_count",
    "upstream_score_named_numeric_use_count",
    "receipt_raw_sha256",
)
_FIXED_FILE_RECORD_FIELDS = (
    "raw_sha256",
    "size_bytes",
    "volume_serial_number",
    "file_id_128",
)
_SPENT_FIXED_FILE_RAW_SHA256 = {
    "research/model_zoo/portfolio_governance_v1/HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json": RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
    "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821/CHECKSUMS.sha256": "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7",
    "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821/FREEZE_RECEIPT.json": "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14",
    "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821/replays/pass_1/seed_2026082001/dgp_A/canonical150.csv": "aa6bb2f3e63b4423c79a578c3ed2fb8353050dd5ed7dc2d117931abfde1bb384",
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/CHECKSUMS.sha256": "4453e6ac01c0479cee794a4ef825fba392fde5ed22fe1dbbbb6729961b072b80",
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/PREDICTIONS.csv": "bb19a0a15ab20bda7d384a87df5ab0c26ef2b1db1db35a0c7f9b9c77d0542fcd",
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/TASK_RECEIPTS.jsonl": "3e93b16c29ebfb10068f0feaa82a40c90f1958bf5405c3c219c15b01551df76b",
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/FOLD_RECEIPTS.jsonl": "a4ba4822e8a792cec66b81850e301f1c1103c7a64e51779dee95d998612f34ee",
}
_CAPABILITY_MINT_TOKEN = object()
_PUBLICATION_CAPABILITY_CONSUMED = False


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class _SpentEvidencePublicationApprovalCapability:
    """Identity of a separately created immutable root-approval record."""

    approval_record_raw_sha256: str
    approval_record_size_bytes: int
    approval_record_volume_serial_number: int
    approval_record_file_id_128: str
    _mint_token: object

    def __post_init__(self) -> None:
        if self._mint_token is not _CAPABILITY_MINT_TOKEN:
            raise HofsV12QualificationServiceError(
                "publication capability can only be minted by the fixed root launcher"
            )
        _require_hex(self.approval_record_raw_sha256, digits=64, label="approval raw hash")
        _require_nonnegative_int(self.approval_record_size_bytes, label="approval size")
        _require_nonnegative_int(
            self.approval_record_volume_serial_number, label="approval volume serial"
        )
        _require_hex(
            self.approval_record_file_id_128, digits=32, label="approval FileId"
        )


def _require_exact_dict(
    value: object, *, fields: tuple[str, ...], label: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields) or len(value) != len(fields):
        raise HofsV12QualificationServiceError(f"{label} field universe drifted")
    return value


def _require_nonnegative_int(value: object, *, label: str, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum:
        raise HofsV12QualificationServiceError(
            f"{label} must be an exact integer >= {minimum}"
        )
    return value


def _require_zero_int(value: object, *, label: str) -> None:
    if type(value) is not int or value != 0:
        raise HofsV12QualificationServiceError(f"{label} must be exact integer zero")


def _require_hex(value: object, *, digits: int, label: str) -> str:
    alphabet = _HEX64 if digits == 64 else _HEX32
    if (
        type(value) is not str
        or len(value) != digits
        or any(character not in alphabet for character in value)
    ):
        raise HofsV12QualificationServiceError(
            f"{label} must be {digits} lowercase hex digits"
        )
    return value


def _receipt_payload_without_self_hash(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if type(receipt) is not dict:
        raise HofsV12QualificationServiceError("evidence receipt must be an exact dict")
    payload = dict(receipt)
    claimed = payload.pop("receipt_raw_sha256")
    _require_hex(claimed, digits=64, label="receipt raw hash")
    if hashlib.sha256(canonical_json_bytes(payload)).hexdigest() != claimed:
        raise HofsV12QualificationServiceError("evidence receipt self hash drifted")
    return payload


def _validate_memory(value: object, *, label: str) -> dict[str, Any]:
    memory = _require_exact_dict(value, fields=_MEMORY_FIELDS, label=label)
    for field in _MEMORY_FIELDS:
        _require_nonnegative_int(memory[field], label=f"{label}.{field}")
    if memory["peak_rss_bytes"] < memory["rss_bytes"]:
        raise HofsV12QualificationServiceError(f"{label} peak RSS is incoherent")
    return memory


def _validate_resource_observation(
    value: object,
    *,
    worker_ordinal: int,
    controller: bool,
    memory_required: bool,
) -> dict[str, Any]:
    extra = ("process_role",) if controller else ()
    if memory_required:
        extra += ("memory",)
    row = _require_exact_dict(
        value,
        fields=(*_OBSERVATION_FIELDS, *extra),
        label="resource observation",
    )
    if (
        row["logical_cpu_count"] != len(EXPECTED_CPU_IDS)
        or type(row["logical_cpu_count"]) is not int
        or row["logical_cpu_ids"] != list(EXPECTED_CPU_IDS)
        or any(type(cpu_id) is not int for cpu_id in row["logical_cpu_ids"])
        or row["affinity_mask"] != f"0x{WORKER_AFFINITY_MASK:08X}"
        or row["affinity_policy"] != WORKER_AFFINITY_POLICY
        or type(row["inner_threads"]) is not int
        or row["inner_threads"] != INNER_THREADS
        or type(row["environment"]) is not dict
        or row["environment"] != GPU_OFF_ENVIRONMENT
        or row["process_start_method"] != PROCESS_START_METHOD
        or row["status"] != NUMERIC_RESOURCE_GATE_STATUS
        or type(row["worker_ordinal"]) is not int
        or row["worker_ordinal"] != worker_ordinal
    ):
        raise HofsV12QualificationServiceError("resource observation envelope drifted")
    _require_nonnegative_int(row["pid"], label="resource observation PID", positive=True)
    if controller and row["process_role"] != "controller":
        raise HofsV12QualificationServiceError("controller process role drifted")
    if memory_required:
        _validate_memory(row["memory"], label="resource observation memory")
    return row


def validate_spent_evidence_receipts(
    resource_receipt: Mapping[str, Any],
    spent_receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate exact PASS evidence without granting publication authority."""

    validate_exact_json_primitives(resource_receipt)
    validate_exact_json_primitives(spent_receipt)
    resource = _require_exact_dict(
        resource_receipt,
        fields=_RESOURCE_RECEIPT_FIELDS,
        label="resource preflight receipt",
    )
    spent = _require_exact_dict(
        spent_receipt,
        fields=_SPENT_RECEIPT_FIELDS,
        label="spent equivalence receipt",
    )
    _receipt_payload_without_self_hash(resource)
    _receipt_payload_without_self_hash(spent)
    if (
        resource["schema_version"] != "expected_pe.hofs_v12.resource_preflight.v1"
        or resource.get("status") != _RESOURCE_STATUS
        or resource["resource_resolution_lock_raw_sha256"]
        != RESOURCE_RESOLUTION_LOCK_RAW_SHA256
        or resource["process_start_method"] != PROCESS_START_METHOD
    ):
        raise HofsV12QualificationServiceError("resource preflight receipt is not exact PASS")
    for field in ("actual_controller_worker_count", "simultaneous_ready_worker_count"):
        if type(resource[field]) is not int or resource[field] != OUTER_WORKERS:
            raise HofsV12QualificationServiceError("resource worker count is not exact")
    controller = _validate_resource_observation(
        resource["controller_observation"],
        worker_ordinal=0,
        controller=True,
        memory_required=True,
    )
    observations = resource["worker_observations"]
    if (
        type(observations) is not list
        or len(observations) != OUTER_WORKERS
    ):
        raise HofsV12QualificationServiceError("resource worker evidence universe drifted")
    workers = [
        _validate_resource_observation(
            row,
            worker_ordinal=ordinal,
            controller=False,
            memory_required=True,
        )
        for ordinal, row in enumerate(observations)
    ]
    pids = [controller["pid"], *(row["pid"] for row in workers)]
    if len(set(pids)) != OUTER_WORKERS + 1:
        raise HofsV12QualificationServiceError("controller/worker PIDs are not distinct")
    exits = resource["process_exit_records"]
    if type(exits) is not list or len(exits) != OUTER_WORKERS + 1:
        raise HofsV12QualificationServiceError("resource process exit universe drifted")
    for row in exits:
        exit_row = _require_exact_dict(
            row,
            fields=("process_role", "worker_ordinal", "exit_code"),
            label="resource process exit",
        )
        if (
            type(exit_row["process_role"]) is not str
            or type(exit_row["worker_ordinal"]) is not int
            or type(exit_row["exit_code"]) is not int
        ):
            raise HofsV12QualificationServiceError("resource process exit types drifted")
    if exits != list(expected_process_exit_records()):
        raise HofsV12QualificationServiceError("resource process exits differ from success")
    _require_nonnegative_int(resource["elapsed_ns"], label="resource elapsed ns", positive=True)
    peak_rows = [row["memory"]["peak_rss_bytes"] for row in workers]
    max_peak = _require_nonnegative_int(
        resource["worker_peak_rss_max_bytes"], label="resource worker max peak RSS"
    )
    sum_peak = _require_nonnegative_int(
        resource["worker_peak_rss_sum_bytes"], label="resource worker sum peak RSS"
    )
    if max_peak != max(peak_rows) or sum_peak != sum(peak_rows):
        raise HofsV12QualificationServiceError("resource worker memory aggregate drifted")
    for field in (
        "qualification_access_count",
        "fresh_access_count",
        "truth_access_count",
        "heldout_access_count",
        "score_access_count",
        "publication_count",
    ):
        _require_zero_int(resource[field], label=f"resource {field}")
    if (
        spent["schema_version"]
        != "expected_pe.hofs_v12.spent_public_equivalence_smoke.v1"
        or spent.get("status") != _SPENT_STATUS
        or spent["resource_resolution_lock_raw_sha256"]
        != RESOURCE_RESOLUTION_LOCK_RAW_SHA256
        or type(spent["spent_seed"]) is not int
        or spent["spent_seed"] != 2_026_082_001
        or spent["spent_dgp"] != "A"
    ):
        raise HofsV12QualificationServiceError("spent equivalence receipt is not exact PASS")
    for field, expected in (
        ("fold_count", 62),
        ("prediction_row_count", 1_296),
        ("bitwise_numeric_comparison_count", 6_480),
        ("bitwise_numeric_mismatch_count", 0),
        ("identity_or_hash_mismatch_count", 0),
        ("surface_log_bitwise_mismatch_count", 0),
    ):
        if type(spent[field]) is not int or spent[field] != expected:
            raise HofsV12QualificationServiceError(f"spent {field} is not exact")
    for field in ("current_prediction_rows_sha256", "frozen_r2_prediction_rows_sha256"):
        if spent[field] != _EXPECTED_PREDICTION_ROWS_SHA256:
            raise HofsV12QualificationServiceError("spent prediction row digest drifted")
    _validate_resource_observation(
        spent["resource_envelope"],
        worker_ordinal=0,
        controller=False,
        memory_required=False,
    )
    fixed_records = _require_exact_dict(
        spent["fixed_file_records"],
        fields=tuple(_SPENT_FIXED_FILE_RAW_SHA256),
        label="spent fixed file records",
    )
    for relative, expected_hash in _SPENT_FIXED_FILE_RAW_SHA256.items():
        row = _require_exact_dict(
            fixed_records[relative],
            fields=_FIXED_FILE_RECORD_FIELDS,
            label=f"spent fixed file {relative}",
        )
        if row["raw_sha256"] != expected_hash:
            raise HofsV12QualificationServiceError("spent fixed file raw hash drifted")
        _require_nonnegative_int(row["size_bytes"], label="spent fixed file size", positive=True)
        _require_nonnegative_int(
            row["volume_serial_number"], label="spent fixed file volume serial"
        )
        _require_hex(row["file_id_128"], digits=32, label="spent fixed file FileId")
    _require_nonnegative_int(spent["elapsed_ns"], label="spent elapsed ns", positive=True)
    _require_nonnegative_int(
        spent["peak_process_rss_bytes"], label="spent peak process RSS", positive=True
    )
    for field in (
        "qualification_access_count",
        "fresh_access_count",
        "truth_artifact_access_count",
        "heldout_access_count",
        "score_artifact_access_count",
        "upstream_score_named_numeric_use_count",
        "publication_count",
    ):
        _require_zero_int(spent[field], label=f"spent {field}")
    return dict(resource), dict(spent)


def _write_new(path: Path, content: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _source_records(root: Path) -> list[dict[str, Any]]:
    if len(_SOURCE_RELATIVES) != len(set(_SOURCE_RELATIVES)):
        raise HofsV12QualificationServiceError("source freeze universe is duplicated")
    records: list[dict[str, Any]] = []
    for relative in _SOURCE_RELATIVES:
        path = (root / relative).resolve(strict=True)
        if root not in path.parents or not path.is_file() or path.is_symlink():
            raise HofsV12QualificationServiceError("source freeze candidate escaped its root")
        raw = path.read_bytes()
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        expected_pin = _PINNED_DEPENDENCY_RAW_SHA256.get(relative)
        if expected_pin is not None and raw_sha256 != expected_pin:
            raise HofsV12QualificationServiceError(
                f"pinned source dependency drifted: {relative}"
            )
        records.append(
            {
                "relative": relative,
                "raw_sha256": raw_sha256,
                "size_bytes": len(raw),
            }
        )
    return records


def _capture_approval_record(
    root: Path,
) -> tuple[_SpentEvidencePublicationApprovalCapability, bytes]:
    candidate = root / _APPROVAL_RELATIVE
    if candidate.is_symlink():
        raise HofsV12QualificationServiceError("root approval record cannot be a symlink")
    try:
        path = candidate.resolve(strict=True)
    except OSError as exc:
        raise HofsV12QualificationServiceError(
            "fixed root approval record is absent or inaccessible"
        ) from exc
    if root not in path.parents or not path.is_file():
        raise HofsV12QualificationServiceError("root approval record escaped project root")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read()
        after = os.fstat(stream.fileno())
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(raw) != before.st_size
    ):
        raise HofsV12QualificationServiceError("root approval record identity changed while read")
    return (
        _SpentEvidencePublicationApprovalCapability(
            approval_record_raw_sha256=hashlib.sha256(raw).hexdigest(),
            approval_record_size_bytes=len(raw),
            approval_record_volume_serial_number=int(before.st_dev),
            approval_record_file_id_128=(
                f"{int(before.st_ino) & ((1 << 128) - 1):032x}"
            ),
            _mint_token=_CAPABILITY_MINT_TOKEN,
        ),
        raw,
    )


def _validate_root_approval(
    *,
    root: Path,
    capability: object,
    resource_receipt_raw_sha256: str,
    spent_receipt_raw_sha256: str,
    source_records_semantic_sha256: str,
) -> dict[str, Any]:
    if type(capability) is not _SpentEvidencePublicationApprovalCapability:
        raise HofsV12QualificationServiceError(
            "explicit immutable root publication approval capability is required"
        )
    if Path.cwd().resolve(strict=True) != root:
        raise HofsV12QualificationServiceError("spent publication is project-root-only")
    observed, raw = _capture_approval_record(root)
    if observed != capability:
        raise HofsV12QualificationServiceError("root approval FileId/hash/size binding drifted")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HofsV12QualificationServiceError("root approval JSON is invalid") from exc
    validate_exact_json_primitives(payload)
    approval = _require_exact_dict(
        payload,
        fields=_APPROVAL_FIELDS,
        label="root publication approval",
    )
    if canonical_json_bytes(approval) != raw:
        raise HofsV12QualificationServiceError("root approval bytes are not canonical")
    if (
        approval["schema_version"] != _APPROVAL_SCHEMA_VERSION
        or approval["status"] != _APPROVAL_STATUS
        or approval["output_relative"] != SPENT_EVIDENCE_OUTPUT_ROOT
        or approval["resource_receipt_raw_sha256"] != resource_receipt_raw_sha256
        or approval["spent_receipt_raw_sha256"] != spent_receipt_raw_sha256
        or approval["source_records_semantic_sha256"]
        != source_records_semantic_sha256
        or approval["one_shot"] is not True
    ):
        raise HofsV12QualificationServiceError("root publication approval binding drifted")
    _require_hex(approval["approval_nonce_sha256"], digits=64, label="approval nonce")
    _require_zero_int(
        approval["publication_count_before"], label="approval publication count before"
    )
    return approval


def _publish_spent_evidence_with_root_approval(
    *,
    resource_receipt: Mapping[str, Any],
    spent_receipt: Mapping[str, Any],
    approval_capability: _SpentEvidencePublicationApprovalCapability,
) -> dict[str, Any]:
    """Publish only the fixed approved evidence identity; never overwrite/retry."""

    global _PUBLICATION_CAPABILITY_CONSUMED  # noqa: PLW0603

    resource, spent = validate_spent_evidence_receipts(resource_receipt, spent_receipt)
    root = _project_root().resolve(strict=True)
    source_records = _source_records(root)
    source_semantic_sha256 = hashlib.sha256(canonical_json_bytes(source_records)).hexdigest()
    approval = _validate_root_approval(
        root=root,
        capability=approval_capability,
        resource_receipt_raw_sha256=resource["receipt_raw_sha256"],
        spent_receipt_raw_sha256=spent["receipt_raw_sha256"],
        source_records_semantic_sha256=source_semantic_sha256,
    )
    if _PUBLICATION_CAPABILITY_CONSUMED:
        raise HofsV12QualificationServiceError(
            "root publication approval capability was already consumed"
        )
    _PUBLICATION_CAPABILITY_CONSUMED = True
    outputs = (root / "outputs").resolve(strict=True)
    final = (root / SPENT_EVIDENCE_OUTPUT_ROOT).resolve()
    staging = (root / SPENT_EVIDENCE_STAGING_ROOT).resolve()
    if final.parent != outputs or staging.parent != outputs:
        raise HofsV12QualificationServiceError("fixed evidence identity escaped outputs")
    if final.exists() or staging.exists():
        raise HofsV12QualificationServiceError("fixed final or staging identity is consumed")
    files = {
        "RESOURCE_PREFLIGHT_RECEIPT.json": canonical_json_bytes(resource),
        "SPENT_EQUIVALENCE_RECEIPT.json": canonical_json_bytes(spent),
        "SOURCE_RECORDS.json": canonical_json_bytes(source_records),
    }
    manifest = {
        "schema_version": "expected_pe.hofs_v12.resource_resolution_evidence.v1",
        "status": "PASS_EXCLUSIVE_SPENT_RESOURCE_EVIDENCE",
        "resource_resolution_lock_raw_sha256": RESOURCE_RESOLUTION_LOCK_RAW_SHA256,
        "resource_receipt_raw_sha256": resource["receipt_raw_sha256"],
        "spent_receipt_raw_sha256": spent["receipt_raw_sha256"],
        "source_record_count": len(source_records),
        "source_records_semantic_sha256": source_semantic_sha256,
        "publication_authority_source": _APPROVAL_STATUS,
        "publication_approval_relative": _APPROVAL_RELATIVE,
        "publication_approval_raw_sha256": (
            approval_capability.approval_record_raw_sha256
        ),
        "publication_approval_volume_serial_number": (
            approval_capability.approval_record_volume_serial_number
        ),
        "publication_approval_file_id_128": (
            approval_capability.approval_record_file_id_128
        ),
        "publication_approval_nonce_sha256": approval["approval_nonce_sha256"],
        "qualification_access_count": 0,
        "fresh_access_count": 0,
        "truth_access_count": 0,
        "heldout_access_count": 0,
        "score_access_count": 0,
    }
    files["MANIFEST.json"] = canonical_json_bytes(manifest)
    ledger = b"".join(
        f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in sorted(files)
    )
    staging.mkdir(exist_ok=False)
    try:
        for name in sorted(files):
            _write_new(staging / name, files[name])
        _write_new(staging / "CHECKSUMS.sha256", ledger)
        expected = set(files) | {"CHECKSUMS.sha256"}
        observed = {path.name for path in staging.iterdir() if path.is_file()}
        if observed != expected or any(path.is_dir() for path in staging.iterdir()):
            raise HofsV12QualificationServiceError("staged evidence universe drifted")
        os.rename(staging, final)
    except Exception:
        # Preserve consumed staging as forensic evidence; never retry or overwrite.
        raise
    return {
        "status": "PASS_EXCLUSIVE_SPENT_RESOURCE_EVIDENCE_PUBLICATION",
        "output_relative": SPENT_EVIDENCE_OUTPUT_ROOT,
        "file_count": len(files) + 1,
        "checksums_raw_sha256": hashlib.sha256(ledger).hexdigest(),
    }


def _publish_spent_evidence_from_fixed_root_approval_record(
    *,
    resource_receipt: Mapping[str, Any],
    spent_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Private root launcher; mint only from the fixed approval record's held identity."""

    root = _project_root().resolve(strict=True)
    capability, _ = _capture_approval_record(root)
    return _publish_spent_evidence_with_root_approval(
        resource_receipt=resource_receipt,
        spent_receipt=spent_receipt,
        approval_capability=capability,
    )


__all__ = ["validate_spent_evidence_receipts"]
