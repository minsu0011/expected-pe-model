"""Independent, stdlib-only R3 heldout post-generation audit.

The auditor is deliberately outside the frozen producer/evaluator package.  It
derives every heldout seed and task identity from a caller-pinned execution
authority; no future heldout seed is embedded in this source.  The only file it
opens below the protected vault root is the explicitly supplied
``VAULT_MANIFEST.json``.  Truth references are checked lexically and are never
resolved, stat'ed, or opened.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


DGPS = tuple("ABCDEFGHIJ")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FILE_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
PUBLIC_FRAME_KEYS = {
    "benchmark",
    "corporate_actions",
    "eps_events",
    "price",
    "public_factors",
}
PUBLIC_FILE_UNIVERSE = {
    "PUBLIC_REPLAY_RECEIPT.json",
    "PUBLIC_TASK_MANIFEST.json",
    "canonical150.csv",
    "v04_overlay.csv",
}
MAX_PATH_CHARS = 239
REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
REPORT_NAME = "R3_POST_GENERATION_AUDIT.json"
ARTIFACT_REF_FIELDS = {
    "file_id_128",
    "raw_sha256",
    "relative_path",
    "size_bytes",
    "volume_serial_number",
}
EXECUTION_AUTHORITY_FIELDS = {
    "schema_version",
    "status",
    "run_id",
    "survivor_freeze",
    "qualification_survivor_freeze_semantic_sha256",
    "generation_plan",
    "generation_plan_semantic_sha256",
    "formula_lock_semantic_sha256",
    "source_manifest",
    "source_manifest_semantic_sha256",
    "source_records_semantic_sha256",
    "runtime_semantic_sha256",
    "r2_protocol_lock_relative_path",
    "r2_protocol_lock_raw_sha256",
    "r2_protocol_binding_semantic_sha256",
    "r2_protocol_lock",
    "source_frozen_before_generation",
    "candidate_tuning_allowed",
    "truth_open_count",
    "heldout_content_open_count",
    "score_open_count",
    "retry_allowed",
    "execution_authority_semantic_sha256",
}
GENERATION_PLAN_FIELDS = {
    "schema_version",
    "status",
    "qualification_result_raw_sha256",
    "heldout_seeds_in_order",
    "heldout_seed_aliases_in_order",
    "estimator_rng_seeds_in_order",
    "estimator_rng_aliases_in_order",
    "estimator_rng_is_mechanical_heldout_data_seed",
    "fold_rng_formula",
    "estimator_rng_is_feature_router_weight_or_formula_parameter",
    "dgp_ids_in_order",
    "task_order",
    "task_count",
    "source_rows_per_task",
    "identity_count",
    "prediction_row_count",
    "tasks",
    "protected_generator",
    "public_replay",
    "public_predictor",
    "c4_numeric_lineage_is_seed_free",
    "prediction_must_be_frozen_before_truth",
    "truth_open_count",
    "heldout_content_open_count_at_authority",
    "adapter_source_bindings",
    "c2_c3_frozen_numeric_source_records",
    "c4_source_model_version",
    "c4_source_tree_relatives",
    "c4_source_file_relatives",
    "c4_runtime_must_recompute_full_source_closure",
    "plan_semantic_sha256",
}
TASK_FIELDS = {
    "data_seed",
    "dgp_id",
    "estimator_rng_alias",
    "estimator_rng_seed",
    "seed_alias",
    "task_ordinal",
}
SURVIVOR_FIELDS = {
    "schema_version",
    "status",
    "qualification_result_ref",
    "qualification_result_raw_sha256",
    "qualification_result_schema_version",
    "qualification_result_status",
    "qualification_run_id",
    "champion_id",
    "survivor_ids_in_qualification_rank_order",
    "model_ids_in_order",
    "research_only_ids_excluded",
    "excluded_c1_prediction_row_count",
    "source_model_versions",
    "formula_lock",
    "heldout_seeds_in_order",
    "estimator_rng_seeds_in_order",
    "estimator_rng_is_bound_generation_seed",
    "estimator_rng_is_feature_router_weight_or_formula_parameter",
    "dgp_ids_in_order",
    "task_count",
    "identity_count",
    "prediction_row_count",
    "candidate_tuning_allowed",
    "prediction_before_truth",
    "truth_open_count",
    "heldout_content_open_count",
    "score_open_count",
    "survivor_freeze_semantic_sha256",
}
SOURCE_MANIFEST_FIELDS = {
    "schema_version",
    "status",
    "qualification_result_raw_sha256",
    "public_replay_design_lock_raw_sha256",
    "adapter_source_records",
    "c2_c3_frozen_numeric_source_records",
    "c4_source_model_version",
    "c4_source_tree_records",
    "c4_source_file_records",
    "runtime_versions",
    "runtime_semantic_sha256",
    "source_record_count",
    "source_records_semantic_sha256",
    "source_manifest_semantic_sha256",
}
SOURCE_RECORD_FIELDS = {"relative_path", "raw_sha256", "size_bytes"}
RUNTIME_VERSION_FIELDS = {
    "python_implementation",
    "python_version",
    "joblib",
    "lightgbm",
    "numpy",
    "pandas",
    "scikit-learn",
    "scipy",
    "statsmodels",
    "threadpoolctl",
}
ADAPTER_SOURCE_BINDING_FIELDS = {
    "research/model_zoo/dgp_exploration_v2/contracts.py",
    "research/model_zoo/dgp_exploration_v2/generator.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1/public_role.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1/replay.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v1/prediction.py",
    "research/model_zoo/observable_fair_value_state_v1_ablation/contracts.py",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/contracts.py",
    "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/prediction.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/service.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v2/service.py",
}
PROTOCOL_LOCK_FIELDS = {
    "schema_version",
    "status",
    "run_id",
    "r2_protocol_binding",
    "r2_protocol_binding_semantic_sha256",
    "policy_lock_sha256",
}
PROTOCOL_BINDING_FIELDS = {
    "r1_terminal_failure",
    "replacement_seed_precommit",
    "final_nonreserved_preflight",
    "quarantine_seeds_never_generate_or_score",
    "heldout_seeds_in_order",
    "heldout_seed_commitment_sha256",
    "reservation_contract",
    "spent_seed_reservation",
    "registry_transition",
    "overlap_audit",
    "candidate_performance_consulted",
    "heldout_truth_consulted",
    "retry_allowed",
    "additional_recovery_reservation_allowed",
    "candidate_tuning_allowed",
    "truth_open_count_at_lock",
    "score_open_count_at_lock",
    "heldout_content_open_count_at_lock",
}
PROTOCOL_REF_FIELDS = {"relative_path", "raw_sha256"}
PREFLIGHT_FIELDS = {
    "relative_path",
    "raw_sha256",
    "status",
    "reserved_generator_invocation_count",
    "truth_leakage_count",
    "heldout_access_count",
    "score_open_count",
    "registry_mutation_count",
}
RESERVATION_CONTRACT_FIELDS = {
    "format_version",
    "registry_id",
    "owner_output_root",
    "source_config_sha256",
    "candidates_sha256",
    "policy_config_sha256",
    "tuning_seeds",
    "locked_seeds",
    "reserved_seeds",
}
RESERVATION_RECEIPT_FIELDS = {
    "format_version",
    "registry_id",
    "registry_path",
    "genesis_sha256",
    "reservation_id",
    "reservation_sequence",
    "reservation_entry_sha256",
}
REGISTRY_TRANSITION_FIELDS = {
    "registry_relative_path",
    "registry_before_raw_sha256",
    "registry_after_raw_sha256",
    "entry_count_before",
    "entry_count_after",
    "append_count",
    "previous_entry_sha256",
    "reservation_entry_sha256",
    "reservation_created_at_utc",
}
OVERLAP_FIELDS = {
    "prior_spent_overlap_count",
    "r1_heldout_overlap_count",
    "qualification_seed_overlap_count",
    "within_allocation_duplicate_count",
}
GENERATION_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "run_id",
    "execution_authority_semantic_sha256",
    "source_frozen_before_generation",
    "task_count",
    "outer_workers",
    "inner_blas_threads",
    "cpu_affinity",
    "gpu_enabled",
    "protected_public_process_separation",
    "anonymous_one_way_pipe_used",
    "public_pass_1_pass_2_byte_exact",
    "public_task_receipts",
    "truth_ref_inventory_received_by_public_process",
    "truth_open_count_by_controller",
    "truth_open_count_by_public_process",
    "score_open_count",
}
PUBLIC_TASK_MANIFEST_FIELDS = {
    "schema_version",
    "status",
    "task",
    "public_replay_design_lock_raw_sha256",
    "canonical_ref",
    "overlay_ref",
    "public_frame_raw_sha256",
    "public_frame_rows",
    "public_frame_raw_hashes_equal",
    "public_frame_rows_equal",
    "canonical_replay_bytes_equal",
    "overlay_replay_bytes_equal",
    "protected_generator_imported",
    "truth_open_count",
    "score_open_count",
    "task_manifest_semantic_sha256",
}
PUBLIC_PASS_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "task_ordinal",
    "data_seed",
    "seed_alias",
    "dgp_id",
    "replay_pass",
    "rows",
    "protected_generator_imported",
    "protected_path_received",
    "protected_value_received",
    "truth_open_count",
    "score_open_count",
    "public_frame_raw_sha256",
    "public_frame_rows",
    "upstream_replay_receipt",
}
PUBLIC_REPLAY_RECEIPT_FIELDS = {
    *PUBLIC_PASS_RECEIPT_FIELDS,
    "public_frame_raw_hashes_equal",
    "public_frame_rows_equal",
    "canonical_replay_bytes_equal",
    "overlay_replay_bytes_equal",
    "pass_1_replay_receipt",
    "pass_2_replay_receipt",
    "public_replay_design_lock_raw_sha256",
    "canonical_ref",
    "overlay_ref",
    "task_manifest_ref",
    "task_manifest_semantic_sha256",
}
UPSTREAM_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "stage",
    "truth_namespace_accessed",
    "protected_path_received",
    "score_fit_prediction_evaluation",
    "public_inputs_used",
    "public_input_raw_sha256",
    "canonical150_raw_sha256",
    "canonical150_logical_sha256",
    "canonical150_header_semantic_sha256",
    "canonical150_header_raw_sha256",
    "canonical150_rows",
    "canonical150_columns",
    "v04_overlay_raw_sha256",
    "v04_overlay_logical_sha256",
    "v04_overlay_header_raw_sha256",
    "v04_overlay_rows",
    "v04_overlay_columns",
    "identity_sha256",
    "replay_inventory_combined_sha256",
    "normalized_invocations",
    "child_attestation",
}
CHILD_ATTESTATION_FIELDS = {
    "stage",
    "output_csv",
    "resource_probe",
    "runtime_before",
    "runtime_after",
    "threadpool_probe",
    "staged_project_tree_sha256_before",
    "staged_project_tree_sha256_after",
}
RESOURCE_PROBE_FIELDS = {
    "cpu_ids",
    "affinity_mask_hex",
    "environment",
    "all_five_thread_variables_one",
    "both_gpu_variables_sealed",
    "isolated_python",
}
BASE_NUMERIC_ENVIRONMENT_FIELDS = {
    "CUDA_VISIBLE_DEVICES",
    "MKL_NUM_THREADS",
    "NVIDIA_VISIBLE_DEVICES",
    "NUMEXPR_NUM_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
}
CHILD_RUNTIME_FIELDS = {
    "python_version",
    "python_executable",
    "python_executable_raw_sha256",
    "python_base_executable",
    "python_base_executable_raw_sha256",
    "distributions",
    "combined_sha256",
}
CHILD_RUNTIME_DISTRIBUTIONS = {
    "joblib",
    "lightgbm",
    "numpy",
    "pandas",
    "pyyaml",
    "scikit-learn",
    "scipy",
    "statsmodels",
    "threadpoolctl",
}
VAULT_MANIFEST_FIELDS = {
    "schema_version",
    "status",
    "vault_relative_path",
    "qualification_result_raw_sha256",
    "generation_plan_semantic_sha256",
    "truth_refs",
    "truth_ref_count",
    "protected_task_metadata_count",
    "task_order",
    "metadata_read_count",
    "pass_1_pass_2_protected_hashes_equal",
    "pass_1_pass_2_public_hashes_equal",
    "truth_content_open_count",
    "truth_attribute_open_count_by_manifest_builder",
    "truth_attribute_open_count_at_protected_write_time",
    "pass_2_truth_ref_export_count",
    "latent_ref_export_count",
    "truth_refs_origin",
    "outer_truth_content_open_count",
    "evaluator_pre_marker_truth_content_open_count",
    "vault_manifest_semantic_sha256",
}


class AuditFailure(RuntimeError):
    def __init__(self, severity: str, code: str, message: str) -> None:
        super().__init__(message)
        self.severity = severity
        self.code = code
        self.safe_message = message


class State:
    def __init__(self) -> None:
        self.check_count = 0
        self.max_path_chars = 0
        self.public_file_identities: set[tuple[int, int]] = set()
        self.task_evidence: list[dict[str, Any]] = []

    def require(
        self,
        condition: bool,
        code: str,
        message: str,
        severity: str = "P0",
    ) -> None:
        if not condition:
            raise AuditFailure(severity, code, message)
        self.check_count += 1


def require_exact_keys(
    value: Any,
    expected: set[str],
    *,
    code: str,
    label: str,
    state: State,
) -> dict[str, Any]:
    state.require(
        type(value) is dict and set(value) == expected,
        code,
        f"{label} key universe differs",
        "P1",
    )
    return value


def compact_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def compact_file_bytes(value: Any) -> bytes:
    return compact_bytes(value) + b"\n"


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def semantic_sha256(value: Any) -> str:
    return sha256(compact_bytes(value))


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def parse_json(raw: bytes, *, pretty: bool, state: State) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8" if pretty else "ascii"),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditFailure("P1", "JSON_PARSE", "JSON bytes are invalid") from exc
    state.require(
        type(value) is dict,
        "JSON_ROOT",
        "JSON root is not an object",
        "P1",
    )
    canonical = pretty_bytes(value) if pretty else compact_file_bytes(value)
    state.require(
        raw == canonical,
        "JSON_CANONICAL",
        "JSON canonical bytes differ",
        "P1",
    )
    return value


def _is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0) & REPARSE_FLAG
    )


def check_path(path: Path, *, state: State, kind: str) -> os.stat_result:
    absolute = Path(os.path.abspath(path))
    state.max_path_chars = max(state.max_path_chars, len(str(absolute)))
    state.require(
        len(str(absolute)) <= MAX_PATH_CHARS,
        "PATH_LENGTH",
        "audited path is 240 characters or longer",
        "P1",
    )
    try:
        state.require(
            not _is_reparse(absolute),
            "REPARSE_POINT",
            "reparse point detected",
        )
        info = os.lstat(absolute)
    except OSError as exc:
        raise AuditFailure(
            "P1", "PATH_STAT", "required audit path is unavailable"
        ) from exc
    expected = stat.S_ISREG(info.st_mode) if kind == "file" else stat.S_ISDIR(
        info.st_mode
    )
    state.require(expected, "PATH_TYPE", f"expected {kind}", "P1")
    return info


def stable_read(path: Path, *, state: State) -> tuple[bytes, os.stat_result]:
    before = check_path(path, state=state, kind="file")
    raw = path.read_bytes()
    after = os.lstat(path)
    state.require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        "FILE_MUTATION",
        "file changed during audit read",
    )
    state.require(
        len(raw) == after.st_size,
        "FILE_SIZE",
        "file read size differs",
        "P1",
    )
    return raw, after


def inventory(
    path: Path,
    expected: set[str],
    *,
    state: State,
) -> dict[str, os.DirEntry[str]]:
    check_path(path, state=state, kind="dir")
    entries = {entry.name: entry for entry in os.scandir(path)}
    state.require(set(entries) == expected, "FILE_UNIVERSE", "file universe differs")
    state.require(
        len({name.casefold() for name in entries}) == len(entries),
        "CASE_COLLISION",
        "case-folded path collision detected",
    )
    for name, entry in entries.items():
        kind = "file" if "." in name else "dir"
        check_path(Path(entry.path), state=state, kind=kind)
    return entries


def _hex_sha(value: Any) -> bool:
    return type(value) is str and SHA256_RE.fullmatch(value) is not None


def _project_path(value: Path, project: Path) -> Path:
    candidate = value if value.is_absolute() else project / value
    return Path(os.path.abspath(candidate))


def _relative(path: Path, project: Path, *, state: State, code: str) -> str:
    try:
        relative = path.relative_to(project)
    except ValueError as exc:
        raise AuditFailure("P1", code, "artifact path is outside project") from exc
    state.require(
        ".." not in relative.parts,
        code,
        "artifact path escapes project",
        "P1",
    )
    return relative.as_posix()


def validate_r3_run_paths(
    *,
    run_id: str,
    authority_relative: str,
    public_relative: str,
    vault_relative: str,
    vault_manifest_leaf: str,
    state: State,
) -> None:
    state.require(
        type(run_id) is str
        and run_id.startswith("r3_")
        and len(run_id) <= 96
        and all(
            character.isascii()
            and (character.isalnum() or character in "_-")
            for character in run_id
        ),
        "R3_RUN_ID",
        "run id is not an exact safe R3 identity",
        "P1",
    )
    state.require(
        authority_relative
        == f"build/pe_four_model_heldout_execution_authority_{run_id}.json"
        and public_relative
        == f"outputs/model_zoo_pe_four_model_heldout_public_replay_{run_id}"
        and vault_relative
        == f"outputs/.model_zoo_pe_four_model_heldout_vault_{run_id}"
        and vault_manifest_leaf == "VAULT_MANIFEST.json",
        "R3_PATH_BINDING",
        "R3 authority/public/vault run-specific paths differ",
        "P1",
    )


def _register_public(info: os.stat_result, *, state: State) -> None:
    identity = (info.st_dev, info.st_ino)
    state.require(
        identity not in state.public_file_identities,
        "PUBLIC_HARDLINK",
        "public file identity alias detected",
    )
    state.public_file_identities.add(identity)


def validate_ref(
    ref: Any,
    *,
    expected_relative_path: str,
    raw: bytes,
    info: os.stat_result,
    state: State,
) -> None:
    state.require(
        type(ref) is dict and set(ref) == ARTIFACT_REF_FIELDS,
        "ARTIFACT_REF_SCHEMA",
        "public ArtifactRef schema differs",
        "P1",
    )
    state.require(
        ref["relative_path"] == expected_relative_path,
        "ARTIFACT_PATH",
        "public ArtifactRef path differs",
    )
    state.require(
        _hex_sha(ref["raw_sha256"]),
        "ARTIFACT_SHA_FORMAT",
        "public ArtifactRef hash malformed",
        "P1",
    )
    state.require(
        ref["raw_sha256"] == sha256(raw),
        "ARTIFACT_SHA",
        "public ArtifactRef hash differs",
    )
    state.require(
        ref["size_bytes"] == len(raw),
        "ARTIFACT_SIZE",
        "public ArtifactRef size differs",
        "P1",
    )
    state.require(
        type(ref["volume_serial_number"]) is int
        and ref["volume_serial_number"] == info.st_dev,
        "ARTIFACT_VOLUME",
        "public ArtifactRef volume identity differs",
    )
    file_id = ref["file_id_128"]
    state.require(
        type(file_id) is str and FILE_ID_RE.fullmatch(file_id) is not None,
        "ARTIFACT_FILE_ID_FORMAT",
        "public ArtifactRef FileId malformed",
        "P1",
    )
    state.require(
        int.from_bytes(bytes.fromhex(file_id), "little") == info.st_ino,
        "ARTIFACT_FILE_ID",
        "public ArtifactRef FileId differs",
    )
    _register_public(info, state=state)


def csv_geometry(
    raw: bytes,
    *,
    columns: int,
    state: State,
) -> tuple[str, tuple[str, ...]]:
    state.require(
        raw.endswith(b"\n"),
        "CSV_FINAL_NEWLINE",
        "CSV final newline differs",
        "P1",
    )
    state.require(
        raw.count(b"\n") == 1801,
        "CSV_LINE_COUNT",
        "CSV line count differs",
        "P1",
    )
    try:
        reader = csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
        header = next(reader)
        dates: list[str] = []
        for row in reader:
            if len(row) != columns or DATE_RE.fullmatch(row[0]) is None:
                raise ValueError("row geometry")
            dates.append(row[0])
    except (UnicodeDecodeError, csv.Error, StopIteration, ValueError) as exc:
        raise AuditFailure(
            "P1",
            "CSV_GEOMETRY",
            "CSV header, row width, or identity differs",
        ) from exc
    state.require(
        len(header) == columns and header[0] == "date",
        "CSV_HEADER",
        "CSV header differs",
        "P1",
    )
    state.require(
        len(dates) == 1800 and dates == sorted(set(dates)),
        "CSV_IDENTITY",
        "CSV date identity differs",
    )
    first_line = raw.split(b"\n", 1)[0].rstrip(b"\r")
    return sha256(first_line), tuple(dates)


def scan_public_protection(value: Any, *, state: State) -> None:
    false_flags = {
        "protected_generator_imported",
        "protected_path_received",
        "protected_value_received",
        "score_fit_prediction_evaluation",
        "truth_namespace_accessed",
        "truth_ref_inventory_received_by_public_process",
    }
    zero_counts = {
        "heldout_content_open_count",
        "score_open_count",
        "truth_content_open_count",
        "truth_open_count",
        "truth_open_count_by_controller",
        "truth_open_count_by_public_process",
    }
    forbidden_tokens = (
        "_vault_",
        "/truth.csv",
        "\\truth.csv",
        "latent_events.csv",
    )

    def walk(node: Any) -> None:
        if type(node) is dict:
            for key, child in node.items():
                if key in false_flags:
                    state.require(
                        child is False,
                        "PROTECTED_FLAG",
                        "public protected-access flag is not false",
                    )
                if key in zero_counts:
                    state.require(
                        type(child) is int and child == 0,
                        "ACCESS_COUNT",
                        "public access count is not zero",
                    )
                walk(child)
        elif type(node) is list:
            for child in node:
                walk(child)
        elif type(node) is str:
            lowered = node.casefold()
            state.require(
                not any(token in lowered for token in forbidden_tokens),
                "PROTECTED_VALUE",
                "protected path/value appeared in public JSON",
            )

    walk(value)


def expected_geometry(dgp: str) -> dict[str, int]:
    return {
        "benchmark": 1800,
        "corporate_actions": 0,
        "eps_events": 29,
        "price": 1800,
        "public_factors": 1800 if dgp == "I" else 3600,
    }


def _require_source_records(value: Any, *, label: str, state: State) -> list[Any]:
    state.require(type(value) is list, "SOURCE_RECORD_LIST", f"{label} is not a list", "P1")
    for record in value:
        require_exact_keys(
            record,
            SOURCE_RECORD_FIELDS,
            code="SOURCE_RECORD_KEY_UNIVERSE",
            label=f"{label} record",
            state=state,
        )
    return value


def _validate_protocol_shape(protocol: Any, *, state: State) -> None:
    lock = require_exact_keys(
        protocol,
        PROTOCOL_LOCK_FIELDS,
        code="PROTOCOL_KEY_UNIVERSE",
        label="legacy-wire protocol lock",
        state=state,
    )
    binding = require_exact_keys(
        lock["r2_protocol_binding"],
        PROTOCOL_BINDING_FIELDS,
        code="PROTOCOL_BINDING_KEY_UNIVERSE",
        label="legacy-wire protocol binding",
        state=state,
    )
    for field in ("r1_terminal_failure", "replacement_seed_precommit"):
        require_exact_keys(
            binding[field],
            PROTOCOL_REF_FIELDS,
            code="PROTOCOL_REF_KEY_UNIVERSE",
            label=f"protocol {field}",
            state=state,
        )
    require_exact_keys(
        binding["final_nonreserved_preflight"],
        PREFLIGHT_FIELDS,
        code="PREFLIGHT_KEY_UNIVERSE",
        label="protocol preflight",
        state=state,
    )
    require_exact_keys(
        binding["reservation_contract"],
        RESERVATION_CONTRACT_FIELDS,
        code="RESERVATION_CONTRACT_KEY_UNIVERSE",
        label="reservation contract",
        state=state,
    )
    require_exact_keys(
        binding["spent_seed_reservation"],
        RESERVATION_RECEIPT_FIELDS,
        code="RESERVATION_RECEIPT_KEY_UNIVERSE",
        label="reservation receipt",
        state=state,
    )
    require_exact_keys(
        binding["registry_transition"],
        REGISTRY_TRANSITION_FIELDS,
        code="REGISTRY_TRANSITION_KEY_UNIVERSE",
        label="registry transition",
        state=state,
    )
    require_exact_keys(
        binding["overlap_audit"],
        OVERLAP_FIELDS,
        code="OVERLAP_KEY_UNIVERSE",
        label="seed overlap audit",
        state=state,
    )
    binding_unsigned = dict(binding)
    state.require(
        lock["r2_protocol_binding_semantic_sha256"]
        == semantic_sha256(binding_unsigned),
        "PROTOCOL_BINDING_SEAL",
        "legacy-wire protocol binding semantic seal differs",
    )


def _validate_generation_plan_shape(plan: Any, *, state: State) -> None:
    value = require_exact_keys(
        plan,
        GENERATION_PLAN_FIELDS,
        code="AUTHORITY_PLAN_KEY_UNIVERSE",
        label="authority generation plan",
        state=state,
    )
    tasks = value["tasks"]
    state.require(type(tasks) is list, "AUTHORITY_TASK_LIST", "authority tasks are not a list", "P1")
    for task in tasks:
        require_exact_keys(
            task,
            TASK_FIELDS,
            code="AUTHORITY_TASK_KEY_UNIVERSE",
            label="authority task",
            state=state,
        )
    expected_capabilities = {
        "protected_generator": {
            "imports_generator": True,
            "may_write_truth_and_latent_to_private_vault": True,
            "may_emit_public_frames_one_way": True,
            "may_fit_or_predict": False,
            "may_score": False,
        },
        "public_replay": {
            "imports_generator": False,
            "accepts_public_frames_only": True,
            "may_open_private_vault": False,
            "may_fit_or_predict": False,
            "may_score": False,
        },
        "public_predictor": {
            "imports_generator": False,
            "accepts_public_replay_only": True,
            "uses_bound_generation_seed_as_constituent_rng_only": True,
            "may_open_private_vault": False,
            "may_open_truth_or_latent": False,
            "may_score": False,
        },
    }
    for field, expected in expected_capabilities.items():
        state.require(
            type(value[field]) is dict
            and set(value[field]) == set(expected)
            and value[field] == expected,
            "AUTHORITY_CAPABILITY_KEY_UNIVERSE",
            f"authority {field} capability differs",
        )
    bindings = require_exact_keys(
        value["adapter_source_bindings"],
        ADAPTER_SOURCE_BINDING_FIELDS,
        code="ADAPTER_BINDING_KEY_UNIVERSE",
        label="authority adapter source bindings",
        state=state,
    )
    state.require(
        all(_hex_sha(digest) for digest in bindings.values()),
        "ADAPTER_BINDING_HASH",
        "authority adapter source hash differs",
        "P1",
    )
    _require_source_records(
        value["c2_c3_frozen_numeric_source_records"],
        label="authority C2/C3 source",
        state=state,
    )


def _validate_survivor_shape(survivor: Any, *, state: State) -> dict[str, Any]:
    value = require_exact_keys(
        survivor,
        SURVIVOR_FIELDS,
        code="SURVIVOR_KEY_UNIVERSE",
        label="survivor freeze",
        state=state,
    )
    require_exact_keys(
        value["qualification_result_ref"],
        ARTIFACT_REF_FIELDS,
        code="SURVIVOR_REF_KEY_UNIVERSE",
        label="survivor qualification ref",
        state=state,
    )
    versions = value["source_model_versions"]
    state.require(
        type(versions) is list and len(versions) == 4,
        "SURVIVOR_VERSION_LIST",
        "survivor source-model versions differ",
        "P1",
    )
    for version in versions:
        require_exact_keys(
            version,
            {"model_id", "source_model_version"},
            code="SURVIVOR_VERSION_KEY_UNIVERSE",
            label="survivor source-model version",
            state=state,
        )
    formula = require_exact_keys(
        value["formula_lock"],
        {
            "bce_v1_d_observable_state_confidence_shrinkage",
            "bce_tournament_v1_fixed_alpha_040_directional_consensus",
            "hofs_v4_expected_pe",
        },
        code="FORMULA_LOCK_KEY_UNIVERSE",
        label="survivor formula lock",
        state=state,
    )
    formula_fields = {
        "bce_v1_d_observable_state_confidence_shrinkage": {
            "direction_epsilon",
            "alpha",
            "log_formula",
        },
        "bce_tournament_v1_fixed_alpha_040_directional_consensus": {
            "direction_epsilon",
            "fixed_alpha",
            "log_formula",
        },
        "hofs_v4_expected_pe": {
            "global_log_shrink",
            "log_formula",
            "numeric_lineage_is_seed_free",
        },
    }
    for model_id, fields in formula_fields.items():
        require_exact_keys(
            formula[model_id],
            fields,
            code="FORMULA_ENTRY_KEY_UNIVERSE",
            label=f"formula lock {model_id}",
            state=state,
        )
    unsigned = dict(value)
    seal = unsigned.pop("survivor_freeze_semantic_sha256")
    state.require(
        _hex_sha(seal) and seal == semantic_sha256(unsigned),
        "SURVIVOR_SELF_SEAL",
        "survivor freeze semantic seal differs",
    )
    return value


def _validate_source_manifest_shape(source: Any, *, state: State) -> dict[str, Any]:
    value = require_exact_keys(
        source,
        SOURCE_MANIFEST_FIELDS,
        code="SOURCE_MANIFEST_KEY_UNIVERSE",
        label="authority source manifest",
        state=state,
    )
    record_fields = (
        "adapter_source_records",
        "c2_c3_frozen_numeric_source_records",
        "c4_source_tree_records",
        "c4_source_file_records",
    )
    groups = [
        _require_source_records(value[field], label=field, state=state)
        for field in record_fields
    ]
    flattened = [record for group in groups for record in group]
    state.require(
        tuple(len(group) for group in groups) == (74, 26, 34, 3)
        and len(flattened) == 137,
        "SOURCE_MANIFEST_GEOMETRY",
        "authority source manifest group geometry differs",
    )
    runtime = require_exact_keys(
        value["runtime_versions"],
        RUNTIME_VERSION_FIELDS,
        code="SOURCE_RUNTIME_KEY_UNIVERSE",
        label="authority runtime versions",
        state=state,
    )
    state.require(
        value["source_record_count"] == len(flattened)
        and value["source_records_semantic_sha256"]
        == semantic_sha256(flattened)
        and value["runtime_semantic_sha256"] == semantic_sha256(runtime),
        "SOURCE_MANIFEST_BINDING",
        "authority source manifest record/runtime binding differs",
    )
    unsigned = dict(value)
    seal = unsigned.pop("source_manifest_semantic_sha256")
    state.require(
        _hex_sha(seal) and seal == semantic_sha256(unsigned),
        "SOURCE_MANIFEST_SELF_SEAL",
        "authority source manifest semantic seal differs",
    )
    return value


def validate_authority(
    path: Path,
    *,
    run_id: str,
    expected_semantic_sha256: str,
    expected_raw_sha256: str,
    state: State,
) -> tuple[dict[str, Any], bytes, list[dict[str, Any]]]:
    state.require(
        _hex_sha(expected_semantic_sha256),
        "AUTHORITY_EXPECTED_SEMANTIC_FORMAT",
        "expected authority semantic hash is malformed",
        "P1",
    )
    state.require(
        _hex_sha(expected_raw_sha256),
        "AUTHORITY_EXPECTED_RAW_FORMAT",
        "expected authority raw hash is malformed",
        "P1",
    )
    raw, _ = stable_read(path, state=state)
    state.require(
        sha256(raw) == expected_raw_sha256,
        "AUTHORITY_RAW_SHA",
        "execution-authority raw hash differs",
    )
    authority = parse_json(raw, pretty=True, state=state)
    require_exact_keys(
        authority,
        EXECUTION_AUTHORITY_FIELDS,
        code="AUTHORITY_KEY_UNIVERSE",
        label="execution authority",
        state=state,
    )
    unsigned = dict(authority)
    seal = unsigned.pop("execution_authority_semantic_sha256", None)
    state.require(
        seal == expected_semantic_sha256 == semantic_sha256(unsigned),
        "AUTHORITY_SELF_SEAL",
        "execution-authority semantic seal differs",
    )
    exact = {
        "schema_version": "expected_pe.four_model.heldout_execution_authority.v1",
        "status": "FROZEN_PRETRUTH_SOURCE_PLAN_AND_SURVIVOR_AUTHORITY",
        "run_id": run_id,
        "source_frozen_before_generation": True,
        "candidate_tuning_allowed": False,
        "retry_allowed": False,
        "heldout_content_open_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
    }
    for key, expected in exact.items():
        state.require(
            authority.get(key) == expected,
            "AUTHORITY_EXACT",
            "execution-authority contract differs",
        )
    plan = authority.get("generation_plan")
    _validate_generation_plan_shape(plan, state=state)
    plan_unsigned = dict(plan)
    plan_seal = plan_unsigned.pop("plan_semantic_sha256", None)
    state.require(
        _hex_sha(plan_seal)
        and plan_seal == semantic_sha256(plan_unsigned)
        and authority.get("generation_plan_semantic_sha256") == plan_seal,
        "AUTHORITY_PLAN_SEAL",
        "generation-plan semantic seal differs",
    )
    aliases = plan.get("heldout_seed_aliases_in_order")
    seeds = plan.get("heldout_seeds_in_order")
    rng_aliases = plan.get("estimator_rng_aliases_in_order")
    rng_seeds = plan.get("estimator_rng_seeds_in_order")
    state.require(
        type(aliases) is list
        and aliases
        == [f"heldout_seed_{index:02d}" for index in range(1, 6)],
        "AUTHORITY_ALIAS_ORDER",
        "authority seed-alias order differs",
    )
    state.require(
        type(seeds) is list
        and len(seeds) == 5
        and all(type(value) is int and value >= 0 for value in seeds)
        and len(set(seeds)) == 5,
        "AUTHORITY_SEED_ORDER",
        "authority seed order differs",
    )
    state.require(
        rng_aliases == aliases and rng_seeds == seeds,
        "AUTHORITY_RNG_BINDING",
        "authority RNG binding differs",
    )
    state.require(
        plan.get("dgp_ids_in_order") == list(DGPS)
        and plan.get("task_count") == 50
        and plan.get("task_order")
        == "heldout_data_seed_major_then_dgp_A_to_J",
        "AUTHORITY_TASK_CONTRACT",
        "authority task contract differs",
    )
    expected_tasks = [
        {
            "data_seed": seed,
            "dgp_id": dgp,
            "estimator_rng_alias": alias,
            "estimator_rng_seed": seed,
            "seed_alias": alias,
            "task_ordinal": seed_index * 10 + dgp_index,
        }
        for seed_index, (alias, seed) in enumerate(zip(aliases, seeds, strict=True))
        for dgp_index, dgp in enumerate(DGPS)
    ]
    state.require(
        plan.get("tasks") == expected_tasks,
        "AUTHORITY_TASK_ORDER",
        "authority task identities/order differ",
    )
    state.require(
        plan.get("identity_count") == 64800
        and plan.get("prediction_row_count") == 259200
        and plan.get("source_rows_per_task") == 1800,
        "AUTHORITY_GEOMETRY",
        "authority prediction geometry differs",
    )
    state.require(
        plan.get("truth_open_count") == 0
        and plan.get("heldout_content_open_count_at_authority") == 0
        and plan.get("prediction_must_be_frozen_before_truth") is True,
        "AUTHORITY_PRETRUTH",
        "authority pretruth contract differs",
    )
    survivor = _validate_survivor_shape(authority.get("survivor_freeze"), state=state)
    state.require(
        type(survivor) is dict
        and survivor.get("heldout_seeds_in_order") == seeds
        and survivor.get("estimator_rng_seeds_in_order") == seeds,
        "AUTHORITY_SURVIVOR_SEEDS",
        "survivor freeze seed binding differs",
    )
    source_manifest = _validate_source_manifest_shape(
        authority.get("source_manifest"), state=state
    )
    state.require(
        type(source_manifest) is dict
        and _hex_sha(source_manifest.get("public_replay_design_lock_raw_sha256")),
        "AUTHORITY_DESIGN_LOCK",
        "authority public replay design lock is missing",
    )
    state.require(
        _hex_sha(plan.get("qualification_result_raw_sha256")),
        "AUTHORITY_QUALIFICATION_LOCK",
        "authority qualification-result lock is missing",
    )
    protocol = authority.get("r2_protocol_lock")
    _validate_protocol_shape(protocol, state=state)
    state.require(
        protocol["run_id"] == run_id
        and protocol["r2_protocol_binding_semantic_sha256"]
        == authority["r2_protocol_binding_semantic_sha256"]
        and sha256(pretty_bytes(protocol))
        == authority["r2_protocol_lock_raw_sha256"]
        and authority["qualification_survivor_freeze_semantic_sha256"]
        == survivor["survivor_freeze_semantic_sha256"]
        and authority["formula_lock_semantic_sha256"]
        == semantic_sha256(survivor["formula_lock"])
        and authority["source_manifest_semantic_sha256"]
        == source_manifest["source_manifest_semantic_sha256"]
        and authority["source_records_semantic_sha256"]
        == source_manifest["source_records_semantic_sha256"]
        and authority["runtime_semantic_sha256"]
        == source_manifest["runtime_semantic_sha256"]
        and plan["qualification_result_raw_sha256"]
        == survivor["qualification_result_raw_sha256"]
        == source_manifest["qualification_result_raw_sha256"],
        "AUTHORITY_NESTED_BINDING",
        "execution-authority nested hash binding differs",
    )
    return authority, raw, expected_tasks


def validate_upstream(
    upstream: Any,
    *,
    canonical_sha: str,
    overlay_sha: str,
    canonical_header_sha: str,
    overlay_header_sha: str,
    state: State,
) -> None:
    value = require_exact_keys(
        upstream,
        UPSTREAM_RECEIPT_FIELDS,
        code="UPSTREAM_KEY_UNIVERSE",
        label="upstream replay receipt",
        state=state,
    )
    expected_scalars = {
        "schema_version": "expected_pe.r7.qualification.public_replay_receipt.v1",
        "status": "PASS_SCORE_FREE_PUBLIC_CANONICAL_OVERLAY_REPLAY",
        "stage": "QUALIFICATION",
        "canonical150_rows": 1800,
        "canonical150_columns": 150,
        "v04_overlay_rows": 1800,
        "v04_overlay_columns": 254,
        "canonical150_raw_sha256": canonical_sha,
        "v04_overlay_raw_sha256": overlay_sha,
        "canonical150_header_raw_sha256": canonical_header_sha,
        "v04_overlay_header_raw_sha256": overlay_header_sha,
        "protected_path_received": False,
        "truth_namespace_accessed": False,
        "score_fit_prediction_evaluation": False,
    }
    for key, expected in expected_scalars.items():
        state.require(
            value.get(key) == expected,
            "UPSTREAM_BINDING",
            "upstream replay binding differs",
        )
    state.require(
        value["public_inputs_used"] == ["benchmark", "eps_events", "price"],
        "UPSTREAM_PUBLIC_INPUT_ORDER",
        "upstream public input order differs",
    )
    public_hashes = require_exact_keys(
        value["public_input_raw_sha256"],
        {"benchmark", "eps_events", "price"},
        code="UPSTREAM_PUBLIC_HASH_KEY_UNIVERSE",
        label="upstream public input hashes",
        state=state,
    )
    state.require(
        all(_hex_sha(digest) for digest in public_hashes.values()),
        "UPSTREAM_PUBLIC_HASH",
        "upstream public input hash differs",
        "P1",
    )
    for key in (
        "canonical150_logical_sha256",
        "canonical150_header_semantic_sha256",
        "v04_overlay_logical_sha256",
        "identity_sha256",
        "replay_inventory_combined_sha256",
    ):
        state.require(
            _hex_sha(value[key]),
            "UPSTREAM_HASH_FORMAT",
            "upstream replay hash is malformed",
            "P1",
        )
    invocations = require_exact_keys(
        value["normalized_invocations"],
        {"v03", "v04"},
        code="UPSTREAM_INVOCATION_KEY_UNIVERSE",
        label="upstream normalized invocations",
        state=state,
    )
    for stage in ("v03", "v04"):
        command = invocations[stage]
        state.require(
            type(command) is list
            and len(command) == 10
            and all(type(token) is str for token in command)
            and command[1:4] == ["-I", "-B", "-X"]
            and command[6:] == ["--stage", stage, "--spec", f"$REPLAY_ROOT/{stage}_spec.json"],
            "UPSTREAM_INVOCATION_SHAPE",
            "upstream normalized invocation differs",
            "P1",
        )
    attestations = require_exact_keys(
        value["child_attestation"],
        {"v03", "v04"},
        code="UPSTREAM_ATTESTATION_KEY_UNIVERSE",
        label="upstream child attestations",
        state=state,
    )
    for stage in ("v03", "v04"):
        _validate_child_attestation(attestations[stage], stage=stage, state=state)


def _validate_child_runtime(value: Any, *, state: State) -> dict[str, Any]:
    runtime = require_exact_keys(
        value,
        CHILD_RUNTIME_FIELDS,
        code="CHILD_RUNTIME_KEY_UNIVERSE",
        label="upstream child runtime",
        state=state,
    )
    distributions = require_exact_keys(
        runtime["distributions"],
        CHILD_RUNTIME_DISTRIBUTIONS,
        code="CHILD_DISTRIBUTION_KEY_UNIVERSE",
        label="upstream child distributions",
        state=state,
    )
    for record in distributions.values():
        item = require_exact_keys(
            record,
            {"version", "record_raw_sha256"},
            code="CHILD_DISTRIBUTION_RECORD_KEY_UNIVERSE",
            label="upstream child distribution record",
            state=state,
        )
        state.require(
            type(item["version"]) is str
            and bool(item["version"])
            and _hex_sha(item["record_raw_sha256"]),
            "CHILD_DISTRIBUTION_RECORD",
            "upstream child distribution record differs",
            "P1",
        )
    state.require(
        type(runtime["python_version"]) is str
        and type(runtime["python_executable"]) is str
        and type(runtime["python_base_executable"]) is str
        and _hex_sha(runtime["python_executable_raw_sha256"])
        and _hex_sha(runtime["python_base_executable_raw_sha256"])
        and _hex_sha(runtime["combined_sha256"]),
        "CHILD_RUNTIME_VALUE",
        "upstream child runtime value differs",
        "P1",
    )
    return runtime


def _validate_child_attestation(value: Any, *, stage: str, state: State) -> None:
    attestation = require_exact_keys(
        value,
        CHILD_ATTESTATION_FIELDS,
        code="CHILD_ATTESTATION_KEY_UNIVERSE",
        label=f"upstream {stage} child attestation",
        state=state,
    )
    expected_environment = {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }
    resource = require_exact_keys(
        attestation["resource_probe"],
        RESOURCE_PROBE_FIELDS,
        code="CHILD_RESOURCE_KEY_UNIVERSE",
        label=f"upstream {stage} resource probe",
        state=state,
    )
    environment = require_exact_keys(
        resource["environment"],
        BASE_NUMERIC_ENVIRONMENT_FIELDS,
        code="CHILD_ENVIRONMENT_KEY_UNIVERSE",
        label=f"upstream {stage} child environment",
        state=state,
    )
    state.require(
        attestation["stage"] == stage
        and type(attestation["output_csv"]) is str
        and attestation["output_csv"].startswith("$REPLAY_ROOT/")
        and resource["cpu_ids"] == list(range(32))
        and resource["affinity_mask_hex"] == "0xFFFFFFFF"
        and environment == expected_environment
        and resource["all_five_thread_variables_one"] is True
        and resource["both_gpu_variables_sealed"] is True
        and resource["isolated_python"] is True,
        "CHILD_ATTESTATION_VALUE",
        "upstream child attestation value differs",
    )
    runtime_before = _validate_child_runtime(attestation["runtime_before"], state=state)
    runtime_after = _validate_child_runtime(attestation["runtime_after"], state=state)
    state.require(
        runtime_before == runtime_after,
        "CHILD_RUNTIME_MUTATION",
        "upstream child runtime changed",
    )
    probes = attestation["threadpool_probe"]
    state.require(
        type(probes) is list,
        "CHILD_THREADPOOL_LIST",
        "upstream child threadpool probe differs",
        "P1",
    )
    for probe in probes:
        item = require_exact_keys(
            probe,
            {"internal_api", "prefix", "user_api", "num_threads"},
            code="CHILD_THREADPOOL_KEY_UNIVERSE",
            label="upstream child threadpool record",
            state=state,
        )
        state.require(
            item["num_threads"] is None
            or (type(item["num_threads"]) is int and item["num_threads"] <= 1),
            "CHILD_THREADPOOL_VALUE",
            "upstream child threadpool escaped one thread",
        )
    state.require(
        _hex_sha(attestation["staged_project_tree_sha256_before"])
        and attestation["staged_project_tree_sha256_before"]
        == attestation["staged_project_tree_sha256_after"],
        "CHILD_STAGED_TREE",
        "upstream child staged tree binding differs",
    )


def validate_public_json_key_universes(
    manifest: Any,
    receipt: Any,
    *,
    state: State,
) -> None:
    manifest_value = require_exact_keys(
        manifest,
        PUBLIC_TASK_MANIFEST_FIELDS,
        code="PUBLIC_MANIFEST_KEY_UNIVERSE",
        label="public task manifest",
        state=state,
    )
    receipt_value = require_exact_keys(
        receipt,
        PUBLIC_REPLAY_RECEIPT_FIELDS,
        code="PUBLIC_RECEIPT_KEY_UNIVERSE",
        label="public replay receipt",
        state=state,
    )
    require_exact_keys(
        manifest_value["task"],
        TASK_FIELDS,
        code="PUBLIC_TASK_KEY_UNIVERSE",
        label="public manifest task",
        state=state,
    )
    require_exact_keys(
        receipt_value["pass_1_replay_receipt"],
        PUBLIC_PASS_RECEIPT_FIELDS,
        code="PASS_RECEIPT_KEY_UNIVERSE",
        label="pass-1 public replay receipt",
        state=state,
    )
    require_exact_keys(
        receipt_value["pass_2_replay_receipt"],
        PUBLIC_PASS_RECEIPT_FIELDS,
        code="PASS_RECEIPT_KEY_UNIVERSE",
        label="pass-2 public replay receipt",
        state=state,
    )


def validate_task(
    *,
    task_root: Path,
    public_relative: str,
    task: dict[str, Any],
    embedded: Any,
    design_lock_sha256: str,
    state: State,
) -> None:
    inventory(task_root, PUBLIC_FILE_UNIVERSE, state=state)
    paths = {name: task_root / name for name in PUBLIC_FILE_UNIVERSE}
    manifest_raw, manifest_info = stable_read(
        paths["PUBLIC_TASK_MANIFEST.json"], state=state
    )
    receipt_raw, receipt_info = stable_read(
        paths["PUBLIC_REPLAY_RECEIPT.json"], state=state
    )
    canonical_raw, canonical_info = stable_read(paths["canonical150.csv"], state=state)
    overlay_raw, overlay_info = stable_read(paths["v04_overlay.csv"], state=state)
    manifest = parse_json(manifest_raw, pretty=True, state=state)
    receipt = parse_json(receipt_raw, pretty=True, state=state)
    validate_public_json_key_universes(manifest, receipt, state=state)
    scan_public_protection(manifest, state=state)
    scan_public_protection(receipt, state=state)
    state.require(
        receipt == embedded,
        "EMBEDDED_RECEIPT",
        "generation receipt task binding differs",
    )
    state.require(
        manifest.get("schema_version")
        == "expected_pe.four_model.heldout_public_task_manifest.v1"
        and manifest.get("status") == "PASS_TWO_PUBLIC_REPLAYS_FROZEN_PRETRUTH"
        and manifest.get("task") == task,
        "TASK_IDENTITY",
        "public task manifest identity differs",
    )
    unsigned = dict(manifest)
    manifest_seal = unsigned.pop("task_manifest_semantic_sha256", None)
    state.require(
        _hex_sha(manifest_seal) and manifest_seal == semantic_sha256(unsigned),
        "MANIFEST_SELF_SEAL",
        "task manifest self-seal differs",
    )
    geometry = expected_geometry(task["dgp_id"])
    state.require(
        set(manifest.get("public_frame_rows", {})) == PUBLIC_FRAME_KEYS
        and manifest.get("public_frame_rows") == geometry,
        "RAW_GEOMETRY",
        "declared heterogeneous public raw geometry differs",
    )
    hashes = manifest.get("public_frame_raw_sha256")
    state.require(
        type(hashes) is dict
        and set(hashes) == PUBLIC_FRAME_KEYS
        and all(_hex_sha(value) for value in hashes.values()),
        "RAW_HASHES",
        "declared public raw hashes differ",
    )
    for key in (
        "public_frame_raw_hashes_equal",
        "public_frame_rows_equal",
        "canonical_replay_bytes_equal",
        "overlay_replay_bytes_equal",
    ):
        state.require(
            manifest.get(key) is True,
            "TWO_PASS_FLAG",
            "task two-pass equality flag differs",
        )
    state.require(
        manifest.get("public_replay_design_lock_raw_sha256")
        == design_lock_sha256,
        "DESIGN_LOCK",
        "public design lock differs",
    )

    canonical_header, canonical_dates = csv_geometry(
        canonical_raw, columns=150, state=state
    )
    overlay_header, overlay_dates = csv_geometry(
        overlay_raw, columns=254, state=state
    )
    state.require(
        canonical_dates == overlay_dates,
        "CSV_IDENTITY_JOIN",
        "canonical/overlay row identities differ",
    )
    base = (
        f"{public_relative}/{task['seed_alias']}/dgp_{task['dgp_id']}"
    )
    validate_ref(
        manifest.get("canonical_ref"),
        expected_relative_path=f"{base}/canonical150.csv",
        raw=canonical_raw,
        info=canonical_info,
        state=state,
    )
    validate_ref(
        manifest.get("overlay_ref"),
        expected_relative_path=f"{base}/v04_overlay.csv",
        raw=overlay_raw,
        info=overlay_info,
        state=state,
    )
    validate_ref(
        receipt.get("task_manifest_ref"),
        expected_relative_path=f"{base}/PUBLIC_TASK_MANIFEST.json",
        raw=manifest_raw,
        info=manifest_info,
        state=state,
    )
    _register_public(receipt_info, state=state)
    state.require(
        receipt.get("canonical_ref") == manifest.get("canonical_ref")
        and receipt.get("overlay_ref") == manifest.get("overlay_ref"),
        "RECEIPT_REF",
        "public replay receipt refs differ",
    )
    state.require(
        receipt.get("task_manifest_semantic_sha256") == manifest_seal,
        "RECEIPT_SEAL",
        "receipt manifest seal differs",
    )
    expected_receipt = {
        "schema_version": "expected_pe.four_model.heldout_public_replay_receipt.v1",
        "status": "PASS_TWO_PUBLIC_PASSES_BYTE_EXACT_PRETRUTH",
        "data_seed": task["data_seed"],
        "dgp_id": task["dgp_id"],
        "seed_alias": task["seed_alias"],
        "task_ordinal": task["task_ordinal"],
        "rows": 1800,
        "replay_pass": 1,
        "public_replay_design_lock_raw_sha256": design_lock_sha256,
        "protected_generator_imported": False,
        "protected_path_received": False,
        "protected_value_received": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "public_frame_raw_hashes_equal": True,
        "public_frame_rows_equal": True,
        "canonical_replay_bytes_equal": True,
        "overlay_replay_bytes_equal": True,
    }
    for key, expected in expected_receipt.items():
        state.require(
            receipt.get(key) == expected,
            "RECEIPT_EXACT",
            "public replay receipt differs",
        )
    state.require(
        receipt.get("public_frame_rows") == geometry
        and receipt.get("public_frame_raw_sha256") == hashes,
        "RECEIPT_RAW_BINDING",
        "receipt raw geometry/hash binding differs",
    )
    pass_1 = receipt.get("pass_1_replay_receipt")
    pass_2 = receipt.get("pass_2_replay_receipt")
    require_exact_keys(
        pass_1,
        PUBLIC_PASS_RECEIPT_FIELDS,
        code="PASS_RECEIPT_KEY_UNIVERSE",
        label="pass-1 public replay receipt",
        state=state,
    )
    require_exact_keys(
        pass_2,
        PUBLIC_PASS_RECEIPT_FIELDS,
        code="PASS_RECEIPT_KEY_UNIVERSE",
        label="pass-2 public replay receipt",
        state=state,
    )
    normalized_1, normalized_2 = dict(pass_1), dict(pass_2)
    state.require(
        normalized_1.pop("replay_pass", None) == 1
        and normalized_2.pop("replay_pass", None) == 2,
        "PASS_ORDINAL",
        "two-pass ordinals differ",
    )
    state.require(
        normalized_1 == normalized_2,
        "TWO_PASS_RECEIPT",
        "pass-1/pass-2 receipts differ",
    )
    pass_expected = {
        "schema_version": "expected_pe.four_model.heldout_public_replay_receipt.v1",
        "status": "PASS_PUBLIC_ONLY_REPLAY_PRETRUTH",
        "task_ordinal": task["task_ordinal"],
        "data_seed": task["data_seed"],
        "seed_alias": task["seed_alias"],
        "dgp_id": task["dgp_id"],
        "rows": 1800,
        "protected_generator_imported": False,
        "protected_path_received": False,
        "protected_value_received": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "public_frame_raw_sha256": hashes,
        "public_frame_rows": geometry,
    }
    for replay_pass, ordinal in ((pass_1, 1), (pass_2, 2)):
        state.require(
            replay_pass["replay_pass"] == ordinal
            and all(replay_pass[key] == expected for key, expected in pass_expected.items()),
            "PASS_RECEIPT_EXACT",
            "public pass replay receipt differs",
        )
    state.require(
        pass_1.get("public_frame_rows") == geometry
        and pass_2.get("public_frame_rows") == geometry
        and pass_1.get("public_frame_raw_sha256") == hashes
        and pass_2.get("public_frame_raw_sha256") == hashes,
        "TWO_PASS_RAW_BINDING",
        "two-pass raw declarations differ",
    )
    canonical_sha, overlay_sha = sha256(canonical_raw), sha256(overlay_raw)
    for upstream in (
        receipt.get("upstream_replay_receipt"),
        pass_1.get("upstream_replay_receipt"),
        pass_2.get("upstream_replay_receipt"),
    ):
        validate_upstream(
            upstream,
            canonical_sha=canonical_sha,
            overlay_sha=overlay_sha,
            canonical_header_sha=canonical_header,
            overlay_header_sha=overlay_header,
            state=state,
        )
    state.require(
        receipt.get("upstream_replay_receipt")
        == pass_1.get("upstream_replay_receipt")
        == pass_2.get("upstream_replay_receipt"),
        "TWO_PASS_UPSTREAM",
        "two-pass upstream receipts differ",
    )
    state.task_evidence.append(
        {
            "data_seed": task["data_seed"],
            "dgp_id": task["dgp_id"],
            "task_ordinal": task["task_ordinal"],
            "public_frame_rows": geometry,
            "manifest_raw_sha256": sha256(manifest_raw),
            "receipt_raw_sha256": sha256(receipt_raw),
            "canonical_raw_sha256": canonical_sha,
            "overlay_raw_sha256": overlay_sha,
        }
    )


def validate_vault_manifest(
    raw: bytes,
    *,
    project: Path,
    vault_relative: str,
    tasks: list[dict[str, Any]],
    qualification_raw_sha256: str,
    generation_plan_semantic_sha256: str,
    state: State,
) -> None:
    manifest = parse_json(raw, pretty=False, state=state)
    require_exact_keys(
        manifest,
        VAULT_MANIFEST_FIELDS,
        code="VAULT_KEY_UNIVERSE",
        label="vault manifest",
        state=state,
    )
    core = dict(manifest)
    seal = core.pop("vault_manifest_semantic_sha256", None)
    state.require(
        _hex_sha(seal) and seal == semantic_sha256(core),
        "VAULT_SELF_SEAL",
        "vault manifest self-seal differs",
    )
    expected = {
        "schema_version": "expected_pe.four_model.heldout_vault_manifest.v1",
        "status": "FROZEN_PROTECTED_TRUTH_REFS_NO_OUTER_TRUTH_CONTENT_OPEN",
        "vault_relative_path": vault_relative,
        "qualification_result_raw_sha256": qualification_raw_sha256,
        "generation_plan_semantic_sha256": generation_plan_semantic_sha256,
        "truth_ref_count": 50,
        "protected_task_metadata_count": 100,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "metadata_read_count": 100,
        "pass_1_pass_2_protected_hashes_equal": True,
        "pass_1_pass_2_public_hashes_equal": True,
        "truth_content_open_count": 0,
        "truth_attribute_open_count_by_manifest_builder": 0,
        "truth_attribute_open_count_at_protected_write_time": 100,
        "pass_2_truth_ref_export_count": 0,
        "latent_ref_export_count": 0,
        "truth_refs_origin": "protected_write_time_FILE_READ_ATTRIBUTES_only",
        "outer_truth_content_open_count": 0,
        "evaluator_pre_marker_truth_content_open_count": 0,
    }
    for key, expected_value in expected.items():
        state.require(
            manifest.get(key) == expected_value,
            "VAULT_EXACT",
            "vault manifest metadata differs",
        )
    refs = manifest.get("truth_refs")
    state.require(
        type(refs) is list and len(refs) == 50,
        "VAULT_REF_COUNT",
        "vault truth-ref count differs",
    )
    identities: set[tuple[int, str]] = set()
    for task, ref in zip(tasks, refs, strict=True):
        state.require(
            type(ref) is dict and set(ref) == ARTIFACT_REF_FIELDS,
            "VAULT_REF_SCHEMA",
            "vault ref metadata schema differs",
        )
        expected_path = (
            f"{vault_relative}/pass_1/seed_{task['data_seed']}/"
            f"dgp_{task['dgp_id']}/truth.csv"
        )
        state.require(
            ref["relative_path"] == expected_path,
            "VAULT_REF_ORDER",
            "vault ref identity/order differs",
        )
        state.require(
            _hex_sha(ref["raw_sha256"])
            and type(ref["size_bytes"]) is int
            and ref["size_bytes"] > 0,
            "VAULT_REF_METADATA",
            "vault ref metadata differs",
        )
        state.require(
            type(ref["volume_serial_number"]) is int
            and type(ref["file_id_128"]) is str
            and FILE_ID_RE.fullmatch(ref["file_id_128"]) is not None,
            "VAULT_REF_IDENTITY",
            "vault ref file identity differs",
        )
        identity = (ref["volume_serial_number"], ref["file_id_128"])
        state.require(
            identity not in identities,
            "VAULT_REF_ALIAS",
            "vault ref identity alias detected",
        )
        identities.add(identity)
        # Lexical length only.  Never resolve, stat, enumerate, or open this ref.
        lexical = Path(os.path.abspath(project / Path(*expected_path.split("/"))))
        state.max_path_chars = max(state.max_path_chars, len(str(lexical)))
        state.require(
            len(str(lexical)) <= MAX_PATH_CHARS,
            "PATH_LENGTH",
            "vault ref path is 240 characters or longer",
            "P1",
        )


def validate_generation_receipt(
    generation: Any,
    *,
    run_id: str,
    authority_semantic_sha256: str,
    state: State,
) -> list[Any]:
    value = require_exact_keys(
        generation,
        GENERATION_RECEIPT_FIELDS,
        code="GENERATION_KEY_UNIVERSE",
        label="generation execution receipt",
        state=state,
    )
    expected = {
        "schema_version": "expected_pe.four_model.heldout_generation_execution.v1",
        "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
        "run_id": run_id,
        "execution_authority_semantic_sha256": authority_semantic_sha256,
        "source_frozen_before_generation": True,
        "task_count": 50,
        "outer_workers": 16,
        "inner_blas_threads": 1,
        "cpu_affinity": "CPU0-31",
        "gpu_enabled": False,
        "protected_public_process_separation": True,
        "anonymous_one_way_pipe_used": True,
        "public_pass_1_pass_2_byte_exact": True,
        "truth_ref_inventory_received_by_public_process": False,
        "truth_open_count_by_controller": 0,
        "truth_open_count_by_public_process": 0,
        "score_open_count": 0,
    }
    for key, expected_value in expected.items():
        state.require(
            value[key] == expected_value,
            "GENERATION_EXACT",
            "generation receipt differs",
        )
    embedded = value["public_task_receipts"]
    state.require(
        type(embedded) is list and len(embedded) == 50,
        "GENERATION_TASK_COUNT",
        "generation embedded receipt count differs",
    )
    return embedded


def run_audit(
    project: Path,
    *,
    run_id: str,
    execution_authority: Path,
    authority_semantic_sha256: str,
    authority_raw_sha256: str,
    public_replay_root: Path,
    vault_manifest_path: Path,
) -> dict[str, Any]:
    state = State()
    project = Path(os.path.abspath(project))
    check_path(project, state=state, kind="dir")
    authority_path = _project_path(execution_authority, project)
    public_root = _project_path(public_replay_root, project)
    vault_manifest = _project_path(vault_manifest_path, project)
    authority_relative = _relative(
        authority_path, project, state=state, code="AUTHORITY_SCOPE"
    )
    public_relative = _relative(
        public_root, project, state=state, code="PUBLIC_SCOPE"
    )
    vault_relative = _relative(
        vault_manifest.parent, project, state=state, code="VAULT_SCOPE"
    )
    validate_r3_run_paths(
        run_id=run_id,
        authority_relative=authority_relative,
        public_relative=public_relative,
        vault_relative=vault_relative,
        vault_manifest_leaf=vault_manifest.name,
        state=state,
    )
    state.require(
        public_root != vault_manifest.parent,
        "PUBLIC_PRIVATE_SCOPE",
        "public and vault roots are not distinct",
        "P1",
    )
    check_path(project / "outputs", state=state, kind="dir")
    check_path(authority_path.parent, state=state, kind="dir")
    check_path(vault_manifest.parent, state=state, kind="dir")
    authority, authority_raw, tasks = validate_authority(
        authority_path,
        run_id=run_id,
        expected_semantic_sha256=authority_semantic_sha256,
        expected_raw_sha256=authority_raw_sha256,
        state=state,
    )
    plan = authority["generation_plan"]
    aliases = plan["heldout_seed_aliases_in_order"]
    design_lock_sha256 = authority["source_manifest"][
        "public_replay_design_lock_raw_sha256"
    ]
    qualification_raw_sha256 = plan["qualification_result_raw_sha256"]
    generation_plan_semantic_sha256 = authority[
        "generation_plan_semantic_sha256"
    ]

    expected_root = set(aliases) | {"GENERATION_EXECUTION_RECEIPT.json"}
    inventory(public_root, expected_root, state=state)
    generation_raw, generation_info = stable_read(
        public_root / "GENERATION_EXECUTION_RECEIPT.json", state=state
    )
    _register_public(generation_info, state=state)
    generation = parse_json(generation_raw, pretty=False, state=state)
    scan_public_protection(generation, state=state)
    embedded = validate_generation_receipt(
        generation,
        run_id=run_id,
        authority_semantic_sha256=authority_semantic_sha256,
        state=state,
    )
    for task in tasks:
        alias_root = public_root / task["seed_alias"]
        if task["dgp_id"] == DGPS[0]:
            inventory(
                alias_root,
                {f"dgp_{dgp}" for dgp in DGPS},
                state=state,
            )
        validate_task(
            task_root=alias_root / f"dgp_{task['dgp_id']}",
            public_relative=public_relative,
            task=task,
            embedded=embedded[task["task_ordinal"]],
            design_lock_sha256=design_lock_sha256,
            state=state,
        )
    state.require(
        len(state.task_evidence) == 50,
        "TASK_COMPLETENESS",
        "post-generation audit did not validate 50 tasks",
    )
    state.require(
        len(state.public_file_identities) == 201,
        "PUBLIC_FILE_ALIAS",
        "public file identities are not unique",
    )
    geometries = {
        semantic_sha256(item["public_frame_rows"])
        for item in state.task_evidence
    }
    state.require(
        len(geometries) == 2,
        "HETEROGENEOUS_GEOMETRY",
        "heterogeneous raw geometry was not preserved",
    )

    # This is the only protected-root file opened by this program.
    vault_raw, _ = stable_read(vault_manifest, state=state)
    validate_vault_manifest(
        vault_raw,
        project=project,
        vault_relative=vault_relative,
        tasks=tasks,
        qualification_raw_sha256=qualification_raw_sha256,
        generation_plan_semantic_sha256=generation_plan_semantic_sha256,
        state=state,
    )
    report: dict[str, Any] = {
        "schema_version": "expected_pe.four_model.r3_post_generation_audit.v1",
        "status": "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0",
        "run_id": run_id,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "authority": {
            "relative_path": authority_relative,
            "raw_sha256": sha256(authority_raw),
            "execution_authority_semantic_sha256": authority_semantic_sha256,
            "generation_plan_semantic_sha256": generation_plan_semantic_sha256,
            "exact_authority_task_order_validated": True,
        },
        "public_evidence": {
            "relative_root": public_relative,
            "root_entry_count": 6,
            "seed_alias_count": 5,
            "dgp_count_per_alias": 10,
            "task_count": 50,
            "public_file_count": 201,
            "canonical_rows_per_task": 1800,
            "overlay_rows_per_task": 1800,
            "generation_receipt_raw_sha256": sha256(generation_raw),
            "task_inventory_semantic_sha256": semantic_sha256(
                state.task_evidence
            ),
            "two_distinct_declared_raw_geometry_profiles": True,
            "truth_open_count": 0,
            "score_open_count": 0,
            "protected_path_or_value_received": False,
        },
        "vault_metadata_evidence": {
            "manifest_relative_path": f"{vault_relative}/VAULT_MANIFEST.json",
            "manifest_raw_sha256": sha256(vault_raw),
            "truth_ref_count": 50,
            "truth_content_open_count": 0,
            "outer_truth_content_open_count": 0,
            "evaluator_pre_marker_truth_content_open_count": 0,
            "latent_ref_export_count": 0,
            "payload_directories_enumerated": False,
            "payload_refs_resolved_or_statted": 0,
            "payload_leaves_opened": 0,
        },
        "filesystem_evidence": {
            "reparse_points": 0,
            "max_audited_path_chars": state.max_path_chars,
            "path_limit_exclusive": 240,
        },
        "audit_check_count": state.check_count,
        "auditor_source_raw_sha256": sha256(Path(__file__).read_bytes()),
    }
    report["audit_semantic_sha256"] = semantic_sha256(report)
    return report


def failure_report(
    failure: AuditFailure,
    *,
    run_id: str,
    source_hash: str,
) -> dict[str, Any]:
    counts = {"P0": 0, "P1": 0, "P2": 0}
    counts[failure.severity] = 1
    report: dict[str, Any] = {
        "schema_version": "expected_pe.four_model.r3_post_generation_audit.v1",
        "status": "NO_GO_R3_POST_GENERATION_AUDIT",
        "run_id": run_id,
        "finding_counts": counts,
        "findings": [
            {
                "severity": failure.severity,
                "code": failure.code,
                "message": failure.safe_message,
            }
        ],
        "protected_boundary": {
            "payload_directories_enumerated": False,
            "payload_refs_resolved_or_statted": 0,
            "payload_leaves_opened": 0,
        },
        "auditor_source_raw_sha256": source_hash,
    }
    report["audit_semantic_sha256"] = semantic_sha256(report)
    return report


def publish(report: dict[str, Any], *, project: Path, output_root: Path) -> str:
    project = Path(os.path.abspath(project))
    build = project / "build"
    root = _project_path(output_root, project)
    if root.parent != build:
        raise AuditFailure(
            "P1",
            "OUTPUT_SCOPE",
            "audit output root must be one directory below project/build",
        )
    check_state = State()
    check_path(build, state=check_state, kind="dir")
    if root.exists():
        raise AuditFailure(
            "P1", "OUTPUT_EXISTS", "audit output root already exists"
        )
    root.mkdir()
    output = root / REPORT_NAME
    raw = pretty_bytes(report)
    with output.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    observed = output.read_bytes()
    if observed != raw:
        raise AuditFailure(
            "P1", "OUTPUT_MUTATION", "published audit bytes differ"
        )
    return sha256(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--execution-authority",
        "--execution-authority-path",
        dest="execution_authority",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--execution-authority-semantic-sha256", required=True
    )
    parser.add_argument("--execution-authority-raw-sha256", required=True)
    parser.add_argument("--public-replay-root", type=Path, required=True)
    parser.add_argument(
        "--vault-manifest",
        "--vault-manifest-path",
        dest="vault_manifest",
        type=Path,
        required=True,
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    source_hash = sha256(Path(__file__).read_bytes())
    try:
        report = run_audit(
            args.project_root,
            run_id=args.run_id,
            execution_authority=args.execution_authority,
            authority_semantic_sha256=(
                args.execution_authority_semantic_sha256
            ),
            authority_raw_sha256=args.execution_authority_raw_sha256,
            public_replay_root=args.public_replay_root,
            vault_manifest_path=args.vault_manifest,
        )
    except AuditFailure as failure:
        report = failure_report(
            failure,
            run_id=args.run_id,
            source_hash=source_hash,
        )
    except Exception:
        report = failure_report(
            AuditFailure(
                "P0",
                "UNEXPECTED_EXCEPTION",
                "unexpected fail-closed audit exception",
            ),
            run_id=args.run_id,
            source_hash=source_hash,
        )
    try:
        raw_hash = publish(
            report,
            project=args.project_root,
            output_root=args.output_root,
        )
    except AuditFailure as failure:
        print(
            json.dumps(
                {
                    "status": "NO_GO_AUDIT_PUBLICATION",
                    "code": failure.code,
                },
                sort_keys=True,
            )
        )
        return 3
    print(
        json.dumps(
            {
                "status": report["status"],
                "audit_raw_sha256": raw_hash,
                "audit_semantic_sha256": report["audit_semantic_sha256"],
                "finding_counts": report["finding_counts"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if report["status"].startswith("GO_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
