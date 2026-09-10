"""Explicit-hash CLI for the detached one-shot qualification scorer."""

# ruff: noqa: E402

from __future__ import annotations

import sys


# This gate is intentionally the first executable statement after importing ``sys``.  Production
# first native-holds and hash-verifies these exact launcher bytes from a caller-supplied stdlib-only
# ``-c`` trust anchor, then compile/executes those held bytes.  Package/module execution is blocked;
# importing anything else here first would escape the frozen bootstrap boundary.
if (
    sys.flags.isolated != 1
    or sys.flags.no_site != 1
    or sys.flags.ignore_environment != 1
    or not sys.dont_write_bytecode
):
    raise SystemExit("production scorer requires exact python -I -S -B -E invocation")
_EXTERNAL_LAUNCHER_RAW_SHA256 = globals().get("_QUALIFICATION_VERIFIED_LAUNCHER_RAW_SHA256")
_EXTERNAL_LAUNCHER_HANDLE = globals().get("_QUALIFICATION_VERIFIED_LAUNCHER_HANDLE")
if (
    type(_EXTERNAL_LAUNCHER_RAW_SHA256) is not str
    or len(_EXTERNAL_LAUNCHER_RAW_SHA256) != 64
    or any(character not in "0123456789abcdef" for character in _EXTERNAL_LAUNCHER_RAW_SHA256)
    or type(_EXTERNAL_LAUNCHER_HANDLE) is not int
    or _EXTERNAL_LAUNCHER_HANDLE <= 0
):
    raise SystemExit("production scorer requires an external held-byte launcher trust anchor")

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import stat
import types
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


_ACTIVATION_LEAF = "QUALIFICATION_ACTIVATION.json"
_PUBLICATION_PROTOCOL = "NTCREATEFILE_EXACT_FINAL_ROOT_RELATIVE_LEAVES_V2"
_ACTIVATION_ROOT_NAME = (
    "model_zoo_pe_five_candidate_qualification_activation_r4_r8_r14_20260824T000005"
)
_SCORER_OUTPUT_RELATIVE = (
    "outputs/model_zoo_pe_five_candidate_fresh_qualification_result_r4_r8_r14_20260824T000005"
)
_ACTIVATION_OUTPUT_FILES = (
    "ACTIVATION_SEAL.json",
    "ATTEMPT_CLAIM.json",
    "QUALIFICATION_ACTIVATION.json",
)
_ACTIVATION_CLAIM_SCHEMA = "expected_pe.qualification.activation_attempt_claim.r8.r14.v2"
_ACTIVATION_CLAIM_STATUS = "CLAIMED_SCORER_ACTIVATION_EXACT_FINAL_ROOT_NONRETRYABLE"
_ACTIVATION_SEAL_SCHEMA = "expected_pe.qualification.activation_publication_seal.r8.r14.v2"
_ACTIVATION_SEAL_STATUS = "SEALED_GO_SCORER_ACTIVATION_AFTER_PRESCORE_GO_V2"
_LAUNCHER_RELATIVE = (
    "scripts/model_lab/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/run_once.py"
)
_TARGET_LEAF = "PRE_SCORE_TARGET_BINDING.json"
_AUDIT_LEAF = "PRE_SCORE_AUDIT.json"
_SEAL_LEAF = "AUDIT_SEAL.json"
_PREDICTION_AUDIT_ROOT_NAME = (
    "pe_five_model_qualification_prediction_audit_r3_r8_r14_20260824T000005"
)
_AUDIT_STATUS = "GO_PRE_SCORE_TARGET_BOUND_P0_0_P1_0_P2_0"
_SEAL_STATUS = "SEALED_GO_PRE_SCORE_TARGET_BOUND_P0_0_P1_0_P2_0"
_ACTIVATION_SCHEMA = "expected_pe.qualification.detached_scorer.r8.r14.v1.activation"
_ACTIVATION_STATUS = "FROZEN_ONE_SHOT_QUALIFICATION_HELDOUT_FALSE"
_TARGET_SCHEMA = "expected_pe.qualification.pre_score_target_binding.r8.r14.v2"
_TARGET_STATUS = "FROZEN_SCORER_TARGET_BEFORE_MARKER_AND_TRUTH_PUBLICATION_V2"
_AUDIT_SCHEMA = "expected_pe.qualification.pre_score_audit.r8.r14.v2"
_SEAL_SCHEMA = "expected_pe.qualification.pre_score_audit_seal.r8.r14.v2"
_TARGET_ROOT_NAME = "pe_five_model_qualification_prescore_target_r4_r8_r14_20260824T000005"
_PRESCORE_AUDIT_ROOT_NAME = "pe_five_model_qualification_prescore_audit_r4_r8_r14_20260824T000005"
_TARGET_CLAIM_SCHEMA = "expected_pe.qualification.pre_score_target_attempt_claim.r8.r14.v2"
_TARGET_CLAIM_STATUS = "CLAIMED_PRE_SCORE_TARGET_EXACT_FINAL_ROOT_NONRETRYABLE"
_TARGET_SEAL_SCHEMA = "expected_pe.qualification.pre_score_target_publication_seal.r8.r14.v2"
_TARGET_SEAL_STATUS = "SEALED_FROZEN_PRE_SCORE_TARGET_HANDLE_CUSTODY_V2"
_AUDIT_CLAIM_SCHEMA = "expected_pe.qualification.pre_score_audit_attempt_claim.r8.r14.v2"
_AUDIT_CLAIM_STATUS = "CLAIMED_PRE_SCORE_AUDIT_EXACT_FINAL_ROOT_NONRETRYABLE"
_TARGET_OUTPUT_FILES = (
    "ATTEMPT_CLAIM.json",
    "PRE_SCORE_TARGET_BINDING.json",
    "TARGET_PUBLICATION_SEAL.json",
)
_AUDIT_OUTPUT_FILES = (
    "ATTEMPT_CLAIM.json",
    "AUDIT_SEAL.json",
    "AUDITOR_SOURCE_MANIFEST.json",
    "CHECKSUMS.sha256",
    "PRE_SCORE_AUDIT.json",
)
_REF_FIELDS = (
    "relative_path",
    "raw_sha256",
    "size_bytes",
    "volume_serial_number",
    "file_id_128",
)
_CORE_FIELDS = (
    "schema_version",
    "status",
    "run_id",
    "output_relative_path",
    "vault_relative_path",
    "policy_raw_sha256",
    "heldout_authority",
    "prediction_ref",
    "prediction_audit_ref",
    "prediction_audit_seal_ref",
    "prediction_semantic_sha256",
    "common_full_identities_semantic_sha256",
    "source_model_versions",
    "truth_refs",
)
_ACTIVATION_FIELDS = (
    *_CORE_FIELDS,
    "activation_core_semantic_sha256",
    "pre_score_target_ref",
    "pre_score_audit_ref",
    "pre_score_audit_seal_ref",
)
_ACTIVATION_CLAIM_FIELDS = (
    "schema_version",
    "status",
    "run_id",
    "output_root_relative_path",
    "payload_leaf",
    "activation_raw_sha256",
    "activation_semantic_sha256",
    "activation_core_semantic_sha256",
    "pre_score_target_raw_sha256",
    "pre_score_audit_raw_sha256",
    "pre_score_audit_seal_raw_sha256",
    "publication_protocol",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "same_target_retry_allowed",
    "claim_semantic_sha256",
)
_ACTIVATION_SEAL_FIELDS = (
    "schema_version",
    "status",
    "verdict",
    "run_id",
    "output_root_relative_path",
    "output_root_volume_serial_number",
    "output_root_file_id_128",
    "attempt_claim_ref",
    "activation_ref",
    "activation_raw_sha256",
    "activation_semantic_sha256",
    "activation_core_semantic_sha256",
    "pre_score_target_raw_sha256",
    "pre_score_audit_raw_sha256",
    "pre_score_audit_seal_raw_sha256",
    "output_file_universe",
    "publication_protocol",
    "attempt_claim_published_first",
    "seal_published_last",
    "same_target_retry_allowed",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "terminal",
)
_TARGET_FIELDS = (
    "schema_version",
    "status",
    "activation_core",
    "activation_core_semantic_sha256",
    "scorer_source_refs",
    "python_runtime",
    "prediction_chain",
    "pre_score_output_relative_path",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "target_binding_semantic_sha256",
)
_TARGET_CLAIM_FIELDS = (
    "schema_version",
    "status",
    "run_id",
    "output_root_relative_path",
    "payload_leaf",
    "target_binding_raw_sha256",
    "target_binding_semantic_sha256",
    "activation_core_raw_sha256",
    "activation_core_semantic_sha256",
    "pre_score_audit_output_relative_path",
    "publication_protocol",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "same_target_retry_allowed",
    "claim_semantic_sha256",
)
_TARGET_SEAL_FIELDS = (
    "schema_version",
    "status",
    "verdict",
    "run_id",
    "output_root_relative_path",
    "output_root_volume_serial_number",
    "output_root_file_id_128",
    "attempt_claim_ref",
    "target_binding_ref",
    "target_binding_semantic_sha256",
    "activation_core_raw_sha256",
    "activation_core_semantic_sha256",
    "output_file_universe",
    "publication_protocol",
    "attempt_claim_published_first",
    "seal_published_last",
    "same_target_retry_allowed",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "terminal",
)
_AUDIT_CLAIM_FIELDS = (
    "schema_version",
    "status",
    "run_id",
    "output_root_relative_path",
    "payload_leaf",
    "audit_raw_sha256",
    "audit_semantic_sha256",
    "audit_verdict",
    "target_binding_raw_sha256",
    "target_binding_semantic_sha256",
    "auditor_source_manifest_raw_sha256",
    "auditor_source_manifest_semantic_sha256",
    "publication_protocol",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "same_target_retry_allowed",
    "claim_semantic_sha256",
)
_RUNTIME_FIELDS = (
    "implementation",
    "version_info",
    "cache_tag",
    "executable_final_path",
    "executable_raw_sha256",
    "executable_size_bytes",
    "executable_volume_serial_number",
    "executable_file_id_128",
    "required_flags_in_order",
)
_PREDICTION_CHAIN_FIELDS = (
    "common_run_id",
    "common_root_name",
    "common_checksums_ref",
    "common_manifest_ref",
    "common_full_identities_ref",
    "postgen_audit_ref",
    "postgen_audit_seal_ref",
    "postgen_checksums_ref",
    "combined_root_name",
    "combined_checksums_ref",
    "combined_combination_receipt_ref",
    "combined_input_binding_ref",
    "combined_input_custody_ref",
    "combined_manifest_ref",
    "combined_runtime_ref",
    "combined_source_manifest_ref",
    "prediction_ref",
    "prediction_audit_ref",
    "prediction_audit_seal_ref",
    "prediction_auditor_source_manifest_ref",
    "prediction_audit_checksums_ref",
)
_AUDIT_FIELDS = (
    "schema_version",
    "status",
    "verdict",
    "finding_counts",
    "findings",
    "target_binding_raw_sha256",
    "target_binding_semantic_sha256",
    "target_binding_size_bytes",
    "target_binding_volume_serial_number",
    "target_binding_file_id_128",
    "activation_core_semantic_sha256",
    "scorer_run_id",
    "scorer_output_relative_path",
    "vault_relative_path",
    "policy_raw_sha256",
    "scorer_source_manifest_semantic_sha256",
    "scorer_source_file_count",
    "scorer_source_static_checks",
    "python_runtime_binding_semantic_sha256",
    "python_executable_raw_sha256",
    "python_executable_volume_serial_number",
    "python_executable_file_id_128",
    "prediction_raw_sha256",
    "prediction_semantic_sha256",
    "prediction_audit_raw_sha256",
    "prediction_audit_semantic_sha256",
    "prediction_audit_seal_raw_sha256",
    "prediction_audit_target_binding_semantic_sha256",
    "common_run_id",
    "common_root_name",
    "common_checksums_raw_sha256",
    "common_manifest_raw_sha256",
    "common_full_identities_raw_sha256",
    "common_full_identities_semantic_sha256",
    "postgen_audit_raw_sha256",
    "postgen_audit_semantic_sha256",
    "postgen_audit_seal_raw_sha256",
    "combined_root_name",
    "combined_checksums_raw_sha256",
    "combined_input_binding_raw_sha256",
    "combined_manifest_raw_sha256",
    "combined_runtime_raw_sha256",
    "combined_source_manifest_raw_sha256",
    "source_model_versions",
    "truth_ref_count",
    "truth_ref_inventory_semantic_sha256",
    "qualification_task_count",
    "identity_count",
    "prediction_row_count",
    "prediction_before_truth",
    "checks",
    "access",
    "independence",
    "auditor_source_manifest_raw_sha256",
    "auditor_source_manifest_semantic_sha256",
)
_SEAL_FIELDS = (
    "schema_version",
    "status",
    "verdict",
    "finding_counts",
    "pre_score_audit_raw_sha256",
    "pre_score_audit_semantic_sha256",
    "pre_score_audit_size_bytes",
    "pre_score_audit_volume_serial_number",
    "pre_score_audit_file_id_128",
    "target_binding_raw_sha256",
    "target_binding_semantic_sha256",
    "activation_core_semantic_sha256",
    "policy_raw_sha256",
    "scorer_source_manifest_semantic_sha256",
    "python_runtime_binding_semantic_sha256",
    "prediction_raw_sha256",
    "prediction_semantic_sha256",
    "prediction_audit_raw_sha256",
    "prediction_audit_seal_raw_sha256",
    "common_root_name",
    "common_checksums_raw_sha256",
    "postgen_audit_raw_sha256",
    "postgen_audit_seal_raw_sha256",
    "combined_root_name",
    "combined_checksums_raw_sha256",
    "auditor_source_manifest_raw_sha256",
    "audit_output_file_universe",
    "attempt_claim_ref",
    "output_root_volume_serial_number",
    "output_root_file_id_128",
    "publication_protocol",
    "attempt_claim_published_first",
    "seal_published_last",
    "same_target_retry_allowed",
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "terminal",
)
_STATIC_CHECK_FIELDS = (
    "exact_source_path_order",
    "all_source_hash_size_volume_file_ids_held",
    "policy_v2_raw_identity_exact",
    "marker_durable_before_first_truth_open",
    "no_truth_vault_heldout_score_cli",
    "no_glob_walk_or_path_discovery",
    "mandatory_pre_score_chain_in_activation",
    "v1_formula_and_v2_custody_dependencies_bound",
    "source_only_test_evidence_bound",
    "external_launcher_handle_preimport_bound",
)
_CHECK_FIELDS = (
    "target_self_seal_exact",
    "activation_core_target_exact",
    "scorer_source_config_formula_policy_closure_held",
    "scorer_marker_before_truth_static_order_exact",
    "python_runtime_executable_held",
    "common_r8_r14_identity_and_postgen_go_seal_exact",
    "combined_prediction_hash_size_file_ids_exact",
    "independent_prediction_audit_go_seal_exact",
    "prediction_geometry_and_source_versions_exact",
    "truth_refs_metadata_only_never_opened",
    "heldout_authority_absent",
)
_ACCESS_FIELDS = (
    "truth_open_count",
    "score_open_count",
    "heldout_open_count",
    "protected_namespace_open_count",
)
_INDEPENDENCE_FIELDS = (
    "scorer_package_imported",
    "prediction_auditor_package_imported",
    "combiner_or_model_package_imported",
    "truth_vault_opened",
    "heldout_namespace_received",
    "scoring_executed",
)
_MODEL_IDS = (
    "v04_expected_pe",
    "bce_v1_b_causal_rolling_dispersion_budget",
    "bce_v1_d_observable_state_confidence_shrinkage",
    "bce_tournament_v1_fixed_alpha_040_directional_consensus",
    "hofs_v4_expected_pe",
)
_SCORER_PACKAGE = "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1"
_V1_PACKAGE = "research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1"
_V2_PACKAGE = "research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2"
_V2_REQUIRED = (
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/custody.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/contracts.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/canonical.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/constants.py",
)
_SOURCE_RELATIVES = tuple(
    f"{_SCORER_PACKAGE}/{leaf}"
    for leaf in (
        "__init__.py",
        "__main__.py",
        "audit.py",
        "canonical.py",
        "constants.py",
        "contracts.py",
        "metrics.py",
        "prediction.py",
        "publication.py",
        "runner.py",
        "truth.py",
        "DESIGN.md",
    )
) + (
    "scripts/model_lab/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/run_once.py",
    "tests/model_lab/test_pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/evaluator.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/contract.py",
    *_V2_REQUIRED,
    "research/model_zoo/portfolio_governance_v1/QUALIFICATION_CERTIFICATION_DESIGN_LOCK_V2.json",
)
_PINNED_SOURCE_SHA256 = {
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/evaluator.py": "49e0d24fc87a9d1f2cc1d7026570252f768994927b8f023b1570075cee6bae26",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/contract.py": "62131354aab94e1145572570c0ee99a9da7f1fad10d334c7c345e6f692eaf379",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/custody.py": "dae048d7e02789d421981faae021c36a8af6d17230d7bad7de8168b8b7df001c",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/contracts.py": "bfd383542f706edd4efc4136c2afe7e4bab44b2aea70b1876d73aa0251ea2bfb",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/canonical.py": "09de1cc5384f4f2072f8dbd7d7dffe52e49966430f356dde655632495661e021",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/constants.py": "b8f10cf9b5f89260ed6c79cae84d080569081f43bee09965fec0298d9ceba77d",
    "research/model_zoo/portfolio_governance_v1/QUALIFICATION_CERTIFICATION_DESIGN_LOCK_V2.json": "8574fb9a375d4dc93e74201729868ef2e64371544165e2c84d9da1f3c063d112",
}

_FILE_ID_INFO_CLASS = 18
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_LIST_DIRECTORY = 0x0001
_FILE_TRAVERSE = 0x0020
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_BEGIN = 0
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FileIdInfo(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_ulonglong),
        ("file_id", _FileId128),
    )


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    )


@dataclass(slots=True)
class _BootstrapHeld:
    handle: int
    path: Path
    directory: bool
    volume_serial_number: int
    file_id_128: str
    raw_sha256: str | None
    size_bytes: int | None


class _HeldSourceLoader:
    def __init__(self, sources: dict[str, tuple[str, bytes]]) -> None:
        self._sources = sources

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        fullname = str(module.__spec__.name)
        relative, raw = self._sources[fullname]
        code = compile(raw, str(PROJECT_ROOT / relative), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__, module.__dict__)


class _HeldSourceFinder:
    def __init__(
        self,
        *,
        sources: dict[str, tuple[str, bytes]],
        protected_packages: tuple[str, ...],
    ) -> None:
        self._sources = sources
        self._protected_packages = protected_packages
        self._loader = _HeldSourceLoader(sources)

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> Any:
        if fullname in self._sources:
            return importlib.util.spec_from_loader(
                fullname,
                self._loader,
                origin=str(PROJECT_ROOT / self._sources[fullname][0]),
                is_package=False,
            )
        if any(fullname.startswith(f"{package}.") for package in self._protected_packages):
            raise ImportError(f"unheld protected scorer dependency rejected: {fullname}")
        return None


def _canonical_pretty(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_compact(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _kernel32() -> Any:
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    library.CreateFileW.restype = wintypes.HANDLE
    library.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    library.GetFileInformationByHandleEx.restype = wintypes.BOOL
    library.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    library.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    library.GetFileSizeEx.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_longlong),
    )
    library.GetFileSizeEx.restype = wintypes.BOOL
    library.SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    library.SetFilePointerEx.restype = wintypes.BOOL
    library.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    library.ReadFile.restype = wintypes.BOOL
    library.CloseHandle.argtypes = (wintypes.HANDLE,)
    library.CloseHandle.restype = wintypes.BOOL
    return library


def _path_key(value: str | Path) -> str:
    raw = str(value)
    if raw.startswith("\\\\?\\UNC\\"):
        raw = "\\\\" + raw[8:]
    elif raw.startswith("\\\\?\\"):
        raw = raw[4:]
    return ntpath.normcase(ntpath.normpath(raw))


def _final_path(handle: int) -> str:
    library = _kernel32()
    needed = int(library.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0))
    if needed <= 0:
        raise RuntimeError("bootstrap final-path size query failed")
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = int(
        library.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), buffer, len(buffer), 0)
    )
    if written <= 0 or written >= len(buffer):
        raise RuntimeError("bootstrap final-path query failed")
    return buffer.value


def _identity(handle: int) -> tuple[int, str]:
    information = _FileIdInfo()
    if not _kernel32().GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise RuntimeError("bootstrap FileId query failed")
    return int(information.volume_serial_number), bytes(information.file_id.identifier).hex()


def _attributes(handle: int) -> tuple[int, int]:
    information = _FileAttributeTagInfo()
    if not _kernel32().GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise RuntimeError("bootstrap attribute/tag query failed")
    return int(information.file_attributes), int(information.reparse_tag)


def _read_handle(handle: int) -> bytes:
    library = _kernel32()
    size = ctypes.c_longlong()
    if not library.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)) or size.value < 0:
        raise RuntimeError("bootstrap file-size query failed")
    if not library.SetFilePointerEx(wintypes.HANDLE(handle), 0, None, _FILE_BEGIN):
        raise RuntimeError("bootstrap file seek failed")
    remaining = int(size.value)
    chunks: list[bytes] = []
    while remaining:
        requested = min(remaining, 1024 * 1024)
        buffer = ctypes.create_string_buffer(requested)
        read = wintypes.DWORD()
        if (
            not library.ReadFile(
                wintypes.HANDLE(handle), buffer, requested, ctypes.byref(read), None
            )
            or read.value == 0
        ):
            raise RuntimeError("bootstrap source read failed")
        chunks.append(buffer.raw[: read.value])
        remaining -= int(read.value)
    return b"".join(chunks)


def _hold(path: Path, *, directory: bool) -> tuple[_BootstrapHeld, bytes | None]:
    absolute = Path(os.path.abspath(path))
    if _is_reparse(absolute):
        raise RuntimeError("bootstrap reparse source/ancestor rejected")
    desired = _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        desired |= _FILE_LIST_DIRECTORY | _FILE_TRAVERSE
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    else:
        desired |= _GENERIC_READ
    handle = _kernel32().CreateFileW(
        str(absolute),
        desired,
        _FILE_SHARE_READ | (_FILE_SHARE_WRITE if directory else 0),
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    numeric = int(handle or 0)
    if numeric in (0, _INVALID_HANDLE_VALUE):
        raise RuntimeError("bootstrap CreateFileW failed")
    try:
        attributes, tag = _attributes(numeric)
        if (
            bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            or tag != 0
            or bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) is not directory
            or _path_key(_final_path(numeric)) != _path_key(absolute)
        ):
            raise RuntimeError("bootstrap held source kind/final path differs")
        volume, file_id = _identity(numeric)
        raw = None if directory else _read_handle(numeric)
        return (
            _BootstrapHeld(
                handle=numeric,
                path=absolute,
                directory=directory,
                volume_serial_number=volume,
                file_id_128=file_id,
                raw_sha256=None if raw is None else hashlib.sha256(raw).hexdigest(),
                size_bytes=None if raw is None else len(raw),
            ),
            raw,
        )
    except BaseException:
        _kernel32().CloseHandle(wintypes.HANDLE(numeric))
        raise


def _directory_chain(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    result = [current]
    for part in absolute.parts[1:]:
        current /= part
        result.append(current)
    return tuple(result)


def _assert_held(rows: list[_BootstrapHeld]) -> None:
    for row in rows:
        attributes, tag = _attributes(row.handle)
        volume, file_id = _identity(row.handle)
        if (
            bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            or tag != 0
            or bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) is not row.directory
            or volume != row.volume_serial_number
            or file_id != row.file_id_128
            or _path_key(_final_path(row.handle)) != _path_key(row.path)
        ):
            raise RuntimeError("bootstrap held source identity changed")
        if not row.directory:
            raw = _read_handle(row.handle)
            if len(raw) != row.size_bytes or hashlib.sha256(raw).hexdigest() != row.raw_sha256:
                raise RuntimeError("bootstrap held source bytes changed")


def _close_held(rows: list[_BootstrapHeld]) -> None:
    failures = 0
    for row in reversed(rows):
        if not _kernel32().CloseHandle(wintypes.HANDLE(row.handle)):
            failures += 1
    rows.clear()
    if failures:
        raise RuntimeError("bootstrap held-source cleanup failed")


def _exact_keys(value: dict[str, Any], fields: tuple[str, ...], *, label: str) -> None:
    if tuple(sorted(value)) != tuple(sorted(fields)):
        raise RuntimeError(f"bootstrap {label} field universe differs")


def _hex(value: object, digits: int, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != digits
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"bootstrap {label} is not lowercase hex-{digits}")
    return value


def _ref(value: object, *, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise RuntimeError(f"bootstrap {label} ArtifactRef is not an object")
    _exact_keys(value, _REF_FIELDS, label=f"{label} ArtifactRef")
    relative = value["relative_path"]
    if (
        type(relative) is not str
        or not relative
        or "\\" in relative
        or relative.startswith("/")
        or any(part in ("", ".", "..") for part in relative.split("/"))
    ):
        raise RuntimeError(f"bootstrap {label} relative path differs")
    _hex(value["raw_sha256"], 64, label=f"{label} raw hash")
    _hex(value["file_id_128"], 32, label=f"{label} FileId")
    if type(value["size_bytes"]) is not int or value["size_bytes"] <= 0:
        raise RuntimeError(f"bootstrap {label} size differs")
    if type(value["volume_serial_number"]) is not int or value["volume_serial_number"] <= 0:
        raise RuntimeError(f"bootstrap {label} volume differs")
    return value


def _object(raw: bytes, *, compact: bool) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("bootstrap authority JSON contains a duplicate key")
            result[key] = value
        return result

    value = json.loads(
        raw.decode("ascii" if compact else "utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            RuntimeError(f"bootstrap non-finite JSON rejected: {token}")
        ),
    )
    canonical = _canonical_compact(value) if compact else _canonical_pretty(value)
    if type(value) is not dict or canonical != raw:
        raise RuntimeError("bootstrap authority JSON canonical bytes differ")
    return value


def _public_path(path: Path, *, leaf: str) -> Path:
    absolute = Path(os.path.abspath(path))
    outputs = Path(os.path.abspath(PROJECT_ROOT / "outputs"))
    protected = ("heldout", "vault", "latent", "pass_1", "pass_2", "truth")
    if (
        absolute.name != leaf
        or absolute.parent.parent != outputs
        or absolute.parent.name.startswith(".")
        or any(token in str(absolute).casefold() for token in protected)
    ):
        raise RuntimeError("bootstrap input is not one exact direct public artifact")
    return absolute


def _hold_once(
    path: Path,
    *,
    directory: bool,
    held: list[_BootstrapHeld],
    by_path: dict[str, _BootstrapHeld],
) -> tuple[_BootstrapHeld, bytes | None]:
    absolute = Path(os.path.abspath(path))
    key = _path_key(absolute)
    existing = by_path.get(key)
    if existing is not None:
        if existing.directory is not directory:
            raise RuntimeError("bootstrap held path is both file and directory")
        return existing, None if directory else _read_handle(existing.handle)
    row, raw = _hold(absolute, directory=directory)
    held.append(row)
    by_path[key] = row
    return row, raw


def _hold_file_with_ancestors(
    path: Path,
    *,
    held: list[_BootstrapHeld],
    by_path: dict[str, _BootstrapHeld],
) -> tuple[_BootstrapHeld, bytes]:
    absolute = Path(os.path.abspath(path))
    for directory in _directory_chain(absolute.parent):
        _hold_once(directory, directory=True, held=held, by_path=by_path)
    row, raw = _hold_once(absolute, directory=False, held=held, by_path=by_path)
    if raw is None:
        raise RuntimeError("bootstrap held file has no bytes")
    return row, raw


def _held_ref(row: _BootstrapHeld, raw: bytes, *, relative_path: str) -> dict[str, Any]:
    return {
        "relative_path": relative_path,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "volume_serial_number": row.volume_serial_number,
        "file_id_128": row.file_id_128,
    }


def _hold_publication_root(
    root: Path,
    *,
    expected_files: tuple[str, ...],
    held: list[_BootstrapHeld],
    by_path: dict[str, _BootstrapHeld],
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]], _BootstrapHeld]:
    absolute = Path(os.path.abspath(root))
    root_row, _ = _hold_once(absolute, directory=True, held=held, by_path=by_path)
    if tuple(sorted(os.listdir(absolute))) != tuple(sorted(expected_files)):
        raise RuntimeError("bootstrap publication root file universe differs")
    raws: dict[str, bytes] = {}
    refs: dict[str, dict[str, Any]] = {}
    identities: set[tuple[int, str]] = set()
    for leaf in expected_files:
        row, raw = _hold_file_with_ancestors(absolute / leaf, held=held, by_path=by_path)
        relative = (absolute / leaf).relative_to(PROJECT_ROOT).as_posix()
        raws[leaf] = raw
        refs[leaf] = _held_ref(row, raw, relative_path=relative)
        identity = (row.volume_serial_number, row.file_id_128)
        if identity in identities:
            raise RuntimeError("bootstrap publication contains a FileId alias")
        identities.add(identity)
    if tuple(sorted(os.listdir(absolute))) != tuple(sorted(expected_files)):
        raise RuntimeError("bootstrap held publication root changed")
    return raws, refs, root_row


def _match_ref(row: _BootstrapHeld, raw: bytes, ref: dict[str, Any], *, label: str) -> None:
    if (
        row.raw_sha256 != ref["raw_sha256"]
        or row.size_bytes != ref["size_bytes"]
        or row.volume_serial_number != ref["volume_serial_number"]
        or row.file_id_128 != ref["file_id_128"]
        or hashlib.sha256(raw).hexdigest() != ref["raw_sha256"]
        or len(raw) != ref["size_bytes"]
    ):
        raise RuntimeError(f"bootstrap held {label} ArtifactRef differs")


def _source_module_name(relative: str) -> str | None:
    if not relative.endswith(".py"):
        return None
    dotted = relative[:-3].replace("/", ".")
    if dotted.endswith(".__init__"):
        return None
    for package in (
        _SCORER_PACKAGE.replace("/", "."),
        _V1_PACKAGE,
        _V2_PACKAGE,
    ):
        if dotted.startswith(f"{package}."):
            return dotted
    return None


def _bootstrap_source_custody(
    *, activation_path: Path, activation_hash: str
) -> tuple[list[_BootstrapHeld], dict[str, Any]]:
    _hex(activation_hash, 64, label="activation expected hash")
    held: list[_BootstrapHeld] = []
    held_by_path: dict[str, _BootstrapHeld] = {}
    try:
        activation_absolute = _public_path(activation_path, leaf=_ACTIVATION_LEAF)
        if activation_absolute.parent.name != _ACTIVATION_ROOT_NAME:
            raise RuntimeError("bootstrap activation root name differs")
        activation_publication_raws, activation_publication_refs, activation_root_row = (
            _hold_publication_root(
                activation_absolute.parent,
                expected_files=_ACTIVATION_OUTPUT_FILES,
                held=held,
                by_path=held_by_path,
            )
        )
        activation_raw = activation_publication_raws[_ACTIVATION_LEAF]
        if hashlib.sha256(activation_raw).hexdigest() != activation_hash:
            raise RuntimeError("bootstrap activation hash differs")
        activation = _object(activation_raw, compact=False)
        _exact_keys(activation, _ACTIVATION_FIELDS, label="activation")
        if (
            activation["schema_version"] != _ACTIVATION_SCHEMA
            or activation["status"] != _ACTIVATION_STATUS
            or activation["output_relative_path"] != _SCORER_OUTPUT_RELATIVE
            or activation["heldout_authority"] is not False
        ):
            raise RuntimeError("bootstrap activation schema/status/authority differs")
        activation_claim = _object(activation_publication_raws["ATTEMPT_CLAIM.json"], compact=True)
        activation_seal = _object(activation_publication_raws["ACTIVATION_SEAL.json"], compact=True)
        _exact_keys(activation_claim, _ACTIVATION_CLAIM_FIELDS, label="activation claim")
        _exact_keys(activation_seal, _ACTIVATION_SEAL_FIELDS, label="activation seal")
        unsigned_activation_claim = dict(activation_claim)
        activation_claim_semantic = unsigned_activation_claim.pop("claim_semantic_sha256")
        activation_semantic = hashlib.sha256(_canonical_compact(activation)[:-1]).hexdigest()
        activation_root_relative = activation_absolute.parent.relative_to(PROJECT_ROOT).as_posix()
        if (
            _hex(activation_claim_semantic, 64, label="activation claim semantic")
            != hashlib.sha256(_canonical_compact(unsigned_activation_claim)[:-1]).hexdigest()
            or activation_claim["schema_version"] != _ACTIVATION_CLAIM_SCHEMA
            or activation_claim["status"] != _ACTIVATION_CLAIM_STATUS
            or activation_claim["run_id"] != activation["run_id"]
            or activation_claim["output_root_relative_path"] != activation_root_relative
            or activation_claim["payload_leaf"] != _ACTIVATION_LEAF
            or activation_claim["activation_raw_sha256"] != activation_hash
            or activation_claim["activation_semantic_sha256"] != activation_semantic
            or activation_claim["activation_core_semantic_sha256"]
            != activation["activation_core_semantic_sha256"]
            or activation_claim["pre_score_target_raw_sha256"]
            != activation["pre_score_target_ref"]["raw_sha256"]
            or activation_claim["pre_score_audit_raw_sha256"]
            != activation["pre_score_audit_ref"]["raw_sha256"]
            or activation_claim["pre_score_audit_seal_raw_sha256"]
            != activation["pre_score_audit_seal_ref"]["raw_sha256"]
            or activation_claim["publication_protocol"] != _PUBLICATION_PROTOCOL
            or activation_claim["same_target_retry_allowed"] is not False
            or any(
                type(activation_claim[field]) is not int or activation_claim[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
        ):
            raise RuntimeError("bootstrap activation claim differs")
        if (
            activation_seal["schema_version"] != _ACTIVATION_SEAL_SCHEMA
            or activation_seal["status"] != _ACTIVATION_SEAL_STATUS
            or activation_seal["verdict"] != _ACTIVATION_SEAL_STATUS
            or activation_seal["run_id"] != activation["run_id"]
            or activation_seal["output_root_relative_path"] != activation_root_relative
            or activation_seal["output_root_volume_serial_number"]
            != activation_root_row.volume_serial_number
            or activation_seal["output_root_file_id_128"] != activation_root_row.file_id_128
            or activation_seal["attempt_claim_ref"]
            != activation_publication_refs["ATTEMPT_CLAIM.json"]
            or activation_seal["activation_ref"] != activation_publication_refs[_ACTIVATION_LEAF]
            or activation_seal["activation_raw_sha256"] != activation_hash
            or activation_seal["activation_semantic_sha256"] != activation_semantic
            or activation_seal["activation_core_semantic_sha256"]
            != activation["activation_core_semantic_sha256"]
            or activation_seal["pre_score_target_raw_sha256"]
            != activation["pre_score_target_ref"]["raw_sha256"]
            or activation_seal["pre_score_audit_raw_sha256"]
            != activation["pre_score_audit_ref"]["raw_sha256"]
            or activation_seal["pre_score_audit_seal_raw_sha256"]
            != activation["pre_score_audit_seal_ref"]["raw_sha256"]
            or activation_seal["output_file_universe"] != list(_ACTIVATION_OUTPUT_FILES)
            or activation_seal["publication_protocol"] != _PUBLICATION_PROTOCOL
            or activation_seal["attempt_claim_published_first"] is not True
            or activation_seal["seal_published_last"] is not True
            or activation_seal["same_target_retry_allowed"] is not False
            or any(
                type(activation_seal[field]) is not int or activation_seal[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
            or activation_seal["terminal"] is not False
        ):
            raise RuntimeError("bootstrap activation publication seal differs")
        prediction_ref = _ref(activation["prediction_ref"], label="prediction")
        prediction_audit_ref = _ref(activation["prediction_audit_ref"], label="prediction audit")
        prediction_audit_seal_ref = _ref(
            activation["prediction_audit_seal_ref"], label="prediction audit seal"
        )
        prediction_audit_parts = prediction_audit_ref["relative_path"].split("/")
        prediction_seal_parts = prediction_audit_seal_ref["relative_path"].split("/")
        if (
            prediction_audit_parts[-2] != _PREDICTION_AUDIT_ROOT_NAME
            or prediction_seal_parts[-2] != _PREDICTION_AUDIT_ROOT_NAME
            or prediction_audit_parts[:-1] != prediction_seal_parts[:-1]
        ):
            raise RuntimeError("bootstrap prediction audit is not exact authorized R3 root")
        if type(activation["truth_refs"]) is not list or len(activation["truth_refs"]) != 50:
            raise RuntimeError("bootstrap activation truth inventory count differs")
        versions = activation["source_model_versions"]
        if type(versions) is not dict or set(versions) != set(_MODEL_IDS):
            raise RuntimeError("bootstrap source-model version universe/order differs")
        for model_id in _MODEL_IDS:
            version = versions[model_id]
            if type(version) is not str or not version.startswith("sha256:") or len(version) != 71:
                raise RuntimeError("bootstrap source-model version is not final")
            _hex(version[7:], 64, label=f"source-model version/{model_id}")
        truth_refs = [
            _ref(row, label=f"truth metadata {index}")
            for index, row in enumerate(activation["truth_refs"])
        ]

        target_ref = _ref(activation["pre_score_target_ref"], label="pre-score target")
        audit_ref = _ref(activation["pre_score_audit_ref"], label="pre-score audit")
        seal_ref = _ref(activation["pre_score_audit_seal_ref"], label="pre-score audit seal")
        target_path = _public_path(PROJECT_ROOT / target_ref["relative_path"], leaf=_TARGET_LEAF)
        audit_path = _public_path(PROJECT_ROOT / audit_ref["relative_path"], leaf=_AUDIT_LEAF)
        seal_path = _public_path(PROJECT_ROOT / seal_ref["relative_path"], leaf=_SEAL_LEAF)
        if (
            target_path.parent.name != _TARGET_ROOT_NAME
            or audit_path.parent.name != _PRESCORE_AUDIT_ROOT_NAME
            or audit_path.parent != seal_path.parent
        ):
            raise RuntimeError("bootstrap pre-score V2 root geometry differs")
        target_publication_raws, target_publication_refs, target_root_row = _hold_publication_root(
            target_path.parent,
            expected_files=_TARGET_OUTPUT_FILES,
            held=held,
            by_path=held_by_path,
        )
        audit_publication_raws, audit_publication_refs, audit_root_row = _hold_publication_root(
            audit_path.parent,
            expected_files=_AUDIT_OUTPUT_FILES,
            held=held,
            by_path=held_by_path,
        )
        target_raw = target_publication_raws[_TARGET_LEAF]
        audit_raw = audit_publication_raws[_AUDIT_LEAF]
        seal_raw = audit_publication_raws[_SEAL_LEAF]
        target_row = held_by_path[_path_key(target_path)]
        audit_row = held_by_path[_path_key(audit_path)]
        seal_row = held_by_path[_path_key(seal_path)]
        _match_ref(target_row, target_raw, target_ref, label="pre-score target")
        _match_ref(audit_row, audit_raw, audit_ref, label="pre-score audit")
        _match_ref(seal_row, seal_raw, seal_ref, label="pre-score audit seal")

        target = _object(target_raw, compact=True)
        audit = _object(audit_raw, compact=True)
        seal = _object(seal_raw, compact=True)
        target_claim = _object(target_publication_raws["ATTEMPT_CLAIM.json"], compact=True)
        target_publication_seal = _object(
            target_publication_raws["TARGET_PUBLICATION_SEAL.json"], compact=True
        )
        audit_claim = _object(audit_publication_raws["ATTEMPT_CLAIM.json"], compact=True)
        _exact_keys(target, _TARGET_FIELDS, label="pre-score target")
        _exact_keys(audit, _AUDIT_FIELDS, label="pre-score audit")
        _exact_keys(seal, _SEAL_FIELDS, label="pre-score audit seal")
        _exact_keys(target_claim, _TARGET_CLAIM_FIELDS, label="pre-score target claim")
        _exact_keys(
            target_publication_seal,
            _TARGET_SEAL_FIELDS,
            label="pre-score target publication seal",
        )
        _exact_keys(audit_claim, _AUDIT_CLAIM_FIELDS, label="pre-score audit claim")
        core = {field: activation[field] for field in _CORE_FIELDS}
        core_semantic = hashlib.sha256(_canonical_compact(core)[:-1]).hexdigest()
        unsealed_target = dict(target)
        target_semantic = unsealed_target.pop("target_binding_semantic_sha256")
        _hex(target_semantic, 64, label="pre-score target semantic hash")
        if (
            target["schema_version"] != _TARGET_SCHEMA
            or target["status"] != _TARGET_STATUS
            or target["activation_core"] != core
            or target["activation_core_semantic_sha256"] != core_semantic
            or activation["activation_core_semantic_sha256"] != core_semantic
            or hashlib.sha256(_canonical_compact(unsealed_target)[:-1]).hexdigest()
            != target_semantic
            or any(
                target[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
            or target["pre_score_output_relative_path"]
            != audit_path.parent.relative_to(PROJECT_ROOT).as_posix()
        ):
            raise RuntimeError("bootstrap activation/target semantic binding differs")
        core_raw = _canonical_compact(core)
        unsigned_target_claim = dict(target_claim)
        target_claim_semantic = unsigned_target_claim.pop("claim_semantic_sha256")
        target_root_relative = target_path.parent.relative_to(PROJECT_ROOT).as_posix()
        audit_root_relative = audit_path.parent.relative_to(PROJECT_ROOT).as_posix()
        if (
            _hex(target_claim_semantic, 64, label="target claim semantic")
            != hashlib.sha256(_canonical_compact(unsigned_target_claim)[:-1]).hexdigest()
            or target_claim["schema_version"] != _TARGET_CLAIM_SCHEMA
            or target_claim["status"] != _TARGET_CLAIM_STATUS
            or target_claim["run_id"] != activation["run_id"]
            or target_claim["output_root_relative_path"] != target_root_relative
            or target_claim["payload_leaf"] != _TARGET_LEAF
            or target_claim["target_binding_raw_sha256"] != target_ref["raw_sha256"]
            or target_claim["target_binding_semantic_sha256"] != target_semantic
            or target_claim["activation_core_raw_sha256"] != hashlib.sha256(core_raw).hexdigest()
            or target_claim["activation_core_semantic_sha256"] != core_semantic
            or target_claim["pre_score_audit_output_relative_path"] != audit_root_relative
            or target_claim["publication_protocol"] != _PUBLICATION_PROTOCOL
            or target_claim["same_target_retry_allowed"] is not False
            or any(
                type(target_claim[field]) is not int or target_claim[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
        ):
            raise RuntimeError("bootstrap pre-score target claim differs")
        if (
            target_publication_seal["schema_version"] != _TARGET_SEAL_SCHEMA
            or target_publication_seal["status"] != _TARGET_SEAL_STATUS
            or target_publication_seal["verdict"] != _TARGET_SEAL_STATUS
            or target_publication_seal["run_id"] != activation["run_id"]
            or target_publication_seal["output_root_relative_path"] != target_root_relative
            or target_publication_seal["output_root_volume_serial_number"]
            != target_root_row.volume_serial_number
            or target_publication_seal["output_root_file_id_128"] != target_root_row.file_id_128
            or target_publication_seal["attempt_claim_ref"]
            != target_publication_refs["ATTEMPT_CLAIM.json"]
            or target_publication_seal["target_binding_ref"] != target_ref
            or target_publication_seal["target_binding_semantic_sha256"] != target_semantic
            or target_publication_seal["activation_core_raw_sha256"]
            != hashlib.sha256(core_raw).hexdigest()
            or target_publication_seal["activation_core_semantic_sha256"] != core_semantic
            or target_publication_seal["output_file_universe"] != list(_TARGET_OUTPUT_FILES)
            or target_publication_seal["publication_protocol"] != _PUBLICATION_PROTOCOL
            or target_publication_seal["attempt_claim_published_first"] is not True
            or target_publication_seal["seal_published_last"] is not True
            or target_publication_seal["same_target_retry_allowed"] is not False
            or any(
                type(target_publication_seal[field]) is not int
                or target_publication_seal[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
            or target_publication_seal["terminal"] is not False
        ):
            raise RuntimeError("bootstrap pre-score target publication seal differs")

        runtime = target["python_runtime"]
        chain = target["prediction_chain"]
        if type(runtime) is not dict or type(chain) is not dict:
            raise RuntimeError("bootstrap target runtime/prediction chain differs")
        _exact_keys(runtime, _RUNTIME_FIELDS, label="Python runtime")
        _exact_keys(chain, _PREDICTION_CHAIN_FIELDS, label="prediction chain")
        chain_refs = {
            field: _ref(chain[field], label=f"prediction chain/{field}")
            for field in _PREDICTION_CHAIN_FIELDS
            if field.endswith("_ref")
        }
        if (
            chain_refs["prediction_ref"] != prediction_ref
            or chain_refs["prediction_audit_ref"] != prediction_audit_ref
            or chain_refs["prediction_audit_seal_ref"] != prediction_audit_seal_ref
        ):
            raise RuntimeError("bootstrap activation/prediction-chain refs differ")
        if (
            runtime["implementation"] != "cpython"
            or runtime["version_info"] != list(sys.version_info)
            or runtime["cache_tag"] != sys.implementation.cache_tag
            or runtime["required_flags_in_order"] != ["-I", "-S", "-B", "-E"]
            or _path_key(runtime["executable_final_path"]) != _path_key(sys.executable)
        ):
            raise RuntimeError("bootstrap Python runtime contract differs")
        runtime_ref = {
            "relative_path": "bootstrap-runtime-only",
            "raw_sha256": _hex(
                runtime["executable_raw_sha256"], 64, label="Python executable hash"
            ),
            "size_bytes": runtime["executable_size_bytes"],
            "volume_serial_number": runtime["executable_volume_serial_number"],
            "file_id_128": _hex(
                runtime["executable_file_id_128"], 32, label="Python executable FileId"
            ),
        }
        if (
            type(runtime_ref["size_bytes"]) is not int
            or runtime_ref["size_bytes"] <= 0
            or type(runtime_ref["volume_serial_number"]) is not int
            or runtime_ref["volume_serial_number"] <= 0
        ):
            raise RuntimeError("bootstrap Python executable size/volume differs")
        runtime_row, runtime_raw = _hold_file_with_ancestors(
            Path(runtime["executable_final_path"]), held=held, by_path=held_by_path
        )
        _match_ref(runtime_row, runtime_raw, runtime_ref, label="Python executable")

        raw_refs = target["scorer_source_refs"]
        if type(raw_refs) is not list or len(raw_refs) != len(_SOURCE_RELATIVES):
            raise RuntimeError("bootstrap scorer source closure is absent")
        source_refs = [
            _ref(row, label=f"scorer source {index}") for index, row in enumerate(raw_refs)
        ]
        if [row["relative_path"] for row in source_refs] != list(_SOURCE_RELATIVES):
            raise RuntimeError("bootstrap scorer source order differs")
        source_semantic = hashlib.sha256(_canonical_compact(source_refs)[:-1]).hexdigest()
        source_identities: list[tuple[int, str]] = []
        held_module_sources: dict[str, tuple[str, bytes]] = {}
        for ref in source_refs:
            relative = ref["relative_path"]
            pinned = _PINNED_SOURCE_SHA256.get(relative)
            if pinned is not None and ref["raw_sha256"] != pinned:
                raise RuntimeError(f"bootstrap pinned dependency differs: {relative}")
            row, raw = _hold_file_with_ancestors(
                PROJECT_ROOT / relative, held=held, by_path=held_by_path
            )
            _match_ref(row, raw, ref, label=relative)
            if relative == _LAUNCHER_RELATIVE:
                external_attributes, external_tag = _attributes(_EXTERNAL_LAUNCHER_HANDLE)
                external_raw = _read_handle(_EXTERNAL_LAUNCHER_HANDLE)
                if (
                    bool(external_attributes & _FILE_ATTRIBUTE_DIRECTORY)
                    or bool(external_attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
                    or external_tag != 0
                    or _path_key(_final_path(_EXTERNAL_LAUNCHER_HANDLE))
                    != _path_key(PROJECT_ROOT / relative)
                    or _identity(_EXTERNAL_LAUNCHER_HANDLE)
                    != (row.volume_serial_number, row.file_id_128)
                    or hashlib.sha256(external_raw).hexdigest() != _EXTERNAL_LAUNCHER_RAW_SHA256
                    or ref["raw_sha256"] != _EXTERNAL_LAUNCHER_RAW_SHA256
                    or external_raw != raw
                ):
                    raise RuntimeError("bootstrap external launcher handle/source binding differs")
            source_identities.append((row.volume_serial_number, row.file_id_128))
            module_name = _source_module_name(relative)
            if module_name is not None:
                if module_name in held_module_sources:
                    raise RuntimeError("bootstrap held module mapping is not unique")
                held_module_sources[module_name] = (relative, raw)
        if len(source_identities) != len(set(source_identities)):
            raise RuntimeError("bootstrap scorer source closure contains a FileId alias")

        zero = {"P0": 0, "P1": 0, "P2": 0}
        access_zero = {field: 0 for field in _ACCESS_FIELDS}
        expected_audit_raw = hashlib.sha256(audit_raw).hexdigest()
        expected_target_raw = hashlib.sha256(target_raw).hexdigest()
        audit_semantic = hashlib.sha256(audit_raw[:-1]).hexdigest()
        runtime_semantic = hashlib.sha256(_canonical_compact(runtime)[:-1]).hexdigest()
        truth_semantic = hashlib.sha256(_canonical_compact(truth_refs)[:-1]).hexdigest()
        auditor_source_ref = audit_publication_refs["AUDITOR_SOURCE_MANIFEST.json"]
        audit_claim_ref = audit_publication_refs["ATTEMPT_CLAIM.json"]
        unsigned_audit_claim = dict(audit_claim)
        audit_claim_semantic = unsigned_audit_claim.pop("claim_semantic_sha256")
        if (
            _hex(audit_claim_semantic, 64, label="audit claim semantic")
            != hashlib.sha256(_canonical_compact(unsigned_audit_claim)[:-1]).hexdigest()
            or audit_claim["schema_version"] != _AUDIT_CLAIM_SCHEMA
            or audit_claim["status"] != _AUDIT_CLAIM_STATUS
            or audit_claim["run_id"] != activation["run_id"]
            or audit_claim["output_root_relative_path"] != audit_root_relative
            or audit_claim["payload_leaf"] != _AUDIT_LEAF
            or audit_claim["audit_raw_sha256"] != expected_audit_raw
            or audit_claim["audit_semantic_sha256"] != audit_semantic
            or audit_claim["audit_verdict"] != _AUDIT_STATUS
            or audit_claim["target_binding_raw_sha256"] != expected_target_raw
            or audit_claim["target_binding_semantic_sha256"] != target_semantic
            or audit_claim["auditor_source_manifest_raw_sha256"] != auditor_source_ref["raw_sha256"]
            or audit_claim["auditor_source_manifest_semantic_sha256"]
            != audit["auditor_source_manifest_semantic_sha256"]
            or audit_claim["publication_protocol"] != _PUBLICATION_PROTOCOL
            or audit_claim["same_target_retry_allowed"] is not False
            or any(
                type(audit_claim[field]) is not int or audit_claim[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
        ):
            raise RuntimeError("bootstrap pre-score audit claim differs")
        audit_bindings = {
            "activation_core_semantic_sha256": core_semantic,
            "scorer_run_id": activation["run_id"],
            "scorer_output_relative_path": activation["output_relative_path"],
            "vault_relative_path": activation["vault_relative_path"],
            "policy_raw_sha256": _PINNED_SOURCE_SHA256[_SOURCE_RELATIVES[-1]],
            "scorer_source_manifest_semantic_sha256": source_semantic,
            "scorer_source_file_count": len(_SOURCE_RELATIVES),
            "python_runtime_binding_semantic_sha256": runtime_semantic,
            "python_executable_raw_sha256": runtime_row.raw_sha256,
            "python_executable_volume_serial_number": runtime_row.volume_serial_number,
            "python_executable_file_id_128": runtime_row.file_id_128,
            "prediction_raw_sha256": prediction_ref["raw_sha256"],
            "prediction_semantic_sha256": activation["prediction_semantic_sha256"],
            "prediction_audit_raw_sha256": prediction_audit_ref["raw_sha256"],
            "prediction_audit_seal_raw_sha256": prediction_audit_seal_ref["raw_sha256"],
            "common_run_id": chain["common_run_id"],
            "common_root_name": chain["common_root_name"],
            "common_checksums_raw_sha256": chain_refs["common_checksums_ref"]["raw_sha256"],
            "common_manifest_raw_sha256": chain_refs["common_manifest_ref"]["raw_sha256"],
            "common_full_identities_raw_sha256": chain_refs["common_full_identities_ref"][
                "raw_sha256"
            ],
            "common_full_identities_semantic_sha256": activation[
                "common_full_identities_semantic_sha256"
            ],
            "postgen_audit_raw_sha256": chain_refs["postgen_audit_ref"]["raw_sha256"],
            "postgen_audit_seal_raw_sha256": chain_refs["postgen_audit_seal_ref"]["raw_sha256"],
            "combined_root_name": chain["combined_root_name"],
            "combined_checksums_raw_sha256": chain_refs["combined_checksums_ref"]["raw_sha256"],
            "combined_input_binding_raw_sha256": chain_refs["combined_input_binding_ref"][
                "raw_sha256"
            ],
            "combined_manifest_raw_sha256": chain_refs["combined_manifest_ref"]["raw_sha256"],
            "combined_runtime_raw_sha256": chain_refs["combined_runtime_ref"]["raw_sha256"],
            "combined_source_manifest_raw_sha256": chain_refs["combined_source_manifest_ref"][
                "raw_sha256"
            ],
            "source_model_versions": [
                {"model_id": model_id, "source_model_version": versions[model_id]}
                for model_id in _MODEL_IDS
            ],
            "truth_ref_count": 50,
            "truth_ref_inventory_semantic_sha256": truth_semantic,
            "qualification_task_count": 50,
            "identity_count": 64_800,
            "prediction_row_count": 324_000,
            "prediction_before_truth": True,
        }
        if (
            audit["schema_version"] != _AUDIT_SCHEMA
            or audit["status"] != _AUDIT_STATUS
            or audit["verdict"] != _AUDIT_STATUS
            or audit["finding_counts"] != zero
            or audit["findings"] != []
            or audit["target_binding_raw_sha256"] != expected_target_raw
            or audit["target_binding_semantic_sha256"] != target_semantic
            or any(audit[field] != expected for field, expected in audit_bindings.items())
            or audit["access"] != access_zero
            or audit["scorer_source_static_checks"]
            != {field: True for field in _STATIC_CHECK_FIELDS}
            or audit["checks"] != {field: True for field in _CHECK_FIELDS}
            or audit["independence"] != {field: False for field in _INDEPENDENCE_FIELDS}
            or seal["schema_version"] != _SEAL_SCHEMA
            or seal["status"] != _SEAL_STATUS
            or seal["verdict"] != _AUDIT_STATUS
            or seal["finding_counts"] != zero
            or seal["pre_score_audit_raw_sha256"] != expected_audit_raw
            or seal["pre_score_audit_semantic_sha256"] != audit_semantic
            or seal["pre_score_audit_size_bytes"] != len(audit_raw)
            or seal["pre_score_audit_volume_serial_number"] != audit_row.volume_serial_number
            or seal["pre_score_audit_file_id_128"] != audit_row.file_id_128
            or seal["target_binding_raw_sha256"] != expected_target_raw
            or seal["target_binding_semantic_sha256"] != target_semantic
            or seal["scorer_source_manifest_semantic_sha256"] != source_semantic
            or seal["activation_core_semantic_sha256"] != core_semantic
            or seal["python_runtime_binding_semantic_sha256"] != runtime_semantic
            or seal["audit_output_file_universe"] != list(_AUDIT_OUTPUT_FILES)
            or seal["attempt_claim_ref"] != audit_claim_ref
            or seal["output_root_volume_serial_number"] != audit_root_row.volume_serial_number
            or seal["output_root_file_id_128"] != audit_root_row.file_id_128
            or seal["publication_protocol"] != _PUBLICATION_PROTOCOL
            or seal["attempt_claim_published_first"] is not True
            or seal["seal_published_last"] is not True
            or seal["same_target_retry_allowed"] is not False
            or any(
                seal[field] != 0
                for field in ("truth_open_count", "score_open_count", "heldout_open_count")
            )
            or seal["terminal"] is not False
        ):
            raise RuntimeError("bootstrap independent pre-score GO/seal differs")
        expected_checksums = "".join(
            f"{digest}  {leaf}\n"
            for leaf, digest in sorted(
                {
                    "ATTEMPT_CLAIM.json": audit_claim_ref["raw_sha256"],
                    "AUDIT_SEAL.json": seal_ref["raw_sha256"],
                    "AUDITOR_SOURCE_MANIFEST.json": auditor_source_ref["raw_sha256"],
                    "PRE_SCORE_AUDIT.json": audit_ref["raw_sha256"],
                }.items()
            )
        ).encode("ascii")
        if audit_publication_raws["CHECKSUMS.sha256"] != expected_checksums:
            raise RuntimeError("bootstrap pre-score checksum ledger differs")
        common_seal_fields = (
            "target_binding_raw_sha256",
            "target_binding_semantic_sha256",
            "activation_core_semantic_sha256",
            "policy_raw_sha256",
            "scorer_source_manifest_semantic_sha256",
            "python_runtime_binding_semantic_sha256",
            "prediction_raw_sha256",
            "prediction_semantic_sha256",
            "prediction_audit_raw_sha256",
            "prediction_audit_seal_raw_sha256",
            "common_root_name",
            "common_checksums_raw_sha256",
            "postgen_audit_raw_sha256",
            "postgen_audit_seal_raw_sha256",
            "combined_root_name",
            "combined_checksums_raw_sha256",
            "auditor_source_manifest_raw_sha256",
        )
        if any(audit[field] != seal[field] for field in common_seal_fields):
            raise RuntimeError("bootstrap pre-score audit/seal cross-binding differs")
        if (
            audit["target_binding_size_bytes"] != target_row.size_bytes
            or audit["target_binding_volume_serial_number"] != target_row.volume_serial_number
            or audit["target_binding_file_id_128"] != target_row.file_id_128
            or audit["python_executable_raw_sha256"] != runtime_row.raw_sha256
            or audit["python_executable_volume_serial_number"] != runtime_row.volume_serial_number
            or audit["python_executable_file_id_128"] != runtime_row.file_id_128
        ):
            raise RuntimeError("bootstrap target/runtime held identity differs from GO audit")

        _assert_held(held)
        research = types.ModuleType("research")
        research.__package__ = "research"
        research.__path__ = [str(PROJECT_ROOT / "research")]
        model_zoo = types.ModuleType("research.model_zoo")
        model_zoo.__package__ = "research.model_zoo"
        model_zoo.__path__ = [str(PROJECT_ROOT / "research/model_zoo")]
        sys.modules["research"] = research
        sys.modules["research.model_zoo"] = model_zoo
        setattr(research, "model_zoo", model_zoo)
        scorer_package = _SCORER_PACKAGE.replace("/", ".")
        for package_name in (_V1_PACKAGE, _V2_PACKAGE, scorer_package):
            package = types.ModuleType(package_name)
            package.__package__ = package_name
            package.__path__ = [str(PROJECT_ROOT / package_name.replace(".", "/"))]
            sys.modules[package_name] = package
            setattr(model_zoo, package_name.rsplit(".", 1)[1], package)
        for module_name in held_module_sources:
            if module_name in sys.modules:
                raise RuntimeError("bootstrap protected module was imported before held loader")
        sys.meta_path.insert(
            0,
            _HeldSourceFinder(
                sources=held_module_sources,
                protected_packages=(_V1_PACKAGE, _V2_PACKAGE, scorer_package),
            ),
        )
        _assert_held(held)
        return held, activation
    except BaseException:
        _close_held(held)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--activation-raw-sha256", required=True)
    arguments = parser.parse_args()
    held, _ = _bootstrap_source_custody(
        activation_path=arguments.activation,
        activation_hash=arguments.activation_raw_sha256,
    )
    try:
        module = importlib.import_module(
            "research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1.runner"
        )
        output = module.run_once(
            project_root=PROJECT_ROOT,
            activation_path=arguments.activation,
            expected_activation_raw_sha256=arguments.activation_raw_sha256,
        )
        _assert_held(held)
    finally:
        _close_held(held)
    print(output.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
