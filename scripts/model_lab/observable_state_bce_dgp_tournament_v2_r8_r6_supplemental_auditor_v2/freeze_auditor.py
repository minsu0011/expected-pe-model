"""Freeze the production-disabled R8-r6 supplemental-auditor v2 source bundle.

This builder never launches a signer, freezes a binding, runs a live audit,
contacts an endpoint, issues authority, or generates qualification payloads.
R8-r6 compatibility blockers are deliberately preserved as terminal NO_GO.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping
import zipfile

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.canonical import (
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.command_lock import (
    build_frozen_archive_command,
    validate_disabled_r8_r6_command_lock,
    validate_frozen_archive_command,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.compatibility import (
    analyze_r8_r6_archive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.hardened_fs import (
    read_stable_plain_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.preflight import (
    scan_forbidden_phase2_identities,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v2.source_identity import (
    SourceRecord,
    build_source_identity,
    parse_source_identity,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
FREEZE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v2_attempt_r2_no_go_20260822"
)
FREEZE_ROOT = PROJECT_ROOT / FREEZE_ROOT_RELATIVE
STAGING = FREEZE_ROOT.parent / f".{FREEZE_ROOT.name}.{os.getpid()}.staging"
DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_static_design_r6_20260822"
)
DESIGN_ROOT = PROJECT_ROOT / DESIGN_ROOT_RELATIVE
R8_R6_SOURCE_ARCHIVE = DESIGN_ROOT / "SOURCE_ARCHIVE.zip"
V1_SOURCE_FREEZE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v1_20260822"
)
V1_SOURCE_FREEZE_ROOT = PROJECT_ROOT / V1_SOURCE_FREEZE_ROOT_RELATIVE
V1_REVIEW_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_pre_phase2_adversarial_review_v1_20260822"
)
V1_REVIEW_ROOT = PROJECT_ROOT / V1_REVIEW_ROOT_RELATIVE
R1_FAILURE_RECEIPT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_independent_"
    "supplemental_auditor_source_freeze_v2_attempt_r1_failure_receipt_20260822"
)
R1_FAILURE_RECEIPT_ROOT = PROJECT_ROOT / R1_FAILURE_RECEIPT_ROOT_RELATIVE
R1_FAILURE_RECEIPT_CHECKSUMS_SHA256 = (
    "c62d43f34d2527a228f7776acf205a9e31dd1bb78baf0575c64fb2079a1e2acd"
)
V1_PREDECESSOR_HASHES = {
    "review/AUDIT.json": "10a5c54f973404ce8dcbc8ccda9b331e9deecc14c1af7201a03e66e0f288a77d",
    "review/FINDINGS.json": "4694a5b7f66ca336b7c042d0458fa683a34aff8a80971a04929cd2df5484e5f6",
    "review/SEAL.json": "4ec41c7191ff04855c9473fd529c829b4f7caa8a0e2b46b350409f51acb8cb01",
    "review/CHECKSUMS.sha256": "8026dbaebe0950333557517b8bc50b687b14d27fd75c6f8953e2a7d1eae57f80",
    "source_freeze/COMMAND_LOCK.json": "55f1b52157bbaf61661926bae24e6728a65fb115d23d8f6afa6a9fd6344f473e",
    "source_freeze/CHECKSUMS.sha256": "2bb1542943122f9bfc0828e5deb90bc1d9b78bc4e1cf433f7b6f3856ef032a08",
}
REGISTRY = PROJECT_ROOT / "outputs/v04_spent_seed_registry.json"
GENERATION_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v2"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v2"
)
R1_FAILURE_RECEIPT_SCRIPT_RELATIVE = f"{SCRIPT_RELATIVE}/seal_attempt_failure_r1.py"
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v2.py"
)
SELECTED_TESTS = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v1.py",
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_supplemental_auditor_v2.py",
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r6_qualification_generation.py",
)
RUNTIME_SOURCE_NAMES = (
    "__init__.py",
    "archive_entry.py",
    "canonical.py",
    "command_lock.py",
    "compatibility.py",
    "hardened_fs.py",
    "preflight.py",
    "source_identity.py",
    "terminal.py",
    "validation.py",
)


def _source_path(relative: str) -> Path:
    path = PROJECT_ROOT / relative
    if not path.is_file():
        raise RuntimeError(f"source is unavailable: {relative}")
    return path


def _read_source(relative: str) -> bytes:
    raw, _receipt = read_stable_plain_file(
        _source_path(relative),
        root=PROJECT_ROOT,
    )
    return raw


def _runtime_sources() -> tuple[list[SourceRecord], dict[str, bytes]]:
    records: list[SourceRecord] = []
    archive_members: dict[str, bytes] = {}
    for name in RUNTIME_SOURCE_NAMES:
        source_relative = f"{PACKAGE_RELATIVE}/{name}"
        archive_member = f"auditor_v2/{name}"
        raw = _read_source(source_relative)
        records.append(
            SourceRecord(
                source_relative=source_relative,
                archive_member=archive_member,
                raw_sha256=sha256_bytes(raw),
                size_bytes=len(raw),
            )
        )
        archive_members[archive_member] = raw
    main_relative = f"{SCRIPT_RELATIVE}/archive_main.py"
    main_raw = _read_source(main_relative)
    records.append(
        SourceRecord(
            source_relative=main_relative,
            archive_member="__main__.py",
            raw_sha256=sha256_bytes(main_raw),
            size_bytes=len(main_raw),
        )
    )
    archive_members["__main__.py"] = main_raw
    return records, archive_members


def _full_source_lock(runtime_records: list[SourceRecord]) -> Mapping[str, Any]:
    runtime_by_source = {record.source_relative: record for record in runtime_records}
    relatives = [
        *(f"{PACKAGE_RELATIVE}/{name}" for name in RUNTIME_SOURCE_NAMES),
        f"{SCRIPT_RELATIVE}/archive_main.py",
        f"{SCRIPT_RELATIVE}/freeze_auditor.py",
        R1_FAILURE_RECEIPT_SCRIPT_RELATIVE,
        TEST_RELATIVE,
    ]
    rows: list[dict[str, Any]] = []
    for relative in sorted(relatives):
        raw = _read_source(relative)
        runtime = runtime_by_source.get(relative)
        if runtime is not None and (
            runtime.raw_sha256 != sha256_bytes(raw)
            or runtime.size_bytes != len(raw)
        ):
            raise RuntimeError("runtime source changed between archive and source lock")
        rows.append(
            {
                "relative_path": relative,
                "raw_sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
                "runtime_archive_member": (
                    None if runtime is None else runtime.archive_member
                ),
                "runtime_member": runtime is not None,
            }
        )
    return {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_lock.v2",
        "status": "FROZEN_SOURCE_ATTEMPT_R2_R8_R6_INCOMPATIBLE_NO_GO",
        "record_count": len(rows),
        "records": rows,
        "records_semantic_sha256": sha256_bytes(canonical_json_bytes(rows)),
    }


def _zipinfo(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _build_archive(
    *, source_identity_raw: bytes, archive_members: Mapping[str, bytes]
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        archive.writestr(_zipinfo("SOURCE_IDENTITY.json"), source_identity_raw)
        for name, raw in sorted(archive_members.items()):
            archive.writestr(_zipinfo(name), raw)
    return buffer.getvalue()


def _verify_archive(
    *, archive_raw: bytes, expected_identity: Mapping[str, Any]
) -> Mapping[str, Any]:
    with zipfile.ZipFile(io.BytesIO(archive_raw), "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("v2 archive has duplicate members")
        if any(
            name.startswith(("/", "\\")) or ".." in Path(name).parts for name in names
        ):
            raise RuntimeError("v2 archive contains an escaped member")
        identity_raw = archive.read("SOURCE_IDENTITY.json")
        identity = json.loads(identity_raw)
        if canonical_json_bytes(identity) != identity_raw:
            raise RuntimeError("v2 archive source identity is non-canonical")
        parsed = parse_source_identity(identity)
        if parsed != expected_identity:
            raise RuntimeError("freeze/runtime source identity schema diverged")
        expected_names = {"SOURCE_IDENTITY.json"}
        for record in parsed["records"]:
            member = record["archive_member"]
            raw = archive.read(member)
            if (
                len(raw) != record["size_bytes"]
                or sha256_bytes(raw) != record["raw_sha256"]
            ):
                raise RuntimeError("v2 archive member hash/size drifted")
            expected_names.add(member)
        if set(names) != expected_names:
            raise RuntimeError("v2 archive has a missing or extra member")
    return {
        "status": "PASS_ARCHIVE_REOPEN_WITH_ONE_CANONICAL_SOURCE_SCHEMA",
        "archive_raw_sha256": sha256_bytes(archive_raw),
        "archive_size_bytes": len(archive_raw),
        "member_count": len(names),
        "source_record_count": parsed["record_count"],
        "source_records_semantic_sha256": parsed["records_semantic_sha256"],
        "source_identity_raw_sha256": sha256_bytes(identity_raw),
    }


def _run(command: list[str]) -> Mapping[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=600,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout_raw_sha256": sha256_bytes(result.stdout),
        "stderr_raw_sha256": sha256_bytes(result.stderr),
        "stdout_tail": result.stdout.decode("utf-8", errors="replace")[-2000:],
        "stderr_tail": result.stderr.decode("utf-8", errors="replace")[-2000:],
    }


def _full_repository_test_snapshot() -> Mapping[str, Any]:
    return {
        "schema_version": (
            "expected_pe.r8.r6.supplemental_auditor_v2."
            "full_repository_test_snapshot.v1"
        ),
        "status": "NONPASS_BASELINE_NOT_CAUSED_BY_SUPPLEMENTAL_AUDITOR_V2",
        "collection": {
            "command": [
                "C:/Users/minsu/anaconda3/python.exe",
                "-B",
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests",
            ],
            "returncode": 0,
            "collected_test_count": 2017,
            "files_with_tests": 126,
            "elapsed_seconds_approx": 8.3,
        },
        "initial_full_run": {
            "command": [
                "C:/Users/minsu/anaconda3/python.exe",
                "-B",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests",
            ],
            "completion_status": "INTERRUPTED_AFTER_NONPASS_SNAPSHOT",
            "returncode": 1,
            "progress_percent_at_interrupt": 28,
            "first_failure_progress_percent_approx": 10,
            "failures_and_errors_observed": True,
            "full_suite_pass_claimed": False,
            "estimated_total_runtime_minutes": "20-25",
        },
        "bounded_first_three": {
            "command_suffix": ["--maxfail=3", "--tb=short", "tests"],
            "returncode": 1,
            "progress_percent_when_stopped_approx": 12,
            "elapsed_seconds_approx": 180,
            "failures": [
                {
                    "node_id": (
                        "tests/model_lab/test_dgp_suite.py::"
                        "test_dual_comparator_contract_is_exact_truth_blind_and_not_authorized"
                    ),
                    "classification": "EXISTING_SEALED_RUNTIME_ENVIRONMENT_MISMATCH",
                    "detail": (
                        "Anaconda Python 3.13.9/package versions differ from the "
                        "sealed comparator production policy."
                    ),
                },
                {
                    "node_id": (
                        "tests/model_lab/test_dgp_suite.py::"
                        "test_fixed_fixture_root_rejects_altered_price_and_self_resealed_ledgers"
                    ),
                    "classification": "EXISTING_FIXED_COMPARATOR_TRUST_ROOT_MISMATCH",
                    "detail": (
                        "Fixed comparator audit differs from the implementation trust root."
                    ),
                },
                {
                    "node_id": (
                        "tests/model_lab/test_finalize_global_integration_v2.py::"
                        "test_v2_finalizer_requires_its_distinct_exact_token"
                    ),
                    "classification": "EXISTING_OUTPUT_STATE_PRECONDITION_FAILURE",
                    "detail": (
                        "outputs/model_zoo_expected_pe_global_leaderboards_"
                        "exploration_only_v2_20260820 already exists."
                    ),
                },
            ],
        },
        "isolated_causality_repeat": {
            "selection": "THE_EXACT_THREE_NODE_IDS_ONLY",
            "supplemental_auditor_v2_test_module_collected_or_imported": False,
            "returncode": 1,
            "same_three_failures_reproduced": True,
            "elapsed_seconds_approx": 10.8,
            "conclusion": "FIRST_THREE_FAILURES_ARE_NOT_V2_IMPORT_OR_GLOBAL_STATE_EFFECTS",
        },
        "post_r2_workspace_collection_snapshot": {
            "returncode": 2,
            "partial_collected_test_count_before_collection_abort": 2041,
            "files_with_tests_before_collection_abort": 127,
            "error": (
                "pytest import-file-mismatch between concurrent TCN research_v1/"
                "test_sharded.py and research_v2/test_sharded.py"
            ),
            "classification": "CONCURRENT_UNRELATED_WORKSPACE_TEST_NAMING_COLLISION",
            "supplemental_auditor_v2_caused": False,
            "full_suite_pass_claimed": False,
        },
        "full_repository_suite_passed": False,
        "snapshot_preserved_instead_of_false_pass": True,
    }


def _predecessor_no_go_receipt() -> Mapping[str, Any]:
    paths = {
        "review/AUDIT.json": V1_REVIEW_ROOT / "AUDIT.json",
        "review/FINDINGS.json": V1_REVIEW_ROOT / "FINDINGS.json",
        "review/SEAL.json": V1_REVIEW_ROOT / "SEAL.json",
        "review/CHECKSUMS.sha256": V1_REVIEW_ROOT / "CHECKSUMS.sha256",
        "source_freeze/COMMAND_LOCK.json": V1_SOURCE_FREEZE_ROOT
        / "COMMAND_LOCK.json",
        "source_freeze/CHECKSUMS.sha256": V1_SOURCE_FREEZE_ROOT
        / "CHECKSUMS.sha256",
    }
    records: list[Mapping[str, Any]] = []
    payloads: dict[str, Any] = {}
    for label, path in sorted(paths.items()):
        raw, stable = read_stable_plain_file(path, root=PROJECT_ROOT)
        actual = sha256_bytes(raw)
        if actual != V1_PREDECESSOR_HASHES[label]:
            raise RuntimeError(f"immutable v1 predecessor drifted: {label}")
        if path.suffix == ".json":
            payload = json.loads(raw)
            if label.startswith("source_freeze/") and canonical_json_bytes(payload) != raw:
                raise RuntimeError(f"immutable v1 predecessor is non-canonical: {label}")
            payloads[label] = payload
        records.append(
            {
                "identity": label,
                "relative_path": path.relative_to(PROJECT_ROOT).as_posix(),
                "raw_sha256": actual,
                "stable_file_identity": stable,
            }
        )
    review = payloads["review/AUDIT.json"]
    if (
        review.get("verdict") != "NO_GO"
        or review.get("finding_counts") != {"P0": 2, "P1": 4, "P2": 3}
        or review.get("phase2_signer_launch_authorized") is not False
        or review.get("phase2_authority_issuance_authorized") is not False
        or review.get("phase2_qualification_generation_authorized") is not False
    ):
        raise RuntimeError("immutable v1 predecessor no longer seals decisive NO_GO")
    return {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.predecessor_no_go.v1",
        "status": "V1_SOURCE_AND_REVIEW_IMMUTABLY_PRESERVED_NO_GO",
        "v1_review_root_relative": V1_REVIEW_ROOT_RELATIVE,
        "v1_source_freeze_root_relative": V1_SOURCE_FREEZE_ROOT_RELATIVE,
        "v1_finding_counts": {"P0": 2, "P1": 4, "P2": 3},
        "phase2_launch_authorized": False,
        "record_count": len(records),
        "records": records,
    }


def _r1_failure_receipt() -> Mapping[str, Any]:
    expected_names = {
        "AUDIT.json",
        "CHECKSUMS.sha256",
        "COMMAND.json",
        "FAILURE.json",
        "REPORT.md",
        "SEAL.json",
        "SOURCE_LOCK.json",
        "ZERO_STATE.json",
    }
    if (
        not R1_FAILURE_RECEIPT_ROOT.is_dir()
        or {item.name for item in R1_FAILURE_RECEIPT_ROOT.iterdir()}
        != expected_names
    ):
        raise RuntimeError("sealed r1 failure receipt member universe drifted")
    ledger_raw, ledger_stable = read_stable_plain_file(
        R1_FAILURE_RECEIPT_ROOT / "CHECKSUMS.sha256",
        root=PROJECT_ROOT,
    )
    if sha256_bytes(ledger_raw) != R1_FAILURE_RECEIPT_CHECKSUMS_SHA256:
        raise RuntimeError("sealed r1 failure receipt checksum identity drifted")
    records: list[Mapping[str, Any]] = []
    payloads: dict[str, Any] = {}
    for row in ledger_raw.decode("ascii").splitlines():
        if len(row) < 67 or row[64:66] != "  ":
            raise RuntimeError("sealed r1 failure receipt ledger is malformed")
        digest = row[:64]
        name = row[66:]
        if name == "CHECKSUMS.sha256" or name not in expected_names:
            raise RuntimeError("sealed r1 failure receipt ledger member drifted")
        raw, stable = read_stable_plain_file(
            R1_FAILURE_RECEIPT_ROOT / name,
            root=PROJECT_ROOT,
        )
        if sha256_bytes(raw) != digest:
            raise RuntimeError("sealed r1 failure receipt member hash drifted")
        if name.endswith(".json"):
            payload = json.loads(raw)
            if canonical_json_bytes(payload) != raw:
                raise RuntimeError("sealed r1 failure receipt JSON is non-canonical")
            payloads[name] = payload
        records.append(
            {
                "relative_path": name,
                "raw_sha256": digest,
                "size_bytes": len(raw),
                "stable_file_identity": stable,
            }
        )
    if {record["relative_path"] for record in records} != expected_names - {
        "CHECKSUMS.sha256"
    }:
        raise RuntimeError("sealed r1 failure receipt ledger coverage drifted")
    audit = payloads["AUDIT.json"]
    zero = payloads["ZERO_STATE.json"]
    if (
        audit.get("verdict") != "NO_GO"
        or audit.get("r1_retry_authorized") is not False
        or zero.get("source_freeze_publication_count") != 0
        or zero.get("signer_launch_count") != 0
        or zero.get("production_supplemental_audit_count") != 0
    ):
        raise RuntimeError("sealed r1 failure receipt authorization state drifted")
    return {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.r1_failure_predecessor.v1",
        "status": "SEALED_R1_FAILURE_NO_GO_REQUIRED_PREDECESSOR_FOR_R2",
        "root_relative": R1_FAILURE_RECEIPT_ROOT_RELATIVE,
        "checksums_raw_sha256": R1_FAILURE_RECEIPT_CHECKSUMS_SHA256,
        "checksums_stable_file_identity": ledger_stable,
        "record_count": len(records),
        "records": records,
        "r1_retry_authorized": False,
        "r2_source_freeze_only_authorized": True,
        "phase2_execution_authorized": False,
    }


def _quality(*, full_repository_snapshot_raw_sha256: str) -> Mapping[str, Any]:
    pytest_receipt = _run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            *SELECTED_TESTS,
        ]
    )
    collection_receipt = _run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            *SELECTED_TESTS,
        ]
    )
    ruff_receipt = _run(
        [
            sys.executable,
            "-B",
            "-m",
            "ruff",
            "check",
            PACKAGE_RELATIVE,
            SCRIPT_RELATIVE,
            TEST_RELATIVE,
        ]
    )
    collected_count = sum(
        int(line.rsplit(":", maxsplit=1)[1].strip())
        for line in collection_receipt["stdout_tail"].splitlines()
        if line.rsplit(":", maxsplit=1)[-1].strip().isdigit()
    )
    if (
        pytest_receipt["returncode"] != 0
        or collection_receipt["returncode"] != 0
        or collected_count != 80
        or ruff_receipt["returncode"] != 0
    ):
        raise RuntimeError("v2 source quality gate failed")
    return {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.quality.v1",
        "status": "PASS_SCOPED_V2_GATES_FULL_REPOSITORY_BASELINE_NONPASS",
        "pytest": pytest_receipt,
        "pytest_collection": collection_receipt,
        "selected_test_case_count": collected_count,
        "ruff": ruff_receipt,
        "original_v1_finding_reproduction_and_v2_rejection_pair_count": 9,
        "supplemental_auditor_v2_test_case_count": 39,
        "full_repository_suite_status": "NONPASS_NOT_V2_CAUSED",
        "full_repository_test_snapshot_raw_sha256": (
            full_repository_snapshot_raw_sha256
        ),
        "full_repository_suite_pass_claimed": False,
        "real_signer_test_count": 0,
        "real_binding_test_count": 0,
        "production_audit_test_count": 0,
        "authority_generation_truth_test_count": 0,
    }


def _boundary() -> Mapping[str, Any]:
    binding = OUTPUTS_ROOT / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_"
        "r8_r6_supervised_signer_binding_20260822"
    )
    supplemental = OUTPUTS_ROOT / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
        "independent_signer_binding_supplemental_audit_r6_20260822"
    )
    blackhole = OUTPUTS_ROOT / ".expected_pe_r8_r6_bytecode_blackhole_DO_NOT_CREATE"
    preflight = scan_forbidden_phase2_identities(OUTPUTS_ROOT)
    freeze_staging_names = sorted(
        item.name
        for item in OUTPUTS_ROOT.iterdir()
        if item.name.startswith(f".{FREEZE_ROOT.name}.")
        and item.name.endswith(".staging")
    )
    registry_raw, registry_receipt = read_stable_plain_file(
        REGISTRY,
        root=PROJECT_ROOT,
    )
    design_checksums_raw, design_checksums_receipt = read_stable_plain_file(
        DESIGN_ROOT / "CHECKSUMS.sha256",
        root=PROJECT_ROOT,
    )
    source_archive_raw, source_archive_receipt = read_stable_plain_file(
        R8_R6_SOURCE_ARCHIVE,
        root=PROJECT_ROOT,
    )
    return {
        "binding_root_present": binding.exists(),
        "production_supplemental_root_present": supplemental.exists(),
        "bytecode_blackhole_present": blackhole.exists(),
        "phase2_forbidden_identity_count": preflight["forbidden_identity_count"],
        "phase2_forbidden_identities": preflight["forbidden_identities"],
        "force_inclusive_phase2_preflight": preflight,
        "source_freeze_staging_identities": freeze_staging_names,
        "registry_raw_sha256": sha256_bytes(registry_raw),
        "registry_stable_file_identity": registry_receipt,
        "r8_r6_design_checksums_raw_sha256": sha256_bytes(design_checksums_raw),
        "r8_r6_design_checksums_stable_file_identity": design_checksums_receipt,
        "r8_r6_source_archive_raw_sha256": sha256_bytes(source_archive_raw),
        "r8_r6_source_archive_stable_file_identity": source_archive_receipt,
    }


def _minimum_r7_delta() -> Mapping[str, Any]:
    return {
        "schema_version": "expected_pe.r8.r7.minimum_delta_for_supplemental_v2.v1",
        "status": "REQUIRED_BEFORE_ANY_NEW_PHASE2_LAUNCH",
        "preferred_process_and_job_design": {
            "auditor_runtime": "FROZEN_STANDALONE_PYZ_LIVE_PACKAGE_IMPORT_ZERO",
            "archive_custody": (
                "SUPERVISOR_HOLDS_CREATEFILEW_NO_SHARE_WRITE_DELETE_HANDLE_"
                "AND_RECHECKS_FILE_ID_HASH_BEFORE_AFTER"
            ),
            "auditor_launch": "SUPERVISOR_LAUNCHES_AUDITOR_AS_EXPLICIT_CHILD",
            "exact_job_witness": (
                "INHERITED_OR_DUPLICATED_QUERY_ONLY_HANDLE_TO_THE_EXACT_"
                "SUPERVISOR_OWNED_JOB"
            ),
            "launch_time_assignment": "PROC_THREAD_ATTRIBUTE_JOB_LIST",
            "job_checks": [
                "IsProcessInJob(signer, exact_non_null_job_handle)",
                "QueryInformationJobObject extended limit includes KILL_ON_JOB_CLOSE",
                "basic process ID list contains the exact signer creation-time identity",
                "supervisor retains the lifetime-owning handle",
            ],
            "named_job_fallback": (
                "NOT_PREFERRED_BECAUSE_A_THIRD_HANDLE_CAN_EXTEND_KILL_ON_LAST_CLOSE_CUSTODY"
            ),
        },
        "required_schema_changes": {
            "readiness_binding_telemetry": [
                "signer_creation_time_100ns",
                "supervisor_creation_time_100ns",
                "signer_image_path",
                "signer_image_raw_sha256",
                "signer_image_volume_serial_number",
                "signer_image_file_id_128",
                "supervisor_image_path",
                "supervisor_image_raw_sha256",
                "supervisor_image_volume_serial_number",
                "supervisor_image_file_id_128",
                "signer_command_line_sha256",
                "supervisor_command_line_sha256",
                "signer_source_identity_sha256",
                "supervisor_source_identity_sha256",
                "job_identity_sha256",
                "job_limit_flags",
                "job_active_process_count",
                "signer_pid_listed_by_exact_job",
                "auditor_inherited_or_duplicated_job_query_handle_witness",
            ],
            "supplemental_audit_seal_claim_authority": [
                "supplemental_auditor_archive_raw_sha256",
                "supplemental_auditor_source_identity_raw_sha256",
                "supplemental_auditor_source_records_semantic_sha256",
                "supplemental_auditor_command_lock_raw_sha256",
                "supplemental_auditor_source_freeze_checksums_raw_sha256",
                "signer_binding_raw_sha256",
                "supplemental_audit_json_raw_sha256",
                "supplemental_audit_seal_raw_sha256",
            ],
        },
        "required_consumer_changes": [
            "immediate issuance rejects any missing or unequal v2 source/command/process/audit/seal field before PING",
            "signer claim validation independently reopens and enforces every exact field before signing",
            "authority authentication preserves and revalidates the same fields before generation",
            "original R8-r6 issuance CLI cannot accept the R8-r7 schema or bypass the new gate",
        ],
        "required_filesystem_and_time_changes": [
            "all lexical path components and ancestors reparse-free",
            "GetFileInformationByHandleEx volume/file ID and hash stable before/after",
            "FILE_ID_INFO volume serial plus 128-bit FileId is authoritative; pathname/handle mode and mtime are diagnostics only",
            "GetProcessTimes creation FILETIME stable on held process handles",
            "strict heartbeat increase across two snapshots with age at most five seconds",
            "zero request/signature counters in both snapshots",
            "final process/job/path/counter/expiry snapshot no more than one second before GO publication",
            "heartbeat age is at most five seconds at publication, not merely at final read",
            "at least thirty seconds expiry margin",
            "all post-consumption exceptions publish canonical immutable NO_GO",
            "force-inclusive file/directory scan covers hidden vault, journal, and staging identities",
        ],
        "official_win32_references": [
            "https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob",
            "https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute",
            "https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects",
            "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes",
            "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex",
        ],
    }


def _v1_regression_matrix() -> Mapping[str, Any]:
    rows = [
        {
            "v1_finding_id": "P0-001",
            "v1_reproduction": "frozen/runtime source-schema hashes differ and arbitrary source identity is downstream-accepted",
            "v2_rejection": "one exact canonical source schema plus archive member/hash and command identity enforcement",
        },
        {
            "v1_finding_id": "P0-002",
            "v1_reproduction": "PID plus any-job plus shared-Python-image evidence passes",
            "v2_rejection": "creation times, command/source, image file IDs, exact inherited job handle, limit and PID-list evidence required",
        },
        {
            "v1_finding_id": "P1-001",
            "v1_reproduction": "v1 inspects only resolved target and has no lexical ancestor/file-ID custody",
            "v2_rejection": "every lexical ancestor to volume anchor is reparse-free and device/file IDs are stable before/after",
        },
        {
            "v1_finding_id": "P1-002",
            "v1_reproduction": "synthetic v1 GO seals heartbeat 61 to 61",
            "v2_rejection": "final heartbeat sequence must strictly increase",
        },
        {
            "v1_finding_id": "P1-003",
            "v1_reproduction": "synthetic v1 GO generated after binding expiry",
            "v2_rejection": "final snapshot publication delay at most one second, heartbeat fresh at publication, expiry margin at least thirty seconds",
        },
        {
            "v1_finding_id": "P1-004",
            "v1_reproduction": "frozen v1 command uses non-isolated -B -m mutable workspace import",
            "v2_rejection": "exact -I -S -B -E frozen-archive-only command; R8-r6 command lock remains disabled",
        },
        {
            "v1_finding_id": "P2-001",
            "v1_reproduction": "synthetic precheck exception leaves no terminal NO_GO root",
            "v2_rejection": "future wrapper converts post-consumption operation exceptions to canonical no-overwrite NO_GO",
        },
        {
            "v1_finding_id": "P2-002",
            "v1_reproduction": "synthetic v1 NO_GO with forbidden generation identity still labels zero-access PASS",
            "v2_rejection": "zero-access status is derived from the actual probe result",
        },
        {
            "v1_finding_id": "P2-003",
            "v1_reproduction": "v1 runbook preflight omits -Force, vault and journal identities",
            "v2_rejection": "os.scandir force-inclusive files/directories covers public, vault, journal, binding and staging identities",
        },
    ]
    return {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.v1_regression_matrix.v1",
        "status": "NINE_OF_NINE_V1_FINDINGS_REPRODUCED_AND_PAIRED",
        "pair_count": len(rows),
        "synthetic_or_static_only": True,
        "live_phase2_execution_count": 0,
        "rows": rows,
    }


def _write_new(path: Path, raw: bytes) -> str:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return sha256_bytes(raw)


def _verify_published_freeze(
    *, root: Path, artifacts: Mapping[str, bytes], ledger_raw: bytes
) -> Mapping[str, Any]:
    expected_names = set(artifacts) | {"CHECKSUMS.sha256"}
    actual_names = {member.name for member in root.iterdir()}
    if actual_names != expected_names:
        raise RuntimeError("published v2 source-freeze member universe drifted")
    stable_receipts: list[Mapping[str, Any]] = []
    for name, expected_raw in sorted(
        {**artifacts, "CHECKSUMS.sha256": ledger_raw}.items()
    ):
        actual_raw, stable = read_stable_plain_file(
            root / name,
            root=PROJECT_ROOT,
        )
        if actual_raw != expected_raw:
            raise RuntimeError(f"published v2 source-freeze member drifted: {name}")
        if name.endswith(".json"):
            parsed = json.loads(actual_raw)
            if canonical_json_bytes(parsed) != actual_raw:
                raise RuntimeError(f"published v2 JSON is non-canonical: {name}")
        stable_receipts.append(stable)
    expected_ledger = "".join(
        f"{sha256_bytes(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("ascii")
    if ledger_raw != expected_ledger:
        raise RuntimeError("published v2 source-freeze checksum ledger drifted")
    command_lock = json.loads(artifacts["COMMAND_LOCK.json"])
    validate_disabled_r8_r6_command_lock(command_lock)
    return {
        "status": "PASS_EXACT_STABLE_REOPEN",
        "member_count": len(expected_names),
        "checksums_raw_sha256": sha256_bytes(ledger_raw),
        "stable_file_receipts_semantic_sha256": sha256_bytes(
            canonical_json_bytes(stable_receipts)
        ),
        "all_ancestors_reparse_free": True,
        "all_member_volume_file_ids_stable_before_after": True,
    }


def freeze() -> Mapping[str, Any]:
    if FREEZE_ROOT.exists() or STAGING.exists():
        raise RuntimeError("v2 source-freeze identity already exists")
    before = _boundary()
    if (
        before["binding_root_present"]
        or before["production_supplemental_root_present"]
        or before["bytecode_blackhole_present"]
        or before["phase2_forbidden_identity_count"] != 0
        or before["source_freeze_staging_identities"]
    ):
        raise RuntimeError("Phase 2 boundary is not pristine")
    predecessor_before = _predecessor_no_go_receipt()
    predecessor_before_raw = canonical_json_bytes(predecessor_before)
    r1_failure_before = _r1_failure_receipt()
    r1_failure_before_raw = canonical_json_bytes(r1_failure_before)
    full_repository_snapshot = _full_repository_test_snapshot()
    full_repository_snapshot_raw = canonical_json_bytes(full_repository_snapshot)
    quality = _quality(
        full_repository_snapshot_raw_sha256=sha256_bytes(
            full_repository_snapshot_raw
        )
    )
    runtime_records, archive_members = _runtime_sources()
    source_identity = build_source_identity(runtime_records)
    source_identity_raw = canonical_json_bytes(source_identity)
    archive_raw = _build_archive(
        source_identity_raw=source_identity_raw,
        archive_members=archive_members,
    )
    archive_reopen = _verify_archive(
        archive_raw=archive_raw,
        expected_identity=source_identity,
    )
    compatibility = analyze_r8_r6_archive(R8_R6_SOURCE_ARCHIVE)
    if compatibility.compatible or not compatibility.blockers:
        raise RuntimeError("R8-r6 unexpectedly appeared compatible; independent review required")
    executable_raw, executable_stable_receipt = read_stable_plain_file(
        GENERATION_PYTHON,
        root=Path(GENERATION_PYTHON.anchor),
    )
    future_archive_path = str((FREEZE_ROOT / "AUDITOR.pyz").resolve(strict=False))
    archive_command = build_frozen_archive_command(
        python_executable=str(GENERATION_PYTHON),
        python_executable_raw_sha256=sha256_bytes(executable_raw),
        archive_path=future_archive_path,
        archive_raw_sha256=sha256_bytes(archive_raw),
        source_records_semantic_sha256=source_identity[
            "records_semantic_sha256"
        ],
    )
    validate_frozen_archive_command(
        archive_command,
        python_executable=str(GENERATION_PYTHON),
        python_executable_raw_sha256=sha256_bytes(executable_raw),
        archive_path=future_archive_path,
        archive_raw_sha256=sha256_bytes(archive_raw),
        source_records_semantic_sha256=source_identity[
            "records_semantic_sha256"
        ],
    )
    command_lock = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.command_lock.v2",
        "status": "DISABLED_R8_R7_REQUIRED",
        "production_execution_allowed": False,
        "production_command": None,
        "signer_launch_allowed": False,
        "binding_freeze_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
        "truth_vault_heldout_access_allowed": False,
        "self_go_audit_allowed": False,
        "frozen_archive_relative": f"{FREEZE_ROOT_RELATIVE}/AUDITOR.pyz",
        "frozen_archive_raw_sha256": sha256_bytes(archive_raw),
        "python_executable": str(GENERATION_PYTHON),
        "python_executable_raw_sha256": sha256_bytes(executable_raw),
        "source_identity_raw_sha256": sha256_bytes(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "python_executable_stable_file_identity": executable_stable_receipt,
        "disabled_archive_verification_command_not_authorized_for_execution": archive_command,
        "mutable_live_package_import_allowed": False,
        "source_freeze_checksums_self_pin_impossible_requires_external_anchor": True,
        "source_freeze_attempt_id": "R2_AFTER_SEALED_R1_FAILURE",
        "predecessor_r1_failure_receipt_checksums_raw_sha256": (
            R1_FAILURE_RECEIPT_CHECKSUMS_SHA256
        ),
        "r8_r7_downstream_exact_pin_fields_required": [
            "supplemental_auditor_archive_raw_sha256",
            "supplemental_auditor_source_identity_raw_sha256",
            "supplemental_auditor_source_records_semantic_sha256",
            "supplemental_auditor_command_lock_raw_sha256",
            "supplemental_auditor_source_freeze_checksums_raw_sha256",
            "supplemental_audit_json_raw_sha256",
            "supplemental_audit_seal_raw_sha256",
        ],
        "minimum_compatible_revision": "R8_R7",
    }
    validate_disabled_r8_r6_command_lock(command_lock)
    source_lock = _full_source_lock(runtime_records)
    blockers = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.compatibility.v1",
        "status": "NO_GO_R8_R7_REQUIRED",
        **compatibility.as_mapping(),
        "phase2_signer_launch_authorized": False,
        "phase2_authority_issuance_authorized": False,
        "phase2_generation_authorized": False,
    }
    minimum_delta = _minimum_r7_delta()
    v1_regression_matrix = _v1_regression_matrix()
    after_analysis = _boundary()
    predecessor_after_analysis = _predecessor_no_go_receipt()
    r1_failure_after_analysis = _r1_failure_receipt()
    if before != after_analysis:
        raise RuntimeError("Phase 2 boundary changed during v2 source analysis")
    if predecessor_before != predecessor_after_analysis:
        raise RuntimeError("immutable v1 predecessor changed during v2 source analysis")
    if r1_failure_before != r1_failure_after_analysis:
        raise RuntimeError("immutable r1 failure receipt changed during r2 source analysis")
    self_check = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor_v2.self_check.v1",
        "status": "PASS_SOURCE_FREEZE_ATTEMPT_R2_ONLY_NO_SELF_GO_AUDIT",
        "archive_reopen": archive_reopen,
        "canonical_source_identity_equal_freeze_runtime_consumer": True,
        "original_v1_finding_regression_pair_count": v1_regression_matrix[
            "pair_count"
        ],
        "compatibility_blocker_count": len(compatibility.blockers),
        "full_repository_suite_passed": False,
        "full_repository_nonpass_first_three_v2_caused": False,
        "predecessor_v1_no_go_preserved": True,
        "predecessor_v1_no_go_receipt_raw_sha256": sha256_bytes(
            predecessor_before_raw
        ),
        "predecessor_r1_failure_receipt_preserved": True,
        "predecessor_r1_failure_receipt_raw_sha256": sha256_bytes(
            r1_failure_before_raw
        ),
        "source_freeze_attempt_id": "R2_AFTER_SEALED_R1_FAILURE",
        "production_execution_allowed": False,
        "self_go_audit_count": 0,
        "real_signer_launch_count": 0,
        "real_binding_freeze_count": 0,
        "production_supplemental_audit_count": 0,
        "signer_endpoint_contact_count": 0,
        "authority_issuance_count": 0,
        "qualification_generation_count": 0,
        "fresh_truth_heldout_access_count": 0,
        "phase2_boundary_before": before,
        "phase2_boundary_after_analysis": after_analysis,
    }
    report = (
        "# R8-r6 supplemental-auditor v2 source-freeze attempt r2\n\n"
        "Status: **FROZEN ATTEMPT R2 NO_GO — R8-r7 REQUIRED**.\n\n"
        "The fail-closed r1 attempt is separately sealed and is not retried or reused. "
        "This is a source/command freeze only. No self-GO audit or live Phase 2 command "
        "was executed. The standalone archive imports no mutable live package, uses one "
        "canonical source-identity schema, and contains strict path/process/job/heartbeat "
        "validators. It remains production-disabled because the immutable R8-r6 binding, "
        "signer, immediate issuance, and authority consumers cannot enforce the required "
        "v2 identity, process creation times, or exact Job Object witness.\n\n"
        "The scoped v1/v2/generation tests and Ruff gate passed. The 2,017-test "
        "full-repository run is explicitly not reported as PASS: a bounded snapshot "
        "reproduced three pre-existing environment/state failures even when the v2 "
        "test module was excluded.\n\n"
        "The preferred R8-r7 design gives a supervisor-launched standalone auditor a "
        "query-only inherited/duplicated handle to the exact supervisor-owned job while "
        "the supervisor retains the lifetime-owning handle. A named job is not preferred "
        "because a third handle can extend kill-on-last-close custody.\n"
    ).encode("utf-8")
    artifacts: dict[str, bytes] = {
        "AUDITOR.pyz": archive_raw,
        "COMMAND_LOCK.json": canonical_json_bytes(command_lock),
        "COMPATIBILITY_BLOCKERS.json": canonical_json_bytes(blockers),
        "FULL_REPOSITORY_TEST_SNAPSHOT.json": full_repository_snapshot_raw,
        "MINIMUM_R8_R7_DELTA.json": canonical_json_bytes(minimum_delta),
        "PREDECESSOR_V1_NO_GO.json": predecessor_before_raw,
        "PREDECESSOR_R1_FAILURE_NO_GO.json": r1_failure_before_raw,
        "QUALITY_RECEIPT.json": canonical_json_bytes(quality),
        "REPORT.md": report,
        "SELF_CHECK.json": canonical_json_bytes(self_check),
        "SOURCE_IDENTITY.json": source_identity_raw,
        "SOURCE_LOCK.json": canonical_json_bytes(source_lock),
        "V1_REGRESSION_MATRIX.json": canonical_json_bytes(v1_regression_matrix),
    }
    seal_records = [
        {
            "relative_path": name,
            "raw_sha256": sha256_bytes(raw),
            "size_bytes": len(raw),
        }
        for name, raw in sorted(artifacts.items())
    ]
    seal = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_seal.v2",
        "status": "SEALED_SOURCE_FREEZE_ATTEMPT_R2_NO_GO_R8_R7_REQUIRED",
        "source_freeze_attempt_id": "R2_AFTER_SEALED_R1_FAILURE",
        "finding_counts": {"P0": 5, "P1": 1, "P2": 0},
        "production_execution_allowed": False,
        "self_go_audit_allowed": False,
        "signer_launch_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
        "frozen_archive_raw_sha256": sha256_bytes(archive_raw),
        "source_identity_raw_sha256": sha256_bytes(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "file_records": seal_records,
    }
    artifacts["SEAL.json"] = canonical_json_bytes(seal)
    manifest_records = [
        {
            "relative_path": name,
            "raw_sha256": sha256_bytes(raw),
            "size_bytes": len(raw),
        }
        for name, raw in sorted(artifacts.items())
    ]
    manifest = {
        "schema_version": "expected_pe.r8.r6.supplemental_auditor.source_freeze_manifest.v2",
        "status": "FROZEN_ATTEMPT_R2_NO_GO_R8_R7_REQUIRED",
        "source_freeze_attempt_id": "R2_AFTER_SEALED_R1_FAILURE",
        "freeze_root_relative": FREEZE_ROOT_RELATIVE,
        "record_count": len(manifest_records),
        "records": manifest_records,
        "production_execution_allowed": False,
        "self_go_audit_count": 0,
    }
    artifacts["MANIFEST.json"] = canonical_json_bytes(manifest)
    STAGING.mkdir(parents=False, exist_ok=False)
    for name, raw in sorted(artifacts.items()):
        _write_new(STAGING / name, raw)
    ledger_raw = "".join(
        f"{sha256_bytes(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("ascii")
    ledger_hash = _write_new(STAGING / "CHECKSUMS.sha256", ledger_raw)
    staging_reopen = _verify_published_freeze(
        root=STAGING,
        artifacts=artifacts,
        ledger_raw=ledger_raw,
    )
    os.replace(STAGING, FREEZE_ROOT)
    final_reopen = _verify_published_freeze(
        root=FREEZE_ROOT,
        artifacts=artifacts,
        ledger_raw=ledger_raw,
    )
    final_boundary = _boundary()
    if final_boundary != before:
        raise RuntimeError("Phase 2 boundary changed during source-freeze publication")
    if _predecessor_no_go_receipt() != predecessor_before:
        raise RuntimeError("immutable v1 predecessor changed during source-freeze publication")
    if _r1_failure_receipt() != r1_failure_before:
        raise RuntimeError("immutable r1 failure receipt changed during r2 publication")
    return {
        "status": "FROZEN_SOURCE_ATTEMPT_R2_ONLY_NO_GO_R8_R7_REQUIRED",
        "root": str(FREEZE_ROOT),
        "source_freeze_attempt_id": "R2_AFTER_SEALED_R1_FAILURE",
        "checksums_raw_sha256": ledger_hash,
        "archive_raw_sha256": sha256_bytes(archive_raw),
        "source_identity_raw_sha256": sha256_bytes(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "staging_reopen_status": staging_reopen["status"],
        "final_reopen_status": final_reopen["status"],
        "compatibility_blocker_count": len(compatibility.blockers),
        "production_execution_allowed": False,
        "self_go_audit_count": 0,
    }


def main() -> int:
    if sys.argv != [
        sys.argv[0],
        "--freeze-production-disabled-v2-source-attempt-r2-after-sealed-r1-failure",
    ]:
        return 64
    result = freeze()
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
