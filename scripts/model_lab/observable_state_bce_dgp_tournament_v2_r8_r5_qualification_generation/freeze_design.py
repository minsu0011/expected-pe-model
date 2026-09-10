"""Freeze the score-free R8 repair design; never activate generation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for value in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.contracts import (  # noqa: E402
    AUDITOR_KEY_ID,
    AUDITOR_POSSESSION_CHALLENGE,
    AUDITOR_POSSESSION_SIGNATURE_HEX,
    AUDITOR_PUBLIC_KEY_HEX,
    BYTECODE_BLACKHOLE_RELATIVE,
    DESIGN_ROOT,
    DESIGN_ROOT_RELATIVE,
    DGPS,
    EXTERNAL_ANCHOR_RELATIVE,
    EXACT_CHILD_ENVIRONMENT,
    HELDOUT_SEEDS,
    QUALIFICATION_SEEDS,
    R7_DESIGN_CHECKSUMS_RAW_SHA256,
    R7_DESIGN_ROOT_RELATIVE,
    REGISTRY_RAW_SHA256,
    SIGNER_READINESS_RAW_SHA256,
    SIGNER_READINESS_RELATIVE,
    SIGNER_READINESS_ROOT_RELATIVE,
    SIGNER_SERVICE_RAW_SHA256,
    SIGNER_SERVICE_RELATIVE,
    TEST_RELATIVE,
    canonical_json_bytes,
    require_registry_snapshot,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.authority import (  # noqa: E402
    verify_ed25519,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.resource import (  # noqa: E402
    memory_status_gib,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.publication import (  # noqa: E402
    durably_fsync_tree,
    fsync_directory,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.runtime_tcb import (  # noqa: E402
    capture_runtime_tcb,
    verify_complete_runtime_tcb,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.scheduler import (  # noqa: E402
    admit_scheduler,
    benchmark_isolated_children,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.source_custody import (  # noqa: E402
    capture_source_lock,
    source_archive_bytes,
    verify_source_archive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_signer_service.custody_service import (  # noqa: E402
    load_readiness,
    ping_service,
)


BASE_QUALITY_PYTHON = Path("C:/Users/minsu/anaconda3/python.exe")
EXPECTED_RUNTIME_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
LAUNCHER_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/external_launcher.py"
)
ISSUANCE_LAUNCHER_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/issuance_launch.py"
)
RUNTIME_STARTUP_PROBE_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/runtime_startup_probe.py"
)
R1_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_20260821"
)
R1_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "a419df279f4daa986db449b0923db37ae5ffbdd1824c4de7121ef21b8f62f8f1"
)
R1_EXTERNAL_ANCHOR_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_20260821.json"
)
R1_EXTERNAL_ANCHOR_RAW_SHA256 = (
    "7b5a5827aa27e1ff807bed3c949a12effcda19b1c69cad65e1876b44a6d7e1b0"
)
R2_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r2_20260821"
)
R2_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "ae94d41b089810413949e62a478b3e37661d73defe77c4f4a64d83a6cc74f634"
)
R2_EXTERNAL_ANCHOR_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_r2_20260821.json"
)
R2_EXTERNAL_ANCHOR_RAW_SHA256 = (
    "46f81a65e9ec4307df5a954479cf2359419ba60a7ba7a5b52848436f76c7ab8a"
)
R2_FAILED_NEGATIVE_STAGING_RELATIVE = (
    "outputs/.model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_builder_frozen_negative_checks_r2_20260821.staging"
)
R3_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r3_20260821"
)
R3_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "ed46581164a80c115226e9f7b4dcc532ec6a3e85d8190b6956327ff183e715dd"
)
R3_EXTERNAL_ANCHOR_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_r3_20260821.json"
)
R3_EXTERNAL_ANCHOR_RAW_SHA256 = (
    "90602bee1fd5d3a269de892dec798f3e619b0c6321901c5c1a347938431d4f9b"
)
R3_FAILED_NEGATIVE_STAGING_RELATIVE = (
    "outputs/.model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_builder_frozen_negative_checks_r3_20260821.staging"
)
R4_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r4_20260821"
)
R4_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "496c8f778373aa827985430bb761710f07bdd0674716d4547565918e076d9b8c"
)
R4_EXTERNAL_ANCHOR_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_r4_20260821.json"
)
R4_EXTERNAL_ANCHOR_RAW_SHA256 = (
    "8ac1851a5485b1dc92de4910081f361d21819c90f75faa6e74a7e3fbc1e454ad"
)
R4_AUDIT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
    "independent_qualification_pre_generation_audit_r4_20260821"
)
R4_AUDIT_CHECKSUMS_RAW_SHA256 = (
    "107c07abf796b24e28cdcb7dfece17d201431f83e01b4d4fd7caf53ebc7be333"
)
R4_AUDIT_JSON_RAW_SHA256 = (
    "e83960d173c4909ac4a7d82955f6c2d3c617fd8277324218765dfdc738962646"
)
R4_AUDIT_SEAL_RAW_SHA256 = (
    "e72ef3292c3b50ef3ec8532aafbdce817660ecb881e2d6ed2846756f9d22ed9f"
)
R4_ISSUANCE_FAILURE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
    "independent_capability_issuance_failure_r4_20260821"
)
R4_ISSUANCE_FAILURE_CHECKSUMS_RAW_SHA256 = (
    "839ee2dc9e244829795315202348d317775d2a1d6aeadc6933903b92629dd205"
)


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes(value)


def _sealed(value: Mapping[str, Any]) -> bytes:
    payload = dict(value)
    payload["manifest_sha256"] = sha256_bytes(_canonical(payload))
    return _canonical(payload)


def _file_record(path: Path) -> Mapping[str, Any]:
    raw = path.resolve(strict=True).read_bytes()
    return {
        "path": path.resolve(strict=True).as_posix(),
        "raw_sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _run(command: Sequence[str], *, environment: Mapping[str, str]) -> Mapping[str, Any]:
    completed = subprocess.run(
        list(command),
        cwd=PROJECT_ROOT,
        env=dict(environment),
        capture_output=True,
        check=False,
        timeout=7_200,
    )
    return {
        "command": list(command),
        "cwd": PROJECT_ROOT.as_posix(),
        "environment_overrides": {
            key: environment[key]
            for key in ("PYTHONDONTWRITEBYTECODE", "PYTHONPATH")
            if key in environment
        },
        "returncode": completed.returncode,
        "stdout_raw_sha256": sha256_bytes(completed.stdout),
        "stderr_raw_sha256": sha256_bytes(completed.stderr),
        "stdout_size_bytes": len(completed.stdout),
        "stderr_size_bytes": len(completed.stderr),
        "stdout_tail": completed.stdout[-4_000:].decode("utf-8", errors="replace"),
        "stderr_tail": completed.stderr[-4_000:].decode("utf-8", errors="replace"),
    }


def _quality_receipt() -> Mapping[str, Any]:
    if not BASE_QUALITY_PYTHON.is_file():
        raise RuntimeError("base quality Python is absent")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    with tempfile.TemporaryDirectory(prefix="r8_quality_") as temporary_text:
        receipt_path = Path(temporary_text) / "pytest_receipt.json"
        environment["EXPECTED_PE_R8_PYTEST_RECEIPT"] = str(receipt_path)
        tests = [
            TEST_RELATIVE,
            "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r6_transaction.py",
            (
                "tests/model_lab/"
                "test_observable_state_bce_dgp_tournament_v2_r6_qualification_generation.py"
            ),
        ]
        pytest_command = [
            str(BASE_QUALITY_PYTHON),
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            (
                "scripts.model_lab.observable_state_bce_dgp_tournament_v2_"
                "r8_r5_qualification_generation.pytest_receipt_plugin"
            ),
            *tests,
        ]
        pytest_run = _run(pytest_command, environment=environment)
        if pytest_run["returncode"] != 0 or not receipt_path.is_file():
            raise RuntimeError(f"R8 cache-disabled pytest failed: {pytest_run}")
        machine = json.loads(receipt_path.read_bytes())
        if (
            machine["exitstatus"] != 0
            or machine["collected_item_count"] != machine["executed_item_count"]
            or machine["passed_item_count"] != machine["executed_item_count"]
            or machine["failed_item_count"] != 0
        ):
            raise RuntimeError("R8 machine-readable pytest counts differ")
        ruff_command = [
            str(BASE_QUALITY_PYTHON),
            "-B",
            "-m",
            "ruff",
            "check",
            (
                "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
                "r8_r5_qualification_generation"
            ),
            (
                "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
                "r8_r5_qualification_generation"
            ),
            TEST_RELATIVE,
            "--output-format",
            "concise",
        ]
        ruff_run = _run(ruff_command, environment=environment)
        if ruff_run["returncode"] != 0:
            raise RuntimeError(f"R8 Ruff failed: {ruff_run}")
    payload = {
        "schema_version": "expected_pe.r8.quality_receipt.v1",
        "status": "PASS_CACHE_DISABLED_FOCUSED_AND_REGRESSION_QUALITY",
        "quality_python": _file_record(BASE_QUALITY_PYTHON),
        "pytest": pytest_run,
        "pytest_machine_receipt": machine,
        "ruff": ruff_run,
        "pytest_cache_provider_disabled": True,
        "bytecode_writes_disabled": True,
        "collected_item_count": machine["collected_item_count"],
        "executed_item_count": machine["executed_item_count"],
        "passed_item_count": machine["passed_item_count"],
        "failed_item_count": machine["failed_item_count"],
    }
    payload["receipt_semantic_sha256"] = sha256_bytes(_canonical(payload))
    return payload


def _runtime_startup_preflight(
    runtime: Mapping[str, Any], source_lock: Mapping[str, Any]
) -> Mapping[str, Any]:
    runtime_raw = _canonical(runtime)
    source_raw = _canonical(source_lock)
    allowed = {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update(EXACT_CHILD_ENVIRONMENT)
    blackhole = (PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE).resolve(strict=False)
    with tempfile.TemporaryDirectory(prefix="r8_native_startup_") as temporary_text:
        temporary = Path(temporary_text)
        runtime_path = temporary / "RUNTIME_TCB.json"
        source_path = temporary / "SOURCE_LOCK.json"
        _write(runtime_path, runtime_raw)
        _write(source_path, source_raw)
        command = [
            str(EXPECTED_RUNTIME_PYTHON),
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={blackhole}",
            str(PROJECT_ROOT / RUNTIME_STARTUP_PROBE_RELATIVE),
            "--runtime",
            str(runtime_path),
            "--runtime-sha256",
            sha256_bytes(runtime_raw),
            "--source-lock",
            str(source_path),
            "--source-lock-sha256",
            sha256_bytes(source_raw),
        ]
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            check=False,
            timeout=600,
        )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError(
            "R8 isolated native/startup TCB preflight failed: "
            f"rc={completed.returncode}, stderr={completed.stderr[-2000:]!r}"
        )
    child = json.loads(completed.stdout)
    if (
        child.get("status") != "PASS_NO_UNSEALED_STARTUP_OR_NATIVE_MODULE_ORIGIN"
        or child.get("unsealed_loaded_origin_count") != 0
        or child.get("protected_generator_import_count") != 0
        or child.get("qualification_generation_authorized") is not False
        or child.get("payload_generation_count") != 0
        or child.get("truth_vault_latent_open_count") != 0
        or child.get("registry_mutation_count") != 0
    ):
        raise RuntimeError("R8 isolated native/startup TCB preflight receipt drifted")
    return {
        "schema_version": "expected_pe.r8.r5.runtime_startup_preflight_receipt.v1",
        "status": "PASS_EXACT_ISOLATED_STARTUP_AND_NATIVE_ORIGIN_CLOSURE",
        "executed_command_shape": [
            str(EXPECTED_RUNTIME_PYTHON),
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={blackhole}",
            str(PROJECT_ROOT / RUNTIME_STARTUP_PROBE_RELATIVE),
            "--runtime",
            "<TEMP_RUNTIME_TCB_JSON>",
            "--runtime-sha256",
            sha256_bytes(runtime_raw),
            "--source-lock",
            "<TEMP_SOURCE_LOCK_JSON>",
            "--source-lock-sha256",
            sha256_bytes(source_raw),
        ],
        "returncode": completed.returncode,
        "stdout_raw_sha256": sha256_bytes(completed.stdout),
        "stderr_raw_sha256": sha256_bytes(completed.stderr),
        "child_receipt": child,
        "post_freeze_replay_command_template": [
            str(EXPECTED_RUNTIME_PYTHON),
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={blackhole}",
            str(PROJECT_ROOT / RUNTIME_STARTUP_PROBE_RELATIVE),
            "--runtime",
            str(PROJECT_ROOT / DESIGN_ROOT_RELATIVE / "RUNTIME_TCB.json"),
            "--runtime-sha256",
            sha256_bytes(runtime_raw),
            "--source-lock",
            str(PROJECT_ROOT / DESIGN_ROOT_RELATIVE / "SOURCE_LOCK.json"),
            "--source-lock-sha256",
            sha256_bytes(source_raw),
        ],
    }


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _checksums(root: Path) -> bytes:
    lines: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_file() and path.name != "CHECKSUMS.sha256":
            lines.append(f"{sha256_bytes(path.read_bytes())}  {path.relative_to(root).as_posix()}\n")
    return "".join(lines).encode("ascii")


def _verify_preserved_checksum_tree(
    root_relative: str, expected_checksums_raw_sha256: str
) -> Mapping[str, Any]:
    root = PROJECT_ROOT / root_relative
    checksum_path = root / "CHECKSUMS.sha256"
    raw = checksum_path.read_bytes()
    if sha256_bytes(raw) != expected_checksums_raw_sha256:
        raise RuntimeError(f"preserved checksum ledger drifted: {root_relative}")
    expected: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in expected
        ):
            raise RuntimeError(f"preserved checksum ledger is malformed: {root_relative}")
        expected[relative] = digest
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "CHECKSUMS.sha256"
    }
    if actual_paths != set(expected):
        raise RuntimeError(f"preserved checksum tree universe drifted: {root_relative}")
    for relative, digest in expected.items():
        if sha256_bytes((root / relative).read_bytes()) != digest:
            raise RuntimeError(f"preserved checksum member drifted: {root_relative}/{relative}")
    return {
        "root_relative": root_relative,
        "checksums_raw_sha256": expected_checksums_raw_sha256,
        "ledger_member_count": len(expected),
        "exact_tree_reopened": True,
    }


def _verify_r4_predecessor_evidence() -> Mapping[str, Any]:
    design = _verify_preserved_checksum_tree(
        R4_DESIGN_ROOT_RELATIVE, R4_DESIGN_CHECKSUMS_RAW_SHA256
    )
    audit = _verify_preserved_checksum_tree(
        R4_AUDIT_ROOT_RELATIVE, R4_AUDIT_CHECKSUMS_RAW_SHA256
    )
    failure = _verify_preserved_checksum_tree(
        R4_ISSUANCE_FAILURE_ROOT_RELATIVE,
        R4_ISSUANCE_FAILURE_CHECKSUMS_RAW_SHA256,
    )
    anchor_raw = (PROJECT_ROOT / R4_EXTERNAL_ANCHOR_RELATIVE).read_bytes()
    audit_raw = (PROJECT_ROOT / R4_AUDIT_ROOT_RELATIVE / "AUDIT.json").read_bytes()
    seal_raw = (PROJECT_ROOT / R4_AUDIT_ROOT_RELATIVE / "SEAL.json").read_bytes()
    failure_raw = (
        PROJECT_ROOT / R4_ISSUANCE_FAILURE_ROOT_RELATIVE / "FAILURE_RECEIPT.json"
    ).read_bytes()
    if (
        sha256_bytes(anchor_raw) != R4_EXTERNAL_ANCHOR_RAW_SHA256
        or sha256_bytes(audit_raw) != R4_AUDIT_JSON_RAW_SHA256
        or sha256_bytes(seal_raw) != R4_AUDIT_SEAL_RAW_SHA256
    ):
        raise RuntimeError("immutable R8-r4 predecessor raw evidence drifted")
    audit_payload = json.loads(audit_raw)
    failure_payload = json.loads(failure_raw)
    if (
        audit_payload.get("verdict") != "GO"
        or audit_payload.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or audit_payload.get("design_checksums_raw_sha256")
        != R4_DESIGN_CHECKSUMS_RAW_SHA256
        or failure_payload.get("status") != "FAIL_CLOSED_EXECUTION_CUSTODY_BROKEN"
        or failure_payload.get("capability_issued") is not False
        or failure_payload.get("generation_executed") is not False
        or failure_payload.get("authority", {}).get("exists") is not False
        or any(value != 0 for value in failure_payload.get("access_counts", {}).values())
    ):
        raise RuntimeError("R8-r4 GO or fail-closed custody evidence semantics drifted")
    return {
        "status": "PASS_R4_DESIGN_GO_BUT_ISSUANCE_CUSTODY_BROKEN",
        "r4_design": design,
        "r4_external_anchor_relative": R4_EXTERNAL_ANCHOR_RELATIVE,
        "r4_external_anchor_raw_sha256": R4_EXTERNAL_ANCHOR_RAW_SHA256,
        "r4_independent_audit": audit,
        "r4_audit_json_raw_sha256": R4_AUDIT_JSON_RAW_SHA256,
        "r4_audit_seal_raw_sha256": R4_AUDIT_SEAL_RAW_SHA256,
        "r4_issuance_failure": failure,
        "r4_failure_receipt_raw_sha256": sha256_bytes(failure_raw),
        "r4_authority_created": False,
        "r4_generation_executed": False,
    }


def _verify_signer_readiness() -> Mapping[str, Any]:
    readiness_path = PROJECT_ROOT / SIGNER_READINESS_RELATIVE
    readiness_raw, readiness = load_readiness(readiness_path)
    service_raw = (PROJECT_ROOT / SIGNER_SERVICE_RELATIVE).read_bytes()
    if (
        sha256_bytes(readiness_raw) != SIGNER_READINESS_RAW_SHA256
        or sha256_bytes(service_raw) != SIGNER_SERVICE_RAW_SHA256
        or readiness.get("key_id") != AUDITOR_KEY_ID
        or readiness.get("public_key_hex") != AUDITOR_PUBLIC_KEY_HEX
    ):
        raise RuntimeError("fixed r5 signer public binding drifted")
    status = ping_service(readiness_path)
    if (
        status.get("status") != "PASS_READ_ONLY_STATUS"
        or status.get("state") != "READY"
        or status.get("sign_request_count") != 0
        or status.get("signing_count") != 0
        or status.get("within_six_hour_window") is not True
    ):
        raise RuntimeError("r5 signer service is not live and unused")
    binding = {
        "key_id": AUDITOR_KEY_ID,
        "public_key_hex": AUDITOR_PUBLIC_KEY_HEX,
        "readiness_raw_sha256": SIGNER_READINESS_RAW_SHA256,
        "readiness_root_relative": SIGNER_READINESS_ROOT_RELATIVE,
        "service_source_raw_sha256": SIGNER_SERVICE_RAW_SHA256,
    }
    return {
        "schema_version": "expected_pe.r8.r5.signer_readiness_verification.v1",
        "status": "PASS_LIVE_MEMORY_ONLY_ZERO_SIGNINGS",
        "r5_signer_service_binding": binding,
        "read_only_status": status,
        "sign_request_count": 0,
        "signing_count": 0,
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
    }


def main() -> int:
    destination = DESIGN_ROOT
    anchor_path = PROJECT_ROOT / EXTERNAL_ANCHOR_RELATIVE
    staging = destination.parent / f".{destination.name}.staging"
    if any(path.exists() for path in (destination, staging, anchor_path)):
        raise RuntimeError("R8 immutable design/staging/anchor already exists")
    if Path(sys.executable).resolve(strict=True) != EXPECTED_RUNTIME_PYTHON.resolve(strict=True):
        raise RuntimeError("R8 freeze must run under exact Python3.10 execution runtime")
    if (PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE).exists():
        raise RuntimeError("R8 bytecode blackhole must remain absent")
    preserved_design_receipts = [
        _verify_preserved_checksum_tree(
            R1_DESIGN_ROOT_RELATIVE, R1_DESIGN_CHECKSUMS_RAW_SHA256
        ),
        _verify_preserved_checksum_tree(
            R2_DESIGN_ROOT_RELATIVE, R2_DESIGN_CHECKSUMS_RAW_SHA256
        ),
        _verify_preserved_checksum_tree(
            R3_DESIGN_ROOT_RELATIVE, R3_DESIGN_CHECKSUMS_RAW_SHA256
        ),
    ]
    preserved_anchor_evidence = {
        R1_EXTERNAL_ANCHOR_RELATIVE: R1_EXTERNAL_ANCHOR_RAW_SHA256,
        R2_EXTERNAL_ANCHOR_RELATIVE: R2_EXTERNAL_ANCHOR_RAW_SHA256,
        R3_EXTERNAL_ANCHOR_RELATIVE: R3_EXTERNAL_ANCHOR_RAW_SHA256,
    }
    for relative, expected_sha256 in preserved_anchor_evidence.items():
        path = PROJECT_ROOT / relative
        if not path.is_file() or sha256_bytes(path.read_bytes()) != expected_sha256:
            raise RuntimeError(f"immutable R8-r1/r2/r3 evidence drifted: {relative}")
    for failed_staging_relative in (
        R2_FAILED_NEGATIVE_STAGING_RELATIVE,
        R3_FAILED_NEGATIVE_STAGING_RELATIVE,
    ):
        failed_staging = PROJECT_ROOT / failed_staging_relative
        if not failed_staging.is_dir() or any(failed_staging.iterdir()):
            raise RuntimeError(
                f"immutable empty failed negative-check staging drifted: {failed_staging_relative}"
            )
    r4_predecessor = _verify_r4_predecessor_evidence()
    registry = require_registry_snapshot()
    r7_design_checksums = (
        PROJECT_ROOT / R7_DESIGN_ROOT_RELATIVE / "CHECKSUMS.sha256"
    ).read_bytes()
    if sha256_bytes(r7_design_checksums) != R7_DESIGN_CHECKSUMS_RAW_SHA256:
        raise RuntimeError("inherited frozen R7 design checksum bytes drifted")
    if not verify_ed25519(
        bytes.fromhex(AUDITOR_PUBLIC_KEY_HEX),
        AUDITOR_POSSESSION_CHALLENGE,
        bytes.fromhex(AUDITOR_POSSESSION_SIGNATURE_HEX),
    ):
        raise RuntimeError("independent auditor public-key possession proof failed")
    signer_readiness = _verify_signer_readiness()

    quality = _quality_receipt()
    source_lock = capture_source_lock()
    source_archive = source_archive_bytes(source_lock)
    recovery = verify_source_archive(source_lock, source_archive)
    runtime = capture_runtime_tcb()
    runtime_replay = verify_complete_runtime_tcb(runtime)
    runtime_startup_preflight = _runtime_startup_preflight(runtime, source_lock)
    total, available = memory_status_gib()
    base_admission = admit_scheduler(
        logical_cpu_count=os.cpu_count() or 0,
        total_physical_gib=total,
        available_physical_gib=available,
    )
    benchmark = benchmark_isolated_children(base_admission, rounds=2)
    selected_workers = int(benchmark["benchmark_best_workers"])
    final_admission = admit_scheduler(
        logical_cpu_count=os.cpu_count() or 0,
        total_physical_gib=total,
        available_physical_gib=available,
        benchmark_worker_cap=selected_workers,
    )
    if final_admission.admitted_workers != selected_workers:
        raise RuntimeError("R8 benchmark selection no longer satisfies live RAM admission")
    candidate_workers = [int(row["workers"]) for row in benchmark["candidate_rows"]]
    if base_admission.admitted_workers == 16 and candidate_workers != [4, 8, 12, 16]:
        raise RuntimeError("R8 benchmark did not measure the exact 4/8/12/16 candidate set")

    staging.mkdir(exist_ok=False)
    source_lock_raw = _canonical(source_lock)
    runtime_raw = _canonical(runtime)
    _write(staging / "SOURCE_LOCK.json", source_lock_raw)
    _write(staging / "SOURCE_ARCHIVE.zip", source_archive)
    _write(staging / "RUNTIME_TCB.json", runtime_raw)
    _write(staging / "RUNTIME_STARTUP_PREFLIGHT.json", _sealed(runtime_startup_preflight))
    _write(staging / "SCHEDULER_BENCHMARK.json", _sealed(benchmark))
    _write(staging / "QUALITY_RECEIPT.json", _sealed(quality))
    _write(staging / "SOURCE_RECOVERY_RECEIPT.json", _sealed(recovery))
    _write(
        staging / "SIGNER_READINESS_VERIFICATION.json",
        _sealed(signer_readiness),
    )

    finding_matrix = {
        "schema_version": "expected_pe.r8.r5.r7_finding_closure_matrix.v1",
        "status": "IMPLEMENTED_PENDING_NEW_INDEPENDENT_AUDIT",
        "finding_counts_claimed_by_builder": {"P0": 0, "P1": 0, "P2": 0},
        "closures": [
            {
                "id": "P0-001",
                "implementation": (
                    "one memory-only signer-service Ed25519 activation bound to audit/design/"
                    "source/runtime/registry/readiness/external anchor; run-id is derived from "
                    "the signed issuance time; exact Win32 anonymous inherited-handle allowlist "
                    "is verified by unique markers through PeekNamedPipe/ReadFile and selects "
                    "202 role/task-bound one-time secret capabilities whose disk claim retains "
                    "only distinct hashes; no role CLI or caller protected dispatch"
                ),
                "tests": [
                    "test_valid_fixture_signed_exact_key_authority_passes",
                    "test_direct_child_invocation_fails_without_inherited_handle",
                    "test_windows_capability_pipe_abi_and_os_handle_allowlist",
                    "test_one_shot_claim_persists_only_role_bound_child_secret_hashes",
                    "test_protected_generator_import_is_below_capability_validation",
                ],
            },
            {
                "id": "P0-002",
                "implementation": (
                    "strict run-id and four distinct absent direct children validated before claim "
                    "and before each create/rename"
                ),
                "tests": [
                    "test_run_id_path_escape_is_rejected_before_plan",
                    "test_four_paths_are_distinct_absent_direct_children",
                ],
            },
            {
                "id": "P0-003",
                "implementation": (
                    "external launcher self-pin; complete Python3.10 stdlib and all non-bytecode "
                    "RECORD members; complete conda DLLs and Library/bin native trees plus all "
                    "startup/module origins; explicit forbidden bytecode rows; -I/-S/-B/-E and "
                    "fail-closed unsealed native loads plus absent "
                    "pycache prefix; exact RUNTIME_TCB site-packages reconstruction and "
                    "loaded-origin closure in direct and nested children; inherited frozen R7 "
                    "design exact checksum universe independently pinned"
                ),
                "tests": ["test_runtime_tcb_code_verifies_every_record_member_and_child_flags"],
            },
            {
                "id": "P1-001",
                "implementation": (
                    "protected-only finalizer reopens exact two-pass tree, CSV schema/geometry/date "
                    "identity, exact producer metadata/proof schemas and public/protected hash "
                    "maps, raw and independently recomputed logical parity, then vault seal"
                ),
                "tests": [
                    "test_protected_finalizer_reopens_both_passes_and_seals_checksums",
                    "test_protected_finalizer_corruption_fails_closed",
                ],
            },
            {
                "id": "P1-002",
                "implementation": (
                    "journal-first append-only phases, durable file/directory fsync, exact tree "
                    "metadata, canonical semantic hash-linked ancestry, transition-time topology, "
                    "and authenticated top-level idempotent recovery across both partial renames"
                ),
                "tests": [
                    "test_publication_recovers_idempotently_from_each_commit_crash_phase",
                    "test_authenticated_top_level_reentry_recovers_without_generator_import",
                    "test_every_journal_ancestry_record_semantics_and_hash_link_are_reopened",
                    "test_reentry_recovers_rename_completed_before_directory_fsync",
                    "test_reentry_recovers_phase_file_written_before_journal_directory_fsync",
                    "test_durable_tree_reopens_every_file_and_binds_full_metadata",
                    "test_prepublication_abort_is_preserved_and_not_resumable",
                ],
            },
            {
                "id": "P1-003",
                "implementation": (
                    "zero governed pycache/pyc, absent redirected cache prefix, individual source "
                    "records and deterministic byte-for-byte recovery archive"
                ),
                "tests": [
                    "test_governed_r8_namespaces_forbid_pycache_and_archive_every_source"
                ],
            },
            {
                "id": "P2-001",
                "implementation": (
                    "measured 4/8/12/16 score-free concurrency, RAM<=75GiB, two logical CPUs per "
                    "worker, inner BLAS=1, stable two-wave schedule/result ordering"
                ),
                "tests": [
                    "test_scheduler_admission_partitions_cpu0_31_without_overlap",
                    "test_scheduler_result_order_is_stable_despite_partition_queues",
                ],
            },
            {
                "id": "P2-002",
                "implementation": (
                    "pytest hook writes exact collected nodeids and terminal per-item outcomes; "
                    "command/environment/return/stdout/stderr hashes frozen"
                ),
                "tests": ["test_pytest_receipt_plugin_records_collection_and_executed_items"],
            },
        ],
        "independent_audit_required": True,
        "qualification_generation_authorized": False,
    }
    _write(staging / "FINDING_CLOSURE_MATRIX.json", _sealed(finding_matrix))

    authority_state = {
        "schema_version": "expected_pe.r8.r5.qualification.authority_state.v1",
        "status": "FROZEN_SCORE_FREE_AWAITING_NEW_INDEPENDENT_AUDIT",
        "auditor_public_key_hex": AUDITOR_PUBLIC_KEY_HEX,
        "auditor_key_id": AUDITOR_KEY_ID,
        "non_authorizing_possession_challenge_hex": AUDITOR_POSSESSION_CHALLENGE.hex(),
        "non_authorizing_possession_signature_hex": AUDITOR_POSSESSION_SIGNATURE_HEX,
        "activation_authority_file_present": False,
        "qualification_generation_authorized": False,
        "heldout_generation_authorized": False,
        "model_fit_prediction_evaluation_score_authorized": False,
        "registry_mutation_authorized": False,
        "production_promotion_authorized": False,
        "private_key_received_or_persisted": False,
        "activation_token_received_or_persisted": False,
        "r5_signer_service_binding": signer_readiness["r5_signer_service_binding"],
        "signer_status_at_freeze": signer_readiness["read_only_status"],
        "issuance_transport": "STDIN_TOKEN_TO_AF_PIPE_SIGNER_TO_ANONYMOUS_STDIN_LAUNCH",
        "authority_persisted": False,
        "r4_predecessor_evidence": r4_predecessor,
        "r1_immutable_failed_self_audit_preserved": True,
        "r2_immutable_failed_post_freeze_self_audit_preserved": True,
        "r3_immutable_failed_post_freeze_self_audit_preserved": True,
        "r5_revision_only": True,
    }
    _write(staging / "AUTHORITY_STATE.json", _sealed(authority_state))

    process_contract = {
        "schema_version": "expected_pe.r8.r5.process_isolation_contract.v1",
        "status": "FROZEN_NO_CALLER_ACCESSIBLE_PRIVATE_ROLE_DISPATCH",
        "issuance_cli_arguments": [],
        "top_level_cli_arguments": [],
        "activation_token_transport": "ISSUANCE_STDIN_EXACT_64_LOWERCASE_HEX_ONLY",
        "authority_transport": "AF_PIPE_RESPONSE_TO_ANONYMOUS_STDIN_IN_MEMORY_ONLY",
        "authority_file_present": False,
        "run_id_source": "SIGNED_ISSUED_AT_UTC_DERIVED_YYYYMMDDTHHMMSS",
        "private_role_transport": "INHERITED_ANONYMOUS_PIPE_HANDLE_ONLY",
        "windows_security_attributes_size_bytes": 24,
        "windows_pipe_read_handle_inheritable": True,
        "windows_pipe_write_handle_inheritable": False,
        "windows_child_handle_allowlist_exact": True,
        "unrelated_inheritable_handles_excluded": True,
        "windows_handle_object_identity_probe": (
            "UNIQUE_MARKER_PEEKNAMEDPIPE_AND_READFILE"
        ),
        "numeric_handle_alias_is_not_object_identity": True,
        "role_task_bound_child_capability_count": 202,
        "child_capability_plaintext_secret_persisted": False,
        "child_capability_distinct_hashes_in_one_shot_claim": True,
        "private_roles": [
            "PROTECTED_GENERATE",
            "PUBLIC_RUN",
            "PROTECTED_FINALIZE",
            "PUBLIC_FINALIZE",
        ],
        "child_flags": ["-I", "-S", "-B", "-E"],
        "bytecode_prefix": BYTECODE_BLACKHOLE_RELATIVE,
        "bytecode_prefix_must_be_absent": True,
        "protected_generator_import_after_capability_validation": True,
        "sealed_recovery_reentry_before_generator_import": True,
        "preseal_payload_resume_forbidden": True,
        "public_role_protected_import_forbidden": True,
        "runtime_native_member_count": len(runtime["python_native_members"]),
        "runtime_native_complete_tree_count": len(
            runtime["python_native_inventory"]["complete_tree_roots"]
        ),
        "unsealed_native_loaded_origin_count": 0,
        "selected_outer_workers": selected_workers,
        "cpu_ids": list(range(32)),
        "logical_cpus_per_worker": 2,
        "inner_threads": 1,
    }
    _write(staging / "PROCESS_ISOLATION_CONTRACT.json", _sealed(process_contract))

    design_lock = {
        "schema_version": "expected_pe.r8.r5.qualification.design_lock.v1",
        "status": "FROZEN_SCORE_FREE_PRE_GENERATION",
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "revision": "R8_R5",
        "r5_signer_service_binding": signer_readiness["r5_signer_service_binding"],
        "r4_predecessor_evidence": r4_predecessor,
        "future_independent_r5_audit_required": True,
        "authority_and_token_persisted": False,
        "supersedes_immutable_failed_self_audit_designs_relative": [
            R1_DESIGN_ROOT_RELATIVE,
            R2_DESIGN_ROOT_RELATIVE,
            R3_DESIGN_ROOT_RELATIVE,
        ],
        "preserved_r1_design_checksums_raw_sha256": (
            R1_DESIGN_CHECKSUMS_RAW_SHA256
        ),
        "preserved_r1_external_anchor_raw_sha256": R1_EXTERNAL_ANCHOR_RAW_SHA256,
        "preserved_r2_design_checksums_raw_sha256": (
            R2_DESIGN_CHECKSUMS_RAW_SHA256
        ),
        "preserved_r2_external_anchor_raw_sha256": R2_EXTERNAL_ANCHOR_RAW_SHA256,
        "preserved_r3_design_checksums_raw_sha256": (
            R3_DESIGN_CHECKSUMS_RAW_SHA256
        ),
        "preserved_r3_external_anchor_raw_sha256": R3_EXTERNAL_ANCHOR_RAW_SHA256,
        "preserved_prior_design_tree_receipts": preserved_design_receipts,
        "preserved_r2_failed_negative_staging_relative": (
            R2_FAILED_NEGATIVE_STAGING_RELATIVE
        ),
        "preserved_r2_failed_negative_staging_empty": True,
        "preserved_r3_failed_negative_staging_relative": (
            R3_FAILED_NEGATIVE_STAGING_RELATIVE
        ),
        "preserved_r3_failed_negative_staging_empty": True,
        "qualification_seed_ids": list(QUALIFICATION_SEEDS),
        "heldout_seed_ids": list(HELDOUT_SEEDS),
        "dgp_ids": list(DGPS),
        "rows_per_task": 1_800,
        "replay_passes": [1, 2],
        "registry_raw_sha256": REGISTRY_RAW_SHA256,
        "registry_entry_count": registry["entry_count"],
        "new_seed_reserved": False,
        "source_lock_raw_sha256": sha256_bytes(source_lock_raw),
        "source_archive_raw_sha256": sha256_bytes(source_archive),
        "runtime_tcb_raw_sha256": sha256_bytes(runtime_raw),
        "r7_design_root_relative": R7_DESIGN_ROOT_RELATIVE,
        "r7_design_checksums_raw_sha256": R7_DESIGN_CHECKSUMS_RAW_SHA256,
        "runtime_replay_receipt": runtime_replay,
        "runtime_startup_preflight_receipt": runtime_startup_preflight,
        "runtime_python": _file_record(EXPECTED_RUNTIME_PYTHON),
        "runtime_stdlib_member_count": len(runtime["stdlib_members"]),
        "runtime_native_member_count": len(runtime["python_native_members"]),
        "runtime_native_complete_tree_count": len(
            runtime["python_native_inventory"]["complete_tree_roots"]
        ),
        "runtime_distribution_count": len(runtime["distributions"]),
        "runtime_distribution_member_count": sum(
            len(item["members"]) for item in runtime["distributions"].values()
        ),
        "runtime_record_bytecode_rows_forbidden": runtime[
            "record_bytecode_rows_explicitly_forbidden"
        ],
        "source_record_count": source_lock["record_count"],
        "selected_outer_workers": selected_workers,
        "scheduler_final_admission": {
            "logical_cpu_count": final_admission.logical_cpu_count,
            "total_physical_gib": final_admission.total_physical_gib,
            "available_physical_gib_at_freeze": final_admission.available_physical_gib,
            "admitted_workers": final_admission.admitted_workers,
            "partitions": [
                {"worker_index": item.worker_index, "cpu_ids": list(item.cpu_ids)}
                for item in final_admission.partitions
            ],
            "inner_threads": final_admission.inner_threads,
            "generation_ram_cap_gib": 75.0,
        },
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
        "heldout_access_count": 0,
        "model_fit_prediction_evaluation_score_count": 0,
        "registry_mutation_count": 0,
    }
    _write(staging / "DESIGN_LOCK.json", _sealed(design_lock))

    design_files_without_checksums = sorted(
        {
            "AUTHORITY_STATE.json",
            "DESIGN_LOCK.json",
            "FINDING_CLOSURE_MATRIX.json",
            "MANIFEST.json",
            "PROCESS_ISOLATION_CONTRACT.json",
            "QUALITY_RECEIPT.json",
            "REPORT.md",
            "RUNTIME_TCB.json",
            "RUNTIME_STARTUP_PREFLIGHT.json",
            "SCHEDULER_BENCHMARK.json",
            "SOURCE_ARCHIVE.zip",
            "SOURCE_LOCK.json",
            "SOURCE_RECOVERY_RECEIPT.json",
            "SIGNER_READINESS_VERIFICATION.json",
        }
    )
    manifest = {
        "schema_version": "expected_pe.r8.r5.qualification.design_manifest.v1",
        "status": "FROZEN_SCORE_FREE_PRE_GENERATION_PENDING_INDEPENDENT_AUDIT",
        "file_universe_without_checksums": design_files_without_checksums,
        "finding_closure_count": 8,
        "pytest_collected_items": quality["collected_item_count"],
        "pytest_executed_items": quality["executed_item_count"],
        "pytest_passed_items": quality["passed_item_count"],
        "ruff_passed": True,
        "complete_runtime_replay_passed": True,
        "isolated_runtime_startup_preflight_passed": True,
        "source_byte_recovery_passed": True,
        "scheduler_benchmark_passed": True,
        "selected_outer_workers": selected_workers,
        "qualification_generation_authorized": False,
        "heldout_generation_authorized": False,
    }
    _write(staging / "MANIFEST.json", _sealed(manifest))
    report = (
        "# DGP Qualification Generation R8-r5 Isolated Custody Design\n\n"
        "Status: FROZEN_SCORE_FREE_PRE_GENERATION_PENDING_INDEPENDENT_AUDIT.\n\n"
        "R8-r5 preserves R8-r4's independently audited zero-finding design while replacing "
        "its lost follow-up private-key custody with a separately frozen memory-only one-shot "
        "signer service. R8-r4 remains immutable and its fail-closed issuance receipt proves "
        "that no authority, token, capability, or generation was created. "
        "R8-r4 had superseded the preserved immutable R8-r1, R8-r2, and R8-r3 failures. "
        "R8-r2's post-freeze OS probe treated a reused numeric handle value as object identity; "
        "R8-r3 corrected that probe using a unique pipe-object marker, then its post-freeze "
        "suite exposed an unsealed conda DLL extension origin (`_bz2.pyd`). R8-r5 carries "
        "forward r4's complete native closure and "
        "reopens the complete Python native DLLs and Library/bin trees and fails on every "
        "unsealed native module origin. "
        "It closes the "
        "builder-side implementation for all eight sealed R7 findings. "
        "Its sole production entrypoint reads a token from stdin, obtains one exact signed "
        "authority over AF_PIPE, and passes token plus authority to the isolated launcher only "
        "through anonymous stdin; neither is a CLI argument or file. It retains strict four-path "
        "custody and a complete "
        "Python 3.10 runtime/member closure with an exact isolated startup preflight, protected "
        "reopened-byte vault finalization, "
        "full-tree durable authenticated crash recovery, recoverable source bytes without "
        "pycache, measured bounded "
        f"scheduling ({selected_workers} workers), and exact machine-readable pytest counts "
        f"({quality['executed_item_count']} executed/passed).\n\n"
        "No qualification or heldout payload was generated or opened. No fit, prediction, "
        "evaluation, score, seed reservation, registry mutation, or promotion action occurred. "
        "A new independent r5 audit must report GO with P0/P1/P2=0/0/0 before the signer will "
        "issue the sole in-memory authority.\n"
    ).encode("utf-8")
    _write(staging / "REPORT.md", report)

    if sorted(path.name for path in staging.iterdir()) != design_files_without_checksums:
        raise RuntimeError("R8 design exact pre-checksum file universe drifted")

    checksums_raw = _checksums(staging)
    _write(staging / "CHECKSUMS.sha256", checksums_raw)
    durably_fsync_tree(staging)
    os.replace(staging, destination)
    fsync_directory(destination.parent)
    launcher_raw = (PROJECT_ROOT / LAUNCHER_RELATIVE).read_bytes()
    issuance_launcher_raw = (PROJECT_ROOT / ISSUANCE_LAUNCHER_RELATIVE).read_bytes()
    anchor = {
        "schema_version": "expected_pe.r8.r5.external_launcher_anchor.v1",
        "status": "FROZEN_EXTERNAL_PIN_REPORT_HASH_OUT_OF_BAND",
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "design_checksums_raw_sha256": sha256_bytes(checksums_raw),
        "launcher_relative": LAUNCHER_RELATIVE,
        "launcher_raw_sha256": sha256_bytes(launcher_raw),
        "issuance_launcher_relative": ISSUANCE_LAUNCHER_RELATIVE,
        "issuance_launcher_raw_sha256": sha256_bytes(issuance_launcher_raw),
        "source_lock_relative": f"{DESIGN_ROOT_RELATIVE}/SOURCE_LOCK.json",
        "source_lock_raw_sha256": sha256_bytes(source_lock_raw),
        "source_archive_relative": f"{DESIGN_ROOT_RELATIVE}/SOURCE_ARCHIVE.zip",
        "source_archive_raw_sha256": sha256_bytes(source_archive),
        "runtime_tcb_relative": f"{DESIGN_ROOT_RELATIVE}/RUNTIME_TCB.json",
        "runtime_tcb_raw_sha256": sha256_bytes(runtime_raw),
        "r7_design_root_relative": R7_DESIGN_ROOT_RELATIVE,
        "r7_design_checksums_raw_sha256": R7_DESIGN_CHECKSUMS_RAW_SHA256,
        "scheduler_worker_cap": selected_workers,
        "r5_signer_service_binding": signer_readiness["r5_signer_service_binding"],
        "predecessor_evidence": r4_predecessor,
    }
    _write(anchor_path, _canonical(anchor))
    fsync_directory(anchor_path.parent)
    result = {
        "status": "FROZEN_R8_R5_SCORE_FREE_DESIGN",
        "design_root": DESIGN_ROOT_RELATIVE,
        "design_checksums_raw_sha256": sha256_bytes(checksums_raw),
        "external_anchor_relative": EXTERNAL_ANCHOR_RELATIVE,
        "external_anchor_raw_sha256": sha256_bytes(anchor_path.read_bytes()),
        "source_lock_raw_sha256": sha256_bytes(source_lock_raw),
        "source_archive_raw_sha256": sha256_bytes(source_archive),
        "runtime_tcb_raw_sha256": sha256_bytes(runtime_raw),
        "selected_outer_workers": selected_workers,
        "pytest_collected_executed_passed": quality["passed_item_count"],
        "qualification_generation_authorized": False,
        "heldout_generation_authorized": False,
        "payload_generation_count": 0,
    }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
