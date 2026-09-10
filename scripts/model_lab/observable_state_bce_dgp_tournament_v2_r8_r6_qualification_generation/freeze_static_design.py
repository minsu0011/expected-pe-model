"""Freeze the R8-r6 Phase 1 static design without launching Phase 2."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for value in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.contracts import (  # noqa: E402
    BYTECODE_BLACKHOLE_RELATIVE,
    DESIGN_ROOT,
    DESIGN_ROOT_RELATIVE,
    DGPS,
    EXTERNAL_ANCHOR_RELATIVE,
    HELDOUT_SEEDS,
    PACKAGE_RELATIVE,
    QUALIFICATION_SEEDS,
    REGISTRY_RAW_SHA256,
    SCRIPT_RELATIVE,
    SIGNER_BINDING_RELATIVE,
    SIGNER_BINDING_ROOT_RELATIVE,
    SIGNER_TELEMETRY_RELATIVE,
    STATIC_AUDIT_ROOT_RELATIVE,
    SUPPLEMENTAL_AUDIT_ROOT_RELATIVE,
    TEST_RELATIVE,
    canonical_json_bytes,
    require_registry_snapshot,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.resource import (  # noqa: E402
    memory_status_gib,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.runtime_tcb import (  # noqa: E402
    capture_runtime_tcb,
    verify_complete_runtime_tcb,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.scheduler import (  # noqa: E402
    admit_scheduler,
    canonical_task_specs,
    run_deterministic_bounded,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.source_custody import (  # noqa: E402
    capture_source_lock,
    source_archive_bytes,
    verify_source_archive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.supervision import (  # noqa: E402
    static_supervision_contract,
)


QUALITY_PYTHON = Path("C:/Users/minsu/anaconda3/python.exe")
EXPECTED_RUNTIME_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
LAUNCHER_RELATIVE = f"{SCRIPT_RELATIVE}/external_launcher.py"
BUILDER_RELATIVE = f"{SCRIPT_RELATIVE}/freeze_static_design.py"
R7_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation_design_20260821"
)
R7_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "d0cd9c9f90a56f0eed37cf5c4d9ef742eefca682155561ae5a10ea52ed3ec20a"
)
R5_DESIGN_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r5_20260821"
)
R5_DESIGN_CHECKSUMS_RAW_SHA256 = (
    "9efc0e503d8fddbc144270fdeec1c2a86c60c083f2cee9aa0b263aaba719e70c"
)
R5_MAIN_AUDIT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
    "independent_qualification_pre_generation_audit_r5_20260821"
)
R5_MAIN_AUDIT_CHECKSUMS_RAW_SHA256 = (
    "b88b6c6e4803b504b495aaade7cdf6e8761994545c6c1d7892e53a37c9dc9292"
)
R5_META_AUDIT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r5_"
    "independent_activation_readiness_meta_audit_20260821"
)
R5_META_AUDIT_CHECKSUMS_RAW_SHA256 = (
    "429c9ff234d28edac893643973bd30a451104e5db09edaa2cfa4ab4c67bf7e0c"
)
R5_META_AUDIT_JSON_RAW_SHA256 = (
    "8d3f080af15178873de5b3dd901db219ba4b37a583f639d6827b432610d5bc8e"
)


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes(value)


def _sealed(value: Mapping[str, Any]) -> bytes:
    payload = dict(value)
    payload["manifest_sha256"] = sha256_bytes(_canonical(payload))
    return _canonical(payload)


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _run(command: Sequence[str], *, env: Mapping[str, str]) -> Mapping[str, Any]:
    started = time.perf_counter()
    result = subprocess.run(
        list(command),
        cwd=PROJECT_ROOT,
        env=dict(env),
        capture_output=True,
        check=False,
        timeout=600,
    )
    return {
        "command": list(command),
        "returncode": result.returncode,
        "wall_seconds": time.perf_counter() - started,
        "stdout_raw_sha256": sha256_bytes(result.stdout),
        "stderr_raw_sha256": sha256_bytes(result.stderr),
        "stdout_tail": result.stdout[-2_000:].decode("utf-8", errors="replace"),
        "stderr_tail": result.stderr[-2_000:].decode("utf-8", errors="replace"),
    }


def _quality_receipt() -> Mapping[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    pytest_run = _run(
        [
            str(QUALITY_PYTHON),
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            TEST_RELATIVE,
        ],
        env=environment,
    )
    ruff_run = _run(
        [
            str(QUALITY_PYTHON),
            "-B",
            "-m",
            "ruff",
            "check",
            PACKAGE_RELATIVE,
            SCRIPT_RELATIVE,
            TEST_RELATIVE,
        ],
        env=environment,
    )
    if pytest_run["returncode"] != 0 or ruff_run["returncode"] != 0:
        raise RuntimeError(f"R8-r6 static quality failed: {pytest_run!r} {ruff_run!r}")
    return {
        "schema_version": "expected_pe.r8.r6.static_quality_receipt.v1",
        "status": "PASS_STATIC_TESTS_AND_RUFF",
        "pytest": pytest_run,
        "ruff": ruff_run,
        "signer_launch_count": 0,
        "key_generation_count": 0,
        "authority_issuance_count": 0,
        "payload_generation_count": 0,
        "truth_access_count": 0,
        "heldout_access_count": 0,
    }


def _predecessor_evidence() -> Mapping[str, Any]:
    records = (
        (R5_DESIGN_ROOT_RELATIVE, R5_DESIGN_CHECKSUMS_RAW_SHA256),
        (R5_MAIN_AUDIT_ROOT_RELATIVE, R5_MAIN_AUDIT_CHECKSUMS_RAW_SHA256),
        (R5_META_AUDIT_ROOT_RELATIVE, R5_META_AUDIT_CHECKSUMS_RAW_SHA256),
        (R7_DESIGN_ROOT_RELATIVE, R7_DESIGN_CHECKSUMS_RAW_SHA256),
    )
    evidence: dict[str, Any] = {}
    for relative, expected in records:
        raw = (PROJECT_ROOT / relative / "CHECKSUMS.sha256").read_bytes()
        if sha256_bytes(raw) != expected:
            raise RuntimeError(f"immutable predecessor checksum drifted: {relative}")
        evidence[relative] = {"checksums_raw_sha256": expected, "reopened": True}
    meta_raw = (PROJECT_ROOT / R5_META_AUDIT_ROOT_RELATIVE / "AUDIT.json").read_bytes()
    if sha256_bytes(meta_raw) != R5_META_AUDIT_JSON_RAW_SHA256:
        raise RuntimeError("R5 terminal meta-audit bytes drifted")
    meta = json.loads(meta_raw)
    if (
        meta.get("verdict") != "NO_GO_LIVE_CUSTODY_UNAVAILABLE"
        or meta.get("finding_counts") != {"P0": 1, "P1": 0, "P2": 0}
        or meta.get("activation_authorized") is not False
    ):
        raise RuntimeError("R5 terminal semantics drifted")
    return {
        "schema_version": "expected_pe.r8.r6.predecessor_terminal_evidence.v1",
        "status": "PASS_R5_TERMINAL_NO_RETRY_NEW_ISOLATED_REVISION",
        "r5_terminal_verdict": "NO_GO_LIVE_CUSTODY_UNAVAILABLE",
        "r5_meta_audit_json_raw_sha256": R5_META_AUDIT_JSON_RAW_SHA256,
        "records": evidence,
        "r5_restarted_or_patched": False,
    }


def _resource_receipt() -> Mapping[str, Any]:
    total_gib, available_gib = memory_status_gib()
    admission = admit_scheduler(
        logical_cpu_count=os.cpu_count() or 0,
        total_physical_gib=total_gib,
        available_physical_gib=available_gib,
        benchmark_worker_cap=16,
    )
    smoke_tasks = canonical_task_specs()[:32]
    started = time.perf_counter()
    smoke = run_deterministic_bounded(
        admission,
        lambda task, partition: sha256_bytes(
            f"{task.ordinal}|{task.seed}|{task.dgp}|{task.replay_pass}|{partition.worker_index}".encode(
                "ascii"
            )
        ),
        tasks=smoke_tasks,
    )
    gpu = _run(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ],
        env=os.environ,
    )
    if gpu["returncode"] != 0:
        raise RuntimeError("GPU inventory probe failed")
    return {
        "schema_version": "expected_pe.r8.r6.static_resource_contract.v1",
        "status": "PASS_16X1_CPU_ADMISSION_SHORT_SMOKE_GPU_RESERVED",
        "host": {
            "platform": platform.platform(),
            "logical_cpu_count": os.cpu_count(),
            "total_physical_gib": total_gib,
            "available_physical_gib": available_gib,
        },
        "scheduler_admission": asdict(admission),
        "short_smoke": {
            "task_count": len(smoke_tasks),
            "wall_seconds": time.perf_counter() - started,
            "result_sha256": sha256_bytes(_canonical(list(smoke))),
            "full_generation": False,
            "long_benchmark": False,
        },
        "gpu_inventory": gpu,
        "generation_gpu_allocation_count": 0,
        "generation_cuda_visible_devices": "-1",
        "reason": "DGP replay is CPU-bound; RTX 5080 remains reserved for later TCN work.",
    }


def _checksums(root: Path) -> bytes:
    rows = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name == "CHECKSUMS.sha256":
            continue
        if not path.is_file():
            raise RuntimeError("static design root contains a non-file member")
        rows.append(f"{sha256_bytes(path.read_bytes())}  {path.name}\n")
    return "".join(rows).encode("ascii")


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_RUNTIME_PYTHON.resolve(strict=True):
        raise RuntimeError("freeze must use the sealed generation Python 3.10 runtime")
    if DESIGN_ROOT.exists() or (PROJECT_ROOT / EXTERNAL_ANCHOR_RELATIVE).exists():
        raise RuntimeError("R8-r6 static identity already exists")
    if any(
        (PROJECT_ROOT / relative).exists()
        for relative in (
            SIGNER_BINDING_ROOT_RELATIVE,
            SIGNER_BINDING_RELATIVE,
            SIGNER_TELEMETRY_RELATIVE,
            STATIC_AUDIT_ROOT_RELATIVE,
            SUPPLEMENTAL_AUDIT_ROOT_RELATIVE,
        )
    ):
        raise RuntimeError("future Phase 2/audit artifact exists before static freeze")
    blackhole = PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE
    if blackhole.exists():
        raise RuntimeError("bytecode blackhole path must remain absent")
    registry = require_registry_snapshot()
    predecessor = _predecessor_evidence()
    quality = _quality_receipt()
    resource = _resource_receipt()
    source_lock = capture_source_lock()
    source_raw = _canonical(source_lock)
    source_archive = source_archive_bytes(source_lock)
    source_verification = verify_source_archive(source_lock, source_archive)
    runtime = capture_runtime_tcb()
    runtime_verification = verify_complete_runtime_tcb(runtime)
    runtime_raw = _canonical(runtime)

    staging = DESIGN_ROOT.parent / f".{DESIGN_ROOT.name}.staging"
    if staging.exists():
        raise RuntimeError("R8-r6 static staging identity already exists")
    staging.mkdir(exist_ok=False)
    _write_new(staging / "SOURCE_LOCK.json", source_raw)
    _write_new(staging / "SOURCE_ARCHIVE.zip", source_archive)
    _write_new(staging / "RUNTIME_TCB.json", runtime_raw)
    _write_new(staging / "SOURCE_RECOVERY_RECEIPT.json", _sealed(source_verification))
    _write_new(staging / "RUNTIME_REOPEN_RECEIPT.json", _sealed(runtime_verification))
    _write_new(staging / "QUALITY_RECEIPT.json", _sealed(quality))
    _write_new(staging / "RESOURCE_CONTRACT.json", _sealed(resource))
    _write_new(staging / "PREDECESSOR_TERMINAL_EVIDENCE.json", _sealed(predecessor))
    supervision = static_supervision_contract()
    _write_new(staging / "STATIC_SUPERVISION_CONTRACT.json", _sealed(supervision))
    process_contract = {
        "schema_version": "expected_pe.r8.r6.static_process_isolation_contract.v1",
        "status": "FROZEN_CONTROLLER_WORKER_PRIVATE_PUBLIC_SEPARATION",
        "roles": ["PROTECTED_GENERATE", "PUBLIC_RUN", "PROTECTED_FINALIZE", "PUBLIC_FINALIZE"],
        "controller_imports_protected_generator": False,
        "protected_to_public_transport": "ANONYMOUS_PIPE_STREAM_ONLY",
        "role_capability_transport": "INHERITED_ANONYMOUS_PIPE_HANDLE_ONLY",
        "top_level_authority_transport": "ANONYMOUS_STDIN_ONLY",
        "secret_cli_arguments": [],
        "secret_environment_variables": [],
        "worker_flags": ["-I", "-S", "-B", "-E"],
        "bytecode_blackhole_relative": BYTECODE_BLACKHOLE_RELATIVE,
        "foreground_signer_supervisor_source": (
            f"{PACKAGE_RELATIVE}/signer_supervisor.py"
        ),
        "signer_service_source": f"{PACKAGE_RELATIVE}/signer_service.py",
        "binding_freezer_source": f"{PACKAGE_RELATIVE}/binding_freeze.py",
        "immediate_issuance_source": f"{PACKAGE_RELATIVE}/immediate_issuance.py",
        "phase_1_signer_launch_count": 0,
        "phase_1_key_generation_count": 0,
    }
    _write_new(staging / "PROCESS_ISOLATION_CONTRACT.json", _sealed(process_contract))
    filesystem_contract = {
        "schema_version": "expected_pe.r8.r6.static_filesystem_publication_contract.v1",
        "status": "FROZEN_ATOMIC_DUAL_TREE_ONE_SHOT_PUBLICATION",
        "run_id_source": "SIGNED_ISSUED_AT_UTC_YYYYMMDDTHHMMSS",
        "public_prefix": (
            "model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_qualification_generation_"
        ),
        "vault_prefix": (
            ".model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r8_r6_qualification_vault_"
        ),
        "publication_order": ["vault_staging_to_final", "public_staging_to_final"],
        "atomic_primitive": "os.replace_same_parent",
        "tree_fsync_before_rename": True,
        "journal_hash_chain": True,
        "partial_publication_recovery": True,
        "preseal_resume": False,
        "same_run_id_retry": False,
        "heldout_paths_authorized": False,
    }
    _write_new(
        staging / "FILESYSTEM_PUBLICATION_CONTRACT.json", _sealed(filesystem_contract)
    )
    authority_state = {
        "schema_version": "expected_pe.r8.r6.qualification.static_authority_state.v1",
        "status": "PHASE_1_NO_SIGNER_IDENTITY_NO_AUTHORITY",
        "activation_authority_file_present": False,
        "signer_identity_bound": False,
        "private_key_received_or_persisted": False,
        "qualification_generation_authorized": False,
        "heldout_generation_authorized": False,
        "model_fit_prediction_evaluation_score_authorized": False,
        "registry_mutation_authorized": False,
        "production_promotion_authorized": False,
        "signer_launch_count": 0,
        "key_generation_count": 0,
        "authority_issuance_count": 0,
        "signature_count": 0,
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
    }
    _write_new(staging / "AUTHORITY_STATE.json", _sealed(authority_state))
    design_lock = {
        "schema_version": "expected_pe.r8.r6.qualification.static_design_lock.v1",
        "status": "FROZEN_PHASE_1_STATIC_SCORE_FREE_NO_SIGNER_IDENTITY",
        "revision": "R8_R6_STATIC",
        "phase": "PHASE_1_STATIC_ONLY",
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "qualification_seed_ids": list(QUALIFICATION_SEEDS),
        "heldout_seed_ids": list(HELDOUT_SEEDS),
        "dgp_ids": list(DGPS),
        "rows_per_task": 1800,
        "replay_passes": [1, 2],
        "scheduled_task_count": 100,
        "source_lock_raw_sha256": sha256_bytes(source_raw),
        "source_archive_raw_sha256": sha256_bytes(source_archive),
        "runtime_tcb_raw_sha256": sha256_bytes(runtime_raw),
        "registry_raw_sha256": REGISTRY_RAW_SHA256,
        "registry_entry_count": registry["entry_count"],
        "selected_outer_workers": resource["scheduler_admission"]["admitted_workers"],
        "inner_threads": 1,
        "signer_identity_bound": False,
        "signer_launch_count": 0,
        "key_generation_count": 0,
        "authority_issuance_count": 0,
        "payload_generation_count": 0,
        "heldout_access_count": 0,
        "model_fit_prediction_evaluation_score_count": 0,
        "registry_mutation_count": 0,
        "truth_vault_latent_open_count": 0,
        "future_independent_static_audit_required": True,
        "future_static_audit_required_bindings": [
            "design_checksums_raw_sha256",
            "source_lock_raw_sha256",
            "source_archive_raw_sha256",
            "runtime_tcb_raw_sha256",
            "external_anchor_raw_sha256",
        ],
        "static_audit_may_authorize_only_signer_launch": True,
        "supplemental_audit_required_after_binding": True,
        "alive_recheck_required_immediately_before_issuance": True,
        "maximum_future_qualification_generation_count": 1,
        "r5_terminal_no_retry": True,
    }
    _write_new(staging / "DESIGN_LOCK.json", _sealed(design_lock))
    report = (
        "# R8-r6 Common Qualification Generator — Phase 1 Static Freeze\n\n"
        "This new isolated identity does not restart or patch terminal R8-r5. "
        "The complete controller/worker, source/runtime closure, public/private split, "
        "resource admission, journaled atomic publication, future one-shot signer service, "
        "foreground parent supervisor, telemetry, and public binding freezer are frozen.\n\n"
        "Phase 1 generated no signer key or public identity, launched no signer, issued no "
        "authority, generated no payload, and opened neither qualification truth nor heldout. "
        "An independent static audit may authorize only a future Phase 2 signer launch.\n"
    )
    _write_new(staging / "REPORT.md", report.encode("utf-8"))
    manifest_records = []
    for path in sorted(staging.iterdir(), key=lambda item: item.name):
        manifest_records.append(
            {
                "relative_path": path.name,
                "raw_sha256": sha256_bytes(path.read_bytes()),
                "size_bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": "expected_pe.r8.r6.static_design_manifest.v1",
        "status": "FROZEN_PHASE_1_STATIC_AWAITING_INDEPENDENT_AUDIT",
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "records": manifest_records,
        "record_count": len(manifest_records),
        "signer_identity_bound": False,
        "payload_generation_count": 0,
    }
    _write_new(staging / "MANIFEST.json", _sealed(manifest))
    _write_new(staging / "CHECKSUMS.sha256", _checksums(staging))
    os.replace(staging, DESIGN_ROOT)

    launcher = PROJECT_ROOT / LAUNCHER_RELATIVE
    builder = PROJECT_ROOT / BUILDER_RELATIVE
    anchor = {
        "schema_version": "expected_pe.r8.r6.static_external_anchor.v1",
        "status": "FROZEN_STATIC_PIN_NO_SIGNER_IDENTITY_HASH_OUT_OF_BAND",
        "phase": "PHASE_1_STATIC_ONLY",
        "signer_identity_bound": False,
        "design_root_relative": DESIGN_ROOT_RELATIVE,
        "design_checksums_raw_sha256": sha256_bytes(
            (DESIGN_ROOT / "CHECKSUMS.sha256").read_bytes()
        ),
        "source_lock_relative": f"{DESIGN_ROOT_RELATIVE}/SOURCE_LOCK.json",
        "source_lock_raw_sha256": sha256_bytes(source_raw),
        "source_archive_relative": f"{DESIGN_ROOT_RELATIVE}/SOURCE_ARCHIVE.zip",
        "source_archive_raw_sha256": sha256_bytes(source_archive),
        "runtime_tcb_relative": f"{DESIGN_ROOT_RELATIVE}/RUNTIME_TCB.json",
        "runtime_tcb_raw_sha256": sha256_bytes(runtime_raw),
        "launcher_relative": LAUNCHER_RELATIVE,
        "launcher_raw_sha256": sha256_bytes(launcher.read_bytes()),
        "r7_design_root_relative": R7_DESIGN_ROOT_RELATIVE,
        "r7_design_checksums_raw_sha256": R7_DESIGN_CHECKSUMS_RAW_SHA256,
        "scheduler_worker_cap": 16,
        "predecessor_evidence": predecessor,
        "builder_relative": BUILDER_RELATIVE,
        "builder_raw_sha256": sha256_bytes(builder.read_bytes()),
    }
    anchor_path = PROJECT_ROOT / EXTERNAL_ANCHOR_RELATIVE
    anchor_staging = anchor_path.parent / f".{anchor_path.name}.staging"
    _write_new(anchor_staging, _canonical(anchor))
    os.replace(anchor_staging, anchor_path)
    print(
        _canonical(
            {
                "status": "FROZEN_R8_R6_PHASE_1_STATIC_NO_SIGNER_IDENTITY",
                "design_root_relative": DESIGN_ROOT_RELATIVE,
                "design_checksums_raw_sha256": sha256_bytes(
                    (DESIGN_ROOT / "CHECKSUMS.sha256").read_bytes()
                ),
                "external_anchor_relative": EXTERNAL_ANCHOR_RELATIVE,
                "external_anchor_raw_sha256": sha256_bytes(anchor_path.read_bytes()),
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
