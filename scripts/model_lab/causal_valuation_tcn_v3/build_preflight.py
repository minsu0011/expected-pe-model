"""Build and freeze the isolated score-free Causal Valuation TCN V3 preflight."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping


PROJECT_ROOT = Path(
    "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
SCRIPT_ROOT = PROJECT_ROOT / "scripts/model_lab/causal_valuation_tcn_v3"
PACKAGE_ROOT = PROJECT_ROOT / "research/model_zoo/causal_valuation_tcn_v3"
TEST_ROOT = PROJECT_ROOT / "tests/model_lab/causal_valuation_tcn_v3"
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
RUFF_EXECUTABLE = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
RUFF_EXECUTABLE_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)
TRUSTED_LAUNCHER = SCRIPT_ROOT / "trusted_launcher.py"
SOURCE_LOCK = SCRIPT_ROOT / "V3_SOURCE_LOCK.json"
RUNTIME_LOCK = SCRIPT_ROOT / "V3_RUNTIME_LOCK.json"
FINAL_OUTPUT = OUTPUTS_ROOT / (
    "model_zoo_causal_valuation_tcn_v3_"
    "score_free_design_environment_preflight_20260821"
)
STAGE = OUTPUTS_ROOT / ".causal_valuation_tcn_v3_verified_stage"
BUNDLE_FILES = (
    "ACCESS_RECEIPT.json",
    "CHECKSUMS.sha256",
    "DESIGN.md",
    "DESIGN_CONTRACT.json",
    "ENVIRONMENT_DEPENDENCY_CLOSURE.json",
    "INPUT_AGNOSTIC_PREFLIGHT.json",
    "MANIFEST.json",
    "MODEL_HYPOTHESIS.md",
    "QUALITY_RECEIPT.json",
    "REFERENCE_LICENSE_REGISTRY.json",
    "SEAL.json",
    "SOURCE_CLOSURE.json",
    "STATIC_SOURCE_AUDIT.json",
    "SYNTHETIC_SMOKE.json",
)
PAYLOAD_FILES = tuple(
    name for name in BUNDLE_FILES if name not in {"CHECKSUMS.sha256", "SEAL.json"}
)
CONTAINER_CHILDREN = ("EXTERNAL_ANCHOR.json", "EXTERNAL_ANCHOR.sha256", "bundle")
CANDIDATES = (
    "cvtcn_v3_tcn_residual",
    "cvtcn_v3_grud_residual",
    "cvtcn_v3_static_state_mlp",
)
AUTHORITY_ZERO = {
    "real_fit": False,
    "real_prediction": False,
    "evaluation": False,
    "truth_or_vault": False,
    "heldout": False,
    "score": False,
    "registry_or_champion": False,
    "seed_derivation_or_reservation": False,
    "promotion": False,
}
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class V3BuildError(RuntimeError):
    """Raised when the score-free freeze cannot be proven complete."""


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(8 * 1024 * 1024)
            if not block:
                return hasher.hexdigest()
            hasher.update(block)


def _ordinary(path: Path, *, directory: bool, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise V3BuildError(f"{label} is absent") from error
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise V3BuildError(f"{label} contains a reparse/symlink component")
    metadata = os.lstat(absolute)
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise V3BuildError(f"{label} is not an ordinary directory")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise V3BuildError(f"{label} is not an ordinary file")
    return absolute


def _file_record(path: Path, *, relative_to: Path | None = None) -> dict[str, Any]:
    ordinary = _ordinary(path, directory=False, label=str(path))
    name = ordinary.relative_to(relative_to).as_posix() if relative_to else ordinary.as_posix()
    return {
        "path": name,
        "bytes": ordinary.stat().st_size,
        "raw_sha256": _sha256_file(ordinary),
    }


def _semantic(payload: Mapping[str, Any]) -> dict[str, Any]:
    if "semantic_sha256" in payload:
        raise V3BuildError("payload already contains a semantic seal")
    output = dict(payload)
    output["semantic_sha256"] = _sha256_bytes(_canonical(payload))
    return output


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return _canonical(payload) + b"\n"


def _clean_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    keep = (
        "ALLUSERSPROFILE", "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH",
        "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROGRAMDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "SYSTEMDRIVE", "SYSTEMROOT",
        "TEMP", "TMP", "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR",
    )
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    environment.update({
        "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "2026082107",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    if extra:
        environment.update(extra)
    return environment


def _run(command: list[str], *, timeout: int, environment: Mapping[str, str]) -> dict[str, Any]:
    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=dict(environment),
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    stdout = process.stdout or b""
    stderr = process.stderr or b""
    try:
        stdout_text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise V3BuildError("subprocess stdout is not strict UTF-8") from error
    return {
        "command": command,
        "return_code": process.returncode,
        "stdout": stdout_text,
        "stdout_sha256": _sha256_bytes(stdout),
        "stderr_sha256": _sha256_bytes(stderr),
        "output_sha256": _sha256_bytes(stdout + stderr),
        "output_tail": (stdout + stderr)[-10000:].decode(
            "utf-8", errors="backslashreplace"
        ),
    }


def _strict_single_object(text: str, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise V3BuildError(f"{label} did not emit one JSON object") from error
    if type(payload) is not dict:
        raise V3BuildError(f"{label} root is not an object")
    return payload


def _launcher_hashes() -> tuple[str, str]:
    text = _ordinary(TRUSTED_LAUNCHER, directory=False, label="trusted launcher").read_text(
        encoding="utf-8", errors="strict"
    )
    source_match = re.search(r'^PINNED_SOURCE_LOCK_SHA256 = "([0-9a-f]{64})"$', text, re.MULTILINE)
    runtime_match = re.search(r'^PINNED_RUNTIME_LOCK_SHA256 = "([0-9a-f]{64})"$', text, re.MULTILINE)
    if source_match is None or runtime_match is None:
        raise V3BuildError("trusted launcher lock hashes are not finalized literals")
    if _sha256_file(SOURCE_LOCK) != source_match.group(1):
        raise V3BuildError("source lock differs from trusted launcher")
    if _sha256_file(RUNTIME_LOCK) != runtime_match.group(1):
        raise V3BuildError("runtime lock differs from trusted launcher")
    return source_match.group(1), runtime_match.group(1)


def _trusted_preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    command = [
        str(PINNED_PYTHON), "-I", "-B", "-S", "-X",
        f"pycache_prefix={STAGE / 'forbidden_bytecode_sink'}",
        str(TRUSTED_LAUNCHER), "--preflight",
    ]
    result = _run(command, timeout=2400, environment=_clean_environment())
    if result["return_code"] != 0:
        raise V3BuildError("trusted preflight failed:\n" + result["output_tail"])
    payload = _strict_single_object(result["stdout"], label="trusted preflight")
    if (
        payload.get("status")
        != "PASS_TRUSTED_TEST_CPU_TWO_INDEPENDENT_GPU_PREFLIGHT"
        or payload.get("authority") != AUTHORITY_ZERO
    ):
        raise V3BuildError("trusted preflight receipt drifted")
    return result, payload


def _test_receipt(preflight: Mapping[str, Any]) -> dict[str, Any]:
    text = preflight.get("test_stdout")
    if type(text) is not str:
        raise V3BuildError("trusted test stdout is absent")
    receipt = _strict_single_object(text, label="trusted adversarial tests")
    if receipt != {
        "schema_version": "expected_pe.causal_valuation_tcn_v3.adversarial_tests.v1",
        "status": "PASS_CAUSAL_VALUATION_TCN_V3_ADVERSARIAL_TESTS",
        "tests_run": 18,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "scope": "synthetic_contract_and_source_attacks_only",
    }:
        raise V3BuildError("trusted adversarial test receipt drifted")
    return receipt


def _validate_smoke(preflight: Mapping[str, Any]) -> dict[str, Any]:
    workers = json.loads(json.dumps(preflight.get("workers")))
    if type(workers) is not dict or set(workers) != {
        "cpu", "gpu_process_1", "gpu_process_2"
    }:
        raise V3BuildError("trusted worker universe drifted")
    boundary = {
        "external_dataset_opened": False,
        "protected_artifact_opened": False,
        "synthetic_fit_count": 0,
        "input_agnostic_model_probe_count": 3,
        "score_computed": False,
        "registry_opened_or_mutated": False,
        "seed_derived_or_reserved": False,
    }
    for name, worker in workers.items():
        if (
            worker.get("status") != "PASS_INPUT_AGNOSTIC_MODEL_AND_CUSTODY_PROBE"
            or worker.get("device") != ("cpu" if name == "cpu" else "cuda")
            or worker.get("access_boundary") != boundary
            or set(worker.get("variants", {})) != set(CANDIDATES)
        ):
            raise V3BuildError(f"trusted smoke worker drifted: {name}")
        nuisance = worker.get("nuisance_end_to_end")
        if (
            type(nuisance) is not dict
            or nuisance.get("loss_finite") is not True
            or nuisance.get("nuisance_effect_sum") != 0.0
            or nuisance.get("nuisance_in_deployable_state") is not False
        ):
            raise V3BuildError("end-to-end nuisance smoke drifted")
    first = workers["gpu_process_1"]
    second = workers["gpu_process_2"]
    if first["reproducibility_digest"] != second["reproducibility_digest"]:
        raise V3BuildError("independent GPU reproducibility digest drifted")
    for field in ("module_origin_records", "module_origin_closure_sha256"):
        if first["runtime_receipt"][field] != second["runtime_receipt"][field]:
            raise V3BuildError(f"independent GPU runtime closure drifted: {field}")
    normalized_native: dict[str, list[dict[str, Any]]] = {}
    for name, worker in (("gpu_process_1", first), ("gpu_process_2", second)):
        records = worker["runtime_receipt"].get("loaded_native_module_records")
        if type(records) is not list:
            raise V3BuildError(f"{name} native runtime closure is not a list")
        canonical_records: dict[str, dict[str, Any]] = {}
        for record in records:
            if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
                raise V3BuildError(f"{name} native runtime record drifted")
            key = record["path"].casefold()
            if key in canonical_records:
                raise V3BuildError(f"{name} native runtime universe is ambiguous")
            canonical_records[key] = {
                "path": key,
                "bytes": record["bytes"],
                "raw_sha256": record["raw_sha256"],
            }
        normalized_native[name] = [canonical_records[key] for key in sorted(canonical_records)]
    if normalized_native["gpu_process_1"] != normalized_native["gpu_process_2"]:
        raise V3BuildError("independent GPU normalized native runtime closure drifted")
    normalized_native_sha256 = _sha256_bytes(
        _canonical(normalized_native["gpu_process_1"])
    )
    comparisons: dict[str, float] = {}
    for candidate in CANDIDATES:
        cpu_values = workers["cpu"]["variants"][candidate].pop("output_values")
        gpu_one_values = first["variants"][candidate].pop("output_values")
        gpu_two_values = second["variants"][candidate].pop("output_values")
        if gpu_one_values != gpu_two_values or not cpu_values or len(cpu_values) != len(gpu_one_values):
            raise V3BuildError(f"candidate output geometry/reproducibility drifted: {candidate}")
        maximum = max(abs(float(left) - float(right)) for left, right in zip(cpu_values, gpu_one_values))
        if maximum > 7.5e-5:
            raise V3BuildError(f"CPU/GPU tolerance drifted: {candidate}={maximum}")
        comparisons[candidate] = maximum
        for worker in workers.values():
            variant = worker["variants"][candidate]
            if (
                variant["causal_prior_decision_max_abs_delta"] != 0.0
                or variant["nuisance_in_deployable_state"] is not False
                or variant["optimizer_steps"] != 0
            ):
                raise V3BuildError(f"candidate causal/deploy boundary drifted: {candidate}")
    return _semantic({
        "schema_version": "expected_pe.causal_valuation_tcn_v3.synthetic_smoke.v1",
        "status": "PASS_CPU_AND_TWO_GPU_INPUT_AGNOSTIC_MODEL_PROBE",
        "workers": workers,
        "cpu_gpu_max_abs_by_candidate": comparisons,
        "cpu_gpu_absolute_tolerance": 7.5e-5,
        "gpu_two_process_digest_equal": True,
        "gpu_two_process_module_and_dll_closure_equal": True,
        "gpu_normalized_native_module_closure_sha256": normalized_native_sha256,
        "scope": "deterministically_generated_input_agnostic_tensors_only",
    })


def _ruff() -> dict[str, Any]:
    if _sha256_file(RUFF_EXECUTABLE) != RUFF_EXECUTABLE_SHA256:
        raise V3BuildError("pinned Ruff executable drifted")
    command = [
        str(RUFF_EXECUTABLE), "check", "--no-cache",
        str(PACKAGE_ROOT), str(SCRIPT_ROOT), str(TEST_ROOT),
    ]
    result = _run(command, timeout=300, environment=_clean_environment())
    if result["return_code"] != 0:
        raise V3BuildError("Ruff failed:\n" + result["output_tail"])
    return result


def _source_lock_payload() -> dict[str, Any]:
    payload = _strict_single_object(SOURCE_LOCK.read_text(encoding="utf-8"), label="source lock")
    if payload.get("authority") != AUTHORITY_ZERO:
        raise V3BuildError("source lock authority drifted")
    return payload


def _payloads(
    *, preflight_process: Mapping[str, Any], preflight: Mapping[str, Any],
    tests: Mapping[str, Any], ruff: Mapping[str, Any], smoke: Mapping[str, Any],
    source_lock_sha: str, runtime_lock_sha: str,
) -> dict[str, bytes]:
    source_lock = _source_lock_payload()
    preimport = preflight["preimport_attestation"]
    runtime_receipts = {
        name: preflight["workers"][name]["runtime_receipt"]
        for name in ("cpu", "gpu_process_1", "gpu_process_2")
    }
    json_payloads: dict[str, dict[str, Any]] = {
        "ACCESS_RECEIPT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.access_receipt.v1",
            "status": "PASS_SCORE_FREE_SYNTHETIC_ONLY_ACCESS_BOUNDARY",
            "external_dataset_open_count": 0,
            "protected_payload_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "score_count": 0,
            "registry_open_or_mutation_count": 0,
            "synthetic_worker_count": 3,
            "authority": AUTHORITY_ZERO,
        }),
        "DESIGN_CONTRACT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.design_contract.v1",
            "status": "FROZEN_SCORE_FREE_DESIGN_CONTRACT",
            "candidate_ids": list(CANDIDATES),
            "sequence_length": 128,
            "observed_age": 0,
            "missing_age_recurrence": "exact_global_session_distance_capped_at_127",
            "static_control": "same_row_only_mlp",
            "global_calendar_fold": {
                "minimum_train_rows": 756,
                "purge_sessions": 127,
                "embargo_sessions": 5,
                "validation_strictly_post_train": True,
                "validation_entity_history_train_overlap_required": True,
            },
            "nuisance": {
                "group_universe": list("ABCDEFGHIJ"),
                "training_only": True,
                "zero_sum": True,
                "single_end_to_end_custody": True,
                "removed_from_deployable_state": True,
            },
            "torch_public_entrypoints": "canonical_source_fold_candidate_row_and_live_digest_custody_only",
            "authority": AUTHORITY_ZERO,
        }),
        "ENVIRONMENT_DEPENDENCY_CLOSURE.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.environment_closure.v1",
            "status": "PASS_EXTERNALLY_PINNED_RUNTIME_AND_TWO_GPU_CLOSURE",
            "preimport_attestation": preimport,
            "cpu_runtime_receipt": runtime_receipts["cpu"],
            "gpu_process_1_runtime_receipt": runtime_receipts["gpu_process_1"],
            "gpu_process_2_runtime_receipt": runtime_receipts["gpu_process_2"],
            "source_lock_sha256": source_lock_sha,
            "runtime_lock_sha256": runtime_lock_sha,
            "authority": AUTHORITY_ZERO,
        }),
        "INPUT_AGNOSTIC_PREFLIGHT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.input_agnostic_preflight.v1",
            "status": "PASS_NO_FIT_NO_REAL_DATA_MODEL_AND_CUSTODY_PROBES",
            "candidate_ids": list(CANDIDATES),
            "cpu_reproducibility_digest": preflight["workers"]["cpu"]["reproducibility_digest"],
            "gpu_process_1_reproducibility_digest": preflight["workers"]["gpu_process_1"]["reproducibility_digest"],
            "gpu_process_2_reproducibility_digest": preflight["workers"]["gpu_process_2"]["reproducibility_digest"],
            "gpu_two_process_digest_equal": True,
            "optimizer_step_count": 0,
            "real_row_count": 0,
            "authority": AUTHORITY_ZERO,
        }),
        "MANIFEST.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.manifest.v1",
            "status": "FROZEN_EXACT_UNIVERSE_DECLARATION",
            "bundle_file_universe": list(BUNDLE_FILES),
            "bundle_file_count": len(BUNDLE_FILES),
            "container_child_universe": list(CONTAINER_CHILDREN),
            "container_child_count": len(CONTAINER_CHILDREN),
            "source_record_count": len(source_lock["source_records"]),
            "authority": AUTHORITY_ZERO,
        }),
        "QUALITY_RECEIPT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.quality_receipt.v1",
            "status": "PASS_RUFF_18_TESTS_CPU_TWO_GPU",
            "ruff_return_code": ruff["return_code"],
            "ruff_output_sha256": ruff["output_sha256"],
            "tests": tests,
            "trusted_launcher_return_code": preflight_process["return_code"],
            "trusted_launcher_output_sha256": preflight_process["output_sha256"],
            "cpu_worker_return_code": preflight["worker_process_receipts"]["cpu"]["return_code"],
            "gpu_process_1_return_code": preflight["worker_process_receipts"]["gpu_process_1"]["return_code"],
            "gpu_process_2_return_code": preflight["worker_process_receipts"]["gpu_process_2"]["return_code"],
            "authority": AUTHORITY_ZERO,
        }),
        "SOURCE_CLOSURE.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.source_closure.v1",
            "status": "PASS_EXTERNALLY_PINNED_VERIFIED_BYTES_SOURCE_CLOSURE",
            "source_lock_sha256": source_lock_sha,
            "runtime_lock_sha256": runtime_lock_sha,
            "source_manifest_sha256": source_lock["source_manifest_sha256"],
            "source_records": source_lock["source_records"],
            "exact_roots": source_lock["exact_roots"],
            "trusted_launcher": _file_record(TRUSTED_LAUNCHER),
            "cross_seal_verifier": _file_record(Path(__file__)),
            "authority": AUTHORITY_ZERO,
        }),
        "STATIC_SOURCE_AUDIT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v3.static_source_audit.v1",
            "status": "PASS_ALL_V2_NO_GO_REPAIRS_AND_V3_ATTACK_REGRESSIONS",
            "p0": 0,
            "p1": 0,
            "p2": 0,
            "attack_regression_test_count": tests["tests_run"],
            "verified_bytes_loader": True,
            "caller_source_map_allowed": False,
            "normal_governed_filesystem_import_allowed": False,
            "extra_source_directory_or_bytecode_allowed": False,
            "source_live_digest_revalidated_at_every_entrypoint": True,
            "unified_nuisance_loss_and_deploy_custody": True,
            "authority": AUTHORITY_ZERO,
        }),
        "SYNTHETIC_SMOKE.json": dict(smoke),
    }
    output = {name: _json_bytes(payload) for name, payload in json_payloads.items()}
    output["DESIGN.md"] = (PACKAGE_ROOT / "DESIGN.md").read_bytes()
    output["MODEL_HYPOTHESIS.md"] = (PACKAGE_ROOT / "MODEL_HYPOTHESIS.md").read_bytes()
    output["REFERENCE_LICENSE_REGISTRY.json"] = (
        PACKAGE_ROOT / "REFERENCE_LICENSE_REGISTRY.json"
    ).read_bytes()
    if set(output) != set(PAYLOAD_FILES):
        raise V3BuildError("provisional payload universe drifted")
    return output


def _write_bundle(bundle: Path, payloads: Mapping[str, bytes]) -> None:
    bundle.mkdir()
    for name in PAYLOAD_FILES:
        (bundle / name).write_bytes(payloads[name])
    records = [_file_record(bundle / name, relative_to=bundle) for name in PAYLOAD_FILES]
    checksum_content = "".join(
        f"{record['raw_sha256']}  {record['path']}\n" for record in records
    ).encode("ascii")
    (bundle / "CHECKSUMS.sha256").write_bytes(checksum_content)
    checksum_record = _file_record(bundle / "CHECKSUMS.sha256", relative_to=bundle)
    seal = _semantic({
        "schema_version": "expected_pe.causal_valuation_tcn_v3.seal.v1",
        "status": "SEALED_EXACT_14_FILE_SCORE_FREE_PREFLIGHT",
        "bundle_file_universe": list(BUNDLE_FILES),
        "payload_records": records,
        "payload_record_root_sha256": _sha256_bytes(_canonical(records)),
        "checksums_record": checksum_record,
        "source_lock_record": _file_record(SOURCE_LOCK),
        "runtime_lock_record": _file_record(RUNTIME_LOCK),
        "trusted_launcher_record": _file_record(TRUSTED_LAUNCHER),
        "cross_seal_verifier_record": _file_record(Path(__file__)),
        "authority": AUTHORITY_ZERO,
    })
    (bundle / "SEAL.json").write_bytes(_json_bytes(seal))
    _verify_bundle(bundle)


def _verify_bundle(bundle: Path) -> dict[str, Any]:
    bundle = _ordinary(bundle, directory=True, label="frozen bundle")
    actual: list[str] = []
    for child in bundle.iterdir():
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ) or not stat.S_ISREG(metadata.st_mode):
            raise V3BuildError("bundle contains a non-ordinary file member")
        actual.append(child.name)
    if tuple(sorted(actual)) != BUNDLE_FILES:
        raise V3BuildError("bundle exact 14-file universe drifted")
    records = [_file_record(bundle / name, relative_to=bundle) for name in PAYLOAD_FILES]
    expected_checksums = "".join(
        f"{record['raw_sha256']}  {record['path']}\n" for record in records
    ).encode("ascii")
    if (bundle / "CHECKSUMS.sha256").read_bytes() != expected_checksums:
        raise V3BuildError("bundle checksum cross-seal drifted")
    seal = _strict_single_object((bundle / "SEAL.json").read_text(encoding="utf-8"), label="bundle seal")
    semantic = seal.pop("semantic_sha256", None)
    if semantic != _sha256_bytes(_canonical(seal)):
        raise V3BuildError("bundle seal semantic hash drifted")
    if (
        seal.get("status") != "SEALED_EXACT_14_FILE_SCORE_FREE_PREFLIGHT"
        or seal.get("bundle_file_universe") != list(BUNDLE_FILES)
        or seal.get("payload_records") != records
        or seal.get("payload_record_root_sha256") != _sha256_bytes(_canonical(records))
        or seal.get("checksums_record") != _file_record(bundle / "CHECKSUMS.sha256", relative_to=bundle)
        or seal.get("authority") != AUTHORITY_ZERO
    ):
        raise V3BuildError("bundle seal cross-reference drifted")
    for name in PAYLOAD_FILES:
        if not name.endswith(".json") or name == "REFERENCE_LICENSE_REGISTRY.json":
            continue
        payload = _strict_single_object((bundle / name).read_text(encoding="utf-8"), label=name)
        payload_semantic = payload.pop("semantic_sha256", None)
        if payload_semantic != _sha256_bytes(_canonical(payload)):
            raise V3BuildError(f"artifact semantic seal drifted: {name}")
        if payload.get("authority", AUTHORITY_ZERO) != AUTHORITY_ZERO:
            raise V3BuildError(f"artifact authority drifted: {name}")
    complete_records = [_file_record(bundle / name, relative_to=bundle) for name in BUNDLE_FILES]
    return {
        "bundle_file_records": complete_records,
        "bundle_tree_sha256": _sha256_bytes(_canonical(complete_records)),
        "seal_raw_sha256": _sha256_file(bundle / "SEAL.json"),
        "checksums_raw_sha256": _sha256_file(bundle / "CHECKSUMS.sha256"),
    }


def _write_anchor(container: Path) -> None:
    closure = _verify_bundle(container / "bundle")
    anchor = _semantic({
        "schema_version": "expected_pe.causal_valuation_tcn_v3.external_anchor.v1",
        "status": "EXTERNALLY_ANCHORED_EXACT_UNIVERSE_PREFLIGHT",
        "container_child_universe": list(CONTAINER_CHILDREN),
        **closure,
        "source_lock_record": _file_record(SOURCE_LOCK),
        "runtime_lock_record": _file_record(RUNTIME_LOCK),
        "trusted_launcher_record": _file_record(TRUSTED_LAUNCHER),
        "cross_seal_verifier_record": _file_record(Path(__file__)),
        "authority": AUTHORITY_ZERO,
    })
    anchor_path = container / "EXTERNAL_ANCHOR.json"
    anchor_path.write_bytes(_json_bytes(anchor))
    anchor_sha = _sha256_file(anchor_path)
    (container / "EXTERNAL_ANCHOR.sha256").write_text(
        f"{anchor_sha}  EXTERNAL_ANCHOR.json\n", encoding="ascii", newline=""
    )


def _verify_container(container: Path) -> dict[str, Any]:
    container = _ordinary(container, directory=True, label="frozen output container")
    actual: dict[str, str] = {}
    for child in container.iterdir():
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise V3BuildError("container contains a reparse/symlink child")
        if stat.S_ISDIR(metadata.st_mode):
            actual[child.name] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            actual[child.name] = "file"
        else:
            raise V3BuildError("container contains a non-file/non-directory child")
    if tuple(sorted(actual)) != CONTAINER_CHILDREN or actual["bundle"] != "directory" or any(
        actual[name] != "file" for name in CONTAINER_CHILDREN[:2]
    ):
        raise V3BuildError("container exact 3-child universe drifted")
    closure = _verify_bundle(container / "bundle")
    anchor_path = _ordinary(container / "EXTERNAL_ANCHOR.json", directory=False, label="external anchor")
    expected_pointer = f"{_sha256_file(anchor_path)}  EXTERNAL_ANCHOR.json\n".encode("ascii")
    if (container / "EXTERNAL_ANCHOR.sha256").read_bytes() != expected_pointer:
        raise V3BuildError("external anchor pointer drifted")
    anchor = _strict_single_object(anchor_path.read_text(encoding="utf-8"), label="external anchor")
    semantic = anchor.pop("semantic_sha256", None)
    if semantic != _sha256_bytes(_canonical(anchor)):
        raise V3BuildError("external anchor semantic hash drifted")
    if (
        anchor.get("status") != "EXTERNALLY_ANCHORED_EXACT_UNIVERSE_PREFLIGHT"
        or anchor.get("container_child_universe") != list(CONTAINER_CHILDREN)
        or any(anchor.get(key) != value for key, value in closure.items())
        or anchor.get("authority") != AUTHORITY_ZERO
    ):
        raise V3BuildError("external anchor cross-seal drifted")
    return {
        **closure,
        "external_anchor_raw_sha256": _sha256_file(anchor_path),
        "external_anchor_pointer_raw_sha256": _sha256_file(
            container / "EXTERNAL_ANCHOR.sha256"
        ),
    }


def _safe_remove_provisional(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    outputs = Path(os.path.abspath(OUTPUTS_ROOT))
    if absolute.parent != outputs or not absolute.name.startswith(
        ".causal_valuation_tcn_v3_provisional."
    ):
        raise V3BuildError("refused unsafe provisional cleanup target")
    if absolute.exists():
        _ordinary(absolute, directory=True, label="provisional cleanup target")
        shutil.rmtree(absolute)


def main() -> int:
    _ordinary(OUTPUTS_ROOT, directory=True, label="outputs root")
    _ordinary(PINNED_PYTHON, directory=False, label="pinned Python")
    _ordinary(RUFF_EXECUTABLE, directory=False, label="pinned Ruff")
    if FINAL_OUTPUT.exists() or STAGE.exists():
        raise V3BuildError("final output or fixed verified stage already exists")
    source_lock_sha, runtime_lock_sha = _launcher_hashes()
    provisional = Path(
        tempfile.mkdtemp(prefix=".causal_valuation_tcn_v3_provisional.", dir=OUTPUTS_ROOT)
    )
    try:
        preflight_process, preflight = _trusted_preflight()
        tests = _test_receipt(preflight)
        smoke = _validate_smoke(preflight)
        ruff = _ruff()
        payloads = _payloads(
            preflight_process=preflight_process,
            preflight=preflight,
            tests=tests,
            ruff=ruff,
            smoke=smoke,
            source_lock_sha=source_lock_sha,
            runtime_lock_sha=runtime_lock_sha,
        )
        _write_bundle(provisional / "bundle", payloads)
        _write_anchor(provisional)
        provisional.replace(FINAL_OUTPUT)
        final_closure = _verify_container(FINAL_OUTPUT)
        output = {
            "schema_version": "expected_pe.causal_valuation_tcn_v3.build_result.v1",
            "status": "FROZEN_SCORE_FREE_DESIGN_ENVIRONMENT_PREFLIGHT_ONLY",
            "output_directory": FINAL_OUTPUT.relative_to(PROJECT_ROOT).as_posix(),
            "bundle_file_count": len(BUNDLE_FILES),
            "container_child_count": len(CONTAINER_CHILDREN),
            "tests_run": tests["tests_run"],
            "ruff_return_code": ruff["return_code"],
            "cpu_worker_return_code": preflight["worker_process_receipts"]["cpu"]["return_code"],
            "gpu_process_1_return_code": preflight["worker_process_receipts"]["gpu_process_1"]["return_code"],
            "gpu_process_2_return_code": preflight["worker_process_receipts"]["gpu_process_2"]["return_code"],
            "source_lock_sha256": source_lock_sha,
            "runtime_lock_sha256": runtime_lock_sha,
            **final_closure,
            "authority": AUTHORITY_ZERO,
        }
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        if provisional.exists():
            _safe_remove_provisional(provisional)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
