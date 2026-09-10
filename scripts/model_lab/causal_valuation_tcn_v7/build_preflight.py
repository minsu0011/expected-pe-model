"""Build and freeze the isolated score-free Causal Valuation TCN V7 preflight."""

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
SCRIPT_ROOT = PROJECT_ROOT / "scripts/model_lab/causal_valuation_tcn_v7"
PACKAGE_ROOT = PROJECT_ROOT / "research/model_zoo/causal_valuation_tcn_v7"
TEST_ROOT = PROJECT_ROOT / "tests/model_lab/causal_valuation_tcn_v7"
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
RUFF_EXECUTABLE = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
RUFF_EXECUTABLE_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)
TRUSTED_LAUNCHER = SCRIPT_ROOT / "trusted_launcher.py"
SOURCE_LOCK = SCRIPT_ROOT / "V7_SOURCE_LOCK.json"
RUNTIME_LOCK = SCRIPT_ROOT / "V7_RUNTIME_LOCK.json"
FINAL_OUTPUT = OUTPUTS_ROOT / (
    "model_zoo_causal_valuation_tcn_v7_"
    "score_free_design_environment_preflight_20260821"
)
STAGE = OUTPUTS_ROOT / ".causal_valuation_tcn_v7_verified_stage"
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
    "cvtcn_v7_tcn_residual",
    "cvtcn_v7_grud_residual",
    "cvtcn_v7_static_state_mlp",
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


class V7BuildError(RuntimeError):
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
            raise V7BuildError(f"{label} is absent") from error
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise V7BuildError(f"{label} contains a reparse/symlink component")
    metadata = os.lstat(absolute)
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise V7BuildError(f"{label} is not an ordinary directory")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise V7BuildError(f"{label} is not an ordinary file")
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
        raise V7BuildError("payload already contains a semantic seal")
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
        "PYTHONHASHSEED": "2026082109",
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
        raise V7BuildError("subprocess stdout is not strict UTF-8") from error
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
        raise V7BuildError(f"{label} did not emit one JSON object") from error
    if type(payload) is not dict:
        raise V7BuildError(f"{label} root is not an object")
    return payload


def _launcher_hashes() -> tuple[str, str]:
    text = _ordinary(TRUSTED_LAUNCHER, directory=False, label="trusted launcher").read_text(
        encoding="utf-8", errors="strict"
    )
    source_match = re.search(r'^PINNED_SOURCE_LOCK_SHA256 = "([0-9a-f]{64})"$', text, re.MULTILINE)
    runtime_match = re.search(r'^PINNED_RUNTIME_LOCK_SHA256 = "([0-9a-f]{64})"$', text, re.MULTILINE)
    if source_match is None or runtime_match is None:
        raise V7BuildError("trusted launcher lock hashes are not finalized literals")
    if _sha256_file(SOURCE_LOCK) != source_match.group(1):
        raise V7BuildError("source lock differs from trusted launcher")
    if _sha256_file(RUNTIME_LOCK) != runtime_match.group(1):
        raise V7BuildError("runtime lock differs from trusted launcher")
    return source_match.group(1), runtime_match.group(1)


def _trusted_preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    command = [
        str(PINNED_PYTHON), "-I", "-B", "-S", "-X",
        f"pycache_prefix={STAGE / 'forbidden_bytecode_sink'}",
        str(TRUSTED_LAUNCHER), "--preflight",
    ]
    result = _run(command, timeout=2400, environment=_clean_environment())
    if result["return_code"] != 0:
        raise V7BuildError("trusted preflight failed:\n" + result["output_tail"])
    payload = _strict_single_object(result["stdout"], label="trusted preflight")
    if (
        payload.get("status")
        != "PASS_TRUSTED_TEST_CPU_TWO_INDEPENDENT_GPU_PREFLIGHT"
        or payload.get("authority") != AUTHORITY_ZERO
    ):
        raise V7BuildError("trusted preflight receipt drifted")
    return result, payload


def _test_receipt(preflight: Mapping[str, Any]) -> dict[str, Any]:
    text = preflight.get("test_stdout")
    if type(text) is not str:
        raise V7BuildError("trusted test stdout is absent")
    receipt = _strict_single_object(text, label="trusted adversarial tests")
    if receipt != {
        "schema_version": "expected_pe.causal_valuation_tcn_v7.adversarial_tests.v1",
        "status": "PASS_CAUSAL_VALUATION_TCN_V7_ADVERSARIAL_TESTS",
        "tests_run": 67,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "scope": "synthetic_contract_and_source_attacks_only",
    }:
        raise V7BuildError("trusted adversarial test receipt drifted")
    return receipt


def _validate_smoke(preflight: Mapping[str, Any]) -> dict[str, Any]:
    workers = json.loads(json.dumps(preflight.get("workers")))
    if type(workers) is not dict or set(workers) != {
        "cpu", "gpu_process_1", "gpu_process_2"
    }:
        raise V7BuildError("trusted worker universe drifted")
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
            raise V7BuildError(f"trusted smoke worker drifted: {name}")
        nuisance = worker.get("nuisance_end_to_end")
        if (
            type(nuisance) is not dict
            or nuisance.get("loss_finite") is not True
            or type(nuisance.get("nuisance_effect_weighted_sum")) is not float
            or type(nuisance.get("nuisance_projection_residual")) is not float
            or abs(nuisance["nuisance_effect_weighted_sum"])
            != nuisance["nuisance_projection_residual"]
            or nuisance["nuisance_projection_residual"] > 1.0e-12
            or nuisance.get("nuisance_zero_semantics")
            != "BOUNDED_ABSOLUTE_RESIDUAL_NOT_EXACT_ZERO"
            or nuisance.get("nuisance_in_deployable_state") is not False
        ):
            raise V7BuildError("end-to-end nuisance smoke drifted")
    first = workers["gpu_process_1"]
    second = workers["gpu_process_2"]
    if first["reproducibility_digest"] != second["reproducibility_digest"]:
        raise V7BuildError("independent GPU reproducibility digest drifted")
    for field in ("module_origin_records", "module_origin_closure_sha256"):
        if first["runtime_receipt"][field] != second["runtime_receipt"][field]:
            raise V7BuildError(f"independent GPU runtime closure drifted: {field}")
    normalized_native: dict[str, list[dict[str, Any]]] = {}
    for name, worker in (("gpu_process_1", first), ("gpu_process_2", second)):
        records = worker["runtime_receipt"].get("loaded_native_module_records")
        if type(records) is not list:
            raise V7BuildError(f"{name} native runtime closure is not a list")
        canonical_records: dict[str, dict[str, Any]] = {}
        for record in records:
            if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
                raise V7BuildError(f"{name} native runtime record drifted")
            key = record["path"].casefold()
            if key in canonical_records:
                raise V7BuildError(f"{name} native runtime universe is ambiguous")
            canonical_records[key] = {
                "path": key,
                "bytes": record["bytes"],
                "raw_sha256": record["raw_sha256"],
            }
        normalized_native[name] = [canonical_records[key] for key in sorted(canonical_records)]
    if normalized_native["gpu_process_1"] != normalized_native["gpu_process_2"]:
        raise V7BuildError("independent GPU normalized native runtime closure drifted")
    normalized_native_sha256 = _sha256_bytes(
        _canonical(normalized_native["gpu_process_1"])
    )
    comparisons: dict[str, float] = {}
    for candidate in CANDIDATES:
        cpu_values = workers["cpu"]["variants"][candidate].pop("output_values")
        gpu_one_values = first["variants"][candidate].pop("output_values")
        gpu_two_values = second["variants"][candidate].pop("output_values")
        if gpu_one_values != gpu_two_values or not cpu_values or len(cpu_values) != len(gpu_one_values):
            raise V7BuildError(f"candidate output geometry/reproducibility drifted: {candidate}")
        maximum = max(abs(float(left) - float(right)) for left, right in zip(cpu_values, gpu_one_values))
        if maximum > 7.5e-5:
            raise V7BuildError(f"CPU/GPU tolerance drifted: {candidate}={maximum}")
        comparisons[candidate] = maximum
        for worker in workers.values():
            variant = worker["variants"][candidate]
            if (
                variant["causal_prior_decision_max_abs_delta"] != 0.0
                or variant["nuisance_in_deployable_state"] is not False
                or variant["optimizer_steps"] != 0
                or variant.get("future_only_training_center_values_equal") is not True
                or variant.get("future_only_training_center_provenance_distinct")
                is not True
            ):
                raise V7BuildError(f"candidate causal/deploy boundary drifted: {candidate}")
            for provenance in (
                "training_center_custody_sha256",
                "training_center_values_sha256",
                "training_center_value_commitment_sha256",
            ):
                value = variant.get(provenance)
                if (
                    type(value) is not str
                    or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                ):
                    raise V7BuildError(
                        f"candidate training-center provenance drifted: {candidate}"
                    )
    return _semantic({
        "schema_version": "expected_pe.causal_valuation_tcn_v7.synthetic_smoke.v1",
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
        raise V7BuildError("pinned Ruff executable drifted")
    command = [
        str(RUFF_EXECUTABLE), "check", "--no-cache",
        str(PACKAGE_ROOT), str(SCRIPT_ROOT), str(TEST_ROOT),
    ]
    result = _run(command, timeout=300, environment=_clean_environment())
    if result["return_code"] != 0:
        raise V7BuildError("Ruff failed:\n" + result["output_tail"])
    return result


def _source_lock_payload() -> dict[str, Any]:
    payload = _strict_single_object(SOURCE_LOCK.read_text(encoding="utf-8"), label="source lock")
    if payload.get("authority") != AUTHORITY_ZERO:
        raise V7BuildError("source lock authority drifted")
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
            "schema_version": "expected_pe.causal_valuation_tcn_v7.access_receipt.v1",
            "status": "PASS_SCORE_FREE_SYNTHETIC_ONLY_ACCESS_BOUNDARY",
            "external_dataset_open_count": 0,
            "protected_payload_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "score_count": 0,
            "registry_open_or_mutation_count": 0,
            "optimizer_step_count": 0,
            "heldout_open_count": 0,
            "truth_vault_latent_open_count": 0,
            "seed_derivation_or_reservation_count": 0,
            "synthetic_worker_count": 3,
            "authority": AUTHORITY_ZERO,
        }),
        "DESIGN_CONTRACT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v7.design_contract.v1",
            "status": "FROZEN_SCORE_FREE_DESIGN_CONTRACT",
            "candidate_ids": list(CANDIDATES),
            "v3_frozen_design_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v3_"
                    "score_free_design_environment_preflight_20260821"
                ),
                "checksums_raw_sha256": (
                    "5b05ff93a939f408652ec43900e788fdf676e20c8329dc3342cbddd4e073cb47"
                ),
                "external_anchor_raw_sha256": (
                    "d83a1145bea94cea3e2871a731187ddbace6056f3060999140a591cc171efd91"
                ),
                "source_manifest_sha256": (
                    "636f896d5f02e551b722d9c64796e0c9dd7efb898568db7101d1794bdec9282f"
                ),
            },
            "v3_terminal_no_go_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v3_"
                    "independent_score_free_prelaunch_audit_r1_20260821"
                ),
                "checksums_raw_sha256": (
                    "08c8cf99ced148229e6cadd48d4690539a5cb4b75992494d72926bdfda1c5266"
                ),
                "audit_raw_sha256": (
                    "4bdfcd750f016a22a25e5de618eda4ffcd900caf878990176e21812e917015f7"
                ),
                "audit_semantic_sha256": (
                    "5a14ef43ad4f052ef0c50ec967b150d6cf111cb32df3ea530e32932961ed1cb4"
                ),
                "seal_raw_sha256": (
                    "0a75caeb422302210bdeaeb52f506cc4ab9146af46db67443ee8058f734f5eb1"
                ),
                "verdict": (
                    "NO_GO_CAUSAL_VALUATION_TCN_V3_FUTURE_SCORE_BLIND_"
                    "RESEARCH_FIT_OR_PREDICTION"
                ),
                "finding_ids": ["P0-001", "P1-001", "P1-002", "P1-003"],
            },
            "closed_v3_findings": {
                "P0-001": "factory_only_canonical_fold_row_rederivation",
                "P1-001": "live_fold_rebuilt_at_every_downstream_entry",
                "P1-002": "sealed_state_fresh_forward_prediction_artifact",
                "P1-003": "finite_actual_weighted_projection_sum_and_residual",
            },
            "v4_frozen_design_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v4_"
                    "score_free_design_environment_preflight_20260821"
                ),
                "checksums_raw_sha256": (
                    "300eca8f1d177ec251fb52eecacd282bacc99a7726865767872d223a0c116b3e"
                ),
                "external_anchor_raw_sha256": (
                    "fcadb73970b09268fac00e41977316720cb5d1655714559d85f72efa09e351eb"
                ),
                "seal_raw_sha256": (
                    "f7956772ba74eecfc46e386ae55fe22e1fcd05c236e390fba872f9fec8b064b2"
                ),
                "source_manifest_sha256": (
                    "497264e071ac8a31184116567042096cd421f4ced3e7a1ac8784efc8008cfdd9"
                ),
            },
            "v4_terminal_no_go_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v4_"
                    "independent_score_free_prelaunch_audit_r1_20260821"
                ),
                "checksums_raw_sha256": (
                    "949861fb6ba0c0c9e0ba65c5b69a3cecd93855597472d535a65e6977da4c67e2"
                ),
                "audit_raw_sha256": (
                    "5dd132d2f157235a3d3a6a99fa25f4ce80c3e04e950dd2fbad3795f63332be40"
                ),
                "audit_semantic_sha256": (
                    "5d3619233583dcccc0925d536b5dd45345f9f569434b2b9a82137bfa6197917d"
                ),
                "seal_raw_sha256": (
                    "4679bae052d0a52b4fe66a6496c649c5e4b944686afa74d617fe2e6e6f0da6e9"
                ),
                "verdict": (
                    "NO_GO_CAUSAL_VALUATION_TCN_V4_FUTURE_SCORE_BLIND_"
                    "RESEARCH_FIT_OR_PREDICTION"
                ),
                "finding_ids": ["P0-001", "P1-001", "P1-002"],
            },
            "closed_v4_findings": {
                "P0-001": (
                    "factory_private_canonical_train_row_center_derivation_and_"
                    "state_prediction_provenance"
                ),
                "P1-001": (
                    "conv_rf_125_distinguished_from_end_to_end_raw_rf_128_with_"
                    "purge_and_raw_overlap_proof"
                ),
                "P1-002": (
                    "factory_only_receipt_with_exact_live_tensor_recomputation_"
                    "and_sub_tolerance_forgery_rejection"
                ),
            },
            "v5_frozen_design_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v5_"
                    "score_free_design_environment_preflight_20260821"
                ),
                "checksums_raw_sha256": (
                    "4ee771a78c3175ef7e50343e2dedc02b36066541cd8014f0c8654fdb3797f419"
                ),
                "external_anchor_raw_sha256": (
                    "ec12639d93557e92129807c8e89181f9769a57d6ccd5df9fe3e1086b4467c0de"
                ),
                "seal_raw_sha256": (
                    "cf15c1695739623c3dfbdfe35f9edd6ce4f24696f4f51bbf4c621f36b96d9b50"
                ),
                "bundle_tree_sha256": (
                    "071045862419861dc33b25bdb48a59bd6055cb74fdb241e27607c3eaa3f66519"
                ),
                "source_manifest_sha256": (
                    "b0a364796ab78289e789c2f2ef8c7d248f950dca7e386fb3d49a83661f0f2e58"
                ),
            },
            "v5_terminal_no_go_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v5_"
                    "independent_score_free_prelaunch_audit_r1_20260821"
                ),
                "checksums_raw_sha256": (
                    "648b528120b2b087a9f9129df12ad1aff0c04b09eaa12c49226d88da78d16b8e"
                ),
                "audit_raw_sha256": (
                    "ba794d02b38444ff2bf4ca7b1ac25335b2fdbdfb181d5d2775f8948cf65a2ebd"
                ),
                "audit_semantic_sha256": (
                    "0247adf9a9aa24b9e4d35603f5ebe37021a1b77cc021ed808ba740ebed0678ec"
                ),
                "seal_raw_sha256": (
                    "50d6c72625d2045564a775659a7b637c9f51e5ca28a95b14bdcea57d9018802a"
                ),
                "seal_semantic_sha256": (
                    "a3c0e7d1df52fb24ebce1ca9cbd989c8ea64ba1f5976d37fb1bfcef3ccafbf08"
                ),
                "verdict": (
                    "NO_GO_CAUSAL_VALUATION_TCN_V5_FUTURE_SCORE_BLIND_"
                    "RESEARCH_FIT_OR_PREDICTION"
                ),
                "finding_ids": ["P0-001"],
            },
            "closed_v5_findings": {
                "P0-001": (
                    "live_canonical_training_center_rederivation_at_every_model_"
                    "encoder_state_load_export_reconstruction_and_artifact_boundary"
                ),
            },
            "v6_frozen_design_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v6_"
                    "score_free_design_environment_preflight_20260821"
                ),
                "checksums_raw_sha256": (
                    "030917397f474f9cbfa26e4aa8515b75fc70e5f62506ff73ad7476486bac8271"
                ),
                "external_anchor_raw_sha256": (
                    "1f833f41e9216f7e4625b67211f8230c62927237ebbcd9b58edf5fff7e01cfdd"
                ),
                "seal_raw_sha256": (
                    "320ceb73f23622b2767fb054f1205498ad80384fbc62b0ef7ffe3c026aab34bf"
                ),
                "bundle_tree_sha256": (
                    "031da8e0a8dd9e3696409327644879812252afa55f03cd0b68819f0e2baf0c9a"
                ),
                "source_manifest_sha256": (
                    "e8ff976330fcd6cd00df1643ee09fb87896886746cb4208e5b64c750b367b58b"
                ),
            },
            "v6_terminal_no_go_binding": {
                "relative_root": (
                    "outputs/model_zoo_causal_valuation_tcn_v6_"
                    "independent_score_free_prelaunch_audit_r1_20260821"
                ),
                "checksums_raw_sha256": (
                    "54b423a79deb617cd9f7803e83354ce00b1be6b8c3690be3965554c963192e63"
                ),
                "audit_raw_sha256": (
                    "94f552be95c5e3b9bfb5b65f56b752e0db2c1b0590052270d9be08c3b92bb9f4"
                ),
                "audit_semantic_sha256": (
                    "fbc316c3a36edb7e50b120fff360d4093783dc6f9edda9a02a5b9db6e9595531"
                ),
                "seal_raw_sha256": (
                    "5eab9f0de95a03d4c5bbc9767c16016735ceaba558c221f25e73eda4aa843b87"
                ),
                "seal_semantic_sha256": (
                    "c4681c709d3b2299333165f053da92e66563ce5c72e8afe956a9ccc78216f650"
                ),
                "verdict": (
                    "NO_GO_CAUSAL_VALUATION_TCN_V6_STATE_LIFECYCLE_BOUNDARY_"
                    "REPAIR_REQUIRED"
                ),
                "finding_ids": ["P1-001"],
            },
            "closed_v6_findings": {
                "P1-001": (
                    "no_identity_tokens_always_closed_base_hooks_manual_exact_"
                    "schema_export_and_atomic_validated_load"
                ),
            },
            "sequence_length": 128,
            "convolutional_receptive_field": 125,
            "candidate_end_to_end_raw_input_receptive_fields": {
                "cvtcn_v7_tcn_residual": 128,
                "cvtcn_v7_grud_residual": 128,
                "cvtcn_v7_static_state_mlp": 1,
            },
            "maximum_end_to_end_raw_input_receptive_field": 128,
            "observed_age": 0,
            "missing_age_recurrence": "exact_global_session_distance_capped_at_4096",
            "static_control": "same_row_only_mlp",
            "global_calendar_fold": {
                "minimum_train_rows": 756,
                "purge_sessions": 127,
                "purge_derived_from_maximum_raw_dependency_minus_one": True,
                "embargo_sessions": 5,
                "validation_strictly_post_train": True,
                "validation_entity_history_train_overlap_forbidden": True,
                "candidate_train_validation_raw_session_overlap_forbidden": True,
            },
            "training_center": {
                "policy": (
                    "LOWER_ORDER_STATISTIC_FINITE_MEDIAN_FROM_CANONICAL_TRAIN_"
                    "WINDOWS_ONLY"
                ),
                "public_or_free_tensor_setter_allowed": False,
                "public_constructor_statistic_injection_allowed": False,
                "factory_private_canonical_train_row_custody_only": True,
                "validation_or_future_row_substitution_rejected": True,
                "row_commitment_bound_to_state_and_prediction_artifact": True,
                "center_provenance_bound_to_state_and_prediction_artifact": True,
                "stored_custody_receipt_is_authority": False,
                "live_rederivation_at_every_model_forward": True,
                "live_rederivation_at_every_encoder_forward": True,
                "live_rederivation_at_state_export_and_strict_load": True,
                "synchronized_center_and_receipt_substitution_rejected": True,
                "copy_deepcopy_pickle_and_attribute_substitution_rejected": True,
                "python_base_class_state_bypass_rejected": True,
                "state_identity_tokens_or_mutable_capabilities_present": False,
                "manual_exact_parameter_buffer_export": True,
                "complete_shape_dtype_finite_validation_before_load_mutation": True,
                "atomic_manual_load_and_post_copy_rederivation": True,
                "partial_nested_and_noncanonical_state_rejected": True,
                "public_factory_free_row_or_value_inputs_allowed": False,
            },
            "nuisance": {
                "group_universe": list("ABCDEFGHIJ"),
                "training_only": True,
                "projection": (
                    "ROW_FREQUENCY_WEIGHTED_FLOAT64_MEAN_A_TO_J_BOUNDED_RESIDUAL"
                ),
                "projection_tolerance": 1.0e-12,
                "zero_semantics": "BOUNDED_ABSOLUTE_RESIDUAL_NOT_EXACT_ZERO",
                "caller_supplied_sum_or_residual_accepted": False,
                "receipt_factory_only": True,
                "receipt_exactly_recomputed_from_sealed_live_tensors_and_state": True,
                "forged_sub_tolerance_receipt_rejected": True,
                "actual_weighted_sum_and_residual_sealed": True,
                "finite_raw_effects_weights_residuals_losses": True,
                "single_end_to_end_custody": True,
                "removed_from_deployable_state": True,
                "prediction_values": (
                    "fresh_forward_from_exact_sealed_state_and_decision_positions"
                ),
            },
            "fold_row_custody": "factory_only_private_canonical_batch_and_fold_derivation",
            "torch_public_entrypoints": (
                "canonical_batch_fold_candidate_and_live_fold_reconstruction_only"
            ),
            "authority": AUTHORITY_ZERO,
        }),
        "ENVIRONMENT_DEPENDENCY_CLOSURE.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v7.environment_closure.v1",
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
            "schema_version": "expected_pe.causal_valuation_tcn_v7.input_agnostic_preflight.v1",
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
            "schema_version": "expected_pe.causal_valuation_tcn_v7.manifest.v1",
            "status": "FROZEN_EXACT_UNIVERSE_DECLARATION",
            "bundle_file_universe": list(BUNDLE_FILES),
            "bundle_file_count": len(BUNDLE_FILES),
            "container_child_universe": list(CONTAINER_CHILDREN),
            "container_child_count": len(CONTAINER_CHILDREN),
            "source_record_count": len(source_lock["source_records"]),
            "authority": AUTHORITY_ZERO,
        }),
        "QUALITY_RECEIPT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v7.quality_receipt.v1",
            "status": "PASS_RUFF_67_TESTS_CPU_TWO_GPU",
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
            "schema_version": "expected_pe.causal_valuation_tcn_v7.source_closure.v1",
            "status": "PASS_EXTERNALLY_PINNED_VERIFIED_BYTES_SOURCE_CLOSURE",
            "source_lock_sha256": source_lock_sha,
            "runtime_lock_sha256": runtime_lock_sha,
            "source_manifest_sha256": source_lock["source_manifest_sha256"],
            "source_records": source_lock["source_records"],
            "exact_roots": source_lock["exact_roots"],
            "trusted_launcher": _file_record(TRUSTED_LAUNCHER),
            "cross_seal_verifier": _file_record(Path(__file__)),
            "v1_to_v6_immutable_source_and_audit_attested": True,
            "authority": AUTHORITY_ZERO,
        }),
        "STATIC_SOURCE_AUDIT.json": _semantic({
            "schema_version": "expected_pe.causal_valuation_tcn_v7.static_source_audit.v1",
            "status": "PASS_ALL_V6_NO_GO_REPAIRS_AND_V7_ATTACK_REGRESSIONS",
            "p0": 0,
            "p1": 0,
            "p2": 0,
            "attack_regression_test_count": tests["tests_run"],
            "verified_bytes_loader": True,
            "caller_source_map_allowed": False,
            "normal_governed_filesystem_import_allowed": False,
            "extra_source_directory_or_bytecode_allowed": False,
            "source_live_digest_revalidated_at_every_entrypoint": True,
            "canonical_fold_and_rows_rederived_at_every_entrypoint": True,
            "caller_fold_row_custody_allowed": False,
            "caller_prediction_vector_allowed": False,
            "sealed_state_fresh_forward_required": True,
            "finite_nuisance_projection_and_actual_residual_required": True,
            "nuisance_receipt_exact_live_recomputation_required": True,
            "sub_tolerance_nuisance_receipt_forgery_rejected": True,
            "unified_nuisance_loss_and_deploy_custody": True,
            "training_center_factory_private_canonical_train_custody_only": True,
            "training_center_caller_tensor_or_statistic_injection_allowed": False,
            "training_center_state_and_prediction_provenance_required": True,
            "training_center_stored_receipt_authority_allowed": False,
            "training_center_live_rederived_at_every_forward_and_state_boundary": True,
            "synchronized_center_and_receipt_attack_rejected": True,
            "copy_deepcopy_pickle_attribute_substitution_attack_rejected": True,
            "python_base_class_state_export_and_load_bypass_rejected": True,
            "state_identity_token_global_or_mutable_authority_present": False,
            "parent_and_encoder_state_hooks_always_fail_closed": True,
            "manual_exact_parameter_buffer_clone_export": True,
            "complete_state_schema_validated_before_mutation": True,
            "atomic_manual_load_and_post_copy_center_rederivation": True,
            "partial_nested_noncanonical_and_atomic_failure_attacks_rejected": True,
            "validation_or_future_rows_manufacturable_as_train": False,
            "convolutional_receptive_field": 125,
            "maximum_end_to_end_raw_input_receptive_field": 128,
            "purge_derived_from_raw_input_dependency": True,
            "candidate_raw_train_validation_overlap_forbidden": True,
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
        raise V7BuildError("provisional payload universe drifted")
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
        "schema_version": "expected_pe.causal_valuation_tcn_v7.seal.v1",
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
            raise V7BuildError("bundle contains a non-ordinary file member")
        actual.append(child.name)
    if tuple(sorted(actual)) != BUNDLE_FILES:
        raise V7BuildError("bundle exact 14-file universe drifted")
    records = [_file_record(bundle / name, relative_to=bundle) for name in PAYLOAD_FILES]
    expected_checksums = "".join(
        f"{record['raw_sha256']}  {record['path']}\n" for record in records
    ).encode("ascii")
    if (bundle / "CHECKSUMS.sha256").read_bytes() != expected_checksums:
        raise V7BuildError("bundle checksum cross-seal drifted")
    seal = _strict_single_object((bundle / "SEAL.json").read_text(encoding="utf-8"), label="bundle seal")
    semantic = seal.pop("semantic_sha256", None)
    if semantic != _sha256_bytes(_canonical(seal)):
        raise V7BuildError("bundle seal semantic hash drifted")
    if (
        seal.get("status") != "SEALED_EXACT_14_FILE_SCORE_FREE_PREFLIGHT"
        or seal.get("bundle_file_universe") != list(BUNDLE_FILES)
        or seal.get("payload_records") != records
        or seal.get("payload_record_root_sha256") != _sha256_bytes(_canonical(records))
        or seal.get("checksums_record") != _file_record(bundle / "CHECKSUMS.sha256", relative_to=bundle)
        or seal.get("authority") != AUTHORITY_ZERO
    ):
        raise V7BuildError("bundle seal cross-reference drifted")
    for name in PAYLOAD_FILES:
        if not name.endswith(".json") or name == "REFERENCE_LICENSE_REGISTRY.json":
            continue
        payload = _strict_single_object((bundle / name).read_text(encoding="utf-8"), label=name)
        payload_semantic = payload.pop("semantic_sha256", None)
        if payload_semantic != _sha256_bytes(_canonical(payload)):
            raise V7BuildError(f"artifact semantic seal drifted: {name}")
        if payload.get("authority", AUTHORITY_ZERO) != AUTHORITY_ZERO:
            raise V7BuildError(f"artifact authority drifted: {name}")
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
        "schema_version": "expected_pe.causal_valuation_tcn_v7.external_anchor.v1",
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
            raise V7BuildError("container contains a reparse/symlink child")
        if stat.S_ISDIR(metadata.st_mode):
            actual[child.name] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            actual[child.name] = "file"
        else:
            raise V7BuildError("container contains a non-file/non-directory child")
    if tuple(sorted(actual)) != CONTAINER_CHILDREN or actual["bundle"] != "directory" or any(
        actual[name] != "file" for name in CONTAINER_CHILDREN[:2]
    ):
        raise V7BuildError("container exact 3-child universe drifted")
    closure = _verify_bundle(container / "bundle")
    anchor_path = _ordinary(container / "EXTERNAL_ANCHOR.json", directory=False, label="external anchor")
    expected_pointer = f"{_sha256_file(anchor_path)}  EXTERNAL_ANCHOR.json\n".encode("ascii")
    if (container / "EXTERNAL_ANCHOR.sha256").read_bytes() != expected_pointer:
        raise V7BuildError("external anchor pointer drifted")
    anchor = _strict_single_object(anchor_path.read_text(encoding="utf-8"), label="external anchor")
    semantic = anchor.pop("semantic_sha256", None)
    if semantic != _sha256_bytes(_canonical(anchor)):
        raise V7BuildError("external anchor semantic hash drifted")
    if (
        anchor.get("status") != "EXTERNALLY_ANCHORED_EXACT_UNIVERSE_PREFLIGHT"
        or anchor.get("container_child_universe") != list(CONTAINER_CHILDREN)
        or any(anchor.get(key) != value for key, value in closure.items())
        or anchor.get("authority") != AUTHORITY_ZERO
    ):
        raise V7BuildError("external anchor cross-seal drifted")
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
        ".causal_valuation_tcn_v7_provisional."
    ):
        raise V7BuildError("refused unsafe provisional cleanup target")
    if absolute.exists():
        _ordinary(absolute, directory=True, label="provisional cleanup target")
        shutil.rmtree(absolute)


def main() -> int:
    _ordinary(OUTPUTS_ROOT, directory=True, label="outputs root")
    _ordinary(PINNED_PYTHON, directory=False, label="pinned Python")
    _ordinary(RUFF_EXECUTABLE, directory=False, label="pinned Ruff")
    if FINAL_OUTPUT.exists() or STAGE.exists():
        raise V7BuildError("final output or fixed verified stage already exists")
    source_lock_sha, runtime_lock_sha = _launcher_hashes()
    provisional = Path(
        tempfile.mkdtemp(prefix=".causal_valuation_tcn_v7_provisional.", dir=OUTPUTS_ROOT)
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
            "schema_version": "expected_pe.causal_valuation_tcn_v7.build_result.v1",
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
