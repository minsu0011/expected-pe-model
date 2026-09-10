"""V6 truth-blind Structural runner; blocked until an independent V6 GO."""

# ruff: noqa: E402 -- executable/runtime guards intentionally precede workload imports.

from __future__ import annotations

import os

THREAD_ENV = {
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
}
for _key, _value in THREAD_ENV.items():
    os.environ[_key] = _value
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import ctypes
from ctypes import wintypes
from importlib import metadata, util
import json
import multiprocessing as mp
from pathlib import Path
import platform
import re
import subprocess
import sys
import sysconfig
import time
import traceback
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

PINNED_LAUNCHER = (ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve()
PINNED_LAUNCHER_RAW = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_PROCESS_IMAGE = Path("C:/Users/minsu/anaconda3/envs/myenv/python.exe")
PINNED_PROCESS_IMAGE_RAW = "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
PINNED_VERSION = (3, 10, 19)
RUNTIME_ENVIRONMENT_RAW = "fd41ccf93204f9b8248c681f09fa676b23cc4eb2149acebb7ff3ff369e832e00"
RUNTIME_ENVIRONMENT_LOGICAL = "921b3e818c22e11b23790296da69277a8e9c39be18c8f87c7ffa16a4e7dd3c56"
RUNTIME_ENVIRONMENT_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/RUNTIME_ENVIRONMENT_V6.json"
)
V5_RUNNER_PATH = ROOT / "scripts/model_lab/structural/run_spent_predictions_v5.py"
V5_RUNNER_RAW = "b9d31bf723820d3ffdbba2471a3e1c7dc9174b9e4909c08429ac3162ec0d81df"
V4_RUNNER_PATH = ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py"
V4_RUNNER_RAW = "cc5c3345baf6319a2e1f5612ba9735b0cbd86943810a9219c3c9f87502e398f0"
V5_AUTHORIZATION_PATH = ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v5.py"
V5_AUTHORIZATION_RAW = "9a02cb4fbcb2701f979a992f74218cfd6e8f3777c039dfcd761fdffbdf7a4dcc"
V6_AUTHORIZATION_PATH = ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v6.py"
V5_AUDIT_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_fifth_independent_audit_20260819/AUDIT.json"
)
V5_AUDIT_RAW = "53d64d5ff92388478d5ad409fef8c76e1ac13ce976c66adc1d22f4979913a9c0"
V4_FAILURE_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json"
)
V4_FAILURE_RAW = "d8b6723854ce03a897bbef6febcc8e5bae0654896c3f73a1bcaddeabe4544cb8"
ACTIVATION_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/ACTIVATION_EXECUTION_V6.json"
)
POLICY_PIN_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/"
    "EXTERNAL_POLICY_PIN_EXECUTION_V6.json"
)
EXPECTED_ENABLED = (
    "decomp_block_ridge_ar1_lag1",
    "decomp_block_ridge_ar1_current",
    "residual_ar1_nested_oof",
    "stack_geometric_equal_pair",
    "stack_simplex_pair_frozen",
)
SEEDS = (6301, 6421, 6521, 6607, 6701)
FOLD_IDS = tuple(f"fold_{index:03d}" for index in range(12, 74))
FORMAL_OUTER_FOLD_COUNT = 74
FORMAL_OUTER_POSITION_SCHEDULE_SHA256 = (
    "1d2423311c01397dafca26f7a865be7fb470fd337897e714a8a975a32f559c00"
)
FORMAL_OUTER_COVERAGE_SHA256 = "2cbc336c9ea85a7cbc42af253e6f259940ee748189cdf4f4cc38c66545866f37"
WORKERS = 8
CHUNKS_PER_SEED_CANDIDATE = 8
WORKER_FAILURE_PREFIX = "STRUCTURAL_V6_WORKER_FAILURE="
BRANCH_CRITICAL_PACKAGES = {
    "catboost": "1.2.10",
    "lightgbm": "4.6.0",
    "pyyaml": "6.0.2",
    "statsmodels": "0.14.6",
    "xgboost": "3.2.0",
}

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
_KERNEL32.GetModuleFileNameW.argtypes = [
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
_KERNEL32.GetModuleFileNameW.restype = wintypes.DWORD


def _raw_sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _actual_process_image() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = _KERNEL32.GetModuleFileNameW(None, buffer, len(buffer))
    if not length:
        raise RuntimeError("GetModuleFileNameW failed")
    return Path(buffer.value).resolve(strict=True)


def _preimport_runtime_gate() -> None:
    executable = Path(sys.executable).resolve(strict=True)
    if executable != PINNED_LAUNCHER or _raw_sha256(executable) != PINNED_LAUNCHER_RAW:
        raise RuntimeError("Structural V6 rejects non-pinned Python launcher")
    if sys.version_info[:3] != PINNED_VERSION or platform.python_implementation() != "CPython":
        raise RuntimeError("Structural V6 requires exact CPython 3.10.19")
    image = _actual_process_image()
    if image != PINNED_PROCESS_IMAGE or _raw_sha256(image) != PINNED_PROCESS_IMAGE_RAW:
        raise RuntimeError("Structural V6 process image differs from the runtime pin")


if __name__ in {"__main__", "__mp_main__"}:
    _preimport_runtime_gate()

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    StructuralContractError,
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)


_RUNTIME_CACHE: tuple[int, dict[str, Any]] | None = None
_DEPS: SimpleNamespace | None = None


class StructuralV6TaskFailure(StructuralContractError):
    """Parent-side immutable task failure with shutdown attribution."""

    def __init__(self, receipt: Mapping[str, Any]):
        self.receipt = dict(receipt)
        super().__init__(
            "Structural V6 task failed: "
            + json.dumps(self.receipt, sort_keys=True, separators=(",", ":"))
        )


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _metadata_package_map() -> dict[str, str]:
    installed_roots = sorted(
        {
            str(Path(value).resolve())
            for key in ("purelib", "platlib")
            if (value := sysconfig.get_path(key))
        }
    )
    packages: dict[str, str] = {}
    for distribution in metadata.distributions(path=installed_roots):
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise StructuralContractError("installed distribution lacks a Name field")
        name = _normalize_distribution(str(raw_name))
        if name in packages:
            raise StructuralContractError(f"duplicate installed distribution: {name}")
        packages[name] = str(distribution.version)
    return dict(sorted(packages.items()))


def _freeze_package_map(lines: Sequence[str]) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in lines:
        if line.count("==") != 1:
            raise StructuralContractError(f"non-exact pip freeze entry: {line}")
        raw_name, version = line.split("==", 1)
        name = _normalize_distribution(raw_name)
        if not name or not version or name in packages:
            raise StructuralContractError(f"invalid/duplicate pip freeze entry: {line}")
        packages[name] = version
    return dict(sorted(packages.items()))


def _pip_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    return environment


def _read_sealed(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StructuralContractError(f"sealed object required: {path}")
    verify_payload_seal(value)
    return value


def _validate_runtime_inventory(
    environment: Mapping[str, Any],
    *,
    freeze_stdout: bytes,
    freeze_lines: Sequence[str],
    package_versions: Mapping[str, str],
) -> dict[str, Any]:
    import hashlib

    expected_lines = tuple(str(value) for value in environment.get("pip_freeze_all", ()))
    expected_packages = dict(environment.get("package_versions_all", {}))
    actual_lines = tuple(str(value) for value in freeze_lines)
    actual_packages = dict(
        sorted((str(key), str(value)) for key, value in package_versions.items())
    )
    if actual_lines != expected_lines:
        raise StructuralContractError("V6 complete pip freeze entries changed")
    if _freeze_package_map(actual_lines) != actual_packages:
        raise StructuralContractError("V6 pip freeze and installed package maps differ")
    if actual_packages != expected_packages:
        raise StructuralContractError("V6 complete installed package map changed")
    if sha256_bytes(canonical_json_bytes(actual_lines)) != environment.get("pip_freeze_all_sha256"):
        raise StructuralContractError("V6 complete pip freeze logical hash changed")
    if hashlib.sha256(freeze_stdout).hexdigest() != environment.get("freeze_stdout_raw_sha256"):
        raise StructuralContractError("V6 pip freeze stdout bytes changed")
    if len(freeze_stdout) != environment.get("freeze_stdout_bytes"):
        raise StructuralContractError("V6 pip freeze stdout length changed")
    if sha256_bytes(canonical_json_bytes(actual_packages)) != environment.get(
        "package_versions_all_sha256"
    ):
        raise StructuralContractError("V6 complete package-map hash changed")
    if environment.get("branch_critical_packages") != BRANCH_CRITICAL_PACKAGES or any(
        actual_packages.get(name) != version for name, version in BRANCH_CRITICAL_PACKAGES.items()
    ):
        raise StructuralContractError("V6 branch-critical package changed")
    return {
        "package_count": len(actual_packages),
        "pip_freeze_all_sha256": str(environment["pip_freeze_all_sha256"]),
        "freeze_stdout_raw_sha256": str(environment["freeze_stdout_raw_sha256"]),
        "package_versions_all_sha256": str(environment["package_versions_all_sha256"]),
        "lightgbm_version": actual_packages["lightgbm"],
        "pyyaml_version": actual_packages["pyyaml"],
    }


def _verify_runtime(*, force: bool = False) -> dict[str, Any]:
    global _RUNTIME_CACHE
    _preimport_runtime_gate()
    if not force and _RUNTIME_CACHE is not None and _RUNTIME_CACHE[0] == os.getpid():
        return dict(_RUNTIME_CACHE[1])
    if sha256_file(RUNTIME_ENVIRONMENT_PATH) != RUNTIME_ENVIRONMENT_RAW:
        raise StructuralContractError("V6 runtime environment bytes changed")
    environment = _read_sealed(RUNTIME_ENVIRONMENT_PATH)
    if (
        environment.get("manifest_sha256") != RUNTIME_ENVIRONMENT_LOGICAL
        or environment.get("format_version") != 2
        or environment.get("mode") != "structural_v6_complete_exact_runtime_environment"
        or environment.get("thread_gpu_policy")
        != {**THREAD_ENV, "CUDA_VISIBLE_DEVICES": "-1", "NVIDIA_VISIBLE_DEVICES": "void"}
    ):
        raise StructuralContractError("V6 runtime environment contract changed")
    freeze = subprocess.run(
        [str(PINNED_LAUNCHER), "-m", "pip", "freeze", "--all"],
        check=True,
        capture_output=True,
        env=_pip_environment(),
    )
    lines = tuple(
        line.strip()
        for line in freeze.stdout.decode("utf-8", errors="strict").splitlines()
        if line.strip()
    )
    verified = _validate_runtime_inventory(
        environment,
        freeze_stdout=freeze.stdout,
        freeze_lines=lines,
        package_versions=_metadata_package_map(),
    )
    runtime = environment["runtime"]
    if (
        Path(sys.prefix).resolve().as_posix() != runtime["sys_prefix"]
        or Path(sys.base_prefix).resolve().as_posix() != runtime["sys_base_prefix"]
        or Path(sysconfig.get_path("stdlib")).resolve().as_posix() != runtime["stdlib"]
        or platform.python_implementation() != runtime["implementation"]
        or list(sys.version_info[:3]) != runtime["version_info"]
        or sys.version != runtime["version"]
    ):
        raise StructuralContractError("V6 exact Python runtime identity changed")
    verified.update(
        {
            "pid": os.getpid(),
            "sys_executable": Path(sys.executable).resolve().as_posix(),
            "python_version": list(sys.version_info[:3]),
            "actual_process_image": _actual_process_image().as_posix(),
            "runtime_environment_raw_sha256": RUNTIME_ENVIRONMENT_RAW,
            "runtime_environment_logical_sha256": RUNTIME_ENVIRONMENT_LOGICAL,
        }
    )
    _RUNTIME_CACHE = (os.getpid(), dict(verified))
    return verified


def _deps() -> SimpleNamespace:
    global _DEPS
    if _DEPS is not None:
        return _DEPS
    _verify_runtime()
    if sha256_file(V5_RUNNER_PATH) != V5_RUNNER_RAW:
        raise StructuralContractError("frozen V5 runner dependency changed")
    if sha256_file(V4_RUNNER_PATH) != V4_RUNNER_RAW:
        raise StructuralContractError("frozen V4 runner dependency changed")
    if sha256_file(V5_AUTHORIZATION_PATH) != V5_AUTHORIZATION_RAW:
        raise StructuralContractError("frozen V5 authorization dependency changed")
    spec = util.spec_from_file_location("_structural_v5_frozen_dependency", V5_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise StructuralContractError("cannot load frozen V5 runner dependency")
    v5 = util.module_from_spec(spec)
    spec.loader.exec_module(v5)
    from pe_regime_v04.model_lab.models.wave1.artifacts import (
        PREDICTION_COLUMNS,
        file_record,
        write_immutable_json,
        write_round_trip_csv,
    )
    from pe_regime_v04.model_lab.structural.authorization_v6 import (
        load_structural_execution_authorization_v6,
    )
    from pe_regime_v04.model_lab.structural.dispatcher import StructuralDispatcher
    from pe_regime_v04.model_lab.structural.resources import (
        CPU_AFFINITY,
        MAX_TOTAL_RSS_BYTES,
        MINIMUM_FREE_RAM_BYTES,
    )

    _DEPS = SimpleNamespace(
        v5=v5,
        PREDICTION_COLUMNS=PREDICTION_COLUMNS,
        file_record=file_record,
        write_immutable_json=write_immutable_json,
        write_round_trip_csv=write_round_trip_csv,
        load_authorization=load_structural_execution_authorization_v6,
        StructuralDispatcher=StructuralDispatcher,
        CPU_AFFINITY=CPU_AFFINITY,
        MAX_TOTAL_RSS_BYTES=MAX_TOTAL_RSS_BYTES,
        MINIMUM_FREE_RAM_BYTES=MINIMUM_FREE_RAM_BYTES,
    )
    return _DEPS


def _verify_activation(
    *, activation_raw_sha256: str, policy_raw_sha256: str, policy_pin_raw_sha256: str
) -> dict[str, Any]:
    if sha256_file(ACTIVATION_PATH) != activation_raw_sha256:
        raise StructuralContractError("V6 execution activation bytes changed")
    activation = _read_sealed(ACTIVATION_PATH)
    if sha256_file(POLICY_PIN_PATH) != policy_pin_raw_sha256:
        raise StructuralContractError("V6 external policy pin bytes changed")
    pin = _read_sealed(POLICY_PIN_PATH)
    bindings = activation.get("exact_bindings", {})
    expected = {
        "physical_prediction_runner_v6": (Path(__file__).resolve(), sha256_file(Path(__file__))),
        "frozen_runner_v5_dependency": (V5_RUNNER_PATH, V5_RUNNER_RAW),
        "frozen_runner_v4_transitive_dependency": (V4_RUNNER_PATH, V4_RUNNER_RAW),
        "authorization_v5_transitive_dependency": (
            V5_AUTHORIZATION_PATH,
            V5_AUTHORIZATION_RAW,
        ),
        "authorization_v6": (V6_AUTHORIZATION_PATH, sha256_file(V6_AUTHORIZATION_PATH)),
        "runtime_environment_v6": (RUNTIME_ENVIRONMENT_PATH, RUNTIME_ENVIRONMENT_RAW),
        "v5_independent_no_go_audit": (V5_AUDIT_PATH, V5_AUDIT_RAW),
        "v4_failed_attempt": (V4_FAILURE_PATH, V4_FAILURE_RAW),
    }
    if set(bindings) != set(expected):
        raise StructuralContractError("V6 execution binding universe changed")
    for name, (path, raw_sha256) in expected.items():
        row = bindings[name]
        if (
            row.get("path") != path.relative_to(ROOT).as_posix()
            or row.get("bytes") != path.stat().st_size
            or row.get("raw_sha256") != raw_sha256
        ):
            raise StructuralContractError(f"V6 execution closure changed: {name}")
    if (
        pin.get("authority_policy", {}).get("raw_sha256") != policy_raw_sha256
        or pin.get("activation_binding", {}).get("raw_sha256") != activation_raw_sha256
        or pin.get("activation_binding", {}).get("logical_sha256")
        != activation.get("manifest_sha256")
        or pin.get("formal_spent_activated") is not True
    ):
        raise StructuralContractError("V6 external policy pin changed")
    contract = activation.get("execution_contract", {})
    folds = activation.get("fold_contract", {})
    if (
        tuple(contract.get("candidate_ids", ())) != EXPECTED_ENABLED
        or tuple(contract.get("seeds", ())) != SEEDS
        or contract.get("outer_workers") != WORKERS
        or contract.get("inner_threads") != 1
        or contract.get("gpu") != "OFF"
        or contract.get("task_count") != 200
        or contract.get("chunks_per_seed_candidate") != CHUNKS_PER_SEED_CANDIDATE
        or contract.get("failure_receipt_required") is not True
        or tuple(folds.get("required_evaluation_fold_ids", ())) != FOLD_IDS
        or folds.get("full_membership_schedule_sha256") != FORMAL_OUTER_POSITION_SCHEDULE_SHA256
        or folds.get("coverage_sha256") != FORMAL_OUTER_COVERAGE_SHA256
    ):
        raise StructuralContractError("V6 activation execution/fold contract changed")
    return activation


def _fold_membership(fold_ids: Sequence[str]) -> list[dict[str, Any]]:
    membership: list[dict[str, Any]] = []
    for fold_id in fold_ids:
        if fold_id not in FOLD_IDS:
            raise StructuralContractError("V6 task contains an unknown formal fold")
        index = int(fold_id.removeprefix("fold_"))
        test_start = 252 + index * 21
        test_stop = min(test_start + 21, 1800)
        train_start = max(0, test_start - 1008)
        train_positions = list(range(train_start, test_start))
        test_positions = list(range(test_start, test_stop))
        membership.append(
            {
                "fold_id": fold_id,
                "train_positions": train_positions,
                "test_positions": test_positions,
            }
        )
    return membership


def _task_identity(payload: Mapping[str, Any]) -> dict[str, Any]:
    fold_ids = tuple(str(value) for value in payload.get("fold_ids", ()))
    membership: list[dict[str, Any]] | None
    membership_error: str | None = None
    try:
        membership = _fold_membership(fold_ids)
    except BaseException as exc:
        membership = None
        membership_error = f"{type(exc).__name__}: {exc}"
    return {
        "payload_sha256": str(payload.get("payload_sha256", "MISSING")),
        "seed": payload.get("seed"),
        "candidate_id": payload.get("candidate_id"),
        "fold_ids": list(fold_ids),
        "fold_positions": membership,
        "fold_positions_error": membership_error,
    }


def _validate_payload(payload: Mapping[str, Any]) -> tuple[int, str, tuple[str, ...]]:
    required = {
        "project_root",
        "seed",
        "candidate_id",
        "fold_ids",
        "fold_positions_sha256",
        "activation_raw_sha256",
        "policy_raw_sha256",
        "policy_pin_raw_sha256",
        "payload_sha256",
    }
    if set(payload) != required:
        raise StructuralContractError("V6 worker payload schema changed")
    unsigned = {key: payload[key] for key in required if key != "payload_sha256"}
    if sha256_bytes(canonical_json_bytes(unsigned)) != payload["payload_sha256"]:
        raise StructuralContractError("V6 worker payload seal changed")
    seed = int(payload["seed"])
    candidate_id = str(payload["candidate_id"])
    fold_ids = tuple(str(value) for value in payload["fold_ids"])
    membership = _fold_membership(fold_ids)
    if sha256_bytes(canonical_json_bytes(membership)) != payload["fold_positions_sha256"]:
        raise StructuralContractError("V6 worker exact fold-position binding changed")
    if seed not in SEEDS or candidate_id not in EXPECTED_ENABLED or not fold_ids:
        raise StructuralContractError("V6 worker payload is outside activated universe")
    return seed, candidate_id, fold_ids


def _receipt_environment(runtime: Mapping[str, Any] | None = None) -> dict[str, Any]:
    image = "UNAVAILABLE"
    image_error = None
    try:
        image = _actual_process_image().as_posix()
    except BaseException as exc:
        image_error = f"{type(exc).__name__}: {exc}"
    return {
        "pid": os.getpid(),
        "sys_executable": Path(sys.executable).resolve().as_posix(),
        "python_version": list(sys.version_info[:3]),
        "implementation": platform.python_implementation(),
        "actual_process_image": image,
        "actual_process_image_error": image_error,
        "thread_environment": {key: os.environ.get(key) for key in THREAD_ENV},
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "nvidia_visible_devices": os.environ.get("NVIDIA_VISIBLE_DEVICES"),
        "runtime_verification": dict(runtime) if runtime is not None else None,
    }


def _worker_failure_receipt(
    payload: Mapping[str, Any], exc: BaseException, runtime: Mapping[str, Any] | None
) -> dict[str, Any]:
    return seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_worker_first_observation",
            "task_identity": _task_identity(payload),
            "worker_environment": _receipt_environment(runtime),
            "exception": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            },
        }
    )


def _raise_worker_failure(
    payload: Mapping[str, Any], exc: BaseException, runtime: Mapping[str, Any] | None
) -> None:
    receipt = _worker_failure_receipt(payload, exc, runtime)
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    raise RuntimeError(WORKER_FAILURE_PREFIX + encoded) from exc


def _worker_initializer() -> None:
    for key, value in THREAD_ENV.items():
        os.environ[key] = value
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"
    _preimport_runtime_gate()


def _worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    runtime: dict[str, Any] | None = None
    try:
        runtime = _verify_runtime()
        deps = _deps()
        deps.v5._set_affinity()
        seed, candidate_id, fold_ids = _validate_payload(payload)
        _verify_activation(
            activation_raw_sha256=str(payload["activation_raw_sha256"]),
            policy_raw_sha256=str(payload["policy_raw_sha256"]),
            policy_pin_raw_sha256=str(payload["policy_pin_raw_sha256"]),
        )
        project_root = Path(str(payload["project_root"])).resolve(strict=True)
        authorization = deps.load_authorization(
            project_root,
            external_policy_sha256=str(payload["policy_raw_sha256"]),
            scope="FORMAL_SPENT",
        )
        dispatcher = deps.StructuralDispatcher.from_authorization(authorization)
        if candidate_id.startswith("decomp_"):
            predictions, diagnostics = deps.v5._run_decomposition(
                project_root, seed, candidate_id, fold_ids, dispatcher
            )
        else:
            predictions = []
            diagnostics = []
            for fold_id in fold_ids:
                rows, diagnostic = deps.v5.v4._run_nested_fold(
                    project_root, seed, candidate_id, fold_id, dispatcher
                )
                predictions.extend(rows)
                diagnostics.append(diagnostic)
        telemetry = deps.v5._worker_telemetry()
        telemetry.update(runtime)
        return {
            "payload_sha256": str(payload["payload_sha256"]),
            "predictions": predictions,
            "diagnostics": diagnostics,
            "telemetry": telemetry,
        }
    except BaseException as exc:
        _raise_worker_failure(payload, exc, runtime)


def _synthetic_failure_worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    runtime: dict[str, Any] | None = None
    try:
        runtime = _verify_runtime()
        _validate_payload(payload)
        raise RuntimeError("forced-structural-v6-synthetic-worker-failure")
    except BaseException as exc:
        _raise_worker_failure(payload, exc, runtime)


def _chunk_fold_ids() -> tuple[tuple[str, ...], ...]:
    chunks = tuple(FOLD_IDS[offset::CHUNKS_PER_SEED_CANDIDATE] for offset in range(8))
    flattened = [fold_id for chunk in chunks for fold_id in chunk]
    if sorted(flattened) != sorted(FOLD_IDS) or len(flattened) != len(set(flattened)):
        raise StructuralContractError("V6 fold chunks do not partition the formal schedule")
    return chunks


def _payloads(
    *, activation_raw_sha256: str, policy_raw_sha256: str, policy_pin_raw_sha256: str
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for seed in SEEDS:
        for candidate_id in EXPECTED_ENABLED:
            for fold_ids in _chunk_fold_ids():
                unsigned = {
                    "project_root": str(ROOT),
                    "seed": seed,
                    "candidate_id": candidate_id,
                    "fold_ids": list(fold_ids),
                    "fold_positions_sha256": sha256_bytes(
                        canonical_json_bytes(_fold_membership(fold_ids))
                    ),
                    "activation_raw_sha256": activation_raw_sha256,
                    "policy_raw_sha256": policy_raw_sha256,
                    "policy_pin_raw_sha256": policy_pin_raw_sha256,
                }
                output.append(
                    {
                        **unsigned,
                        "payload_sha256": sha256_bytes(canonical_json_bytes(unsigned)),
                    }
                )
    if len(output) != 200:
        raise StructuralContractError("V6 task count changed")
    return output


def _parse_worker_receipt(exc: BaseException) -> tuple[dict[str, Any] | None, str | None]:
    message = str(exc)
    index = message.find(WORKER_FAILURE_PREFIX)
    if index < 0:
        return None, "worker exception lacks a sealed first-observation receipt"
    encoded = message[index + len(WORKER_FAILURE_PREFIX) :]
    try:
        receipt = json.loads(encoded)
        if not isinstance(receipt, dict):
            raise TypeError("receipt is not an object")
        verify_payload_seal(receipt)
    except BaseException as parse_error:
        return None, f"invalid worker receipt: {type(parse_error).__name__}: {parse_error}"
    return receipt, None


def _shutdown_failed(executor: ProcessPoolExecutor, pending: Sequence[Any]) -> dict[str, Any]:
    started = time.perf_counter()
    processes = tuple(getattr(executor, "_processes", {}).values())
    pids = sorted(process.pid for process in processes if getattr(process, "pid", None))
    cancel_results = [bool(future.cancel()) for future in pending]
    terminated: list[int] = []
    for process in processes:
        try:
            process.terminate()
            if process.pid is not None:
                terminated.append(int(process.pid))
        except (AttributeError, OSError):
            continue
    executor.shutdown(wait=False, cancel_futures=True)
    deadline = time.perf_counter() + 5.0
    alive: list[int] = []
    while True:
        alive = sorted(
            int(process.pid)
            for process in processes
            if getattr(process, "pid", None) is not None and process.is_alive()
        )
        if not alive or time.perf_counter() >= deadline:
            break
        time.sleep(0.01)
    return seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_fail_fast_cancellation_termination",
            "pending_future_count": len(pending),
            "cancel_requested_count": len(cancel_results),
            "cancelled_immediately_count": sum(cancel_results),
            "worker_pids_before_termination": pids,
            "termination_requested_pids": sorted(terminated),
            "worker_pids_alive_after_poll": alive,
            "shutdown_wait": False,
            "cancel_futures": True,
            "elapsed_seconds": time.perf_counter() - started,
        }
    )


def _parent_failure_receipt(
    *,
    payload: Mapping[str, Any],
    exc: BaseException,
    worker_receipt: Mapping[str, Any] | None,
    worker_receipt_error: str | None,
    shutdown_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    task_identity = _task_identity(payload)
    if worker_receipt is not None and worker_receipt.get("task_identity") != task_identity:
        worker_receipt_error = "worker receipt identity differs from parent future_map identity"
    return seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_parent_first_observation_and_shutdown",
            "task_identity": task_identity,
            "parent_environment": _receipt_environment(_verify_runtime()),
            "future_exception": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            },
            "worker_first_observation_receipt": worker_receipt,
            "worker_receipt_validation_error": worker_receipt_error,
            "fail_fast_shutdown_receipt": dict(shutdown_receipt),
        }
    )


def _execute_pool(
    payloads: Sequence[Mapping[str, Any]],
    *,
    worker: Callable[[Mapping[str, Any]], dict[str, Any]],
    max_workers: int,
    resource_guards: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    deps = _deps() if resource_guards else None
    results: list[dict[str, Any]] = []
    max_rss = 0
    min_free = deps.v5._available_memory() if deps is not None else 0
    observed_pids: set[int] = set()
    executor = ProcessPoolExecutor(
        max_workers=max_workers,
        mp_context=mp.get_context("spawn"),
        initializer=_worker_initializer,
    )
    pending: set[Any] = set()
    future_map: dict[Any, Mapping[str, Any]] = {}
    try:
        future_map = {executor.submit(worker, payload): payload for payload in payloads}
        pending = set(future_map)
        while pending:
            if deps is not None:
                rss, pids = deps.v5._aggregate_rss(executor)
                free = deps.v5._available_memory()
                max_rss = max(max_rss, rss)
                min_free = min(min_free, free)
                observed_pids.update(pids)
                if rss > deps.MAX_TOTAL_RSS_BYTES or free < deps.MINIMUM_FREE_RAM_BYTES:
                    raise StructuralContractError("V6 live aggregate RSS/free-RAM guard breached")
            done, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
            for future in done:
                try:
                    results.append(future.result())
                except BaseException as exc:
                    payload = future_map[future]
                    worker_receipt, receipt_error = _parse_worker_receipt(exc)
                    shutdown = _shutdown_failed(executor, tuple(pending))
                    receipt = _parent_failure_receipt(
                        payload=payload,
                        exc=exc,
                        worker_receipt=worker_receipt,
                        worker_receipt_error=receipt_error,
                        shutdown_receipt=shutdown,
                    )
                    raise StructuralV6TaskFailure(receipt) from exc
    except StructuralV6TaskFailure:
        raise
    except BaseException:
        _shutdown_failed(executor, tuple(pending))
        raise
    else:
        executor.shutdown(wait=True)
    return results, {
        "peak_live_aggregate_rss_bytes": max_rss,
        "minimum_live_free_ram_bytes": min_free,
        "observed_process_ids": sorted(observed_pids),
    }


def _write_failure_receipt(output_directory: Path, receipt: Mapping[str, Any]) -> Path:
    deps = _deps()
    path = output_directory / "FAILURE_RECEIPT_V6.json"
    deps.write_immutable_json(path, dict(receipt))
    return path


def run(
    output_directory: Path,
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> Path:
    runtime_parent = _verify_runtime()
    deps = _deps()
    activation = _verify_activation(
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    authorization = deps.load_authorization(
        ROOT, external_policy_sha256=policy_raw_sha256, scope="FORMAL_SPENT"
    )
    authorization.verify()
    output_directory = output_directory.resolve()
    prediction_path = output_directory / "structural_predictions.csv"
    diagnostic_path = output_directory / "structural_fold_diagnostics.csv"
    manifest_path = output_directory / "PREDICTION_MANIFEST.json"
    failure_path = output_directory / "FAILURE_RECEIPT_V6.json"
    if any(
        path.exists() for path in (prediction_path, diagnostic_path, manifest_path, failure_path)
    ):
        raise FileExistsError("V6 structural output custody is immutable")
    output_directory.mkdir(parents=True, exist_ok=True)
    if deps.v5._available_memory() < deps.MINIMUM_FREE_RAM_BYTES:
        raise StructuralContractError("free RAM is below activated 16-GiB floor")
    payloads = _payloads(
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    started = time.perf_counter()
    try:
        results, resources = _execute_pool(
            payloads, worker=_worker, max_workers=WORKERS, resource_guards=True
        )
    except StructuralV6TaskFailure as exc:
        _write_failure_receipt(output_directory, exc.receipt)
        raise
    wall = time.perf_counter() - started
    predictions, diagnostics = deps.v5._assemble_results(results)
    if set(predictions["model_id"]) != set(EXPECTED_ENABLED):
        raise StructuralContractError("V6 prediction candidate universe changed")
    for candidate_id in EXPECTED_ENABLED:
        candidate = predictions.loc[predictions["model_id"] == candidate_id]
        if len(candidate) != len(SEEDS) * 1296:
            raise StructuralContractError(f"V6 candidate coverage changed: {candidate_id}")
        for seed in SEEDS:
            group = candidate.loc[candidate["seed"] == seed]
            if (
                len(group) != 1296
                or group["date"].duplicated().any()
                or tuple(group["test_start_position"].drop_duplicates())
                != tuple(range(504, 1800, 21))
            ):
                raise StructuralContractError(
                    f"V6 required identity changed: {candidate_id}/{seed}"
                )
    telemetry = [result["telemetry"] for result in results]
    if any(
        row["thread_environment"] != THREAD_ENV
        or row["cuda_visible_devices"] != "-1"
        or row["nvidia_visible_devices"] != "void"
        or tuple(row["affinity"]) != deps.CPU_AFFINITY
        or any(value != 1 for value in row["native_pool_threads"])
        or Path(row["sys_executable"]) != PINNED_LAUNCHER
        or tuple(row["python_version"]) != PINNED_VERSION
        or Path(row["actual_process_image"]) != PINNED_PROCESS_IMAGE
        or row["runtime_environment_raw_sha256"] != RUNTIME_ENVIRONMENT_RAW
        or row["pip_freeze_all_sha256"] != runtime_parent["pip_freeze_all_sha256"]
        or row["freeze_stdout_raw_sha256"] != runtime_parent["freeze_stdout_raw_sha256"]
        or row["package_versions_all_sha256"] != runtime_parent["package_versions_all_sha256"]
        or row["lightgbm_version"] != "4.6.0"
        or row["pyyaml_version"] != "6.0.2"
        for row in telemetry
    ):
        raise StructuralContractError("V6 worker full runtime/thread/GPU/affinity telemetry failed")
    prediction_record = deps.write_round_trip_csv(
        predictions, prediction_path, columns=deps.PREDICTION_COLUMNS
    )
    diagnostic_record = deps.write_round_trip_csv(
        diagnostics, diagnostic_path, columns=deps.v5.v4.DIAGNOSTIC_COLUMNS
    )
    runtime = diagnostics.groupby("model_id", sort=True)["runtime_seconds"].sum().to_dict()
    manifest = seal_payload(
        {
            "format_version": 3,
            "mode": "structural_v6_truth_blind_spent_prediction_artifact",
            "activation_binding": deps.file_record(ACTIVATION_PATH),
            "external_policy_pin": deps.file_record(POLICY_PIN_PATH),
            "runtime_environment": deps.file_record(RUNTIME_ENVIRONMENT_PATH),
            "runtime_parent_verification": runtime_parent,
            "external_policy_raw_sha256": policy_raw_sha256,
            "authorization_sha256": authorization.authorization_sha256,
            "predict_inputs": deps.file_record(
                ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
            ),
            "evaluation_data_used": False,
            "candidate_scores_computed": False,
            "seeds": list(SEEDS),
            "seed_role": "ALREADY_SPENT_WAVE1_ONLY",
            "candidate_model_ids": list(EXPECTED_ENABLED),
            "formal_fold_count_bound": FORMAL_OUTER_FOLD_COUNT,
            "formal_schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
            "formal_coverage_sha256": FORMAL_OUTER_COVERAGE_SHA256,
            "executed_required_fold_ids": list(FOLD_IDS),
            "required_rows_per_seed_candidate": 1296,
            "prediction_rows": len(predictions),
            "diagnostic_rows": len(diagnostics),
            "predictions_csv": prediction_record,
            "fold_diagnostics_csv": diagnostic_record,
            "runtime_seconds_by_model": {key: float(value) for key, value in runtime.items()},
            "end_to_end_wall_seconds_diagnostic_only": wall,
            "outer_backend": "ProcessPoolExecutor",
            "start_method": "spawn",
            "outer_workers": WORKERS,
            "chunks_per_seed_candidate": CHUNKS_PER_SEED_CANDIDATE,
            "task_count": len(payloads),
            "inner_threads": 1,
            "gpu": "sealed_off",
            **resources,
            "worker_telemetry": telemetry,
            "activation_decision": activation["decision"],
            "target_eligibility_rule": "positive_finite_target_leading_warmup_filter_v1",
            "feature_imputation": "outer-train median; all-missing column drop; frozen transform",
            "worker_failure_receipt_contract": "sealed_identity_environment_trace_and_shutdown_v1",
            "fresh_seed_selected_or_reserved": False,
            "heldout_opened": False,
        }
    )
    deps.write_immutable_json(manifest_path, manifest)
    return manifest_path


def _synthetic_failure_self_test() -> dict[str, Any]:
    _verify_runtime(force=True)
    payload = _payloads(
        activation_raw_sha256="a" * 64,
        policy_raw_sha256="b" * 64,
        policy_pin_raw_sha256="c" * 64,
    )[0]
    try:
        _execute_pool(
            [payload, payload, payload, payload],
            worker=_synthetic_failure_worker,
            max_workers=2,
            resource_guards=False,
        )
    except StructuralV6TaskFailure as exc:
        receipt = exc.receipt
    else:
        raise AssertionError("synthetic worker failure did not fail")
    verify_payload_seal(receipt)
    identity = receipt["task_identity"]
    worker_receipt = receipt["worker_first_observation_receipt"]
    shutdown = receipt["fail_fast_shutdown_receipt"]
    if (
        identity != _task_identity(payload)
        or worker_receipt is None
        or worker_receipt["task_identity"] != identity
        or receipt["worker_receipt_validation_error"] is not None
        or shutdown["shutdown_wait"] is not False
        or shutdown["cancel_futures"] is not True
        or shutdown["worker_pids_alive_after_poll"]
    ):
        raise AssertionError("V6 synthetic failure attribution/shutdown contract failed")
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--activation-raw-sha256")
    parser.add_argument("--policy-raw-sha256")
    parser.add_argument("--policy-pin-raw-sha256")
    parser.add_argument("--runtime-preflight-only", action="store_true")
    parser.add_argument("--failure-attribution-self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runtime = _verify_runtime()
    if args.runtime_preflight_only:
        print("STRUCTURAL_V6_RUNTIME_PREFLIGHT_PASS " + json.dumps(runtime, sort_keys=True))
        return 0
    if args.failure_attribution_self_test:
        receipt = _synthetic_failure_self_test()
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    required = (
        args.output_directory,
        args.activation_raw_sha256,
        args.policy_raw_sha256,
        args.policy_pin_raw_sha256,
    )
    if any(value is None for value in required):
        raise SystemExit("prediction mode requires output/activation/policy/pin arguments")
    print(
        run(
            args.output_directory,
            activation_raw_sha256=args.activation_raw_sha256,
            policy_raw_sha256=args.policy_raw_sha256,
            policy_pin_raw_sha256=args.policy_pin_raw_sha256,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
