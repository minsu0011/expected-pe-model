"""Physical truth-blind Structural V4 spent prediction process."""

# ruff: noqa: E402 -- native thread/GPU guards must precede numerical imports.

from __future__ import annotations

import os

for _key in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ[_key] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import json
import multiprocessing as mp
from pathlib import Path
import sys
import time
from typing import Any, Mapping

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.folds import generate_pit_folds
from pe_regime_v04.model_lab.models.wave1.artifacts import (
    PREDICTION_COLUMNS,
    file_record,
    load_predict_inputs,
    load_wave1_seed_frames,
    seal_payload,
    write_immutable_json,
    write_round_trip_csv,
)
from pe_regime_v04.model_lab.structural.authorization import (
    EXPECTED_ENABLED,
    EXPECTED_PAIR,
    load_structural_execution_authorization,
)
from pe_regime_v04.model_lab.structural.contracts import (
    FULL_META_IDENTITY_COLUMNS,
    StructuralContractError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.structural.dispatcher import StructuralDispatcher
from pe_regime_v04.model_lab.structural.ensemble import PAIR_IDENTITY_COLUMNS
from pe_regime_v04.model_lab.structural.features import (
    MARKET_CURRENT,
    REGIME_CURRENT,
    REQUIRED_UPSTREAM_AUDITS,
    TRACK_A_FEATURE_COLUMNS,
    TRACK_C_FEATURE_COLUMNS,
    TrackASourceAuditBinding,
    build_track_a_lag1_artifact,
)
from pe_regime_v04.model_lab.structural.meta import execute_nested_oof_plan_formal_spent
from pe_regime_v04.model_lab.structural.nested import (
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_FOLD_COUNT,
    FORMAL_OUTER_FOLD_SPEC,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
    build_formal_nested_oof_plan,
)
from pe_regime_v04.model_lab.structural.resources import (
    CPU_AFFINITY,
    MAX_TOTAL_RSS_BYTES,
    MINIMUM_FREE_RAM_BYTES,
    THREAD_ENVIRONMENT,
)


TRACK_A_AUDIT_RAW = "1ace868983aff8ad73419380d26af88c5efefc1dd748fe78d77e579e8513cd38"
SEEDS = (6301, 6421, 6521, 6607, 6701)
FOLD_IDS = tuple(f"fold_{index:03d}" for index in range(12, FORMAL_OUTER_FOLD_COUNT))
WORKERS = 8
DIAGNOSTIC_COLUMNS = (
    "seed",
    "model_id",
    "fold_id",
    "test_start_position",
    "test_rows",
    "status",
    "runtime_seconds",
    "fit_sha256",
    "weight0",
    "weight1",
    "genuinely_distinct",
    "ar1_rho",
    "warnings_json",
    "pid",
)


def _read_sealed(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StructuralContractError(f"sealed object required: {path}")
    verify_payload_seal(value)
    return value


def _verify_activation(
    project_root: Path,
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> dict[str, Any]:
    activation_path = (
        project_root
        / "outputs/model_zoo_structural_wave_spent_screen_20260819/ACTIVATION_BINDING_EXECUTION.json"
    )
    pin_path = (
        project_root
        / "outputs/model_zoo_structural_wave_spent_screen_20260819/EXTERNAL_POLICY_PIN_EXECUTION.json"
    )
    if sha256_file(activation_path) != activation_raw_sha256:
        raise StructuralContractError("spent activation raw bytes changed")
    activation = _read_sealed(activation_path)
    runner_binding = activation.get("exact_bindings", {}).get("physical_prediction_runner", {})
    runner_path = Path(__file__).resolve()
    if (
        runner_binding.get("path") != runner_path.relative_to(project_root).as_posix()
        or runner_binding.get("bytes") != runner_path.stat().st_size
        or runner_binding.get("raw_sha256") != sha256_file(runner_path)
    ):
        raise StructuralContractError("physical prediction runner is outside execution closure")
    if sha256_file(pin_path) != policy_pin_raw_sha256:
        raise StructuralContractError("external policy-pin raw bytes changed")
    pin = _read_sealed(pin_path)
    if (
        pin.get("authority_policy", {}).get("raw_sha256") != policy_raw_sha256
        or pin.get("activation_binding", {}).get("raw_sha256") != activation_raw_sha256
        or pin.get("activation_binding", {}).get("logical_sha256")
        != activation.get("manifest_sha256")
        or pin.get("formal_spent_activated") is not True
    ):
        raise StructuralContractError("external policy pin changed")
    contract = activation.get("execution_contract")
    folds = activation.get("fold_contract")
    if not isinstance(contract, Mapping) or not isinstance(folds, Mapping):
        raise StructuralContractError("activation execution/fold contract missing")
    if (
        tuple(contract.get("candidate_ids", ())) != EXPECTED_ENABLED
        or tuple(contract.get("seeds", ())) != SEEDS
        or contract.get("outer_workers") != WORKERS
        or contract.get("inner_threads") != 1
        or contract.get("gpu") != "OFF"
        or tuple(folds.get("required_evaluation_fold_ids", ())) != FOLD_IDS
        or folds.get("full_membership_schedule_sha256") != FORMAL_OUTER_POSITION_SCHEDULE_SHA256
        or folds.get("coverage_sha256") != FORMAL_OUTER_COVERAGE_SHA256
    ):
        raise StructuralContractError("activation candidate/seed/resource/fold contract changed")
    return activation


def _worker_initializer() -> None:
    for key, value in THREAD_ENVIRONMENT.items():
        os.environ[key] = value
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"
    import psutil

    process = psutil.Process()
    available = tuple(int(value) for value in process.cpu_affinity())
    desired = tuple(value for value in CPU_AFFINITY if value in available)
    if desired:
        process.cpu_affinity(list(desired))


def _worker_telemetry() -> dict[str, Any]:
    import psutil
    from threadpoolctl import threadpool_info

    process = psutil.Process()
    pools = sorted(
        {int(row["num_threads"]) for row in threadpool_info() if row.get("num_threads") is not None}
    )
    return {
        "pid": os.getpid(),
        "rss_bytes": int(process.memory_info().rss),
        "affinity": list(process.cpu_affinity()),
        "thread_environment": {key: os.environ.get(key) for key in THREAD_ENVIRONMENT},
        "native_pool_threads": pools,
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "nvidia_visible_devices": os.environ.get("NVIDIA_VISIBLE_DEVICES"),
    }


def _seed_frame(project_root: Path, seed: int) -> pd.DataFrame:
    manifest = load_predict_inputs(
        project_root / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
    )
    rows = [row for row in manifest["seeds"] if int(row["seed"]) == seed]
    if len(rows) != 1:
        raise StructuralContractError("worker seed is outside spent input custody")
    frame, _ = load_wave1_seed_frames(rows[0])
    if len(frame) != 1800:
        raise StructuralContractError("spent worker surface must have 1,800 rows")
    return frame


def _folds(frame: pd.DataFrame):
    identity = pd.DataFrame({"date": pd.to_datetime(frame["date"], errors="raise")})
    folds = generate_pit_folds(identity, FORMAL_OUTER_FOLD_SPEC, date_column="date")
    if (
        len(folds) != FORMAL_OUTER_FOLD_COUNT
        or tuple(fold.fold_id for fold in folds[12:]) != FOLD_IDS
        or [position for fold in folds[12:] for position in fold.test_positions]
        != list(range(504, 1800))
    ):
        raise StructuralContractError("worker formal fold schedule changed")
    return folds


def _prediction_rows(
    output: pd.DataFrame,
    *,
    seed: int,
    symbol: str,
    model_id: str,
    fold_id: str,
    test_start: int,
) -> list[dict[str, Any]]:
    values = pd.to_numeric(output["expected_pe"], errors="coerce").to_numpy(
        dtype=np.float64, na_value=np.nan
    )
    dates = pd.to_datetime(output["date"], errors="coerce")
    if dates.isna().any() or not np.isfinite(values).all() or (values <= 0.0).any():
        raise StructuralContractError("candidate fold lacks full positive predictions")
    return [
        {
            "seed": seed,
            "date": pd.Timestamp(date).strftime("%Y-%m-%d"),
            "symbol": symbol,
            "fold_id": fold_id,
            "test_start_position": test_start,
            "model_id": model_id,
            "prediction": float(prediction),
        }
        for date, prediction in zip(dates, values, strict=True)
    ]


def _diagnostic(
    *,
    seed: int,
    model_id: str,
    fold_id: str,
    test_start: int,
    test_rows: int,
    runtime: float,
    pid: int,
    fit_sha256: str = "",
    weight0: float = np.nan,
    weight1: float = np.nan,
    genuinely_distinct: bool | None = None,
    ar1_rho: float = np.nan,
) -> dict[str, Any]:
    return {
        "seed": seed,
        "model_id": model_id,
        "fold_id": fold_id,
        "test_start_position": test_start,
        "test_rows": test_rows,
        "status": "PASS",
        "runtime_seconds": runtime,
        "fit_sha256": fit_sha256,
        "weight0": weight0,
        "weight1": weight1,
        "genuinely_distinct": genuinely_distinct,
        "ar1_rho": ar1_rho,
        "warnings_json": "[]",
        "pid": pid,
    }


def _run_decomposition(
    project_root: Path,
    seed: int,
    candidate_id: str,
    dispatcher: StructuralDispatcher,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    frame = _seed_frame(project_root, seed)
    folds = _folds(frame)
    symbol = str(frame["symbol"].iloc[0])
    if candidate_id == "decomp_block_ridge_ar1_lag1":
        source = frame.loc[:, ["date", *MARKET_CURRENT, *REGIME_CURRENT]].copy()
        source.insert(0, "entity_id", symbol)
        source.insert(0, "seed", seed)
        artifact = build_track_a_lag1_artifact(
            source,
            source_audit=TrackASourceAuditBinding(
                audit_sha256=TRACK_A_AUDIT_RAW,
                passed_audits=REQUIRED_UPSTREAM_AUDITS,
            ),
        ).to_frame()
        features = frame.loc[:, list(TRACK_A_FEATURE_COLUMNS[:9])].copy()
        for column in TRACK_A_FEATURE_COLUMNS[9:]:
            features[column] = artifact[column].to_numpy(copy=True)
        features = features.loc[:, list(TRACK_A_FEATURE_COLUMNS)]
    else:
        features = frame.loc[:, list(TRACK_C_FEATURE_COLUMNS)].copy()
    predictions: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for fold in folds[12:]:
        started = time.perf_counter()
        fold_hash = sha256_bytes(
            canonical_json_bytes(
                {
                    "seed": seed,
                    "fold_id": fold.fold_id,
                    "train_positions": list(fold.train_positions),
                    "test_positions": list(fold.test_positions),
                    "schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
                }
            )
        )
        binding = dispatcher.decomposition_binding(candidate_id=candidate_id, fold_sha256=fold_hash)
        train_positions = list(fold.train_positions)
        test_positions = list(fold.test_positions)
        fit = dispatcher.fit_decomposition(
            candidate_id,
            features.iloc[train_positions].reset_index(drop=True),
            frame["observed_pe"].iloc[train_positions].reset_index(drop=True),
            frame["date"].iloc[train_positions].reset_index(drop=True),
            binding=binding,
        )
        output = dispatcher.predict_decomposition(
            candidate_id,
            fit,
            features.iloc[test_positions].reset_index(drop=True),
            frame["date"].iloc[test_positions].reset_index(drop=True),
        )
        elapsed = time.perf_counter() - started
        predictions.extend(
            _prediction_rows(
                output,
                seed=seed,
                symbol=symbol,
                model_id=candidate_id,
                fold_id=fold.fold_id,
                test_start=test_positions[0],
            )
        )
        diagnostics.append(
            _diagnostic(
                seed=seed,
                model_id=candidate_id,
                fold_id=fold.fold_id,
                test_start=test_positions[0],
                test_rows=len(test_positions),
                runtime=elapsed,
                pid=os.getpid(),
                fit_sha256=fit.fit_sha256,
                ar1_rho=fit.ar1.rho,
            )
        )
    return predictions, diagnostics


def _observed_labels(
    meta: pd.DataFrame,
    frame: pd.DataFrame,
    *,
    columns: tuple[str, ...],
) -> pd.DataFrame:
    output = meta.loc[:, list(columns)].copy()
    positions = meta["session_position"].to_numpy(dtype=np.int64)
    output["observed_pe"] = pd.to_numeric(
        frame["observed_pe"].iloc[positions], errors="raise"
    ).to_numpy(dtype=np.float64)
    return output


def _run_nested_fold(
    project_root: Path,
    seed: int,
    candidate_id: str,
    fold_id: str,
    dispatcher: StructuralDispatcher,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    frame = _seed_frame(project_root, seed)
    fold_index = int(fold_id.removeprefix("fold_"))
    fold = _folds(frame)[fold_index]
    symbol = str(frame["symbol"].iloc[0])
    started = time.perf_counter()
    fit_sha = ""
    weight0 = np.nan
    weight1 = np.nan
    distinct: bool | None = None
    rho = np.nan
    if candidate_id == "residual_ar1_nested_oof":
        plan = build_formal_nested_oof_plan(
            seed=seed,
            outer_fold_id=fold_id,
            candidate_id=candidate_id,
            base_model_id="v04_expected_pe",
            authorization=dispatcher.authorization,
        )
        inner = execute_nested_oof_plan_formal_spent(
            plan, dispatcher.authorization, role="INNER_OOS_FIT"
        )
        outer = execute_nested_oof_plan_formal_spent(
            plan, dispatcher.authorization, role="OUTER_TEST_PREDICT"
        )
        fit = dispatcher.fit_residual_ar1(
            inner,
            _observed_labels(inner.to_frame(), frame, columns=FULL_META_IDENTITY_COLUMNS),
        )
        output = dispatcher.predict_residual_ar1(fit, outer)
        fit_sha = fit.fit_sha256
        rho = fit.ar1.rho
    else:
        plans = tuple(
            build_formal_nested_oof_plan(
                seed=seed,
                outer_fold_id=fold_id,
                candidate_id=candidate_id,
                base_model_id=base_id,
                authorization=dispatcher.authorization,
            )
            for base_id in EXPECTED_PAIR
        )
        if candidate_id == "stack_geometric_equal_pair":
            outer = tuple(
                execute_nested_oof_plan_formal_spent(
                    plan, dispatcher.authorization, role="OUTER_TEST_PREDICT"
                )
                for plan in plans
            )
            output = dispatcher.equal_blend(*outer)
        elif candidate_id == "stack_simplex_pair_frozen":
            inner = tuple(
                execute_nested_oof_plan_formal_spent(
                    plan, dispatcher.authorization, role="INNER_OOS_FIT"
                )
                for plan in plans
            )
            outer = tuple(
                execute_nested_oof_plan_formal_spent(
                    plan, dispatcher.authorization, role="OUTER_TEST_PREDICT"
                )
                for plan in plans
            )
            fit = dispatcher.fit_simplex(
                *inner,
                _observed_labels(inner[0].to_frame(), frame, columns=PAIR_IDENTITY_COLUMNS),
            )
            output = dispatcher.apply_simplex(fit, *outer)
            fit_sha = fit.weight_sha256
            weight0 = fit.weight0
            weight1 = fit.weight1
            distinct = fit.genuinely_distinct
        else:
            raise StructuralContractError("worker received an unknown nested candidate")
    elapsed = time.perf_counter() - started
    predictions = _prediction_rows(
        output,
        seed=seed,
        symbol=symbol,
        model_id=candidate_id,
        fold_id=fold_id,
        test_start=fold.test_positions[0],
    )
    diagnostic = _diagnostic(
        seed=seed,
        model_id=candidate_id,
        fold_id=fold_id,
        test_start=fold.test_positions[0],
        test_rows=len(fold.test_positions),
        runtime=elapsed,
        pid=os.getpid(),
        fit_sha256=fit_sha,
        weight0=weight0,
        weight1=weight1,
        genuinely_distinct=distinct,
        ar1_rho=rho,
    )
    return predictions, diagnostic


def _worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "project_root",
        "seed",
        "candidate_id",
        "fold_ids",
        "activation_raw_sha256",
        "policy_raw_sha256",
        "policy_pin_raw_sha256",
        "payload_sha256",
    }
    if set(payload) != required:
        raise StructuralContractError("worker payload schema changed")
    unsigned = {key: payload[key] for key in required if key != "payload_sha256"}
    if sha256_bytes(canonical_json_bytes(unsigned)) != payload["payload_sha256"]:
        raise StructuralContractError("worker payload seal changed")
    project_root = Path(str(payload["project_root"])).resolve(strict=True)
    _verify_activation(
        project_root,
        activation_raw_sha256=str(payload["activation_raw_sha256"]),
        policy_raw_sha256=str(payload["policy_raw_sha256"]),
        policy_pin_raw_sha256=str(payload["policy_pin_raw_sha256"]),
    )
    authorization = load_structural_execution_authorization(
        project_root,
        external_policy_sha256=str(payload["policy_raw_sha256"]),
        scope="FORMAL_SPENT",
    )
    dispatcher = StructuralDispatcher.from_authorization(authorization)
    seed = int(payload["seed"])
    candidate_id = str(payload["candidate_id"])
    fold_ids = tuple(str(value) for value in payload["fold_ids"])
    if seed not in SEEDS or candidate_id not in EXPECTED_ENABLED or not fold_ids:
        raise StructuralContractError("worker payload is outside the activated universe")
    if candidate_id.startswith("decomp_"):
        if fold_ids != FOLD_IDS:
            raise StructuralContractError("decomposition task must carry all required folds")
        predictions, diagnostics = _run_decomposition(project_root, seed, candidate_id, dispatcher)
    else:
        predictions = []
        diagnostics = []
        for fold_id in fold_ids:
            if fold_id not in FOLD_IDS:
                raise StructuralContractError("nested task fold is outside required identities")
            fold_predictions, diagnostic = _run_nested_fold(
                project_root, seed, candidate_id, fold_id, dispatcher
            )
            predictions.extend(fold_predictions)
            diagnostics.append(diagnostic)
    return {
        "payload_sha256": str(payload["payload_sha256"]),
        "predictions": predictions,
        "diagnostics": diagnostics,
        "telemetry": _worker_telemetry(),
    }


def _payload(
    seed: int,
    candidate_id: str,
    fold_ids: tuple[str, ...],
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> dict[str, Any]:
    unsigned = {
        "project_root": str(ROOT),
        "seed": seed,
        "candidate_id": candidate_id,
        "fold_ids": list(fold_ids),
        "activation_raw_sha256": activation_raw_sha256,
        "policy_raw_sha256": policy_raw_sha256,
        "policy_pin_raw_sha256": policy_pin_raw_sha256,
    }
    return {**unsigned, "payload_sha256": sha256_bytes(canonical_json_bytes(unsigned))}


def _payloads(
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for seed in SEEDS:
        for candidate_id in EXPECTED_ENABLED:
            if candidate_id.startswith("decomp_"):
                output.append(
                    _payload(
                        seed,
                        candidate_id,
                        FOLD_IDS,
                        activation_raw_sha256=activation_raw_sha256,
                        policy_raw_sha256=policy_raw_sha256,
                        policy_pin_raw_sha256=policy_pin_raw_sha256,
                    )
                )
            elif candidate_id == "stack_simplex_pair_frozen":
                for offset in range(8):
                    chunk = FOLD_IDS[offset::8]
                    if chunk:
                        output.append(
                            _payload(
                                seed,
                                candidate_id,
                                chunk,
                                activation_raw_sha256=activation_raw_sha256,
                                policy_raw_sha256=policy_raw_sha256,
                                policy_pin_raw_sha256=policy_pin_raw_sha256,
                            )
                        )
            else:
                output.append(
                    _payload(
                        seed,
                        candidate_id,
                        FOLD_IDS,
                        activation_raw_sha256=activation_raw_sha256,
                        policy_raw_sha256=policy_raw_sha256,
                        policy_pin_raw_sha256=policy_pin_raw_sha256,
                    )
                )
    return output


def _aggregate_rss() -> tuple[int, list[int]]:
    import psutil

    parent = psutil.Process()
    total = 0
    pids: list[int] = []
    for process in (parent, *parent.children(recursive=True)):
        try:
            total += int(process.memory_info().rss)
            pids.append(int(process.pid))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return total, sorted(set(pids))


def _terminate(executor: ProcessPoolExecutor) -> None:
    processes = getattr(executor, "_processes", {})
    for process in tuple(processes.values()):
        try:
            process.terminate()
        except (AttributeError, OSError):
            pass


def run(
    output_directory: Path,
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> Path:
    activation = _verify_activation(
        ROOT,
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    authorization = load_structural_execution_authorization(
        ROOT, external_policy_sha256=policy_raw_sha256, scope="FORMAL_SPENT"
    )
    authorization.verify()
    output_directory = output_directory.resolve()
    prediction_path = output_directory / "structural_predictions.csv"
    diagnostic_path = output_directory / "structural_fold_diagnostics.csv"
    manifest_path = output_directory / "PREDICTION_MANIFEST.json"
    if any(path.exists() for path in (prediction_path, diagnostic_path, manifest_path)):
        raise FileExistsError("structural prediction outputs are immutable")
    output_directory.mkdir(parents=True, exist_ok=True)
    import psutil

    if int(psutil.virtual_memory().available) < MINIMUM_FREE_RAM_BYTES:
        raise StructuralContractError("free RAM is below the activated 16-GiB floor")
    payloads = _payloads(
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    results: list[dict[str, Any]] = []
    max_rss = 0
    min_free = int(psutil.virtual_memory().available)
    observed_pids: set[int] = set()
    started = time.perf_counter()
    context = mp.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=WORKERS,
        mp_context=context,
        initializer=_worker_initializer,
    ) as executor:
        future_map = {executor.submit(_worker, payload): payload for payload in payloads}
        pending = set(future_map)
        while pending:
            rss, pids = _aggregate_rss()
            free = int(psutil.virtual_memory().available)
            max_rss = max(max_rss, rss)
            min_free = min(min_free, free)
            observed_pids.update(pids)
            if rss > MAX_TOTAL_RSS_BYTES or free < MINIMUM_FREE_RAM_BYTES:
                for future in pending:
                    future.cancel()
                _terminate(executor)
                raise StructuralContractError("live aggregate RSS/free-RAM guard breached")
            done, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
            for future in done:
                results.append(future.result())
    wall = time.perf_counter() - started
    predictions = pd.DataFrame([row for result in results for row in result["predictions"]]).loc[
        :, list(PREDICTION_COLUMNS)
    ]
    diagnostics = pd.DataFrame([row for result in results for row in result["diagnostics"]]).loc[
        :, list(DIAGNOSTIC_COLUMNS)
    ]
    predictions = predictions.sort_values(
        ["seed", "date", "model_id"], kind="mergesort"
    ).reset_index(drop=True)
    diagnostics = diagnostics.sort_values(
        ["seed", "test_start_position", "model_id"], kind="mergesort"
    ).reset_index(drop=True)
    if set(predictions["model_id"]) != set(EXPECTED_ENABLED):
        raise StructuralContractError("prediction candidate universe changed")
    for candidate_id in EXPECTED_ENABLED:
        candidate = predictions.loc[predictions["model_id"] == candidate_id]
        if len(candidate) != len(SEEDS) * 1296:
            raise StructuralContractError(f"candidate coverage row count changed: {candidate_id}")
        for seed in SEEDS:
            group = candidate.loc[candidate["seed"] == seed]
            if (
                len(group) != 1296
                or group["date"].duplicated().any()
                or tuple(group["test_start_position"].drop_duplicates())
                != tuple(range(504, 1800, 21))
            ):
                raise StructuralContractError(
                    f"candidate required identity changed: {candidate_id}/{seed}"
                )
    telemetry = [result["telemetry"] for result in results]
    if any(
        row["thread_environment"] != THREAD_ENVIRONMENT
        or row["cuda_visible_devices"] != "-1"
        or row["nvidia_visible_devices"] != "void"
        or tuple(row["affinity"]) != CPU_AFFINITY
        or any(value != 1 for value in row["native_pool_threads"])
        for row in telemetry
    ):
        raise StructuralContractError("worker thread/GPU/affinity telemetry failed")
    prediction_record = write_round_trip_csv(
        predictions, prediction_path, columns=PREDICTION_COLUMNS
    )
    diagnostic_record = write_round_trip_csv(
        diagnostics, diagnostic_path, columns=DIAGNOSTIC_COLUMNS
    )
    runtime = diagnostics.groupby("model_id", sort=True)["runtime_seconds"].sum().to_dict()
    manifest = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v4_truth_blind_spent_prediction_artifact",
            "activation_binding": file_record(
                ROOT
                / "outputs/model_zoo_structural_wave_spent_screen_20260819/ACTIVATION_BINDING_EXECUTION.json"
            ),
            "external_policy_pin": file_record(
                ROOT
                / "outputs/model_zoo_structural_wave_spent_screen_20260819/EXTERNAL_POLICY_PIN_EXECUTION.json"
            ),
            "external_policy_raw_sha256": policy_raw_sha256,
            "authorization_sha256": authorization.authorization_sha256,
            "predict_inputs": file_record(
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
            "inner_threads": 1,
            "gpu": "sealed_off",
            "task_count": len(payloads),
            "peak_live_aggregate_rss_bytes": max_rss,
            "minimum_live_free_ram_bytes": min_free,
            "observed_process_ids": sorted(observed_pids),
            "worker_telemetry": telemetry,
            "activation_decision": activation["decision"],
            "fresh_seed_selected_or_reserved": False,
            "heldout_opened": False,
        }
    )
    write_immutable_json(manifest_path, manifest)
    return manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--activation-raw-sha256", required=True)
    parser.add_argument("--policy-raw-sha256", required=True)
    parser.add_argument("--policy-pin-raw-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
    mp.freeze_support()
    raise SystemExit(main())
