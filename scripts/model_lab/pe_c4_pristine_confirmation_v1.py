"""Precommit, execute, activate, and detach-score unchanged C4 confirmation."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
PYTHON = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)
WORKER = (PROJECT_ROOT / "scripts/model_lab/pe_c4_pristine_worker_v1.py").resolve(strict=True)
SELF = Path(__file__).resolve(strict=True)
OUTER_WORKERS = 16
TIMEOUT = 7_200
SOURCE_RELATIVES = (
    "research/model_zoo/pe_c4_pristine_confirmation_v1/__init__.py",
    "research/model_zoo/pe_c4_pristine_confirmation_v1/canonical.py",
    "research/model_zoo/pe_c4_pristine_confirmation_v1/contracts.py",
    "research/model_zoo/pe_c4_pristine_confirmation_v1/engine.py",
    "scripts/model_lab/pe_c4_pristine_confirmation_v1.py",
    "scripts/model_lab/pe_c4_pristine_worker_v1.py",
    "research/model_zoo/dgp_exploration_v2/contracts.py",
    "research/model_zoo/dgp_exploration_v2/generator.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1/public_role.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1/replay.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/contracts.py",
    "research/model_zoo/hofs_v12_fresh_qualification_service_v1/service.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/prediction.py",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/metrics.py",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/evaluator.py",
)


class OrchestratorError(RuntimeError):
    pass


def _bootstrap() -> None:
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def _safe_run_id(value: str) -> str:
    if (
        not value
        or len(value) > 96
        or any(not (char.isascii() and (char.isalnum() or char in "_-")) for char in value)
    ):
        raise OrchestratorError("unsafe run id")
    return value


def _source_records() -> list[dict[str, object]]:
    records = []
    for relative in SOURCE_RELATIVES:
        raw = (PROJECT_ROOT / relative).resolve(strict=True).read_bytes()
        records.append(
            {
                "relative_path": relative,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        )
    return records


def _source_closure(records: list[dict[str, object]]) -> str:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import semantic_sha256

    return semantic_sha256(records)


def _paths(run_id: str) -> dict[str, Path]:
    return {
        "precommit": PROJECT_ROOT / "build" / f"pe_c4_pristine_precommit_{run_id}.json",
        "rehearsal": PROJECT_ROOT / "build" / f"pe_c4_pristine_serializer_rehearsal_{run_id}.json",
        "vault": PROJECT_ROOT / "outputs" / f".model_zoo_c4_pristine_vault_{run_id}",
        "public": PROJECT_ROOT / "outputs" / f"model_zoo_c4_pristine_public_{run_id}",
        "work": PROJECT_ROOT / "build" / f"pe_c4_pristine_work_{run_id}",
        "prediction": PROJECT_ROOT / "outputs" / f"model_zoo_c4_pristine_prediction_{run_id}",
        "activation": PROJECT_ROOT / "outputs" / f"model_zoo_c4_pristine_activation_{run_id}",
        "result": PROJECT_ROOT / "outputs" / f"model_zoo_c4_pristine_confirmation_{run_id}",
        "pycache": PROJECT_ROOT / "build" / f"pe_c4_pristine_pycache_{run_id}",
    }


def _child_env() -> dict[str, str]:
    allowed = {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(
        {
            "CUDA_VISIBLE_DEVICES": "-1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
            "PYTHONHASHSEED": "2026082401",
        }
    )
    return env


def _worker_command(pycache_prefix: Path, *arguments: str) -> list[str]:
    return [
        str(PYTHON),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={pycache_prefix}",
        str(WORKER),
        *arguments,
    ]


def _run_generation_task(ordinal: int, paths: dict[str, Path]) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import tasks

    task = tasks()[ordinal]
    public_task = paths["public"] / task.seed_alias / f"dgp_{task.dgp_id}"
    protected = subprocess.Popen(
        _worker_command(
            paths["pycache"],
            "protected",
            "--task-ordinal",
            str(ordinal),
            "--pass-1-root",
            str(paths["vault"] / "pass_1"),
            "--pass-2-root",
            str(paths["vault"] / "pass_2"),
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=_child_env(),
    )
    if protected.stdout is None or protected.stderr is None:
        raise OrchestratorError("protected pipe is unavailable")
    public = subprocess.Popen(
        _worker_command(
            paths["pycache"],
            "public",
            "--task-ordinal",
            str(ordinal),
            "--output-root",
            str(public_task),
        ),
        stdin=protected.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=_child_env(),
    )
    protected.stdout.close()
    stdout, public_stderr = public.communicate(timeout=TIMEOUT)
    protected_stderr = protected.stderr.read()
    protected_code = protected.wait(timeout=TIMEOUT)
    if protected_code != 0 or public.returncode != 0:
        raise OrchestratorError(
            f"generation task {ordinal} failed: protected={protected_code}:{protected_stderr[-1500:]!r}; public={public.returncode}:{public_stderr[-1500:]!r}"
        )
    receipt = json.loads(stdout.decode("utf-8"))
    if receipt.get("status") != "PASS_PUBLIC_TWO_PASS":
        raise OrchestratorError("public generation receipt differs")
    return receipt


def _run_prediction_task(ordinal: int, paths: dict[str, Path]) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import tasks

    task = tasks()[ordinal]
    public_task = paths["public"] / task.seed_alias / f"dgp_{task.dgp_id}"
    work_task = paths["work"] / task.seed_alias / f"dgp_{task.dgp_id}"
    completed = subprocess.run(
        _worker_command(
            paths["pycache"],
            "predict",
            "--task-ordinal",
            str(ordinal),
            "--public-root",
            str(public_task),
            "--output-root",
            str(work_task),
        ),
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=_child_env(),
        timeout=TIMEOUT,
    )
    if completed.returncode != 0:
        raise OrchestratorError(f"prediction task {ordinal} failed: {completed.stderr[-2000:]!r}")
    return json.loads(completed.stdout.decode("utf-8"))


def _prepare_roots(paths: dict[str, Path]) -> None:
    for path in paths.values():
        if path.exists():
            raise OrchestratorError(f"run identity already consumed: {path}")
    paths["vault"].mkdir()
    (paths["vault"] / "pass_1").mkdir()
    (paths["vault"] / "pass_2").mkdir()
    paths["public"].mkdir()
    paths["work"].mkdir()
    paths["prediction"].mkdir()
    paths["activation"].mkdir()
    paths["result"].mkdir()
    paths["pycache"].mkdir()
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import tasks

    for task in tasks():
        (paths["public"] / task.seed_alias / f"dgp_{task.dgp_id}").mkdir(
            parents=True, exist_ok=False
        )
        (paths["work"] / task.seed_alias / f"dgp_{task.dgp_id}").mkdir(parents=True, exist_ok=False)


def _serializer_rehearsal(path: Path) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        canonical_json_bytes,
        read_canonical_json,
        semantic_sha256,
        write_canonical_json_new,
    )

    payload = {
        "schema_version": "expected_pe.c4_pristine.serializer_rehearsal.v1",
        "status": "PASS_WRITER_READER_ACTIVATION_SCORER_CANONICAL_ROUNDTRIP",
        "unicode_probe": "직렬화-동일성",
        "nested": {"b": [2, 1], "a": True},
        "terminal_lf": True,
    }
    write_canonical_json_new(path, payload)
    decoded = read_canonical_json(path)
    if decoded != payload or path.read_bytes() != canonical_json_bytes(payload):
        raise OrchestratorError("serializer writer-reader rehearsal failed")
    return {
        "path": path.relative_to(PROJECT_ROOT).as_posix(),
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "semantic_sha256": semantic_sha256(payload),
        "decoded_equality": True,
        "writer_reader_bytes_equal": True,
    }


def _write_precommit(run_id: str, paths: dict[str, Path]) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        semantic_sha256,
        write_canonical_json_new,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import (
        C4_ID,
        CHAMPION_ID,
        DGP_IDS,
        FORMULA_LOCK_SHA256,
        GLOBAL_HOFS_LOG_SHRINK,
        HELDOUT_GATE,
        MODEL_VERSIONS,
        SEEDS,
        SEED_ALIASES,
        SEED_SELECTION_RULE,
        tasks,
    )

    rehearsal = _serializer_rehearsal(paths["rehearsal"])
    records = _source_records()
    core = {
        "schema_version": "expected_pe.c4_pristine_confirmation.v1.precommit",
        "status": "FROZEN_PRETRUTH_UNCHANGED_C4_PRISTINE_CONFIRMATION",
        "run_id": run_id,
        "branch_reason": "R3 statistically valid but governance-inadmissible; new identity required",
        "seed_selection_rule": SEED_SELECTION_RULE,
        "seeds_in_order": list(SEEDS),
        "seed_aliases_in_order": list(SEED_ALIASES),
        "seed_search_scope": "17 relevant seed-ledger/seed-artifact files under build, outputs, research",
        "seed_reuse_match_count_before_precommit": 0,
        "dgp_ids_in_order": list(DGP_IDS),
        "tasks": [task.payload() for task in tasks()],
        "models_in_order": [CHAMPION_ID, C4_ID],
        "model_versions": MODEL_VERSIONS,
        "global_hofs_log_shrink": GLOBAL_HOFS_LOG_SHRINK,
        "formula_lock_sha256": FORMULA_LOCK_SHA256,
        "formula_or_feature_change_allowed": False,
        "candidate_tuning_allowed": False,
        "same_evaluator_gate": HELDOUT_GATE,
        "bootstrap": {
            "draws": 10_000,
            "rng": "numpy.random.Generator(PCG64DXSM(2026082205))",
            "hierarchy": "sample 5 seed clusters, then 62 fold blocks within fixed DGP",
        },
        "serializer_rehearsal": rehearsal,
        "canonicalizer_relative_path": "research/model_zoo/pe_c4_pristine_confirmation_v1/canonical.py",
        "one_canonicalizer_for_writer_reader_activation_scorer": True,
        "source_records": records,
        "source_closure_semantic_sha256": _source_closure(records),
        "truth_access_before_precommit": 0,
        "score_access_before_precommit": 0,
        "promotion_authority_before_result": False,
    }
    precommit = {**core, "precommit_semantic_sha256": semantic_sha256(core)}
    write_canonical_json_new(paths["precommit"], precommit)
    return precommit


def _validate_sources(precommit: dict[str, Any]) -> None:
    records = _source_records()
    if records != precommit.get("source_records") or _source_closure(records) != precommit.get(
        "source_closure_semantic_sha256"
    ):
        raise OrchestratorError("source closure changed after precommit")


def _freeze_predictions(
    run_id: str, paths: dict[str, Path], precommit: dict[str, Any]
) -> dict[str, Any]:
    import pandas as pd

    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        semantic_sha256,
        write_canonical_json_new,
        write_new,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import tasks
    from research.model_zoo.pe_c4_pristine_confirmation_v1.engine import (
        prediction_csv_bytes,
    )

    frames = []
    task_receipts = []
    for task in tasks():
        task_root = paths["work"] / task.seed_alias / f"dgp_{task.dgp_id}"
        frames.append(pd.read_csv(task_root / "PREDICTIONS.csv", float_precision="round_trip"))
        task_receipts.append(
            json.loads((task_root / "PREDICTION_RECEIPT.json").read_text(encoding="utf-8"))
        )
    full = pd.concat(frames, ignore_index=True)
    prediction_raw = prediction_csv_bytes(full)
    prediction_path = paths["prediction"] / "PREDICTIONS.csv"
    write_new(prediction_path, prediction_raw)
    core = {
        "schema_version": "expected_pe.c4_pristine_confirmation.v1.prediction_manifest",
        "status": "FROZEN_PRETRUTH_UNCHANGED_C4_PREDICTIONS",
        "run_id": run_id,
        "precommit_raw_sha256": hashlib.sha256(paths["precommit"].read_bytes()).hexdigest(),
        "precommit_semantic_sha256": precommit["precommit_semantic_sha256"],
        "prediction_raw_sha256": hashlib.sha256(prediction_raw).hexdigest(),
        "prediction_rows": len(full),
        "task_count": len(task_receipts),
        "source_closure_semantic_sha256": precommit["source_closure_semantic_sha256"],
        "two_pass_generation_byte_exact": True,
        "protected_public_process_separation": True,
        "anonymous_one_way_pipe_used": True,
        "truth_open_count": 0,
        "score_open_count": 0,
        "formula_changed": False,
        "candidate_tuned": False,
    }
    manifest = {**core, "manifest_semantic_sha256": semantic_sha256(core)}
    write_canonical_json_new(paths["prediction"] / "PREDICTION_MANIFEST.json", manifest)
    ledger = "".join(
        f"{hashlib.sha256((paths['prediction'] / leaf).read_bytes()).hexdigest()}  {leaf}\n"
        for leaf in ("PREDICTIONS.csv", "PREDICTION_MANIFEST.json")
    ).encode("ascii")
    write_new(paths["prediction"] / "CHECKSUMS.sha256", ledger)
    return manifest


def _activate_and_score(
    run_id: str, paths: dict[str, Path], manifest: dict[str, Any]
) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        semantic_sha256,
        write_canonical_json_new,
    )

    core = {
        "schema_version": "expected_pe.c4_pristine_confirmation.v1.activation",
        "status": "FROZEN_ONE_SHOT_PRISTINE_CONFIRMATION_NO_TUNING",
        "run_id": run_id,
        "prediction_root_relative_path": paths["prediction"].relative_to(PROJECT_ROOT).as_posix(),
        "prediction_raw_sha256": manifest["prediction_raw_sha256"],
        "prediction_manifest_semantic_sha256": manifest["manifest_semantic_sha256"],
        "truth_root_relative_path": (paths["vault"] / "pass_1")
        .relative_to(PROJECT_ROOT)
        .as_posix(),
        "result_root_relative_path": paths["result"].relative_to(PROJECT_ROOT).as_posix(),
        "canonicalizer_relative_path": "research/model_zoo/pe_c4_pristine_confirmation_v1/canonical.py",
        "retry_allowed": False,
        "candidate_tuning_allowed": False,
    }
    activation = {**core, "activation_semantic_sha256": semantic_sha256(core)}
    activation_path = paths["activation"] / "ACTIVATION.json"
    write_canonical_json_new(activation_path, activation)
    completed = subprocess.run(
        [str(PYTHON), "-B", str(SELF), "score", "--activation", str(activation_path)],
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=_child_env(),
        timeout=TIMEOUT,
    )
    if completed.returncode != 0:
        raise OrchestratorError(f"detached scorer failed: {completed.stderr[-3000:]!r}")
    result_path = paths["result"] / "PRISTINE_CONFIRMATION_RESULT.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("run_id") != run_id:
        raise OrchestratorError("detached result run id differs")
    return result


def run(run_id: str) -> dict[str, Any]:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        write_canonical_json_new,
    )

    run_id = _safe_run_id(run_id)
    paths = _paths(run_id)
    _prepare_roots(paths)
    precommit = _write_precommit(run_id, paths)
    _validate_sources(precommit)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=OUTER_WORKERS) as pool:
        generation_receipts = list(
            pool.map(lambda ordinal: _run_generation_task(ordinal, paths), range(50))
        )
    _validate_sources(precommit)
    with ThreadPoolExecutor(max_workers=OUTER_WORKERS) as pool:
        prediction_receipts = list(
            pool.map(lambda ordinal: _run_prediction_task(ordinal, paths), range(50))
        )
    _validate_sources(precommit)
    manifest = _freeze_predictions(run_id, paths, precommit)
    execution = {
        "status": "PASS_50_TWO_PASS_GENERATIONS_AND_UNCHANGED_C4_PREDICTIONS_PRETRUTH",
        "run_id": run_id,
        "outer_workers": OUTER_WORKERS,
        "inner_numeric_threads": 1,
        "gpu_used": False,
        "gpu_reason": "frozen C4 numeric lineage is CPU-only; GPU substitution would change implementation",
        "generation_task_count": len(generation_receipts),
        "prediction_task_count": len(prediction_receipts),
        "wall_time_seconds_pre_activation": time.perf_counter() - started,
        "truth_open_count": 0,
        "score_open_count": 0,
    }
    write_canonical_json_new(paths["prediction"] / "EXECUTION_RECEIPT.json", execution)
    result = _activate_and_score(run_id, paths, manifest)
    print(json.dumps({"result_root": str(paths["result"]), "result": result}, ensure_ascii=False))
    return result


def score(activation_path: Path) -> dict[str, Any]:
    import pandas as pd

    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        read_canonical_json,
        semantic_sha256,
        write_canonical_json_new,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.engine import score_predictions

    activation = read_canonical_json(activation_path)
    unsigned = dict(activation)
    stored = unsigned.pop("activation_semantic_sha256")
    if stored != semantic_sha256(unsigned) or activation.get("retry_allowed") is not False:
        raise OrchestratorError("activation contract differs")
    prediction_root = PROJECT_ROOT / activation["prediction_root_relative_path"]
    truth_root = PROJECT_ROOT / activation["truth_root_relative_path"]
    result_root = PROJECT_ROOT / activation["result_root_relative_path"]
    marker_path = activation_path.parent / "CONSUMPTION_MARKER.json"
    write_canonical_json_new(
        marker_path,
        {
            "status": "CONSUMED_BEFORE_FIRST_TRUTH_OPEN",
            "run_id": activation["run_id"],
            "activation_raw_sha256": hashlib.sha256(activation_path.read_bytes()).hexdigest(),
            "scorer_pid": os.getpid(),
            "truth_open_count_before_marker": 0,
            "retry_allowed": False,
        },
    )
    prediction_raw = (prediction_root / "PREDICTIONS.csv").read_bytes()
    if hashlib.sha256(prediction_raw).hexdigest() != activation["prediction_raw_sha256"]:
        raise OrchestratorError("activated prediction bytes differ")
    predictions = pd.read_csv(prediction_root / "PREDICTIONS.csv", float_precision="round_trip")
    result = score_predictions(predictions, truth_root)
    result = {
        **result,
        "run_id": activation["run_id"],
        "activation_raw_sha256": hashlib.sha256(activation_path.read_bytes()).hexdigest(),
        "consumption_marker_raw_sha256": hashlib.sha256(marker_path.read_bytes()).hexdigest(),
        "detached_scorer_pid": os.getpid(),
        "truth_opened_only_after_consumption_marker": True,
        "production_promotion_authority": bool(result["gate"]["all_heldout_gates_pass"]),
    }
    write_canonical_json_new(result_root / "PRISTINE_CONFIRMATION_RESULT.json", result)
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--run-id", required=True)
    score_parser = commands.add_parser("score")
    score_parser.add_argument("--activation", type=Path, required=True)
    return root


def main() -> int:
    _bootstrap()
    args = parser().parse_args()
    if args.command == "run":
        run(args.run_id)
        return 0
    if args.command == "score":
        score(args.activation)
        return 0
    raise OrchestratorError("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
