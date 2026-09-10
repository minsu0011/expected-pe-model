"""Run the one-shot, production-scale, non-reserved R3 infrastructure rehearsal."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
MAX_PATH_BUDGET = 239
TIMEOUT_SECONDS = 7_200
GENERATION_WORKERS = 16
NUMERIC_WORKERS_PER_LANE = 16
_CREATE_NEW_PROCESS_GROUP = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
_PREFIX_NAMES = (
    "PREDICTIONS.csv",
    "REHEARSAL_EXECUTION_RECEIPT.json",
    "REHEARSAL_MANIFEST.json",
    "REHEARSAL_SOURCE_LOCK.json",
)
_LEDGER_NAMES = (*_PREFIX_NAMES, "REHEARSAL_AUDIT.json")
_SEALED_NAMES = (*_LEDGER_NAMES, "CHECKSUMS.sha256", "REHEARSAL_SEAL.json")


class RehearsalControllerError(RuntimeError):
    """Fail-closed R3 rehearsal controller error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RehearsalControllerError("R3 rehearsal controller requires -I -B")
    if sys.pycache_prefix is None:
        raise RehearsalControllerError("R3 controller pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RehearsalControllerError("R3 controller pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = str(path.resolve(strict=True))
        if resolved not in sys.path:
            sys.path.append(resolved)


def _safe_run_id(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 24
        or any(
            not (character.isascii() and (character.isalnum() or character in "_-"))
            for character in value
        )
    ):
        raise RehearsalControllerError("R3 rehearsal run id is unsafe or too long")
    return value


def _registry_state() -> tuple[bytes, dict[str, Any], set[int]]:
    path = (PROJECT_ROOT / "outputs/v04_spent_seed_registry.json").resolve(strict=True)
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalControllerError("spent-seed registry is unreadable") from exc
    if type(value) is not dict or type(value.get("entries")) is not list:
        raise RehearsalControllerError("spent-seed registry schema differs")
    spent = {int(item) for item in value.get("baseline_spent_evidence_seeds", [])}
    for entry in value["entries"]:
        if type(entry) is not dict or type(entry.get("reserved_seeds")) is not list:
            raise RehearsalControllerError("spent-seed registry entry differs")
        spent.update(int(item) for item in entry["reserved_seeds"])
    return raw, value, spent


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_lock() -> tuple[bytes, dict[str, object]]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import (
        REHEARSAL_SOURCE_RELATIVES,
    )

    records = []
    for relative in REHEARSAL_SOURCE_RELATIVES:
        raw = (PROJECT_ROOT / relative).resolve(strict=True).read_bytes()
        records.append(
            {
                "relative_path": relative,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        )
    core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_rehearsal.source_lock.v1",
        "status": "FROZEN_BEFORE_NONRESERVED_GENERATION",
        "source_relatives_in_order": list(REHEARSAL_SOURCE_RELATIVES),
        "source_records": records,
        "candidate_formula_changes_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "formal_seed_reservation_count": 0,
    }
    value = {**core, "source_lock_semantic_sha256": semantic_sha256(core)}
    return canonical_pretty_bytes(value), value


def _python() -> Path:
    executable = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(
        strict=True
    )
    if executable.name.casefold() != "python.exe":
        raise RehearsalControllerError("pinned R3 Python differs")
    return executable


def _command(*, script: str, pycache_prefix: Path, arguments: tuple[str, ...]) -> tuple[str, ...]:
    prefix = pycache_prefix.resolve(strict=True)
    if not prefix.is_dir() or any(prefix.iterdir()):
        raise RehearsalControllerError("R3 child pycache prefix is not empty")
    entrypoint = (PROJECT_ROOT / "scripts/model_lab" / script).resolve(strict=True)
    return (
        str(_python()),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={prefix}",
        str(entrypoint),
        *arguments,
    )


def _parse_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalControllerError(f"{label} returned invalid JSON") from exc
    if type(value) is not dict:
        raise RehearsalControllerError(f"{label} returned non-object JSON")
    return value


def _run_json(
    command: tuple[str, ...], *, environment: dict[str, str], label: str
) -> tuple[bytes, dict[str, Any]]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=environment,
        timeout=TIMEOUT_SECONDS,
        creationflags=_CREATE_NEW_PROCESS_GROUP,
    )
    if completed.returncode != 0:
        raise RehearsalControllerError(f"{label} failed: {completed.stderr[-4000:]!r}")
    return completed.stdout, _parse_json(completed.stdout, label=label)


def _task_root(base: Path, task: Any) -> Path:
    return base / task.seed_alias / f"dgp_{task.dgp_id}"


def _run_generation_pipeline(
    *,
    task: Any,
    pass_1: Path,
    pass_2: Path,
    public: Path,
    caches: Mapping[str, Path],
    environment: dict[str, str],
) -> dict[str, Any]:
    protected_command = _command(
        script="pe_four_model_r3_rehearsal_worker.py",
        pycache_prefix=caches["protected"],
        arguments=(
            "protected-two-pass",
            "--task-ordinal",
            str(task.task_ordinal),
            "--pass-1-root",
            str(pass_1),
            "--pass-2-root",
            str(pass_2),
        ),
    )
    public_command = _command(
        script="pe_four_model_r3_rehearsal_worker.py",
        pycache_prefix=caches["public"],
        arguments=(
            "public-two-pass",
            "--task-ordinal",
            str(task.task_ordinal),
            "--public-task-root",
            str(_task_root(public, task)),
        ),
    )
    if any(token in "\n".join(public_command).casefold() for token in ("vault", "truth", "latent")):
        raise RehearsalControllerError("public rehearsal command contains protected path")
    protected = subprocess.Popen(
        protected_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=environment,
        creationflags=_CREATE_NEW_PROCESS_GROUP,
    )
    public_process: subprocess.Popen[bytes] | None = None
    try:
        if protected.stdout is None or protected.stderr is None:
            raise RehearsalControllerError("protected rehearsal pipes differ")
        public_process = subprocess.Popen(
            public_command,
            stdin=protected.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=environment,
            creationflags=_CREATE_NEW_PROCESS_GROUP,
        )
        protected.stdout.close()
        public_stdout, public_stderr = public_process.communicate(timeout=TIMEOUT_SECONDS)
        protected_stderr = protected.stderr.read()
        protected_code = protected.wait(timeout=TIMEOUT_SECONDS)
        if protected_code != 0 or public_process.returncode != 0:
            raise RehearsalControllerError(
                "R3 protected/public pipeline failed: "
                f"protected={protected_code}:{protected_stderr[-4000:]!r}; "
                f"public={public_process.returncode}:{public_stderr[-4000:]!r}"
            )
        receipt = _parse_json(public_stdout, label="R3 public replay")
        if receipt.get("status") != "PASS_TWO_PUBLIC_PASSES_BYTE_EXACT_PRETRUTH":
            raise RehearsalControllerError("R3 public replay receipt differs")
        return receipt
    except BaseException:
        if public_process is not None and public_process.poll() is None:
            public_process.kill()
            public_process.communicate()
        if protected.poll() is None:
            protected.kill()
            protected.communicate()
        raise
    finally:
        if protected.poll() is None:
            protected.kill()
        protected.wait()


def _numeric_task(
    *,
    lane: str,
    task: Any,
    public: Path,
    work: Path,
    cache: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    command = _command(
        script="pe_four_model_r3_rehearsal_worker.py",
        pycache_prefix=cache,
        arguments=(
            f"numeric-{lane}",
            "--task-ordinal",
            str(task.task_ordinal),
            "--public-task-root",
            str(_task_root(public, task)),
            "--numeric-task-root",
            str(_task_root(work / lane, task)),
            "--worker-slot",
            str(task.task_ordinal % NUMERIC_WORKERS_PER_LANE),
        ),
    )
    if any(token in "\n".join(command).casefold() for token in ("vault", "truth", "latent")):
        raise RehearsalControllerError("numeric rehearsal command contains protected path")
    _, receipt = _run_json(command, environment=environment, label=f"R3 numeric {lane} task")
    expected_status = (
        "PASS_C2_C3_PUBLIC_ONLY_NUMERIC_TASK"
        if lane == "bce"
        else "PASS_C4_SEED_FREE_NUMERIC_TASK_AND_IDENTITY_PROJECTION"
    )
    if receipt.get("status") != expected_status or receipt.get("task") != task.payload():
        raise RehearsalControllerError(f"R3 numeric {lane} receipt differs")
    return receipt


def _common_identity_semantic(frame: Any) -> str:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        IDENTITY_COLUMNS,
    )

    identities = frame.loc[frame["model_ordinal"].eq(0), list(IDENTITY_COLUMNS)]
    digest = hashlib.sha256()
    for row in identities.itertuples(index=False, name=None):
        identity = [
            str(row[0]),
            str(row[1]),
            int(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            int(row[6]),
            int(row[7]),
        ]
        digest.update(
            (
                json.dumps(
                    identity,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        )
    return digest.hexdigest()


def _read_surface(work: Path, *, lane: str, task: Any) -> Any:
    import pandas as pd

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        BCE_TASK_SURFACE_COLUMNS,
        HOFS_TASK_SURFACE_COLUMNS,
    )

    leaf = "BCE_SURFACE.csv" if lane == "bce" else "C4_SURFACE.csv"
    expected = BCE_TASK_SURFACE_COLUMNS if lane == "bce" else HOFS_TASK_SURFACE_COLUMNS
    raw = (_task_root(work / lane, task) / leaf).resolve(strict=True).read_bytes()
    try:
        frame = pd.read_csv(io.BytesIO(raw), float_precision="round_trip")
    except (UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        raise RehearsalControllerError(f"R3 numeric {lane} surface differs") from exc
    if tuple(map(str, frame.columns)) != expected or canonical_csv_bytes(frame) != raw:
        raise RehearsalControllerError(f"R3 numeric {lane} canonical surface differs")
    return frame


def _artifact(project: Path, published: Any) -> dict[str, object]:
    published.assert_live()
    return {
        "relative_path": published.path.relative_to(project).as_posix(),
        "raw_sha256": published.raw_sha256,
        "size_bytes": published.size_bytes,
        "volume_serial_number": int(published.volume_serial_number, 16),
        "file_id_128": published.file_id_128,
    }


def _root_identity(root: Any) -> dict[str, object]:
    value = root.identity_payload()
    return {
        "volume_serial_number": int(value["volume_serial_number"], 16),
        "file_id_128": value["file_id_128"],
    }


def _planned_paths(root: Path, prediction_root: Path, activation_root: Path) -> list[Path]:
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import rehearsal_tasks

    result: list[Path] = []
    for task in rehearsal_tasks():
        result.extend(
            root / "v" / pass_name / f"seed_{task.data_seed}" / f"dgp_{task.dgp_id}" / leaf
            for pass_name in ("pass_1", "pass_2")
            for leaf in ("METADATA.json", "latent_events.csv", "truth.csv")
        )
        result.extend(
            _task_root(root / "p", task) / leaf
            for leaf in (
                "PUBLIC_REPLAY_RECEIPT.json",
                "PUBLIC_TASK_MANIFEST.json",
                "canonical150.csv",
                "v04_overlay.csv",
            )
        )
        result.extend(
            _task_root(root / "n" / lane, task) / leaf
            for lane, leaves in (
                ("bce", ("BCE_RECEIPT.json", "BCE_SURFACE.csv")),
                ("c4", ("C4_RECEIPT.json", "C4_SURFACE.csv")),
            )
            for leaf in leaves
        )
    result.extend(prediction_root / leaf for leaf in _SEALED_NAMES)
    result.append(activation_root / "ACTIVATION.json")
    result.extend(
        root / leaf for leaf in ("DETACHED_PLUMBING_RECEIPT.json", "R3_REHEARSAL_RESULT.json")
    )
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    return result


def main() -> int:  # noqa: C901, PLR0915 - fail-closed orchestration is intentionally linear
    _bootstrap()
    run_id = _safe_run_id(parser().parse_args().run_id)
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        C1_ID,
        IDENTITY_COLUMNS,
        MODEL_IDS_IN_ORDER,
        SOURCE_MODEL_VERSIONS,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation_execution import (
        child_environment,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction import (
        build_task_prediction_rows,
        validate_full_prediction_rows,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction_execution import (
        numeric_child_environment,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.publisher import (
        _reacquire_commit_directory_custody,
        _release_prefix_write_custody,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
        HeldDirectory,
        claim_output_root,
        publish_leaf,
        reconcile_tree,
    )
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import (
        REHEARSAL_DGP_IDS,
        REHEARSAL_IDENTITY_COUNT,
        REHEARSAL_PREDICTION_ROW_COUNT,
        REHEARSAL_SEED_ALIASES,
        REHEARSAL_SEEDS,
        REHEARSAL_TASK_COUNT,
        rehearsal_tasks,
    )

    # Both bytes and profile are frozen before the first non-reserved generator call.
    registry_before_raw, registry_before, spent_before = _registry_state()
    overlap = sorted(set(REHEARSAL_SEEDS) & spent_before)
    if overlap:
        raise RehearsalControllerError(f"R3 rehearsal fixture overlaps spent seeds: {overlap}")
    source_lock_raw, source_lock = _source_lock()
    fixture_profile = {
        "seeds_in_order": list(REHEARSAL_SEEDS),
        "seed_selection": "EXPLICIT_FIXED_NONRANDOM_FIXTURE",
        "seed_profile_frozen_before_execution": True,
        "permanently_excluded_from_formal_reservation": True,
        "formal_seed_reservation_count": 0,
        "dgp_ids_in_order": list(REHEARSAL_DGP_IDS),
    }
    root = PROJECT_ROOT / "build" / f"pe_r3r_{run_id}"
    prediction_path = PROJECT_ROOT / "outputs" / f"model_zoo_pe_four_model_r3_rehearsal_{run_id}"
    activation_path = (
        PROJECT_ROOT / "outputs" / f"model_zoo_pe_four_model_r3_rehearsal_activation_{run_id}"
    )
    if root.exists() or prediction_path.exists() or activation_path.exists():
        raise RehearsalControllerError("R3 rehearsal identity is already consumed")
    planned = _planned_paths(root, prediction_path, activation_path)
    longest = max(planned, key=lambda path: len(str(path)))
    if len(str(longest)) > MAX_PATH_BUDGET:
        raise RehearsalControllerError("R3 rehearsal planned path exceeds budget")

    root.mkdir(exist_ok=False)
    vault = root / "v"
    pass_1 = vault / "pass_1"
    pass_2 = vault / "pass_2"
    public = root / "p"
    numeric = root / "n"
    pycache = root / "c"
    for path in (vault, pass_1, pass_2, public, numeric, pycache):
        path.mkdir(exist_ok=False)
    caches: dict[str, Path] = {}
    for role in ("protected", "public", "bce", "c4", "audit", "plumbing"):
        caches[role] = pycache / role
        caches[role].mkdir(exist_ok=False)
    for seed, alias in zip(REHEARSAL_SEEDS, REHEARSAL_SEED_ALIASES, strict=True):
        for pass_root in (pass_1, pass_2):
            (pass_root / f"seed_{seed}").mkdir(exist_ok=False)
        (public / alias).mkdir(exist_ok=False)
        for lane in ("bce", "c4"):
            (numeric / lane / alias).mkdir(parents=True, exist_ok=False)
    for task in rehearsal_tasks():
        _task_root(public, task).mkdir(exist_ok=False)
        for lane in ("bce", "c4"):
            _task_root(numeric / lane, task).mkdir(exist_ok=False)

    base_environment = child_environment()
    with ThreadPoolExecutor(max_workers=GENERATION_WORKERS) as pool:
        public_receipts = list(
            pool.map(
                lambda task: _run_generation_pipeline(
                    task=task,
                    pass_1=pass_1,
                    pass_2=pass_2,
                    public=public,
                    caches=caches,
                    environment=base_environment,
                ),
                rehearsal_tasks(),
            )
        )
    protected_leaf_count = 0
    for task in rehearsal_tasks():
        for pass_root in (pass_1, pass_2):
            task_root = pass_root / f"seed_{task.data_seed}" / f"dgp_{task.dgp_id}"
            if {path.name for path in task_root.iterdir()} != {
                "METADATA.json",
                "latent_events.csv",
                "truth.csv",
            }:
                raise RehearsalControllerError("R3 protected final leaf universe differs")
            protected_leaf_count += 3
    if protected_leaf_count != 300:
        raise RehearsalControllerError("R3 protected leaf count differs")

    def run_lane(lane: str) -> list[dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=NUMERIC_WORKERS_PER_LANE) as lane_pool:
            return list(
                lane_pool.map(
                    lambda task: _numeric_task(
                        lane=lane,
                        task=task,
                        public=public,
                        work=numeric,
                        cache=caches[lane],
                        environment=numeric_child_environment(lane),
                    ),
                    rehearsal_tasks(),
                )
            )

    with ThreadPoolExecutor(max_workers=2) as lane_controller:
        bce_future = lane_controller.submit(run_lane, "bce")
        c4_future = lane_controller.submit(run_lane, "c4")
        bce_receipts = bce_future.result()
        c4_receipts = c4_future.result()

    prediction_tasks = []
    for task in rehearsal_tasks():
        prediction_tasks.append(
            build_task_prediction_rows(
                _read_surface(numeric, lane="bce", task=task),
                _read_surface(numeric, lane="c4", task=task),
                source_versions=SOURCE_MODEL_VERSIONS,
            )
        )
    import pandas as pd

    prediction = pd.concat(prediction_tasks, ignore_index=True)
    validate_full_prediction_rows(prediction)
    prediction_raw = canonical_csv_bytes(prediction)
    identities = prediction.loc[prediction["model_ordinal"].eq(0), list(IDENTITY_COLUMNS)]
    if (
        len(identities) != REHEARSAL_IDENTITY_COUNT
        or identities.duplicated().any()
        or len(prediction) != REHEARSAL_PREDICTION_ROW_COUNT
        or prediction["pe_model_id"].eq(C1_ID).any()
        or tuple(prediction["pe_model_id"].drop_duplicates()) != MODEL_IDS_IN_ORDER
    ):
        raise RehearsalControllerError("R3 aggregate prediction geometry differs")
    common_semantic = _common_identity_semantic(prediction)

    def receipt_hashes(lane: str, leaf: str) -> list[str]:
        return [_raw_sha256(_task_root(numeric / lane, task) / leaf) for task in rehearsal_tasks()]

    execution_core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_full_nonreserved_rehearsal.execution.v1",
        "status": "PASS_50_PROTECTED_PUBLIC_AND_100_NUMERIC_COLD_WORKERS",
        "run_id": run_id,
        "fixture_profile": fixture_profile,
        "task_count": REHEARSAL_TASK_COUNT,
        "protected_process_count": REHEARSAL_TASK_COUNT,
        "public_process_count": REHEARSAL_TASK_COUNT,
        "bce_process_count": REHEARSAL_TASK_COUNT,
        "c4_process_count": REHEARSAL_TASK_COUNT,
        "generation_outer_workers": GENERATION_WORKERS,
        "bce_lane_workers": NUMERIC_WORKERS_PER_LANE,
        "c4_lane_workers": NUMERIC_WORKERS_PER_LANE,
        "numeric_lanes_executed_concurrently": True,
        "inner_blas_threads": 1,
        "cpu_affinity": "CPU0-31",
        "gpu_enabled": False,
        "production_role_functions": [
            "heldout_role_worker._protected_two_pass",
            "heldout_role_worker._public_two_pass",
            "heldout_role_worker._numeric_task[lane=bce]",
            "heldout_role_worker._numeric_task[lane=c4]",
            "prediction.build_task_prediction_rows",
        ],
        "protected_public_anonymous_one_way_pipe": True,
        "public_pass_1_pass_2_byte_exact": True,
        "protected_leaf_count_metadata_only_inventory": protected_leaf_count,
        "public_receipt_statuses": [str(receipt.get("status")) for receipt in public_receipts],
        "bce_receipt_raw_sha256_in_task_order": receipt_hashes("bce", "BCE_RECEIPT.json"),
        "c4_receipt_raw_sha256_in_task_order": receipt_hashes("c4", "C4_RECEIPT.json"),
        "bce_receipt_count": len(bce_receipts),
        "c4_receipt_count": len(c4_receipts),
        "all_child_processes_reaped": True,
        "reserved_generator_invocation_count": 0,
        "formal_seed_reservation_count": 0,
        "candidate_tuning_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    execution = {
        **execution_core,
        "execution_semantic_sha256": semantic_sha256(execution_core),
    }
    execution_raw = canonical_pretty_bytes(execution)

    outputs = HeldDirectory.open_existing(PROJECT_ROOT / "outputs")
    prediction_root = None
    published: list[Any] = []
    prediction_root_identity: dict[str, object] | None = None
    sealed_refs: dict[str, dict[str, object]] = {}
    audit: dict[str, Any] | None = None
    seal: dict[str, Any] | None = None
    try:
        prediction_root = claim_output_root(
            path=prediction_path, project_root=PROJECT_ROOT, outputs_parent=outputs
        )
        prediction_file = publish_leaf(
            parent=prediction_root, final_leaf="PREDICTIONS.csv", raw=prediction_raw
        )
        published.append(prediction_file)
        execution_file = publish_leaf(
            parent=prediction_root,
            final_leaf="REHEARSAL_EXECUTION_RECEIPT.json",
            raw=execution_raw,
        )
        published.append(execution_file)
        source_file = publish_leaf(
            parent=prediction_root,
            final_leaf="REHEARSAL_SOURCE_LOCK.json",
            raw=source_lock_raw,
        )
        published.append(source_file)
        prediction_root_identity = _root_identity(prediction_root)
        manifest_core: dict[str, object] = {
            "schema_version": "expected_pe.four_model.r3_full_nonreserved_rehearsal.manifest.v1",
            "status": "FROZEN_PRODUCTION_SCALE_PREFIX_PRETRUTH",
            "run_id": run_id,
            "fixture_profile": fixture_profile,
            "nonreserved_seeds_in_order": list(REHEARSAL_SEEDS),
            "seed_aliases_in_order": list(REHEARSAL_SEED_ALIASES),
            "dgp_ids_in_order": list(REHEARSAL_DGP_IDS),
            "task_order": "nonreserved_seed_major_then_dgp_A_to_J",
            "task_count": REHEARSAL_TASK_COUNT,
            "identity_count": REHEARSAL_IDENTITY_COUNT,
            "prediction_row_count": REHEARSAL_PREDICTION_ROW_COUNT,
            "model_ids_in_order": list(MODEL_IDS_IN_ORDER),
            "prediction_ref": _artifact(PROJECT_ROOT, prediction_file),
            "execution_receipt_ref": _artifact(PROJECT_ROOT, execution_file),
            "source_lock_ref": _artifact(PROJECT_ROOT, source_file),
            "prediction_raw_sha256": prediction_file.raw_sha256,
            "common_identity_semantic_sha256": common_semantic,
            "execution_semantic_sha256": execution["execution_semantic_sha256"],
            "source_lock_semantic_sha256": source_lock["source_lock_semantic_sha256"],
            "output_root_identity": prediction_root_identity,
            "prefix_file_count": 4,
            "independent_auditor_required": True,
            "detached_evaluator_plumbing_required": True,
            "handle_write_custody_release_required": True,
            "formal_seed_reservation_count": 0,
            "candidate_tuning_allowed": False,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_content_open_count": 0,
        }
        manifest = {
            **manifest_core,
            "manifest_semantic_sha256": semantic_sha256(manifest_core),
        }
        manifest_file = publish_leaf(
            parent=prediction_root,
            final_leaf="REHEARSAL_MANIFEST.json",
            raw=canonical_pretty_bytes(manifest),
        )
        published.append(manifest_file)
        prefix_files = tuple(published)
        _release_prefix_write_custody(
            outputs=outputs,
            root=prediction_root,
            prefix_files=prefix_files,
        )
        audit_command = _command(
            script="pe_four_model_r3_rehearsal_auditor.py",
            pycache_prefix=caches["audit"],
            arguments=(
                "audit",
                "--prediction-root",
                str(prediction_path),
                "--numeric-work-root",
                str(numeric),
                "--run-id",
                run_id,
            ),
        )
        if any(
            token in "\n".join(audit_command).casefold() for token in ("vault", "truth", "latent")
        ):
            raise RehearsalControllerError("R3 auditor command contains protected path")
        audit_raw, audit = _run_json(
            audit_command, environment=base_environment, label="R3 independent auditor"
        )
        expected_prefix_refs = {
            "prediction_ref": _artifact(PROJECT_ROOT, prediction_file),
            "manifest_ref": _artifact(PROJECT_ROOT, manifest_file),
            "execution_receipt_ref": _artifact(PROJECT_ROOT, execution_file),
            "source_lock_ref": _artifact(PROJECT_ROOT, source_file),
        }
        if (
            audit.get("status") != "GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH"
            or audit.get("verdict") != "GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH"
            or audit.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
            or audit.get("findings") != []
            or any(audit.get(key) != value for key, value in expected_prefix_refs.items())
        ):
            raise RehearsalControllerError("R3 independent audit did not return exact GO")
        _reacquire_commit_directory_custody(
            outputs=outputs,
            root=prediction_root,
            prefix_files=prefix_files,
        )
        audit_file = publish_leaf(
            parent=prediction_root,
            final_leaf="REHEARSAL_AUDIT.json",
            raw=audit_raw,
        )
        published.append(audit_file)
        by_name = {item.name: item for item in published}
        ledger_raw = b"".join(
            f"{by_name[name].raw_sha256}  {name}\n".encode("ascii") for name in _LEDGER_NAMES
        )
        checksums_file = publish_leaf(
            parent=prediction_root, final_leaf="CHECKSUMS.sha256", raw=ledger_raw
        )
        published.append(checksums_file)
        seal_core: dict[str, object] = {
            "schema_version": "expected_pe.four_model.r3_rehearsal.seal.v1",
            "status": "SEALED_GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH",
            "verdict": "GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH",
            "run_id": run_id,
            "prediction_ref": _artifact(PROJECT_ROOT, prediction_file),
            "manifest_ref": _artifact(PROJECT_ROOT, manifest_file),
            "execution_receipt_ref": _artifact(PROJECT_ROOT, execution_file),
            "source_lock_ref": _artifact(PROJECT_ROOT, source_file),
            "audit_ref": _artifact(PROJECT_ROOT, audit_file),
            "checksums_ref": _artifact(PROJECT_ROOT, checksums_file),
            "audit_semantic_sha256": audit["audit_semantic_sha256"],
            "common_identity_semantic_sha256": common_semantic,
            "output_root_identity": prediction_root_identity,
            "output_file_universe": list(_SEALED_NAMES),
            "authorization_commit_leaf": "REHEARSAL_SEAL.json",
            "authorization_commit_published_last": True,
            "checksums_excludes_authorization_commit_leaf": True,
            "handle_write_custody_released_before_path_audit": True,
            "handle_directory_write_custody_reacquired_after_audit": True,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_content_open_count": 0,
            "formal_seed_reservation_count": 0,
            "terminal": False,
            "retry_allowed": False,
        }
        seal = {**seal_core, "seal_semantic_sha256": semantic_sha256(seal_core)}
        seal_file = publish_leaf(
            parent=prediction_root,
            final_leaf="REHEARSAL_SEAL.json",
            raw=canonical_pretty_bytes(seal),
        )
        published.append(seal_file)
        reconcile_tree(
            outputs_parent=outputs,
            output_root=prediction_root,
            files=tuple(published),
            expected_names=_SEALED_NAMES,
        )
        sealed_refs = {item.name: _artifact(PROJECT_ROOT, item) for item in published}
    finally:
        for item in reversed(published):
            item.close()
        if prediction_root is not None:
            prediction_root.close()
        outputs.close()
    if prediction_root_identity is None or audit is None or seal is None:
        raise RehearsalControllerError("R3 rehearsal seal state is incomplete")

    activation_outputs = HeldDirectory.open_existing(PROJECT_ROOT / "outputs")
    activation_root = None
    activation_files: list[Any] = []
    activation_ref: dict[str, object] | None = None
    activation_root_identity: dict[str, object] | None = None
    try:
        activation_root = claim_output_root(
            path=activation_path,
            project_root=PROJECT_ROOT,
            outputs_parent=activation_outputs,
        )
        activation_core: dict[str, object] = {
            "schema_version": "expected_pe.four_model.r3_rehearsal.activation.v1",
            "status": "PASS_REHEARSAL_ACTIVATION_PRETRUTH",
            "run_id": run_id,
            "prediction_root_relative_path": prediction_path.relative_to(PROJECT_ROOT).as_posix(),
            "prediction_root_identity": prediction_root_identity,
            "seal_ref": sealed_refs["REHEARSAL_SEAL.json"],
            "seal_semantic_sha256": seal["seal_semantic_sha256"],
            "audit_ref": sealed_refs["REHEARSAL_AUDIT.json"],
            "audit_semantic_sha256": audit["audit_semantic_sha256"],
            "task_count": REHEARSAL_TASK_COUNT,
            "identity_count": REHEARSAL_IDENTITY_COUNT,
            "prediction_row_count": REHEARSAL_PREDICTION_ROW_COUNT,
            "detached_evaluator_plumbing_only": True,
            "formal_scoring_authorized": False,
            "formal_seed_reservation_count": 0,
            "candidate_tuning_allowed": False,
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_content_open_count": 0,
        }
        activation = {
            **activation_core,
            "activation_semantic_sha256": semantic_sha256(activation_core),
        }
        activation_file = publish_leaf(
            parent=activation_root,
            final_leaf="ACTIVATION.json",
            raw=canonical_pretty_bytes(activation),
        )
        activation_files.append(activation_file)
        reconcile_tree(
            outputs_parent=activation_outputs,
            output_root=activation_root,
            files=tuple(activation_files),
            expected_names=("ACTIVATION.json",),
        )
        activation_ref = _artifact(PROJECT_ROOT, activation_file)
        activation_root_identity = _root_identity(activation_root)
    finally:
        for item in reversed(activation_files):
            item.close()
        if activation_root is not None:
            activation_root.close()
        activation_outputs.close()
    if activation_ref is None or activation_root_identity is None:
        raise RehearsalControllerError("R3 rehearsal activation is incomplete")

    plumbing_command = _command(
        script="pe_four_model_r3_rehearsal_auditor.py",
        pycache_prefix=caches["plumbing"],
        arguments=(
            "plumbing",
            "--activation-root",
            str(activation_path),
            "--prediction-root",
            str(prediction_path),
            "--run-id",
            run_id,
        ),
    )
    if any(
        token in "\n".join(plumbing_command).casefold()
        for token in ("vault", "truth", "latent", "heldout")
    ):
        raise RehearsalControllerError("detached plumbing command contains blocked path")
    plumbing_raw, plumbing = _run_json(
        plumbing_command,
        environment=base_environment,
        label="R3 detached evaluator plumbing",
    )
    if (
        plumbing.get("status") != "PASS_DETACHED_EVALUATOR_PLUMBING_SIMULATION"
        or plumbing.get("truth_open_count") != 0
        or plumbing.get("score_open_count") != 0
        or plumbing.get("heldout_content_open_count") != 0
    ):
        raise RehearsalControllerError("R3 detached evaluator plumbing differs")
    plumbing_path = root / "DETACHED_PLUMBING_RECEIPT.json"
    atomic_write_new(plumbing_path, plumbing_raw)

    registry_after_raw, registry_after, spent_after = _registry_state()
    if (
        registry_after_raw != registry_before_raw
        or registry_after != registry_before
        or spent_after != spent_before
    ):
        raise RehearsalControllerError("R3 rehearsal mutated spent-seed registry")
    result_core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_full_nonreserved_rehearsal.result.v1",
        "status": "GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE",
        "run_id": run_id,
        "fixture_profile": fixture_profile,
        "task_count": REHEARSAL_TASK_COUNT,
        "identity_count": REHEARSAL_IDENTITY_COUNT,
        "prediction_row_count": REHEARSAL_PREDICTION_ROW_COUNT,
        "model_ids_in_order": list(MODEL_IDS_IN_ORDER),
        "c1_prediction_row_count": 0,
        "source_lock_raw_sha256": hashlib.sha256(source_lock_raw).hexdigest(),
        "prediction_root_relative_path": prediction_path.relative_to(PROJECT_ROOT).as_posix(),
        "prediction_root_identity": prediction_root_identity,
        "prediction_raw_sha256": sealed_refs["PREDICTIONS.csv"]["raw_sha256"],
        "audit_ref": sealed_refs["REHEARSAL_AUDIT.json"],
        "audit_semantic_sha256": audit["audit_semantic_sha256"],
        "seal_ref": sealed_refs["REHEARSAL_SEAL.json"],
        "seal_semantic_sha256": seal["seal_semantic_sha256"],
        "activation_root_relative_path": activation_path.relative_to(PROJECT_ROOT).as_posix(),
        "activation_root_identity": activation_root_identity,
        "activation_ref": activation_ref,
        "detached_plumbing_ref": {
            "relative_path": plumbing_path.relative_to(PROJECT_ROOT).as_posix(),
            "raw_sha256": hashlib.sha256(plumbing_raw).hexdigest(),
            "size_bytes": len(plumbing_raw),
        },
        "registry_before_raw_sha256": hashlib.sha256(registry_before_raw).hexdigest(),
        "registry_after_raw_sha256": hashlib.sha256(registry_after_raw).hexdigest(),
        "registry_entry_count": len(registry_before["entries"]),
        "registry_bytes_unchanged": True,
        "spent_seed_overlap_count": 0,
        "formal_seed_reservation_count": 0,
        "handle_write_to_read_only_custody_transition": "PASS",
        "independent_path_reopen_hash_fileid_recompute": "PASS",
        "commit_last_audit_checksums_seal": "PASS",
        "rehearsal_activation": "PASS",
        "detached_evaluator_plumbing": "PASS",
        "all_child_processes_reaped": True,
        "no_r2_path_or_artifact_reuse": True,
        "path_budget_chars": MAX_PATH_BUDGET,
        "max_planned_path_chars": len(str(longest)),
        "max_planned_path": str(longest),
        "candidate_tuning_allowed": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    result = {
        **result_core,
        "result_semantic_sha256": semantic_sha256(result_core),
    }
    result_path = root / "R3_REHEARSAL_RESULT.json"
    atomic_write_new(result_path, canonical_pretty_bytes(result))
    print(
        json.dumps(
            {
                "status": result["status"],
                "result_path": result_path.relative_to(PROJECT_ROOT).as_posix(),
                "result_raw_sha256": _raw_sha256(result_path),
                "prediction_raw_sha256": result["prediction_raw_sha256"],
                "task_count": REHEARSAL_TASK_COUNT,
                "identity_count": REHEARSAL_IDENTITY_COUNT,
                "prediction_row_count": REHEARSAL_PREDICTION_ROW_COUNT,
                "registry_mutation_count": 0,
                "truth_open_count": 0,
                "score_open_count": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
