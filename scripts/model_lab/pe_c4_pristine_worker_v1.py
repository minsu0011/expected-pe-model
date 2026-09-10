"""Cold role worker for the C4 pristine confirmation."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
DESIGN_LOCK = PROJECT_ROOT / (
    "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json"
)
DESIGN_LOCK_SHA256 = "cae42b76858f72e0ad0690ccc49a761421b8c17665028a6eb8a498b6cac2f295"
INVENTORY_SHA256 = "6305758d1820bd00e7e23f121839d1fe6479b49ca2c54976c3a5d568a9c1ff77"
RUNTIME_SHA256 = {
    "v03": "747a4c997a0e844a5bbd9336fd9bb2867b04c1ba3bb9cf8bac4a1cb0dbfc5f6e",
    "v04": "6d8b846aeaef60c0020e1c8a846f4eee8bd8a0bebf98123c25ff5f25d3a6fc5d",
}
FRAME = struct.Struct(">QQ")
MAX_CHANNEL = 512 * 1024 * 1024


class WorkerError(RuntimeError):
    pass


def _bootstrap() -> None:
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)
    for name in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        os.environ[name] = "1"


def _task(ordinal: int):
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import tasks

    plan = tasks()
    if ordinal not in range(len(plan)):
        raise WorkerError("task ordinal differs")
    return plan[ordinal]


def _design():
    raw = DESIGN_LOCK.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DESIGN_LOCK_SHA256:
        raise WorkerError("public replay design lock differs")
    payload = json.loads(raw.decode("ascii"))
    inventory = payload["replay_inventory"]
    runtime = payload["child_runtime_reference"]
    if inventory.get("combined_sha256") != INVENTORY_SHA256 or any(
        runtime[name].get("combined_sha256") != expected
        for name, expected in RUNTIME_SHA256.items()
    ):
        raise WorkerError("replay source binding differs")
    return inventory, runtime


def _protected(args: argparse.Namespace) -> int:
    from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        canonical_csv_bytes,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.channel import (
        write_message,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        write_canonical_json_new,
        write_new,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import (
        PROTECTED_NAMES,
        PUBLIC_NAMES,
        SOURCE_ROWS,
    )

    task = _task(args.task_ordinal)
    channels: list[bytes] = []
    protected_hashes: list[dict[str, str]] = []
    public_hashes: list[dict[str, str]] = []
    for replay_pass, vault_arg in enumerate((args.pass_1_root, args.pass_2_root), 1):
        generated = generate_dgp(task.dgp_id, master_seed=task.data_seed)
        if (
            tuple(generated.public) != PUBLIC_NAMES
            or tuple(generated.evaluator_only) != PROTECTED_NAMES
        ):
            raise WorkerError("generator namespace differs")
        public_raw = {name: canonical_csv_bytes(generated.public[name]) for name in PUBLIC_NAMES}
        protected_raw = {
            name: canonical_csv_bytes(generated.evaluator_only[name]) for name in PROTECTED_NAMES
        }
        if any(len(generated.evaluator_only[name]) != SOURCE_ROWS for name in PROTECTED_NAMES):
            raise WorkerError("protected row geometry differs")
        task_root = Path(vault_arg).resolve(strict=True) / task.seed_alias / f"dgp_{task.dgp_id}"
        task_root.mkdir(parents=True, exist_ok=False)
        for name, raw in protected_raw.items():
            write_new(task_root / f"{name}.csv", raw)
        p_hash = {name: hashlib.sha256(raw).hexdigest() for name, raw in protected_raw.items()}
        u_hash = {name: hashlib.sha256(raw).hexdigest() for name, raw in public_raw.items()}
        write_canonical_json_new(
            task_root / "METADATA.json",
            {
                "status": "PASS_PROTECTED_GENERATION_PRETRUTH",
                "task": task.payload(),
                "replay_pass": replay_pass,
                "protected_raw_sha256": p_hash,
                "public_raw_sha256": u_hash,
                "fit_predict_or_score": False,
            },
        )
        stream = io.BytesIO()
        write_message(
            stream,
            {
                "schema_version": "expected_pe.c4_pristine.public_channel.v1",
                "task": task.payload(),
                "replay_pass": replay_pass,
                "protected_path_included": False,
                "protected_value_included": False,
            },
            public_raw,
        )
        channels.append(stream.getvalue())
        protected_hashes.append(p_hash)
        public_hashes.append(u_hash)
    if protected_hashes[0] != protected_hashes[1] or public_hashes[0] != public_hashes[1]:
        raise WorkerError("two-pass generator bytes differ")
    sys.stdout.buffer.write(FRAME.pack(len(channels[0]), len(channels[1])))
    sys.stdout.buffer.write(channels[0])
    sys.stdout.buffer.write(channels[1])
    sys.stdout.buffer.flush()
    return 0


def _read_channels() -> tuple[bytes, bytes]:
    raw = sys.stdin.buffer.read(MAX_CHANNEL + 1)
    if len(raw) <= FRAME.size or len(raw) > MAX_CHANNEL:
        raise WorkerError("public channel size differs")
    first, second = FRAME.unpack(raw[: FRAME.size])
    if first <= 0 or second <= 0 or FRAME.size + first + second != len(raw):
        raise WorkerError("public channel frame differs")
    split = FRAME.size + first
    return raw[FRAME.size : split], raw[split:]


def _replay_one(raw: bytes, task, replay_pass: int):
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.channel import (
        read_message,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.replay import (
        run_public_replay,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import PUBLIC_NAMES

    header, frames = read_message(io.BytesIO(raw))
    if (
        header.get("schema_version") != "expected_pe.c4_pristine.public_channel.v1"
        or header.get("task") != task.payload()
        or header.get("replay_pass") != replay_pass
        or header.get("protected_path_included") is not False
        or header.get("protected_value_included") is not False
        or tuple(frames) != PUBLIC_NAMES
    ):
        raise WorkerError("public channel header differs")
    import pandas as pd

    public = {
        name: pd.read_csv(io.BytesIO(frames[name]), float_precision="round_trip")
        for name in PUBLIC_NAMES
    }
    inventory, runtime = _design()
    replay = run_public_replay(public, expected_inventory=inventory, expected_child_runtime=runtime)
    return replay, {name: hashlib.sha256(frames[name]).hexdigest() for name in PUBLIC_NAMES}


def _public(args: argparse.Namespace) -> int:
    if any(name.startswith("research.model_zoo.dgp_exploration_v2") for name in sys.modules):
        raise WorkerError("protected generator imported by public role")
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        semantic_sha256,
        write_canonical_json_new,
        write_new,
    )

    task = _task(args.task_ordinal)
    first, second = _read_channels()
    replay_1, hashes_1 = _replay_one(first, task, 1)
    replay_2, hashes_2 = _replay_one(second, task, 2)
    if (
        hashes_1 != hashes_2
        or replay_1.canonical_raw != replay_2.canonical_raw
        or replay_1.overlay_raw != replay_2.overlay_raw
    ):
        raise WorkerError("two public replays differ")
    output = Path(args.output_root).resolve(strict=True)
    if any(output.iterdir()):
        raise WorkerError("public output task root is not empty")
    write_new(output / "canonical150.csv", replay_1.canonical_raw)
    write_new(output / "v04_overlay.csv", replay_1.overlay_raw)
    core = {
        "schema_version": "expected_pe.c4_pristine.public_task_manifest.v1",
        "status": "FROZEN_TWO_PASS_PUBLIC_REPLAY_PRETRUTH",
        "task": task.payload(),
        "canonical_raw_sha256": hashlib.sha256(replay_1.canonical_raw).hexdigest(),
        "overlay_raw_sha256": hashlib.sha256(replay_1.overlay_raw).hexdigest(),
        "public_source_raw_sha256": hashes_1,
        "canonical_replay_bytes_equal": True,
        "overlay_replay_bytes_equal": True,
        "protected_generator_imported": False,
        "truth_open_count": 0,
        "score_open_count": 0,
    }
    manifest = {**core, "semantic_sha256": semantic_sha256(core)}
    write_canonical_json_new(output / "PUBLIC_TASK_MANIFEST.json", manifest)
    print(json.dumps({"status": "PASS_PUBLIC_TWO_PASS", "task": task.payload()}))
    return 0


def _predict(args: argparse.Namespace) -> int:
    from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
        read_canonical_json,
        semantic_sha256,
        write_canonical_json_new,
        write_new,
    )
    from research.model_zoo.pe_c4_pristine_confirmation_v1.engine import (
        build_c4_surface,
        build_task_predictions,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        stable_read,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        canonical_csv_bytes,
    )

    task = _task(args.task_ordinal)
    public = Path(args.public_root).resolve(strict=True)
    manifest_path = public / "PUBLIC_TASK_MANIFEST.json"
    manifest = read_canonical_json(manifest_path)
    manifest_raw, manifest_ref = stable_read(
        manifest_path,
        relative_path=manifest_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    unsigned = dict(manifest)
    stored_semantic = unsigned.pop("semantic_sha256")
    if manifest.get("task") != task.payload() or stored_semantic != semantic_sha256(unsigned):
        raise WorkerError("public task manifest binding differs")
    canonical_raw = (public / "canonical150.csv").read_bytes()
    overlay_raw = (public / "v04_overlay.csv").read_bytes()
    if (
        hashlib.sha256(canonical_raw).hexdigest() != manifest["canonical_raw_sha256"]
        or hashlib.sha256(overlay_raw).hexdigest() != manifest["overlay_raw_sha256"]
    ):
        raise WorkerError("public task bytes changed")
    surface, receipt = build_c4_surface(
        canonical_raw,
        task=task,
        task_manifest_raw_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        task_manifest_semantic_sha256=str(stored_semantic),
        task_manifest_volume_serial_number=int(manifest_ref.volume_serial_number, 16),
        task_manifest_file_id_128=manifest_ref.file_id_128,
    )
    predictions = build_task_predictions(overlay_raw, surface, task=task)
    output = Path(args.output_root).resolve(strict=True)
    if any(output.iterdir()):
        raise WorkerError("prediction task root is not empty")
    surface_raw = canonical_csv_bytes(surface)
    prediction_raw = canonical_csv_bytes(predictions)
    write_new(output / "C4_SURFACE.csv", surface_raw)
    write_new(output / "PREDICTIONS.csv", prediction_raw)
    write_canonical_json_new(
        output / "PREDICTION_RECEIPT.json",
        {
            **receipt,
            "surface_raw_sha256": hashlib.sha256(surface_raw).hexdigest(),
            "prediction_raw_sha256": hashlib.sha256(prediction_raw).hexdigest(),
            "source_public_manifest_raw_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        },
    )
    print(json.dumps({"status": "PASS_C4_TASK_PREDICTION", "task": task.payload()}))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    protected = commands.add_parser("protected")
    protected.add_argument("--task-ordinal", type=int, required=True)
    protected.add_argument("--pass-1-root", required=True)
    protected.add_argument("--pass-2-root", required=True)
    public = commands.add_parser("public")
    public.add_argument("--task-ordinal", type=int, required=True)
    public.add_argument("--output-root", required=True)
    predict = commands.add_parser("predict")
    predict.add_argument("--task-ordinal", type=int, required=True)
    predict.add_argument("--public-root", required=True)
    predict.add_argument("--output-root", required=True)
    return root


def main() -> int:
    _bootstrap()
    args = parser().parse_args()
    if args.command == "protected":
        return _protected(args)
    if args.command == "public":
        return _public(args)
    if args.command == "predict":
        return _predict(args)
    raise WorkerError("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
