"""Cold, isolated roles for the score-free non-reserved R2 preflight."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
PREFLIGHT_DATA_SEED = 9_900_001
PREFLIGHT_DGP_ID = "A"
PREFLIGHT_SEED_ALIAS = "heldout_seed_01"
EXPECTED_PUBLIC_GEOMETRY = {
    "price": 1_800,
    "benchmark": 1_800,
    "eps_events": 29,
    "public_factors": 3_600,
    "corporate_actions": 0,
}
_FRAME = struct.Struct(">QQ")
_CPU_0_31_MASK = (1 << 32) - 1


class PreflightError(RuntimeError):
    """Fail-closed non-reserved preflight error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise PreflightError("preflight worker requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise PreflightError("Python environment controls are forbidden")
    if sys.pycache_prefix is None:
        raise PreflightError("preflight worker pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise PreflightError("preflight worker pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = str(path.resolve(strict=True))
        if resolved not in sys.path:
            sys.path.append(resolved)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(
        kernel32.GetCurrentProcess(), ctypes.c_size_t(_CPU_0_31_MASK)
    ):
        raise PreflightError("preflight worker CPU0-31 affinity assignment failed")
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )

    require_process_resources()


def _preflight_task() -> Any:
    """Create an exact nominal task without entering the heldout constructor."""

    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        HeldoutTask,
    )

    task = object.__new__(HeldoutTask)
    object.__setattr__(task, "task_ordinal", 0)
    object.__setattr__(task, "data_seed", PREFLIGHT_DATA_SEED)
    object.__setattr__(task, "seed_alias", PREFLIGHT_SEED_ALIAS)
    object.__setattr__(task, "estimator_rng_seed", PREFLIGHT_DATA_SEED)
    object.__setattr__(task, "estimator_rng_alias", PREFLIGHT_SEED_ALIAS)
    object.__setattr__(task, "dgp_id", PREFLIGHT_DGP_ID)
    return task


def _production_worker() -> Any:
    from scripts.model_lab.pe_four_model_fresh_heldout_authority_v1 import (
        heldout_role_worker,
    )

    heldout_role_worker._task = lambda ordinal: (  # noqa: SLF001
        _preflight_task()
        if ordinal == 0
        else (_ for _ in ()).throw(PreflightError("preflight ordinal differs"))
    )
    return heldout_role_worker


def _protected(args: argparse.Namespace) -> int:
    from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
        canonical_json_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.protected_generation import (
        generate_two_pass_task,
    )

    task = _preflight_task()
    pass_1_root = Path(args.pass_1_root).resolve(strict=True)
    pass_2_root = Path(args.pass_2_root).resolve(strict=True)
    if (
        pass_1_root.name != "pass_1"
        or pass_2_root.name != "pass_2"
        or pass_1_root.parent != pass_2_root.parent
    ):
        raise PreflightError("protected preflight pass roots differ")
    first = io.BytesIO()
    second = io.BytesIO()
    receipt = generate_two_pass_task(
        task=task,
        pass_1_root=pass_1_root,
        pass_2_root=pass_2_root,
        pass_1_stream=first,
        pass_2_stream=second,
        generator=generate_dgp,
        project_root=PROJECT_ROOT,
    )
    expected_task_leaves = {"METADATA.json", "latent_events.csv", "truth.csv"}
    task_roots = [
        root / f"seed_{PREFLIGHT_DATA_SEED}" / f"dgp_{PREFLIGHT_DGP_ID}"
        for root in (pass_1_root, pass_2_root)
    ]
    if any(
        {path.name for path in task_root.iterdir()} != expected_task_leaves
        for task_root in task_roots
    ):
        raise PreflightError("protected preflight final file universe differs")
    atomic_write_new(
        pass_1_root.parent / "PREFLIGHT_PROTECTED_FINALIZATION.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.four_model.r2_nonreserved_preflight.protected.v1",
                "status": "PASS_TWO_PASS_PROTECTED_FINALIZATION_NON_RESERVED",
                "test_seed": PREFLIGHT_DATA_SEED,
                "dgp_id": PREFLIGHT_DGP_ID,
                "protected_parity_equal": receipt["protected_parity_equal"],
                "protected_task_file_count": 6,
                "protected_values_exported": False,
                "protected_paths_exported": False,
                "truth_open_count_outside_protected_process": 0,
                "heldout_seed_invocation_count": 0,
            }
        ),
    )
    first_raw = first.getvalue()
    second_raw = second.getvalue()
    sys.stdout.buffer.write(_FRAME.pack(len(first_raw), len(second_raw)))
    sys.stdout.buffer.write(first_raw)
    sys.stdout.buffer.write(second_raw)
    sys.stdout.buffer.flush()
    return 0


def _public_replay(args: argparse.Namespace) -> int:
    worker = _production_worker()
    return worker._public_two_pass(  # noqa: SLF001
        SimpleNamespace(task_ordinal=0, public_task_root=args.public_task_root)
    )


def _numeric(args: argparse.Namespace, *, lane: str) -> int:
    worker = _production_worker()
    return worker._numeric_task(  # noqa: SLF001
        SimpleNamespace(
            task_ordinal=0,
            public_task_root=args.public_task_root,
            numeric_task_root=args.numeric_task_root,
            worker_slot=0,
        ),
        lane=lane,
    )


def _read_surface(root: Path, *, lane: str) -> tuple[bytes, Any]:
    import pandas as pd

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        BCE_TASK_SURFACE_COLUMNS,
        HOFS_TASK_SURFACE_COLUMNS,
    )

    leaf = "BCE_SURFACE.csv" if lane == "bce" else "C4_SURFACE.csv"
    raw = (root / leaf).resolve(strict=True).read_bytes()
    frame = pd.read_csv(io.BytesIO(raw), float_precision="round_trip")
    expected = BCE_TASK_SURFACE_COLUMNS if lane == "bce" else HOFS_TASK_SURFACE_COLUMNS
    if tuple(map(str, frame.columns)) != expected or canonical_csv_bytes(frame) != raw:
        raise PreflightError(f"preflight {lane} surface differs")
    return raw, frame


def _predict(args: argparse.Namespace) -> int:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        C1_ID,
        MODEL_IDS_IN_ORDER,
        SOURCE_MODEL_VERSIONS,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction import (
        build_task_prediction_rows,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.public_generation import (
        _require_no_protected_imports,
    )

    _require_no_protected_imports()
    public_root = Path(args.public_task_root).resolve(strict=True)
    bce_root = Path(args.bce_root).resolve(strict=True)
    c4_root = Path(args.c4_root).resolve(strict=True)
    expected_public = {
        "PUBLIC_REPLAY_RECEIPT.json",
        "PUBLIC_TASK_MANIFEST.json",
        "canonical150.csv",
        "v04_overlay.csv",
    }
    if {path.name for path in public_root.iterdir()} != expected_public:
        raise PreflightError("preflight public replay universe differs")
    public_receipt = json.loads(
        (public_root / "PUBLIC_REPLAY_RECEIPT.json").read_text(encoding="utf-8")
    )
    geometry = public_receipt.get("public_frame_rows")
    if geometry != EXPECTED_PUBLIC_GEOMETRY:
        raise PreflightError(f"preflight natural public geometry differs: {geometry}")
    bce_raw, bce = _read_surface(bce_root, lane="bce")
    c4_raw, c4 = _read_surface(c4_root, lane="c4")
    predictions = build_task_prediction_rows(
        bce,
        c4,
        source_versions=SOURCE_MODEL_VERSIONS,
    )
    if (
        len(bce) != 1_296
        or len(c4) != 1_296
        or len(predictions) != 5_184
        or predictions["pe_model_id"].eq(C1_ID).any()
        or tuple(predictions["pe_model_id"].drop_duplicates()) != MODEL_IDS_IN_ORDER
    ):
        raise PreflightError("preflight prediction plumbing geometry differs")
    publication_parent = Path(args.publication_parent).resolve(strict=True)
    staging = publication_parent / "staging"
    final = publication_parent / "final"
    if staging.exists() or final.exists():
        raise PreflightError("preflight publication identity already exists")
    staging.mkdir(exist_ok=False)
    inputs = {
        "BCE_RECEIPT.json": (bce_root / "BCE_RECEIPT.json").read_bytes(),
        "BCE_SURFACE.csv": bce_raw,
        "C4_RECEIPT.json": (c4_root / "C4_RECEIPT.json").read_bytes(),
        "C4_SURFACE.csv": c4_raw,
        "PREDICTIONS.csv": canonical_csv_bytes(predictions),
        "PUBLIC_REPLAY_RECEIPT.json": (
            public_root / "PUBLIC_REPLAY_RECEIPT.json"
        ).read_bytes(),
        "PUBLIC_TASK_MANIFEST.json": (
            public_root / "PUBLIC_TASK_MANIFEST.json"
        ).read_bytes(),
        "canonical150.csv": (public_root / "canonical150.csv").read_bytes(),
        "v04_overlay.csv": (public_root / "v04_overlay.csv").read_bytes(),
    }
    for leaf, raw in inputs.items():
        atomic_write_new(staging / leaf, raw)
    artifact_hashes = {
        leaf: hashlib.sha256(raw).hexdigest() for leaf, raw in inputs.items()
    }
    longest_path = max(
        [str(staging / leaf) for leaf in (*inputs, "PREFLIGHT_RECEIPT.json")]
        + [str(final / leaf) for leaf in (*inputs, "PREFLIGHT_RECEIPT.json")],
        key=len,
    )
    receipt = {
        "schema_version": "expected_pe.four_model.r2_nonreserved_full_process_preflight.v2",
        "status": "PASS_COLD_PUBLIC_REPLAY_NUMERIC_PREDICTION_ATOMIC_PUBLICATION",
        "test_seed": PREFLIGHT_DATA_SEED,
        "dgp_id": PREFLIGHT_DGP_ID,
        "raw_public_geometry": geometry,
        "protected_rows_contract": {"truth": 1_800, "latent_events": 1_800},
        "canonical_rows": 1_800,
        "overlay_rows": 1_800,
        "bce_surface_rows": len(bce),
        "c4_surface_rows": len(c4),
        "prediction_rows": len(predictions),
        "models_in_order": list(MODEL_IDS_IN_ORDER),
        "c1_prediction_rows": 0,
        "artifact_sha256": artifact_hashes,
        "max_publication_path_chars": len(longest_path),
        "max_publication_path": longest_path,
        "cold_process_roles": ["public_replay", "numeric_bce", "numeric_c4", "prediction"],
        "protected_generator_imported": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_access_count": 0,
        "atomic_publication": True,
    }
    atomic_write_new(staging / "PREFLIGHT_RECEIPT.json", canonical_pretty_bytes(receipt))
    os.replace(staging, final)
    if staging.exists() or not final.is_dir():
        raise PreflightError("preflight atomic publication finalization differs")
    _require_no_protected_imports()
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    protected = commands.add_parser("protected")
    protected.add_argument("--pass-1-root", required=True)
    protected.add_argument("--pass-2-root", required=True)
    public = commands.add_parser("public-replay")
    public.add_argument("--public-task-root", required=True)
    for name in ("numeric-bce", "numeric-c4"):
        numeric = commands.add_parser(name)
        numeric.add_argument("--public-task-root", required=True)
        numeric.add_argument("--numeric-task-root", required=True)
    prediction = commands.add_parser("prediction")
    prediction.add_argument("--public-task-root", required=True)
    prediction.add_argument("--bce-root", required=True)
    prediction.add_argument("--c4-root", required=True)
    prediction.add_argument("--publication-parent", required=True)
    return result


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    if arguments.command == "protected":
        return _protected(arguments)
    if arguments.command == "public-replay":
        return _public_replay(arguments)
    if arguments.command == "numeric-bce":
        return _numeric(arguments, lane="bce")
    if arguments.command == "numeric-c4":
        return _numeric(arguments, lane="c4")
    if arguments.command == "prediction":
        return _predict(arguments)
    raise PreflightError("preflight role differs")


if __name__ == "__main__":
    raise SystemExit(main())
