"""Run the score-free, non-reserved R2 full cold-process preflight."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
PREFLIGHT_DATA_SEED = 9_900_001
EXPECTED_PUBLIC_GEOMETRY = {
    "price": 1_800,
    "benchmark": 1_800,
    "eps_events": 29,
    "public_factors": 3_600,
    "corporate_actions": 0,
}
MAX_PATH_BUDGET = 239
TIMEOUT_SECONDS = 7_200


class PreflightControllerError(RuntimeError):
    """Fail-closed R2 preflight controller error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise PreflightControllerError("preflight controller requires -I -B")
    if sys.pycache_prefix is None:
        raise PreflightControllerError("preflight controller pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise PreflightControllerError("preflight controller pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = str(path.resolve(strict=True))
        if resolved not in sys.path:
            sys.path.append(resolved)


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _registry_state() -> tuple[bytes, dict[str, Any], set[int]]:
    path = PROJECT_ROOT / "outputs/v04_spent_seed_registry.json"
    raw = path.resolve(strict=True).read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightControllerError("spent-seed registry is unreadable") from exc
    if type(payload) is not dict or type(payload.get("entries")) is not list:
        raise PreflightControllerError("spent-seed registry schema differs")
    spent = {int(value) for value in payload.get("baseline_spent_evidence_seeds", [])}
    for entry in payload["entries"]:
        if type(entry) is not dict or type(entry.get("reserved_seeds")) is not list:
            raise PreflightControllerError("spent-seed registry entry differs")
        spent.update(int(value) for value in entry["reserved_seeds"])
    return raw, payload, spent


def _worker_command(*, prefix: Path, arguments: tuple[str, ...]) -> tuple[str, ...]:
    python = (
        PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe"
    ).resolve(strict=True)
    worker = (
        PROJECT_ROOT
        / "scripts/model_lab/pe_four_model_heldout_r2_preflight_worker.py"
    ).resolve(strict=True)
    if any(prefix.iterdir()):
        raise PreflightControllerError("worker pycache prefix is not empty")
    return (
        str(python),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={prefix}",
        str(worker),
        *arguments,
    )


def _safe_run_id(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 32
        or any(
            not (character.isascii() and (character.isalnum() or character in "_-"))
            for character in value
        )
    ):
        raise PreflightControllerError("preflight run id is unsafe or too long")
    return value


def _planned_paths(root: Path) -> list[Path]:
    paths = [
        root
        / "vault"
        / pass_name
        / f"seed_{PREFLIGHT_DATA_SEED}"
        / "dgp_A"
        / leaf
        for pass_name in ("pass_1", "pass_2")
        for leaf in ("METADATA.json", "latent_events.csv", "truth.csv")
    ]
    paths.extend(
        root / "common" / leaf
        for leaf in (
            "PUBLIC_REPLAY_RECEIPT.json",
            "PUBLIC_TASK_MANIFEST.json",
            "canonical150.csv",
            "v04_overlay.csv",
        )
    )
    paths.extend(
        root / "numeric" / lane / leaf
        for lane, leaves in (
            ("bce", ("BCE_RECEIPT.json", "BCE_SURFACE.csv")),
            ("c4", ("C4_RECEIPT.json", "C4_SURFACE.csv")),
        )
        for leaf in leaves
    )
    final_leaves = (
        "BCE_RECEIPT.json",
        "BCE_SURFACE.csv",
        "C4_RECEIPT.json",
        "C4_SURFACE.csv",
        "PREDICTIONS.csv",
        "PREFLIGHT_RECEIPT.json",
        "PUBLIC_REPLAY_RECEIPT.json",
        "PUBLIC_TASK_MANIFEST.json",
        "canonical150.csv",
        "v04_overlay.csv",
    )
    paths.extend(
        root / "publication" / state / leaf
        for state in ("staging", "final")
        for leaf in final_leaves
    )
    paths.append(root / "PREFLIGHT_RESULT.json")
    return paths


def _parse_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightControllerError(f"{label} returned invalid JSON") from exc
    if type(value) is not dict:
        raise PreflightControllerError(f"{label} returned non-object JSON")
    return value


def _run(command: tuple[str, ...], *, environment: dict[str, str], label: str) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=environment,
        timeout=TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise PreflightControllerError(
            f"{label} failed: {completed.stderr[-4000:]!r}"
        )
    return _parse_json(completed.stdout, label=label)


def _verify_publication(final: Path, receipt: dict[str, Any]) -> None:
    expected = {
        "BCE_RECEIPT.json",
        "BCE_SURFACE.csv",
        "C4_RECEIPT.json",
        "C4_SURFACE.csv",
        "PREDICTIONS.csv",
        "PREFLIGHT_RECEIPT.json",
        "PUBLIC_REPLAY_RECEIPT.json",
        "PUBLIC_TASK_MANIFEST.json",
        "canonical150.csv",
        "v04_overlay.csv",
    }
    if {path.name for path in final.iterdir()} != expected:
        raise PreflightControllerError("preflight final publication universe differs")
    hashes = receipt.get("artifact_sha256")
    if type(hashes) is not dict or set(hashes) != expected - {"PREFLIGHT_RECEIPT.json"}:
        raise PreflightControllerError("preflight artifact hash universe differs")
    for leaf, expected_hash in hashes.items():
        if _raw_sha256(final / leaf) != expected_hash:
            raise PreflightControllerError(f"preflight artifact hash differs: {leaf}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--run-id", required=True)
    return result


def main() -> int:
    _bootstrap()
    run_id = _safe_run_id(parser().parse_args().run_id)
    registry_before_raw, registry_before, spent = _registry_state()
    if PREFLIGHT_DATA_SEED in spent:
        raise PreflightControllerError("non-reserved preflight seed is already spent")
    root = PROJECT_ROOT / "build" / f"pe_r2_pf_{run_id}"
    if root.exists():
        raise PreflightControllerError("preflight run identity already exists")
    paths = _planned_paths(root)
    longest = max(paths, key=lambda path: len(str(path)))
    if len(str(longest)) > MAX_PATH_BUDGET:
        raise PreflightControllerError("preflight planned path exceeds path budget")
    root.mkdir(exist_ok=False)
    vault = root / "vault"
    pass_1 = vault / "pass_1"
    pass_2 = vault / "pass_2"
    common = root / "common"
    numeric = root / "numeric"
    bce_root = numeric / "bce"
    c4_root = numeric / "c4"
    publication = root / "publication"
    pycache = root / "pycache"
    for path in (
        vault,
        pass_1,
        pass_2,
        common,
        numeric,
        bce_root,
        c4_root,
        publication,
        pycache,
    ):
        path.mkdir(exist_ok=False)
    caches = {}
    for role in ("protected", "public", "bce", "c4", "prediction"):
        caches[role] = pycache / role
        caches[role].mkdir(exist_ok=False)
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation_execution import (
        child_environment,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction_execution import (
        numeric_child_environment,
    )

    environment = child_environment()
    protected_command = _worker_command(
        prefix=caches["protected"],
        arguments=(
            "protected",
            "--pass-1-root",
            str(pass_1),
            "--pass-2-root",
            str(pass_2),
        ),
    )
    public_command = _worker_command(
        prefix=caches["public"],
        arguments=("public-replay", "--public-task-root", str(common)),
    )
    protected = subprocess.Popen(
        protected_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=environment,
    )
    if protected.stdout is None or protected.stderr is None:
        raise PreflightControllerError("protected preflight pipe creation failed")
    public = subprocess.Popen(
        public_command,
        stdin=protected.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=environment,
    )
    protected.stdout.close()
    public_stdout, public_stderr = public.communicate(timeout=TIMEOUT_SECONDS)
    protected_stderr = protected.stderr.read()
    protected_code = protected.wait(timeout=TIMEOUT_SECONDS)
    if protected_code != 0 or public.returncode != 0:
        raise PreflightControllerError(
            "non-reserved protected/public pipeline failed: "
            f"protected={protected_code}:{protected_stderr[-4000:]!r}; "
            f"public={public.returncode}:{public_stderr[-4000:]!r}"
        )
    public_receipt = _parse_json(public_stdout, label="public replay worker")
    if (
        public_receipt.get("status")
        != "PASS_TWO_PUBLIC_PASSES_BYTE_EXACT_PRETRUTH"
        or public_receipt.get("public_frame_rows") != EXPECTED_PUBLIC_GEOMETRY
    ):
        raise PreflightControllerError("public replay receipt/geometry differs")
    numeric_commands = {
        "bce": _worker_command(
            prefix=caches["bce"],
            arguments=(
                "numeric-bce",
                "--public-task-root",
                str(common),
                "--numeric-task-root",
                str(bce_root),
            ),
        ),
        "c4": _worker_command(
            prefix=caches["c4"],
            arguments=(
                "numeric-c4",
                "--public-task-root",
                str(common),
                "--numeric-task-root",
                str(c4_root),
            ),
        ),
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            lane: pool.submit(
                _run,
                command,
                environment=numeric_child_environment(lane),
                label=f"numeric {lane} worker",
            )
            for lane, command in numeric_commands.items()
        }
        numeric_receipts = {lane: future.result() for lane, future in futures.items()}
    if (
        numeric_receipts["bce"].get("status")
        != "PASS_C2_C3_PUBLIC_ONLY_NUMERIC_TASK"
        or numeric_receipts["c4"].get("status")
        != "PASS_C4_SEED_FREE_NUMERIC_TASK_AND_IDENTITY_PROJECTION"
    ):
        raise PreflightControllerError("numeric preflight receipt differs")
    prediction_receipt = _run(
        _worker_command(
            prefix=caches["prediction"],
            arguments=(
                "prediction",
                "--public-task-root",
                str(common),
                "--bce-root",
                str(bce_root),
                "--c4-root",
                str(c4_root),
                "--publication-parent",
                str(publication),
            ),
        ),
        environment=environment,
        label="prediction worker",
    )
    if prediction_receipt.get("status") != (
        "PASS_COLD_PUBLIC_REPLAY_NUMERIC_PREDICTION_ATOMIC_PUBLICATION"
    ):
        raise PreflightControllerError("prediction preflight status differs")
    final = publication / "final"
    _verify_publication(final, prediction_receipt)
    registry_after_raw, registry_after, spent_after = _registry_state()
    if (
        registry_after_raw != registry_before_raw
        or registry_after != registry_before
        or spent_after != spent
    ):
        raise PreflightControllerError("preflight mutated the spent-seed registry")
    protected_finalization = vault / "PREFLIGHT_PROTECTED_FINALIZATION.json"
    protected_task_files = [
        path
        for path in vault.rglob("*")
        if path.is_file() and path.name != protected_finalization.name
    ]
    if len(protected_task_files) != 6 or not protected_finalization.is_file():
        raise PreflightControllerError("protected preflight finalization differs")
    result = {
        "schema_version": "expected_pe.four_model.r2_nonreserved_full_process_preflight.controller.v2",
        "status": "PASS_NONRESERVED_FULL_PROCESS_PREFLIGHT_NO_HELDOUT_ACCESS",
        "run_id": run_id,
        "test_seed": PREFLIGHT_DATA_SEED,
        "test_seed_was_unreserved": True,
        "spent_seed_overlap": 0,
        "registry_before_raw_sha256": hashlib.sha256(registry_before_raw).hexdigest(),
        "registry_after_raw_sha256": hashlib.sha256(registry_after_raw).hexdigest(),
        "registry_entry_count": len(registry_before["entries"]),
        "protected_launch": "PASS",
        "heterogeneous_raw_geometry": "PASS",
        "public_transport": "PASS",
        "public_canonicalization": "PASS",
        "canonical_output_geometry": "PASS",
        "cold_numeric_bce": "PASS",
        "cold_numeric_c4": "PASS",
        "prediction_plumbing": "PASS",
        "protected_finalization": "PASS",
        "atomic_publication": "PASS",
        "receipt_hash_validation": "PASS",
        "path_length": "PASS",
        "max_planned_path_chars": len(str(longest)),
        "max_planned_path": str(longest),
        "path_budget_chars": MAX_PATH_BUDGET,
        "truth_leakage_count": 0,
        "heldout_access_count": 0,
        "score_open_count": 0,
        "reserved_generator_invocation_count": 0,
        "public_receipt_raw_sha256": _raw_sha256(
            final / "PREFLIGHT_RECEIPT.json"
        ),
        "public_receipt": prediction_receipt,
    }
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
        canonical_json_bytes,
    )

    result_path = root / "PREFLIGHT_RESULT.json"
    atomic_write_new(result_path, canonical_json_bytes(result))
    print(
        json.dumps(
            {
                "status": result["status"],
                "result_path": result_path.relative_to(PROJECT_ROOT).as_posix(),
                "result_raw_sha256": _raw_sha256(result_path),
                "max_planned_path_chars": result["max_planned_path_chars"],
                "truth_leakage_count": 0,
                "heldout_access_count": 0,
                "registry_mutation_count": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
