"""Isolated child dispatcher for the R8-r14 qualification-only execution identity."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
SITE_PACKAGES = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Lib\site-packages"
)
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r8_"
    "qualification_generation_design_source_freeze_v1_no_go_20260822"
)
V3_DESIGN_LOCK = PROJECT_ROOT / (
    "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json"
)
V3_DESIGN_LOCK_RAW_SHA256 = (
    "cae42b76858f72e0ad0690ccc49a761421b8c17665028a6eb8a498b6cac2f295"
)
V3_REPLAY_INVENTORY_COMBINED_SHA256 = (
    "6305758d1820bd00e7e23f121839d1fe6479b49ca2c54976c3a5d568a9c1ff77"
)
V3_CHILD_RUNTIME_COMBINED_SHA256 = {
    "v03": "747a4c997a0e844a5bbd9336fd9bb2867b04c1ba3bb9cf8bac4a1cb0dbfc5f6e",
    "v04": "6d8b846aeaef60c0020e1c8a846f4eee8bd8a0bebf98123c25ff5f25d3a6fc5d",
}
REQUIRED_ENVIRONMENT = {
    "CUDA_VISIBLE_DEVICES": "-1",
    "MKL_NUM_THREADS": "1",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "NUMEXPR_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
}


class WorkerError(RuntimeError):
    """Fail-closed child-dispatch error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise WorkerError("worker requires -I -S -B isolation")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise WorkerError("Python environment controls are forbidden")
    for name, value in REQUIRED_ENVIRONMENT.items():
        if os.environ.get(name) != value:
            raise WorkerError(f"resource environment drifted: {name}")
    if sys.pycache_prefix is None:
        raise WorkerError("held pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise WorkerError("held pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = path.resolve(strict=True)
        if str(resolved) not in sys.path:
            sys.path.append(str(resolved))


def _mapping(encoded: str, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(base64.b64decode(encoded, validate=True).decode("ascii"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError(f"{label} is invalid") from exc
    if type(value) is not dict:
        raise WorkerError(f"{label} must be one object")
    return value


def _design() -> tuple[dict[str, Any], dict[str, Any]]:
    raw = V3_DESIGN_LOCK.resolve(strict=True).read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_DESIGN_LOCK_RAW_SHA256:
        raise WorkerError("V3 replay design lock bytes drifted")
    try:
        payload = json.loads(raw.decode("ascii"))
        inventory = payload["replay_inventory"]
        runtime = payload["child_runtime_reference"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise WorkerError("V3 replay design lock schema drifted") from exc
    if (
        not isinstance(inventory, dict)
        or inventory.get("combined_sha256") != V3_REPLAY_INVENTORY_COMBINED_SHA256
        or not isinstance(runtime, dict)
        or set(runtime) != {"v03", "v04"}
        or any(
            not isinstance(runtime[name], dict)
            or runtime[name].get("combined_sha256") != expected
            for name, expected in V3_CHILD_RUNTIME_COMBINED_SHA256.items()
        )
    ):
        raise WorkerError("V3 replay inventory/runtime binding drifted")
    return inventory, runtime


def _public_guard(root: Path) -> None:
    from scripts.model_lab.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.trusted_bootstrap import (  # noqa: E501
        PublicFilesystemGuard,
    )

    comparator_archive = (
        PROJECT_ROOT.parent / "pe-regime-v03-source.zip"
    ).resolve(strict=True)
    pinned_python = (SITE_PACKAGES.parents[1] / "Scripts/python.exe").resolve(strict=True)

    class QualificationPublicFilesystemGuard(PublicFilesystemGuard):
        """Add read-only access to the one exact, inventory-pinned V03 archive."""

        def _allowed(self, candidate: Path, *, write: bool) -> bool:
            resolved = candidate.resolve(strict=False)
            if resolved in {comparator_archive, pinned_python}:
                return not write
            return super()._allowed(candidate, write=write)

    sys.addaudithook(QualificationPublicFilesystemGuard(public_root=root))


def _require_public_namespace() -> None:
    forbidden = [
        name
        for name in sys.modules
        if name.startswith(("research.model_zoo.dgp_exploration_v2", "research.model_zoo.dgp_suite"))
        or name.endswith(".protected_role")
    ]
    if forbidden:
        raise WorkerError("public process imported protected namespace")


def dispatch(args: argparse.Namespace) -> int:
    command = args.command
    if command == "role-protected-check":
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.protected_role import (  # noqa: E501
            check_only,
        )

        check_only(nonce=args.nonce)
        return 0
    if command == "role-public-check":
        root = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r14_"
            "qualification_generation_check_only_probe"
        )
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.public_role import (  # noqa: E501
            check_only,
        )

        print(json.dumps(check_only(nonce=args.nonce), sort_keys=True, allow_nan=False))
        return 0
    if command == "role-public-finalize-check":
        root = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r14_"
            "qualification_generation_check_only_probe"
        )
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.controller import (  # noqa: E501
            validate_planned_public_path,
        )

        receipt = validate_planned_public_path(root, outputs_root=PROJECT_ROOT / "outputs")
        print(
            json.dumps(
                {
                    "status": "PASS_PUBLIC_FINALIZER_IMPORTED_NO_PAYLOAD",
                    "planned_public": receipt,
                    "artifact_open_count": 0,
                    "protected_import_present": False,
                },
                sort_keys=True,
                allow_nan=False,
            )
        )
        return 0
    if command == "role-protected-generate":
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.protected_role import (  # noqa: E501
            generate_task,
        )

        first = (
            None
            if args.first_protected_hashes_base64 is None
            else _mapping(args.first_protected_hashes_base64, label="first protected hashes")
        )
        generate_task(
            seed=args.seed,
            dgp=args.dgp,
            replay_pass=args.replay_pass,
            vault_pass_root=Path(args.vault_pass_root),
            expected_first_protected_hashes=first,
        )
        return 0
    if command == "role-public-run":
        root = Path(args.public_task_root)
        # Verify and materialize the exact non-secret replay authority before
        # the output-tree guard is installed. The guard intentionally denies
        # every outputs/ subtree except the static R8-r8 design and this task
        # root, whereas the executable V3 replay lock lives in its own sealed
        # outputs/ root. No task/public bytes have been read at this point.
        inventory, runtime = _design()
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.public_role import (  # noqa: E501
            run_task,
        )

        receipt = run_task(
            seed=args.seed,
            dgp=args.dgp,
            replay_pass=args.replay_pass,
            task_root=root,
            expected_inventory=inventory,
            expected_child_runtime=runtime,
        )
        _require_public_namespace()
        print(json.dumps(receipt, sort_keys=True, allow_nan=False))
        return 0
    if command == "role-public-finalize":
        root = Path(args.public_staging)
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1.controller import (  # noqa: E501
            finalize_public_staging,
        )

        receipt = finalize_public_staging(
            staging=root,
            protected_metadata=_mapping(args.opaque_metadata_base64, label="protected metadata"),
            design_checksums_raw_sha256=args.design_checksums_raw_sha256,
            source_lock_raw_sha256=args.source_lock_raw_sha256,
            runtime_lock_semantic_sha256=args.runtime_lock_semantic_sha256,
        )
        _require_public_namespace()
        print(json.dumps(receipt, sort_keys=True, allow_nan=False))
        return 0
    raise WorkerError("unsupported worker command")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    protected_check = sub.add_parser("role-protected-check")
    protected_check.add_argument("--nonce", required=True)
    public_check = sub.add_parser("role-public-check")
    public_check.add_argument("--nonce", required=True)
    finalizer_check = sub.add_parser("role-public-finalize-check")
    finalizer_check.add_argument("--nonce", required=True)
    protected = sub.add_parser("role-protected-generate")
    protected.add_argument("--seed", type=int, required=True)
    protected.add_argument("--dgp", required=True)
    protected.add_argument("--replay-pass", type=int, required=True)
    protected.add_argument("--vault-pass-root", required=True)
    protected.add_argument("--first-protected-hashes-base64")
    public = sub.add_parser("role-public-run")
    public.add_argument("--seed", type=int, required=True)
    public.add_argument("--dgp", required=True)
    public.add_argument("--replay-pass", type=int, required=True)
    public.add_argument("--public-task-root", required=True)
    public.add_argument("--design-checksums-raw-sha256", required=True)
    finalizer = sub.add_parser("role-public-finalize")
    finalizer.add_argument("--public-staging", required=True)
    finalizer.add_argument("--opaque-metadata-base64", required=True)
    finalizer.add_argument("--design-checksums-raw-sha256", required=True)
    finalizer.add_argument("--source-lock-raw-sha256", required=True)
    finalizer.add_argument("--runtime-lock-semantic-sha256", required=True)
    return root


def main() -> int:
    _bootstrap()
    return dispatch(parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
