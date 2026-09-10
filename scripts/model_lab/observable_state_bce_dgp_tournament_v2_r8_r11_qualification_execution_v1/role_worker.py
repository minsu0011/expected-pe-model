"""Isolated child dispatcher for the R8-r11 qualification-only execution identity."""

from __future__ import annotations

import argparse
import base64
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
    payload = json.loads((DESIGN_ROOT / "DESIGN_LOCK.json").read_text(encoding="ascii"))
    return payload["replay_inventory"], payload["child_runtime_reference"]


def _public_guard(root: Path) -> None:
    from scripts.model_lab.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.trusted_bootstrap import (  # noqa: E501
        PublicFilesystemGuard,
    )

    sys.addaudithook(PublicFilesystemGuard(public_root=root))


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
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.protected_role import (  # noqa: E501
            check_only,
        )

        check_only(nonce=args.nonce)
        return 0
    if command == "role-public-check":
        root = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r11_"
            "qualification_generation_check_only_probe"
        )
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.public_role import (  # noqa: E501
            check_only,
        )

        print(json.dumps(check_only(nonce=args.nonce), sort_keys=True, allow_nan=False))
        return 0
    if command == "role-public-finalize-check":
        root = PROJECT_ROOT / "outputs" / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r11_"
            "qualification_generation_check_only_probe"
        )
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.controller import (  # noqa: E501
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
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.protected_role import (  # noqa: E501
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
        _public_guard(root)
        _require_public_namespace()
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.public_role import (  # noqa: E501
            run_task,
        )

        inventory, runtime = _design()
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
        from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r11_qualification_execution_v1.controller import (  # noqa: E501
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
