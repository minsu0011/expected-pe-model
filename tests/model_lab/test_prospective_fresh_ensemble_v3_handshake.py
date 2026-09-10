from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable
import uuid

import pytest

from research.model_zoo.prospective_fresh_ensemble_v1.artifacts import (
    file_record,
    write_json_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v3.contracts import (
    LANE_ID,
    ProspectiveContractError,
    seal_payload,
)
from research.model_zoo.prospective_fresh_ensemble_v3.pid_handshake import (
    CAPABILITY_SCHEMA,
    CAPABILITY_SELF_FIELD,
    READY_CLAIM_SCHEMA,
    READY_CLAIM_SELF_FIELD,
    current_interpreter_evidence,
    handshake_artifact_paths,
    load_actual_child_capability,
    publish_child_ready_claim,
    spawn_actual_child_bound_worker,
    verify_child_ready_claim,
    wait_for_actual_child_capability,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PINNED_WORKER_PYTHON = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310" / "Scripts" / "python.exe"
).resolve()


def _reported_base_executable(worker_python: Path) -> Path:
    completed = subprocess.run(
        [
            str(worker_python),
            "-c",
            "import sys; print(sys._base_executable)",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return Path(completed.stdout.strip()).resolve(strict=True)


def _write_descriptor(
    tmp_path: Path,
    *,
    worker_python: Path | None = None,
    worker_base_python: Path | None = None,
) -> Path:
    launcher = Path(worker_python or sys.executable).resolve(strict=True)
    base_image = Path(
        worker_base_python or getattr(sys, "_base_executable", sys.executable)
    ).resolve(strict=True)
    evidence = current_interpreter_evidence()
    root = (tmp_path / "v3").resolve()
    root.mkdir()
    descriptor_path = root / "QUALIFICATION_STAGE_DESCRIPTOR.json"
    payload = seal_payload(
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "precommit_root": str(root),
            "runtime_root": str((root / "runtime" / "qualification").resolve()),
            "capability_policy": {
                "worker_python": str(launcher),
                "worker_python_sha256": file_record(launcher)["sha256"],
                "worker_base_python": str(base_image),
                "worker_base_python_sha256": file_record(base_image)["sha256"],
                "worker_prefix": evidence["sys_prefix"],
                "worker_base_prefix": evidence["sys_base_prefix"],
                "worker_python_version": evidence["python_version"],
            },
        },
        "descriptor_sha256",
    )
    write_json_exclusive(descriptor_path, payload)
    return descriptor_path


def _ready_payload(
    descriptor_path: Path,
    *,
    invocation_id: str,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[Path, dict[str, Any]]:
    paths = handshake_artifact_paths(
        descriptor_path,
        stage="qualification",
        kind="generate",
        invocation_id=invocation_id,
    )
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    payload: dict[str, Any] = {
        "format_version": 1,
        "schema": READY_CLAIM_SCHEMA,
        "lane_id": LANE_ID,
        "stage": "qualification",
        "kind": "generate",
        "invocation_id": invocation_id,
        "actual_child_pid": os.getpid(),
        "launcher_pid": os.getppid(),
        "created_at_utc": "2026-08-20T00:00:00+00:00",
        "ready_claim_path": str(paths.ready_claim),
        "capability_path": str(paths.capability),
        "stage_descriptor": file_record(descriptor_path),
        "stage_descriptor_sha256": descriptor["descriptor_sha256"],
        "interpreter": current_interpreter_evidence(),
    }
    if mutate is not None:
        mutate(payload)
    sealed = seal_payload(payload, READY_CLAIM_SELF_FIELD)
    write_json_exclusive(paths.ready_claim, sealed)
    return paths.ready_claim, sealed


@pytest.mark.skipif(
    os.name != "nt" or not PINNED_WORKER_PYTHON.is_file(),
    reason="requires the pinned Windows venv launcher",
)
def test_actual_pinned_windows_launcher_binds_actual_child_pid(tmp_path: Path) -> None:
    base_image = _reported_base_executable(PINNED_WORKER_PYTHON)
    descriptor_path = _write_descriptor(
        tmp_path,
        worker_python=PINNED_WORKER_PYTHON,
        worker_base_python=base_image,
    )
    result = spawn_actual_child_bound_worker(
        descriptor_path=descriptor_path,
        project_root=PROJECT_ROOT,
        stage="qualification",
        kind="generate",
        child_script=Path(__file__),
        bound_inputs_factory=lambda _descriptor, _stage, _kind: {},
    )

    assert result.returncode == 0
    assert result.launcher_pid != result.actual_child_pid
    capability = load_actual_child_capability(
        result.capability_path,
        descriptor_path=descriptor_path,
        expected_stage="qualification",
        expected_kind="generate",
        expected_invocation_id=result.invocation_id,
        expected_actual_child_pid=result.actual_child_pid,
        expected_launcher_pid=result.launcher_pid,
    )
    assert capability.payload["authorized_pid"] == result.actual_child_pid
    assert capability.payload["launcher_pid"] == result.launcher_pid
    assert capability.ready_claim.payload["actual_child_pid"] != capability.ready_claim.payload[
        "launcher_pid"
    ]
    assert capability.ready_claim.payload["interpreter"]["sys_executable"]["path"] == str(
        PINNED_WORKER_PYTHON
    )
    assert capability.ready_claim.payload["interpreter"]["sys_base_executable"][
        "path"
    ] == str(base_image)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.__setitem__("actual_child_pid", os.getpid() + 100_000),
        lambda payload: payload.__setitem__("launcher_pid", os.getppid() + 100_000),
        lambda payload: payload.__setitem__("ready_claim_path", str(Path("wrong-ready"))),
        lambda payload: payload.__setitem__("capability_path", str(Path("wrong-cap"))),
        lambda payload: payload.__setitem__("stage", "heldout"),
        lambda payload: payload.__setitem__("kind", "predict"),
        lambda payload: payload.__setitem__("invocation_id", "f" * 32),
    ],
    ids=(
        "wrong-actual-pid",
        "wrong-parent-pid",
        "wrong-ready-path",
        "wrong-capability-path",
        "wrong-stage",
        "wrong-kind",
        "wrong-invocation",
    ),
)
def test_ready_claim_rejects_identity_swaps(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    descriptor_path = _write_descriptor(tmp_path)
    invocation_id = uuid.uuid4().hex
    ready_path, _payload = _ready_payload(
        descriptor_path, invocation_id=invocation_id, mutate=mutation
    )
    with pytest.raises(ProspectiveContractError, match="binding failed"):
        verify_child_ready_claim(
            ready_path,
            descriptor_path=descriptor_path,
            expected_stage="qualification",
            expected_kind="generate",
            expected_invocation_id=invocation_id,
            expected_launcher_pid=os.getppid(),
            expected_actual_child_pid=os.getpid(),
            require_current_runtime=True,
        )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("authorized_pid", lambda: os.getpid() + 100_000),
        ("launcher_pid", lambda: os.getppid() + 100_000),
        ("stage", lambda: "heldout"),
        ("kind", lambda: "evaluate"),
        ("invocation_id", lambda: "e" * 32),
        ("capability_path", lambda: str(Path("wrong-capability"))),
    ],
    ids=(
        "wrong-actual-pid",
        "wrong-parent-pid",
        "wrong-stage",
        "wrong-kind",
        "wrong-invocation",
        "wrong-path",
    ),
)
def test_child_capability_load_rejects_identity_swaps(
    tmp_path: Path, field: str, replacement: Callable[[], Any]
) -> None:
    descriptor_path = _write_descriptor(tmp_path)
    invocation_id = uuid.uuid4().hex
    ready_path, ready_payload = _ready_payload(
        descriptor_path, invocation_id=invocation_id
    )
    paths = handshake_artifact_paths(
        descriptor_path,
        stage="qualification",
        kind="generate",
        invocation_id=invocation_id,
    )
    payload: dict[str, Any] = {
        "format_version": 1,
        "schema": CAPABILITY_SCHEMA,
        "lane_id": LANE_ID,
        "stage": "qualification",
        "kind": "generate",
        "invocation_id": invocation_id,
        "authorized_pid": os.getpid(),
        "launcher_pid": os.getppid(),
        "issued_at_utc": "2026-08-20T00:00:00+00:00",
        "ready_claim": file_record(ready_path),
        "stage_descriptor": dict(ready_payload["stage_descriptor"]),
        "bound_inputs": {},
        "capability_path": str(paths.capability),
    }
    payload[field] = replacement()
    write_json_exclusive(
        paths.capability, seal_payload(payload, CAPABILITY_SELF_FIELD)
    )
    with pytest.raises(ProspectiveContractError, match="binding failed"):
        load_actual_child_capability(
            paths.capability,
            descriptor_path=descriptor_path,
            expected_stage="qualification",
            expected_kind="generate",
            expected_invocation_id=invocation_id,
            expected_actual_child_pid=os.getpid(),
            expected_launcher_pid=os.getppid(),
            require_current_runtime=True,
        )


@pytest.mark.skipif(
    os.name != "nt" or not PINNED_WORKER_PYTHON.is_file(),
    reason="requires the pinned Windows venv launcher",
)
def test_parent_rejects_launcher_exit_before_ready(tmp_path: Path) -> None:
    descriptor_path = _write_descriptor(
        tmp_path,
        worker_python=PINNED_WORKER_PYTHON,
        worker_base_python=_reported_base_executable(PINNED_WORKER_PYTHON),
    )
    with pytest.raises(ProspectiveContractError, match="exited before ready"):
        spawn_actual_child_bound_worker(
            descriptor_path=descriptor_path,
            project_root=PROJECT_ROOT,
            stage="qualification",
            kind="generate",
            child_script=Path(__file__),
            bound_inputs_factory=lambda _descriptor, _stage, _kind: {},
            child_extra_args=("--exit-before-ready",),
        )


def _child_main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("_child",))
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--invocation-id", required=True)
    parser.add_argument("--stage", choices=("qualification", "heldout"), required=True)
    parser.add_argument(
        "--worker-kind", choices=("generate", "predict", "evaluate"), required=True
    )
    parser.add_argument("--exit-before-ready", action="store_true")
    arguments = parser.parse_args()
    if arguments.exit_before_ready:
        return 19
    publish_child_ready_claim(
        descriptor_path=arguments.descriptor,
        stage=arguments.stage,
        kind=arguments.worker_kind,
        invocation_id=arguments.invocation_id,
    )
    wait_for_actual_child_capability(
        descriptor_path=arguments.descriptor,
        stage=arguments.stage,
        kind=arguments.worker_kind,
        invocation_id=arguments.invocation_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_child_main())
