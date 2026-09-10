from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from research.model_zoo.prospective_fresh_ensemble_v5.contracts import (
    DESCRIPTOR_SELF_FIELD,
    V5ContractError,
    authority_descriptor_path,
    heldout_runtime_root,
    seal_payload,
    write_json_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v5.descriptor import (
    build_probe_descriptor,
    verify_probe_descriptor,
    write_probe_descriptor,
)
from research.model_zoo.prospective_fresh_ensemble_v5.pid_handshake import (
    spawn_no_model_probe,
    verify_capability,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PINNED_WORKER_PYTHON = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310" / "Scripts" / "python.exe"
).resolve()
CHILD_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "model_lab"
    / "prospective_fresh_ensemble_v5"
    / "handshake_probe.py"
).resolve()


def _write_mutated_descriptor(
    tmp_path: Path,
    mutate: callable,  # type: ignore[type-arg]
    *,
    destination: Path | None = None,
) -> tuple[Path, Path]:
    root = (tmp_path / "v5_authority").resolve()
    root.mkdir()
    payload = build_probe_descriptor(root, PINNED_WORKER_PYTHON)
    payload.pop(DESCRIPTOR_SELF_FIELD)
    mutate(payload, root)
    sealed = seal_payload(payload, DESCRIPTOR_SELF_FIELD)
    target = destination or authority_descriptor_path(root)
    write_json_exclusive(target, sealed)
    return root, target


@pytest.mark.skipif(
    os.name != "nt" or not PINNED_WORKER_PYTHON.is_file(),
    reason="requires the pinned Windows venv launcher",
)
def test_pinned_windows_heldout_descriptor_to_handshake_roundtrip_no_model(
    tmp_path: Path,
) -> None:
    root = (tmp_path / "v5_authority").resolve()
    descriptor = write_probe_descriptor(root, PINNED_WORKER_PYTHON)
    result = spawn_no_model_probe(
        descriptor_path=descriptor,
        project_root=PROJECT_ROOT,
        child_script=CHILD_SCRIPT,
    )

    assert result.returncode == 0
    assert result.descriptor_path == authority_descriptor_path(root)
    assert result.descriptor_path.parent == root
    assert result.runtime_root == heldout_runtime_root(root)
    assert result.descriptor_path.parent != result.runtime_root
    assert result.launcher_pid != result.actual_child_pid
    assert result.ready_claim_path.is_relative_to(result.runtime_root)
    assert result.capability_path.is_relative_to(result.runtime_root)

    capability = verify_capability(
        result.capability_path,
        descriptor_path=result.descriptor_path,
        invocation_id=result.invocation_id,
        expected_actual_child_pid=result.actual_child_pid,
        expected_launcher_pid=result.launcher_pid,
    )
    assert capability.payload["bound_inputs"] == {}
    assert capability.payload["execution_authority"] is False
    assert capability.payload["model_operations_authorized"] is False


@pytest.mark.skipif(
    not PINNED_WORKER_PYTHON.is_file(), reason="requires pinned worker interpreter"
)
def test_v4_style_descriptor_inside_runtime_root_is_rejected(tmp_path: Path) -> None:
    root = (tmp_path / "v5_authority").resolve()
    root.mkdir()
    runtime_descriptor = heldout_runtime_root(root) / "HELDOUT_STAGE_DESCRIPTOR.json"
    payload = build_probe_descriptor(root, PINNED_WORKER_PYTHON)
    payload.pop(DESCRIPTOR_SELF_FIELD)
    payload["descriptor_path"] = str(runtime_descriptor)
    write_json_exclusive(
        runtime_descriptor, seal_payload(payload, DESCRIPTOR_SELF_FIELD)
    )
    with pytest.raises(V5ContractError, match="root-level authority artifact"):
        verify_probe_descriptor(runtime_descriptor, expected_authority_root=root)


@pytest.mark.skipif(
    not PINNED_WORKER_PYTHON.is_file(), reason="requires pinned worker interpreter"
)
@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda payload, root: payload.__setitem__("runtime_root", str(root)),
            "runtime root substitution",
        ),
        (
            lambda payload, root: payload.__setitem__(
                "runtime_root", str((root / "runtime" / "sibling").resolve())
            ),
            "runtime root substitution",
        ),
        (
            lambda payload, _root: payload["path_policy"].__setitem__(
                "descriptor_outside_runtime_root", False
            ),
            "path policy changed",
        ),
        (
            lambda payload, _root: payload["capability_policy"].__setitem__(
                "execution_authority", True
            ),
            "no-model capability policy changed",
        ),
        (
            lambda payload, _root: payload.__setitem__(
                "model_operations_authorized", True
            ),
            "descriptor identity changed",
        ),
    ],
    ids=(
        "runtime-equals-authority-root",
        "runtime-sibling-substitution",
        "path-policy-downgrade",
        "capability-authority-escalation",
        "model-authority-escalation",
    ),
)
def test_descriptor_adversarial_mutations_fail_closed(
    tmp_path: Path, mutation: callable, match: str  # type: ignore[type-arg]
) -> None:
    root, descriptor = _write_mutated_descriptor(tmp_path, mutation)
    with pytest.raises(V5ContractError, match=match):
        verify_probe_descriptor(descriptor, expected_authority_root=root)


@pytest.mark.skipif(
    not PINNED_WORKER_PYTHON.is_file(), reason="requires pinned worker interpreter"
)
def test_descriptor_byte_tamper_breaks_seal(tmp_path: Path) -> None:
    root = (tmp_path / "v5_authority").resolve()
    descriptor = write_probe_descriptor(root, PINNED_WORKER_PYTHON)
    payload = json.loads(descriptor.read_text(encoding="utf-8"))
    payload["purpose"] = "TAMPERED"
    descriptor.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(V5ContractError, match="descriptor_sha256 mismatch"):
        verify_probe_descriptor(descriptor, expected_authority_root=root)
