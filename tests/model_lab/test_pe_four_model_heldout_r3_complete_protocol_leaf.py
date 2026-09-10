from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

import pytest

from scripts.model_lab import pe_four_model_heldout_r3_complete_protocol_leaf as leaf


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _semantic(value: object) -> str:
    return _sha(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    )


def _pretty(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _registry_lf(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _write(project: Path, relative: str, raw: bytes) -> Path:
    path = project / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


@dataclass
class SyntheticLane:
    project: Path
    expected: leaf.ExpectedState
    runtime: leaf.RuntimeBindings
    authority_path: Path
    authority_raw_sha256: str
    registry_raw: bytes
    tool_path: Path
    test_path: Path


def _make_lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SyntheticLane:
    project = (tmp_path / "repo").resolve()
    project.mkdir()
    expected = replace(
        leaf.FORMAL,
        run_id="r3_synthetic",
        authority_relative_path="build/completion_authority.json",
        tool_relative_path="scripts/model_lab/completion.py",
        test_relative_path="tests/model_lab/test_completion.py",
        execution_gate_relative_path="build/execution_gate.json",
        apply_forensic_relative_path="build/apply_forensic.json",
        independent_audit_relative_path="build/independent_audit.json",
        precommit_relative_path="build/precommit.json",
        terminal_relative_path="outputs/terminal/TERMINAL_FAILURE.json",
        rehearsal_relative_path="build/rehearsal/R3_REHEARSAL_RESULT.json",
        registry_relative_path="outputs/registry.json",
        registry_lock_relative_path="outputs/registry.json.lock",
        registry_temp_glob=".registry.json.*.tmp",
        output_root_relative_path="outputs/reservation_r3_synthetic",
        registry_entry_count=1,
        globally_spent_seed_count=10,
        predecessor_entry_count=0,
        reservation_sequence=1,
        predecessor_raw_sha256="1" * 64,
        predecessor_self_sha256="2" * 64,
        predecessor_last_entry_sha256="3" * 64,
        reservation_created_at_utc="2026-08-24T00:00:00+00:00",
    )
    tool_path = _write(project, expected.tool_relative_path, b"synthetic tool\n")
    test_path = _write(project, expected.test_relative_path, b"synthetic test\n")
    monkeypatch.setattr(leaf, "__file__", str(tool_path))
    output_root = project / expected.output_root_relative_path
    output_root.mkdir(parents=True)

    source_hash = _semantic({"synthetic_source": 1})
    formula_lock = {"formula": "locked"}
    model_ids = ("m1", "m2", "m3", "m4")
    survivor_ids = model_ids
    versions = {model_id: "v1" for model_id in model_ids}
    generation = {
        "heldout_seeds_in_order": list(expected.heldout_seeds),
        "estimator_rng_seeds_in_order": list(expected.heldout_seeds),
        "task_count": 50,
        "identity_count": 64_800,
        "prediction_row_count": 259_200,
        "plan_semantic_sha256": "4" * 64,
    }
    candidate_config = {
        "model_ids_in_order": list(model_ids),
        "survivor_ids_in_qualification_rank_order": list(survivor_ids),
        "source_model_versions": versions,
        "formula_lock": formula_lock,
        "formula_lock_semantic_sha256": _semantic(formula_lock),
        "generation_plan": generation,
    }
    candidate_hash = _semantic(candidate_config)
    policy_hash = _semantic({"synthetic_policy": 1})
    expected = replace(
        expected,
        source_config_sha256=source_hash,
        candidate_config_sha256=candidate_hash,
        reservation_policy_config_sha256=policy_hash,
    )

    def canonical_output_root(path: Path) -> str:
        return os.path.normcase(str(path.resolve()))

    contract = {
        "format_version": 1,
        "registry_id": "synthetic-registry",
        "owner_output_root": canonical_output_root(output_root),
        "source_config_sha256": source_hash,
        "candidates_sha256": candidate_hash,
        "policy_config_sha256": policy_hash,
        "tuning_seeds": list(expected.quarantine_seeds),
        "locked_seeds": list(expected.heldout_seeds),
        "reserved_seeds": sorted((*expected.quarantine_seeds, *expected.heldout_seeds)),
    }
    reservation_id = _semantic(contract)
    unsigned_entry = {
        **contract,
        "sequence": 1,
        "previous_entry_sha256": expected.predecessor_last_entry_sha256,
        "reservation_id": reservation_id,
        "created_at_utc": expected.reservation_created_at_utc,
    }
    entry = {**unsigned_entry, "entry_sha256": _semantic(unsigned_entry)}
    unsigned_registry = {
        "format_version": 1,
        "registry_id": "synthetic-registry",
        "genesis_sha256": "5" * 64,
        "entries": [entry],
        "updated_at_utc": "2026-08-24T00:00:01+00:00",
    }
    registry = {
        **unsigned_registry,
        "registry_sha256": _semantic(unsigned_registry),
    }
    registry_lf = _registry_lf(registry)
    registry_raw = registry_lf.replace(b"\n", b"\r\n")
    _write(project, expected.registry_relative_path, registry_raw)
    expected = replace(
        expected,
        registry_raw_sha256=_sha(registry_raw),
        registry_size_bytes=len(registry_raw),
        registry_self_sha256=registry["registry_sha256"],
        registry_lf_raw_sha256=_sha(registry_lf),
        registry_lf_size_bytes=len(registry_lf),
        registry_crlf_count=registry_raw.count(b"\r\n"),
        registry_bare_lf_count=0,
        maximum_reserved_seed=max(contract["reserved_seeds"]),
        reservation_entry_sha256=entry["entry_sha256"],
        reservation_id=reservation_id,
    )

    def verify_registry(value: Mapping[str, Any]) -> None:
        unsigned = dict(value)
        stored = unsigned.pop("registry_sha256")
        if stored != _semantic(unsigned):
            raise ValueError("registry self seal")
        previous = expected.predecessor_last_entry_sha256
        for index, row in enumerate(value["entries"], start=1):
            unsigned_row = dict(row)
            stored_row = unsigned_row.pop("entry_sha256")
            if (
                stored_row != _semantic(unsigned_row)
                or row["sequence"] != index
                or row["previous_entry_sha256"] != previous
            ):
                raise ValueError("entry chain")
            previous = stored_row

    def read_registry(path: Path) -> Mapping[str, Any]:
        value = json.loads(path.read_bytes().decode("utf-8"))
        verify_registry(value)
        return value

    contract_fields = set(contract)

    def reservation_contract_from_entry(row: Mapping[str, Any]) -> Mapping[str, Any]:
        return {field: row[field] for field in contract_fields}

    def build_protocol_lock(
        *, run_id: str, r2_protocol_binding: Mapping[str, object]
    ) -> Mapping[str, object]:
        core = {
            "schema_version": expected.protocol_schema,
            "status": expected.protocol_status,
            "run_id": run_id,
            "r2_protocol_binding": dict(r2_protocol_binding),
            "r2_protocol_binding_semantic_sha256": _semantic(r2_protocol_binding),
        }
        return {**core, "policy_lock_sha256": _semantic(core)}

    def validate_protocol_lock(
        value: Mapping[str, object],
        *,
        expected_run_id: str,
        project_root: Path | None = None,
        expected_lock_relative_path: str | None = None,
    ) -> Mapping[str, object]:
        del project_root, expected_lock_relative_path
        unsigned = dict(value)
        stored = unsigned.pop("policy_lock_sha256")
        if (
            value.get("run_id") != expected_run_id
            or stored != _semantic(unsigned)
            or value.get("r2_protocol_binding_semantic_sha256")
            != _semantic(value["r2_protocol_binding"])
        ):
            raise ValueError("protocol")
        return dict(value)

    def read_protocol_lock(
        path: Path,
        *,
        project_root: Path,
        expected_run_id: str,
        expected_raw_sha256: str,
    ) -> Mapping[str, object]:
        del project_root
        raw = path.read_bytes()
        if _sha(raw) != expected_raw_sha256:
            raise ValueError("protocol raw")
        value = json.loads(raw.decode("utf-8"))
        if _pretty(value) != raw:
            raise ValueError("protocol canonical")
        return validate_protocol_lock(value, expected_run_id=expected_run_id)

    source_manifest = {"source_manifest_semantic_sha256": source_hash}
    runtime = leaf.RuntimeBindings(
        canonical_pretty_bytes=_pretty,
        semantic_sha256=_semantic,
        safe_run_id=lambda value: str(value),
        build_protocol_lock=build_protocol_lock,
        validate_protocol_lock=validate_protocol_lock,
        read_protocol_lock=read_protocol_lock,
        verify_live_protocol_evidence=lambda project, protocol: None,
        read_registry=read_registry,
        verify_registry=verify_registry,
        reservation_contract_from_entry=reservation_contract_from_entry,
        reservation_id=_semantic,
        canonical_output_root=canonical_output_root,
        registry_jsonable=lambda value: value,
        baseline_spent_seeds=(),
        registry_format_version=1,
        registry_id="synthetic-registry",
        heldout_seeds=expected.heldout_seeds,
        quarantine_seeds=expected.quarantine_seeds,
        heldout_seed_commitment_sha256=expected.heldout_seed_commitment_sha256,
        precommit_relative_path=expected.precommit_relative_path,
        precommit_raw_sha256=expected.precommit_raw_sha256,
        terminal_relative_path=expected.terminal_relative_path,
        terminal_raw_sha256=expected.terminal_raw_sha256,
        rehearsal_relative_path=expected.rehearsal_relative_path,
        rehearsal_raw_sha256=expected.rehearsal_raw_sha256,
        independent_audit_relative_path=expected.independent_audit_relative_path,
        independent_audit_raw_sha256="6" * 64,
        protocol_schema=expected.protocol_schema,
        protocol_status=expected.protocol_status,
        protocol_root_prefix="reservation_",
        protocol_leaf=expected.protocol_leaf,
        model_ids_in_order=model_ids,
        survivor_ids_in_order=survivor_ids,
        source_model_versions=versions,
        formula_lock=formula_lock,
        build_source_manifest=lambda **kwargs: source_manifest,
        source_manifest_inputs=lambda project: {},
        generation_plan=lambda: generation,
    )

    audit_unsigned = {
        "schema_version": expected.independent_audit_schema,
        "status": expected.independent_audit_status,
        "run_id": expected.run_id,
        "append_performed": False,
    }
    audit_semantic = _semantic(audit_unsigned)
    audit = {**audit_unsigned, "audit_semantic_sha256": audit_semantic}
    audit_raw = _pretty(audit)
    _write(project, expected.independent_audit_relative_path, audit_raw)
    expected = replace(
        expected,
        independent_audit_raw_sha256=_sha(audit_raw),
        independent_audit_semantic_sha256=audit_semantic,
    )
    runtime = replace(
        runtime,
        independent_audit_raw_sha256=expected.independent_audit_raw_sha256,
    )

    gate = {
        "schema_version": expected.execution_gate_schema,
        "status": expected.execution_gate_status,
        "run_id": expected.run_id,
        "authorization": {
            "additional_reservation_allowed": False,
            "apply_call_count_authorized": 1,
            "automatic_retry_allowed": False,
        },
        "formal_seed_allocation": {
            "quarantine_seeds_never_generate_or_score": list(expected.quarantine_seeds),
            "heldout_seeds_in_order": list(expected.heldout_seeds),
            "heldout_seed_commitment_sha256": (expected.heldout_seed_commitment_sha256),
        },
        "access_state": {
            "formal_heldout_generation_count": 0,
            "performance_content_consulted_count": 0,
            "protected_content_open_count": 0,
            "registry_append_count": 0,
            "score_open_count": 0,
            "truth_open_count": 0,
        },
    }
    gate_raw = _pretty(gate)
    _write(project, expected.execution_gate_relative_path, gate_raw)
    expected = replace(expected, execution_gate_raw_sha256=_sha(gate_raw))

    # Compute the exact protocol without passing through the fixed-hash gate.
    binding = leaf._protocol_binding(
        project=project,
        expected=expected,
        runtime=runtime,
        registry=registry,
        entry=entry,
    )
    protocol = build_protocol_lock(run_id=expected.run_id, r2_protocol_binding=binding)
    protocol_raw = _pretty(protocol)
    expected = replace(
        expected,
        protocol_raw_sha256=_sha(protocol_raw),
        protocol_size_bytes=len(protocol_raw),
        protocol_binding_semantic_sha256=protocol["r2_protocol_binding_semantic_sha256"],
        protocol_policy_lock_sha256=protocol["policy_lock_sha256"],
    )

    forensic = {
        "schema_version": expected.apply_forensic_schema,
        "status": expected.apply_forensic_status,
        "run_id": expected.run_id,
        "serialization_forensics": {
            "actual_raw_sha256": expected.registry_raw_sha256,
            "expected_lf_raw_sha256": expected.registry_lf_raw_sha256,
            "actual_was_exact_crlf_expansion_of_expected_lf": True,
            "semantic_or_hash_chain_corruption": False,
        },
        "registry_after": {
            "raw_sha256": expected.registry_raw_sha256,
            "registry_self_sha256": expected.registry_self_sha256,
            "entry_count": expected.registry_entry_count,
            "last_entry_sha256": expected.reservation_entry_sha256,
        },
        "registry_before": {
            "raw_sha256": expected.predecessor_raw_sha256,
            "registry_self_sha256": expected.predecessor_self_sha256,
            "entry_count": expected.predecessor_entry_count,
            "last_entry_sha256": expected.predecessor_last_entry_sha256,
        },
        "reservation_entry": {
            "entry_sha256": expected.reservation_entry_sha256,
            "reservation_id": expected.reservation_id,
            "source_config_sha256": expected.source_config_sha256,
            "candidate_config_sha256": expected.candidate_config_sha256,
            "policy_config_sha256": expected.reservation_policy_config_sha256,
        },
        "reservation_root_state": {
            "child_count": 0,
            "protocol_lock_exists": False,
            "active_registry_lock_exists": False,
            "temporary_registry_file_exists": False,
        },
        "in_memory_protocol_reconstruction": {
            "protocol_raw_sha256": expected.protocol_raw_sha256,
            "protocol_binding_semantic_sha256": (expected.protocol_binding_semantic_sha256),
            "policy_lock_sha256": expected.protocol_policy_lock_sha256,
            "source_manifest_matches_reservation_entry": True,
        },
        "verdict": {
            "registry_append_is_valid_and_consumed": True,
            "helper_apply_retry_allowed": False,
            "additional_seed_or_registry_reservation_allowed": False,
            "protocol_leaf_only_completion_requires_separate_frozen_authority": True,
        },
        "access_counts": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_content_open_count": 0,
        },
    }
    forensic_raw = _pretty(forensic)
    _write(project, expected.apply_forensic_relative_path, forensic_raw)
    expected = replace(expected, apply_forensic_raw_sha256=_sha(forensic_raw))

    unsigned_authority = leaf.completion_authority_unsigned_template(
        completion_tool_raw_sha256=_sha(tool_path.read_bytes()),
        completion_test_raw_sha256=_sha(test_path.read_bytes()),
        expected=expected,
    )
    authority = leaf.seal_completion_authority(unsigned_authority)
    authority_raw = _pretty(authority)
    authority_path = _write(project, expected.authority_relative_path, authority_raw)
    return SyntheticLane(
        project=project,
        expected=expected,
        runtime=runtime,
        authority_path=authority_path,
        authority_raw_sha256=_sha(authority_raw),
        registry_raw=registry_raw,
        tool_path=tool_path,
        test_path=test_path,
    )


def _plan(lane: SyntheticLane) -> leaf.CompletionPlan:
    return leaf.build_completion_plan(
        project_root=lane.project,
        completion_authority=lane.authority_path,
        completion_authority_raw_sha256=lane.authority_raw_sha256,
        runtime=lane.runtime,
        expected=lane.expected,
    )


def test_dry_run_accepts_exact_crlf_consumed_append_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    before = {
        path.relative_to(lane.project).as_posix(): path.read_bytes()
        for path in lane.project.rglob("*")
        if path.is_file()
    }
    plan = _plan(lane)
    after = {
        path.relative_to(lane.project).as_posix(): path.read_bytes()
        for path in lane.project.rglob("*")
        if path.is_file()
    }
    assert before == after
    assert plan.report["status"] == leaf.DRY_RUN_STATUS
    assert plan.report["registry_append_count"] == 0
    assert plan.report["protocol_leaf_create_count"] == 0
    assert plan.registry_raw == lane.registry_raw


@pytest.mark.parametrize("attack", ["missing", "wrong_hash", "content", "tool", "test"])
def test_completion_authority_and_source_pin_attacks_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    authority = lane.authority_path
    digest = lane.authority_raw_sha256
    if attack == "missing":
        authority = lane.project / "build/missing.json"
    elif attack == "wrong_hash":
        digest = "a" * 64
    elif attack == "content":
        value = json.loads(authority.read_text(encoding="utf-8"))
        value["completion_action_counts"]["registry_append_count"] = 1
        authority.write_bytes(_pretty(value))
        digest = _sha(authority.read_bytes())
    elif attack == "tool":
        lane.tool_path.write_bytes(b"drifted tool\n")
    elif attack == "test":
        lane.test_path.write_bytes(b"drifted test\n")
    with pytest.raises(leaf.R3ProtocolLeafCompletionError):
        leaf.build_completion_plan(
            project_root=lane.project,
            completion_authority=authority,
            completion_authority_raw_sha256=digest,
            runtime=lane.runtime,
            expected=lane.expected,
        )
    assert not (lane.project / lane.expected.protocol_relative_path).exists()


@pytest.mark.parametrize(
    "attack",
    [
        "registry_lf",
        "registry_byte",
        "registry_lock",
        "registry_temp",
        "root_child",
        "source",
        "candidate",
        "live_evidence",
    ],
)
def test_registry_sidecar_root_and_closure_attacks_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    runtime = lane.runtime
    registry_path = lane.project / lane.expected.registry_relative_path
    if attack == "registry_lf":
        registry_path.write_bytes(lane.registry_raw.replace(b"\r\n", b"\n"))
    elif attack == "registry_byte":
        raw = bytearray(lane.registry_raw)
        raw[10] ^= 1
        registry_path.write_bytes(bytes(raw))
    elif attack == "registry_lock":
        _write(lane.project, lane.expected.registry_lock_relative_path, b"lock")
    elif attack == "registry_temp":
        _write(lane.project, "outputs/.registry.json.1.tmp", b"tmp")
    elif attack == "root_child":
        _write(
            lane.project,
            f"{lane.expected.output_root_relative_path}/unexpected.txt",
            b"unexpected",
        )
    elif attack == "source":
        runtime = replace(
            runtime,
            build_source_manifest=lambda **kwargs: {"source_manifest_semantic_sha256": "a" * 64},
        )
    elif attack == "candidate":
        runtime = replace(runtime, model_ids_in_order=("attacked",))
    elif attack == "live_evidence":

        def reject_live_evidence(project: Path, protocol: Mapping[str, Any]) -> None:
            raise ValueError("terminal/precommit/rehearsal live drift")

        runtime = replace(runtime, verify_live_protocol_evidence=reject_live_evidence)
    with pytest.raises(leaf.R3ProtocolLeafCompletionError):
        leaf.build_completion_plan(
            project_root=lane.project,
            completion_authority=lane.authority_path,
            completion_authority_raw_sha256=lane.authority_raw_sha256,
            runtime=runtime,
            expected=lane.expected,
        )
    assert not (lane.project / lane.expected.protocol_relative_path).exists()


def _child_report(lane: SyntheticLane) -> dict[str, object]:
    return {
        "schema_version": ("expected_pe.four_model.r3_protocol_leaf_completion_validator.v1"),
        "status": leaf.CHILD_STATUS,
        "run_id": lane.expected.run_id,
        "completion_authority_raw_sha256": lane.authority_raw_sha256,
        "registry_raw_sha256": lane.expected.registry_raw_sha256,
        "registry_entry_count": lane.expected.registry_entry_count,
        "protocol_lock_raw_sha256": lane.expected.protocol_raw_sha256,
        "protocol_leaf_count": 1,
        "additional_seed_reservation_count": 0,
        "formal_generation_count": 0,
        "generation_count": 0,
        "helper_apply_count": 0,
        "original_helper_apply_count": 0,
        "registry_append_count": 0,
        "registry_write_count": 0,
        "registry_lock_count": 0,
        "reservation_count": 0,
        "seed_value_change_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }


def test_apply_creates_only_leaf_after_closed_handle_then_fresh_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    plan = _plan(lane)
    write_returned = False
    original_write = leaf._write_new_leaf

    def tracked_write(path: Path, raw: bytes) -> None:
        nonlocal write_returned
        original_write(path, raw)
        write_returned = True

    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert write_returned
        protocol = lane.project / lane.expected.protocol_relative_path
        assert protocol.read_bytes() == plan.protocol_raw
        assert (lane.project / lane.expected.registry_relative_path).read_bytes() == (
            lane.registry_raw
        )
        assert command[1:4] == ["-I", "-B", "-X"]
        assert command[4].startswith("pycache_prefix=")
        prefix = Path(command[4].split("=", 1)[1])
        assert prefix.is_dir() and not list(prefix.iterdir())
        assert "--_validate-child" in command
        assert "--apply" not in command
        assert kwargs["cwd"] == lane.project
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert "PYTHONPATH" not in environment
        assert "PYTHONHOME" not in environment
        assert "PYTHONPYCACHEPREFIX" not in environment
        observed["called"] = True
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(_child_report(lane), sort_keys=True),
            stderr="",
        )

    monkeypatch.setattr(leaf, "_write_new_leaf", tracked_write)
    monkeypatch.setattr(leaf.subprocess, "run", fake_run)
    report = leaf.apply_completion_plan(plan)
    assert observed == {"called": True}
    assert report["status"] == leaf.COMPLETE_STATUS
    assert report["protocol_leaf_create_count"] == 1
    assert report["registry_append_count"] == 0
    assert (lane.project / lane.expected.registry_relative_path).read_bytes() == (lane.registry_raw)
    assert [
        path.name for path in (lane.project / lane.expected.output_root_relative_path).iterdir()
    ] == [lane.expected.protocol_leaf]
    with pytest.raises(leaf.R3ProtocolLeafCompletionError):
        leaf.apply_completion_plan(plan)


def test_subprocess_failure_leaves_no_retry_leaf_and_registry_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    plan = _plan(lane)

    def reject(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 7, stdout="", stderr="rejected")

    monkeypatch.setattr(leaf.subprocess, "run", reject)
    with pytest.raises(leaf.R3ProtocolLeafCompletionError, match="subprocess rejected"):
        leaf.apply_completion_plan(plan)
    protocol = lane.project / lane.expected.protocol_relative_path
    assert protocol.read_bytes() == plan.protocol_raw
    assert (lane.project / lane.expected.registry_relative_path).read_bytes() == (lane.registry_raw)
    with pytest.raises(leaf.R3ProtocolLeafCompletionError):
        leaf.build_completion_plan(
            project_root=lane.project,
            completion_authority=lane.authority_path,
            completion_authority_raw_sha256=lane.authority_raw_sha256,
            runtime=lane.runtime,
            expected=lane.expected,
        )


def test_forged_plan_protocol_path_is_ignored_in_favor_of_fresh_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    plan = _plan(lane)
    escaped = tmp_path / "escaped.json"
    forged = replace(plan, protocol_path=escaped)
    monkeypatch.setattr(
        leaf,
        "_launch_fresh_validator",
        lambda current: _child_report(lane),
    )
    report = leaf.apply_completion_plan(forged)
    assert report["status"] == leaf.COMPLETE_STATUS
    assert not escaped.exists()
    assert (lane.project / lane.expected.protocol_relative_path).read_bytes() == (plan.protocol_raw)


@pytest.mark.parametrize("attack", ["schema", "extra_key"])
def test_fresh_child_report_requires_exact_schema_and_key_universe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    plan = _plan(lane)
    report = _child_report(lane)
    if attack == "schema":
        report["schema_version"] = "attacked"
    else:
        report["extra"] = 0

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(report, sort_keys=True), stderr=""
        )

    monkeypatch.setattr(leaf.subprocess, "run", fake_run)
    with pytest.raises(
        leaf.R3ProtocolLeafCompletionError,
        match="fresh validator report content differs",
    ):
        leaf._launch_fresh_validator(plan)


def test_completed_state_live_reader_and_attacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _make_lane(tmp_path, monkeypatch)
    plan = _plan(lane)
    leaf._write_new_leaf(plan.protocol_path, plan.protocol_raw)
    report = leaf.validate_completed_state(
        project_root=lane.project,
        completion_authority=lane.authority_path,
        completion_authority_raw_sha256=lane.authority_raw_sha256,
        runtime=lane.runtime,
        expected=lane.expected,
    )
    assert report["status"] == leaf.CHILD_STATUS
    plan.protocol_path.chmod(0o666)
    plan.protocol_path.write_bytes(plan.protocol_raw + b" ")
    with pytest.raises(leaf.R3ProtocolLeafCompletionError):
        leaf.validate_completed_state(
            project_root=lane.project,
            completion_authority=lane.authority_path,
            completion_authority_raw_sha256=lane.authority_raw_sha256,
            runtime=lane.runtime,
            expected=lane.expected,
        )


def test_write_new_leaf_closes_descriptor_even_when_fsync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "leaf.json"
    closed: list[int] = []
    real_close = leaf.os.close

    def fail_fsync(descriptor: int) -> None:
        raise OSError("synthetic fsync failure")

    def tracked_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(leaf.os, "fsync", fail_fsync)
    monkeypatch.setattr(leaf.os, "close", tracked_close)
    with pytest.raises(OSError, match="synthetic fsync failure"):
        leaf._write_new_leaf(target, b"payload")
    assert len(closed) == 1
    assert target.read_bytes() == b"payload"


def test_parser_defaults_to_dry_run_and_child_cannot_apply() -> None:
    arguments = leaf.parser().parse_args(
        [
            "--completion-authority",
            leaf.FORMAL.authority_relative_path,
            "--completion-authority-raw-sha256",
            "a" * 64,
        ]
    )
    assert arguments.apply is False
    assert arguments._validate_child is False
