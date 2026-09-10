from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Mapping

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/model_lab/pe_four_model_heldout_r3_repin_evaluator.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pe_r3_repin_evaluator_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _synthetic_target(module: ModuleType) -> dict[str, object]:
    return {
        "R2_PROTOCOL_LOCK_RAW_SHA256": "a" * 64,
        "R2_PROTOCOL_BINDING_SEMANTIC_SHA256": "b" * 64,
        "HELDOUT_SEEDS": (101, 103, 107, 109, 113),
        "GENERATION_PLAN_SEMANTIC_SHA256": "c" * 64,
    }


def _force_bindings(module: ModuleType, raw: bytes, bindings: Mapping[str, object]) -> bytes:
    """Test-only literal rewrite that can construct either legal start state."""

    _, nodes, _ = module._module_assignments(raw, module.REPINNED_CONSTANT_NAMES)
    text = raw.decode("utf-8")
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    replacements = []
    for name, value in bindings.items():
        node = nodes[name].value
        assert node is not None
        assert node.end_lineno is not None and node.end_col_offset is not None
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        replacements.append((start, end, module._binding_source(name, value)))
    for start, end, replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text.encode("utf-8")


def _live_constants(module: ModuleType) -> bytes:
    return (PROJECT_ROOT / module.CONSTANTS_RELATIVE).read_bytes()


def test_exact_r2_to_r3_repin_preserves_every_other_live_constant() -> None:
    module = _load()
    live = _live_constants(module)
    prior = _force_bindings(module, live, module.FROZEN_R2_PRIOR_BINDINGS)
    assert module._sha256(prior) == module.FROZEN_R3_PRE_REPIN_CONSTANTS_RAW_SHA256
    target = _synthetic_target(module)

    planned, state, observed = module.replace_evaluator_bindings(prior, target_bindings=target)

    assert state == "frozen_r2_prior"
    assert observed == module.FROZEN_R2_PRIOR_BINDINGS
    assert module._normalized_ast(prior) == module._normalized_ast(planned)
    _, _, values = module._module_assignments(planned, module.REPINNED_CONSTANT_NAMES)
    assert values == target
    # R3's new 18-key audit tuple is outside the four-value rewrite.
    assert b"bce_nine_variable_runtime_contract_exact" in planned
    assert b"c4_seven_variable_runtime_contract_exact" in planned
    assert b"python_and_package_runtime_hash_exact" in planned


def test_exact_target_is_a_byte_identical_no_op() -> None:
    module = _load()
    target = _synthetic_target(module)
    target_raw = _force_bindings(module, _live_constants(module), target)

    planned, state, observed = module.replace_evaluator_bindings(target_raw, target_bindings=target)

    assert state == "already_r3_target"
    assert observed == target
    assert planned == target_raw


@pytest.mark.parametrize(
    ("before", "after"),
    (
        (b'"pooled_mae_relative_gain_min": 0.005', b'"pooled_mae_relative_gain_min": 0.006'),
        (b'"global_log_shrink": 0.50', b'"global_log_shrink": 0.51'),
        (b"BOOTSTRAP_DRAWS: Final = 10_000", b"BOOTSTRAP_DRAWS: Final = 10_001"),
        (
            b'"python_and_package_runtime_hash_exact"',
            b'"python_and_package_runtime_hash_exacx"',
        ),
    ),
)
def test_gate_formula_bootstrap_or_audit_tuple_tamper_fails_in_both_states(
    before: bytes, after: bytes
) -> None:
    module = _load()
    live = _live_constants(module)
    assert live.count(before) == 1
    prior = _force_bindings(module, live, module.FROZEN_R2_PRIOR_BINDINGS)
    assert module._sha256(prior) == module.FROZEN_R3_PRE_REPIN_CONSTANTS_RAW_SHA256
    target = _synthetic_target(module)

    attacked_prior = prior.replace(before, after, 1)
    with pytest.raises(module.EvaluatorRepinError, match="pre-repin constants raw"):
        module.replace_evaluator_bindings(attacked_prior, target_bindings=target)

    target_raw = _force_bindings(module, prior, target)
    attacked_target = target_raw.replace(before, after, 1)
    with pytest.raises(module.EvaluatorRepinError, match="do not restore the exact"):
        module.replace_evaluator_bindings(attacked_target, target_bindings=target)


def test_mixed_or_arbitrary_nonzero_prior_binding_fails_closed() -> None:
    module = _load()
    prior = _force_bindings(module, _live_constants(module), module.FROZEN_R2_PRIOR_BINDINGS)
    attacked = _force_bindings(
        module,
        prior,
        {"R2_PROTOCOL_LOCK_RAW_SHA256": "d" * 64},
    )

    with pytest.raises(
        module.EvaluatorRepinError,
        match="neither the exact frozen R2 prior nor R3 target",
    ):
        module.replace_evaluator_bindings(attacked, target_bindings=_synthetic_target(module))


def test_authority_binding_extract_requires_exact_five_seed_geometry() -> None:
    module = _load()
    authority = {
        "r2_protocol_lock_raw_sha256": "a" * 64,
        "r2_protocol_binding_semantic_sha256": "b" * 64,
        "generation_plan_semantic_sha256": "c" * 64,
        "generation_plan": {
            "heldout_seeds_in_order": [101, 103, 107, 109, 113],
            "estimator_rng_seeds_in_order": [101, 103, 107, 109, 113],
            "plan_semantic_sha256": "c" * 64,
            "task_count": 50,
            "identity_count": 64_800,
            "prediction_row_count": 259_200,
        },
        "survivor_freeze": {
            "heldout_seeds_in_order": [101, 103, 107, 109, 113],
            "estimator_rng_seeds_in_order": [101, 103, 107, 109, 113],
        },
    }

    assert module._target_bindings_from_authority(authority) == _synthetic_target(module)
    authority["generation_plan"]["prediction_row_count"] = 259_199
    with pytest.raises(module.EvaluatorRepinError, match="seed/geometry binding"):
        module._target_bindings_from_authority(authority)


def test_authority_loader_accepts_only_canonical_r3_run_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    run_id = "r3_synthetic_loader_test"
    protocol = {
        "r2_protocol_binding_semantic_sha256": "b" * 64,
        "schema_version": "synthetic",
    }
    parsed = {
        "run_id": run_id,
        "r2_protocol_lock_raw_sha256": module._sha256(module._r2._canonical_pretty_bytes(protocol)),
        "r2_protocol_binding_semantic_sha256": "b" * 64,
        "r2_protocol_lock": protocol,
    }
    raw = (json.dumps(parsed, sort_keys=True, indent=2) + "\n").encode()
    authority_path = tmp_path / f"build/pe_four_model_heldout_execution_authority_{run_id}.json"
    authority_path.parent.mkdir()
    authority_path.write_bytes(raw)
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
        execution_authority as authority_module,
    )

    monkeypatch.setattr(
        authority_module,
        "read_execution_authority",
        lambda *args, **kwargs: dict(parsed),
    )

    assert (
        module._load_validated_execution_authority(
            project_root=tmp_path,
            authority_path=authority_path,
            expected_raw_sha256=module._sha256(raw),
        )
        == parsed
    )

    attacked = dict(parsed)
    attacked["run_id"] = "r2_synthetic_loader_test"
    attacked_raw = (json.dumps(attacked, sort_keys=True, indent=2) + "\n").encode()
    attacked_path = tmp_path / (
        "build/pe_four_model_heldout_execution_authority_r2_synthetic_loader_test.json"
    )
    attacked_path.write_bytes(attacked_raw)
    with pytest.raises(module.EvaluatorRepinError, match="not a new R3 authority"):
        module._load_validated_execution_authority(
            project_root=tmp_path,
            authority_path=attacked_path,
            expected_raw_sha256=module._sha256(attacked_raw),
        )


def test_current_launcher_authenticates_prior_or_complete_target_state() -> None:
    module = _load()
    constants_raw = _live_constants(module)
    _, _, bindings = module._module_assignments(constants_raw, module.REPINNED_CONSTANT_NAMES)
    state = (
        "frozen_r2_prior" if bindings == module.FROZEN_R2_PRIOR_BINDINGS else "already_r3_target"
    )
    launcher = (PROJECT_ROOT / module.RUN_ONCE_RELATIVE).read_bytes()

    pins, counts = module._validate_current_launcher_state(
        project_root=PROJECT_ROOT,
        launcher_raw=launcher,
        binding_state=state,
    )

    assert len(pins) == 37
    assert counts == (11, 3, 11, 12)

    victim = next(
        relative
        for relative in pins
        if relative not in {module.CONSTANTS_RELATIVE, module.SOURCE_LOCK_RELATIVE}
    )
    attacked = launcher.replace(pins[victim].encode("ascii"), b"f" * 64, 1)
    with pytest.raises(module.EvaluatorRepinError):
        module._validate_current_launcher_state(
            project_root=PROJECT_ROOT,
            launcher_raw=attacked,
            binding_state=state,
        )

    forged_pins = module._launcher_pins(launcher)
    forged_pins[module.CONSTANTS_RELATIVE] = module._sha256(constants_raw)
    forged_launcher = module._r2.replace_launcher_pin_assignment(launcher, forged_pins)
    with pytest.raises(module.EvaluatorRepinError, match="launcher raw SHA-256"):
        module._validate_current_launcher_state(
            project_root=PROJECT_ROOT,
            launcher_raw=forged_launcher,
            binding_state="frozen_r2_prior",
        )


def test_target_launcher_must_restore_exact_frozen_prior_bytes() -> None:
    module = _load()
    prior_launcher = (PROJECT_ROOT / module.RUN_ONCE_RELATIVE).read_bytes()
    live_pins, _ = module._r2.build_launcher_pins(PROJECT_ROOT, overlays={})
    target_launcher = module._r2.replace_launcher_pin_assignment(prior_launcher, live_pins)

    module._validate_current_launcher_state(
        project_root=PROJECT_ROOT,
        launcher_raw=target_launcher,
        binding_state="already_r3_target",
    )

    before = b"PINNED_PYTHON_SIZE_BYTES = 272_712"
    after = b"PINNED_PYTHON_SIZE_BYTES = 272_713"
    assert target_launcher.count(before) == 1
    attacked = target_launcher.replace(before, after, 1)
    with pytest.raises(module.EvaluatorRepinError, match="restore the exact frozen"):
        module._validate_current_launcher_state(
            project_root=PROJECT_ROOT,
            launcher_raw=attacked,
            binding_state="already_r3_target",
        )


def test_apply_requires_post_write_no_op_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    targets = (
        module.CONSTANTS_RELATIVE,
        module.SOURCE_LOCK_RELATIVE,
        module.RUN_ONCE_RELATIVE,
    )
    current = {relative: f"old:{relative}\n".encode() for relative in targets}
    planned = {relative: f"new:{relative}\n".encode() for relative in targets}
    for relative, raw in current.items():
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    report = {"transition_state": "frozen_r2_prior"}
    plan = module.RepinPlan(
        project_root=tmp_path,
        authority_path=tmp_path / "authority.json",
        authority_raw_sha256="a" * 64,
        current_bytes=current,
        planned_bytes=planned,
        report=report,
    )
    build_calls = 0

    def fake_build_repin_plan(**_: object) -> object:
        nonlocal build_calls
        build_calls += 1
        observed = {
            relative: tmp_path.joinpath(*relative.split("/")).read_bytes() for relative in targets
        }
        if observed == current:
            return plan
        assert observed == planned
        return module.RepinPlan(
            project_root=tmp_path,
            authority_path=plan.authority_path,
            authority_raw_sha256=plan.authority_raw_sha256,
            current_bytes=planned,
            planned_bytes=planned,
            report={"transition_state": "already_r3_target"},
        )

    monkeypatch.setattr(module, "build_repin_plan", fake_build_repin_plan)
    monkeypatch.setattr(
        module._r2,
        "_project_file",
        lambda root, relative: root.joinpath(*relative.split("/")),
    )

    module.apply_repin_plan(plan)

    assert build_calls == 2
    assert {
        relative: tmp_path.joinpath(*relative.split("/")).read_bytes() for relative in targets
    } == planned


def test_claimed_target_must_be_a_complete_byte_identical_no_op() -> None:
    module = _load()
    current = {
        module.CONSTANTS_RELATIVE: b"constants\n",
        module.SOURCE_LOCK_RELATIVE: b"source-lock\n",
        module.RUN_ONCE_RELATIVE: b"launcher with alternate whitespace\n",
    }
    exact = dict(current)
    module._require_complete_target_no_op(
        binding_state="already_r3_target",
        current=current,
        planned=exact,
    )
    changed = {**exact, module.RUN_ONCE_RELATIVE: b"launcher normalized\n"}
    with pytest.raises(module.EvaluatorRepinError, match="byte-identical no-op"):
        module._require_complete_target_no_op(
            binding_state="already_r3_target",
            current=current,
            planned=changed,
        )

    module._require_complete_target_no_op(
        binding_state="frozen_r2_prior",
        current=current,
        planned=changed,
    )


def test_cli_defaults_to_read_only_dry_run() -> None:
    module = _load()
    arguments = module.parser().parse_args(
        [
            "--execution-authority",
            "build/example.json",
            "--execution-authority-raw-sha256",
            "a" * 64,
        ]
    )
    assert arguments.apply is False
