from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts/model_lab/pe_four_model_heldout_r3_allocate.py"
SPEC = importlib.util.spec_from_file_location("pe_four_model_heldout_r3_allocate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_prime_definition() -> None:
    assert not MODULE._is_prime(-3)
    assert not MODULE._is_prime(0)
    assert not MODULE._is_prime(1)
    assert MODULE._is_prime(2)
    assert MODULE._is_prime(3)
    assert not MODULE._is_prime(9)
    assert MODULE._is_prime(97)


def test_create_new_writer_is_byte_exact_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "PRECOMMIT.json"
    raw = b'{"status":"synthetic"}\n'
    MODULE._write_new(output, raw)
    assert output.read_bytes() == raw
    with pytest.raises(FileExistsError):
        MODULE._write_new(output, raw)


def test_live_policy_and_registry_phase_is_deterministic_without_mutation() -> None:
    policy_path = PROJECT_ROOT / MODULE.POLICY_RELATIVE
    registry_path = PROJECT_ROOT / MODULE.REGISTRY_RELATIVE
    policy_raw = policy_path.read_bytes()
    gate_raw = (PROJECT_ROOT / MODULE.DERIVATION_GATE_RELATIVE).read_bytes()
    registry_raw = registry_path.read_bytes()
    policy = MODULE._json_object(policy_raw, label="policy")
    gate = MODULE._json_object(gate_raw, label="gate")
    registry = MODULE._json_object(registry_raw, label="registry")
    entries = registry["entries"]
    assert type(entries) is list
    if len(entries) == MODULE.REGISTRY_BEFORE_ENTRY_COUNT:
        first = MODULE.build_precommit(policy=policy, derivation_gate=gate, registry=registry)
        second = MODULE.build_precommit(policy=policy, derivation_gate=gate, registry=registry)
        assert first == second
        assert first["registry_before"]["globally_spent_seed_count"] == 136
        assert len(first["quarantine_seeds_never_generate_or_score"]) == 5
        assert len(first["heldout_seeds_in_order"]) == 5
        assert all(first["overlap_audit"][name] == 0 for name in first["overlap_audit"])
        assert first["deterministic_next_ten_primes"] == sorted(
            first["deterministic_next_ten_primes"]
        )
        assert all(MODULE._is_prime(seed) for seed in first["deterministic_next_ten_primes"])
    else:
        assert len(entries) == MODULE.REGISTRY_BEFORE_ENTRY_COUNT + 1
        assert entries[-1]["previous_entry_sha256"] == (MODULE.REGISTRY_BEFORE_LAST_ENTRY_SHA256)
        for _ in range(2):
            with pytest.raises(MODULE.R3AllocationError, match="predecessor chain differs"):
                MODULE.build_precommit(policy=policy, derivation_gate=gate, registry=registry)
    assert registry_path.read_bytes() == registry_raw


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("candidate_and_evidence_independence", "heldout_truth_consulted", True),
        ("formal_execution_policy", "reservation_append_count", 2),
        ("allocation_role_policy", "formal_heldout_count", 6),
    ],
)
def test_policy_drift_is_rejected(section: str, field: str, replacement: object) -> None:
    raw = (PROJECT_ROOT / MODULE.POLICY_RELATIVE).read_bytes()
    policy = MODULE._json_object(raw, label="policy")
    changed = copy.deepcopy(policy)
    changed[section][field] = replacement
    with pytest.raises(MODULE.R3AllocationError, match="policy differs"):
        MODULE._validate_policy(changed)


def test_registry_chain_drift_is_rejected() -> None:
    policy = MODULE._json_object(
        (PROJECT_ROOT / MODULE.POLICY_RELATIVE).read_bytes(), label="policy"
    )
    gate = MODULE._json_object(
        (PROJECT_ROOT / MODULE.DERIVATION_GATE_RELATIVE).read_bytes(), label="gate"
    )
    registry = MODULE._json_object(
        (PROJECT_ROOT / MODULE.REGISTRY_RELATIVE).read_bytes(), label="registry"
    )
    changed = copy.deepcopy(registry)
    changed["registry_sha256"] = "0" * 64
    with pytest.raises(MODULE.R3AllocationError, match="predecessor chain differs"):
        MODULE.build_precommit(policy=policy, derivation_gate=gate, registry=changed)


def test_derivation_gate_drift_is_rejected() -> None:
    gate = MODULE._json_object(
        (PROJECT_ROOT / MODULE.DERIVATION_GATE_RELATIVE).read_bytes(), label="gate"
    )
    changed = copy.deepcopy(gate)
    changed["blocked_actions_until_later_reservation_gate"].remove("SPENT_SEED_REGISTRY_APPEND")
    with pytest.raises(MODULE.R3AllocationError, match="gate differs"):
        MODULE._validate_derivation_gate(changed)
