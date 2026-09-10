"""Adversarial score-free tests and fixture benchmark for H-OFS V10."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (  # noqa: E402
    CAPABILITY_AUTHORITY_KIND,
    CAPABILITY_DOMAIN,
    CAPABILITY_SCHEMA,
    CapabilityError,
    CapabilityPolicy,
    FUTURE_AUDIT_VERDICT,
    contract_payload,
    require_task_identity,
    task_manifest_sha256,
    verify_capability_envelope,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (  # noqa: E402
    capability as capability_v10,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (  # noqa: E402
    lifecycle as lifecycle_v10,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v10 import (  # noqa: E402
    prediction_launcher as launcher_v10,
)


# The only private key in V10 is this deterministic test fixture seed.
_TEST_FIXTURE_PRIVATE_SEED = bytes.fromhex(
    "102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff00f"
)
_FIXTURE_NOW = 1_800_000_100
_FIXTURE_ISSUED = 1_800_000_000
_FIXTURE_EXPIRES = 1_800_000_600


def _fixture_public_and_scalar() -> tuple[bytes, int, bytes]:
    expanded = hashlib.sha512(_TEST_FIXTURE_PRIVATE_SEED).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = capability_v10._encode_point(
        capability_v10._scalarmult(capability_v10._BASE, scalar)
    )
    return public_key, scalar, expanded[32:]


def _fixture_sign(message: bytes) -> tuple[bytes, bytes]:
    public_key, scalar, prefix = _fixture_public_and_scalar()
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little")
    nonce %= capability_v10._Q
    encoded_r = capability_v10._encode_point(
        capability_v10._scalarmult(capability_v10._BASE, nonce)
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % capability_v10._Q
    scalar_s = (nonce + challenge * scalar) % capability_v10._Q
    return public_key, encoded_r + scalar_s.to_bytes(32, "little")


def _fixture_tasks(count: int = 50) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    for ordinal in range(count):
        seed = 2026083001 + ordinal // 10
        dgp = "ABCDEFGHIJ"[ordinal % 10]
        relative = (
            f"replays/pass_1/seed_{seed}/dgp_{dgp}/canonical150.csv"
        )
        tasks.append(
            {
                "task_ordinal": ordinal,
                "seed": seed,
                "dgp": dgp,
                "canonical_relative": relative,
                "expected_raw_sha256": hashlib.sha256(
                    relative.encode("ascii")
                ).hexdigest(),
            }
        )
    return tasks


def _fixture_authority(
    *,
    tasks: list[dict[str, Any]] | None = None,
    run_id: str = "20260830T120000",
) -> tuple[bytes, bytes, CapabilityPolicy, list[dict[str, Any]]]:
    exact_tasks = _fixture_tasks() if tasks is None else copy.deepcopy(tasks)
    public_key, _scalar, _prefix = _fixture_public_and_scalar()
    policy = CapabilityPolicy(
        design_contract_sha256="1" * 64,
        design_checksums_raw_sha256="2" * 64,
        audit_checksums_raw_sha256="3" * 64,
        audit_raw_sha256="4" * 64,
        audit_semantic_sha256="5" * 64,
        audit_verdict=FUTURE_AUDIT_VERDICT,
        run_id=run_id,
        public_key_raw_sha256=hashlib.sha256(public_key).hexdigest(),
        task_manifest_sha256=task_manifest_sha256(exact_tasks),
        task_count=len(exact_tasks),
    )
    payload = {
        "schema_version": CAPABILITY_SCHEMA,
        "domain_hex": CAPABILITY_DOMAIN.hex(),
        "authority_kind": CAPABILITY_AUTHORITY_KIND,
        "design_contract_sha256": policy.design_contract_sha256,
        "design_checksums_raw_sha256": policy.design_checksums_raw_sha256,
        "independent_audit": {
            "checksums_raw_sha256": policy.audit_checksums_raw_sha256,
            "audit_raw_sha256": policy.audit_raw_sha256,
            "audit_semantic_sha256": policy.audit_semantic_sha256,
            "verdict": policy.audit_verdict,
            "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "finding_count": 0,
        },
        "run_id": policy.run_id,
        "session_nonce": "a" * 64,
        "custodian_consumption_id": "b" * 64,
        "issued_at_unix": _FIXTURE_ISSUED,
        "expires_at_unix": _FIXTURE_EXPIRES,
        "one_shot": True,
        "task_manifest_sha256": policy.task_manifest_sha256,
        "task_count": policy.task_count,
        "public_key_raw_sha256": policy.public_key_raw_sha256,
    }
    message = CAPABILITY_DOMAIN + capability_v10.canonical_json_bytes(payload)
    observed_public, signature = _fixture_sign(message)
    assert observed_public == public_key
    envelope = capability_v10.canonical_json_bytes(
        {"payload": payload, "signature_hex": signature.hex()}
    )
    return envelope, public_key, policy, exact_tasks


def test_v10_contract_is_score_free_and_closes_only_v9_findings() -> None:
    payload = contract_payload()
    assert payload["authority"]["score_free_design_preflight_only"] is True
    assert payload["authority"]["real_model_fit"] is False
    assert payload["authority"]["research_or_production_prediction"] is False
    assert payload["repair_scope"]["closed_findings_only"] == [
        "HOFS_V9_P0_DIRECT_WORKER_AUTHORITY_BYPASS",
        "HOFS_V9_P1_FORGEABLE_ABSENCE_GUARD_RECEIPT",
    ]
    signed = payload["signed_capability"]
    assert signed["production_private_key_in_code_or_bundle"] is False
    assert signed["production_public_key_value_frozen_in_design"] is False
    assert signed["future_audit_binds_custodian_public_key_raw_sha256"] is True


def test_fixture_signed_capability_verifies_strictly() -> None:
    envelope, public_key, policy, tasks = _fixture_authority()
    with pytest.raises(CapabilityError, match="semantic drift"):
        CapabilityPolicy(
            **{**policy.__dict__, "audit_verdict": "GO_WRONG_AUDIT"}
        )
    verified = verify_capability_envelope(
        envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=_FIXTURE_NOW,
    )
    assert verified.run_id == policy.run_id
    assert verified.session_nonce == "a" * 64
    assert verified.task_manifest_sha256 == policy.task_manifest_sha256
    assert len(verified.task_bindings) == 50


@pytest.mark.parametrize(
    "attack",
    (
        "signature",
        "payload",
        "public_key",
        "public_key_pin",
        "audit_verdict",
        "audit_findings",
        "expired",
        "one_shot",
        "task_manifest",
    ),
)
def test_forged_or_mismatched_authority_fails_closed(attack: str) -> None:
    envelope, public_key, policy, tasks = _fixture_authority()
    attacked_envelope = bytearray(envelope)
    attacked_key = public_key
    attacked_policy = policy
    attacked_now = _FIXTURE_NOW
    if attack == "signature":
        parsed = json.loads(envelope)
        parsed["signature_hex"] = "00" + parsed["signature_hex"][2:]
        attacked_envelope = bytearray(capability_v10.canonical_json_bytes(parsed))
    elif attack == "payload":
        parsed = json.loads(envelope)
        parsed["payload"]["session_nonce"] = "c" * 64
        attacked_envelope = bytearray(capability_v10.canonical_json_bytes(parsed))
    elif attack == "public_key":
        attacked_key = bytes([public_key[0] ^ 1]) + public_key[1:]
    elif attack == "public_key_pin":
        attacked_policy = CapabilityPolicy(
            **{**policy.__dict__, "public_key_raw_sha256": "9" * 64}
        )
    elif attack == "audit_verdict":
        parsed = json.loads(envelope)
        parsed["payload"]["independent_audit"]["verdict"] = "GO_WRONG_AUDIT"
        attacked_envelope = bytearray(capability_v10.canonical_json_bytes(parsed))
    elif attack == "audit_findings":
        parsed = json.loads(envelope)
        parsed["payload"]["independent_audit"]["finding_count"] = 1
        attacked_envelope = bytearray(capability_v10.canonical_json_bytes(parsed))
    elif attack == "expired":
        attacked_now = _FIXTURE_EXPIRES
    elif attack == "one_shot":
        parsed = json.loads(envelope)
        parsed["payload"]["one_shot"] = False
        attacked_envelope = bytearray(capability_v10.canonical_json_bytes(parsed))
    else:
        tasks[-1]["expected_raw_sha256"] = "8" * 64
    with pytest.raises(CapabilityError):
        verify_capability_envelope(
            bytes(attacked_envelope),
            public_key=attacked_key,
            policy=attacked_policy,
            task_bindings=tasks,
            now_unix=attacked_now,
        )


def test_run_and_task_identity_mismatch_fails_closed() -> None:
    envelope, public_key, policy, tasks = _fixture_authority()
    verified = verify_capability_envelope(
        envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=_FIXTURE_NOW,
    )
    first = tasks[0]
    keyword = {
        "run_id": policy.run_id,
        **first,
    }
    assert require_task_identity(verified, **keyword) == first
    with pytest.raises(CapabilityError, match="run ID"):
        require_task_identity(verified, **{**keyword, "run_id": "20260830T120001"})
    with pytest.raises(CapabilityError, match="task identity"):
        require_task_identity(verified, **{**keyword, "seed": first["seed"] + 1})


def _fixture_ledger() -> tuple[launcher_v10._SharedTaskLedger, dict[str, Any]]:
    envelope, public_key, policy, tasks = _fixture_authority()
    verified = verify_capability_envelope(
        envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=_FIXTURE_NOW,
    )
    attestation = {
        "schema_version": "expected_pe.hofs_v10.shared_task_ledger.v1",
        "status": "ACTIVE_SIGNED_ONE_SHOT_TASK_LEDGER",
        "capability_envelope_raw_sha256": verified.envelope_raw_sha256,
        "run_id": verified.run_id,
        "session_nonce": verified.session_nonce,
        "custodian_consumption_id": verified.custodian_consumption_id,
        "task_manifest_sha256": verified.task_manifest_sha256,
        "task_count": len(tasks),
        "one_shot": True,
    }
    ledger = launcher_v10._SharedTaskLedger(
        lock=threading.Lock(),
        consumed={},
        sequence={"value": 0},
        attestation=attestation,
    )
    first_sha = hashlib.sha256(
        capability_v10.canonical_json_bytes(tasks[0])
    ).hexdigest()
    arguments = {
        "capability_envelope_raw_sha256": verified.envelope_raw_sha256,
        "run_id": verified.run_id,
        "session_nonce": verified.session_nonce,
        "custodian_consumption_id": verified.custodian_consumption_id,
        "task_ordinal": 0,
        "task_binding_sha256": first_sha,
        "consumer_pid": os.getpid(),
    }
    return ledger, arguments


def test_duplicate_and_replay_consumption_fail_closed() -> None:
    ledger, arguments = _fixture_ledger()
    receipt = ledger.consume(**arguments)
    assert receipt["status"] == "CONSUMED_ONCE_BEFORE_DOWNSTREAM"
    with pytest.raises(RuntimeError, match="duplicate"):
        ledger.consume(**arguments)


def test_concurrent_duplicate_consumption_has_exactly_one_winner() -> None:
    ledger, arguments = _fixture_ledger()

    def attempt() -> str:
        try:
            ledger.consume(**arguments)
        except RuntimeError:
            return "REJECTED"
        return "CONSUMED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _position: attempt(), range(2)))
    assert outcomes == ["CONSUMED", "REJECTED"]


def test_direct_task_and_initializer_bypass_fail_closed() -> None:
    lifecycle_v10._WORKER_STATE = None
    task = _fixture_tasks(1)[0]
    with pytest.raises(CapabilityError, match="direct task dispatch"):
        lifecycle_v10._authorize_and_consume_task(
            run_id="20260830T120000",
            now_unix=_FIXTURE_NOW,
            **task,
        )
    with pytest.raises(CapabilityError, match="marker"):
        lifecycle_v10._install_worker_state(
            initializer_marker=object(),
            guard_receipt={},
            envelope_bytes=b"{}",
            public_key=b"",
            policy=None,
            task_bindings=[],
            now_unix=_FIXTURE_NOW,
            shared_ledger=None,
            first_task_barrier=None,
        )


def test_worker_and_optional_receipt_builders_are_not_package_exports() -> None:
    import research.model_zoo.hierarchical_observable_fair_value_state_v10 as package

    assert not hasattr(package, "worker_bootstrap_initializer")
    assert not hasattr(package, "build_worker_attestation")
    assert not hasattr(package, "_install_worker_state")
    assert lifecycle_v10.__all__ == []
    source = (
        PROJECT_ROOT
        / "research/model_zoo/hierarchical_observable_fair_value_state_v10/"
        "lifecycle.py"
    ).read_text("utf-8")
    assert "preimport_guard_receipt=None" not in source


def test_preloaded_numpy_fails_actual_initializer_guard() -> None:
    pytest.importorskip("numpy")
    with pytest.raises(RuntimeError, match="preloaded before initializer"):
        launcher_v10.actual_initializer_absence_guard("a" * 64)


def test_launcher_has_no_run_fit_or_prediction_surface() -> None:
    source = Path(launcher_v10.__file__).read_text("utf-8")
    assert 'add_argument("--run"' not in source
    assert "fit_chronological_prefix_v7" not in source
    assert "run_frozen_decision_block_v7" not in source
    assert source.index("_authorize_and_consume_task(") < source.index(
        '"downstream_callback_invoked": False'
    )


def run_fixture_benchmark() -> dict[str, Any]:
    envelope, public_key, policy, tasks = _fixture_authority()
    production = launcher_v10.run_score_free_lifecycle_benchmark(
        envelope_bytes=envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=_FIXTURE_NOW,
        worker_count=32,
        task_count=50,
    )
    targeted = launcher_v10.run_score_free_lifecycle_benchmark(
        envelope_bytes=envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=_FIXTURE_NOW,
        worker_count=1,
        task_count=7,
    )
    if (
        production["worker_count"] != 32
        or production["task_count"] != 50
        or production["reused_worker_count"] < 1
        or targeted["worker_count"] != 1
        or targeted["task_count"] != 7
        or targeted["maximum_reuse_count"] != 7
        or production["public_input_open_count"] != 0
        or production["real_fit_count"] != 0
        or production["real_prediction_count"] != 0
    ):
        raise RuntimeError("V10 fixture lifecycle benchmark drifted")
    return {
        "schema_version": "expected_pe.hofs_v10.fixture_benchmark.v1",
        "status": "PASS_FIXTURE_ONLY_32X50_AND_SAME_PID_7_SCORE_FREE",
        "fixture_private_key_location": (
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py"
        ),
        "production_private_key_present": False,
        "production_public_key_value_present": False,
        "production_equivalent": production,
        "targeted_same_pid": targeted,
        "public_input_open_count": 0,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-benchmark", action="store_true", required=True)
    parser.parse_args()
    print(
        json.dumps(
            run_fixture_benchmark(),
            ensure_ascii=True,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
