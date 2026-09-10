"""Adversarial score-free tests for H-OFS V11 trust and custody."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import time
from types import MappingProxyType
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hierarchical_observable_fair_value_state_v11 import (  # noqa: E402
    AuthorityError,
    PRODUCTION_PUBLIC_KEY_HEX,
    PRODUCTION_PUBLIC_KEY_RAW_SHA256,
    contract_payload,
    derive_exact_r4_task_manifest,
    run_source_audit_v11,
    verify_ed25519_strict,
    verify_production_capability,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v11 import (  # noqa: E402
    authority as authority_v11,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v11.authority import (  # noqa: E402
    VerifiedProductionCapability,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: E402
    FIXTURE_CAPABILITY_DOMAIN,
    FIXTURE_CUSTODY_HANDSHAKE_DOMAIN,
    FIXTURE_WORKER_GRANT_DOMAIN,
    PINNED_OUTER_WORKERS,
    PRODUCTION_CAPABILITY_DOMAIN,
    PRODUCTION_CUSTODY_ENDPOINT,
    PRODUCTION_CUSTODY_HANDSHAKE_DOMAIN,
    PRODUCTION_WORKER_GRANT_DOMAIN,
    R4_DGPS,
    R4_PUBLIC_FILES_SHA256,
    R4_SEEDS,
    R4_TASK_COUNT,
    R4_TASK_MANIFEST_SHA256,
    V10_AUDIT_BINDING,
    canonical_json_bytes,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import (  # noqa: E402
    CustodyError,
    ProductionCustodyClient,
    _DurableAuthorityStore,
    verify_production_worker_grant,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v11 import (  # noqa: E402
    prediction_launcher as launcher_v11,
)


# The only V11 private key literal is this deterministic fixture seed.
_TEST_FIXTURE_PRIVATE_SEED = bytes.fromhex(
    "4b2a8e7cd03f1956aabbccddee1029384756abcdef00112233445566778899aa"
)


def _fixture_public_and_scalar() -> tuple[bytes, int, bytes]:
    expanded = hashlib.sha512(_TEST_FIXTURE_PRIVATE_SEED).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = authority_v11._encode_point(  # noqa: SLF001
        authority_v11._scalarmult(authority_v11._BASE, scalar)  # noqa: SLF001
    )
    return public_key, scalar, expanded[32:]


def _fixture_sign(message: bytes) -> tuple[bytes, bytes]:
    public_key, scalar, prefix = _fixture_public_and_scalar()
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little")
    nonce %= authority_v11._Q  # noqa: SLF001
    encoded_r = authority_v11._encode_point(  # noqa: SLF001
        authority_v11._scalarmult(  # noqa: SLF001
            authority_v11._BASE,  # noqa: SLF001
            nonce,
        )
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % authority_v11._Q  # noqa: SLF001
    scalar_s = (nonce + challenge * scalar) % authority_v11._Q  # noqa: SLF001
    return public_key, encoded_r + scalar_s.to_bytes(32, "little")


def _exact_input_closure() -> dict[str, Any]:
    inherited = json.loads(
        (
            PROJECT_ROOT
            / "outputs/model_zoo_hierarchical_observable_fair_value_state_v10_"
            "dgp_r4_design_preflight_20260821/INPUT_CLOSURE.json"
        ).read_text("ascii")
    )["inherited_input_closure"]
    public_files = copy.deepcopy(inherited["public_files"])
    tasks: list[dict[str, Any]] = []
    ordinal = 0
    for seed in R4_SEEDS:
        for dgp in R4_DGPS:
            relative = f"replays/pass_1/seed_{seed}/dgp_{dgp}/canonical150.csv"
            row = public_files[ordinal * 3]
            assert row[0] == relative
            tasks.append(
                {
                    "task_ordinal": ordinal,
                    "seed": seed,
                    "dgp": dgp,
                    "canonical_relative": relative,
                    "expected_raw_sha256": row[1],
                }
            )
            ordinal += 1
    return {
        "r4_public_files": public_files,
        "r4_public_files_sha256": R4_PUBLIC_FILES_SHA256,
        "task_manifest": tasks,
        "task_manifest_sha256": R4_TASK_MANIFEST_SHA256,
    }


def _fixture_verified_capability(
    run_id: str = "20260821T235900",
) -> VerifiedProductionCapability:
    tasks = derive_exact_r4_task_manifest(_exact_input_closure())
    envelope = canonical_json_bytes({"fixture_run_id": run_id})
    identity = hashlib.sha256(envelope).hexdigest()
    payload = MappingProxyType(
        {
            "run_id": run_id,
            "session_nonce": hashlib.sha256((run_id + ":session").encode()).hexdigest(),
            "custodian_consumption_id": hashlib.sha256(
                (run_id + ":custody").encode()
            ).hexdigest(),
            "task_manifest_sha256": R4_TASK_MANIFEST_SHA256,
        }
    )
    return VerifiedProductionCapability(
        payload=payload,
        envelope_bytes=envelope,
        capability_identity_sha256=identity,
        signed_message_sha256=hashlib.sha256(b"fixture-message" + envelope).hexdigest(),
        tasks=tasks,
        project_root=PROJECT_ROOT,
    )


def _grant_identities() -> list[str]:
    return [hashlib.sha256(f"fixture-grant:{slot}".encode()).hexdigest() for slot in range(32)]


def _new_store(tmp_path: Path) -> _DurableAuthorityStore:
    return _DurableAuthorityStore._open_isolated_fixture(  # noqa: SLF001
        tmp_path / "consumption.sqlite3"
    )


def test_contract_pins_production_key_and_closes_exact_v10_findings() -> None:
    payload = contract_payload()
    trust = payload["production_trust"]
    assert trust["public_key_hex"] == PRODUCTION_PUBLIC_KEY_HEX
    assert trust["public_key_raw_sha256"] == PRODUCTION_PUBLIC_KEY_RAW_SHA256
    assert trust["private_key_present"] is False
    assert trust["signing_api_present"] is False
    assert payload["repair_scope"]["closed_findings_only"] == V10_AUDIT_BINDING[
        "finding_ids"
    ]
    assert payload["authority"]["real_fit"] is False
    assert payload["authority"]["real_prediction"] is False


def test_fixture_ed25519_is_valid_but_not_production_authority() -> None:
    message = FIXTURE_CAPABILITY_DOMAIN + b"fixture-only"
    public_key, signature = _fixture_sign(message)
    verify_ed25519_strict(public_key, message, signature)
    assert public_key.hex() != PRODUCTION_PUBLIC_KEY_HEX
    assert FIXTURE_CAPABILITY_DOMAIN != PRODUCTION_CAPABILITY_DOMAIN


@pytest.mark.parametrize(
    "content",
    (
        b'{ "payload":{},"signature_hex":""}',
        b'{"payload":{},"payload":{},"signature_hex":""}',
        b'{"signature_hex":"","payload":{}}\n',
    ),
)
def test_alternate_or_duplicate_production_envelope_fails_before_authority(
    content: bytes,
) -> None:
    with pytest.raises(AuthorityError):
        verify_production_capability(content)


def test_fixture_domain_key_and_signature_are_rejected_by_production() -> None:
    payload = {
        "schema_version": "expected_pe.hofs_v11.fixture_capability.v1",
        "domain_hex": FIXTURE_CAPABILITY_DOMAIN.hex(),
    }
    _public_key, signature = _fixture_sign(
        FIXTURE_CAPABILITY_DOMAIN + canonical_json_bytes(payload)
    )
    envelope = canonical_json_bytes(
        {"payload": payload, "signature_hex": signature.hex()}
    )
    with pytest.raises(AuthorityError):
        verify_production_capability(envelope)


def test_exact_r4_manifest_is_derived_and_caller_subset_or_path_is_rejected() -> None:
    closure = _exact_input_closure()
    tasks = derive_exact_r4_task_manifest(closure)
    assert len(tasks) == R4_TASK_COUNT
    assert hashlib.sha256(
        canonical_json_bytes([dict(task) for task in tasks])
    ).hexdigest() == R4_TASK_MANIFEST_SHA256
    assert tasks[0]["canonical_relative"].endswith("dgp_A/canonical150.csv")
    assert tasks[-1]["canonical_relative"].endswith("dgp_J/canonical150.csv")
    for attack in ("subset", "traversal", "order", "task"):
        attacked = copy.deepcopy(closure)
        if attack == "subset":
            attacked["r4_public_files"].pop()
        elif attack == "traversal":
            attacked["r4_public_files"][0][0] = "../canonical150.csv"
        elif attack == "order":
            attacked["r4_public_files"][0:2] = reversed(
                attacked["r4_public_files"][0:2]
            )
        else:
            attacked["task_manifest"].pop()
        with pytest.raises(AuthorityError):
            derive_exact_r4_task_manifest(attacked)


def test_production_verifier_and_launcher_expose_no_caller_trust_pins() -> None:
    assert tuple(inspect.signature(verify_production_capability).parameters) == (
        "envelope_bytes",
    )
    assert tuple(
        inspect.signature(launcher_v11.run_authorized_prediction_only).parameters
    ) == ("capability_envelope_bytes",)
    assert tuple(inspect.signature(ProductionCustodyClient).parameters) == ()
    parser = launcher_v11._parser()  # noqa: SLF001
    option_strings = {
        option
        for action in parser._actions  # noqa: SLF001
        for option in action.option_strings
    }
    assert option_strings == {"-h", "--help", "--check", "--run"}


def test_fixture_service_response_and_worker_grant_domains_are_rejected() -> None:
    identity = "a" * 64
    now = time.time_ns() // 1_000_000_000
    grant_payload = {
        "schema_version": "expected_pe.hofs_v11.production_worker_grant.v1",
        "domain_hex": FIXTURE_WORKER_GRANT_DOMAIN.hex(),
        "capability_identity_sha256": identity,
        "worker_slot": 0,
        "grant_nonce": "b" * 64,
        "issued_at_unix": now - 1,
        "expires_at_unix": now + 60,
        "one_shot": True,
    }
    _public, grant_signature = _fixture_sign(
        FIXTURE_WORKER_GRANT_DOMAIN + canonical_json_bytes(grant_payload)
    )
    grant = canonical_json_bytes(
        {"payload": grant_payload, "signature_hex": grant_signature.hex()}
    )
    with pytest.raises(CustodyError):
        verify_production_worker_grant(
            grant,
            capability_identity_sha256=identity,
        )

    response_payload = {
        "schema_version": "expected_pe.hofs_v11.production_custody_response.v1",
        "domain_hex": FIXTURE_CUSTODY_HANDSHAKE_DOMAIN.hex(),
        "request_sha256": "c" * 64,
        "challenge": "d" * 64,
        "operation": "ATTACK",
        "capability_identity_sha256": identity,
        "service_time_unix": now,
        "status": "PASS_FORGED_FIXTURE",
        "receipt": {},
    }
    _public, response_signature = _fixture_sign(
        FIXTURE_CUSTODY_HANDSHAKE_DOMAIN + canonical_json_bytes(response_payload)
    )
    response = canonical_json_bytes(
        {"payload": response_payload, "signature_hex": response_signature.hex()}
    )
    with pytest.raises(CustodyError):
        ProductionCustodyClient._verify_response(  # noqa: SLF001
            response,
            request_sha256="c" * 64,
            challenge="d" * 64,
            operation="ATTACK",
            capability_identity_sha256=identity,
        )
    assert FIXTURE_CUSTODY_HANDSHAKE_DOMAIN != PRODUCTION_CUSTODY_HANDSHAKE_DOMAIN
    assert FIXTURE_WORKER_GRANT_DOMAIN != PRODUCTION_WORKER_GRANT_DOMAIN


def test_durable_store_rejects_separate_launch_replay(tmp_path: Path) -> None:
    capability = _fixture_verified_capability()
    grants = _grant_identities()
    first = _new_store(tmp_path)
    claim = first.claim_full_schedule(
        capability,
        worker_grant_identity_sha256s=grants,
    )
    assert claim["success"] is False
    reopened = _new_store(tmp_path)
    with pytest.raises(CustodyError, match="already claimed"):
        reopened.claim_full_schedule(
            capability,
            worker_grant_identity_sha256s=grants,
        )
    state = reopened.inspect(capability.capability_identity_sha256)
    assert state["state"] == "ACTIVE_INCOMPLETE"
    assert state["production_pass"] is False
    assert state["denial_count"] == 1


def test_partial_and_crashed_schedule_never_reports_success(tmp_path: Path) -> None:
    capability = _fixture_verified_capability("20260821T235901")
    grants = _grant_identities()
    store = _new_store(tmp_path)
    store.claim_full_schedule(capability, worker_grant_identity_sha256s=grants)
    store.claim_worker_grant(
        capability_identity_sha256=capability.capability_identity_sha256,
        worker_grant_identity_sha256=grants[0],
        worker_slot=0,
        worker_pid=1234,
    )
    store.claim_task_once(
        capability_identity_sha256=capability.capability_identity_sha256,
        task=capability.tasks[0],
        worker_slot=0,
        worker_pid=1234,
    )
    with pytest.raises(CustodyError, match="partial or crashed"):
        store.finish_full_schedule(
            capability_identity_sha256=capability.capability_identity_sha256
        )
    reopened = _new_store(tmp_path)
    state = reopened.inspect(capability.capability_identity_sha256)
    assert state["task_state_counts"] == {"IN_PROGRESS": 1, "PENDING": 49}
    assert state["backend_complete"] is False
    assert state["production_pass"] is False


def test_exact_full_schedule_is_durable_but_backend_cannot_sign_pass(
    tmp_path: Path,
) -> None:
    capability = _fixture_verified_capability("20260821T235902")
    grants = _grant_identities()
    store = _new_store(tmp_path)
    store.claim_full_schedule(capability, worker_grant_identity_sha256s=grants)
    for slot in range(PINNED_OUTER_WORKERS):
        store.claim_worker_grant(
            capability_identity_sha256=capability.capability_identity_sha256,
            worker_grant_identity_sha256=grants[slot],
            worker_slot=slot,
            worker_pid=2000 + slot,
        )
    for ordinal, task in enumerate(capability.tasks):
        slot = ordinal % PINNED_OUTER_WORKERS
        store.claim_task_once(
            capability_identity_sha256=capability.capability_identity_sha256,
            task=task,
            worker_slot=slot,
            worker_pid=2000 + slot,
        )
        store.complete_task(
            capability_identity_sha256=capability.capability_identity_sha256,
            task_ordinal=ordinal,
            worker_slot=slot,
            worker_pid=2000 + slot,
        )
    receipt = store.finish_full_schedule(
        capability_identity_sha256=capability.capability_identity_sha256
    )
    assert receipt["production_pass"] is False
    assert "AWAITS_SIGNED_RESPONSE" in receipt["status"]
    state = _new_store(tmp_path).inspect(capability.capability_identity_sha256)
    assert state["backend_complete"] is True
    assert state["production_pass"] is False
    assert state["task_state_counts"] == {"COMPLETE": 50}


def test_concurrent_duplicate_task_has_exactly_one_winner(tmp_path: Path) -> None:
    capability = _fixture_verified_capability("20260821T235903")
    grants = _grant_identities()
    store = _new_store(tmp_path)
    store.claim_full_schedule(capability, worker_grant_identity_sha256s=grants)
    store.claim_worker_grant(
        capability_identity_sha256=capability.capability_identity_sha256,
        worker_grant_identity_sha256=grants[0],
        worker_slot=0,
        worker_pid=3333,
    )

    def attack() -> str:
        try:
            store.claim_task_once(
                capability_identity_sha256=capability.capability_identity_sha256,
                task=capability.tasks[0],
                worker_slot=0,
                worker_pid=3333,
            )
            return "won"
        except CustodyError:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [future.result() for future in [executor.submit(attack) for _ in range(2)]]
    assert sorted(outcomes) == ["denied", "won"]


def test_deleting_fixture_db_does_not_create_production_pass(tmp_path: Path) -> None:
    capability = _fixture_verified_capability("20260821T235904")
    grants = _grant_identities()
    store = _new_store(tmp_path)
    store.claim_full_schedule(capability, worker_grant_identity_sha256s=grants)
    database = store.database_path
    database.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    recreated = _new_store(tmp_path)
    receipt = recreated.claim_full_schedule(
        capability,
        worker_grant_identity_sha256s=grants,
    )
    assert receipt["success"] is False
    assert ProductionCustodyClient()._endpoint == PRODUCTION_CUSTODY_ENDPOINT  # noqa: SLF001
    assert str(database.parent).casefold() not in PRODUCTION_CUSTODY_ENDPOINT.casefold()


def _run_fresh(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(PINNED_PYTHON), "-c", source],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


def test_fresh_process_preloaded_numpy_fails_inside_final_installer() -> None:
    source = """
import os
os.environ.update({'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','NUMEXPR_NUM_THREADS':'1','CUDA_VISIBLE_DEVICES':'-1'})
import numpy
from multiprocessing import Pipe
from research.model_zoo.hierarchical_observable_fair_value_state_v11.lifecycle import _install_worker_from_inherited_channel
r,s=Pipe(False)
try:
    _install_worker_from_inherited_channel(r)
except Exception as e:
    print(type(e).__name__, str(e))
else:
    raise SystemExit(9)
finally:
    s.close()
"""
    result = _run_fresh(source)
    assert result.returncode == 0, result.stderr
    assert "forbidden numeric module preloaded before installer" in result.stdout


def test_fresh_process_forged_pipe_and_initializer_retry_fail_closed() -> None:
    source = """
import os
os.environ.update({'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','NUMEXPR_NUM_THREADS':'1','CUDA_VISIBLE_DEVICES':'-1'})
from multiprocessing import Pipe
from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import PRODUCTION_INHERITED_CHANNEL_DOMAIN,canonical_json_bytes
from research.model_zoo.hierarchical_observable_fair_value_state_v11.lifecycle import _install_worker_from_inherited_channel
r,s=Pipe(False)
s.send_bytes(canonical_json_bytes({'schema_version':'expected_pe.hofs_v11.inherited_worker_channel.v1','domain_hex':PRODUCTION_INHERITED_CHANNEL_DOMAIN.hex(),'canonical_capability_envelope_hex':b'{}'.hex(),'custodian_signed_worker_grant_hex':b'{}'.hex()}));s.close()
try:
    _install_worker_from_inherited_channel(r)
except Exception as first:
    print(type(first).__name__)
else:
    raise SystemExit(9)
r2,s2=Pipe(False)
try:
    _install_worker_from_inherited_channel(r2)
except Exception as second:
    print(str(second))
else:
    raise SystemExit(10)
finally:
    s2.close()
"""
    result = _run_fresh(source)
    assert result.returncode == 0, result.stderr
    assert "AuthorityError" in result.stdout
    assert "one-attempt per PID" in result.stdout


def test_fresh_process_substitute_db_known_secret_and_direct_task_are_insufficient() -> None:
    source = """
import inspect,tempfile
from pathlib import Path
from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import ProductionCustodyClient,_DurableAuthorityStore
from research.model_zoo.hierarchical_observable_fair_value_state_v11.lifecycle import _claim_exact_task_before_downstream,_install_worker_from_inherited_channel
p=Path(tempfile.mkdtemp())/'consumption.sqlite3'
store=_DurableAuthorityStore._open_isolated_fixture(p)
client=ProductionCustodyClient()
assert str(p.parent).casefold() not in client._endpoint.casefold()
assert tuple(inspect.signature(_install_worker_from_inherited_channel).parameters)==('channel',)
try:
    _claim_exact_task_before_downstream(0)
except Exception as e:
    print(type(e).__name__,str(e))
else:
    raise SystemExit(11)
"""
    result = _run_fresh(source)
    assert result.returncode == 0, result.stderr
    assert "direct lifecycle entry lacks installed authority" in result.stdout


def test_package_does_not_export_worker_or_custody_lifecycle() -> None:
    import research.model_zoo.hierarchical_observable_fair_value_state_v11 as package

    forbidden = {
        "ProductionCustodyClient",
        "_install_worker_from_inherited_channel",
        "_claim_exact_task_before_downstream",
        "_complete_exact_task_after_downstream",
        "_DurableAuthorityStore",
    }
    assert forbidden.isdisjoint(package.__all__)
    assert all(not hasattr(package, name) for name in forbidden)


def test_source_audit_and_check_only_remain_score_free() -> None:
    audit = run_source_audit_v11(PROJECT_ROOT)
    assert audit["passed"] is True
    assert audit["production_private_key_literal_hits"] == []
    assert audit["production_signing_api_hits"] == []
    check = launcher_v11.check_only()
    assert check["run_mode_present"] is True
    assert check["production_capability_present"] is False
    assert check["custody_connection_attempt_count"] == 0
    assert check["public_input_open_count"] == 0
    assert check["real_fit_count"] == 0
    assert check["real_prediction_count"] == 0
    assert check["registry_mutation_count"] == 0


def test_production_run_is_not_invoked_by_tests() -> None:
    assert "run_authorized_prediction_only(" in Path(launcher_v11.__file__).read_text(
        "utf-8"
    )
    assert not any(
        path.name.startswith(
            "model_zoo_hierarchical_observable_fair_value_state_v11_"
            "dgp_r4_prediction_only_"
        )
        for path in (PROJECT_ROOT / "outputs").iterdir()
    )
