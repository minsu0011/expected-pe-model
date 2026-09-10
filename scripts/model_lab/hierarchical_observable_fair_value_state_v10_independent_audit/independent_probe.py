"""Independent score-free adversarial probe for the frozen H-OFS V10 design.

This probe never opens public model inputs, truth, qualification, heldout,
evaluator, score, prediction, or registry artifacts.  It exercises only the
frozen authority/lifecycle surface with the builder's documented test fixture.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Mapping


def _resolve_project_root() -> Path:
    script = Path(__file__).resolve()
    candidates = [Path.cwd().resolve()]
    candidates.extend(parent.resolve() for parent in script.parents)
    sentinel = Path(
        "research/model_zoo/hierarchical_observable_fair_value_state_v10/"
        "contracts.py"
    )
    matches: list[Path] = []
    for candidate in candidates:
        if (candidate / sentinel).is_file() and candidate not in matches:
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError("independent V10 probe project root is ambiguous or absent")
    return matches[0]


PROJECT_ROOT = _resolve_project_root()
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _load_fixture_module() -> Any:
    path = (
        PROJECT_ROOT
        / "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py"
    )
    spec = importlib.util.spec_from_file_location("independent_hofs_v10_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the frozen V10 fixture source")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _ReplayLedger:
    """Adversarial duck-typed ledger that returns valid-looking replay receipts."""

    def __init__(self, attestation: Mapping[str, Any]) -> None:
        self._attestation = copy.deepcopy(dict(attestation))
        self._sequence = 0

    def attestation(self) -> dict[str, Any]:
        return copy.deepcopy(self._attestation)

    def consume(self, **arguments: Any) -> dict[str, Any]:
        self._sequence += 1
        return {
            "schema_version": "expected_pe.hofs_v10.task_consumption.v1",
            "status": "CONSUMED_ONCE_BEFORE_DOWNSTREAM",
            "run_id": arguments["run_id"],
            "session_nonce": arguments["session_nonce"],
            "custodian_consumption_id": arguments["custodian_consumption_id"],
            "task_ordinal": arguments["task_ordinal"],
            "task_binding_sha256": arguments["task_binding_sha256"],
            "consumer_pid": arguments["consumer_pid"],
            "global_consumption_sequence": self._sequence,
        }


def _expected_ledger_attestation(verified: Any, task_count: int) -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.hofs_v10.shared_task_ledger.v1",
        "status": "ACTIVE_SIGNED_ONE_SHOT_TASK_LEDGER",
        "capability_envelope_raw_sha256": verified.envelope_raw_sha256,
        "run_id": verified.run_id,
        "session_nonce": verified.session_nonce,
        "custodian_consumption_id": verified.custodian_consumption_id,
        "task_manifest_sha256": verified.task_manifest_sha256,
        "task_count": task_count,
        "one_shot": True,
    }


def _forged_guard(session_nonce: str, contracts: Any) -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.hofs_v10.actual_initializer_guard.v1",
        "status": "PASS_ACTUAL_ABSENCE_GUARD_IN_INITIALIZER",
        "worker_pid": os.getpid(),
        "python_version": contracts.PINNED_PYTHON_VERSION,
        "python_executable": contracts.PINNED_PYTHON_EXECUTABLE,
        "python_executable_sha256": contracts.PINNED_PYTHON_EXECUTABLE_SHA256,
        "logical_cpu_count": 32,
        "outer_workers": contracts.PINNED_OUTER_WORKERS,
        "inner_threads": 1,
        "affinity_mask_hex": f"0x{contracts.PINNED_AFFINITY_MASK:08X}",
        "thread_environment": [list(value) for value in contracts.PINNED_THREAD_ENVIRONMENT],
        "gpu_environment": [list(value) for value in contracts.PINNED_GPU_ENVIRONMENT],
        "absence_guard_observed_modules": [],
        "session_nonce": session_nonce,
        "initializer_count_per_pid": 1,
        "absence_guard_count_per_pid": 1,
    }


def run_probe() -> dict[str, Any]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (
        CapabilityError,
        contract_sha256,
        verify_capability_envelope,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (
        contracts,
        lifecycle,
    )
    from scripts.model_lab.hierarchical_observable_fair_value_state_v10 import (
        prediction_launcher as launcher,
    )

    fixture = _load_fixture_module()
    tasks = fixture._fixture_tasks(2)
    envelope, public_key, policy, tasks = fixture._fixture_authority(tasks=tasks)
    parsed = json.loads(envelope.decode("ascii"))
    signed_payload = parsed["payload"]
    actual_wall_clock = int(time.time())
    verified = verify_capability_envelope(
        envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=fixture._FIXTURE_NOW,
    )
    noncanonical_envelope = json.dumps(
        parsed,
        ensure_ascii=True,
        sort_keys=False,
        indent=1,
        allow_nan=False,
    ).encode("ascii")
    noncanonical_verified = verify_capability_envelope(
        noncanonical_envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=fixture._FIXTURE_NOW,
    )

    wrong_pin_rejected = False
    try:
        wrong_policy = type(policy)(
            **{**policy.__dict__, "public_key_raw_sha256": "9" * 64}
        )
        verify_capability_envelope(
            envelope,
            public_key=public_key,
            policy=wrong_policy,
            task_bindings=tasks,
            now_unix=fixture._FIXTURE_NOW,
        )
    except CapabilityError:
        wrong_pin_rejected = True

    # The same signed capability is accepted by two fresh Manager ledgers, and
    # each launch is also allowed to consume only one task from a signed
    # two-task manifest.
    first_launch = launcher.run_score_free_lifecycle_benchmark(
        envelope_bytes=envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=fixture._FIXTURE_NOW,
        worker_count=1,
        task_count=2,
    )
    second_launch = launcher.run_score_free_lifecycle_benchmark(
        envelope_bytes=envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=fixture._FIXTURE_NOW,
        worker_count=1,
        task_count=1,
    )

    # The honest in-memory ledger is atomic only within one live instance.
    honest_ledger, honest_arguments = fixture._fixture_ledger()

    def honest_attempt() -> str:
        try:
            honest_ledger.consume(**honest_arguments)
        except RuntimeError:
            return "REJECTED"
        return "CONSUMED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        honest_outcomes = sorted(executor.map(lambda _index: honest_attempt(), range(2)))

    # Import NumPy deliberately.  The real guard rejects it, but a caller can
    # import the module-private marker and installer, submit a forged receipt,
    # and inject a duck-typed ledger that accepts the same task repeatedly.
    import numpy  # noqa: F401, PLC0415

    actual_preloaded_guard_rejected = False
    try:
        launcher.actual_initializer_absence_guard(verified.session_nonce)
    except RuntimeError:
        actual_preloaded_guard_rejected = True
    forged = _forged_guard(verified.session_nonce, contracts)
    replay_ledger = _ReplayLedger(_expected_ledger_attestation(verified, len(tasks)))
    lifecycle._WORKER_STATE = None
    none_guard_rejected = False
    try:
        lifecycle._install_worker_state(
            initializer_marker=lifecycle._INITIALIZER_MARKER,
            guard_receipt=None,
            envelope_bytes=envelope,
            public_key=public_key,
            policy=policy,
            task_bindings=tasks,
            now_unix=fixture._FIXTURE_NOW,
            shared_ledger=replay_ledger,
            first_task_barrier=None,
        )
    except CapabilityError:
        none_guard_rejected = True
    initializer_receipt = lifecycle._install_worker_state(
        initializer_marker=lifecycle._INITIALIZER_MARKER,
        guard_receipt=forged,
        envelope_bytes=envelope,
        public_key=public_key,
        policy=policy,
        task_bindings=tasks,
        now_unix=fixture._FIXTURE_NOW,
        shared_ledger=replay_ledger,
        first_task_barrier=None,
    )
    first_direct = lifecycle._authorize_and_consume_task(
        run_id=policy.run_id,
        now_unix=fixture._FIXTURE_NOW,
        **tasks[0],
    )
    second_direct = lifecycle._authorize_and_consume_task(
        run_id=policy.run_id,
        now_unix=fixture._FIXTURE_NOW,
        **tasks[0],
    )
    lifecycle._WORKER_STATE = None

    # The manifest validator accepts parent traversal because it validates only
    # the filename suffix; no file is opened by this probe.
    traversal_task = copy.deepcopy(tasks[0])
    traversal_task["canonical_relative"] = (
        "../../outside/dgp_A/canonical150.csv"
    )
    traversal_task["expected_raw_sha256"] = _sha256(
        traversal_task["canonical_relative"].encode("ascii")
    )
    traversal_envelope, traversal_key, traversal_policy, traversal_tasks = (
        fixture._fixture_authority(tasks=[traversal_task])
    )
    traversal_verified = verify_capability_envelope(
        traversal_envelope,
        public_key=traversal_key,
        policy=traversal_policy,
        task_bindings=traversal_tasks,
        now_unix=fixture._FIXTURE_NOW,
    )

    return {
        "schema_version": "expected_pe.hofs_v10.independent_probe.v1",
        "status": "PASS_INDEPENDENT_SCORE_FREE_FAILURE_REPRODUCTIONS",
        "audited_design_contract_sha256": contract_sha256(),
        "capability_envelope_raw_sha256": verified.envelope_raw_sha256,
        "authority_root_probe": {
            "caller_selected_design_pin": policy.design_contract_sha256,
            "actual_design_pin": contract_sha256(),
            "caller_selected_design_pin_differs_from_actual": (
                policy.design_contract_sha256 != contract_sha256()
            ),
            "caller_selected_audit_hashes_accepted": True,
            "fixture_key_and_fixture_signature_accepted_by_gate": True,
            "wrong_key_pin_alone_rejected": wrong_pin_rejected,
            "trusted_external_policy_or_pin_loader_present": False,
            "noncanonical_envelope_encoding_accepted": True,
            "canonical_and_noncanonical_raw_hashes_differ": (
                verified.envelope_raw_sha256
                != noncanonical_verified.envelope_raw_sha256
            ),
            "canonical_and_noncanonical_signed_message_hashes_equal": (
                verified.signed_message_sha256
                == noncanonical_verified.signed_message_sha256
            ),
        },
        "clock_probe": {
            "actual_wall_clock_unix": actual_wall_clock,
            "signed_issued_at_unix": signed_payload["issued_at_unix"],
            "signed_expires_at_unix": signed_payload["expires_at_unix"],
            "caller_supplied_now_unix": fixture._FIXTURE_NOW,
            "actual_wall_clock_inside_signed_window": (
                signed_payload["issued_at_unix"]
                <= actual_wall_clock
                < signed_payload["expires_at_unix"]
            ),
            "accepted_using_caller_supplied_time": True,
        },
        "fresh_ledger_replay_probe": {
            "same_envelope_hash_both_launches": True,
            "signed_task_manifest_count": len(tasks),
            "first_launch_submitted_task_count": first_launch["task_count"],
            "second_launch_submitted_task_count": second_launch["task_count"],
            "first_launch_status": first_launch["status"],
            "second_launch_status": second_launch["status"],
            "same_capability_accepted_by_two_fresh_ledgers": True,
            "partial_manifest_launch_accepted": True,
            "durable_or_external_consumption_store_used": False,
        },
        "within_instance_atomicity_probe": {
            "honest_concurrent_outcomes": honest_outcomes,
            "exactly_one_winner": honest_outcomes == ["CONSUMED", "REJECTED"],
        },
        "initializer_and_duck_ledger_probe": {
            "numpy_preloaded": "numpy" in sys.modules,
            "actual_guard_rejected_preloaded_numpy": actual_preloaded_guard_rejected,
            "none_guard_rejected": none_guard_rejected,
            "module_private_marker_directly_importable": True,
            "module_private_installer_directly_importable": True,
            "forged_guard_installer_status": initializer_receipt["status"],
            "forged_guard_accepted_with_numpy_preloaded": True,
            "duck_typed_replay_ledger_accepted": True,
            "same_task_first_status": first_direct["status"],
            "same_task_second_status": second_direct["status"],
            "same_task_worker_sequences": [
                first_direct["worker_task_sequence_number"],
                second_direct["worker_task_sequence_number"],
            ],
            "same_task_replay_accepted": True,
        },
        "task_path_probe": {
            "accepted_relative": traversal_verified.task_bindings[0][
                "canonical_relative"
            ],
            "contains_parent_traversal": True,
            "accepted_by_signed_manifest_validator": True,
            "file_opened": False,
        },
        "execution_boundary": {
            "launcher_run_mode_invoked": False,
            "downstream_callback_invocation_count": 0,
            "public_input_open_count": 0,
            "truth_qualification_heldout_evaluator_score_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "registry_or_champion_mutation_count": 0,
        },
    }


def main() -> int:
    print(
        json.dumps(
            run_probe(),
            ensure_ascii=True,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    raise SystemExit(main())
