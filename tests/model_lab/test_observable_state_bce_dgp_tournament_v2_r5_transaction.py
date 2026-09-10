"""Adversarial fixture-only tests for the R5 exactly-once transaction."""

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.artifacts import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r5.transaction import (
    FAULT_POINTS,
    R5TransactionError,
    TransactionRequest,
    _build_plan,
    _journal,
    _verify_plan,
    fixture_registry_payload,
)


ROOT = Path(__file__).resolve().parents[2]
PINNED = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
WORKER = ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r5/"
    "transaction_fixture_worker.py"
)
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="LockFileEx is Windows-only")


def _fixture(tmp_path: Path) -> tuple[Path, str]:
    (tmp_path / ".r5_transaction_test_capability").write_text(
        "fixture-only\n", encoding="ascii"
    )
    registry = tmp_path / "fixture_registry.json"
    registry.write_bytes(canonical_json_bytes(fixture_registry_payload()))
    return registry, sha256_file(registry)


def _command(root: Path, transaction: str, lane: str, before: str) -> list[str]:
    return [str(PINNED), "-B", str(WORKER), str(root), transaction, lane, before]


def _environment(
    *, crash_at: str | None = None, hold_after_marker: float | None = None
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT), str(ROOT / "src")))
    environment.pop("R5_TEST_CRASH_AT", None)
    environment.pop("R5_TEST_HOLD_AFTER_LEGACY_MARKER_SECONDS", None)
    if crash_at is not None:
        environment["R5_TEST_CRASH_AT"] = crash_at
    if hold_after_marker is not None:
        environment["R5_TEST_HOLD_AFTER_LEGACY_MARKER_SECONDS"] = str(
            hold_after_marker
        )
    return environment


def _run(
    root: Path,
    transaction: str,
    lane: str,
    before: str,
    *,
    crash_at: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(root, transaction, lane, before),
        cwd=ROOT,
        env=_environment(crash_at=crash_at),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


def _request(transaction: str, lane: str, before: str) -> TransactionRequest:
    return TransactionRequest(
        transaction_id=transaction,
        lane_id=lane,
        expected_registry_raw_sha256=before,
        payload={"fixed": "fixture", "lane": lane},
    )


def _plan(raw: bytes, transaction: str, lane: str) -> dict[str, object]:
    before = sha256_bytes(raw)
    return _build_plan(raw, _request(transaction, lane, before), "2026-08-21T00:00:00+00:00")


def test_journal_before_after_exact_one_append_cross_bound(tmp_path: Path) -> None:
    registry, before = _fixture(tmp_path)
    raw = registry.read_bytes()
    request = _request("txn_bound", "lane_bound", before)
    plan = _build_plan(raw, request, "2026-08-21T00:00:00+00:00")
    _verify_plan(plan, request)
    before_payload = json.loads(
        base64.b64decode(plan["registry_before_base64"], validate=True)
    )
    after_payload = json.loads(
        base64.b64decode(plan["registry_after_base64"], validate=True)
    )
    assert after_payload["entries"] == [*before_payload["entries"], plan["entry"]]
    assert plan["registry_after_entry_count"] == plan["registry_before_entry_count"] + 1

    unrelated = _plan(raw, "txn_unrelated", "lane_unrelated")
    attacked_after = fixture_registry_payload(
        [plan["entry"], unrelated["entry"]]
    )
    attacked_raw = canonical_json_bytes(attacked_after)
    attacked = copy.deepcopy(plan)
    attacked.update(
        {
            "registry_after_base64": base64.b64encode(attacked_raw).decode("ascii"),
            "registry_raw_after": sha256_bytes(attacked_raw),
            "registry_after_semantic_sha256": attacked_after["registry_sha256"],
            "registry_after_entry_count": 2,
        }
    )
    with pytest.raises(R5TransactionError):
        _verify_plan(attacked, request)
    for field in (
        "request_semantic_sha256",
        "request_payload_semantic_sha256",
        "transaction_context_semantic_sha256",
        "entry_sha256",
        "receipt_raw_sha256",
        "receipt_semantic_sha256",
        "registry_raw_before",
        "registry_raw_after",
    ):
        wrong_hash = copy.deepcopy(plan)
        wrong_hash[field] = "0" * 64
        with pytest.raises(R5TransactionError, match="differs"):
            _verify_plan(wrong_hash, request)


def test_hash_equal_recovery_membership_receipt_exact(tmp_path: Path) -> None:
    registry, before = _fixture(tmp_path)
    raw = registry.read_bytes()
    target = _plan(raw, "txn_target", "lane_target")
    unrelated = _plan(raw, "txn_unrelated", "lane_unrelated")
    forged = copy.deepcopy(unrelated)
    forged["request"] = target["request"]
    forged["request_semantic_sha256"] = target["request_semantic_sha256"]
    forged["request_payload_semantic_sha256"] = target[
        "request_payload_semantic_sha256"
    ]
    (tmp_path / "journal_txn_target.json").write_bytes(
        canonical_json_bytes(_journal(forged, "PREPARED"))
    )
    unrelated_after = base64.b64decode(
        unrelated["registry_after_base64"], validate=True
    )
    registry.write_bytes(unrelated_after)
    runtime = tmp_path / "runtime_txn_target"
    runtime.mkdir()
    unrelated_receipt = base64.b64decode(
        unrelated["receipt_base64"], validate=True
    )
    (runtime / "RESERVATION_RECEIPT.json").write_bytes(unrelated_receipt)

    attacked_hash = sha256_file(registry)
    assert attacked_hash == forged["registry_raw_after"]
    rejected = _run(tmp_path, "txn_target", "lane_target", before)
    assert rejected.returncode == 2
    assert sha256_file(registry) == attacked_hash
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert [entry["transaction_id"] for entry in payload["entries"]] == [
        "txn_unrelated"
    ]
    assert json.loads(rejected.stdout)["error"]


def test_forged_unrelated_prepositioned_journal_receipt_rejected(
    tmp_path: Path,
) -> None:
    registry, before = _fixture(tmp_path)
    raw = registry.read_bytes()
    target_request = _request("txn_prepositioned", "lane_prepositioned", before)
    target = _build_plan(
        raw, target_request, "2026-08-21T00:00:00+00:00"
    )
    unrelated = _plan(raw, "txn_other", "lane_other")
    (tmp_path / "journal_txn_prepositioned.json").write_bytes(
        canonical_json_bytes(_journal(target, "PREPARED"))
    )
    runtime = tmp_path / "runtime_txn_prepositioned"
    runtime.mkdir()
    prepositioned = base64.b64decode(
        unrelated["receipt_base64"], validate=True
    )
    receipt_path = runtime / "RESERVATION_RECEIPT.json"
    receipt_path.write_bytes(prepositioned)

    rejected = _run(tmp_path, "txn_prepositioned", "lane_prepositioned", before)
    assert rejected.returncode == 2
    retry = _run(tmp_path, "txn_prepositioned", "lane_prepositioned", before)
    assert retry.returncode == 2
    assert receipt_path.read_bytes() == prepositioned
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert [entry["transaction_id"] for entry in payload["entries"]] == [
        "txn_prepositioned"
    ]


@pytest.mark.parametrize("fault_point", FAULT_POINTS)
def test_fault_after_each_durable_phase_recovers_exactly_once(
    tmp_path: Path, fault_point: str
) -> None:
    registry, before = _fixture(tmp_path)
    crashed = _run(tmp_path, "txn_same", "lane_same", before, crash_at=fault_point)
    assert crashed.returncode == 93, (fault_point, crashed.stdout, crashed.stderr)
    recovered = _run(tmp_path, "txn_same", "lane_same", before)
    assert recovered.returncode == 0, (fault_point, recovered.stdout, recovered.stderr)
    retried = _run(tmp_path, "txn_same", "lane_same", before)
    assert retried.returncode == 0
    assert json.loads(recovered.stdout) == json.loads(retried.stdout)
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert len(payload["entries"]) == 1
    assert payload["entries"][0]["transaction_id"] == "txn_same"
    runtime = tmp_path / "runtime_txn_same"
    assert {path.name for path in runtime.iterdir()} == {"RESERVATION_RECEIPT.json"}
    journal = json.loads((tmp_path / "journal_txn_same.json").read_text("utf-8"))
    assert journal["phase"] == "COMPLETED"
    assert not (tmp_path / "fixture_registry.json.lock").exists()
    assert not list(tmp_path.glob("*.pending"))


def test_same_transaction_32_processes_return_one_entry_one_receipt(
    tmp_path: Path,
) -> None:
    registry, before = _fixture(tmp_path)
    processes = [
        subprocess.Popen(
            _command(tmp_path, "txn_32", "lane_32", before),
            cwd=ROOT,
            env=_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(32)
    ]
    completed = [process.communicate(timeout=120) + (process.returncode,) for process in processes]
    assert all(returncode == 0 for _stdout, _stderr, returncode in completed), completed
    receipts = {stdout.strip() for stdout, _stderr, _returncode in completed}
    assert len(receipts) == 1
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert len(payload["entries"]) == 1
    assert len(list((tmp_path / "runtime_txn_32").iterdir())) == 1


def test_distinct_lane_same_snapshot_one_success_one_clean_fail_no_orphan(
    tmp_path: Path,
) -> None:
    registry, before = _fixture(tmp_path)
    processes = [
        subprocess.Popen(
            _command(tmp_path, transaction, lane, before),
            cwd=ROOT,
            env=_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for transaction, lane in (("txn_a", "lane_a"), ("txn_b", "lane_b"))
    ]
    completed = [process.communicate(timeout=60) + (process.returncode,) for process in processes]
    assert sorted(returncode for _stdout, _stderr, returncode in completed) == [0, 2]
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert len(payload["entries"]) == 1
    winner = payload["entries"][0]["transaction_id"]
    loser = "txn_b" if winner == "txn_a" else "txn_a"
    assert (tmp_path / f"runtime_{winner}").is_dir()
    assert not (tmp_path / f"runtime_{loser}").exists()
    assert not (tmp_path / f"journal_{loser}.json").exists()


def test_later_unrelated_append_keeps_first_retry_idempotent(tmp_path: Path) -> None:
    registry, before_a = _fixture(tmp_path)
    first = _run(tmp_path, "txn_first", "lane_first", before_a)
    assert first.returncode == 0, first.stderr
    before_b = sha256_file(registry)
    second = _run(tmp_path, "txn_second", "lane_second", before_b)
    assert second.returncode == 0, second.stderr
    retry = _run(tmp_path, "txn_first", "lane_first", before_a)
    assert retry.returncode == 0, retry.stderr
    assert json.loads(retry.stdout) == json.loads(first.stdout)
    assert len(json.loads(registry.read_text("utf-8"))["entries"]) == 2


def test_active_legacy_writer_marker_fails_without_orphan(tmp_path: Path) -> None:
    registry, before = _fixture(tmp_path)
    marker = tmp_path / "fixture_registry.json.lock"
    marker.write_text(f"pid={os.getpid()} lane=legacy\n", encoding="ascii")
    blocked = _run(tmp_path, "txn_blocked", "lane_blocked", before)
    assert blocked.returncode == 2
    assert sha256_file(registry) == before
    assert not (tmp_path / "runtime_txn_blocked").exists()
    assert not (tmp_path / "journal_txn_blocked.json").exists()


def test_legacy_old_writer_race_lost_update_zero(tmp_path: Path) -> None:
    registry, before = _fixture(tmp_path)
    legacy_command = [
        *_command(tmp_path, "ignored", "ignored", before),
        "--legacy-hold-seconds",
        "1.0",
    ]
    legacy = subprocess.Popen(
        legacy_command,
        cwd=ROOT,
        env=_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert legacy.stdout is not None
    assert legacy.stdout.readline().strip() == "LEGACY_READY"
    blocked = _run(tmp_path, "txn_r5_loses", "lane_r5_loses", before)
    assert blocked.returncode == 2
    legacy_stdout, legacy_stderr = legacy.communicate(timeout=30)
    assert legacy.returncode == 0, (legacy_stdout, legacy_stderr)
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert [entry["transaction_id"] for entry in payload["entries"]] == [
        "legacy_transaction"
    ]
    assert not (tmp_path / "runtime_txn_r5_loses").exists()

    second_root = tmp_path / "second"
    second_root.mkdir()
    second_registry, second_before = _fixture(second_root)
    r5 = subprocess.Popen(
        _command(second_root, "txn_r5_wins", "lane_r5_wins", second_before),
        cwd=ROOT,
        env=_environment(hold_after_marker=1.5),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    marker = second_root / "fixture_registry.json.lock"
    deadline = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert marker.exists()
    legacy_loses = subprocess.run(
        [
            *_command(second_root, "ignored", "ignored", second_before),
            "--legacy-hold-seconds",
            "0.0",
        ],
        cwd=ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert legacy_loses.returncode == 3
    r5_stdout, r5_stderr = r5.communicate(timeout=30)
    assert r5.returncode == 0, (r5_stdout, r5_stderr)
    payload = json.loads(second_registry.read_text(encoding="utf-8"))
    assert [entry["transaction_id"] for entry in payload["entries"]] == [
        "txn_r5_wins"
    ]


def test_corrupt_truncated_swapped_journal_receipt_rejected(tmp_path: Path) -> None:
    registry, before = _fixture(tmp_path)
    first = _run(tmp_path, "txn_corrupt", "lane_corrupt", before)
    assert first.returncode == 0
    registry_after = sha256_file(registry)
    journal = tmp_path / "journal_txn_corrupt.json"
    journal.write_bytes(b'{"truncated":')
    rejected = _run(tmp_path, "txn_corrupt", "lane_corrupt", before)
    assert rejected.returncode == 2
    assert sha256_file(registry) == registry_after

    second_root = tmp_path / "swapped"
    second_root.mkdir()
    second_registry, second_before = _fixture(second_root)
    a = _run(second_root, "txn_a", "lane_a", second_before)
    assert a.returncode == 0
    b_before = sha256_file(second_registry)
    b = _run(second_root, "txn_b", "lane_b", b_before)
    assert b.returncode == 0
    receipt_a = second_root / "runtime_txn_a/RESERVATION_RECEIPT.json"
    receipt_b = second_root / "runtime_txn_b/RESERVATION_RECEIPT.json"
    receipt_a.write_bytes(receipt_b.read_bytes())
    swapped = _run(second_root, "txn_a", "lane_a", second_before)
    assert swapped.returncode == 2
