from __future__ import annotations

import hashlib
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.bounded_consensus_v1 import (
    build_observable_state_confidence,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.prediction import (
    FoldPrediction,
    PreparedTask,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1 import core
from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1 import resource as service_resource
from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1 import runtime as batch_runtime
from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.contracts import (
    BCE_TASK_SURFACE_COLUMNS,
    RESOURCE_POLICY,
    SPENT_EQUIVALENCE_ALIAS,
    SPENT_EQUIVALENCE_ESTIMATOR_SEED,
    STATE_SOURCE_COLUMNS,
    UPSTREAM_SOURCE_PINS,
    BCEFreshServiceError,
    TaskIdentity,
    contract_payload,
    semantic_sha256,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.runtime import (
    InjectedTaskBytes,
    _validate_task_batch,
)


def _task_identity() -> TaskIdentity:
    return TaskIdentity(
        seed_alias="qualification_seed_01",
        dgp_id="A",
        estimator_seed=7573,
    )


def _qualification_task_bytes() -> list[InjectedTaskBytes]:
    tasks = []
    task_index = 0
    for seed_ordinal, estimator_seed in enumerate(
        (7573, 7577, 7583, 7589, 7591),
        start=1,
    ):
        for dgp_id in tuple("ABCDEFGHIJ"):
            tasks.append(
                InjectedTaskBytes(
                    task_index=task_index,
                    identity=TaskIdentity(
                        seed_alias=f"qualification_seed_{seed_ordinal:02d}",
                        dgp_id=dgp_id,
                        estimator_seed=estimator_seed,
                    ),
                    canonical_raw=b"held-canonical",
                    overlay_raw=b"held-overlay",
                )
            )
            task_index += 1
    return tasks


def _state_features() -> pd.DataFrame:
    positions = np.arange(1800, dtype=np.float64)
    return pd.DataFrame(
        {
            "ofs_v1_eps_confidence_01": 0.55 + 0.2 * np.sin(positions / 71.0),
            "ofs_v1_eps_staleness_log1p": np.log1p(positions % 253.0),
            "ofs_v1_regime_entropy": 0.35 + 0.1 * np.sin(positions / 89.0),
            "ofs_v1_regime_confidence": 0.65 + 0.1 * np.cos(positions / 97.0),
            "ofs_v1_state_abs_innovation_lag1": 0.1 + 0.05 * np.abs(
                np.sin(positions / 43.0)
            ),
        }
    ).loc[:, list(STATE_SOURCE_COLUMNS)]


def _prepared_task(state: pd.DataFrame) -> PreparedTask:
    identity = _task_identity()
    positions = np.arange(1800, dtype=np.float64)
    confidence = build_observable_state_confidence(state).confidence.to_numpy(
        dtype=np.float64
    )
    return PreparedTask(
        seed_alias=identity.seed_alias,
        dgp_id=identity.dgp_id,
        model_seed=identity.estimator_seed,
        dates=pd.bdate_range("2018-01-02", periods=1800).strftime("%Y-%m-%d").to_numpy(),
        symbols=np.full(1800, "SYNTHETIC_ISSUER", dtype=object),
        target_log_observed_pe=np.log(12.0 + positions / 2_000.0),
        sample_weights=np.full(1800, 0.8),
        reference_prediction=12.0 + positions / 2_000.0,
        lgbm_features=pd.DataFrame({"x": positions}),
        histgb_features=pd.DataFrame({"x": positions}),
        observable_state_confidence=confidence,
        state_feature_sha256=core._state_feature_hash(state),
    )


def _fake_fold(prepared: PreparedTask, test_start: int) -> FoldPrediction:
    test_end = min(1800, test_start + 21)
    positions = np.arange(test_start, test_end, dtype=np.int64)
    base = prepared.reference_prediction[positions]
    frame = pd.DataFrame(
        {
            "seed_alias": prepared.seed_alias,
            "dgp_id": prepared.dgp_id,
            "date": prepared.dates[positions],
            "symbol": prepared.symbols[positions],
            "session_position": positions,
            "fold_id": f"fold_{12 + (test_start - 504) // 21:03d}",
            "train_end_position": test_start - 1,
            "test_start_position": test_start,
            "incumbent__v04_expected_pe": base,
            "challenger__lgbm_full_state": base * np.exp(0.04),
            "challenger__histgb_full_state": base * np.exp(0.05),
            "bce_v1_observable_state_confidence": (
                prepared.observable_state_confidence[positions]
            ),
        }
    )
    return FoldPrediction(
        frame=frame,
        diagnostics={
            "seed_alias": prepared.seed_alias,
            "dgp_id": prepared.dgp_id,
            "fold_id": frame["fold_id"].iat[0],
            "test_start_position": test_start,
            "test_end_exclusive_position": test_end,
            "train_end_position": test_start - 1,
            "train_rows": test_start,
            "train_positions_sha256": "a" * 64,
            "state_feature_sha256": prepared.state_feature_sha256,
            "models": [MappingProxyType({"model_id": "A"}), MappingProxyType({"model_id": "B"})],
            "fitted_state_challengers": 2,
            "within_fold_refit_count": 0,
        },
    )


def _csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False, lineterminator="\n", float_format="%.17g").encode(
        "utf-8"
    )


def _header_hash(raw: bytes) -> str:
    header, separator, _ = raw.partition(b"\n")
    if not separator:
        raise AssertionError("test CSV lacks a header terminator")
    if header.endswith(b"\r"):
        header = header[:-1]
    return hashlib.sha256(header).hexdigest()


def test_raw_header_contract_normalizes_only_the_line_terminator() -> None:
    header = b"\xef\xbb\xbfdate,feature"
    expected = hashlib.sha256(header).hexdigest()
    assert core._raw_header_sha256(header + b"\n1,2\n") == expected
    assert core._raw_header_sha256(header + b"\r\n1,2\r\n") == expected

    for attacked in (
        header,
        b"\n1,2\n",
        header + b"\r\r\n1,2\n",
        b"\xef\xbb\xbfdate\r,feature\n1,2\n",
    ):
        with pytest.raises(BCEFreshServiceError):
            core._raw_header_sha256(attacked)


def test_contract_is_truth_free_and_uses_all_32_logical_cpus_as_16_pairs() -> None:
    payload = contract_payload()
    assert payload["candidate_scope"] == ["PE-C1", "PE-C2", "PE-C3"]
    assert payload["authority"] == {
        "generation": False,
        "truth": False,
        "score": False,
        "heldout": False,
        "publication": False,
        "promotion": False,
    }
    assert payload["input_headers"]["raw_sha256_semantics"].startswith(
        "exact UTF-8 header content"
    )
    assert RESOURCE_POLICY.cpu_pairs == tuple((2 * slot, 2 * slot + 1) for slot in range(16))
    assert RESOURCE_POLICY.affinity_mask(0) == 0x3
    assert RESOURCE_POLICY.affinity_mask(15) == 0xC0000000
    assert RESOURCE_POLICY.environment["CUDA_VISIBLE_DEVICES"] == "-1"
    assert RESOURCE_POLICY.environment["NVIDIA_VISIBLE_DEVICES"] == "void"
    assert len(semantic_sha256(payload)) == 64


def test_spawn_runtime_imports_no_numerical_stack_before_resource_seal() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (
        "import sys;"
        f"sys.path.insert(0,{str(root)!r});"
        "import research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.runtime;"
        "bad=sorted(n for n in sys.modules if n.split('.')[0] in "
        "{'numpy','pandas','sklearn','lightgbm'});"
        "print(repr(bad))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", source],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"seed_alias": "qualification_seed_99", "dgp_id": "A", "estimator_seed": 1},
        {"seed_alias": "qualification_seed_01", "dgp_id": "K", "estimator_seed": 1},
        {"seed_alias": "qualification_seed_01", "dgp_id": "A", "estimator_seed": True},
        {"seed_alias": "qualification_seed_01", "dgp_id": "A", "estimator_seed": -1},
        {"seed_alias": "qualification_seed_01", "dgp_id": "A", "estimator_seed": 7577},
        {"seed_alias": SPENT_EQUIVALENCE_ALIAS, "dgp_id": "A", "estimator_seed": 7573},
    ],
)
def test_task_identity_fails_closed(kwargs: dict[str, object]) -> None:
    with pytest.raises(BCEFreshServiceError):
        TaskIdentity(**kwargs)  # type: ignore[arg-type]


def test_upstream_numeric_sources_remain_exactly_pinned() -> None:
    root = Path(__file__).resolve().parents[2]
    for relative, expected in UPSTREAM_SOURCE_PINS.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected


def test_exact_parser_checks_headers_logical_prefix_and_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = 1800
    canonical = pd.DataFrame(
        {
            "date": pd.bdate_range("2016-01-04", periods=rows).strftime("%Y-%m-%d"),
            "ml_expected_pe": 10.0 + np.arange(rows) / 1000.0,
            **{f"public_{index:03d}": float(index) for index in range(2, 150)},
        }
    )
    overlay = pd.concat(
        [
            canonical.copy(deep=True),
            pd.DataFrame(
                {
                    "v04_expected_pe": canonical["ml_expected_pe"] * 1.01,
                    **{f"v04_public_{index:03d}": float(index) for index in range(103)},
                }
            ),
        ],
        axis=1,
    )
    assert canonical.shape == (1800, 150)
    assert overlay.shape == (1800, 254)
    canonical_raw = _csv_bytes(canonical)
    overlay_raw = _csv_bytes(overlay)
    monkeypatch.setattr(core, "CANONICAL_HEADER_RAW_SHA256", _header_hash(canonical_raw))
    monkeypatch.setattr(core, "OVERLAY_HEADER_RAW_SHA256", _header_hash(overlay_raw))
    monkeypatch.setattr(
        core,
        "CANONICAL_HEADER_SEMANTIC_SHA256",
        hashlib.sha256(core.canonical_json_bytes(list(canonical.columns))).hexdigest(),
    )
    overlay_semantic_sha256 = hashlib.sha256(
        core.canonical_json_bytes(list(overlay.columns))
    ).hexdigest()
    monkeypatch.setattr(
        core,
        "OVERLAY_HEADER_SEMANTIC_SHA256",
        overlay_semantic_sha256,
    )
    parsed_canonical, parsed_overlay = core.parse_public_task_bytes(
        canonical_raw,
        overlay_raw,
    )
    assert parsed_canonical.shape == (1800, 150)
    assert parsed_overlay.shape == (1800, 254)

    renamed_tail = overlay.rename(columns={overlay.columns[-1]: "score_payload"})
    with pytest.raises(BCEFreshServiceError, match="overlay frame header"):
        core.compute_task_surface(
            canonical,
            renamed_tail,
            identity=_task_identity(),
        )

    attacked = canonical.rename(columns={"public_002": "true_intrusion"})
    attacked_overlay = pd.concat(
        [
            attacked.copy(deep=True),
            pd.DataFrame(
                {
                    "v04_expected_pe": canonical["ml_expected_pe"] * 1.01,
                    **{f"v04_public_{index:03d}": float(index) for index in range(103)},
                }
            ),
        ],
        axis=1,
    )
    attacked_raw = _csv_bytes(attacked)
    attacked_overlay_raw = _csv_bytes(attacked_overlay)
    monkeypatch.setattr(core, "CANONICAL_HEADER_RAW_SHA256", _header_hash(attacked_raw))
    monkeypatch.setattr(core, "OVERLAY_HEADER_RAW_SHA256", _header_hash(attacked_overlay_raw))
    monkeypatch.setattr(
        core,
        "CANONICAL_HEADER_SEMANTIC_SHA256",
        hashlib.sha256(core.canonical_json_bytes(list(attacked.columns))).hexdigest(),
    )
    monkeypatch.setattr(
        core,
        "OVERLAY_HEADER_SEMANTIC_SHA256",
        hashlib.sha256(
            core.canonical_json_bytes(list(attacked_overlay.columns))
        ).hexdigest(),
    )
    with pytest.raises(BCEFreshServiceError, match="public boundary"):
        core.parse_public_task_bytes(attacked_raw, attacked_overlay_raw)


def test_prepared_numeric_lineage_emits_exact_clean_bce_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_features()
    prepared = _prepared_task(state)
    monkeypatch.setattr(core, "fit_one_fold", _fake_fold)
    result = core._assemble_prepared_task(prepared, state, _task_identity())
    assert tuple(result.surface.columns) == tuple(BCE_TASK_SURFACE_COLUMNS)
    assert len(result.surface) == 1296
    assert np.array_equal(
        result.surface["session_position"].to_numpy(dtype=np.int64),
        np.arange(504, 1800, dtype=np.int64),
    )
    assert np.allclose(
        result.surface["lgbm_full_state_expected_pe"].to_numpy(),
        result.surface["v04_expected_pe"].to_numpy() * np.exp(0.04),
        rtol=0.0,
        atol=1e-14,
    )
    pd.testing.assert_frame_equal(
        result.surface.loc[:, list(STATE_SOURCE_COLUMNS)].reset_index(drop=True),
        state.iloc[504:1800].reset_index(drop=True),
        check_exact=True,
    )
    assert len(result.fold_diagnostics) == 62
    assert result.receipt["constituent_fits"] == 124
    assert result.receipt["estimator_seed"] == 7573
    assert result.receipt["truth_received"] is False
    assert result.receipt["score_computed"] is False
    assert "estimator_seed" not in result.surface.columns


def test_state_or_prepared_identity_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_features()
    prepared = _prepared_task(state)
    monkeypatch.setattr(core, "fit_one_fold", _fake_fold)
    attacked = state.copy(deep=True)
    attacked.loc[900, "ofs_v1_eps_confidence_01"] += 0.01
    with pytest.raises(BCEFreshServiceError, match="state bytes differ"):
        core._assemble_prepared_task(prepared, attacked, _task_identity())
    wrong = TaskIdentity("qualification_seed_02", "A", 7577)
    with pytest.raises(BCEFreshServiceError, match="prepared task identity"):
        core._assemble_prepared_task(prepared, state, wrong)


def test_batch_requires_exact_seed_alias_then_dgp_order() -> None:
    raw_tasks = _qualification_task_bytes()
    assert _validate_task_batch(raw_tasks) == tuple(raw_tasks)
    attacked = raw_tasks.copy()
    attacked[0], attacked[1] = attacked[1], attacked[0]
    with pytest.raises(BCEFreshServiceError, match="reordered"):
        _validate_task_batch(attacked)

    spent_identity = TaskIdentity(
        SPENT_EQUIVALENCE_ALIAS,
        "A",
        SPENT_EQUIVALENCE_ESTIMATOR_SEED,
    )
    spent_attack = raw_tasks.copy()
    spent_attack[0] = InjectedTaskBytes(
        task_index=0,
        identity=spent_identity,
        canonical_raw=b"held-canonical",
        overlay_raw=b"held-overlay",
    )
    with pytest.raises(BCEFreshServiceError, match="reordered"):
        _validate_task_batch(spent_attack)


class _FakeProcess:
    def __init__(
        self,
        pid: int,
        *,
        terminate_effective: bool = True,
        kill_effective: bool = True,
    ) -> None:
        self.pid = pid
        self.exitcode: int | None = None
        self.alive = False
        self.closed = False
        self.terminate_effective = terminate_effective
        self.kill_effective = kill_effective
        self.terminate_called = False
        self.kill_called = False

    def start(self) -> None:
        self.alive = True

    def is_alive(self) -> bool:
        if self.closed:
            raise ValueError("process handle is closed")
        return self.alive

    def terminate(self) -> None:
        self.terminate_called = True
        if self.terminate_effective:
            self.alive = False
            self.exitcode = -15

    def kill(self) -> None:
        self.kill_called = True
        if self.kill_effective:
            self.alive = False
            self.exitcode = -9

    def join(self, timeout: float | None = None) -> None:
        del timeout

    def close(self) -> None:
        if self.closed or self.alive:
            raise ValueError("process cannot be closed")
        self.closed = True


class _FakePipeEnd:
    def __init__(
        self,
        *,
        blocking_reader: bool = False,
        close_failures_remaining: int = 0,
    ) -> None:
        self.closed = False
        self.blocking_reader = blocking_reader
        self.close_failures_remaining = close_failures_remaining
        self.closed_event = threading.Event()

    def close(self) -> None:
        if self.close_failures_remaining:
            self.close_failures_remaining -= 1
            raise OSError("synthetic close failure")
        self.closed = True
        self.closed_event.set()

    def recv_bytes(self, maxlength: int | None = None) -> bytes:
        del maxlength
        if not self.blocking_reader:
            raise EOFError("no fake payload")
        self.closed_event.wait(timeout=5.0)
        raise EOFError("fake receiver closed")


class _FakeContext:
    def __init__(
        self,
        *,
        process_constructor_fails: bool = False,
        sender_close_fails_once: bool = False,
    ) -> None:
        self.process_constructor_fails = process_constructor_fails
        self.sender_close_fails_once = sender_close_fails_once
        self.pipe_pairs: list[tuple[_FakePipeEnd, _FakePipeEnd]] = []
        self.processes: list[_FakeProcess] = []

    def Pipe(self, *, duplex: bool) -> tuple[_FakePipeEnd, _FakePipeEnd]:
        assert duplex is False
        pair = (
            _FakePipeEnd(blocking_reader=True),
            _FakePipeEnd(
                close_failures_remaining=1 if self.sender_close_fails_once else 0
            ),
        )
        self.pipe_pairs.append(pair)
        return pair

    def Process(self, **kwargs: object) -> _FakeProcess:
        assert kwargs["daemon"] is False
        if self.process_constructor_fails:
            raise OSError("synthetic Process construction failure")
        process = _FakeProcess(10_000 + len(self.processes))
        self.processes.append(process)
        return process


def test_clean_worker_exit_before_delayed_reader_enqueue_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outbox: queue.Queue[tuple[int, dict[str, object] | None, str | None]] = queue.Queue()
    exited = _FakeProcess(20_000)
    exited.exitcode = 0
    assert exited.is_alive() is False

    def delayed_reader() -> None:
        time.sleep(0.02)
        outbox.put((0, {"status": "PASS", "slot": 0}, None))

    reader = threading.Thread(target=delayed_reader, daemon=True)
    reader.start()
    monkeypatch.setattr(batch_runtime, "WAIT_POLL_SECONDS", 0.005)
    messages = batch_runtime._collect_worker_messages(
        outbox,
        worker_count=1,
        terminal_timeout_seconds=1.0,
    )
    reader.join(timeout=1.0)
    assert messages == {0: {"status": "PASS", "slot": 0}}
    assert not reader.is_alive()


def test_success_cleanup_attempts_every_action_before_aggregate_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fail_connections(_values: object) -> None:
        calls.append("connections")
        raise BCEFreshServiceError("synthetic close failure")

    def join_readers(_values: object) -> None:
        calls.append("readers")

    def close_processes(_values: object) -> None:
        calls.append("processes")

    monkeypatch.setattr(batch_runtime, "_close_connections", fail_connections)
    monkeypatch.setattr(batch_runtime, "_join_reader_threads", join_readers)
    monkeypatch.setattr(batch_runtime, "_close_stopped_process_handles", close_processes)
    with pytest.raises(BCEFreshServiceError, match="successful batch cleanup"):
        batch_runtime._finalize_success_resources(
            connections=(),
            reader_threads=(),
            processes=(),
        )
    assert calls == ["connections", "readers", "processes"]


def test_wire_frame_is_size_length_and_sha_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = {"status": "PASS", "slot": 0, "results": ((0, "value"),)}
    raw = batch_runtime._encode_worker_message(message)
    assert batch_runtime._decode_worker_message(raw) == message
    attacked = bytearray(raw)
    attacked[-1] ^= 1
    with pytest.raises(BCEFreshServiceError, match="SHA-256"):
        batch_runtime._decode_worker_message(bytes(attacked))
    monkeypatch.setattr(batch_runtime, "MAX_WORKER_BODY_BYTES", 8)
    with pytest.raises(BCEFreshServiceError, match="size bound"):
        batch_runtime._encode_worker_message(message)


def test_resource_preseal_detects_loaded_numerical_stack_and_restores_environment() -> None:
    assert "numpy" in service_resource.loaded_numerical_stack_modules()
    with pytest.raises(BCEFreshServiceError, match="loaded before resource seal"):
        service_resource.assert_numerical_stack_cold()
    before = {
        key: service_resource.os.environ.get(key) for key in RESOURCE_POLICY.environment
    }
    restore = service_resource.apply_exact_spawn_environment()
    assert restore == before
    assert service_resource.validate_inherited_spawn_environment() == RESOURCE_POLICY.environment
    service_resource.restore_spawn_environment(restore)
    after = {
        key: service_resource.os.environ.get(key) for key in RESOURCE_POLICY.environment
    }
    assert after == before


def test_process_construction_failure_closes_both_pipe_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _FakeContext(process_constructor_fails=True)
    monkeypatch.setattr(batch_runtime, "assert_numerical_stack_cold", lambda: None)
    monkeypatch.setattr(batch_runtime, "get_context", lambda _: context)
    with pytest.raises(BCEFreshServiceError, match="start failed"):
        batch_runtime.run_injected_batch(_qualification_task_bytes())
    assert len(context.pipe_pairs) == 1
    assert all(endpoint.closed for endpoint in context.pipe_pairs[0])


def test_sender_close_failure_after_start_adopts_and_terminates_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _FakeContext(sender_close_fails_once=True)
    monkeypatch.setattr(batch_runtime, "assert_numerical_stack_cold", lambda: None)
    monkeypatch.setattr(batch_runtime, "get_context", lambda _: context)
    with pytest.raises(BCEFreshServiceError, match="start failed"):
        batch_runtime.run_injected_batch(_qualification_task_bytes())
    assert len(context.processes) == 1
    assert context.processes[0].terminate_called and context.processes[0].closed
    assert all(endpoint.closed for endpoint in context.pipe_pairs[0])


def test_batch_deadline_terminates_workers_closes_handles_and_unblocks_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _FakeContext()
    monkeypatch.setattr(batch_runtime, "assert_numerical_stack_cold", lambda: None)
    monkeypatch.setattr(batch_runtime, "get_context", lambda _: context)
    monkeypatch.setattr(batch_runtime, "BATCH_TERMINAL_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(batch_runtime, "WAIT_POLL_SECONDS", 0.005)
    with pytest.raises(BCEFreshServiceError, match="deadline expired"):
        batch_runtime.run_injected_batch(_qualification_task_bytes())
    assert len(context.processes) == 16
    assert all(process.terminate_called and process.closed for process in context.processes)
    assert all(
        endpoint.closed for pair in context.pipe_pairs for endpoint in pair
    )


def test_cleanup_escalates_to_kill_and_rejects_a_survivor() -> None:
    killed = _FakeProcess(20_001, terminate_effective=False, kill_effective=True)
    killed.start()
    batch_runtime._stop_processes((killed,))
    assert killed.terminate_called and killed.kill_called and killed.closed

    survivor = _FakeProcess(20_002, terminate_effective=False, kill_effective=False)
    survivor.start()
    with pytest.raises(BCEFreshServiceError, match="survivor_pids"):
        batch_runtime._stop_processes((survivor,))
    assert survivor.terminate_called and survivor.kill_called and not survivor.closed
