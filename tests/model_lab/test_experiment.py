from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from pe_regime_v04.model_lab import (
    DeterministicExperimentLogger,
    ExperimentLogError,
)
from pe_regime_v04.model_lab import experiment as experiment_module


def _populate(path: Path) -> DeterministicExperimentLogger:
    logger = DeterministicExperimentLogger(path, experiment_id="wave1.seed6301")
    logger.log(
        event_key="config",
        event_type="configuration",
        payload={"models": ["a", "b"], "seed": 6301},
    )
    logger.log(
        event_key="fold_000",
        event_type="fold_complete",
        payload={"fair_log_mae": 0.1, "rows": 1296},
    )
    return logger


def test_logger_produces_identical_bytes_in_different_directories(tmp_path: Path) -> None:
    first = _populate(tmp_path / "first")
    second = _populate(tmp_path / "second")
    assert first.events_path.read_bytes() == second.events_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()
    events = first.verify()
    assert [event.sequence for event in events] == [1, 2]
    assert events[1].previous_entry_sha256 == events[0].entry_sha256


def test_logger_event_keys_are_idempotent_and_conflicts_fail(tmp_path: Path) -> None:
    logger = DeterministicExperimentLogger(tmp_path / "log", experiment_id="experiment")
    first = logger.log(event_key="same", event_type="metric", payload={"value": 1})
    before = logger.events_path.read_bytes()
    second = logger.log(event_key="same", event_type="metric", payload={"value": 1})
    assert first == second
    assert logger.events_path.read_bytes() == before
    with pytest.raises(ExperimentLogError, match="conflicting"):
        logger.log(event_key="same", event_type="metric", payload={"value": 2})


@pytest.mark.parametrize(
    ("first_value", "conflicting_value"),
    [(True, 1), (1, 1.0), (-0.0, 0.0)],
)
def test_logger_idempotency_uses_canonical_json_type_and_number_bytes(
    tmp_path: Path,
    first_value: object,
    conflicting_value: object,
) -> None:
    logger = DeterministicExperimentLogger(tmp_path / "log", experiment_id="typed")
    logger.log(event_key="same", event_type="metric", payload={"value": first_value})
    with pytest.raises(ExperimentLogError, match="conflicting"):
        logger.log(
            event_key="same",
            event_type="metric",
            payload={"value": conflicting_value},
        )


def test_logger_rejects_tampered_event_or_manifest(tmp_path: Path) -> None:
    logger = _populate(tmp_path / "log")
    lines = logger.events_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[0])
    event["payload"]["seed"] = 99
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    logger.events_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    with pytest.raises(ExperimentLogError, match="SHA-256"):
        logger.verify()


def test_logger_rejects_noncanonical_payload_and_unsafe_ids(tmp_path: Path) -> None:
    with pytest.raises(ExperimentLogError, match="path-safe"):
        DeterministicExperimentLogger(tmp_path, experiment_id="bad/id")
    logger = DeterministicExperimentLogger(tmp_path / "safe", experiment_id="safe")
    with pytest.raises(ExperimentLogError, match="canonical JSON"):
        logger.log(event_key="nan", event_type="metric", payload={"value": float("nan")})
    with pytest.raises(ExperimentLogError, match="safe identifiers"):
        logger.log(event_key="bad key", event_type="metric", payload={})


def test_logger_reopen_verifies_existing_chain(tmp_path: Path) -> None:
    original = _populate(tmp_path / "log")
    reopened = DeterministicExperimentLogger(
        original.directory, experiment_id=original.experiment_id
    )
    assert reopened.verify() == original.verify()


def test_independent_logger_instances_are_serialized_as_single_writer(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "shared"
    first = DeterministicExperimentLogger(directory, experiment_id="formal")
    second = DeterministicExperimentLogger(directory, experiment_id="formal")

    def append(logger: DeterministicExperimentLogger, key: str) -> None:
        logger.log(event_key=key, event_type="metric", payload={"key": key})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(append, first, "worker_a"),
            pool.submit(append, second, "worker_b"),
        ]
        for future in futures:
            future.result()
    events = first.verify()
    assert {event.event_key for event in events} == {"worker_a", "worker_b"}
    assert [event.sequence for event in events] == [1, 2]


def test_logger_recovers_interruption_between_event_and_manifest_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger = DeterministicExperimentLogger(tmp_path / "log", experiment_id="recover")
    logger.log(event_key="first", event_type="metric", payload={"value": 1})
    original_atomic_write = experiment_module._atomic_write

    def interrupt_manifest(path: Path, data: bytes) -> None:
        if path.name == "manifest.json":
            raise OSError("simulated interruption")
        original_atomic_write(path, data)

    with monkeypatch.context() as patcher:
        patcher.setattr(experiment_module, "_atomic_write", interrupt_manifest)
        with pytest.raises(OSError, match="interruption"):
            logger.log(event_key="second", event_type="metric", payload={"value": 2})

    recovered = DeterministicExperimentLogger(tmp_path / "log", experiment_id="recover")
    assert [event.event_key for event in recovered.verify()] == ["first", "second"]
    assert json.loads(recovered.manifest_path.read_text(encoding="utf-8"))["event_count"] == 2


def test_logger_reconstructs_missing_derived_manifest(tmp_path: Path) -> None:
    logger = _populate(tmp_path / "log")
    expected_manifest = logger.manifest_path.read_bytes()
    logger.manifest_path.unlink()
    recovered = DeterministicExperimentLogger(logger.directory, experiment_id=logger.experiment_id)
    assert len(recovered.verify()) == 2
    assert recovered.manifest_path.read_bytes() == expected_manifest


def test_logger_rejects_valid_prefix_truncation_and_noncanonical_event_bytes(
    tmp_path: Path,
) -> None:
    truncated = _populate(tmp_path / "truncated")
    first_line = truncated.events_path.read_bytes().splitlines(keepends=True)[0]
    truncated.events_path.write_bytes(first_line)
    with pytest.raises(ExperimentLogError, match="manifest content"):
        truncated.verify()

    noncanonical = _populate(tmp_path / "noncanonical")
    lines = noncanonical.events_path.read_bytes().splitlines()
    noncanonical.events_path.write_bytes(lines[0] + b" \n" + lines[1] + b"\n")
    with pytest.raises(ExperimentLogError, match="not canonical"):
        noncanonical.verify()
