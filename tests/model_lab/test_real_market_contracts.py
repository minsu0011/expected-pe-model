from __future__ import annotations

from datetime import date, datetime, time, timezone

import pytest

from pe_regime_v04.model_lab.real_market import (
    EventLedger,
    ExplicitSessionCalendar,
    MinimumIntervalRateLimiter,
    RawArtifact,
    RealMarketContractError,
    SCOREABILITY,
    SEC_SOURCE_ID,
    validate_sec_user_agent,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.real_market.contracts import build_event


def _artifact() -> RawArtifact:
    return RawArtifact.from_bytes(
        source_id=SEC_SOURCE_ID,
        requested_url="https://data.sec.gov/submissions/CIK0000320193.json",
        retrieved_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
        headers={"Content-Type": "application/json"},
        body=b"{}",
    )


def _event(payload: dict | None = None):
    artifact = _artifact()
    return build_event(
        event_type="SEC_FIXTURE",
        source_id=SEC_SOURCE_ID,
        entity_id="SEC_CIK:0000320193",
        cik="0000320193",
        effective_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        availability_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        availability_basis="FIXTURE_ACCEPTANCE; NEXT_XNYS_SESSION",
        effective_session=date(2025, 1, 3),
        revision_id="0000320193-25-000001",
        revision_kind="ORIGINAL",
        revision_of=None,
        artifact=artifact,
        payload=payload or {"accession_number": "0000320193-25-000001"},
        identity_parts=("fixture",),
    )


def test_explicit_calendar_never_guesses_weekdays_and_honors_cutoff() -> None:
    calendar = ExplicitSessionCalendar.from_iso_dates(
        ["2025-01-02", "2025-01-03", "2025-01-06"]
    )
    assert calendar.next_session_after(date(2025, 1, 3)) == date(2025, 1, 6)
    assert calendar.first_observable_session(
        datetime(2025, 1, 3, 21, 0, tzinfo=timezone.utc)
    ) == date(2025, 1, 3)  # 16:00 America/New_York
    assert calendar.first_observable_session(
        datetime(2025, 1, 3, 21, 30, tzinfo=timezone.utc)
    ) == date(2025, 1, 6)  # after the locked 16:15 cutoff
    with pytest.raises(RealMarketContractError, match="no session after"):
        calendar.next_session_after(date(2025, 1, 6))


def test_sec_user_agent_and_process_limiter_are_fail_closed() -> None:
    assert validate_sec_user_agent("PE-Regime-PIT research@example.org")
    for bad in ("python-urllib/3.13", "Mozilla/5.0 contact@example.org", "short"):
        with pytest.raises(RealMarketContractError, match="User-Agent"):
            validate_sec_user_agent(bad)

    current = [0.0]
    sleeps: list[float] = []

    def sleeper(delay: float) -> None:
        sleeps.append(delay)
        current[0] += delay

    limiter = MinimumIntervalRateLimiter(
        8.0,
        clock=lambda: current[0],
        sleeper=sleeper,
    )
    limiter.acquire()
    limiter.acquire()
    limiter.acquire()
    assert sleeps == pytest.approx([0.125, 0.125])
    with pytest.raises(RealMarketContractError, match=r"\(0, 8\]"):
        MinimumIntervalRateLimiter(8.01)


def test_ledger_is_sealed_conditional_and_cannot_hold_score_or_price_fields() -> None:
    event = _event()
    ledger = EventLedger.from_events([event])
    manifest = ledger.manifest([_artifact()])
    verify_payload_seal(manifest)
    assert manifest["implementation_status"] == "CONDITIONAL"
    assert manifest["scoreability"] == SCOREABILITY == "NOT_SCOREABLE"
    assert manifest["candidate_scores_computed"] is False
    assert manifest["price_data_present"] is False
    assert manifest["fred_data_present"] is False
    record = ledger.records()[0]
    assert record["security_id"] is None
    assert record["scoreability"] == "NOT_SCOREABLE"
    assert ledger.sha256() == manifest["ledger_sha256"]

    with pytest.raises(RealMarketContractError, match="score/price vocabulary"):
        _event({"candidate_score": 0.9})
    with pytest.raises(RealMarketContractError, match="score/price vocabulary"):
        _event({"nested": {"price": 100}})


def test_raw_artifact_hash_and_retrieval_time_are_mandatory() -> None:
    artifact = _artifact()
    assert len(artifact.sha256) == 64
    assert artifact.record()["bytes"] == 2
    with pytest.raises(RealMarketContractError, match="SHA-256"):
        RawArtifact(
            source_id=artifact.source_id,
            requested_url=artifact.requested_url,
            final_url=artifact.final_url,
            retrieved_at=artifact.retrieved_at,
            http_status=200,
            headers=(),
            body=b"{}",
            sha256="0" * 64,
        )

    calendar = ExplicitSessionCalendar((date(2025, 1, 2),))
    assert calendar.decision_cutoff_local == time(16, 15)
