from __future__ import annotations

from datetime import date, datetime, timezone
import json

import pytest

from pe_regime_v04.model_lab.real_market import (
    ExplicitSessionCalendar,
    RawArtifact,
    RealMarketContractError,
    SEC_SOURCE_ID,
    parse_sec_accession_metadata,
    parse_sec_companyfacts,
    parse_sec_submissions,
    sec_accession_index_url,
    sec_companyfacts_url,
    sec_submissions_url,
)


CIK = "0000320193"
ACCESSION = "0000320193-25-000001"
AMENDMENT = "0000320193-25-000002"
RETRIEVED = datetime(2026, 8, 19, tzinfo=timezone.utc)


def _artifact(source_url: str, payload: object) -> RawArtifact:
    return RawArtifact.from_bytes(
        source_id=SEC_SOURCE_ID,
        requested_url=source_url,
        retrieved_at=RETRIEVED,
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )


def _calendar() -> ExplicitSessionCalendar:
    return ExplicitSessionCalendar.from_iso_dates(
        ["2025-01-02", "2025-01-03", "2025-01-06", "2025-01-07", "2025-01-08"]
    )


def _submissions_payload(*, history_files: list[dict] | None = None) -> dict:
    return {
        "cik": 320193,
        "name": "Fixture Issuer Inc.",
        "tickers": ["FIX"],
        "exchanges": ["Nasdaq"],
        "filings": {
            "recent": {
                "accessionNumber": [ACCESSION, AMENDMENT],
                "filingDate": ["2025-01-03", "2025-01-07"],
                "reportDate": ["2024-12-28", "2024-12-28"],
                "acceptanceDateTime": [
                    "2025-01-03T20:00:00.000Z",
                    "2025-01-07T20:00:00.000Z",
                ],
                "form": ["10-Q", "10-Q/A"],
                "primaryDocument": ["fixture10q.htm", "fixture10qa.htm"],
                "isXBRL": [1, 1],
                "isInlineXBRL": [1, 1],
            },
            "files": history_files or [],
        },
    }


def _bundle():
    artifact = _artifact(sec_submissions_url(CIK), _submissions_payload())
    return parse_sec_submissions(artifact, calendar=_calendar())


def test_sec_submissions_use_acceptance_and_conservative_next_session() -> None:
    bundle = _bundle()
    assert bundle.cik == CIK
    assert bundle.entity_id == f"SEC_CIK:{CIK}"
    assert [event.revision_kind for event in bundle.events] == ["ORIGINAL", "AMENDMENT"]
    assert bundle.events[0].availability_at == datetime(
        2025, 1, 3, 20, 0, tzinfo=timezone.utc
    )
    assert bundle.events[0].effective_session == date(2025, 1, 6)
    assert bundle.events[1].effective_session == date(2025, 1, 8)
    assert bundle.events[0].source_document_sha256 == bundle.artifacts[0].sha256
    assert bundle.events[0].scoreability == "NOT_SCOREABLE"


def test_sec_companyfacts_are_accession_joined_and_amendments_do_not_overwrite() -> None:
    bundle = _bundle()
    payload = {
        "cik": 320193,
        "entityName": "Fixture Issuer Inc.",
        "facts": {
            "us-gaap": {
                "EarningsPerShareDiluted": {
                    "label": "Diluted EPS",
                    "description": "fixture",
                    "units": {
                        "USD/shares": [
                            {
                                "start": "2024-09-29",
                                "end": "2024-12-28",
                                "val": 1.23,
                                "accn": ACCESSION,
                                "fy": 2025,
                                "fp": "Q1",
                                "form": "10-Q",
                                "filed": "2025-01-03",
                                "frame": "CY2024Q4",
                            },
                            {
                                "start": "2024-09-29",
                                "end": "2024-12-28",
                                "val": 1.20,
                                "accn": AMENDMENT,
                                "fy": 2025,
                                "fp": "Q1",
                                "form": "10-Q/A",
                                "filed": "2025-01-07",
                                "frame": "CY2024Q4",
                            },
                        ]
                    },
                }
            }
        },
    }
    events = parse_sec_companyfacts(
        _artifact(sec_companyfacts_url(CIK), payload), submissions=bundle
    )
    assert len(events) == 2
    assert [event.revision_kind for event in events] == ["ORIGINAL", "AMENDMENT"]
    assert [event.effective_session for event in events] == [
        date(2025, 1, 6),
        date(2025, 1, 8),
    ]
    assert events[0].payload["value"] == "1.23"
    assert events[1].payload["value"] == "1.2"
    assert events[0].revision_id != events[1].revision_id

    payload["facts"]["us-gaap"]["EarningsPerShareDiluted"]["units"]["USD/shares"][
        0
    ]["accn"] = "0000320193-24-999999"
    with pytest.raises(RealMarketContractError, match="lacks complete submissions"):
        parse_sec_companyfacts(
            _artifact(sec_companyfacts_url(CIK), payload), submissions=bundle
        )


def test_sec_accession_index_is_linked_to_acceptance_and_raw_hash() -> None:
    bundle = _bundle()
    payload = {
        "directory": {
            "name": f"/Archives/edgar/data/320193/{ACCESSION.replace('-', '')}",
            "parent-dir": "/Archives/edgar/data/320193",
            "item": [
                {
                    "name": "fixture10q.htm",
                    "type": "text/html",
                    "size": "1234",
                    "last-modified": "2025-01-03 15:00:00",
                },
                {
                    "name": "index.json",
                    "type": "application/json",
                    "size": "321",
                    "last-modified": "2025-01-03 15:00:01",
                },
            ],
        }
    }
    artifact = _artifact(sec_accession_index_url(CIK, ACCESSION), payload)
    event = parse_sec_accession_metadata(
        artifact, submissions=bundle, accession_number=ACCESSION
    )
    assert event.effective_session == date(2025, 1, 6)
    assert event.payload["primary_document"] == "fixture10q.htm"
    assert event.payload["files"][0]["size"] == 1234
    assert event.source_document_sha256 == artifact.sha256


def test_sec_rejects_unofficial_hosts_and_incomplete_submission_history() -> None:
    payload = _submissions_payload(
        history_files=[
            {
                "name": "CIK0000320193-submissions-001.json",
                "filingCount": 1,
                "filingFrom": "2000-01-01",
                "filingTo": "2000-12-31",
            }
        ]
    )
    with pytest.raises(RealMarketContractError, match="history is incomplete"):
        parse_sec_submissions(
            _artifact(sec_submissions_url(CIK), payload), calendar=_calendar()
        )
    untrusted = RawArtifact.from_bytes(
        source_id=SEC_SOURCE_ID,
        requested_url="https://example.org/submissions/CIK0000320193.json",
        retrieved_at=RETRIEVED,
        body=json.dumps(_submissions_payload()).encode("utf-8"),
    )
    with pytest.raises(RealMarketContractError, match="official SEC submissions"):
        parse_sec_submissions(untrusted, calendar=_calendar())
