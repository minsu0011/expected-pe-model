from __future__ import annotations

from datetime import date, datetime, timezone
import json

import pytest

from pe_regime_v04.model_lab.real_market import (
    ExplicitSessionCalendar,
    NYFED_SOURCE_ID,
    RawArtifact,
    RealMarketContractError,
    TREASURY_SOURCE_ID,
    nyfed_search_url,
    parse_nyfed_reference_rates,
    parse_treasury_csv,
    parse_treasury_xml,
    treasury_csv_url,
    treasury_xml_url,
)


RETRIEVED = datetime(2026, 8, 19, tzinfo=timezone.utc)


def _calendar() -> ExplicitSessionCalendar:
    return ExplicitSessionCalendar.from_iso_dates(
        ["2025-01-02", "2025-01-03", "2025-01-06", "2025-01-07", "2025-01-08"]
    )


def _artifact(source_id: str, url: str, body: bytes) -> RawArtifact:
    return RawArtifact.from_bytes(
        source_id=source_id,
        requested_url=url,
        retrieved_at=RETRIEVED,
        body=body,
    )


def test_treasury_csv_enforces_t_minus_one_at_the_decision_cutoff() -> None:
    body = b"Date,1 Mo,10 Yr,30 Yr\r\n01/02/2025,4.40,4.57,\r\n"
    artifact = _artifact(TREASURY_SOURCE_ID, treasury_csv_url(2025), body)
    event = parse_treasury_csv(artifact, calendar=_calendar())[0]
    assert event.payload["rates_percent"] == {"1 Mo": "4.40", "10 Yr": "4.57"}
    assert event.availability_at == datetime(2025, 1, 2, 23, 0, tzinfo=timezone.utc)
    assert event.effective_session == date(2025, 1, 3)
    assert "T_MINUS_1" in event.availability_basis
    assert event.payload["publication_timestamp_observed"] is False


def test_treasury_xml_parses_official_atom_properties_without_network() -> None:
    body = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"
 xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
 xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
 <entry><content type="application/xml"><m:properties>
  <d:NEW_DATE m:type="Edm.DateTime">2025-01-03T00:00:00</d:NEW_DATE>
  <d:BC_3MONTH m:type="Edm.Double">4.35</d:BC_3MONTH>
  <d:BC_10YEAR m:type="Edm.Double">4.60</d:BC_10YEAR>
 </m:properties></content></entry>
</feed>"""
    artifact = _artifact(TREASURY_SOURCE_ID, treasury_xml_url(2025), body)
    event = parse_treasury_xml(artifact, calendar=_calendar())[0]
    assert event.payload["source_format"] == "XML"
    assert event.payload["rates_percent"]["3 Mo"] == "4.35"
    assert event.effective_session == date(2025, 1, 6)


def test_nyfed_reference_rate_waits_for_post_correction_snapshot() -> None:
    url = nyfed_search_url("EFFR", date(2025, 1, 3), date(2025, 1, 3))
    payload = {
        "refRates": [
            {
                "effectiveDate": "2025-01-03",
                "type": "EFFR",
                "percentRate": 4.33,
                "percentPercentile1": 4.30,
                "percentPercentile25": 4.32,
                "percentPercentile75": 4.34,
                "percentPercentile99": 4.40,
                "volumeInBillions": 2015,
                "targetRateFrom": 4.25,
                "targetRateTo": 4.50,
                "revisionIndicator": "",
            }
        ]
    }
    artifact = _artifact(
        NYFED_SOURCE_ID,
        url,
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    event = parse_nyfed_reference_rates(artifact, calendar=_calendar())[0]
    assert event.payload["series"] == "EFFR"
    assert event.payload["reported_values"]["volumeInBillions"] == "2015"
    assert event.availability_at == datetime(2025, 1, 6, 19, 30, tzinfo=timezone.utc)
    assert event.effective_session == date(2025, 1, 6)
    assert event.payload["first_publication_time_local"] == "09:00"
    assert event.scoreability == "NOT_SCOREABLE"


def test_nyfed_schema_and_series_mismatches_fail_closed() -> None:
    url = nyfed_search_url("SOFR", date(2025, 1, 3), date(2025, 1, 3))
    payload = {
        "refRates": [
            {
                "effectiveDate": "2025-01-03",
                "type": "EFFR",
                "percentRate": 4.33,
                "unexpectedField": "schema drift",
            }
        ]
    }
    artifact = _artifact(
        NYFED_SOURCE_ID,
        url,
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    with pytest.raises(RealMarketContractError, match="schema changed"):
        parse_nyfed_reference_rates(artifact, calendar=_calendar())

    payload["refRates"][0].pop("unexpectedField")
    artifact = _artifact(
        NYFED_SOURCE_ID,
        url,
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    with pytest.raises(RealMarketContractError, match="series differs"):
        parse_nyfed_reference_rates(artifact, calendar=_calendar())


def test_rate_adapters_reject_unofficial_redirects_and_entity_declarations() -> None:
    official = treasury_csv_url(2025)
    artifact = RawArtifact.from_bytes(
        source_id=TREASURY_SOURCE_ID,
        requested_url=official,
        final_url=official.replace("home.treasury.gov", "example.org"),
        retrieved_at=RETRIEVED,
        body=b"Date,1 Mo\n01/02/2025,4.4\n",
    )
    with pytest.raises(RealMarketContractError, match="official HTTPS"):
        parse_treasury_csv(artifact, calendar=_calendar())

    malicious = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><feed>&e;</feed>'
    artifact = _artifact(TREASURY_SOURCE_ID, treasury_xml_url(2025), malicious)
    with pytest.raises(RealMarketContractError, match="DTD/entity"):
        parse_treasury_xml(artifact, calendar=_calendar())
