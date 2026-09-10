"""Run the bounded public PIT collector after explicit CPU/network release.

This CLI is intentionally inert unless ``--allow-live-network`` is present.  It
collects no prices, no FRED data, and computes no model or candidate scores.
"""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.real_market import (  # noqa: E402
    EventLedger,
    ExplicitSessionCalendar,
    NYFED_SOURCE_ID,
    OfficialSourceHttpClient,
    SEC_SOURCE_ID,
    TREASURY_SOURCE_ID,
    discover_submission_history_urls,
    nyfed_search_url,
    parse_nyfed_reference_rates,
    parse_sec_accession_metadata,
    parse_sec_companyfacts,
    parse_sec_submissions,
    parse_treasury_csv,
    seal_payload,
    sec_accession_index_url,
    sec_companyfacts_url,
    sec_submissions_url,
    treasury_csv_url,
    validate_nyfed_search_url,
    validate_sec_accession_index_url,
    validate_sec_companyfacts_url,
    validate_sec_submissions_url,
    validate_sec_user_agent,
    validate_treasury_csv_url,
)
from pe_regime_v04.model_lab.real_market.ledger import (  # noqa: E402
    write_immutable_bytes,
    write_immutable_json,
)


MAX_CIKS = 10
MAX_TREASURY_YEARS = 2
MAX_SEC_HISTORY_FILES_PER_CIK = 12
MAX_ACCESSION_INDEXES_PER_CIK = 20
MAX_NYFED_DAYS = 370
MAX_EVENTS = 500_000


def _unique(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _load_sessions(path: Path) -> ExplicitSessionCalendar:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read explicit session file: {path}") from exc
    values = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    return ExplicitSessionCalendar.from_iso_dates(values)


def _file_record(path: Path) -> dict[str, object]:
    body = Path(path).read_bytes()
    return {
        "path": str(Path(path).resolve()),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must use YYYY-MM-DD") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a bounded, official-source, NOT_SCOREABLE public PIT ledger"
    )
    parser.add_argument(
        "--allow-live-network",
        action="store_true",
        help="required acknowledgement; without it the collector exits before network access",
    )
    parser.add_argument("--user-agent", required=True, help="project plus real contact email")
    parser.add_argument("--sessions-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cik", action="append", default=[])
    parser.add_argument("--treasury-year", action="append", type=int, default=[])
    parser.add_argument("--nyfed-series", action="append", choices=("EFFR", "SOFR"), default=[])
    parser.add_argument("--nyfed-start", type=_parse_date)
    parser.add_argument("--nyfed-end", type=_parse_date)
    parser.add_argument("--accession-index-limit", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.allow_live_network:
        parser.error("live network is disabled; rerun only after CPU release with --allow-live-network")
    validate_sec_user_agent(args.user_agent)
    ciks = _unique(args.cik)
    years = sorted(set(args.treasury_year))
    series = _unique(args.nyfed_series)
    if not ciks and not years and not series:
        parser.error("at least one --cik, --treasury-year, or --nyfed-series is required")
    if len(ciks) > MAX_CIKS:
        parser.error(f"the bounded pilot permits at most {MAX_CIKS} CIKs")
    if len(years) > MAX_TREASURY_YEARS:
        parser.error(f"the bounded pilot permits at most {MAX_TREASURY_YEARS} Treasury years")
    if not 0 <= args.accession_index_limit <= MAX_ACCESSION_INDEXES_PER_CIK:
        parser.error(
            "--accession-index-limit must be between 0 and "
            f"{MAX_ACCESSION_INDEXES_PER_CIK}"
        )
    if bool(series) != bool(args.nyfed_start and args.nyfed_end):
        parser.error("NY Fed series and both NY Fed dates must be provided together")
    if series:
        assert args.nyfed_start is not None and args.nyfed_end is not None
        if args.nyfed_start > args.nyfed_end:
            parser.error("NY Fed start date is after end date")
        if (args.nyfed_end - args.nyfed_start).days > MAX_NYFED_DAYS:
            parser.error(f"NY Fed date range must not exceed {MAX_NYFED_DAYS} days")

    calendar = _load_sessions(args.sessions_file)
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"immutable output directory already exists: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = output_dir.with_name(f".{output_dir.name}.tmp.{os.getpid()}")
    if stage.exists():
        raise FileExistsError(f"staging directory already exists: {stage}")

    client = OfficialSourceHttpClient(user_agent=args.user_agent)
    artifacts = []
    events = []

    for cik in ciks:
        main = client.fetch(
            source_id=SEC_SOURCE_ID,
            url=sec_submissions_url(cik),
            validate_url=validate_sec_submissions_url,
            max_bytes=32 * 1024 * 1024,
        )
        artifacts.append(main)
        history_urls = discover_submission_history_urls(main)
        if len(history_urls) > MAX_SEC_HISTORY_FILES_PER_CIK:
            raise ValueError(
                f"CIK {cik} exceeds the bounded history-file maximum; narrow the pilot"
            )
        history = []
        for url in history_urls:
            item = client.fetch(
                source_id=SEC_SOURCE_ID,
                url=url,
                validate_url=validate_sec_submissions_url,
                max_bytes=32 * 1024 * 1024,
            )
            history.append(item)
            artifacts.append(item)
        bundle = parse_sec_submissions(
            main,
            calendar=calendar,
            history_artifacts=history,
            require_complete_history=True,
        )
        events.extend(bundle.events)
        companyfacts = client.fetch(
            source_id=SEC_SOURCE_ID,
            url=sec_companyfacts_url(bundle.cik),
            validate_url=validate_sec_companyfacts_url,
            max_bytes=96 * 1024 * 1024,
        )
        artifacts.append(companyfacts)
        events.extend(parse_sec_companyfacts(companyfacts, submissions=bundle))
        selected = sorted(
            bundle.submissions,
            key=lambda record: (record.acceptance_at, record.accession_number),
            reverse=True,
        )[: args.accession_index_limit]
        for submission in selected:
            url = sec_accession_index_url(bundle.cik, submission.accession_number)
            index = client.fetch(
                source_id=SEC_SOURCE_ID,
                url=url,
                validate_url=validate_sec_accession_index_url,
                max_bytes=8 * 1024 * 1024,
            )
            artifacts.append(index)
            events.append(
                parse_sec_accession_metadata(
                    index,
                    submissions=bundle,
                    accession_number=submission.accession_number,
                )
            )

    for year in years:
        url = treasury_csv_url(year)
        artifact = client.fetch(
            source_id=TREASURY_SOURCE_ID,
            url=url,
            validate_url=validate_treasury_csv_url,
            max_bytes=8 * 1024 * 1024,
        )
        artifacts.append(artifact)
        events.extend(parse_treasury_csv(artifact, calendar=calendar))

    for name in series:
        assert args.nyfed_start is not None and args.nyfed_end is not None
        url = nyfed_search_url(name, args.nyfed_start, args.nyfed_end)
        artifact = client.fetch(
            source_id=NYFED_SOURCE_ID,
            url=url,
            validate_url=validate_nyfed_search_url,
            max_bytes=8 * 1024 * 1024,
        )
        artifacts.append(artifact)
        events.extend(parse_nyfed_reference_rates(artifact, calendar=calendar))

    if not events or len(events) > MAX_EVENTS:
        raise ValueError(f"bounded event count must be in [1, {MAX_EVENTS}]")
    ledger = EventLedger.from_events(events)
    manifest = ledger.manifest(artifacts)
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256")
    unsigned.update(
        {
            "execution_mode": "EXPLICIT_LIVE_NETWORK_PILOT",
            "session_calendar": _file_record(args.sessions_file),
            "decision_cutoff": "16:15 America/New_York",
            "sec_request_cap_per_second": 8,
            "bounded_inputs": {
                "ciks": ciks,
                "treasury_years": years,
                "nyfed_series": series,
                "nyfed_start": args.nyfed_start.isoformat() if args.nyfed_start else None,
                "nyfed_end": args.nyfed_end.isoformat() if args.nyfed_end else None,
                "accession_index_limit": args.accession_index_limit,
            },
        }
    )
    manifest = seal_payload(unsigned)

    try:
        stage.mkdir()
        write_immutable_bytes(stage / "ledger.jsonl", ledger.canonical_jsonl_bytes())
        for artifact in artifacts:
            raw_path = stage / "raw" / artifact.source_id.lower() / f"{artifact.sha256}.bin"
            if not raw_path.exists():
                write_immutable_bytes(raw_path, artifact.body)
        write_immutable_json(stage / "manifest.json", manifest)
        status = {
            "implementation_status": "CONDITIONAL",
            "scoreability": "NOT_SCOREABLE",
            "live_network_used": True,
            "price_data_present": False,
            "fred_data_present": False,
            "candidate_scores_computed": False,
            "event_count": len(ledger.events),
            "ledger_sha256": ledger.sha256(),
        }
        write_immutable_json(stage / "STATUS.json", status)
        os.replace(stage, output_dir)
    finally:
        if stage.exists():
            resolved_stage = stage.resolve()
            if resolved_stage.parent != output_dir.parent or not resolved_stage.name.startswith(
                f".{output_dir.name}.tmp."
            ):
                raise RuntimeError("refusing to clean an unexpected staging directory")
            shutil.rmtree(resolved_stage)
    print(json.dumps({"output_dir": str(output_dir), "event_count": len(ledger.events)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
