"""Machine-readable pytest collection and executed-item receipt plugin."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


_COLLECTED: list[str] = []
_OUTCOMES: dict[str, str] = {}


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        .encode("ascii")
        + b"\n"
    )


def pytest_collection_finish(session: Any) -> None:
    _COLLECTED[:] = [item.nodeid for item in session.items]


def pytest_runtest_logreport(report: Any) -> None:
    if report.when == "call" or (report.when == "setup" and report.failed):
        _OUTCOMES[report.nodeid] = report.outcome


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    path_value = os.environ.get("EXPECTED_PE_R8_PYTEST_RECEIPT")
    if not path_value:
        return
    outcomes = [[nodeid, _OUTCOMES.get(nodeid, "not_executed")] for nodeid in _COLLECTED]
    payload = {
        "schema_version": "expected_pe.r8.pytest_machine_receipt.v1",
        "exitstatus": int(exitstatus),
        "collected_item_count": len(_COLLECTED),
        "collected_nodeids": _COLLECTED,
        "executed_item_count": sum(value != "not_executed" for _nodeid, value in outcomes),
        "passed_item_count": sum(value == "passed" for _nodeid, value in outcomes),
        "failed_item_count": sum(value == "failed" for _nodeid, value in outcomes),
        "skipped_item_count": sum(value == "skipped" for _nodeid, value in outcomes),
        "outcomes": outcomes,
    }
    payload["receipt_semantic_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    Path(path_value).write_bytes(_canonical(payload))
