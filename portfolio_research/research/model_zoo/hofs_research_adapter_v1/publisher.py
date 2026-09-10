"""Exclusive same-volume atomic publisher for research adapter artifacts."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterable, Mapping

from .contracts import (
    BENCHMARK_OUTPUT_ROOT,
    FAILURE_RECEIPT_ROOT,
    FULL_OUTPUT_ROOT,
    R2_PREFLIGHT_ROOT,
    PREDICTION_COLUMNS,
    SMOKE_OUTPUT_ROOT,
    HofsResearchAdapterError,
)
from .inputs import project_root


_ALLOWED_OUTPUT_ROOTS = frozenset(
    {
        SMOKE_OUTPUT_ROOT,
        BENCHMARK_OUTPUT_ROOT,
        FULL_OUTPUT_ROOT,
        FAILURE_RECEIPT_ROOT,
        R2_PREFLIGHT_ROOT,
    }
)


def pretty_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")


def csv_bytes(rows: Iterable[Mapping[str, Any]], fieldnames: tuple[str, ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(fieldnames), lineterminator="\n")
    writer.writeheader()
    count = 0
    for row in rows:
        if tuple(row) != fieldnames:
            raise HofsResearchAdapterError("CSV row header/order drifted")
        writer.writerow(row)
        count += 1
    if count == 0:
        raise HofsResearchAdapterError("refusing to serialize an empty CSV")
    return stream.getvalue().encode("utf-8")


def prediction_csv_bytes(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return csv_bytes(rows, PREDICTION_COLUMNS)


def jsonl_bytes(rows: Iterable[Mapping[str, Any]]) -> bytes:
    output = bytearray()
    count = 0
    for row in rows:
        output.extend(
            json.dumps(
                row,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        )
        output.extend(b"\n")
        count += 1
    if count == 0:
        raise HofsResearchAdapterError("refusing to serialize empty JSONL")
    return bytes(output)


def _write_exclusive(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_atomic(output_relative: str, files: Mapping[str, bytes]) -> dict[str, Any]:
    """Publish one complete, immutable output universe without overwrite."""

    if output_relative not in _ALLOWED_OUTPUT_ROOTS:
        raise HofsResearchAdapterError("output root is outside the fixed adapter universe")
    if not files or "CHECKSUMS.sha256" in files:
        raise HofsResearchAdapterError("publisher payload universe is invalid")
    if any(
        type(name) is not str
        or not name
        or Path(name).is_absolute()
        or ".." in Path(name).parts
        or type(content) is not bytes
        for name, content in files.items()
    ):
        raise HofsResearchAdapterError("publisher filename/content contract drifted")

    root = project_root()
    final = (root / output_relative).resolve()
    outputs = (root / "outputs").resolve()
    if final.parent != outputs or final.exists():
        raise HofsResearchAdapterError("output destination exists or escaped outputs")
    staging = Path(tempfile.mkdtemp(prefix=f".{final.name}.staging-", dir=outputs))
    published = False
    try:
        for name in sorted(files):
            _write_exclusive(staging / name, files[name])
        ledger = b"".join(
            f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n".encode("ascii")
            for name in sorted(files)
        )
        _write_exclusive(staging / "CHECKSUMS.sha256", ledger)
        expected = set(files) | {"CHECKSUMS.sha256"}
        observed = {
            path.relative_to(staging).as_posix()
            for path in staging.rglob("*")
            if path.is_file()
        }
        if observed != expected:
            raise HofsResearchAdapterError("staged output universe drifted")
        _fsync_directory(staging)
        os.replace(staging, final)
        published = True
        _fsync_directory(outputs)
        return {
            "output_relative": output_relative,
            "file_count": len(expected),
            "checksums_raw_sha256": hashlib.sha256(ledger).hexdigest(),
            "status": "PASS_ATOMIC_RESEARCH_ONLY_PUBLICATION",
        }
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)


__all__ = [
    "csv_bytes",
    "jsonl_bytes",
    "prediction_csv_bytes",
    "pretty_json_bytes",
    "publish_atomic",
]
