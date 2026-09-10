"""Freeze the public qualification result into a truth-free survivor authority."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_new(path: Path, raw: bytes) -> None:
    path = path.resolve(strict=False)
    if not path.parent.is_dir():
        raise RuntimeError("authority output parent must already exist")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification-result", required=True)
    parser.add_argument("--qualification-result-raw-sha256", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _project_root()
    sys.path.insert(0, str(root))
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.authority import (
        qualification_survivor_freeze,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_json_bytes,
        raw_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
        QUALIFICATION_RESULT_RAW_SHA256,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        stable_read,
    )

    if args.qualification_result_raw_sha256 != QUALIFICATION_RESULT_RAW_SHA256:
        raise RuntimeError("qualification result CLI SHA literal differs")
    result_path = Path(args.qualification_result).resolve(strict=True)
    output_path = Path(args.output)
    try:
        relative = result_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeError("qualification result escaped project") from exc
    result_raw, record = stable_read(result_path, relative_path=relative)
    ref = ArtifactRef(
        relative_path=record.relative_path,
        raw_sha256=record.raw_sha256,
        size_bytes=record.size_bytes,
        volume_serial_number=int(record.volume_serial_number, 16),
        file_id_128=record.file_id_128,
    ).payload()
    freeze = qualification_survivor_freeze(
        result_raw,
        qualification_result_ref=ref,
    )
    output_raw = canonical_json_bytes(freeze)
    _write_new(output_path, output_raw)
    print(raw_sha256(output_raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
