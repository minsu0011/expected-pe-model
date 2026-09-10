"""CLI entry point for one exact, bound PE-C1--C3 prediction publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ACTIVATION_LITERAL = "RUN_FRESH_C1_C3_QUALIFICATION_PREDICTION_ONLY_ONCE"
_LOCAL_REQUIRED = (
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/__init__.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/artifacts.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/contracts.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/custody.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/prediction.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/publisher.py",
    "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/DESIGN.md",
    "scripts/model_lab/pe_c1_c3_fresh_qualification_prediction_v1/freeze_binding.py",
    "scripts/model_lab/pe_c1_c3_fresh_qualification_prediction_v1/run_prediction_once.py",
    "tests/model_lab/test_pe_c1_c3_fresh_qualification_prediction_v1.py",
)


def _canonical(value: object, *, terminal_lf: bool) -> bytes:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return raw + (b"\n" if terminal_lf else b"")


def _bootstrap_binding(path: Path) -> dict[str, object]:
    """Verify all downstream source bytes before importing any project module."""

    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("bootstrap binding is not canonical ASCII") from exc
    if type(payload) is not dict or raw != _canonical(payload, terminal_lf=True):
        raise RuntimeError("bootstrap binding bytes are not canonical")
    if (
        payload.get("schema_version")
        != "expected_pe.pe_c1_c3.fresh_qualification_binding.v1"
        or payload.get("status") != "FROZEN_POSTGEN_AUDITED_PREDICTION_ONLY"
    ):
        raise RuntimeError("bootstrap binding identity/status differs")
    claimed = payload.get("binding_semantic_sha256")
    unsigned = dict(payload)
    unsigned.pop("binding_semantic_sha256", None)
    if (
        type(claimed) is not str
        or hashlib.sha256(_canonical(unsigned, terminal_lf=False)).hexdigest() != claimed
    ):
        raise RuntimeError("bootstrap binding self-seal differs")
    records = payload.get("source_records")
    if type(records) is not list:
        raise RuntimeError("bootstrap source records are absent")
    by_relative = {}
    for record in records:
        if type(record) is not dict:
            raise RuntimeError("bootstrap source record syntax differs")
        relative = record.get("relative_path")
        candidate = Path(str(relative).replace("\\", "/"))
        if (
            type(relative) is not str
            or candidate.is_absolute()
            or ".." in candidate.parts
            or relative in by_relative
        ):
            raise RuntimeError("bootstrap source path is unsafe or duplicated")
        by_relative[relative] = record
    if any(relative not in by_relative for relative in _LOCAL_REQUIRED):
        raise RuntimeError("bootstrap local source closure is incomplete")
    for relative, record in by_relative.items():
        source = (PROJECT_ROOT / relative).resolve(strict=True)
        try:
            source.relative_to(PROJECT_ROOT)
        except ValueError as exc:
            raise RuntimeError("bootstrap source escaped project root") from exc
        content = source.read_bytes()
        if (
            len(content) != record.get("size_bytes")
            or hashlib.sha256(content).hexdigest() != record.get("raw_sha256")
        ):
            raise RuntimeError(f"bootstrap source bytes differ: {relative}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-json", type=Path, required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    if args.activation != _ACTIVATION_LITERAL:
        raise RuntimeError("activation literal differs")
    binding_path = args.binding_json.resolve(strict=True)
    bootstrap_binding = _bootstrap_binding(binding_path)

    sys.path.insert(0, str(PROJECT_ROOT))
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.artifacts import (
        canonical_json_bytes,
    )
    from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.contracts import (
        ACTIVATION_LITERAL,
    )
    from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.custody import (
        read_binding_file,
    )
    from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.publisher import (
        run_prediction_once,
    )

    if ACTIVATION_LITERAL != _ACTIVATION_LITERAL:
        raise RuntimeError("bootstrap/project activation literals differ")
    binding = read_binding_file(binding_path)
    if binding != bootstrap_binding:
        raise RuntimeError("binding changed after bootstrap source verification")
    result = run_prediction_once(
        project_root=PROJECT_ROOT,
        binding=binding,
        activation=args.activation,
    )
    sys.stdout.write(canonical_json_bytes(dict(result)).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
