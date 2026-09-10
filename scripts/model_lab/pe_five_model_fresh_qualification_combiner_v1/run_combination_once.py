"""Bootstrap and execute one exact five-model pre-truth composition."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ACTIVATION_LITERAL = "RUN_FIVE_MODEL_FRESH_QUALIFICATION_COMBINATION_ONLY_ONCE"


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
    """Verify every runtime/formula source byte before project imports."""

    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("bootstrap binding is not canonical ASCII") from exc
    if type(payload) is not dict or raw != _canonical(payload, terminal_lf=True):
        raise RuntimeError("bootstrap binding bytes are not canonical")
    if (
        payload.get("schema_version")
        != "expected_pe.five_model.qualification_input_binding.v1"
        or payload.get("status") != "FROZEN_EXACT_PRETRUTH_INPUT_ARTIFACTS"
    ):
        raise RuntimeError("bootstrap binding identity/status differs")
    claimed = payload.get("binding_semantic_sha256")
    unsigned = dict(payload)
    unsigned.pop("binding_semantic_sha256", None)
    if (
        type(claimed) is not str
        or hashlib.sha256(_canonical(unsigned, terminal_lf=False)).hexdigest()
        != claimed
    ):
        raise RuntimeError("bootstrap binding self-seal differs")
    records = payload.get("source_records")
    if type(records) is not list or not records:
        raise RuntimeError("bootstrap source closure is absent")
    seen: set[str] = set()
    for record in records:
        if type(record) is not dict:
            raise RuntimeError("bootstrap source record syntax differs")
        relative = record.get("relative_path")
        candidate = Path(str(relative).replace("\\", "/"))
        if (
            type(relative) is not str
            or candidate.is_absolute()
            or ".." in candidate.parts
            or relative in seen
        ):
            raise RuntimeError("bootstrap source path is unsafe or duplicated")
        seen.add(relative)
        source = (PROJECT_ROOT / candidate).resolve(strict=True)
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
    semantic = hashlib.sha256(
        _canonical(records, terminal_lf=False)
    ).hexdigest()
    if semantic != payload.get("source_records_semantic_sha256"):
        raise RuntimeError("bootstrap source closure semantic hash differs")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-json", type=Path, required=True)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    if args.activation != _ACTIVATION_LITERAL:
        raise RuntimeError("activation literal differs")
    binding_path = args.binding_json.resolve(strict=True)
    bootstrap = _bootstrap_binding(binding_path)

    sys.path.insert(0, str(PROJECT_ROOT))
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.artifacts import (
        canonical_json_bytes,
    )
    from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.binding import (
        read_binding_file,
    )
    from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.contracts import (
        ACTIVATION_LITERAL,
    )
    from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.publisher import (
        run_combination_once,
    )

    if ACTIVATION_LITERAL != _ACTIVATION_LITERAL:
        raise RuntimeError("bootstrap/project activation literals differ")
    binding = read_binding_file(binding_path)
    if binding != bootstrap:
        raise RuntimeError("binding changed after bootstrap verification")
    result = run_combination_once(
        project_root=PROJECT_ROOT,
        binding=binding,
        activation=args.activation,
    )
    sys.stdout.write(canonical_json_bytes(dict(result)).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
