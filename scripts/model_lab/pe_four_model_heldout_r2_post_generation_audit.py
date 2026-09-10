"""Independent, stdlib-only R2 post-generation audit.

This file deliberately lives outside the frozen producer/evaluator packages.  Its
only protected-root read is the metadata-only ``VAULT_MANIFEST.json``.  In
particular, paths carried by ``truth_refs`` are validated as strings and are
never resolved, stat'ed, or opened.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


RUN_ID = "r2_20260824T000005"
PUBLIC_ROOT_NAME = f"model_zoo_pe_four_model_heldout_public_replay_{RUN_ID}"
VAULT_ROOT_NAME = f".model_zoo_pe_four_model_heldout_vault_{RUN_ID}"
ALIASES = tuple(f"heldout_seed_{index:02d}" for index in range(1, 6))
SEEDS = (7691, 7699, 7703, 7717, 7723)
DGPS = tuple("ABCDEFGHIJ")
AUTHORITY_SEMANTIC_SHA256 = (
    "f1afcbf889deeb7859be7338a91540056a36b81a4bce53a6135cfa67313b7920"
)
DESIGN_LOCK_RAW_SHA256 = (
    "cae42b76858f72e0ad0690ccc49a761421b8c17665028a6eb8a498b6cac2f295"
)
QUALIFICATION_RESULT_RAW_SHA256 = (
    "4fbf83c18bbd6f339d4cc3f9ce94b4140349c601d01a9790581adae2d4a8f3a1"
)
GENERATION_PLAN_SEMANTIC_SHA256 = (
    "35bc5d490d044366c1d985944d75f3844e4562c0b2e1312fe5b98cf43b5be27f"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
PUBLIC_FRAME_KEYS = {
    "benchmark",
    "corporate_actions",
    "eps_events",
    "price",
    "public_factors",
}
PUBLIC_FILE_UNIVERSE = {
    "PUBLIC_REPLAY_RECEIPT.json",
    "PUBLIC_TASK_MANIFEST.json",
    "canonical150.csv",
    "v04_overlay.csv",
}
MAX_PATH_CHARS = 239
REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class AuditFailure(RuntimeError):
    def __init__(self, severity: str, code: str, message: str) -> None:
        super().__init__(message)
        self.severity = severity
        self.code = code
        self.safe_message = message


class State:
    def __init__(self) -> None:
        self.check_count = 0
        self.max_path_chars = 0
        self.public_file_identities: set[tuple[int, int]] = set()
        self.task_evidence: list[dict[str, Any]] = []

    def require(
        self, condition: bool, code: str, message: str, severity: str = "P0"
    ) -> None:
        if not condition:
            raise AuditFailure(severity, code, message)
        self.check_count += 1


def compact_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def compact_file_bytes(value: Any) -> bytes:
    return compact_bytes(value) + b"\n"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def semantic_sha256(value: Any) -> str:
    return sha256(compact_bytes(value))


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def parse_json(raw: bytes, *, pretty: bool, state: State) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8" if pretty else "ascii"),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditFailure("P1", "JSON_PARSE", "JSON bytes are invalid") from exc
    state.require(type(value) is dict, "JSON_ROOT", "JSON root is not an object", "P1")
    expected = pretty_bytes(value) if pretty else compact_file_bytes(value)
    state.require(raw == expected, "JSON_CANONICAL", "JSON canonical bytes differ", "P1")
    return value


def _is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & REPARSE_FLAG)


def check_path(path: Path, *, state: State, kind: str) -> os.stat_result:
    absolute = Path(os.path.abspath(path))
    state.max_path_chars = max(state.max_path_chars, len(str(absolute)))
    state.require(
        len(str(absolute)) <= MAX_PATH_CHARS,
        "PATH_LENGTH",
        "audited path is 240 characters or longer",
        "P1",
    )
    try:
        state.require(not _is_reparse(absolute), "REPARSE_POINT", "reparse point detected")
        info = os.lstat(absolute)
    except OSError as exc:
        raise AuditFailure("P1", "PATH_STAT", "required audit path is unavailable") from exc
    if kind == "file":
        state.require(stat.S_ISREG(info.st_mode), "PATH_TYPE", "expected regular file", "P1")
    elif kind == "dir":
        state.require(stat.S_ISDIR(info.st_mode), "PATH_TYPE", "expected directory", "P1")
    else:  # pragma: no cover - internal call contract
        raise AssertionError(kind)
    return info


def stable_read(path: Path, *, state: State) -> tuple[bytes, os.stat_result]:
    before = check_path(path, state=state, kind="file")
    raw = path.read_bytes()
    after = os.lstat(path)
    state.require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        "FILE_MUTATION",
        "file changed during audit read",
    )
    state.require(len(raw) == after.st_size, "FILE_SIZE", "file read size differs", "P1")
    return raw, after


def inventory(path: Path, expected: set[str], *, state: State) -> dict[str, os.DirEntry[str]]:
    check_path(path, state=state, kind="dir")
    entries = {entry.name: entry for entry in os.scandir(path)}
    state.require(set(entries) == expected, "FILE_UNIVERSE", "file universe differs")
    state.require(
        len({name.casefold() for name in entries}) == len(entries),
        "CASE_COLLISION",
        "case-folded path collision detected",
    )
    for name, entry in entries.items():
        check_path(Path(entry.path), state=state, kind="file" if "." in name else "dir")
    return entries


def _hex_sha(value: Any) -> bool:
    return type(value) is str and SHA256_RE.fullmatch(value) is not None


def validate_ref(
    ref: Any,
    *,
    expected_relative_path: str,
    live_path: Path,
    raw: bytes,
    info: os.stat_result,
    state: State,
) -> None:
    state.require(
        type(ref) is dict
        and set(ref)
        == {"file_id_128", "raw_sha256", "relative_path", "size_bytes", "volume_serial_number"},
        "ARTIFACT_REF_SCHEMA",
        "public ArtifactRef schema differs",
        "P1",
    )
    state.require(ref["relative_path"] == expected_relative_path, "ARTIFACT_PATH", "public ArtifactRef path differs")
    state.require(_hex_sha(ref["raw_sha256"]), "ARTIFACT_SHA_FORMAT", "public ArtifactRef hash malformed", "P1")
    state.require(ref["raw_sha256"] == sha256(raw), "ARTIFACT_SHA", "public ArtifactRef hash differs")
    state.require(ref["size_bytes"] == len(raw), "ARTIFACT_SIZE", "public ArtifactRef size differs", "P1")
    state.require(
        type(ref["volume_serial_number"]) is int
        and ref["volume_serial_number"] == info.st_dev,
        "ARTIFACT_VOLUME",
        "public ArtifactRef volume identity differs",
    )
    file_id = ref["file_id_128"]
    state.require(
        type(file_id) is str and re.fullmatch(r"[0-9a-f]{32}", file_id) is not None,
        "ARTIFACT_FILE_ID_FORMAT",
        "public ArtifactRef FileId malformed",
        "P1",
    )
    state.require(
        int.from_bytes(bytes.fromhex(file_id), "little") == info.st_ino,
        "ARTIFACT_FILE_ID",
        "public ArtifactRef FileId differs",
    )
    identity = (info.st_dev, info.st_ino)
    state.require(identity not in state.public_file_identities, "PUBLIC_HARDLINK", "public file identity alias detected")
    state.public_file_identities.add(identity)
    state.require(live_path.is_file(), "PUBLIC_LIVE_FILE", "public artifact is not live", "P1")


def csv_geometry(raw: bytes, *, columns: int, state: State) -> tuple[str, tuple[str, ...]]:
    state.require(raw.endswith(b"\n"), "CSV_FINAL_NEWLINE", "CSV final newline differs", "P1")
    state.require(raw.count(b"\n") == 1801, "CSV_LINE_COUNT", "CSV line count differs", "P1")
    try:
        text = raw.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text, newline=""))
        header = next(reader)
        dates: list[str] = []
        for row in reader:
            if len(row) != columns or DATE_RE.fullmatch(row[0]) is None:
                raise ValueError("row geometry")
            dates.append(row[0])
    except (UnicodeDecodeError, csv.Error, StopIteration, ValueError) as exc:
        raise AuditFailure("P1", "CSV_GEOMETRY", "CSV header, row width, or identity differs") from exc
    state.require(len(header) == columns and header[0] == "date", "CSV_HEADER", "CSV header differs", "P1")
    state.require(len(dates) == 1800 and dates == sorted(set(dates)), "CSV_IDENTITY", "CSV date identity differs")
    first_line = raw.split(b"\n", 1)[0].rstrip(b"\r")
    return sha256(first_line), tuple(dates)


def scan_public_protection(value: Any, *, state: State) -> None:
    false_flags = {
        "protected_generator_imported",
        "protected_path_received",
        "protected_value_received",
        "score_fit_prediction_evaluation",
        "truth_namespace_accessed",
        "truth_ref_inventory_received_by_public_process",
    }
    zero_counts = {
        "score_open_count",
        "truth_open_count",
        "truth_open_count_by_controller",
        "truth_open_count_by_public_process",
    }
    forbidden_value_tokens = ("heldout_vault", "/truth.csv", "\\truth.csv", "latent_events.csv")

    def walk(node: Any) -> None:
        if type(node) is dict:
            for key, child in node.items():
                if key in false_flags:
                    state.require(child is False, "PROTECTED_FLAG", "public protected-access flag is not false")
                if key in zero_counts:
                    state.require(type(child) is int and child == 0, "ACCESS_COUNT", "public access count is not zero")
                walk(child)
        elif type(node) is list:
            for child in node:
                walk(child)
        elif type(node) is str:
            lowered = node.casefold()
            state.require(
                not any(token in lowered for token in forbidden_value_tokens),
                "PROTECTED_VALUE",
                "protected path/value appeared in public JSON",
            )

    walk(value)


def expected_geometry(dgp: str) -> dict[str, int]:
    return {
        "benchmark": 1800,
        "corporate_actions": 0,
        "eps_events": 29,
        "price": 1800,
        "public_factors": 1800 if dgp == "I" else 3600,
    }


def validate_upstream(
    upstream: Any,
    *,
    canonical_sha: str,
    overlay_sha: str,
    canonical_header_sha: str,
    overlay_header_sha: str,
    state: State,
) -> None:
    state.require(type(upstream) is dict, "UPSTREAM_SCHEMA", "upstream receipt differs")
    expected_scalars = {
        "schema_version": "expected_pe.r7.qualification.public_replay_receipt.v1",
        "status": "PASS_SCORE_FREE_PUBLIC_CANONICAL_OVERLAY_REPLAY",
        "stage": "QUALIFICATION",
        "canonical150_rows": 1800,
        "canonical150_columns": 150,
        "v04_overlay_rows": 1800,
        "v04_overlay_columns": 254,
        "canonical150_raw_sha256": canonical_sha,
        "v04_overlay_raw_sha256": overlay_sha,
        "canonical150_header_raw_sha256": canonical_header_sha,
        "v04_overlay_header_raw_sha256": overlay_header_sha,
        "protected_path_received": False,
        "truth_namespace_accessed": False,
        "score_fit_prediction_evaluation": False,
    }
    for key, expected in expected_scalars.items():
        state.require(upstream.get(key) == expected, "UPSTREAM_BINDING", "upstream replay binding differs")


def validate_task(
    *,
    project: Path,
    public_root: Path,
    task_root: Path,
    alias: str,
    seed: int,
    dgp: str,
    ordinal: int,
    embedded: Any,
    state: State,
) -> None:
    inventory(task_root, PUBLIC_FILE_UNIVERSE, state=state)
    paths = {name: task_root / name for name in PUBLIC_FILE_UNIVERSE}
    raw_manifest, manifest_info = stable_read(paths["PUBLIC_TASK_MANIFEST.json"], state=state)
    raw_receipt, receipt_info = stable_read(paths["PUBLIC_REPLAY_RECEIPT.json"], state=state)
    canonical_raw, canonical_info = stable_read(paths["canonical150.csv"], state=state)
    overlay_raw, overlay_info = stable_read(paths["v04_overlay.csv"], state=state)
    manifest = parse_json(raw_manifest, pretty=True, state=state)
    receipt = parse_json(raw_receipt, pretty=True, state=state)
    scan_public_protection(manifest, state=state)
    scan_public_protection(receipt, state=state)
    state.require(receipt == embedded, "EMBEDDED_RECEIPT", "generation receipt task binding differs")
    task = {
        "data_seed": seed,
        "dgp_id": dgp,
        "estimator_rng_alias": alias,
        "estimator_rng_seed": seed,
        "seed_alias": alias,
        "task_ordinal": ordinal,
    }
    state.require(
        manifest.get("schema_version") == "expected_pe.four_model.heldout_public_task_manifest.v1"
        and manifest.get("status") == "PASS_TWO_PUBLIC_REPLAYS_FROZEN_PRETRUTH"
        and manifest.get("task") == task,
        "TASK_IDENTITY",
        "public task manifest identity differs",
    )
    unsigned = dict(manifest)
    seal = unsigned.pop("task_manifest_semantic_sha256", None)
    state.require(_hex_sha(seal) and seal == semantic_sha256(unsigned), "MANIFEST_SELF_SEAL", "task manifest self-seal differs")
    geometry = expected_geometry(dgp)
    state.require(
        set(manifest.get("public_frame_rows", {})) == PUBLIC_FRAME_KEYS
        and manifest.get("public_frame_rows") == geometry,
        "RAW_GEOMETRY",
        "declared heterogeneous public raw geometry differs",
    )
    hashes = manifest.get("public_frame_raw_sha256")
    state.require(
        type(hashes) is dict and set(hashes) == PUBLIC_FRAME_KEYS and all(_hex_sha(value) for value in hashes.values()),
        "RAW_HASHES",
        "declared public raw hashes differ",
    )
    for key in (
        "public_frame_raw_hashes_equal",
        "public_frame_rows_equal",
        "canonical_replay_bytes_equal",
        "overlay_replay_bytes_equal",
    ):
        state.require(manifest.get(key) is True, "TWO_PASS_FLAG", "task two-pass equality flag differs")
    state.require(
        manifest.get("public_replay_design_lock_raw_sha256") == DESIGN_LOCK_RAW_SHA256,
        "DESIGN_LOCK",
        "public design lock differs",
    )

    canonical_header, canonical_dates = csv_geometry(canonical_raw, columns=150, state=state)
    overlay_header, overlay_dates = csv_geometry(overlay_raw, columns=254, state=state)
    state.require(canonical_dates == overlay_dates, "CSV_IDENTITY_JOIN", "canonical/overlay row identities differ")
    base = f"outputs/{PUBLIC_ROOT_NAME}/{alias}/dgp_{dgp}"
    validate_ref(
        manifest.get("canonical_ref"),
        expected_relative_path=f"{base}/canonical150.csv",
        live_path=paths["canonical150.csv"],
        raw=canonical_raw,
        info=canonical_info,
        state=state,
    )
    validate_ref(
        manifest.get("overlay_ref"),
        expected_relative_path=f"{base}/v04_overlay.csv",
        live_path=paths["v04_overlay.csv"],
        raw=overlay_raw,
        info=overlay_info,
        state=state,
    )
    validate_ref(
        receipt.get("task_manifest_ref"),
        expected_relative_path=f"{base}/PUBLIC_TASK_MANIFEST.json",
        live_path=paths["PUBLIC_TASK_MANIFEST.json"],
        raw=raw_manifest,
        info=manifest_info,
        state=state,
    )
    state.public_file_identities.add((receipt_info.st_dev, receipt_info.st_ino))
    state.require(receipt.get("canonical_ref") == manifest.get("canonical_ref"), "RECEIPT_REF", "canonical receipt ref differs")
    state.require(receipt.get("overlay_ref") == manifest.get("overlay_ref"), "RECEIPT_REF", "overlay receipt ref differs")
    state.require(receipt.get("task_manifest_semantic_sha256") == seal, "RECEIPT_SEAL", "receipt manifest seal differs")
    expected_receipt = {
        "schema_version": "expected_pe.four_model.heldout_public_replay_receipt.v1",
        "status": "PASS_TWO_PUBLIC_PASSES_BYTE_EXACT_PRETRUTH",
        "data_seed": seed,
        "dgp_id": dgp,
        "seed_alias": alias,
        "task_ordinal": ordinal,
        "rows": 1800,
        "replay_pass": 1,
        "public_replay_design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
        "protected_generator_imported": False,
        "protected_path_received": False,
        "protected_value_received": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "public_frame_raw_hashes_equal": True,
        "public_frame_rows_equal": True,
        "canonical_replay_bytes_equal": True,
        "overlay_replay_bytes_equal": True,
    }
    for key, expected in expected_receipt.items():
        state.require(receipt.get(key) == expected, "RECEIPT_EXACT", "public replay receipt differs")
    state.require(receipt.get("public_frame_rows") == geometry, "RECEIPT_GEOMETRY", "receipt geometry differs")
    state.require(receipt.get("public_frame_raw_sha256") == hashes, "RECEIPT_RAW_HASH", "receipt raw hash binding differs")
    pass_1 = receipt.get("pass_1_replay_receipt")
    pass_2 = receipt.get("pass_2_replay_receipt")
    state.require(type(pass_1) is dict and type(pass_2) is dict, "PASS_RECEIPTS", "two-pass receipts missing")
    normalized_1, normalized_2 = dict(pass_1), dict(pass_2)
    state.require(normalized_1.pop("replay_pass", None) == 1, "PASS_ORDINAL", "pass-1 ordinal differs")
    state.require(normalized_2.pop("replay_pass", None) == 2, "PASS_ORDINAL", "pass-2 ordinal differs")
    state.require(normalized_1 == normalized_2, "TWO_PASS_RECEIPT", "pass-1/pass-2 receipts differ")
    state.require(
        pass_1.get("public_frame_rows") == geometry
        and pass_2.get("public_frame_rows") == geometry
        and pass_1.get("public_frame_raw_sha256") == hashes
        and pass_2.get("public_frame_raw_sha256") == hashes,
        "TWO_PASS_RAW_BINDING",
        "two-pass raw declarations differ",
    )
    canonical_sha, overlay_sha = sha256(canonical_raw), sha256(overlay_raw)
    for upstream in (
        receipt.get("upstream_replay_receipt"),
        pass_1.get("upstream_replay_receipt"),
        pass_2.get("upstream_replay_receipt"),
    ):
        validate_upstream(
            upstream,
            canonical_sha=canonical_sha,
            overlay_sha=overlay_sha,
            canonical_header_sha=canonical_header,
            overlay_header_sha=overlay_header,
            state=state,
        )
    state.require(
        receipt.get("upstream_replay_receipt") == pass_1.get("upstream_replay_receipt")
        == pass_2.get("upstream_replay_receipt"),
        "TWO_PASS_UPSTREAM",
        "two-pass upstream receipts differ",
    )
    state.task_evidence.append(
        {
            "data_seed": seed,
            "dgp_id": dgp,
            "task_ordinal": ordinal,
            "public_frame_rows": geometry,
            "manifest_raw_sha256": sha256(raw_manifest),
            "receipt_raw_sha256": sha256(raw_receipt),
            "canonical_raw_sha256": canonical_sha,
            "overlay_raw_sha256": overlay_sha,
        }
    )


def validate_vault_manifest(raw: bytes, *, project: Path, state: State) -> dict[str, Any]:
    manifest = parse_json(raw, pretty=False, state=state)
    core = dict(manifest)
    seal = core.pop("vault_manifest_semantic_sha256", None)
    state.require(_hex_sha(seal) and seal == semantic_sha256(core), "VAULT_SELF_SEAL", "vault manifest self-seal differs")
    expected = {
        "schema_version": "expected_pe.four_model.heldout_vault_manifest.v1",
        "status": "FROZEN_PROTECTED_TRUTH_REFS_NO_OUTER_TRUTH_CONTENT_OPEN",
        "vault_relative_path": f"outputs/{VAULT_ROOT_NAME}",
        "qualification_result_raw_sha256": QUALIFICATION_RESULT_RAW_SHA256,
        "generation_plan_semantic_sha256": GENERATION_PLAN_SEMANTIC_SHA256,
        "truth_ref_count": 50,
        "protected_task_metadata_count": 100,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "metadata_read_count": 100,
        "pass_1_pass_2_protected_hashes_equal": True,
        "pass_1_pass_2_public_hashes_equal": True,
        "truth_content_open_count": 0,
        "truth_attribute_open_count_by_manifest_builder": 0,
        "truth_attribute_open_count_at_protected_write_time": 100,
        "pass_2_truth_ref_export_count": 0,
        "latent_ref_export_count": 0,
        "truth_refs_origin": "protected_write_time_FILE_READ_ATTRIBUTES_only",
        "outer_truth_content_open_count": 0,
        "evaluator_pre_marker_truth_content_open_count": 0,
    }
    for key, value in expected.items():
        state.require(manifest.get(key) == value, "VAULT_EXACT", "vault manifest metadata differs")
    refs = manifest.get("truth_refs")
    state.require(type(refs) is list and len(refs) == 50, "VAULT_REF_COUNT", "vault truth-ref count differs")
    identities: set[tuple[int, str]] = set()
    for ordinal, (seed, dgp) in enumerate((seed, dgp) for seed in SEEDS for dgp in DGPS):
        ref = refs[ordinal]
        state.require(
            type(ref) is dict
            and set(ref)
            == {"file_id_128", "raw_sha256", "relative_path", "size_bytes", "volume_serial_number"},
            "VAULT_REF_SCHEMA",
            "vault ref metadata schema differs",
        )
        expected_path = f"outputs/{VAULT_ROOT_NAME}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv"
        state.require(ref["relative_path"] == expected_path, "VAULT_REF_ORDER", "vault ref identity/order differs")
        state.require(_hex_sha(ref["raw_sha256"]) and type(ref["size_bytes"]) is int and ref["size_bytes"] > 0, "VAULT_REF_METADATA", "vault ref metadata differs")
        state.require(
            type(ref["volume_serial_number"]) is int
            and type(ref["file_id_128"]) is str
            and re.fullmatch(r"[0-9a-f]{32}", ref["file_id_128"]) is not None,
            "VAULT_REF_IDENTITY",
            "vault ref file identity differs",
        )
        identity = (ref["volume_serial_number"], ref["file_id_128"])
        state.require(identity not in identities, "VAULT_REF_ALIAS", "vault ref identity alias detected")
        identities.add(identity)
        # Lexical length only: deliberately do not resolve/stat/open this path.
        lexical = Path(os.path.abspath(project / Path(*expected_path.split("/"))))
        state.max_path_chars = max(state.max_path_chars, len(str(lexical)))
        state.require(len(str(lexical)) <= MAX_PATH_CHARS, "PATH_LENGTH", "vault ref path is 240 characters or longer", "P1")
    return manifest


def run_audit(project: Path) -> dict[str, Any]:
    state = State()
    project = Path(os.path.abspath(project))
    check_path(project, state=state, kind="dir")
    outputs = project / "outputs"
    check_path(outputs, state=state, kind="dir")
    public_root = outputs / PUBLIC_ROOT_NAME
    vault_root = outputs / VAULT_ROOT_NAME
    check_path(vault_root, state=state, kind="dir")
    expected_root = set(ALIASES) | {"GENERATION_EXECUTION_RECEIPT.json"}
    inventory(public_root, expected_root, state=state)
    generation_raw, generation_info = stable_read(public_root / "GENERATION_EXECUTION_RECEIPT.json", state=state)
    state.public_file_identities.add((generation_info.st_dev, generation_info.st_ino))
    generation = parse_json(generation_raw, pretty=False, state=state)
    scan_public_protection(generation, state=state)
    expected_generation = {
        "schema_version": "expected_pe.four_model.heldout_generation_execution.v1",
        "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
        "run_id": RUN_ID,
        "execution_authority_semantic_sha256": AUTHORITY_SEMANTIC_SHA256,
        "source_frozen_before_generation": True,
        "task_count": 50,
        "outer_workers": 16,
        "inner_blas_threads": 1,
        "cpu_affinity": "CPU0-31",
        "gpu_enabled": False,
        "protected_public_process_separation": True,
        "anonymous_one_way_pipe_used": True,
        "public_pass_1_pass_2_byte_exact": True,
        "truth_ref_inventory_received_by_public_process": False,
        "truth_open_count_by_controller": 0,
        "truth_open_count_by_public_process": 0,
        "score_open_count": 0,
    }
    for key, expected in expected_generation.items():
        state.require(generation.get(key) == expected, "GENERATION_EXACT", "generation receipt differs")
    embedded = generation.get("public_task_receipts")
    state.require(type(embedded) is list and len(embedded) == 50, "GENERATION_TASK_COUNT", "generation embedded receipt count differs")
    for seed_index, (alias, seed) in enumerate(zip(ALIASES, SEEDS, strict=True)):
        alias_root = public_root / alias
        inventory(alias_root, {f"dgp_{dgp}" for dgp in DGPS}, state=state)
        for dgp_index, dgp in enumerate(DGPS):
            ordinal = seed_index * 10 + dgp_index
            validate_task(
                project=project,
                public_root=public_root,
                task_root=alias_root / f"dgp_{dgp}",
                alias=alias,
                seed=seed,
                dgp=dgp,
                ordinal=ordinal,
                embedded=embedded[ordinal],
                state=state,
            )
    state.require(len(state.public_file_identities) == 201, "PUBLIC_FILE_ALIAS", "public file identities are not unique")
    geometries = {semantic_sha256(item["public_frame_rows"]) for item in state.task_evidence}
    state.require(len(geometries) == 2, "HETEROGENEOUS_GEOMETRY", "heterogeneous raw geometry was not preserved")

    # This is the only protected-root file opened by this program.
    vault_manifest_path = vault_root / "VAULT_MANIFEST.json"
    vault_raw, _ = stable_read(vault_manifest_path, state=state)
    validate_vault_manifest(vault_raw, project=project, state=state)
    task_inventory_semantic = semantic_sha256(state.task_evidence)
    report: dict[str, Any] = {
        "schema_version": "expected_pe.four_model.r2_post_generation_audit.v1",
        "status": "GO_R2_POST_GENERATION_P0_0_P1_0_P2_0",
        "run_id": RUN_ID,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "authority": {"execution_authority_semantic_sha256": AUTHORITY_SEMANTIC_SHA256},
        "public_evidence": {
            "root_entry_count": 6,
            "seed_alias_count": 5,
            "dgp_count_per_alias": 10,
            "task_count": 50,
            "public_file_count": 201,
            "canonical_rows_per_task": 1800,
            "overlay_rows_per_task": 1800,
            "generation_receipt_raw_sha256": sha256(generation_raw),
            "task_inventory_semantic_sha256": task_inventory_semantic,
            "two_distinct_declared_raw_geometry_profiles": True,
            "truth_open_count": 0,
            "score_open_count": 0,
            "protected_path_or_value_received": False,
        },
        "vault_metadata_evidence": {
            "manifest_raw_sha256": sha256(vault_raw),
            "truth_ref_count": 50,
            "truth_content_open_count": 0,
            "outer_truth_content_open_count": 0,
            "evaluator_pre_marker_truth_content_open_count": 0,
            "latent_ref_export_count": 0,
            "payload_directories_enumerated": False,
            "payload_refs_resolved_or_statted": 0,
            "payload_leaves_opened": 0,
        },
        "filesystem_evidence": {
            "reparse_points": 0,
            "max_audited_path_chars": state.max_path_chars,
            "path_limit_exclusive": 240,
        },
        "audit_check_count": state.check_count,
        "auditor_source_raw_sha256": sha256(Path(__file__).read_bytes()),
    }
    report["audit_semantic_sha256"] = semantic_sha256(report)
    return report


def failure_report(failure: AuditFailure, *, source_hash: str) -> dict[str, Any]:
    counts = {"P0": 0, "P1": 0, "P2": 0}
    counts[failure.severity] = 1
    report: dict[str, Any] = {
        "schema_version": "expected_pe.four_model.r2_post_generation_audit.v1",
        "status": "NO_GO_R2_POST_GENERATION_AUDIT",
        "run_id": RUN_ID,
        "finding_counts": counts,
        "findings": [
            {
                "severity": failure.severity,
                "code": failure.code,
                "message": failure.safe_message,
            }
        ],
        "protected_boundary": {
            "payload_directories_enumerated": False,
            "payload_refs_resolved_or_statted": 0,
            "payload_leaves_opened": 0,
        },
        "auditor_source_raw_sha256": source_hash,
    }
    report["audit_semantic_sha256"] = semantic_sha256(report)
    return report


def publish(report: dict[str, Any], *, project: Path, output: Path) -> str:
    project = Path(os.path.abspath(project))
    build = project / "build"
    output = Path(os.path.abspath(output))
    if output.parent.parent != build or output.suffix.casefold() != ".json":
        raise AuditFailure("P1", "OUTPUT_SCOPE", "audit output must be one directory below project/build")
    check_state = State()
    check_path(build, state=check_state, kind="dir")
    if output.parent.exists():
        raise AuditFailure("P1", "OUTPUT_EXISTS", "audit output directory already exists")
    output.parent.mkdir()
    raw = pretty_bytes(report)
    with output.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    observed = output.read_bytes()
    if observed != raw:
        raise AuditFailure("P1", "OUTPUT_MUTATION", "published audit bytes differ")
    return sha256(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    source_hash = sha256(Path(__file__).read_bytes())
    try:
        report = run_audit(args.project_root)
    except AuditFailure as failure:
        report = failure_report(failure, source_hash=source_hash)
    except Exception:
        report = failure_report(
            AuditFailure("P0", "UNEXPECTED_EXCEPTION", "unexpected fail-closed audit exception"),
            source_hash=source_hash,
        )
    try:
        raw_hash = publish(report, project=args.project_root, output=args.output)
    except AuditFailure as failure:
        print(json.dumps({"status": "NO_GO_AUDIT_PUBLICATION", "code": failure.code}, sort_keys=True))
        return 3
    print(
        json.dumps(
            {
                "status": report["status"],
                "audit_raw_sha256": raw_hash,
                "audit_semantic_sha256": report["audit_semantic_sha256"],
                "finding_counts": report["finding_counts"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if report["status"].startswith("GO_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
