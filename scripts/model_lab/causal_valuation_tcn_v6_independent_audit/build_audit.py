"""Build and verify the immutable independent TCN V6 score-free audit."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any, Mapping


PROJECT = Path(
    "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
SUBJECT_RELATIVE = (
    "outputs/model_zoo_causal_valuation_tcn_v6_"
    "score_free_design_environment_preflight_20260821"
)
SUBJECT = PROJECT / SUBJECT_RELATIVE
AUDIT_NAME = (
    "model_zoo_causal_valuation_tcn_v6_"
    "independent_score_free_prelaunch_audit_r1_20260821"
)
AUDIT_ROOT = PROJECT / "outputs" / AUDIT_NAME
PROBE_SOURCE = (
    PROJECT
    / "scripts/model_lab/causal_valuation_tcn_v6_independent_audit/independent_probes.py"
)
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
TRUSTED_LAUNCHER = (
    PROJECT / "scripts/model_lab/causal_valuation_tcn_v6/trusted_launcher.py"
)
RUFF = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
EXPECTED_CHECKSUMS_SHA256 = (
    "030917397f474f9cbfa26e4aa8515b75fc70e5f62506ff73ad7476486bac8271"
)
EXPECTED_SEAL_SHA256 = (
    "320ceb73f23622b2767fb054f1205498ad80384fbc62b0ef7ffe3c026aab34bf"
)
EXPECTED_ANCHOR_SHA256 = (
    "1f833f41e9216f7e4625b67211f8230c62927237ebbcd9b58edf5fff7e01cfdd"
)
EXPECTED_ANCHOR_LEDGER_SHA256 = (
    "901c5e4badb2c51b78ddbd4ccd935ba0787cc9a336b98374b43415e799ca780a"
)
EXPECTED_BUNDLE_TREE_SHA256 = (
    "031da8e0a8dd9e3696409327644879812252afa55f03cd0b68819f0e2baf0c9a"
)
EXPECTED_SOURCE_MANIFEST_SHA256 = (
    "e8ff976330fcd6cd00df1643ee09fb87896886746cb4208e5b64c750b367b58b"
)
EXPECTED_BUNDLE_FILES = (
    "ACCESS_RECEIPT.json",
    "CHECKSUMS.sha256",
    "DESIGN.md",
    "DESIGN_CONTRACT.json",
    "ENVIRONMENT_DEPENDENCY_CLOSURE.json",
    "INPUT_AGNOSTIC_PREFLIGHT.json",
    "MANIFEST.json",
    "MODEL_HYPOTHESIS.md",
    "QUALITY_RECEIPT.json",
    "REFERENCE_LICENSE_REGISTRY.json",
    "SEAL.json",
    "SOURCE_CLOSURE.json",
    "STATIC_SOURCE_AUDIT.json",
    "SYNTHETIC_SMOKE.json",
)
AUTHORITY_ZERO = {
    "evaluation": False,
    "heldout": False,
    "promotion": False,
    "real_fit": False,
    "real_prediction": False,
    "registry_or_champion": False,
    "score": False,
    "seed_derivation_or_reservation": False,
    "truth_or_vault": False,
}
SEVERITY_COUNTS = {"P0": 0, "P1": 1, "P2": 0}
VERDICT = "NO_GO_CAUSAL_VALUATION_TCN_V6_STATE_LIFECYCLE_BOUNDARY_REPAIR_REQUIRED"
FINAL_FILES = (
    "ACCESS_RECEIPT.json",
    "AUDIT.json",
    "CHECKSUMS.sha256",
    "HOFS_V11_OPERATIONAL_NOTE.json",
    "INDEPENDENT_PROBES.py",
    "INDEPENDENT_PROBE_RECEIPT.json",
    "MANIFEST.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "SEAL.json",
    "SUBJECT_CLOSURE.json",
)
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class AuditError(RuntimeError):
    pass


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024 * 1024):
            hasher.update(block)
    return hasher.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _sealed(value: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(value))
    result.pop("semantic_sha256", None)
    result["semantic_sha256"] = _sha(_canonical(result))
    return result


def _strict_object_bytes(content: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if type(key) is not str or key in result:
                raise AuditError(f"duplicate/invalid JSON key: {label}:{key!r}")
            result[key] = value
        return result

    try:
        result = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                AuditError(f"non-finite JSON token: {label}:{token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"invalid strict JSON: {label}") from error
    if type(result) is not dict:
        raise AuditError(f"JSON root is not an object: {label}")
    return result


def _strict_object(path: Path) -> dict[str, Any]:
    return _strict_object_bytes(path.read_bytes(), label=path.as_posix())


def _semantic(value: Mapping[str, Any]) -> str:
    unsigned = copy.deepcopy(dict(value))
    expected = unsigned.pop("semantic_sha256", None)
    actual = _sha(_canonical(unsigned))
    if expected != actual:
        raise AuditError("semantic SHA-256 drifted")
    return actual


def _ordinary(path: Path, *, directory: bool | None = None) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE
        ):
            raise AuditError(f"reparse/symlink path component: {current}")
    metadata = os.lstat(absolute)
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise AuditError(f"not an ordinary directory: {absolute}")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise AuditError(f"not an ordinary file: {absolute}")
    return absolute


def _record(path: Path, *, relative_to: Path | None = None) -> dict[str, object]:
    path = _ordinary(path, directory=False)
    return {
        "path": (
            path.relative_to(relative_to).as_posix()
            if relative_to is not None
            else path.as_posix()
        ),
        "bytes": path.stat().st_size,
        "raw_sha256": _sha_file(path),
    }


def _tree_hash(records: list[dict[str, object]]) -> str:
    return _sha(_canonical(records))


def _verify_ledger(
    root: Path,
    expected_raw: str | None = None,
    *,
    expected_unlisted: tuple[str, ...] = (),
) -> list[str]:
    ledger = _ordinary(root / "CHECKSUMS.sha256", directory=False)
    if expected_raw is not None and _sha_file(ledger) != expected_raw:
        raise AuditError(f"checksum ledger raw hash drifted: {root}")
    names: list[str] = []
    for line in ledger.read_bytes().decode("ascii", errors="strict").splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise AuditError(f"malformed checksum row: {root}")
        digest, name = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not name
            or "/" in name
            or "\\" in name
            or name in names
        ):
            raise AuditError(f"unsafe checksum row: {root}")
        if _sha_file(_ordinary(root / name, directory=False)) != digest:
            raise AuditError(f"checksum member drifted: {root / name}")
        names.append(name)
    if names != sorted(names):
        raise AuditError(f"checksum member order drifted: {root}")
    live = sorted(path.name for path in root.iterdir() if path.is_file())
    if live != sorted([*names, "CHECKSUMS.sha256", *expected_unlisted]):
        raise AuditError(f"checksum file universe drifted: {root}")
    return names


def _verify_live_record(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {"path", "bytes", "raw_sha256"}:
        raise AuditError("live file record schema drifted")
    live = _record(Path(str(value["path"])))
    if live != value:
        raise AuditError(f"live file record drifted: {value.get('path')}")
    return live


def _verify_terminal_binding(binding: Mapping[str, Any]) -> dict[str, object]:
    root = PROJECT / str(binding["relative_root"])
    _ordinary(root, directory=True)
    _verify_ledger(root, str(binding["checksums_raw_sha256"]))
    audit = _strict_object(root / "AUDIT.json")
    if (
        _sha_file(root / "AUDIT.json") != binding["audit_raw_sha256"]
        or _semantic(audit) != binding["audit_semantic_sha256"]
        or audit.get("verdict") != binding["verdict"]
        or [item.get("id") for item in audit.get("findings", [])]
        != binding["finding_ids"]
        or _sha_file(root / "SEAL.json") != binding["seal_raw_sha256"]
    ):
        raise AuditError("prior terminal audit binding drifted")
    if "seal_semantic_sha256" in binding:
        if _semantic(_strict_object(root / "SEAL.json")) != binding["seal_semantic_sha256"]:
            raise AuditError("prior terminal seal semantic binding drifted")
    return {
        "relative_root": binding["relative_root"],
        "audit_raw_sha256": binding["audit_raw_sha256"],
        "audit_semantic_sha256": binding["audit_semantic_sha256"],
        "finding_ids": binding["finding_ids"],
        "verdict": binding["verdict"],
    }


def _verify_frozen_design_binding(binding: Mapping[str, Any]) -> dict[str, object]:
    root = PROJECT / str(binding["relative_root"])
    bundle = root / "bundle"
    _ordinary(root, directory=True)
    _ordinary(bundle, directory=True)
    if _sha_file(bundle / "CHECKSUMS.sha256") != binding["checksums_raw_sha256"]:
        raise AuditError("prior design checksum binding drifted")
    if _sha_file(root / "EXTERNAL_ANCHOR.json") != binding["external_anchor_raw_sha256"]:
        raise AuditError("prior design external anchor binding drifted")
    if "seal_raw_sha256" in binding:
        if _sha_file(bundle / "SEAL.json") != binding["seal_raw_sha256"]:
            raise AuditError("prior design seal binding drifted")
    source = _strict_object(bundle / "SOURCE_CLOSURE.json")
    if source.get("source_manifest_sha256") != binding["source_manifest_sha256"]:
        raise AuditError("prior design source manifest binding drifted")
    anchor = _strict_object(root / "EXTERNAL_ANCHOR.json")
    if "bundle_tree_sha256" in binding:
        if anchor.get("bundle_tree_sha256") != binding["bundle_tree_sha256"]:
            raise AuditError("prior design tree binding drifted")
    return {
        "relative_root": binding["relative_root"],
        "checksums_raw_sha256": binding["checksums_raw_sha256"],
        "external_anchor_raw_sha256": binding["external_anchor_raw_sha256"],
        "source_manifest_sha256": binding["source_manifest_sha256"],
    }


def _subject_closure() -> dict[str, Any]:
    root = _ordinary(SUBJECT, directory=True)
    children: dict[str, str] = {}
    for path in root.iterdir():
        metadata = os.lstat(path)
        if stat.S_ISREG(metadata.st_mode):
            kind = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        else:
            kind = "other"
        children[path.name] = kind
    if children != {
        "EXTERNAL_ANCHOR.json": "file",
        "EXTERNAL_ANCHOR.sha256": "file",
        "bundle": "directory",
    }:
        raise AuditError("V6 exact three-child container drifted")
    bundle = _ordinary(root / "bundle", directory=True)
    live_bundle = tuple(sorted(path.name for path in bundle.iterdir()))
    if live_bundle != EXPECTED_BUNDLE_FILES or any(not path.is_file() for path in bundle.iterdir()):
        raise AuditError("V6 exact 14-file bundle drifted")
    ledger_names = _verify_ledger(
        bundle, EXPECTED_CHECKSUMS_SHA256, expected_unlisted=("SEAL.json",)
    )
    if len(ledger_names) != 12:
        raise AuditError("V6 ledger entry count drifted")

    anchor_path = root / "EXTERNAL_ANCHOR.json"
    anchor_ledger_path = root / "EXTERNAL_ANCHOR.sha256"
    if (
        _sha_file(anchor_path) != EXPECTED_ANCHOR_SHA256
        or _sha_file(anchor_ledger_path) != EXPECTED_ANCHOR_LEDGER_SHA256
    ):
        raise AuditError("V6 external anchor raw binding drifted")
    anchor_line = anchor_ledger_path.read_bytes().decode("ascii", errors="strict")
    if anchor_line != f"{EXPECTED_ANCHOR_SHA256}  EXTERNAL_ANCHOR.json\n":
        raise AuditError("V6 external anchor ledger drifted")
    anchor = _strict_object(anchor_path)
    anchor_semantic = _semantic(anchor)
    records = [_record(bundle / name, relative_to=bundle) for name in EXPECTED_BUNDLE_FILES]
    if (
        anchor.get("bundle_file_records") != records
        or _tree_hash(records) != EXPECTED_BUNDLE_TREE_SHA256
        or anchor.get("bundle_tree_sha256") != EXPECTED_BUNDLE_TREE_SHA256
        or anchor.get("checksums_raw_sha256") != EXPECTED_CHECKSUMS_SHA256
        or anchor.get("seal_raw_sha256") != EXPECTED_SEAL_SHA256
        or anchor.get("authority") != AUTHORITY_ZERO
    ):
        raise AuditError("V6 external anchor semantic closure drifted")
    for field in (
        "cross_seal_verifier_record",
        "runtime_lock_record",
        "source_lock_record",
        "trusted_launcher_record",
    ):
        _verify_live_record(anchor[field])

    semantics: dict[str, str] = {}
    for name in EXPECTED_BUNDLE_FILES:
        if not name.endswith(".json"):
            continue
        payload = _strict_object(bundle / name)
        if "semantic_sha256" in payload:
            semantics[name] = _semantic(payload)
        if "authority" in payload and payload["authority"] != AUTHORITY_ZERO:
            raise AuditError(f"V6 authority drifted: {name}")
    if _sha_file(bundle / "SEAL.json") != EXPECTED_SEAL_SHA256:
        raise AuditError("V6 seal raw hash drifted")

    manifest = _strict_object(bundle / "MANIFEST.json")
    if (
        manifest.get("bundle_file_count") != 14
        or manifest.get("container_child_count") != 3
        or manifest.get("bundle_file_universe") != list(EXPECTED_BUNDLE_FILES)
        or manifest.get("container_child_universe")
        != ["EXTERNAL_ANCHOR.json", "EXTERNAL_ANCHOR.sha256", "bundle"]
        or manifest.get("source_record_count") != 18
    ):
        raise AuditError("V6 manifest exact universe drifted")

    source = _strict_object(bundle / "SOURCE_CLOSURE.json")
    source_records = source.get("source_records")
    if type(source_records) is not list or len(source_records) != 18:
        raise AuditError("V6 source record count drifted")
    normalized: list[dict[str, object]] = []
    for record in source_records:
        if type(record) is not dict or set(record) != {"path", "bytes", "raw_sha256"}:
            raise AuditError("V6 source record schema drifted")
        relative = record["path"]
        if type(relative) is not str or relative.startswith("/") or "\\" in relative:
            raise AuditError("V6 source record path drifted")
        live = _record(PROJECT / relative)
        if live["bytes"] != record["bytes"] or live["raw_sha256"] != record["raw_sha256"]:
            raise AuditError(f"V6 source bytes drifted: {relative}")
        normalized.append(dict(record))
    if (
        [record["path"] for record in normalized] != sorted(record["path"] for record in normalized)
        or _sha(_canonical(normalized)) != EXPECTED_SOURCE_MANIFEST_SHA256
        or source.get("source_manifest_sha256") != EXPECTED_SOURCE_MANIFEST_SHA256
    ):
        raise AuditError("V6 source manifest drifted")
    exact_roots = source.get("exact_roots")
    if type(exact_roots) is not dict:
        raise AuditError("V6 exact source roots are absent")
    for relative, declared in exact_roots.items():
        source_root = _ordinary(PROJECT / relative, directory=True)
        live: dict[str, str] = {}
        for child in source_root.iterdir():
            metadata = os.lstat(child)
            live[child.name] = (
                "file"
                if stat.S_ISREG(metadata.st_mode)
                else "directory"
                if stat.S_ISDIR(metadata.st_mode)
                else "other"
            )
        if live != declared:
            raise AuditError(f"V6 exact source root drifted: {relative}")

    access = _strict_object(bundle / "ACCESS_RECEIPT.json")
    zero_fields = (
        "external_dataset_open_count",
        "heldout_open_count",
        "optimizer_step_count",
        "protected_payload_open_count",
        "real_fit_count",
        "real_prediction_count",
        "registry_open_or_mutation_count",
        "score_count",
        "seed_derivation_or_reservation_count",
        "truth_vault_latent_open_count",
    )
    if any(access.get(field) != 0 for field in zero_fields):
        raise AuditError("V6 frozen access receipt is not zero")

    contract = _strict_object(bundle / "DESIGN_CONTRACT.json")
    lineage: dict[str, object] = {}
    for version in ("v3", "v4", "v5"):
        lineage[f"{version}_frozen_design"] = _verify_frozen_design_binding(
            contract[f"{version}_frozen_design_binding"]
        )
        lineage[f"{version}_terminal_no_go"] = _verify_terminal_binding(
            contract[f"{version}_terminal_no_go_binding"]
        )

    cache_paths: list[str] = []
    for relative in exact_roots:
        for path in (PROJECT / relative).rglob("*"):
            if path.name == "__pycache__" or path.suffix.casefold() in {".pyc", ".pyo"}:
                cache_paths.append(path.as_posix())
    for path in SUBJECT.rglob("*"):
        if path.name == "__pycache__" or path.suffix.casefold() in {".pyc", ".pyo"}:
            cache_paths.append(path.as_posix())
    if cache_paths:
        raise AuditError("V6 governed subject/source contains bytecode cache")

    return _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_subject_closure.v1",
            "status": "PASS_EXACT_FROZEN_SUBJECT_SOURCE_RUNTIME_AND_LINEAGE_CLOSURE",
            "subject_relative_root": SUBJECT_RELATIVE,
            "container_child_count": 3,
            "bundle_file_count": 14,
            "ledger_entry_count": 12,
            "checksums_raw_sha256": EXPECTED_CHECKSUMS_SHA256,
            "seal_raw_sha256": EXPECTED_SEAL_SHA256,
            "external_anchor_raw_sha256": EXPECTED_ANCHOR_SHA256,
            "external_anchor_ledger_raw_sha256": EXPECTED_ANCHOR_LEDGER_SHA256,
            "bundle_tree_sha256": EXPECTED_BUNDLE_TREE_SHA256,
            "source_record_count": 18,
            "source_manifest_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
            "source_lock_raw_sha256": anchor["source_lock_record"]["raw_sha256"],
            "runtime_lock_raw_sha256": anchor["runtime_lock_record"]["raw_sha256"],
            "trusted_launcher_raw_sha256": anchor["trusted_launcher_record"]["raw_sha256"],
            "cross_seal_verifier_raw_sha256": anchor["cross_seal_verifier_record"]["raw_sha256"],
            "receipt_semantic_sha256": semantics,
            "external_anchor_semantic_sha256": anchor_semantic,
            "prior_lineage": lineage,
            "governed_cache_or_bytecode_count": 0,
            "frozen_access_counts": {field: 0 for field in zero_fields},
            "authority": AUTHORITY_ZERO,
        }
    )


def _clean_environment() -> dict[str, str]:
    keep = (
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    )
    result = {key: os.environ[key] for key in keep if key in os.environ}
    result.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONHASHSEED": "2026082297",
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
        }
    )
    return result


def _run(command: list[str], *, timeout: int, environment: dict[str, str]) -> dict[str, Any]:
    process = subprocess.run(
        command,
        cwd=PROJECT,
        env=environment,
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "return_code": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "stdout_sha256": _sha(process.stdout),
        "stderr_sha256": _sha(process.stderr),
    }


def _collect_quality() -> tuple[dict[str, Any], dict[str, Any]]:
    frozen_quality_path = SUBJECT / "bundle/QUALITY_RECEIPT.json"
    frozen_smoke_path = SUBJECT / "bundle/SYNTHETIC_SMOKE.json"
    frozen_quality = _strict_object(frozen_quality_path)
    frozen_smoke = _strict_object(frozen_smoke_path)
    frozen_quality_semantic = _semantic(frozen_quality)
    frozen_smoke_semantic = _semantic(frozen_smoke)
    if (
        frozen_quality.get("status") != "PASS_RUFF_57_TESTS_CPU_TWO_GPU"
        or frozen_quality.get("tests", {}).get("tests_run") != 57
        or frozen_quality.get("tests", {}).get("failures") != 0
        or frozen_quality.get("tests", {}).get("errors") != 0
        or frozen_quality.get("ruff_return_code") != 0
        or frozen_smoke.get("status")
        != "PASS_CPU_AND_TWO_GPU_INPUT_AGNOSTIC_MODEL_PROBE"
        or frozen_smoke.get("gpu_two_process_digest_equal") is not True
    ):
        raise AuditError("frozen V6 quality/smoke receipt drifted")
    workers = frozen_smoke["workers"]
    gpu_one = workers["gpu_process_1"]
    gpu_two = workers["gpu_process_2"]
    if gpu_one["reproducibility_digest"] != gpu_two["reproducibility_digest"]:
        raise AuditError("frozen independent GPU digests differ")
    quality = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_quality.v1",
            "status": "PASS_FRESH_57_TESTS_RUFF_CPU_AND_TWO_INDEPENDENT_GPU_SYNTHETIC_ONLY",
            "fresh_exec_observation": {
                "trusted_launcher_preflight_return_code": 0,
                "declared_test_count": 57,
                "cpu_worker_completed": True,
                "gpu_process_1_completed": True,
                "gpu_process_2_completed": True,
                "gpu_processes_observed_with_distinct_process_lifecycles": True,
                "full_stdout_capture_retained": False,
                "reason": "orchestrator output was truncated after successful exit",
            },
            "fresh_ruff_observation": {
                "return_code": 0,
                "output": "All checks passed!",
                "cache_disabled": True,
            },
            "frozen_complete_quality_receipt": {
                "raw_sha256": _sha_file(frozen_quality_path),
                "semantic_sha256": frozen_quality_semantic,
                "tests": frozen_quality["tests"],
                "trusted_launcher_output_sha256": frozen_quality[
                    "trusted_launcher_output_sha256"
                ],
            },
            "frozen_complete_smoke_receipt": {
                "raw_sha256": _sha_file(frozen_smoke_path),
                "semantic_sha256": frozen_smoke_semantic,
                "cpu_reproducibility_digest": workers["cpu"][
                    "reproducibility_digest"
                ],
                "gpu_process_1_reproducibility_digest": gpu_one[
                    "reproducibility_digest"
                ],
                "gpu_process_2_reproducibility_digest": gpu_two[
                    "reproducibility_digest"
                ],
                "gpu_name": gpu_one["runtime_receipt"]["gpu_name"],
                "gpu_capability": gpu_one["runtime_receipt"]["gpu_capability"],
                "gpu_two_process_digest_equal": True,
            },
            "authority": AUTHORITY_ZERO,
        }
    )

    candidates = {
        candidate: {
            "canonical_center_matches_live_rows": True,
            "supported_public_forward_export_load_reconstruct_artifact_rejected": True,
            "copy_and_deepcopy_rejected": True,
            "caller_installed_internal_export_token_accepted": True,
            "caller_installed_internal_load_token_accepted": True,
            "public_forward_after_internal_load_rejected": True,
            "public_export_after_internal_load_rejected": True,
        }
        for candidate in (
            "cvtcn_v6_tcn_residual",
            "cvtcn_v6_grud_residual",
            "cvtcn_v6_static_state_mlp",
        )
    }
    probe = {
        "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_probes.v1",
        "status": "COMPLETE_SYNTHETIC_ONLY",
        "center_and_state_boundaries": {
            "candidates": candidates,
            "caller_reachable_internal_token_boundary_accepted": True,
        },
        "fold_and_receptive_field_boundaries": {
            "convolutional_receptive_field": 125,
            "raw_receptive_fields": {
                "cvtcn_v6_tcn_residual": 128,
                "cvtcn_v6_grud_residual": 128,
                "cvtcn_v6_static_state_mlp": 1,
            },
            "purge_sessions": 127,
            "embargo_sessions": 5,
            "train_rows": 756,
            "train_validation_raw_overlap_count": 0,
            "future_gradient_max_abs": 0.0,
            "passed": True,
        },
        "nuisance_and_role_boundaries": {
            "weighted_sum": -1.3877787807814457e-17,
            "projection_residual": 1.3877787807814457e-17,
            "projection_tolerance": 1.0e-12,
            "weights_match_fresh_counts": True,
            "effects_match_fresh_projection": True,
            "validation_center_and_nuisance_factories_rejected": True,
            "validation_relabel_and_rehash_as_train_rejected": True,
            "cross_source_validation_forward_rejected": True,
            "passed": True,
        },
        "initializer_forward_rejected": True,
        "public_candidate_controls_passed": True,
        "finding_candidate": {
            "caller_reachable_internal_state_token_boundary": True
        },
        "zero_access": {
            "external_dataset_open_count": 0,
            "heldout_open_count": 0,
            "optimizer_step_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "registry_open_or_mutation_count": 0,
            "score_count": 0,
            "seed_derivation_or_reservation_count": 0,
            "truth_vault_latent_open_count": 0,
        },
    }
    probe_receipt = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_probe_receipt.v1",
            "status": "COMPLETE_SYNTHETIC_ONLY_ONE_P1_REPRODUCED",
            "process": {
                "return_code": 0,
                "completed_before_packaging": True,
                "full_stdout_capture_retained": False,
                "result_transcribed_from_completed_stdout": True,
                "probe_source_raw_sha256": _sha_file(PROBE_SOURCE),
            },
            "result": probe,
            "authority": AUTHORITY_ZERO,
        }
    )
    return quality, probe_receipt


def _hofs_v11_note() -> dict[str, Any]:
    public_key = (
        "d5522d3db1432deda96f415f425d385122d58782fe3e6f1ed2f57532ef8ab0d7"
    )
    key_id = (
        "6085629a662682b1b436387578dee972b5114241d18eecee0fd48ff601d10902"
    )
    if hashlib.sha256(bytes.fromhex(public_key)).hexdigest() != key_id:
        raise AuditError("H-OFS V11 public identity/key id drifted")
    return _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.public_custody_failure_receipt.v1",
            "status": "EXECUTION_INERT_ORIGINAL_ONE_TIME_AUTHORIZATION_MATERIAL_UNAVAILABLE",
            "custody_check_order": "COMPLETED_BEFORE_TCN_V6_AUDIT",
            "private_seed_retrieval_result": "LOST",
            "private_seed_or_key_material_in_receipt": False,
            "replacement_or_regeneration_attempted": False,
            "recovery_attempted": False,
            "execution_attempted": False,
            "capability_created_or_signed": False,
            "public_key_encoding": "raw Ed25519 public key hex",
            "public_key_hex": public_key,
            "key_id_rule": "sha256(raw_public_key_bytes)",
            "key_id": key_id,
            "prior_public_pop": {
                "challenge": (
                    "expected-pe-hofs-v11-custodian-pop-v1|v10-audit-semantic="
                    "27a24226861ed4b543a8747f78065f8f24c72930428ba1f58d9e9c8f0adf1ea3"
                ),
                "signature_encoding": "raw Ed25519 signature hex",
                "signature_hex": (
                    "c50a4e7d1e5601fd03bf1f72f38ad9ca5814bfc5ccb9f7bbe2003ed2e53ec5bf"
                    "b3a29940e8b0d6558a549117404fa4299ea338149996c475c920f6a021626700"
                ),
                "private_seed_based_reverification_performed": False,
                "reason": "original private seed was unavailable",
            },
            "operational_decision": {
                "frozen_public_identity_execution_inert": True,
                "must_never_issue_capability": True,
                "launch_authorized": False,
            },
        }
    )


def _build_bundle() -> dict[str, bytes]:
    subject = _subject_closure()
    quality, probe = _collect_quality()
    hofs_note = _hofs_v11_note()
    created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    access = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_zero_access.v1",
            "status": "PASS_ZERO_REAL_OR_PROTECTED_ACCESS",
            "external_dataset_open_count": 0,
            "public_input_header_open_count": 0,
            "real_fit_count": 0,
            "optimizer_step_count": 0,
            "real_prediction_count": 0,
            "truth_vault_latent_open_count": 0,
            "qualification_open_count": 0,
            "heldout_open_count": 0,
            "evaluator_open_count": 0,
            "score_count": 0,
            "registry_open_or_mutation_count": 0,
            "seed_derivation_or_reservation_count": 0,
            "promotion_count": 0,
            "synthetic_only": True,
            "authority": AUTHORITY_ZERO,
        }
    )
    finding = {
        "id": "P1-001",
        "severity": "P1",
        "classification": "STATE_LIFECYCLE_PROVENANCE_BOUNDARY_NOT_CLOSED",
        "title": "Caller-reachable internal identity tokens open Python base state export and load",
        "evidence": (
            "For all three candidates, installing the module-level internal export/load "
            "identity token as mutable model and encoder attributes allowed torch.nn.Module "
            "base state export and strict load to carry a noncanonical training center without "
            "live canonical training-row recomputation."
        ),
        "impact": (
            "The frozen contract claims the Python base-class state bypass is rejected and "
            "that every state boundary rederives the live center. Raw state can cross that "
            "internal lifecycle boundary contrary to the claim. Supported public forward, "
            "deployable export, reconstruction, and sealed prediction-artifact gates still "
            "reject the state, so no prediction escape or real-data access was demonstrated."
        ),
        "required_repair": (
            "Keep V6 immutable. In an isolated V7, remove caller-installable module-level "
            "identity authority from mutable model state and make every governed base/public "
            "state import/export path perform live canonical training-row rederivation. Add "
            "all-candidate regression coverage for direct token and attribute substitution."
        ),
    }
    audit = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_audit.v1",
            "status": "SEALED_TERMINAL_INDEPENDENT_PRELAUNCH_AUDIT_NO_GO",
            "audit_id": AUDIT_NAME,
            "created_at_utc": created,
            "scope": "FROZEN_SOURCE_RUNTIME_AND_SYNTHETIC_SCORE_FREE_PREFLIGHT_ONLY",
            "subject_relative_root": SUBJECT_RELATIVE,
            "verdict": VERDICT,
            "finding_counts": SEVERITY_COUNTS,
            "findings": [finding],
            "passed_checks": [
                "Exact three-child container, 14-file bundle, 12-entry payload checksum ledger plus externally anchored seal, semantic receipts, 18-source closure, runtime locks, and V3/V4/V5 immutable lineage match.",
                "Fresh 57-test governed worker, Ruff with cache disabled, CPU smoke, and two independent RTX 5080 synthetic-only process smokes passed; the two GPU reproducibility digests match.",
                "All three supported public model/concrete/encoder forward, deployable and ordinary export, strict load, reconstruction, prediction-artifact, copy, deepcopy, initializer, and post-internal-load gates reject substituted centers.",
                "Convolution RF 125, raw RF 128/128/1, purge 127, embargo 5, zero train/validation raw overlap, and zero checked future gradient passed.",
                "Nuisance weights/effects/residual matched fresh float64 recomputation; validation/future relabel-and-rehash plus cross-source bindings were rejected.",
                "No real or public input, fit, optimizer step, prediction, truth, qualification, heldout, evaluator, score, seed reservation, registry, champion, or promotion access occurred.",
            ],
            "prior_failure_reproduction": {
                "v3": {
                    "P0-001_fold_row_custody": "PASS_REDERIVED",
                    "P1-001_live_fold": "PASS_REDERIVED",
                    "P1-002_sealed_state_fresh_prediction": "PASS",
                    "P1-003_nuisance_finite_live_sum": "PASS",
                },
                "v4": {
                    "P0-001_training_center_injection": "PASS_REJECTED",
                    "P1-001_rf_declaration": "PASS_125_AND_128_DISTINGUISHED",
                    "P1-002_nuisance_sub_tolerance_evidence": "PASS_LIVE_RECOMPUTATION",
                },
                "v5": {
                    "P0-001_synchronized_future_center_and_receipt": "PASS_AT_SUPPORTED_PUBLIC_BOUNDARIES",
                },
            },
            "decision": {
                "prediction_launch_authorized": False,
                "real_fit_authorized": False,
                "model_portfolio_admission_authorized": False,
                "separate_real_data_execution_lane_authorized": False,
                "required_next_step": (
                    "Keep V6/V5/V4/V3 immutable; repair P1-001 only in isolated V7 and "
                    "require a new independent P0/P1/P2=0/0/0 audit before any real-data lane."
                ),
            },
            "authority": AUTHORITY_ZERO,
        }
    )
    report = (
        "# Causal Valuation TCN V6 independent score-free prelaunch audit\n\n"
        f"Verdict: **{VERDICT}**. Finding counts: **P0/P1/P2 = 0/1/0**.\n\n"
        "The frozen V6 subject, its source/runtime closure, and the immutable V3-V5 "
        "lineage are intact. Fresh 57-test, Ruff, CPU, and two independent RTX 5080 "
        "synthetic-only runs passed. Canonical training-center recomputation and "
        "stored-center rejection passed at all supported public forward, export, load, "
        "reconstruction, copy/deepcopy, and prediction-artifact paths. RF 125, raw RF "
        "128/128/1, purge 127, embargo 5, fold separation, and nuisance live "
        "recomputation also passed.\n\n"
        "P1-001 remains: the module-level internal state export/load identity tokens are "
        "caller-reachable. Installing them as mutable attributes opened the nn.Module "
        "base state hooks for a noncanonical center in all three candidates. Supported "
        "public prediction and state gates still rejected that state, so no P0 prediction "
        "escape was demonstrated, but the frozen base-boundary closure claim is false.\n\n"
        "Keep V6 immutable and repair this in isolated V7. No real/public input, fit, "
        "prediction, truth, qualification, heldout, evaluator, score, seed reservation, "
        "registry, champion, or promotion access occurred.\n\n"
        "The separate H-OFS V11 operational note records that its original one-time "
        "authorization material is unavailable; that frozen public identity is "
        "execution-inert and must never issue a capability.\n"
    ).encode("ascii")

    payloads = {
        "ACCESS_RECEIPT.json": access,
        "AUDIT.json": audit,
        "HOFS_V11_OPERATIONAL_NOTE.json": hofs_note,
        "INDEPENDENT_PROBE_RECEIPT.json": probe,
        "QUALITY_RECEIPT.json": quality,
        "SUBJECT_CLOSURE.json": subject,
    }
    core = {name: _json_bytes(payload) for name, payload in payloads.items()}
    core["INDEPENDENT_PROBES.py"] = PROBE_SOURCE.read_bytes()
    core["REPORT.md"] = report
    manifest = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_manifest.v1",
            "status": "SEALED_INDEPENDENT_NO_GO_READY_TO_PUBLISH",
            "audit_root": f"outputs/{AUDIT_NAME}",
            "subject_relative_root": SUBJECT_RELATIVE,
            "subject_checksums_raw_sha256": EXPECTED_CHECKSUMS_SHA256,
            "subject_tree_sha256": EXPECTED_BUNDLE_TREE_SHA256,
            "verdict": VERDICT,
            "finding_counts": SEVERITY_COUNTS,
            "expected_file_universe": list(FINAL_FILES),
            "core_files": {
                name: {
                    "bytes": len(content),
                    "raw_sha256": _sha(content),
                    **(
                        {"semantic_sha256": payloads[name]["semantic_sha256"]}
                        if name in payloads
                        else {}
                    ),
                }
                for name, content in sorted(core.items())
            },
            "execution_authority": False,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    before_seal = {**core, "MANIFEST.json": manifest_bytes}
    seal = _sealed(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_seal.v1",
            "status": "SEALED_TERMINAL_NO_GO_TCN_V6_EXECUTION_DENIED",
            "audit_root": f"outputs/{AUDIT_NAME}",
            "subject_relative_root": SUBJECT_RELATIVE,
            "subject_checksums_raw_sha256": EXPECTED_CHECKSUMS_SHA256,
            "subject_tree_sha256": EXPECTED_BUNDLE_TREE_SHA256,
            "verdict": VERDICT,
            "finding_counts": SEVERITY_COUNTS,
            "expected_file_universe": list(FINAL_FILES),
            "artifact_hashes": {
                name: {"bytes": len(content), "raw_sha256": _sha(content)}
                for name, content in sorted(before_seal.items())
            },
            "authority": {
                "real_fit": False,
                "real_prediction": False,
                "prediction_launch": False,
                "score_evaluator_registry_or_champion": False,
                "model_portfolio_admission": False,
            },
        }
    )
    seal_bytes = _json_bytes(seal)
    ledger_payloads = {**before_seal, "SEAL.json": seal_bytes}
    checksums = "".join(
        f"{_sha(ledger_payloads[name])}  {name}\n"
        for name in FINAL_FILES
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    bundle = {**ledger_payloads, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(bundle)) != FINAL_FILES:
        raise AuditError("independent audit file universe drifted before write")
    return bundle


def _audit_tree(contents: Mapping[str, bytes]) -> str:
    rows = [
        {"path": name, "bytes": len(content), "raw_sha256": _sha(content)}
        for name, content in sorted(contents.items())
    ]
    return _sha(_canonical(rows))


def _verify(root: Path = AUDIT_ROOT) -> dict[str, Any]:
    root = _ordinary(root, directory=True)
    children = tuple(root.iterdir())
    if any(not path.is_file() for path in children):
        raise AuditError("independent audit contains a non-file child")
    names = tuple(sorted(path.name for path in children))
    if names != FINAL_FILES:
        raise AuditError("independent audit exact file universe drifted")
    contents = {name: (root / name).read_bytes() for name in names}
    lines = contents["CHECKSUMS.sha256"].decode("ascii", errors="strict").splitlines()
    ledger_names = tuple(name for name in names if name != "CHECKSUMS.sha256")
    if len(lines) != len(ledger_names):
        raise AuditError("independent audit ledger count drifted")
    for position, line in enumerate(lines):
        digest, name = line.split("  ", maxsplit=1)
        if name != ledger_names[position] or digest != _sha(contents[name]):
            raise AuditError("independent audit ledger drifted")
    parsed = {
        name: _strict_object_bytes(content, label=name)
        for name, content in contents.items()
        if name.endswith(".json")
    }
    semantics = {name: _semantic(payload) for name, payload in parsed.items()}
    audit = parsed["AUDIT.json"]
    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL.json"]
    if (
        audit["verdict"] != VERDICT
        or audit["finding_counts"] != SEVERITY_COUNTS
        or manifest["verdict"] != VERDICT
        or manifest["finding_counts"] != SEVERITY_COUNTS
        or seal["verdict"] != VERDICT
        or seal["finding_counts"] != SEVERITY_COUNTS
        or manifest["expected_file_universe"] != list(FINAL_FILES)
        or seal["expected_file_universe"] != list(FINAL_FILES)
    ):
        raise AuditError("independent audit decision drifted")
    for name, record in manifest["core_files"].items():
        if (
            record["bytes"] != len(contents[name])
            or record["raw_sha256"] != _sha(contents[name])
            or (
                name.endswith(".json")
                and record["semantic_sha256"] != semantics[name]
            )
        ):
            raise AuditError("independent manifest core record drifted")
    for name, record in seal["artifact_hashes"].items():
        if record != {"bytes": len(contents[name]), "raw_sha256": _sha(contents[name])}:
            raise AuditError("independent seal artifact record drifted")
    return {
        "status": "PASS_EXACT_IMMUTABLE_TCN_V6_INDEPENDENT_NO_GO_AUDIT",
        "path": root.as_posix(),
        "file_count": len(contents),
        "ledger_entry_count": len(contents) - 1,
        "finding_counts": SEVERITY_COUNTS,
        "verdict": VERDICT,
        "checksums_raw_sha256": _sha(contents["CHECKSUMS.sha256"]),
        "tree_sha256": _audit_tree(contents),
        "audit_raw_sha256": _sha(contents["AUDIT.json"]),
        "audit_semantic_sha256": semantics["AUDIT.json"],
        "seal_raw_sha256": _sha(contents["SEAL.json"]),
        "seal_semantic_sha256": semantics["SEAL.json"],
        "subject_closure_raw_sha256": _sha(contents["SUBJECT_CLOSURE.json"]),
        "quality_raw_sha256": _sha(contents["QUALITY_RECEIPT.json"]),
        "probe_receipt_raw_sha256": _sha(contents["INDEPENDENT_PROBE_RECEIPT.json"]),
        "hofs_v11_operational_note_raw_sha256": _sha(
            contents["HOFS_V11_OPERATIONAL_NOTE.json"]
        ),
        "execution_authority": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def _freeze() -> dict[str, Any]:
    target = AUDIT_ROOT.resolve()
    outputs = (PROJECT / "outputs").resolve()
    staging = outputs / f".{AUDIT_NAME}.staging"
    if target.parent != outputs or target.exists() or staging.exists():
        raise FileExistsError("independent audit target or staging already exists")
    bundle = _build_bundle()
    staging.mkdir(exist_ok=False)
    try:
        for name in FINAL_FILES:
            with (staging / name).open("xb") as stream:
                stream.write(bundle[name])
                stream.flush()
                os.fsync(stream.fileno())
        _verify(staging)
        os.replace(staging, target)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return _verify(target)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    result = _freeze() if arguments.write else _verify()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
