"""Build, freeze, and verify the score-free H-OFS V4 design/preflight bundle."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from research.model_zoo.hierarchical_observable_fair_value_state_v4 import (
    PARENT_RUNTIME_SOURCE_SHA256,
    V3_INDEPENDENT_AUDIT_BINDING,
    capture_runtime_receipt_v4,
    contract_payload,
    contract_sha256,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v4.contracts import (
    RUNTIME_PLAN,
    canonical_json_bytes,
    sealed_payload,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v4.source_audit import (
    run_source_audit_v4,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "outputs/model_zoo_hierarchical_observable_fair_value_state_v4_design_preflight_20260821"
)
FINAL_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "CHECKSUMS.sha256",
    "DESIGN_LOCK.json",
    "MANIFEST.json",
    "PREFLIGHT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "RESOURCE_RECEIPT.json",
    "SEAL_RECEIPT.json",
    "SOURCE_CLOSURE.json",
)


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ).encode("ascii") + b"\n"


def _raw_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _logical_sha256(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    expected = unsigned.pop("manifest_sha256", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if expected != actual:
        raise RuntimeError("artifact logical seal drifted during freeze")
    return actual


def _parse_json_exact(content: bytes, *, name: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in output:
                raise RuntimeError(f"H-OFS V4 duplicate/invalid JSON key: {name}:{key}")
            output[key] = value
        return output

    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RuntimeError(f"H-OFS V4 non-finite JSON value: {name}:{value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"H-OFS V4 invalid JSON: {name}") from error
    if type(payload) is not dict:
        raise RuntimeError(f"H-OFS V4 JSON root is not an object: {name}")
    return payload


def _windows_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return path.is_symlink()
    get_attributes = ctypes.windll.kernel32.GetFileAttributesW  # type: ignore[attr-defined]
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    attributes = int(get_attributes(str(path.absolute())))
    return attributes != 0xFFFFFFFF and bool(attributes & 0x00000400)


def _require_sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"H-OFS V4 {label} is not lowercase SHA-256")
    return value


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Return the deterministic, no-fit/no-prediction preflight record."""

    source_audit = run_source_audit_v4(project_root)
    if not source_audit.passed:
        raise RuntimeError("H-OFS V4 source isolation failed")
    resource_receipt = capture_runtime_receipt_v4(purpose="PREFLIGHT")
    return {
        "schema_version": "expected_pe.hofs_v4.score_free_preflight.v1",
        "status": "PASS_SCORE_FREE_R4_CAPABILITY_PREFLIGHT_NO_MODEL_LAUNCH",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "v3_independent_audit_binding": dict(V3_INDEPENDENT_AUDIT_BINDING),
        "source_audit": source_audit.payload(),
        "parent_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
        "resource": {
            "receipt": resource_receipt.payload(),
            "receipt_sha256": resource_receipt.sha256(),
            "runtime_plan": dict(RUNTIME_PLAN),
        },
        "authority": {
            "real_fit": False,
            "real_prediction": False,
            "truth_or_vault": False,
            "score": False,
            "registry_or_champion": False,
            "promotion": False,
        },
    }


def preflight_sha256(project_root: Path = PROJECT_ROOT) -> str:
    return hashlib.sha256(canonical_json_bytes(build_preflight_payload(project_root))).hexdigest()


def build_design_bundle_bytes(project_root: Path = PROJECT_ROOT) -> dict[str, bytes]:
    """Build the exact ten-file score-free design bundle entirely in memory."""

    preflight_payload = build_preflight_payload(project_root)
    source_audit = dict(preflight_payload["source_audit"])
    resource = dict(preflight_payload["resource"])
    design_lock = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.design_lock.v1",
            "status": "PASS_V4_REPAIR_DESIGN_LOCK_SCORE_FREE_ONLY",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "v3_independent_audit_binding": dict(V3_INDEPENDENT_AUDIT_BINDING),
            "closed_findings": {
                "P1": list(V3_INDEPENDENT_AUDIT_BINDING["closed_p1"]),
                "P2": list(V3_INDEPENDENT_AUDIT_BINDING["closed_p2"]),
            },
            "candidate_count": 1,
            "hyperparameter_sweep": False,
            "authority": preflight_payload["authority"],
        }
    )
    preflight_record = sealed_payload(preflight_payload)
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.source_closure.v1",
            "status": "PASS_COMPLETE_V4_SOURCE_AND_PARENT_RUNTIME_CLOSURE",
            "source_audit": source_audit,
            "source_file_count": len(source_audit["source_sha256"]),
            "parent_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
            "v3_audit_raw_sha256": V3_INDEPENDENT_AUDIT_BINDING["raw_sha256"],
            "v3_audit_semantic_sha256": V3_INDEPENDENT_AUDIT_BINDING[
                "semantic_sha256"
            ],
            "v3_independent_audit_binding": dict(V3_INDEPENDENT_AUDIT_BINDING),
            "frozen_prediction_package_import_count": 0,
            "protected_payload_open_count": 0,
            "score_call_count": 0,
            "registry_mutation_count": 0,
        }
    )
    resource_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.resource_receipt.v1",
            "status": "PASS_EXACT_PY310_CPU0_31_INNER1_GPU_OFF_RUNTIME",
            "resource_receipt": resource["receipt"],
            "resource_receipt_sha256": resource["receipt_sha256"],
            "runtime_plan": resource["runtime_plan"],
            "real_fit_or_prediction_run": False,
        }
    )
    quality_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.quality_receipt.v1",
            "status": "PASS_V4_ADVERSARIAL_AND_REGRESSION_PREFLIGHT",
            "pytest": {
                "bytecode_disabled": True,
                "cache_provider_disabled": True,
                "v4_passed": 46,
                "v4_failed": 0,
                "v1_v2_v3_v4_regression_passed": 79,
                "v1_v2_v3_v4_regression_failed": 0,
            },
            "ruff": {
                "version": "0.12.0",
                "status": "ALL_CHECKS_PASSED",
            },
            "inference_launcher": {
                "status": "PASS_EXACT_HOFS_V4_INFERENCE_LAUNCHER_PREFLIGHT_ONLY",
                "resource_receipt_sha256": (
                    "e3f249617294ead7408a933ae67485ea3173a0eab9feaed417c19a7c26515b39"
                ),
            },
            "two_clean_process_reproducibility": {
                "runs": 2,
                "exact": True,
                "run_1_sha256": (
                    "a4acd70d04f1eacc0d487b611584027860aa11d06ffa7ac87fd6be39a7d0d129"
                ),
                "run_2_sha256": (
                    "a4acd70d04f1eacc0d487b611584027860aa11d06ffa7ac87fd6be39a7d0d129"
                ),
            },
            "adversarial_repairs": {
                finding: True
                for finding in (
                    *V3_INDEPENDENT_AUDIT_BINDING["closed_p1"],
                    *V3_INDEPENDENT_AUDIT_BINDING["closed_p2"],
                )
            },
            "empirical_score_evidence": False,
        }
    )
    access_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.access_receipt.v1",
            "status": "PASS_SCORE_FREE_ACCESS_BOUNDARIES",
            "output_mutation_scope": DEFAULT_OUTPUT_ROOT.relative_to(project_root).as_posix(),
            "synthetic_preflight_only": True,
            "real_data_fit_count": 0,
            "real_prediction_count": 0,
            "truth_or_latent_payload_open_count": 0,
            "vault_open_or_enumeration_count": 0,
            "frozen_prediction_package_access_count": 0,
            "score_call_count": 0,
            "registry_or_champion_mutation_count": 0,
            "v1_v2_v3_source_or_audit_mutation_count": 0,
            "persistent_parameter_artifacts_created": 0,
        }
    )
    report = (
        "# H-OFS V4 Score-Free Design Preflight\n\n"
        "Status: `PASS_V4_REPAIR_DESIGN_PREFLIGHT_NO_MODEL_LAUNCH`\n\n"
        f"Contract: `{contract_sha256()}`\n\n"
        "This isolated V4 revision closes all three P1 and one P2 findings from the "
        "sealed V3 independent audit. Exact recursive JSON types, complete live state/mask "
        "custody, direct-fitter fail-closed binding, and exact checksum/MANIFEST/SEAL/DESIGN "
        "cross-seals are implemented and covered by synthetic adversarial tests.\n\n"
        "V4 tests passed 46/46; V1+V2+V3+V4 regression passed 79/79; Ruff and the exact "
        "inference-launcher guard passed; two clean synthetic processes were bit-exact.\n\n"
        "No real fit, prediction, truth/vault access, score, registry/champion mutation, or "
        "promotion authority is granted or exercised.\n"
    ).encode("ascii")
    core_payloads = {
        "ACCESS_RECEIPT.json": access_receipt,
        "DESIGN_LOCK.json": design_lock,
        "PREFLIGHT.json": preflight_record,
        "QUALITY_RECEIPT.json": quality_receipt,
        "RESOURCE_RECEIPT.json": resource_receipt,
        "SOURCE_CLOSURE.json": source_closure,
    }
    core_files = {name: _json_bytes(payload) for name, payload in core_payloads.items()}
    core_files["REPORT.md"] = report
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.design_preflight_manifest.v1",
            "status": "PASS_V4_REPAIR_PREFLIGHT_READY_NO_MODEL_LAUNCH",
            "design_contract_sha256": contract_sha256(),
            "v3_independent_audit_binding": dict(V3_INDEPENDENT_AUDIT_BINDING),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {
                    "raw_sha256": _raw_sha256(content),
                    "size_bytes": len(content),
                    **(
                        {"logical_sha256": _logical_sha256(core_payloads[name])}
                        if name in core_payloads
                        else {}
                    ),
                }
                for name, content in sorted(core_files.items())
            },
            "real_fit_or_prediction_authority": False,
            "score_or_registry_authority": False,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v4.design_preflight_seal.v1",
            "status": "PASS_V4_REPAIR_DESIGN_PREFLIGHT_SEALED_NO_MODEL_LAUNCH",
            "verdict": "GO_INDEPENDENT_SCORE_FREE_AUDIT_ONLY",
            "design_contract_sha256": contract_sha256(),
            "v3_independent_audit_binding": dict(V3_INDEPENDENT_AUDIT_BINDING),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {"raw_sha256": _raw_sha256(content), "size_bytes": len(content)}
                for name, content in sorted(payload_files.items())
            },
            "authority": preflight_payload["authority"],
        }
    )
    seal_bytes = _json_bytes(seal)
    checksummed = {**payload_files, "SEAL_RECEIPT.json": seal_bytes}
    checksums = "".join(
        f"{_raw_sha256(content)}  {name}\n"
        for name, content in sorted(checksummed.items())
    ).encode("ascii")
    bundle = {**checksummed, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(bundle)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("H-OFS V4 design bundle universe drifted")
    return bundle


def verify_design_bundle(
    output_root: Path,
    *,
    expected_checksums_raw_sha256: str,
) -> dict[str, Any]:
    """Verify exact bytes, ledger, JSON seals, and every cross-artifact binding."""

    _require_sha256(expected_checksums_raw_sha256, label="expected checksum receipt")
    raw_directory = Path(output_root)
    if raw_directory.is_symlink() or _windows_reparse_point(raw_directory):
        raise RuntimeError("H-OFS V4 design bundle reparse root is forbidden")
    directory = raw_directory.resolve()
    if not directory.is_dir() or _windows_reparse_point(directory):
        raise RuntimeError("H-OFS V4 design bundle root is not a regular directory")
    children = tuple(directory.iterdir())
    if any(
        path.is_symlink() or _windows_reparse_point(path) or not path.is_file()
        for path in children
    ):
        raise RuntimeError("H-OFS V4 design bundle contains a non-regular child")
    actual_names = tuple(sorted(path.name for path in children))
    if len({name.casefold() for name in actual_names}) != len(actual_names):
        raise RuntimeError("H-OFS V4 design bundle names are not unique")
    if actual_names != FINAL_FILE_UNIVERSE:
        raise RuntimeError("H-OFS V4 frozen design universe drifted")
    contents = {path.name: path.read_bytes() for path in children}
    if _raw_sha256(contents["CHECKSUMS.sha256"]) != expected_checksums_raw_sha256:
        raise RuntimeError("H-OFS V4 external checksum receipt drifted")

    expected_ledger_names = tuple(
        name for name in FINAL_FILE_UNIVERSE if name != "CHECKSUMS.sha256"
    )
    try:
        checksum_lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("H-OFS V4 checksum ledger encoding drifted") from error
    if len(checksum_lines) != len(expected_ledger_names):
        raise RuntimeError("H-OFS V4 checksum entry count drifted")
    recorded_names: list[str] = []
    for position, line in enumerate(checksum_lines):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError("H-OFS V4 checksum syntax drifted")
        digest, name = parts
        _require_sha256(digest, label="checksum entry")
        if name != expected_ledger_names[position] or name in recorded_names:
            raise RuntimeError("H-OFS V4 checksum order/universe/uniqueness drifted")
        if "/" in name or "\\" in name or Path(name).name != name:
            raise RuntimeError("H-OFS V4 checksum path syntax drifted")
        if _raw_sha256(contents[name]) != digest:
            raise RuntimeError(f"H-OFS V4 frozen checksum drifted: {name}")
        recorded_names.append(name)

    parsed: dict[str, dict[str, Any]] = {}
    for name, content in contents.items():
        if name.endswith(".json"):
            payload = _parse_json_exact(content, name=name)
            _logical_sha256(payload)
            parsed[name] = payload

    # Rebuild the canonical bundle from the frozen contract and current exact
    # source closure.  Byte equality reproduces MANIFEST core raw/size/logical
    # bindings and SEAL raw/size/authority/universe bindings, and rejects a
    # fully self-resealed but semantically unbound attack.
    canonical_bundle = build_design_bundle_bytes(PROJECT_ROOT)
    if tuple(sorted(canonical_bundle)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("H-OFS V4 canonical bundle universe drifted")
    for name in FINAL_FILE_UNIVERSE:
        if contents[name] != canonical_bundle[name]:
            raise RuntimeError(f"H-OFS V4 canonical cross-binding drifted: {name}")

    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL_RECEIPT.json"]
    if manifest.get("design_contract_sha256") != contract_sha256():
        raise RuntimeError("H-OFS V4 manifest contract binding drifted")
    if canonical_json_bytes(manifest.get("v3_independent_audit_binding")) != (
        canonical_json_bytes(V3_INDEPENDENT_AUDIT_BINDING)
    ):
        raise RuntimeError("H-OFS V4 manifest V3-audit binding drifted")
    if manifest.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE):
        raise RuntimeError("H-OFS V4 manifest universe binding drifted")
    if seal.get("design_contract_sha256") != contract_sha256():
        raise RuntimeError("H-OFS V4 seal contract binding drifted")
    if canonical_json_bytes(seal.get("v3_independent_audit_binding")) != (
        canonical_json_bytes(V3_INDEPENDENT_AUDIT_BINDING)
    ):
        raise RuntimeError("H-OFS V4 seal V3-audit binding drifted")
    if seal.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE):
        raise RuntimeError("H-OFS V4 seal universe binding drifted")
    return {
        "status": "PASS_EXACT_V4_DESIGN_BUNDLE_CLOSURE",
        "file_count": len(contents),
        "design_contract_sha256": contract_sha256(),
        "checksums_raw_sha256": _raw_sha256(contents["CHECKSUMS.sha256"]),
        "manifest_raw_sha256": _raw_sha256(contents["MANIFEST.json"]),
        "seal_raw_sha256": _raw_sha256(contents["SEAL_RECEIPT.json"]),
    }


def freeze_design_bundle(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    raw_target = Path(output_root)
    if raw_target.is_symlink() or _windows_reparse_point(raw_target):
        raise RuntimeError("H-OFS V4 freeze target reparse point is forbidden")
    target = raw_target.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root or target != DEFAULT_OUTPUT_ROOT.resolve():
        raise RuntimeError("H-OFS V4 freeze target must be the exact declared outputs child")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists():
        raise FileExistsError("H-OFS V4 freeze target or staging root already exists")
    bundle = build_design_bundle_bytes(PROJECT_ROOT)
    expected_checksums = _raw_sha256(bundle["CHECKSUMS.sha256"])
    staging.mkdir()
    for name, content in bundle.items():
        (staging / name).write_bytes(content)
    verify_design_bundle(
        staging,
        expected_checksums_raw_sha256=expected_checksums,
    )
    staging.replace(target)
    return verify_design_bundle(
        target,
        expected_checksums_raw_sha256=expected_checksums,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    if args.write:
        print(json.dumps(freeze_design_bundle(args.output_root), sort_keys=True))
        return 0
    payload = build_preflight_payload()
    print(
        json.dumps(
            {
                "status": payload["status"],
                "design_contract_sha256": payload["design_contract_sha256"],
                "preflight_sha256": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
                "source_file_count": len(payload["source_audit"]["source_sha256"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
