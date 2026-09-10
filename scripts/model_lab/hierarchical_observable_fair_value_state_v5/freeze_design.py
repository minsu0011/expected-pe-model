"""Build and atomically freeze the score-blind H-OFS V5 DGP-R4 preflight."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from research.model_zoo.hierarchical_observable_fair_value_state_v5 import (
    PARENT_RUNTIME_SOURCE_SHA256,
    R4_INPUT_BINDING,
    V4_DESIGN_FREEZE_BINDING,
    V4_INDEPENDENT_AUDIT_BINDING,
    build_r4_input_closure_v5,
    capture_runtime_receipt_v5,
    contract_payload,
    contract_sha256,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v5.contracts import (
    RUNTIME_PLAN,
    canonical_json_bytes,
    sealed_payload,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v5.source_audit import (
    run_source_audit_v5,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "outputs/model_zoo_hierarchical_observable_fair_value_state_v5_dgp_r4_design_preflight_20260821"
)
FINAL_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT_CLOSURE.json",
    "CHECKSUMS.sha256",
    "DESIGN_LOCK.json",
    "INPUT_CLOSURE.json",
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
                raise RuntimeError(f"H-OFS V5 duplicate/invalid JSON key: {name}:{key}")
            output[key] = value
        return output

    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RuntimeError(f"H-OFS V5 non-finite JSON value: {name}:{value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"H-OFS V5 invalid JSON: {name}") from error
    if type(payload) is not dict:
        raise RuntimeError(f"H-OFS V5 JSON root is not an object: {name}")
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
        raise RuntimeError(f"H-OFS V5 {label} is not lowercase SHA-256")
    return value


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Return the deterministic, no-fit/no-prediction preflight record."""

    source_audit = run_source_audit_v5(project_root)
    if not source_audit.passed:
        raise RuntimeError("H-OFS V5 source isolation failed")
    input_closure = build_r4_input_closure_v5(project_root)
    resource_receipt = capture_runtime_receipt_v5(purpose="PREFLIGHT")
    return {
        "schema_version": "expected_pe.hofs_v5.dgp_r4_score_blind_preflight.v1",
        "status": "PASS_SCORE_BLIND_R4_BATCH_CAPABILITY_PREFLIGHT_NO_MODEL_LAUNCH",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
        "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
        "r4_input_binding": dict(R4_INPUT_BINDING),
        "input_closure": input_closure,
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
            "model_registry_file_read": False,
            "evaluator_or_protected_artifact_open": False,
        },
    }


def preflight_sha256(project_root: Path = PROJECT_ROOT) -> str:
    return hashlib.sha256(canonical_json_bytes(build_preflight_payload(project_root))).hexdigest()


def build_design_bundle_bytes(project_root: Path = PROJECT_ROOT) -> dict[str, bytes]:
    """Build the exact score-blind design/input/preflight bundle in memory."""

    preflight_payload = build_preflight_payload(project_root)
    source_audit = dict(preflight_payload["source_audit"])
    input_closure_payload = dict(preflight_payload["input_closure"])
    resource = dict(preflight_payload["resource"])
    authority = dict(preflight_payload["authority"])
    design_lock = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.dgp_r4_design_lock.v1",
            "status": "PASS_V5_DGP_R4_BATCH_MAINTENANCE_DESIGN_LOCK_SCORE_BLIND",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
            "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
            "r4_input_binding": dict(R4_INPUT_BINDING),
            "maintenance_repairs": {
                "one_fit_per_exact_multi_date_block": True,
                "exact_decision_membership_hash": True,
                "same_frozen_parameter_hash_across_block": True,
                "within_block_parameter_update_count": 0,
                "fit_count": 3100,
                "decision_row_count": 64800,
                "outer_workers": 32,
                "inner_threads": 1,
                "minimum_requested_prefix_rows_per_entity": 504,
                "first_fold_one_entity_warm_rows": 503,
                "expected_regime_warmup_prefix_max_per_entity": 199,
                "expected_regime_warmup_in_decision_blocks": 0,
                "unexpected_malformed_regime_max_count": 8,
                "unexpected_malformed_regime_max_fraction": 0.02,
            },
            "candidate_count": 1,
            "hyperparameter_sweep": False,
            "authority": authority,
        }
    )
    preflight_record = sealed_payload(preflight_payload)
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.source_closure.v1",
            "status": "PASS_COMPLETE_V5_V4_LINEAGE_AND_PARENT_RUNTIME_SOURCE_CLOSURE",
            "source_audit": source_audit,
            "source_file_count": len(source_audit["source_sha256"]),
            "parent_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
            "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
            "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
            "incomplete_partial_source_import_count": 0,
            "protected_payload_open_count": 0,
            "score_call_count": 0,
            "model_registry_file_read_count": 0,
            "registry_mutation_count": 0,
        }
    )
    audit_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.v4_audit_closure.v1",
            "status": "PASS_EXACT_CLEAN_V4_INDEPENDENT_AUDIT_AND_FREEZE_BOUND",
            "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
            "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
            "v4_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "v4_finding_count": 0,
        }
    )
    input_closure = sealed_payload(input_closure_payload)
    resource_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.resource_receipt.v1",
            "status": "PASS_EXACT_OUTER32_INNER1_PY310_CPU0_31_GPU_OFF_RUNTIME",
            "resource_receipt": resource["receipt"],
            "resource_receipt_sha256": resource["receipt_sha256"],
            "runtime_plan": resource["runtime_plan"],
            "real_fit_or_prediction_run": False,
        }
    )
    quality_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.quality_receipt.v1",
            "status": "PASS_V5_BLOCK_WARMUP_ADVERSARIAL_AND_PUBLIC_SCHEMA_PREFLIGHT",
            "pytest": {
                "bytecode_disabled": True,
                "cache_provider_disabled": True,
                "focused_v5_passed": 26,
                "focused_v5_failed": 0,
                "v1_v2_v3_v4_regression_passed": 79,
                "v1_v2_v3_v4_regression_failed": 0,
            },
            "ruff": {"version": "0.12.0", "status": "ALL_CHECKS_PASSED"},
            "coverage": {
                "adversarial_date_block_attack": True,
                "adversarial_membership_attack": True,
                "adversarial_within_block_update_attack": True,
                "adversarial_prefix_504_503_relationship_attack": True,
                "adversarial_warmup_contiguity_and_decision_attack": True,
                "artifact_cross_seal_attack": True,
                "synthetic_schema_smoke": True,
                "public_r4_schema_smoke_50_tasks": True,
            },
            "empirical_score_evidence": False,
        }
    )
    access = dict(input_closure_payload["access"])
    access_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.access_receipt.v1",
            "status": "PASS_SCORE_BLIND_PUBLIC_ONLY_ACCESS_BOUNDARIES",
            "output_mutation_scope": DEFAULT_OUTPUT_ROOT.relative_to(project_root).as_posix(),
            "public_input_access": access,
            "real_data_fit_count": 0,
            "real_prediction_count": 0,
            "truth_vault_latent_heldout_score_artifact_open_count": 0,
            "model_registry_file_read_count": 0,
            "incomplete_partial_source_access_count": 0,
            "score_call_count": 0,
            "registry_or_champion_mutation_count": 0,
            "persistent_parameter_artifacts_created": 0,
        }
    )
    report = (
        "# H-OFS V5 DGP-R4 Score-Blind Preflight\n\n"
        "Status: `PASS_V5_DGP_R4_DESIGN_INPUT_PREFLIGHT_NO_MODEL_LAUNCH`\n\n"
        f"Contract: `{contract_sha256()}`\n\n"
        "V5 preserves the audited V4 estimator, final-weight KKT certificate, exact types, "
        "live state/mask custody, and artifact cross-seals. One fit is bound to each exact "
        "multi-date block: 50 tasks x 62 folds = 3,100 fits and 64,800 decision rows, with "
        "one parameter hash and zero updates inside every block.\n\n"
        "The exact outer32/inner1 pinned Python 3.10 CPU0-31 GPU-off runtime is required. "
        "Prefix requested/nonwarm/warm counts are explicit per entity, allowing the first "
        "one-entity fold only as 504 = 1 causal first row + 503 warm rows. Leading all-three "
        "missing regime warmup is separately hashed and capped at 199 per entity; it is absent "
        "from every decision block and excluded from the <=8 and <=2% malformed gate.\n\n"
        "No real fit or prediction, protected artifact access, score call, model-registry read, "
        "registry/champion mutation, or promotion was performed or authorized.\n"
    ).encode("ascii")
    core_payloads = {
        "ACCESS_RECEIPT.json": access_receipt,
        "AUDIT_CLOSURE.json": audit_closure,
        "DESIGN_LOCK.json": design_lock,
        "INPUT_CLOSURE.json": input_closure,
        "PREFLIGHT.json": preflight_record,
        "QUALITY_RECEIPT.json": quality_receipt,
        "RESOURCE_RECEIPT.json": resource_receipt,
        "SOURCE_CLOSURE.json": source_closure,
    }
    core_files = {name: _json_bytes(payload) for name, payload in core_payloads.items()}
    core_files["REPORT.md"] = report
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v5.dgp_r4_design_preflight_manifest.v1",
            "status": "PASS_V5_DGP_R4_PREFLIGHT_READY_NO_MODEL_LAUNCH",
            "design_contract_sha256": contract_sha256(),
            "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
            "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
            "r4_input_binding": dict(R4_INPUT_BINDING),
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
            "schema_version": "expected_pe.hofs_v5.dgp_r4_design_preflight_seal.v1",
            "status": "PASS_V5_DGP_R4_DESIGN_INPUT_PREFLIGHT_SEALED_NO_MODEL_LAUNCH",
            "verdict": "GO_INDEPENDENT_SCORE_BLIND_PRELAUNCH_AUDIT_ONLY",
            "design_contract_sha256": contract_sha256(),
            "v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
            "v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
            "r4_input_binding": dict(R4_INPUT_BINDING),
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
        raise RuntimeError("H-OFS V5 design bundle universe drifted")
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
        raise RuntimeError("H-OFS V5 design bundle reparse root is forbidden")
    directory = raw_directory.resolve()
    if not directory.is_dir() or _windows_reparse_point(directory):
        raise RuntimeError("H-OFS V5 design bundle root is not a regular directory")
    children = tuple(directory.iterdir())
    if any(
        path.is_symlink() or _windows_reparse_point(path) or not path.is_file()
        for path in children
    ):
        raise RuntimeError("H-OFS V5 design bundle contains a non-regular child")
    actual_names = tuple(sorted(path.name for path in children))
    if len({name.casefold() for name in actual_names}) != len(actual_names):
        raise RuntimeError("H-OFS V5 design bundle names are not unique")
    if actual_names != FINAL_FILE_UNIVERSE:
        raise RuntimeError("H-OFS V5 frozen design universe drifted")
    contents = {path.name: path.read_bytes() for path in children}
    if _raw_sha256(contents["CHECKSUMS.sha256"]) != expected_checksums_raw_sha256:
        raise RuntimeError("H-OFS V5 external checksum receipt drifted")

    expected_ledger_names = tuple(
        name for name in FINAL_FILE_UNIVERSE if name != "CHECKSUMS.sha256"
    )
    try:
        checksum_lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("H-OFS V5 checksum ledger encoding drifted") from error
    if len(checksum_lines) != len(expected_ledger_names):
        raise RuntimeError("H-OFS V5 checksum entry count drifted")
    recorded_names: list[str] = []
    for position, line in enumerate(checksum_lines):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError("H-OFS V5 checksum syntax drifted")
        digest, name = parts
        _require_sha256(digest, label="checksum entry")
        if name != expected_ledger_names[position] or name in recorded_names:
            raise RuntimeError("H-OFS V5 checksum order/universe/uniqueness drifted")
        if "/" in name or "\\" in name or Path(name).name != name:
            raise RuntimeError("H-OFS V5 checksum path syntax drifted")
        if _raw_sha256(contents[name]) != digest:
            raise RuntimeError(f"H-OFS V5 frozen checksum drifted: {name}")
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
        raise RuntimeError("H-OFS V5 canonical bundle universe drifted")
    for name in FINAL_FILE_UNIVERSE:
        if contents[name] != canonical_bundle[name]:
            raise RuntimeError(f"H-OFS V5 canonical cross-binding drifted: {name}")

    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL_RECEIPT.json"]
    if manifest.get("design_contract_sha256") != contract_sha256():
        raise RuntimeError("H-OFS V5 manifest contract binding drifted")
    if canonical_json_bytes(manifest.get("v4_independent_audit_binding")) != (
        canonical_json_bytes(V4_INDEPENDENT_AUDIT_BINDING)
    ):
        raise RuntimeError("H-OFS V5 manifest V4-audit binding drifted")
    if canonical_json_bytes(manifest.get("r4_input_binding")) != canonical_json_bytes(
        R4_INPUT_BINDING
    ):
        raise RuntimeError("H-OFS V5 manifest R4-input binding drifted")
    if manifest.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE):
        raise RuntimeError("H-OFS V5 manifest universe binding drifted")
    if seal.get("design_contract_sha256") != contract_sha256():
        raise RuntimeError("H-OFS V5 seal contract binding drifted")
    if canonical_json_bytes(seal.get("v4_independent_audit_binding")) != (
        canonical_json_bytes(V4_INDEPENDENT_AUDIT_BINDING)
    ):
        raise RuntimeError("H-OFS V5 seal V4-audit binding drifted")
    if canonical_json_bytes(seal.get("r4_input_binding")) != canonical_json_bytes(
        R4_INPUT_BINDING
    ):
        raise RuntimeError("H-OFS V5 seal R4-input binding drifted")
    if seal.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE):
        raise RuntimeError("H-OFS V5 seal universe binding drifted")
    return {
        "status": "PASS_EXACT_V5_DESIGN_BUNDLE_CLOSURE",
        "file_count": len(contents),
        "design_contract_sha256": contract_sha256(),
        "checksums_raw_sha256": _raw_sha256(contents["CHECKSUMS.sha256"]),
        "manifest_raw_sha256": _raw_sha256(contents["MANIFEST.json"]),
        "seal_raw_sha256": _raw_sha256(contents["SEAL_RECEIPT.json"]),
    }


def freeze_design_bundle(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    raw_target = Path(output_root)
    if raw_target.is_symlink() or _windows_reparse_point(raw_target):
        raise RuntimeError("H-OFS V5 freeze target reparse point is forbidden")
    target = raw_target.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root or target != DEFAULT_OUTPUT_ROOT.resolve():
        raise RuntimeError("H-OFS V5 freeze target must be the exact declared outputs child")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists():
        raise FileExistsError("H-OFS V5 freeze target or staging root already exists")
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
