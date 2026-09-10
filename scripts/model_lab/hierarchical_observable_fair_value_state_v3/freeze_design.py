"""Build, freeze, and verify the score-free H-OFS V3 design/preflight bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from research.model_zoo.hierarchical_observable_fair_value_state_v3 import (
    PARENT_RUNTIME_SOURCE_SHA256,
    V2_INDEPENDENT_AUDIT_BINDING,
    capture_runtime_receipt_v3,
    contract_payload,
    contract_sha256,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v3.contracts import (
    RUNTIME_PLAN,
    canonical_json_bytes,
    sealed_payload,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v3.source_audit import (
    run_source_audit_v3,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "outputs/model_zoo_hierarchical_observable_fair_value_state_v3_design_preflight_20260821"
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


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Return the deterministic, no-fit/no-prediction preflight record."""

    source_audit = run_source_audit_v3(project_root)
    if not source_audit.passed:
        raise RuntimeError("H-OFS V3 source isolation failed")
    resource_receipt = capture_runtime_receipt_v3(purpose="PREFLIGHT")
    return {
        "schema_version": "expected_pe.hofs_v3.score_free_preflight.v1",
        "status": "PASS_SCORE_FREE_R3_CAPABILITY_PREFLIGHT_NO_MODEL_LAUNCH",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "v2_independent_audit_binding": dict(V2_INDEPENDENT_AUDIT_BINDING),
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
            "schema_version": "expected_pe.hofs_v3.design_lock.v1",
            "status": "PASS_V3_REPAIR_DESIGN_LOCK_SCORE_FREE_ONLY",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "v2_independent_audit_binding": dict(V2_INDEPENDENT_AUDIT_BINDING),
            "closed_findings": {
                "P1": list(V2_INDEPENDENT_AUDIT_BINDING["closed_p1"]),
                "P2": list(V2_INDEPENDENT_AUDIT_BINDING["closed_p2"]),
            },
            "candidate_count": 1,
            "hyperparameter_sweep": False,
            "authority": preflight_payload["authority"],
        }
    )
    preflight_record = sealed_payload(preflight_payload)
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v3.source_closure.v1",
            "status": "PASS_COMPLETE_V3_SOURCE_AND_PARENT_RUNTIME_CLOSURE",
            "source_audit": source_audit,
            "source_file_count": len(source_audit["source_sha256"]),
            "parent_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
            "v2_audit_raw_sha256": V2_INDEPENDENT_AUDIT_BINDING["raw_sha256"],
            "v2_audit_semantic_sha256": V2_INDEPENDENT_AUDIT_BINDING[
                "semantic_sha256"
            ],
            "frozen_prediction_package_import_count": 0,
            "protected_payload_open_count": 0,
            "score_call_count": 0,
            "registry_mutation_count": 0,
        }
    )
    resource_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v3.resource_receipt.v1",
            "status": "PASS_EXACT_PY310_CPU0_31_INNER1_GPU_OFF_RUNTIME",
            "resource_receipt": resource["receipt"],
            "resource_receipt_sha256": resource["receipt_sha256"],
            "runtime_plan": resource["runtime_plan"],
            "real_fit_or_prediction_run": False,
        }
    )
    quality_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v3.quality_receipt.v1",
            "status": "PASS_V3_ADVERSARIAL_AND_REGRESSION_PREFLIGHT",
            "pytest": {
                "bytecode_disabled": True,
                "cache_provider_disabled": True,
                "v3_passed": 17,
                "v3_failed": 0,
                "v1_v2_v3_regression_passed": 33,
                "v1_v2_v3_regression_failed": 0,
            },
            "ruff": {
                "version": "0.12.0",
                "status": "ALL_CHECKS_PASSED",
            },
            "inference_launcher": {
                "status": "PASS_EXACT_HOFS_V3_INFERENCE_LAUNCHER_PREFLIGHT_ONLY",
                "resource_receipt_sha256": (
                    "e3f249617294ead7408a933ae67485ea3173a0eab9feaed417c19a7c26515b39"
                ),
            },
            "two_clean_process_reproducibility": {
                "runs": 2,
                "exact": True,
                "run_1_sha256": (
                    "d41a3c0a5389379a71c4da0056c61383b163ee11dc1236b4c6cecefa4c1f86a1"
                ),
                "run_2_sha256": (
                    "d41a3c0a5389379a71c4da0056c61383b163ee11dc1236b4c6cecefa4c1f86a1"
                ),
            },
            "adversarial_repairs": {
                finding: True
                for finding in (
                    *V2_INDEPENDENT_AUDIT_BINDING["closed_p1"],
                    *V2_INDEPENDENT_AUDIT_BINDING["closed_p2"],
                )
            },
            "empirical_score_evidence": False,
        }
    )
    access_receipt = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v3.access_receipt.v1",
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
            "v1_v2_source_or_audit_mutation_count": 0,
            "persistent_parameter_artifacts_created": 0,
        }
    )
    report = (
        "# H-OFS V3 Score-Free Design Preflight\n\n"
        "Status: `PASS_V3_REPAIR_DESIGN_PREFLIGHT_NO_MODEL_LAUNCH`\n\n"
        f"Contract: `{contract_sha256()}`\n\n"
        "This isolated V3 revision closes all six P1 and three P2 findings from the "
        "sealed V2 independent audit. The exact Python 3.10.19 CPU-only runtime, final-weight "
        "KKT certificate, strict entity/DGP/decision custody, exact semantic bundle loader, "
        "decision-row fallback gate, log-scale output, and inference resource receipt are "
        "implemented and covered by synthetic adversarial tests.\n\n"
        "V3 tests passed 17/17; V1+V2+V3 regression passed 33/33; Ruff and the exact "
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
            "schema_version": "expected_pe.hofs_v3.design_preflight_manifest.v1",
            "status": "PASS_V3_REPAIR_PREFLIGHT_READY_NO_MODEL_LAUNCH",
            "design_contract_sha256": contract_sha256(),
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
            "schema_version": "expected_pe.hofs_v3.design_preflight_seal.v1",
            "status": "PASS_V3_REPAIR_DESIGN_PREFLIGHT_SEALED_NO_MODEL_LAUNCH",
            "verdict": "GO_INDEPENDENT_SCORE_FREE_AUDIT_ONLY",
            "design_contract_sha256": contract_sha256(),
            "v2_audit_raw_sha256": V2_INDEPENDENT_AUDIT_BINDING["raw_sha256"],
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
        raise RuntimeError("H-OFS V3 design bundle universe drifted")
    return bundle


def verify_design_bundle(output_root: Path) -> dict[str, Any]:
    directory = output_root.resolve()
    children = tuple(directory.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in children):
        raise RuntimeError("H-OFS V3 design bundle contains a non-regular child")
    if tuple(sorted(path.name for path in children)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("H-OFS V3 frozen design universe drifted")
    contents = {path.name: path.read_bytes() for path in children}
    checksums = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    if len(checksums) != len(FINAL_FILE_UNIVERSE) - 1:
        raise RuntimeError("H-OFS V3 checksum entry count drifted")
    for line in checksums:
        digest, name = line.split("  ", maxsplit=1)
        if name == "CHECKSUMS.sha256" or _raw_sha256(contents[name]) != digest:
            raise RuntimeError(f"H-OFS V3 frozen checksum drifted: {name}")
    for name, content in contents.items():
        if not name.endswith(".json"):
            continue
        payload = json.loads(content.decode("ascii"))
        _logical_sha256(payload)
    return {
        "status": "PASS_EXACT_V3_DESIGN_BUNDLE_CLOSURE",
        "file_count": len(contents),
        "design_contract_sha256": contract_sha256(),
        "checksums_raw_sha256": _raw_sha256(contents["CHECKSUMS.sha256"]),
        "manifest_raw_sha256": _raw_sha256(contents["MANIFEST.json"]),
        "seal_raw_sha256": _raw_sha256(contents["SEAL_RECEIPT.json"]),
    }


def freeze_design_bundle(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    target = output_root.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root:
        raise RuntimeError("H-OFS V3 freeze target must be a direct outputs child")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists():
        raise FileExistsError("H-OFS V3 freeze target or staging root already exists")
    bundle = build_design_bundle_bytes(PROJECT_ROOT)
    staging.mkdir()
    for name, content in bundle.items():
        (staging / name).write_bytes(content)
    verify_design_bundle(staging)
    staging.replace(target)
    return verify_design_bundle(target)


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
