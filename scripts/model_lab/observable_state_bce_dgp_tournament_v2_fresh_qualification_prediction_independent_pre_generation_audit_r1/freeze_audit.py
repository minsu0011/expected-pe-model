"""Freeze the bounded independent pre-generation audit for the fresh BCE lane.

This builder reads only the explicitly named precommit, frozen R8-r5 design
evidence, and their exact source closures.  It never resolves or opens a
generation payload root and never calls generation, fitting, prediction, or
assessment code.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
PRECOMMIT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "fresh_qualification_prediction_precommit_20260821"
)
R8_DESIGN_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_design_r5_20260821"
)
AUDIT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "fresh_qualification_prediction_independent_pre_generation_audit_r1_20260821"
)
STAGING_RELATIVE = (
    "outputs/.model_zoo_observable_state_bce_dgp_tournament_v2_"
    "fresh_qualification_prediction_independent_pre_generation_audit_r1_"
    "20260821.staging"
)

EXPECTED_PRECOMMIT_CHECKSUMS = (
    "9cff767a648af46ce16adea8641f71254aa86f2cb4a971c3917ae3a9a934f6e2"
)
EXPECTED_R8_DESIGN_CHECKSUMS = (
    "9efc0e503d8fddbc144270fdeec1c2a86c60c083f2cee9aa0b263aaba719e70c"
)
EXPECTED_R8_SOURCE_LOCK = (
    "b06bc175c8cdcb247ff3f4fe92cd3a05f041644de5c85a46691498c255c0b085"
)

OUTPUT_FILE_UNIVERSE = (
    "AUDIT.json",
    "CHECKSUMS.sha256",
    "FINDINGS.json",
    "REPORT.md",
    "SEAL_RECEIPT.json",
)

RELEVANT_PUBLICATION_SOURCES = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/contracts.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/paths.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/activation.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/publication.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation/controller.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation/contracts.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation/artifacts.py",
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r7_qualification_generation/runtime_custody.py",
)

PRECOMMIT_SEMANTIC_FIELDS = {
    "DESIGN_PREVIEW.json": "design_preview_semantic_sha256",
    "PREFLIGHT.json": "preflight_semantic_sha256",
    "SOURCE_AUDIT.json": "source_audit_semantic_sha256",
    "SOURCE_MANIFEST.json": "source_manifest_semantic_sha256",
    "VERIFICATION.json": "verification_semantic_sha256",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sealed(payload: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = dict(payload)
    if field in result:
        raise RuntimeError(f"semantic field already present: {field}")
    result[field] = sha256_bytes(canonical_bytes(result))
    return result


def verify_sealed(payload: Mapping[str, Any], field: str) -> None:
    clone = dict(payload)
    stored = clone.pop(field, None)
    if stored != sha256_bytes(canonical_bytes(clone)):
        raise RuntimeError(f"semantic seal mismatch: {field}")


def parse_checksums(raw: bytes) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        digest, relative = line.split("  ", 1)
        candidate = Path(relative.replace("\\", "/"))
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in records
            or candidate.is_absolute()
            or ".." in candidate.parts
        ):
            raise RuntimeError("invalid checksum ledger")
        records[relative] = digest
    if not records:
        raise RuntimeError("empty checksum ledger")
    return records


def verify_precommit(precommit: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    expected_files = tuple(sorted((*PRECOMMIT_SEMANTIC_FIELDS, "CHECKSUMS.sha256")))
    actual_files = tuple(sorted(path.name for path in precommit.iterdir() if path.is_file()))
    if actual_files != expected_files:
        raise RuntimeError("precommit exact six-file universe drifted")
    checksums_raw = (precommit / "CHECKSUMS.sha256").read_bytes()
    if sha256_bytes(checksums_raw) != EXPECTED_PRECOMMIT_CHECKSUMS:
        raise RuntimeError("precommit CHECKSUMS bytes drifted")
    ledger = parse_checksums(checksums_raw)
    if tuple(sorted(ledger)) != tuple(sorted(PRECOMMIT_SEMANTIC_FIELDS)):
        raise RuntimeError("precommit checksum member universe drifted")
    semantic: dict[str, Any] = {}
    for name, field in PRECOMMIT_SEMANTIC_FIELDS.items():
        raw = (precommit / name).read_bytes()
        if sha256_bytes(raw) != ledger[name]:
            raise RuntimeError(f"precommit member raw hash drifted: {name}")
        payload = json.loads(raw)
        verify_sealed(payload, field)
        semantic[name] = payload[field]

    manifest = json.loads((precommit / "SOURCE_MANIFEST.json").read_bytes())
    source_records = manifest["files"]
    if manifest.get("file_count") != 14 or len(source_records) != 14:
        raise RuntimeError("precommit source manifest count drifted")
    source_rows: list[dict[str, Any]] = []
    for relative, record in sorted(source_records.items()):
        path = ROOT / relative
        current = sha256_file(path)
        if current != record["raw_sha256"] or path.stat().st_size != record["bytes"]:
            raise RuntimeError(f"precommit source drifted: {relative}")
        source_rows.append(
            {
                "relative_path": relative,
                "raw_sha256": current,
                "size_bytes": path.stat().st_size,
            }
        )
    return {
        "root_relative": PRECOMMIT_RELATIVE,
        "checksums_raw_sha256": EXPECTED_PRECOMMIT_CHECKSUMS,
        "file_count": 6,
        "checksum_member_count": 5,
        "semantic_sha256": semantic,
        "source_count": 14,
        "source_mismatch_count": 0,
    }, source_rows


def verify_r8_design(r8_design: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    checksums_raw = (r8_design / "CHECKSUMS.sha256").read_bytes()
    if sha256_bytes(checksums_raw) != EXPECTED_R8_DESIGN_CHECKSUMS:
        raise RuntimeError("R8-r5 design CHECKSUMS bytes drifted")
    ledger = parse_checksums(checksums_raw)
    for name in (
        "DESIGN_LOCK.json",
        "MANIFEST.json",
        "PROCESS_ISOLATION_CONTRACT.json",
        "SOURCE_LOCK.json",
    ):
        if sha256_file(r8_design / name) != ledger.get(name):
            raise RuntimeError(f"R8-r5 design member drifted: {name}")
    if sha256_file(r8_design / "SOURCE_LOCK.json") != EXPECTED_R8_SOURCE_LOCK:
        raise RuntimeError("R8-r5 source lock bytes drifted")
    design = json.loads((r8_design / "DESIGN_LOCK.json").read_bytes())
    manifest = json.loads((r8_design / "MANIFEST.json").read_bytes())
    isolation = json.loads((r8_design / "PROCESS_ISOLATION_CONTRACT.json").read_bytes())
    if (
        design.get("status") != "FROZEN_SCORE_FREE_PRE_GENERATION"
        or design.get("payload_generation_count") != 0
        or design.get("model_fit_prediction_evaluation_score_count") != 0
        or design.get("truth_vault_latent_open_count") != 0
        or manifest.get("qualification_generation_authorized") is not False
        or isolation.get("run_id_source")
        != "SIGNED_ISSUED_AT_UTC_DERIVED_YYYYMMDDTHHMMSS"
    ):
        raise RuntimeError("R8-r5 frozen design state drifted")
    source_lock = json.loads((r8_design / "SOURCE_LOCK.json").read_bytes())
    locked = {
        record["relative_path"]: record["raw_sha256"]
        for record in source_lock["records"]
    }
    rows: list[dict[str, Any]] = []
    for relative in RELEVANT_PUBLICATION_SOURCES:
        current = sha256_file(ROOT / relative)
        expected = locked.get(relative)
        if current != expected:
            raise RuntimeError(f"R8/R7 publication source drifted: {relative}")
        rows.append(
            {
                "relative_path": relative,
                "raw_sha256": current,
                "source_lock_match": True,
            }
        )
    return {
        "root_relative": R8_DESIGN_RELATIVE,
        "checksums_raw_sha256": EXPECTED_R8_DESIGN_CHECKSUMS,
        "source_lock_raw_sha256": EXPECTED_R8_SOURCE_LOCK,
        "status": design["status"],
        "qualification_generation_authorized": False,
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
        "run_id_source": isolation["run_id_source"],
        "relevant_publication_source_count": len(rows),
        "relevant_publication_source_mismatch_count": 0,
    }, rows


def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "src"))

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction import (  # noqa: E501
        bindings as fresh_bindings,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction import (  # noqa: E501
        contracts as fresh_contracts,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction import (  # noqa: E501
        custody as fresh_custody,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation import (  # noqa: E501
        contracts as r7_contracts,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation import (  # noqa: E501
        contracts as r8_contracts,
    )

    precommit = ROOT / PRECOMMIT_RELATIVE
    r8_design = ROOT / R8_DESIGN_RELATIVE
    destination = ROOT / AUDIT_RELATIVE
    staging = ROOT / STAGING_RELATIVE
    if destination.exists() or staging.exists():
        raise RuntimeError("audit destination or staging already exists")

    precommit_receipt, precommit_sources = verify_precommit(precommit)
    r8_receipt, publication_sources = verify_r8_design(r8_design)

    null_bindings = fresh_bindings.null_future_binding_payload()
    null_hash_fields = [
        [binding_name, field_name]
        for binding_name, binding in null_bindings.items()
        for field_name, value in binding.items()
        if field_name.endswith("_sha256") and value is None
    ]
    if len(null_hash_fields) != 13:
        raise RuntimeError("null future binding hash count drifted")

    expected_generation_root = fresh_bindings.EXPECTED_R8_GENERATION_ROOT
    actual_root_template = (
        "outputs/"
        + r8_contracts.PUBLIC_FINAL_PREFIX
        + "<YYYYMMDDTHHMMSS>"
    )
    expected_metadata = (
        fresh_custody.R8_GENERATION_DESIGN_FILENAME,
        fresh_custody.R8_GENERATION_MANIFEST_FILENAME,
        fresh_custody.R8_FREEZE_RECEIPT_FILENAME,
        fresh_custody.CHECKSUMS_FILENAME,
    )
    actual_root_universe = tuple(r7_contracts.PUBLIC_ROOT_FILE_UNIVERSE)
    missing_metadata = tuple(
        name for name in expected_metadata if name not in actual_root_universe
    )
    if (
        expected_generation_root
        == "outputs/" + r8_contracts.PUBLIC_FINAL_PREFIX + "20260821T000000"
        or missing_metadata != ("DESIGN_LOCK.json", "GENERATION_MANIFEST.json")
    ):
        raise RuntimeError("compatibility proof premise drifted")

    custody_text = (
        ROOT
        / "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
        "fresh_qualification_prediction/custody.py"
    ).read_text(encoding="utf-8")
    r7_controller_text = (
        ROOT
        / "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
        "r7_qualification_generation/controller.py"
    ).read_text(encoding="utf-8")
    expected_freeze_status = (
        "PASS_PUBLIC_CANONICAL_OVERLAY_INPUTS_FROZEN_READY_FOR_ONE_SURVIVOR"
    )
    actual_freeze_status = "PASS_PUBLIC_ROOT_FROZEN_PENDING_ATOMIC_PUBLISH"
    if expected_freeze_status not in custody_text or actual_freeze_status not in r7_controller_text:
        raise RuntimeError("freeze receipt status evidence drifted")

    resource = asdict(fresh_contracts.RESOURCE_POLICY)
    resource.update(
        {
            "affinity_mask_hex": (
                f"0x{fresh_contracts.RESOURCE_POLICY.affinity_mask:08X}"
            ),
            "environment": fresh_contracts.RESOURCE_POLICY.environment,
        }
    )
    if (
        resource["cpu_ids"] != tuple(range(32))
        or resource["outer_workers"] != 32
        or resource["outer_backend"] != "spawn_process_pool"
        or resource["inner_threads"] != 1
        or resource["gpu_enabled"] is not False
    ):
        raise RuntimeError("fresh prediction resource freeze drifted")
    resource["cpu_ids"] = list(resource["cpu_ids"])

    forbidden_columns = sorted(
        column
        for column in fresh_contracts.PREDICTION_COLUMNS
        if any(
            token in column.casefold()
            for token in fresh_contracts.FORBIDDEN_PREDICTION_FIELD_TOKENS
        )
    )
    if forbidden_columns:
        raise RuntimeError("restricted prediction field entered the frozen schema")

    formula_geometry = {
        "model_ids_in_fixed_order": list(fresh_contracts.MODEL_IDS),
        "candidate_ids_in_fixed_order": list(fresh_contracts.CANDIDATE_IDS),
        "constituent_model_ids": list(fresh_contracts.CONSTITUENT_MODEL_IDS),
        "constituent_role": fresh_contracts.CONSTITUENT_ROLE,
        "direction_epsilon": fresh_contracts.DIRECTION_EPSILON,
        "rolling_dispersion_window": fresh_contracts.ROLLING_DISPERSION_WINDOW,
        "rolling_dispersion_min_periods": (
            fresh_contracts.ROLLING_DISPERSION_MIN_PERIODS
        ),
        "fixed_directional_alpha": fresh_contracts.FIXED_DIRECTIONAL_ALPHA,
        "task_count": fresh_contracts.EXPECTED_TASK_COUNT,
        "fold_blocks": fresh_contracts.EXPECTED_FOLD_BLOCKS,
        "identity_count": fresh_contracts.EXPECTED_IDENTITIES,
        "model_identity_rows": fresh_contracts.EXPECTED_MODEL_IDENTITY_ROWS,
        "constituent_fits": fresh_contracts.EXPECTED_CONSTITUENT_FITS,
        "fold_geometry": asdict(fresh_contracts.FOLD_GEOMETRY),
        "fold_count": fresh_contracts.FOLD_GEOMETRY.fold_count,
        "prediction_rows_per_task": (
            fresh_contracts.FOLD_GEOMETRY.prediction_rows_per_task
        ),
        "formula_contract": {
            "directional_agreement": (
                "both constituent log corrections share sign outside epsilon"
            ),
            "raw_consensus": (
                "0.5*(constituent_a_log_correction+constituent_b_log_correction) "
                "on agreement else 0"
            ),
            "candidate_B": (
                "alpha=min(1,sqrt(prior_shift1_rolling_mean_63_min10_of_"
                "half_squared_corrections)/abs(raw_consensus))"
            ),
            "candidate_D": "alpha=observable_state_confidence on agreement else 0",
            "fixed_040": "alpha=0.4 on agreement else 0",
            "output": "exp(log(champion_expected_pe)+alpha*raw_consensus)",
        },
        "causal_future_perturbation_test": "PASS_SYNTHETIC",
        "restricted_prediction_columns": forbidden_columns,
        "truth_or_assessment_values_in_output": False,
    }
    if (
        formula_geometry["task_count"] != 50
        or formula_geometry["fold_blocks"] != 3100
        or formula_geometry["identity_count"] != 64800
        or formula_geometry["model_identity_rows"] != 259200
        or formula_geometry["constituent_fits"] != 6200
        or formula_geometry["fold_count"] != 62
        or formula_geometry["prediction_rows_per_task"] != 1296
    ):
        raise RuntimeError("candidate/formula/geometry invariant drifted")

    compatibility = {
        "expected_generation_root_relative": expected_generation_root,
        "actual_r8_r5_publication_root_template": actual_root_template,
        "root_contract_can_match": False,
        "expected_root_metadata_filenames": list(expected_metadata),
        "actual_r7_public_root_file_universe": list(actual_root_universe),
        "required_metadata_missing_from_actual_publication": list(missing_metadata),
        "actual_public_root_file_universe_is_exact_and_forbids_additions": True,
        "expected_freeze_receipt_status": expected_freeze_status,
        "actual_freeze_receipt_status": actual_freeze_status,
        "freeze_receipt_status_can_match": False,
        "expected_receipt_requires_seed_and_dgp_lists": True,
        "actual_r7_freeze_receipt_has_seed_and_dgp_lists": False,
        "expected_task_paths": (
            "replays/pass_1/seed_<receipt_seed>/dgp_<A-J>/"
            "{canonical150.csv,v04_overlay.csv,GEOMETRY.json}"
        ),
        "actual_public_replay_pass_count": 2,
        "task_payload_names_have_partial_structural_overlap": True,
        "any_conforming_actual_r8_r5_publication_can_satisfy_bind_generation": False,
        "satisfiable_without_frozen_code_change": False,
        "correction_to_task_hypothesis": (
            "The frozen precommit expects DESIGN_LOCK.json, not "
            "GENERATION_DESIGN.json; GENERATION_MANIFEST.json is exact."
        ),
    }

    findings = sealed(
        {
            "schema_version": (
                "expected_pe.observable_state_bce_dgp_tournament.v2."
                "fresh_qualification_prediction.independent_pre_generation_"
                "audit_r1.findings.v1"
            ),
            "status": "CONFIRMED_ONE_TERMINAL_P1_NO_P0_NO_P2",
            "severity_definitions": {
                "P0": (
                    "custody or authority failure permitting unauthorized real "
                    "access, execution, prediction, truth, or score use"
                ),
                "P1": (
                    "terminal core-contract incompatibility while the boundary "
                    "still fails closed"
                ),
                "P2": "non-terminal deficiency or maintenance risk",
            },
            "counts": {"P0": 0, "P1": 1, "P2": 0},
            "findings": [
                {
                    "finding_id": "P1-001",
                    "severity": "P1",
                    "status": "CONFIRMED_TERMINAL_FOR_EXACT_FROZEN_PRECOMMIT",
                    "title": (
                        "Frozen upstream generation binding is structurally "
                        "incompatible with every conforming R8-r5 public publication"
                    ),
                    "evidence": compatibility,
                    "impact": (
                        "The exact precommit can never bind the actual R8-r5 public "
                        "output and therefore cannot reach its prediction lane."
                    ),
                    "safety_characterization": (
                        "The defect fails closed. Null defaults stop before any path "
                        "or worker access, and an actual R8-r5 root string is rejected "
                        "before generation payload bytes are opened."
                    ),
                    "required_remediation": (
                        "Create a new, separately frozen revision whose upstream "
                        "binding accepts the authenticated run-id publication root and "
                        "the exact R7 MANIFEST/FREEZE_RECEIPT/CHECKSUMS contract, then "
                        "repeat independent pre-generation audit."
                    ),
                    "remediated_in_this_audit": False,
                }
            ],
            "exact_precommit_terminal": True,
            "execution_authority_granted": False,
        },
        "findings_semantic_sha256",
    )

    access_counts = {
        "actual_generation_output_roots_enumerated": 0,
        "actual_generation_payload_paths_resolved": 0,
        "actual_generation_payload_files_opened": 0,
        "actual_generation_payload_bytes_read": 0,
        "generation_calls": 0,
        "actual_model_fit_calls": 0,
        "actual_prediction_calls": 0,
        "assessment_calls": 0,
        "truth_vault_paths_resolved": 0,
        "truth_or_latent_files_opened": 0,
        "heldout_payload_files_opened": 0,
        "score_or_metric_files_opened": 0,
        "registry_or_execution_authority_reads": 0,
        "signatures_requested": 0,
        "activation_authorities_created": 0,
    }

    audit = sealed(
        {
            "schema_version": (
                "expected_pe.observable_state_bce_dgp_tournament.v2."
                "fresh_qualification_prediction.independent_pre_generation_"
                "audit_r1.audit.v1"
            ),
            "status": "NO_GO_TERMINAL_EXACT_PRECOMMIT_UPSTREAM_CONTRACT_INCOMPATIBLE",
            "verdict": "NO_GO",
            "audit_root_relative": AUDIT_RELATIVE,
            "audited_at_utc": datetime.now(timezone.utc).isoformat(),
            "independence": {
                "auditor_did_not_author_exact_precommit": True,
                "auditee_mutated": False,
                "revision_built": False,
            },
            "scope": {
                "precommit_root_relative": PRECOMMIT_RELATIVE,
                "precommit_exact_source_test_script_count": 14,
                "r8_r5_design_root_relative": R8_DESIGN_RELATIVE,
                "r8_r5_and_r7_publication_source_paths": list(
                    RELEVANT_PUBLICATION_SOURCES
                ),
                "broad_outputs_enumerated": False,
                "real_payloads_in_scope": False,
            },
            "inputs": {
                "precommit": precommit_receipt,
                "precommit_sources": precommit_sources,
                "r8_r5_design": r8_receipt,
                "publication_sources": publication_sources,
            },
            "reproduction": {
                "pytest_setup_attempt": {
                    "returncode": 1,
                    "tests_executed": 0,
                    "classification": "ENVIRONMENT_SETUP_ONLY_NOT_TEST_FAILURE",
                    "reason": (
                        "repository src package was absent from interpreter path"
                    ),
                    "error": "ModuleNotFoundError: pe_regime_v04",
                },
                "pytest_controlled_final": {
                    "environment": {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                        "PYTEST_ADDOPTS": "-p no:cacheprovider",
                        "PYTHONPATH": "<PROJECT_ROOT>/src",
                    },
                    "test_path": (
                        "tests/model_lab/test_observable_state_bce_dgp_tournament_"
                        "v2_fresh_qualification_prediction.py"
                    ),
                    "returncode": 0,
                    "collected": 17,
                    "passed": 17,
                    "failed": 0,
                    "errors": 0,
                    "skipped": 0,
                    "synthetic_fixtures_only": True,
                },
                "ruff": {
                    "returncode": 0,
                    "audited_path_count": 14,
                    "summary": "All checks passed!",
                },
                "source_hash_check": {
                    "count": 14,
                    "mismatch_count": 0,
                    "status": "PASS",
                },
                "candidate_formula_geometry_truth_free_check": {
                    "status": "PASS",
                    "details": formula_geometry,
                },
                "null_binding_check": {
                    "status": "PASS_FAIL_CLOSED",
                    "null_hash_field_count": len(null_hash_fields),
                    "all_hash_pins_null": True,
                    "path_or_worker_access_before_rejection": False,
                    "future_binding_payload": null_bindings,
                },
                "resource_declaration_check": {
                    "status": "PASS_EXACT_DECLARATION",
                    "resource_policy": resource,
                    "spawn_context": True,
                    "executor_map_chunksize": 1,
                    "input_order_preserved": True,
                    "worker_environment_and_affinity_initializer": True,
                    "note": (
                        "This resource pass does not cure the upstream P1 and grants "
                        "no launch authority."
                    ),
                },
                "generation_binding_satisfiability_check": {
                    "status": "FAIL_TERMINAL",
                    "details": compatibility,
                },
            },
            "finding_counts": {"P0": 0, "P1": 1, "P2": 0},
            "findings_semantic_sha256": findings["findings_semantic_sha256"],
            "access_counts": access_counts,
            "access_counts_are_exact": True,
            "authority": {
                "prediction_execution_authorized": False,
                "generation_authorized": False,
                "truth_open_authorized": False,
                "score_authorized": False,
                "model_portfolio_promotion_authorized": False,
            },
            "terminal_for_exact_precommit": True,
            "next_action": "NEW_REVISION_DESIGN_AND_FRESH_INDEPENDENT_AUDIT_ONLY",
        },
        "audit_semantic_sha256",
    )

    report = f"""# Independent pre-generation audit — fresh BCE qualification prediction

Verdict: **NO_GO — terminal for the exact frozen precommit.**

The audit confirmed P0=0, P1=1, P2=0. The single P1 is decisive: the frozen
`_bind_generation` contract cannot accept any conforming R8-r5 publication.
The boundary fails closed, so this is not an authority or custody bypass.

## Decisive incompatibility

- Frozen expected root: `{expected_generation_root}`
- Actual R8-r5 root template: `{actual_root_template}`
- Frozen required metadata: `{', '.join(expected_metadata)}`
- Actual R7 public finalizer metadata includes `MANIFEST.json`,
  `FREEZE_RECEIPT.json`, and `CHECKSUMS.sha256`; its exact root universe omits
  `DESIGN_LOCK.json` and `GENERATION_MANIFEST.json` and forbids additions.
- Frozen expected freeze status: `{expected_freeze_status}`
- Actual public-finalizer freeze status: `{actual_freeze_status}`

Correction to the initial audit hypothesis: the frozen code expects
`DESIGN_LOCK.json`, not `GENERATION_DESIGN.json`. The incompatibility remains
terminal because the actual publication contains neither `DESIGN_LOCK.json`
nor `GENERATION_MANIFEST.json`, and the root and receipt schemas also differ.

## Reproduction

- Source manifest: 14/14 exact hashes match.
- Pytest: 17/17 synthetic tests pass after explicitly setting
  `PYTHONPATH=<PROJECT_ROOT>/src`; the preceding unconfigured collection attempt
  executed zero tests and failed only because `pe_regime_v04` was not importable.
- Ruff: all 14 declared paths pass.
- Candidate/formula/geometry/truth-free checks: pass.
- Null binding boundary: 13/13 future hash pins remain null and default launch
  fails before path or worker access.
- Resource declaration: exact 32-worker spawn pool, CPU IDs 0–31, one inner
  thread, GPU disabled, deterministic input-order map.

## Access and authority

No actual generation root was enumerated or resolved. No generation payload,
truth, heldout, score, registry authority, model fit, prediction, or assessment
was opened or executed. No signature was requested and no activation authority
was created. This audit grants no execution authority.

Required next action: retire this exact precommit and create a separately frozen
revision bound to the authenticated R8-r5 run-id root and the exact R7 public
`MANIFEST.json` / `FREEZE_RECEIPT.json` / `CHECKSUMS.sha256` contract, followed
by a fresh independent pre-generation audit.
""".encode("utf-8")

    staging.mkdir(parents=False, exist_ok=False)
    write_new(staging / "AUDIT.json", pretty_bytes(audit))
    write_new(staging / "FINDINGS.json", pretty_bytes(findings))
    write_new(staging / "REPORT.md", report)

    seal_receipt = sealed(
        {
            "schema_version": (
                "expected_pe.observable_state_bce_dgp_tournament.v2."
                "fresh_qualification_prediction.independent_pre_generation_"
                "audit_r1.seal_receipt.v1"
            ),
            "status": "SEALED_NO_GO_TERMINAL_EXACT_PRECOMMIT_NO_AUTHORITY",
            "audit_root_relative": AUDIT_RELATIVE,
            "artifact_raw_sha256": {
                name: sha256_file(staging / name)
                for name in ("AUDIT.json", "FINDINGS.json", "REPORT.md")
            },
            "audit_semantic_sha256": audit["audit_semantic_sha256"],
            "findings_semantic_sha256": findings["findings_semantic_sha256"],
            "finding_counts": {"P0": 0, "P1": 1, "P2": 0},
            "verdict": "NO_GO",
            "terminal_for_exact_precommit": True,
            "execution_authority_granted": False,
            "generation_or_prediction_executed": False,
            "real_payload_access_count": 0,
            "output_file_universe": list(OUTPUT_FILE_UNIVERSE),
            "builder_source_relative": Path(__file__).resolve().relative_to(ROOT).as_posix(),
            "builder_source_raw_sha256": sha256_file(Path(__file__).resolve()),
            "next_action": "NEW_REVISION_DESIGN_AND_FRESH_INDEPENDENT_AUDIT_ONLY",
        },
        "seal_receipt_semantic_sha256",
    )
    write_new(staging / "SEAL_RECEIPT.json", pretty_bytes(seal_receipt))

    checksum_members = ("AUDIT.json", "FINDINGS.json", "REPORT.md", "SEAL_RECEIPT.json")
    checksums_raw = "".join(
        f"{sha256_file(staging / name)}  {name}\n" for name in checksum_members
    ).encode("ascii")
    write_new(staging / "CHECKSUMS.sha256", checksums_raw)

    actual_universe = tuple(sorted(path.name for path in staging.iterdir() if path.is_file()))
    if actual_universe != OUTPUT_FILE_UNIVERSE:
        raise RuntimeError("audit output file universe drifted")
    ledger = parse_checksums((staging / "CHECKSUMS.sha256").read_bytes())
    for name, digest in ledger.items():
        if sha256_file(staging / name) != digest:
            raise RuntimeError(f"final audit checksum drifted: {name}")
    verify_sealed(json.loads((staging / "AUDIT.json").read_bytes()), "audit_semantic_sha256")
    verify_sealed(
        json.loads((staging / "FINDINGS.json").read_bytes()),
        "findings_semantic_sha256",
    )
    verify_sealed(
        json.loads((staging / "SEAL_RECEIPT.json").read_bytes()),
        "seal_receipt_semantic_sha256",
    )

    os.replace(staging, destination)
    result = {
        "status": "SEALED_NO_GO_TERMINAL_EXACT_PRECOMMIT_NO_AUTHORITY",
        "root_relative": AUDIT_RELATIVE,
        "checksums_raw_sha256": sha256_file(destination / "CHECKSUMS.sha256"),
        "audit_raw_sha256": sha256_file(destination / "AUDIT.json"),
        "audit_semantic_sha256": audit["audit_semantic_sha256"],
        "findings_raw_sha256": sha256_file(destination / "FINDINGS.json"),
        "findings_semantic_sha256": findings["findings_semantic_sha256"],
        "seal_receipt_raw_sha256": sha256_file(destination / "SEAL_RECEIPT.json"),
        "seal_receipt_semantic_sha256": seal_receipt[
            "seal_receipt_semantic_sha256"
        ],
        "report_raw_sha256": sha256_file(destination / "REPORT.md"),
        "finding_counts": {"P0": 0, "P1": 1, "P2": 0},
        "real_payload_access_count": 0,
        "execution_authority_granted": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
