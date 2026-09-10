"""Consume one R3 prediction authority before any formal public replay read.

This control-plane launcher is intentionally outside the frozen numerical source
closure.  It does not calculate or alter predictions.  It validates the frozen
R3 authorities, durably publishes a create-new invocation claim, and then calls
the already-frozen prediction publisher exactly once.  A surviving claim makes
every ambiguous or failed child invocation terminal and non-retryable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
PYTHON = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve(strict=True)

RUN_ID = "r3_20260824T134417"
AUTHORITY_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_preuse_authority_{RUN_ID}.json"
CLAIM_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_invocation_claim_{RUN_ID}.json"
EXECUTION_AUTHORITY_RELATIVE = f"build/pe_four_model_heldout_execution_authority_{RUN_ID}.json"
PUBLIC_REPLAY_RELATIVE = f"outputs/model_zoo_pe_four_model_heldout_public_replay_{RUN_ID}"
WORK_ROOT_RELATIVE = f"build/pe_four_model_heldout_prediction_work_{RUN_ID}"
PREDICTION_ROOT_RELATIVE = f"outputs/model_zoo_pe_four_model_heldout_predictions_{RUN_ID}"
ACTIVATION_ROOT_RELATIVE = f"outputs/model_zoo_pe_model_portfolio_heldout_activation_{RUN_ID}"
CERTIFICATION_ROOT_RELATIVE = (
    f"outputs/model_zoo_pe_model_portfolio_heldout_certification_result_{RUN_ID}"
)
LAUNCHER_PYCACHE_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_launcher_pycache_{RUN_ID}"
PUBLISHER_PYCACHE_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_publisher_pycache_{RUN_ID}"
WORKER_PYCACHE_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_worker_pycache_{RUN_ID}"
VALIDATOR_PYCACHE_RELATIVE = f"build/pe_four_model_heldout_r3_prediction_validator_pycache_{RUN_ID}"
PUBLISHER_RELATIVE = (
    "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1/publish_heldout_predictions.py"
)
VALIDATOR_RELATIVE = "scripts/model_lab/pe_four_model_heldout_r3_prediction_seal_validator.py"

EXECUTION_AUTHORITY_RAW_SHA256 = "fda61ea7d041020dff30e62eb90730f681062d132f946a2ca840d226bc868cfe"
EXECUTION_AUTHORITY_SEMANTIC_SHA256 = (
    "f0d79e7435a78f26171a43e2c46a038c2fd33907011e674d51bac29b72822bd9"
)
GENERATION_PLAN_SEMANTIC_SHA256 = "2390b49ec02cc330345c107f78b512fc2ee182fe4eee329e41d171d688d984f0"
SURVIVOR_SEMANTIC_SHA256 = "034fae3d704811ed415f8fd009b8f929b2f47dafceac3eec6db0fe6429595e69"
FORMULA_SEMANTIC_SHA256 = "0f0a0fca901252d2e128a3ee4ab63bc9f20a7f76ead170171f4ec6af0472ce30"
SOURCE_MANIFEST_SEMANTIC_SHA256 = "00940a2bba079eeaccb8f62ab43f6985ed797fb0becfea90a876d7af5ca5ba8b"
SOURCE_RECORDS_SEMANTIC_SHA256 = "e8a0c47a272004688887f1d420ecf0bc81562f6319bfea531ccdbb0ca77e634b"
RUNTIME_SEMANTIC_SHA256 = "9255e67207f25a837425c7b6c95677060baa9a5d89da80e18b280f6d2f0c9ce6"
PROTOCOL_SEMANTIC_SHA256 = "880fd56c06312dff4745381690446df0fd14be45b32b4f7a540eef4cadfb2667"

EXPECTED_OUTPUT_LEAVES = {
    "AUDIT_SEAL.json",
    "CHECKSUMS.sha256",
    "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
    "PREDICTION_MANIFEST.json",
    "PREDICTIONS.csv",
    "SOURCE_MANIFEST.json",
}
_TOP_LEVEL_KEYS = {
    "access_contract",
    "artifact_bindings",
    "authority_semantic_sha256",
    "authorized_invocation_count",
    "candidate_tuning_allowed",
    "formal_publisher_argv_relative",
    "mutation_contract",
    "path_contract",
    "post_generation_resolution",
    "postchild_validator_argv_relative",
    "r2_terminal_prohibition",
    "retry_allowed",
    "run_id",
    "runtime_contract",
    "schema_version",
    "source_bindings",
    "status",
}


class R3PredictionLaunchError(RuntimeError):
    """The exact one-shot R3 prediction launch contract differs."""


def _compact(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _pretty(value: Any) -> bytes:
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


def _semantic(value: Any) -> str:
    return hashlib.sha256(_compact(value)).hexdigest()


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise R3PredictionLaunchError("one-shot launcher requires -I -B")
    if sys.pycache_prefix is None:
        raise R3PredictionLaunchError("one-shot launcher pycache prefix is absent")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    result.add_argument("--preuse-authority", required=True)
    result.add_argument("--preuse-authority-raw-sha256", required=True)
    return result


def _canonical_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3PredictionLaunchError(f"{label} JSON differs") from exc
    if type(value) is not dict or _pretty(value) != raw:
        raise R3PredictionLaunchError(f"{label} canonical bytes differ")
    return value


def _read_ref(relative: str, expected: Mapping[str, object]) -> bytes:
    if expected.get("relative_path") != relative:
        raise R3PredictionLaunchError(f"authority path differs: {relative}")
    path = (PROJECT_ROOT / relative).resolve(strict=True)
    if path != (PROJECT_ROOT / relative).resolve() or not path.is_file():
        raise R3PredictionLaunchError(f"authority file differs: {relative}")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or expected.get("raw_sha256") != _raw_sha256(raw)
        or expected.get("size_bytes") != len(raw)
    ):
        raise R3PredictionLaunchError(f"authority bytes drifted: {relative}")
    return raw


def _publisher_argv_relative() -> list[str]:
    return [
        ".venv_pe_model_lab_py310/Scripts/python.exe",
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={PUBLISHER_PYCACHE_RELATIVE}",
        PUBLISHER_RELATIVE,
        "--run-id",
        RUN_ID,
        "--execution-authority",
        EXECUTION_AUTHORITY_RELATIVE,
        "--execution-authority-raw-sha256",
        EXECUTION_AUTHORITY_RAW_SHA256,
        "--public-replay-root",
        PUBLIC_REPLAY_RELATIVE,
        "--worker-pycache-prefix",
        WORKER_PYCACHE_RELATIVE,
    ]


def _publisher_command() -> tuple[str, ...]:
    # Keep command construction lexical.  In particular, do not resolve/stat the
    # formal public replay path until after the durable invocation claim exists.
    return (
        str(PYTHON),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={PROJECT_ROOT / PUBLISHER_PYCACHE_RELATIVE}",
        str(PROJECT_ROOT / PUBLISHER_RELATIVE),
        "--run-id",
        RUN_ID,
        "--execution-authority",
        str(PROJECT_ROOT / EXECUTION_AUTHORITY_RELATIVE),
        "--execution-authority-raw-sha256",
        EXECUTION_AUTHORITY_RAW_SHA256,
        "--public-replay-root",
        str(PROJECT_ROOT / PUBLIC_REPLAY_RELATIVE),
        "--worker-pycache-prefix",
        str(PROJECT_ROOT / WORKER_PYCACHE_RELATIVE),
    )


def _postchild_validator_argv_relative() -> list[str]:
    return [
        ".venv_pe_model_lab_py310/Scripts/python.exe",
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={VALIDATOR_PYCACHE_RELATIVE}",
        VALIDATOR_RELATIVE,
        "--run-id",
        RUN_ID,
        "--execution-authority",
        EXECUTION_AUTHORITY_RELATIVE,
        "--execution-authority-raw-sha256",
        EXECUTION_AUTHORITY_RAW_SHA256,
        "--prediction-root",
        PREDICTION_ROOT_RELATIVE,
    ]


def _postchild_validator_command() -> tuple[str, ...]:
    return (
        str(PYTHON),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={PROJECT_ROOT / VALIDATOR_PYCACHE_RELATIVE}",
        str(PROJECT_ROOT / VALIDATOR_RELATIVE),
        "--run-id",
        RUN_ID,
        "--execution-authority",
        str(PROJECT_ROOT / EXECUTION_AUTHORITY_RELATIVE),
        "--execution-authority-raw-sha256",
        EXECUTION_AUTHORITY_RAW_SHA256,
        "--prediction-root",
        str(PROJECT_ROOT / PREDICTION_ROOT_RELATIVE),
    )


def _validate_absent_and_empty_paths(authority: Mapping[str, Any]) -> None:
    contract = authority.get("path_contract")
    expected = {
        "activation_output_root_relative_path": ACTIVATION_ROOT_RELATIVE,
        "certification_output_root_relative_path": CERTIFICATION_ROOT_RELATIVE,
        "invocation_claim_relative_path": CLAIM_RELATIVE,
        "launcher_pycache_relative_path": LAUNCHER_PYCACHE_RELATIVE,
        "numeric_work_root_relative_path": WORK_ROOT_RELATIVE,
        "prediction_output_root_relative_path": PREDICTION_ROOT_RELATIVE,
        "publisher_pycache_relative_path": PUBLISHER_PYCACHE_RELATIVE,
        "public_replay_root_relative_path": PUBLIC_REPLAY_RELATIVE,
        "worker_pycache_relative_path": WORKER_PYCACHE_RELATIVE,
        "validator_pycache_relative_path": VALIDATOR_PYCACHE_RELATIVE,
        "fresh_roots_required": True,
    }
    if contract != expected:
        raise R3PredictionLaunchError("prediction path contract differs")
    for relative in (
        CLAIM_RELATIVE,
        WORK_ROOT_RELATIVE,
        PREDICTION_ROOT_RELATIVE,
        ACTIVATION_ROOT_RELATIVE,
        CERTIFICATION_ROOT_RELATIVE,
    ):
        if (PROJECT_ROOT / relative).exists():
            raise R3PredictionLaunchError(f"fresh identity is already consumed: {relative}")
    actual_launcher_prefix = Path(sys.pycache_prefix).resolve(strict=True)
    expected_launcher_prefix = (PROJECT_ROOT / LAUNCHER_PYCACHE_RELATIVE).resolve(strict=True)
    if actual_launcher_prefix != expected_launcher_prefix:
        raise R3PredictionLaunchError("launcher pycache identity differs")
    for relative in (
        LAUNCHER_PYCACHE_RELATIVE,
        PUBLISHER_PYCACHE_RELATIVE,
        WORKER_PYCACHE_RELATIVE,
        VALIDATOR_PYCACHE_RELATIVE,
    ):
        path = (PROJECT_ROOT / relative).resolve(strict=True)
        if not path.is_dir() or any(path.iterdir()):
            raise R3PredictionLaunchError(f"pycache prefix is not fresh and empty: {relative}")


def _validate_artifacts(authority: Mapping[str, Any]) -> dict[str, Any]:
    artifacts = authority.get("artifact_bindings")
    if type(artifacts) is not dict or set(artifacts) != {
        "execution_authority",
        "generation_execution_receipt",
        "native_identity_adjudication_go",
        "original_post_generation_no_go",
        "protocol_lock",
        "r2_terminal_evidence",
        "survivor_freeze",
    }:
        raise R3PredictionLaunchError("artifact bindings differ")
    execution_record = artifacts.get("execution_authority")
    if type(execution_record) is not dict:
        raise R3PredictionLaunchError("execution authority binding differs")
    execution_raw = _read_ref(EXECUTION_AUTHORITY_RELATIVE, execution_record)
    execution = _canonical_object(execution_raw, label="execution authority")
    if (
        execution_record.get("semantic_sha256") != EXECUTION_AUTHORITY_SEMANTIC_SHA256
        or execution.get("execution_authority_semantic_sha256")
        != EXECUTION_AUTHORITY_SEMANTIC_SHA256
        or execution.get("generation_plan_semantic_sha256") != GENERATION_PLAN_SEMANTIC_SHA256
        or execution.get("qualification_survivor_freeze_semantic_sha256")
        != SURVIVOR_SEMANTIC_SHA256
        or execution.get("formula_lock_semantic_sha256") != FORMULA_SEMANTIC_SHA256
        or execution.get("source_manifest_semantic_sha256") != SOURCE_MANIFEST_SEMANTIC_SHA256
        or execution.get("source_records_semantic_sha256") != SOURCE_RECORDS_SEMANTIC_SHA256
        or execution.get("runtime_semantic_sha256") != RUNTIME_SEMANTIC_SHA256
        or execution.get("r2_protocol_binding_semantic_sha256") != PROTOCOL_SEMANTIC_SHA256
        or execution.get("truth_open_count") != 0
        or execution.get("heldout_content_open_count") != 0
        or execution.get("score_open_count") != 0
        or execution.get("retry_allowed") is not False
        or execution.get("candidate_tuning_allowed") is not False
    ):
        raise R3PredictionLaunchError("frozen execution authority differs")

    original_record = artifacts.get("original_post_generation_no_go")
    corrected_record = artifacts.get("native_identity_adjudication_go")
    survivor_record = artifacts.get("survivor_freeze")
    r2_record = artifacts.get("r2_terminal_evidence")
    generation_record = artifacts.get("generation_execution_receipt")
    protocol_record = artifacts.get("protocol_lock")
    if not all(
        type(record) is dict
        for record in (
            original_record,
            corrected_record,
            survivor_record,
            r2_record,
            generation_record,
            protocol_record,
        )
    ):
        raise R3PredictionLaunchError("preuse artifact record differs")

    original = _canonical_object(
        _read_ref(str(original_record["relative_path"]), original_record),
        label="original post-generation NO_GO",
    )
    if (
        original.get("status") != "NO_GO_R3_POST_GENERATION_AUDIT"
        or original.get("finding_counts") != {"P0": 1, "P1": 0, "P2": 0}
        or original.get("audit_semantic_sha256") != original_record.get("semantic_sha256")
    ):
        raise R3PredictionLaunchError("original post-generation NO_GO differs")
    corrected = _canonical_object(
        _read_ref(str(corrected_record["relative_path"]), corrected_record),
        label="native identity adjudication GO",
    )
    if (
        corrected.get("status") != "GO_R3_NATIVE_IDENTITY_ADJUDICATION_P0_0_P1_0_P2_0"
        or corrected.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or corrected.get("audit_semantic_sha256") != corrected_record.get("semantic_sha256")
        or corrected.get("audit_check_count") != 86_960
        or corrected.get("full_coverage", {}).get("task_count") != 50
        or corrected.get("full_coverage", {}).get("public_file_count") != 201
        or corrected.get("mutation_ledger", {}).get("prediction_invocation_count") != 0
        or corrected.get("protected_boundary", {}).get("truth_open_count") != 0
        or corrected.get("protected_boundary", {}).get("score_open_count") != 0
    ):
        raise R3PredictionLaunchError("native identity adjudication GO differs")
    survivor = _canonical_object(
        _read_ref(str(survivor_record["relative_path"]), survivor_record),
        label="survivor freeze",
    )
    if (
        survivor.get("survivor_freeze_semantic_sha256") != SURVIVOR_SEMANTIC_SHA256
        or survivor.get("candidate_tuning_allowed") is not False
        or survivor.get("truth_open_count") != 0
        or survivor.get("score_open_count") != 0
    ):
        raise R3PredictionLaunchError("survivor freeze differs")
    r2_terminal = _canonical_object(
        _read_ref(str(r2_record["relative_path"]), r2_record),
        label="R2 terminal evidence",
    )
    if (
        r2_terminal.get("status") != "TERMINAL_UNSEALED_PREDICTION_PREFIX_NO_ACTIVATION_OR_SCORING"
        or r2_terminal.get("retry_allowed") is not False
        or r2_terminal.get("terminal") is not True
    ):
        raise R3PredictionLaunchError("R2 terminal evidence differs")
    protocol = _canonical_object(
        _read_ref(str(protocol_record["relative_path"]), protocol_record),
        label="R3 protocol lock",
    )
    if (
        protocol_record.get("semantic_sha256") != PROTOCOL_SEMANTIC_SHA256
        or protocol.get("r2_protocol_binding_semantic_sha256") != PROTOCOL_SEMANTIC_SHA256
    ):
        raise R3PredictionLaunchError("R3 protocol lock differs")
    # Deliberately do not open the formal R3 public receipt before the claim.
    if generation_record != {
        "relative_path": (f"{PUBLIC_REPLAY_RELATIVE}/GENERATION_EXECUTION_RECEIPT.json"),
        "raw_sha256": ("2102ed765a33790f492f1e9a30e1c892504ff11f0ac2c581c9f80fcef1e1bbd0"),
        "size_bytes": 1_877_625,
        "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
    }:
        raise R3PredictionLaunchError("generation receipt precommit differs")
    return execution


def _validate_sources(authority: Mapping[str, Any], execution: Mapping[str, Any]) -> None:
    records = authority.get("source_bindings")
    if type(records) is not list or not records:
        raise R3PredictionLaunchError("prediction source bindings differ")
    source_manifest = execution.get("source_manifest")
    if type(source_manifest) is not dict:
        raise R3PredictionLaunchError("execution source manifest differs")
    frozen = {
        row["relative_path"]: row
        for field in (
            "adapter_source_records",
            "c2_c3_frozen_numeric_source_records",
            "c4_source_file_records",
            "c4_source_tree_records",
        )
        for row in source_manifest[field]
    }
    control_plane = {
        Path(__file__).resolve().relative_to(PROJECT_ROOT).as_posix(),
        VALIDATOR_RELATIVE,
        "tests/model_lab/test_pe_four_model_heldout_r3_prediction_one_shot_launcher.py",
    }
    seen: set[str] = set()
    for record in records:
        if type(record) is not dict or set(record) != {
            "relative_path",
            "raw_sha256",
            "size_bytes",
        }:
            raise R3PredictionLaunchError("source record schema differs")
        relative = str(record["relative_path"])
        if relative in seen:
            raise R3PredictionLaunchError("source record is duplicated")
        seen.add(relative)
        _read_ref(relative, record)
        if relative not in control_plane and frozen.get(relative) != record:
            raise R3PredictionLaunchError(f"source is outside frozen closure: {relative}")
    if not control_plane.issubset(seen) or PUBLISHER_RELATIVE not in seen:
        raise R3PredictionLaunchError("launcher/publisher source binding is incomplete")


def _validate_authority_contract(
    raw: bytes, *, expected_raw_sha256: str
) -> tuple[dict[str, Any], str]:
    if _raw_sha256(raw) != expected_raw_sha256:
        raise R3PredictionLaunchError("preuse authority raw SHA-256 differs")
    authority = _canonical_object(raw, label="R3 prediction preuse authority")
    if set(authority) != _TOP_LEVEL_KEYS:
        raise R3PredictionLaunchError("preuse authority field universe differs")
    stored = authority.get("authority_semantic_sha256")
    unsigned = dict(authority)
    unsigned.pop("authority_semantic_sha256")
    if type(stored) is not str or stored != _semantic(unsigned):
        raise R3PredictionLaunchError("preuse authority self-seal differs")
    if (
        authority.get("schema_version")
        != "expected_pe.four_model.r3_prediction_preuse_authority.v1"
        or authority.get("status") != "AUTHORIZED_EXACTLY_ONE_FRESH_R3_PREDICTION_PRETRUTH"
        or authority.get("run_id") != RUN_ID
        or authority.get("authorized_invocation_count") != 1
        or authority.get("retry_allowed") is not False
        or authority.get("candidate_tuning_allowed") is not False
        or authority.get("formal_publisher_argv_relative") != _publisher_argv_relative()
        or authority.get("postchild_validator_argv_relative")
        != _postchild_validator_argv_relative()
        or authority.get("access_contract")
        != {
            "activation_minted_before_prediction": False,
            "heldout_protected_open_count": 0,
            "prediction_before_truth": True,
            "score_open_count": 0,
            "truth_open_count": 0,
        }
    ):
        raise R3PredictionLaunchError("preuse authority invariant differs")
    return authority, stored


def _validate_preclaim(
    authority_path: Path, *, expected_raw_sha256: str
) -> tuple[dict[str, Any], str]:
    expected_path = (PROJECT_ROOT / AUTHORITY_RELATIVE).resolve(strict=True)
    if authority_path.resolve(strict=True) != expected_path:
        raise R3PredictionLaunchError("preuse authority path differs")
    raw = expected_path.read_bytes()
    authority, semantic = _validate_authority_contract(raw, expected_raw_sha256=expected_raw_sha256)
    _validate_absent_and_empty_paths(authority)
    execution = _validate_artifacts(authority)
    _validate_sources(authority, execution)
    runtime = authority.get("runtime_contract")
    if runtime != {
        "cpu_affinity": "CPU0-31",
        "gpu_enabled": False,
        "inner_blas_threads": 1,
        "logical_cpu_count": 32,
        "numeric_lane_workers": {"bce": 16, "c4": 16},
        "python_executable_raw_sha256": (
            "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
        ),
        "python_executable_relative_path": (".venv_pe_model_lab_py310/Scripts/python.exe"),
        "python_executable_size_bytes": 272_712,
        "python_version": "3.10.19",
        "total_single_thread_compute_workers": 32,
    }:
        raise R3PredictionLaunchError("prediction runtime contract differs")
    if _raw_sha256(PYTHON.read_bytes()) != runtime["python_executable_raw_sha256"]:
        raise R3PredictionLaunchError("pinned Python executable differs")
    r2 = authority.get("r2_terminal_prohibition")
    if r2 != {
        "r2_numeric_work_reuse_allowed": False,
        "r2_partial_prediction_reuse_allowed": False,
        "r2_prediction_root_relative_path": (
            "outputs/model_zoo_pe_four_model_heldout_predictions_r2_20260824T000005"
        ),
        "r2_run_id": "r2_20260824T000005",
        "r2_work_root_relative_path": (
            "build/pe_four_model_heldout_prediction_work_r2_20260824T000005"
        ),
    }:
        raise R3PredictionLaunchError("R2 terminal prohibition differs")
    resolution = authority.get("post_generation_resolution")
    if resolution != {
        "candidate_formula_or_order_changed": False,
        "corrected_identity_mapping_only": True,
        "original_no_go_preserved": True,
        "post_adjudication_invocation_allowed": True,
        "re_adjudication_allowed": False,
    }:
        raise R3PredictionLaunchError("post-generation resolution differs")
    mutation = authority.get("mutation_contract")
    if mutation != {
        "activation_or_certification_write_allowed": False,
        "allowed_create_new_relative_paths": [
            CLAIM_RELATIVE,
            WORK_ROOT_RELATIVE,
            PREDICTION_ROOT_RELATIVE,
        ],
        "cleanup_delete_or_partial_reuse_allowed": False,
        "formal_public_replay_mutation_allowed": False,
        "registry_or_reservation_write_allowed": False,
        "r2_artifact_mutation_or_reuse_allowed": False,
        "source_or_authority_mutation_allowed_after_claim": False,
        "truth_score_or_vault_mutation_allowed": False,
    }:
        raise R3PredictionLaunchError("prediction mutation contract differs")
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )

    require_process_resources()
    return authority, semantic


def _claim_payload(
    *, authority_raw_sha256: str, authority_semantic_sha256: str
) -> dict[str, object]:
    source_raw = _raw_sha256(Path(__file__).resolve(strict=True).read_bytes())
    core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_prediction_invocation_claim.v1",
        "status": "CLAIMED_EXACTLY_ONE_R3_PREDICTION_INVOCATION_PREPUBLIC_PRETRUTH",
        "run_id": RUN_ID,
        "invocation_ordinal": 1,
        "authorized_invocation_count": 1,
        "retry_allowed": False,
        "recovery_allowed": False,
        "cleanup_and_reuse_allowed": False,
        "preuse_authority_relative_path": AUTHORITY_RELATIVE,
        "preuse_authority_raw_sha256": authority_raw_sha256,
        "preuse_authority_semantic_sha256": authority_semantic_sha256,
        "launcher_relative_path": Path(__file__).resolve().relative_to(PROJECT_ROOT).as_posix(),
        "launcher_raw_sha256": source_raw,
        "formal_publisher_argv_absolute": list(_publisher_command()),
        "claim_created_before_formal_public_replay_read": True,
        "claim_created_before_numeric_work_or_prediction_root_mutation": True,
        "truth_open_count": 0,
        "heldout_protected_open_count": 0,
        "score_open_count": 0,
        "activation_minted": False,
    }
    return {**core, "claim_semantic_sha256": _semantic(core)}


class _HeldClaimCustody:
    """A create-new claim handle denying share-write/delete through validation."""

    def __init__(self, published: Any, raw: bytes) -> None:
        self._published = published
        self.raw = raw
        self.raw_sha256 = _raw_sha256(raw)
        self.path = published.path
        self.volume_serial_number = published.volume_serial_number
        self.file_id_128 = published.file_id_128
        self.raw_guid_path = published.raw_guid_path
        self.closed = False

    def assert_live(self) -> None:
        if self.closed or self._published._handle < 0:
            raise R3PredictionLaunchError("held prediction claim is closed")
        from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1 import (
            secure_publication as secure,
        )

        attributes, tag = secure._attributes(self._published._handle)
        if (
            bool(attributes & secure._FILE_ATTRIBUTE_DIRECTORY)
            or bool(attributes & secure._FILE_ATTRIBUTE_REPARSE_POINT)
            or tag != 0
            or secure._identity(self._published._handle)
            != (self.volume_serial_number, self.file_id_128)
            or secure._path_key(secure._final_path(self._published._handle, volume_guid=True))
            != secure._path_key(self.raw_guid_path)
            or secure._read_handle(self._published._handle) != self.raw
        ):
            raise R3PredictionLaunchError("held prediction claim identity/bytes changed")

    def close_and_revalidate(self) -> dict[str, object]:
        self.assert_live()
        self._published.close()
        self.closed = True
        os.chmod(self.path, stat.S_IREAD)
        from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
            stable_read,
        )

        raw, record = stable_read(self.path, relative_path=CLAIM_RELATIVE)
        observed = {
            "relative_path": record.relative_path,
            "raw_sha256": record.raw_sha256,
            "size_bytes": record.size_bytes,
            "volume_serial_number": int(record.volume_serial_number, 16),
            "file_id_128": record.file_id_128,
        }
        expected = {
            "relative_path": CLAIM_RELATIVE,
            "raw_sha256": self.raw_sha256,
            "size_bytes": len(self.raw),
            "volume_serial_number": int(self.volume_serial_number, 16),
            "file_id_128": self.file_id_128,
        }
        if raw != self.raw or observed != expected:
            raise R3PredictionLaunchError("closed prediction claim fresh validation differs")
        return observed


def _publish_claim(payload: Mapping[str, object]) -> _HeldClaimCustody:
    raw = _pretty(payload)
    build = None
    published = None
    try:
        from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
            HeldDirectory,
            SecurePublicationError,
            publish_leaf,
        )

        build = HeldDirectory.open_existing(PROJECT_ROOT / "build")
        if build.path != (PROJECT_ROOT / "build").resolve(strict=True):
            raise R3PredictionLaunchError("claim build parent identity differs")
        published = publish_leaf(
            parent=build,
            final_leaf=Path(CLAIM_RELATIVE).name,
            raw=raw,
        )
        published.release_write_custody()
        custody = _HeldClaimCustody(published, raw)
        build.close()
        build = None
        custody.assert_live()
        return custody
    except R3PredictionLaunchError:
        if published is not None:
            published.close()
        raise
    except SecurePublicationError as exc:
        if published is not None:
            published.close()
        raise R3PredictionLaunchError(
            "prediction invocation claim is consumed or failed closed"
        ) from exc
    finally:
        if build is not None:
            build.close()


def _validate_generation_receipt_postclaim(
    authority: Mapping[str, Any],
) -> str:
    """Open and raw-pin the formal public receipt only after claim durability."""

    artifacts = authority.get("artifact_bindings")
    if type(artifacts) is not dict:
        raise R3PredictionLaunchError("postclaim artifact bindings differ")
    record = artifacts.get("generation_execution_receipt")
    if type(record) is not dict:
        raise R3PredictionLaunchError("postclaim generation receipt binding differs")
    raw = _read_ref(
        f"{PUBLIC_REPLAY_RELATIVE}/GENERATION_EXECUTION_RECEIPT.json",
        record,
    )
    try:
        receipt = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3PredictionLaunchError("postclaim generation receipt JSON differs") from exc
    if (
        type(receipt) is not dict
        or receipt.get("status") != record.get("status")
        or receipt.get("run_id") != RUN_ID
        or receipt.get("execution_authority_semantic_sha256") != EXECUTION_AUTHORITY_SEMANTIC_SHA256
        or receipt.get("task_count") != 50
        or receipt.get("truth_open_count_by_controller") != 0
        or receipt.get("truth_open_count_by_public_process") != 0
        or receipt.get("score_open_count") != 0
    ):
        raise R3PredictionLaunchError("postclaim generation receipt contract differs")
    return _raw_sha256(raw)


def _revalidate_frozen_sources_postclaim(authority: Mapping[str, Any]) -> None:
    execution = _validate_artifacts(authority)
    _validate_sources(authority, execution)


def _validate_child_success(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    if completed.returncode != 0:
        detail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise R3PredictionLaunchError(
            "formal prediction child failed; claim is consumed and retry is forbidden: " + detail
        )
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3PredictionLaunchError(
            "formal prediction child output is ambiguous; retry is forbidden"
        ) from exc
    if (
        type(result) is not dict
        or result.get("status") != "SEALED_GO_FOUR_MODEL_HELDOUT_PREDICTIONS_PRETRUTH"
        or result.get("output_root_relative_path") != PREDICTION_ROOT_RELATIVE
        or result.get("truth_open_count") != 0
        or result.get("protected_open_count") != 0
        or result.get("score_open_count") != 0
        or result.get("generation_plan_semantic_sha256") != GENERATION_PLAN_SEMANTIC_SHA256
        or result.get("source_records_semantic_sha256") != SOURCE_RECORDS_SEMANTIC_SHA256
    ):
        raise R3PredictionLaunchError("formal prediction child result differs; retry is forbidden")
    return result


def _run_postchild_validator(
    publisher_result: Mapping[str, Any], *, environment: Mapping[str, str]
) -> dict[str, Any]:
    completed = subprocess.run(
        _postchild_validator_command(),
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=dict(environment),
    )
    if completed.returncode != 0:
        detail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise R3PredictionLaunchError(
            "fresh prediction-only seal validator failed; retry is forbidden: " + detail
        )
    try:
        value = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R3PredictionLaunchError(
            "fresh prediction-only seal validator output differs; retry is forbidden"
        ) from exc
    if (
        type(value) is not dict
        or value.get("status") != "PASS_FRESH_PROCESS_R3_PREDICTION_ONLY_SEAL_VALIDATION"
        or value.get("truth_open_count") != 0
        or value.get("heldout_protected_open_count") != 0
        or value.get("score_open_count") != 0
        or type(value.get("prediction_bundle")) is not dict
    ):
        raise R3PredictionLaunchError(
            "fresh prediction-only seal validator contract differs; retry is forbidden"
        )
    bundle = value["prediction_bundle"]
    expected_keys = {
        "prediction_ref",
        "prediction_freeze_receipt_ref",
        "prediction_audit_ref",
        "prediction_audit_seal_ref",
        "prediction_checksums_ref",
        "prediction_semantic_sha256",
        "common_identity_semantic_sha256",
    }
    if set(bundle) != expected_keys or any(
        publisher_result.get(key) != bundle[key] for key in expected_keys
    ):
        raise R3PredictionLaunchError(
            "fresh validator and publisher sealed references differ; retry is forbidden"
        )
    return bundle


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    authority, semantic = _validate_preclaim(
        Path(arguments.preuse_authority),
        expected_raw_sha256=arguments.preuse_authority_raw_sha256,
    )
    claim = _claim_payload(
        authority_raw_sha256=arguments.preuse_authority_raw_sha256,
        authority_semantic_sha256=semantic,
    )
    if arguments.validate_only:
        result = {
            "status": "PASS_R3_PREDICTION_PREUSE_VALIDATION_NO_PUBLIC_READ_NO_MUTATION",
            "preuse_authority_semantic_sha256": semantic,
            "planned_claim_raw_sha256": _raw_sha256(_pretty(claim)),
            "formal_public_replay_open_count": 0,
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
            "execute_invoked": False,
        }
        print(_compact(result).decode("ascii"))
        return 0

    custody = _publish_claim(claim)
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation_execution import (
        child_environment,
    )

    environment = child_environment()
    claim_ref: dict[str, object]
    try:
        custody.assert_live()
        _revalidate_frozen_sources_postclaim(authority)
        generation_receipt_raw_sha256 = _validate_generation_receipt_postclaim(authority)
        custody.assert_live()
        completed = subprocess.run(
            _publisher_command(),
            check=False,
            capture_output=True,
            cwd=PROJECT_ROOT,
            env=environment,
        )
        custody.assert_live()
        publisher_result = _validate_child_success(completed)
        _revalidate_frozen_sources_postclaim(authority)
        validator_bundle = _run_postchild_validator(
            publisher_result,
            environment=environment,
        )
        custody.assert_live()
    finally:
        claim_ref = custody.close_and_revalidate()
    result = {
        "status": "PASS_R3_PREDICTION_EXACT_ONCE_CHILD_SEALED_PRETRUTH",
        "claim_relative_path": CLAIM_RELATIVE,
        "claim_raw_sha256": custody.raw_sha256,
        "claim_ref": claim_ref,
        "generation_receipt_postclaim_raw_sha256": generation_receipt_raw_sha256,
        "preuse_authority_semantic_sha256": semantic,
        "publisher_result": publisher_result,
        "fresh_prediction_only_validator_bundle": validator_bundle,
        "truth_open_count": 0,
        "heldout_protected_open_count": 0,
        "score_open_count": 0,
        "retry_allowed": False,
    }
    print(_compact(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
