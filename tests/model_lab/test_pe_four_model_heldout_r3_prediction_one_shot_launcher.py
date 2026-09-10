from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT_ROOT / "scripts/model_lab/pe_four_model_heldout_r3_prediction_one_shot_launcher.py"
SPEC = importlib.util.spec_from_file_location("r3_prediction_one_shot_launcher", SOURCE)
assert SPEC is not None and SPEC.loader is not None
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def test_claim_is_self_sealed_and_binds_exact_frozen_child() -> None:
    payload = launcher._claim_payload(
        authority_raw_sha256="a" * 64,
        authority_semantic_sha256="b" * 64,
    )
    stored = payload["claim_semantic_sha256"]
    unsigned = dict(payload)
    unsigned.pop("claim_semantic_sha256")
    assert stored == launcher._semantic(unsigned)
    assert payload["invocation_ordinal"] == 1
    assert payload["authorized_invocation_count"] == 1
    assert payload["retry_allowed"] is False
    assert payload["recovery_allowed"] is False
    assert payload["formal_publisher_argv_absolute"] == list(launcher._publisher_command())
    assert "truth" not in "\n".join(payload["formal_publisher_argv_absolute"]).casefold()
    assert "vault" not in "\n".join(payload["formal_publisher_argv_absolute"]).casefold()


def test_preuse_authority_self_seal_and_raw_pin_fail_closed() -> None:
    authority = {key: None for key in launcher._TOP_LEVEL_KEYS}
    authority.update(
        {
            "schema_version": "expected_pe.four_model.r3_prediction_preuse_authority.v1",
            "status": "AUTHORIZED_EXACTLY_ONE_FRESH_R3_PREDICTION_PRETRUTH",
            "run_id": launcher.RUN_ID,
            "authorized_invocation_count": 1,
            "retry_allowed": False,
            "candidate_tuning_allowed": False,
            "formal_publisher_argv_relative": launcher._publisher_argv_relative(),
            "postchild_validator_argv_relative": (launcher._postchild_validator_argv_relative()),
            "access_contract": {
                "activation_minted_before_prediction": False,
                "heldout_protected_open_count": 0,
                "prediction_before_truth": True,
                "score_open_count": 0,
                "truth_open_count": 0,
            },
        }
    )
    unsigned = dict(authority)
    unsigned.pop("authority_semantic_sha256")
    authority["authority_semantic_sha256"] = launcher._semantic(unsigned)
    raw = launcher._pretty(authority)
    parsed, semantic = launcher._validate_authority_contract(
        raw, expected_raw_sha256=launcher._raw_sha256(raw)
    )
    assert parsed == authority
    assert semantic == authority["authority_semantic_sha256"]
    with pytest.raises(launcher.R3PredictionLaunchError, match="raw SHA-256"):
        launcher._validate_authority_contract(raw, expected_raw_sha256="0" * 64)
    tampered = json.loads(raw)
    tampered["retry_allowed"] = True
    tampered_raw = launcher._pretty(tampered)
    with pytest.raises(launcher.R3PredictionLaunchError, match="self-seal"):
        launcher._validate_authority_contract(
            tampered_raw,
            expected_raw_sha256=launcher._raw_sha256(tampered_raw),
        )


def test_create_new_claim_is_durable_and_collision_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = tmp_path / "build"
    build.mkdir()
    claim = build / "claim.json"
    monkeypatch.setattr(launcher, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(launcher, "CLAIM_RELATIVE", "build/claim.json")
    payload = {
        "claim_semantic_sha256": "x",
        "schema_version": "synthetic",
    }
    custody = launcher._publish_claim(payload)
    try:
        custody.assert_live()
        assert claim.read_bytes() == custody.raw
        assert custody.raw_sha256 == launcher._raw_sha256(custody.raw)
        with pytest.raises(OSError):
            claim.open("wb")
        with pytest.raises(OSError):
            claim.unlink()
        with pytest.raises(launcher.R3PredictionLaunchError, match="consumed or failed closed"):
            launcher._publish_claim(payload)
        observed = custody.close_and_revalidate()
        assert observed["raw_sha256"] == custody.raw_sha256
        assert observed["file_id_128"] == custody.file_id_128
    finally:
        if not custody.closed:
            custody._published.close()
        os.chmod(claim, stat.S_IWRITE)
        claim.unlink()


def test_frozen_relative_argv_has_no_r2_reuse_or_protected_namespace() -> None:
    argv = launcher._publisher_argv_relative()
    joined = "\n".join(argv).casefold()
    assert launcher.RUN_ID in argv
    assert "r2_20260824t000005" not in joined
    assert "vault" not in joined
    assert "truth" not in joined
    assert "latent" not in joined
    assert argv.count(launcher.EXECUTION_AUTHORITY_RAW_SHA256) == 1


def test_absolute_command_construction_is_lexical_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launcher, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(launcher, "PUBLIC_REPLAY_RELATIVE", "missing/public-replay")
    command = launcher._publisher_command()
    assert str(tmp_path / "missing/public-replay") in command
    assert not (tmp_path / "missing/public-replay").exists()


def test_postclaim_generation_receipt_is_live_raw_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative = "public/GENERATION_EXECUTION_RECEIPT.json"
    path = tmp_path / relative
    path.parent.mkdir()
    payload = {
        "execution_authority_semantic_sha256": (launcher.EXECUTION_AUTHORITY_SEMANTIC_SHA256),
        "run_id": launcher.RUN_ID,
        "score_open_count": 0,
        "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
        "task_count": 50,
        "truth_open_count_by_controller": 0,
        "truth_open_count_by_public_process": 0,
    }
    raw = launcher._compact(payload)
    path.write_bytes(raw)
    record = {
        "raw_sha256": launcher._raw_sha256(raw),
        "relative_path": relative,
        "size_bytes": len(raw),
        "status": payload["status"],
    }
    authority = {"artifact_bindings": {"generation_execution_receipt": record}}
    monkeypatch.setattr(launcher, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(launcher, "PUBLIC_REPLAY_RELATIVE", "public")
    assert launcher._validate_generation_receipt_postclaim(authority) == record["raw_sha256"]
    path.write_bytes(raw + b" ")
    with pytest.raises(launcher.R3PredictionLaunchError, match="bytes drifted"):
        launcher._validate_generation_receipt_postclaim(authority)


def test_fresh_postchild_validator_is_one_process_and_ref_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = {
        "relative_path": "outputs/x",
        "raw_sha256": "a" * 64,
        "size_bytes": 1,
        "volume_serial_number": 1,
        "file_id_128": "0" * 32,
    }
    bundle = {
        "prediction_ref": reference,
        "prediction_freeze_receipt_ref": {**reference, "relative_path": "outputs/r"},
        "prediction_audit_ref": {**reference, "relative_path": "outputs/a"},
        "prediction_audit_seal_ref": {**reference, "relative_path": "outputs/s"},
        "prediction_checksums_ref": {**reference, "relative_path": "outputs/c"},
        "prediction_semantic_sha256": "b" * 64,
        "common_identity_semantic_sha256": "c" * 64,
    }
    stdout = launcher._compact(
        {
            "status": "PASS_FRESH_PROCESS_R3_PREDICTION_ONLY_SEAL_VALIDATION",
            "prediction_bundle": bundle,
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
        }
    )
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    assert launcher._run_postchild_validator(bundle, environment={}) == bundle
    assert calls == [launcher._postchild_validator_command()]
    with pytest.raises(launcher.R3PredictionLaunchError, match="sealed references differ"):
        launcher._run_postchild_validator(
            {**bundle, "prediction_semantic_sha256": "d" * 64},
            environment={},
        )
    assert len(calls) == 2
