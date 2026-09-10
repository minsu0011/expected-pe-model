from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r9_qualification_execution_v1.authority import (
    DGPS,
    QUALIFICATION_SEEDS,
    MemoryQualificationAuthority,
    QualificationAuthorityError,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r9_"
    "qualification_execution_v1"
)
PREDECESSOR = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "qualification_generation"
)


def test_exact_202_grants_are_unique_signed_and_one_shot() -> None:
    authority = MemoryQualificationAuthority(independent_audit_seal_raw_sha256="1" * 64)
    binding = authority.public_binding()
    assert binding["signature_count"] == 1
    assert binding["private_key_persisted"] is False
    assert binding["grant_secret_persisted_count"] == 0
    assert authority.authority["activation_token_sha256"] == hashlib.sha256(
        authority.activation_token.encode("ascii")
    ).hexdigest()
    rows = authority.authority["grant_commitments"]
    assert len(rows) == len({row["secret_commitment_sha256"] for row in rows}) == 202
    for replay_pass in (1, 2):
        for seed in QUALIFICATION_SEEDS:
            for dgp in DGPS:
                authority.consume(
                    role="PROTECTED", replay_pass=replay_pass, seed=seed, dgp=dgp
                )
                authority.consume(
                    role="PUBLIC", replay_pass=replay_pass, seed=seed, dgp=dgp
                )
    authority.consume(role="PRIVATE_FINALIZER", replay_pass=0, seed=0, dgp="FINAL")
    authority.consume(role="PUBLIC_FINALIZER", replay_pass=0, seed=0, dgp="FINAL")
    receipt = authority.final_receipt()
    assert receipt["consumed_grant_count"] == 202
    assert receipt["activation_token_zeroized"] is True


def test_duplicate_or_unknown_grant_fails_closed() -> None:
    authority = MemoryQualificationAuthority(independent_audit_seal_raw_sha256="2" * 64)
    authority.consume(role="PROTECTED", replay_pass=1, seed=7573, dgp="A")
    with pytest.raises(QualificationAuthorityError, match="already consumed"):
        authority.consume(role="PROTECTED", replay_pass=1, seed=7573, dgp="A")
    with pytest.raises(QualificationAuthorityError, match="absent"):
        authority.consume(role="PUBLIC", replay_pass=1, seed=7603, dgp="A")


def test_predecessor_is_unchanged_and_still_denied() -> None:
    predecessor = (PREDECESSOR / "custodian.py").read_text(encoding="utf-8")
    successor = (PACKAGE / "custodian.py").read_text(encoding="utf-8")
    assert "raise R7QualificationGenerationError(LIVE_EXECUTION_SOURCE_REVISION_STATUS)" in predecessor
    assert "raise R7QualificationGenerationError(LIVE_EXECUTION_SOURCE_REVISION_STATUS)" not in successor
    assert "consume_grant" in successor
    assert '"one_time_grant_count": 202' in successor


def test_public_successor_has_no_live_deny_and_no_protected_import() -> None:
    public = (PACKAGE / "public_role.py").read_text(encoding="utf-8")
    replay = (PACKAGE / "replay.py").read_text(encoding="utf-8")
    controller = (PACKAGE / "controller.py").read_text(encoding="utf-8")
    assert "LIVE_EXECUTION_SOURCE_REVISION_STATUS" not in public
    assert "LIVE_EXECUTION_SOURCE_REVISION_STATUS" not in replay
    assert "LIVE_EXECUTION_SOURCE_REVISION_STATUS" not in controller
    imported = {
        node.module
        for node in ast.walk(ast.parse(public))
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any(module.endswith("protected_role") for module in imported)
    assert "true_fair_pe" not in public
    assert "heldout" not in public.casefold()


def test_role_worker_exposes_only_fixed_closed_commands() -> None:
    source = (
        PROJECT_ROOT
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r9_"
        "qualification_execution_v1/role_worker.py"
    ).read_text(encoding="utf-8")
    commands = {
        "role-protected-check",
        "role-public-check",
        "role-public-finalize-check",
        "role-protected-generate",
        "role-public-run",
        "role-public-finalize",
    }
    for command in commands:
        assert f'"{command}"' in source
    assert "heldout" not in source.casefold()
    assert '"CUDA_VISIBLE_DEVICES": "-1"' in source
    assert "sys.flags.isolated" in source
