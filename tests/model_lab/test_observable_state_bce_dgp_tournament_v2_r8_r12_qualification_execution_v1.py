from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
    canonical_csv_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
    PUBLIC_SOURCE_NAMES,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r12_qualification_execution_v1.authority import (
    DGPS,
    QUALIFICATION_SEEDS,
    MemoryQualificationAuthority,
    QualificationAuthorityError,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r12_qualification_execution_v1.protected_role import (
    _logical_frame_sha256 as protected_pre_serialization_digest,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r12_qualification_execution_v1.protected_role import (
    _public_round_trip_logical_sha256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r12_qualification_execution_v1.public_role import (
    _logical_frame_sha256 as public_reconstructed_digest,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r12_qualification_execution_v1.replay import (
    read_csv_round_trip,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r12_"
    "qualification_execution_v1"
)
PREDECESSOR = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "qualification_generation"
)
TERMINAL_R8_R10 = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r9_"
    "qualification_execution_v1"
)
TERMINAL_R8_R11 = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r11_"
    "qualification_execution_v1"
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


def test_canonical_public_digest_is_round_trip_stable_on_spent_surface() -> None:
    spent_seed = 2026082007
    assert spent_seed not in QUALIFICATION_SEEDS
    generated = generate_dgp("A", master_seed=spent_seed)
    old_contract_mismatches: list[str] = []
    for name in PUBLIC_SOURCE_NAMES:
        original = generated.public[name]
        reconstructed = read_csv_round_trip(canonical_csv_bytes(original))
        stable = _public_round_trip_logical_sha256(original)
        public = public_reconstructed_digest(reconstructed)
        assert stable == public
        if protected_pre_serialization_digest(original) != public:
            old_contract_mismatches.append(name)
    assert old_contract_mismatches == ["price", "benchmark", "eps_events"]


def test_terminal_r8_r10_source_and_failure_evidence_remain_unchanged() -> None:
    known = {
        TERMINAL_R8_R10 / "authority.py": (
            "0a34faa77e266bf24464600d1abe84bf896fc43128cb6b0b91abd841701b858d"
        ),
        TERMINAL_R8_R10 / "public_role.py": (
            "1228ac6929441f8081c63295aa95ff5361afe8a5deffdec6d20906726125cd7e"
        ),
        PROJECT_ROOT
        / "outputs/model_zoo_r8_r10_qualification_execution_v1_actual_once_20260823"
        / "TERMINAL_FAILURE.json": (
            "2a08f84451f5286d9bd44ed1ae4c047aa57d36e44027a62554c08b0d5653b526"
        ),
    }
    for path, expected in known.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_terminal_r8_r11_source_and_failure_evidence_remain_unchanged() -> None:
    known = {
        TERMINAL_R8_R11 / "authority.py": (
            "ba12d3f27b2cd4b01a5ef0f5f857ebe62bd39ecfb6f3a3a7c25cdb9c58807e6b"
        ),
        TERMINAL_R8_R11 / "replay.py": (
            "119065f4b61b14930c71097ff2cd7280846fb2fa2dd851e19d2933c91d5f015d"
        ),
        PROJECT_ROOT
        / "outputs/model_zoo_r8_r11_qualification_execution_v1_actual_once_20260823"
        / "TERMINAL_FAILURE.json": (
            "ddc0887b6fb6d0b535a5375545e64ee51f496ceb558d7d054b9666042a0068a3"
        ),
    }
    for path, expected in known.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


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
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r12_"
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
    assert "r8_r12_qualification_execution_v1.protected_role" in source
    assert "r7_qualification_generation.protected_role" not in source


def test_r8_r12_uses_new_one_shot_paths_and_explicit_digest_contract() -> None:
    custodian = (PACKAGE / "custodian.py").read_text(encoding="utf-8")
    protected = (PACKAGE / "protected_role.py").read_text(encoding="utf-8")
    public = (PACKAGE / "public_role.py").read_text(encoding="utf-8")
    runner = (
        PROJECT_ROOT
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r12_"
        "qualification_execution_v1/run_qualification_once.py"
    ).read_text(encoding="utf-8")
    assert "r8_r12_qualification_activation_20260823" in custodian
    assert "qualification_activation_20260822" not in custodian
    assert 'PUBLIC_RUN_ID = "20260824T000003"' in runner
    assert "20260824T000001" not in runner
    assert "PUBLIC_LOGICAL_CONTRACT" in protected
    assert "PUBLIC_LOGICAL_CONTRACT" in public
    assert "ThreadPoolExecutor" in custodian
    assert "OUTER_TASK_WORKERS = 16" in custodian


def test_r8_r12_binds_real_replay_authority_and_keeps_venv_dependencies() -> None:
    design = PROJECT_ROOT / (
        "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json"
    )
    assert hashlib.sha256(design.read_bytes()).hexdigest() == (
        "cae42b76858f72e0ad0690ccc49a761421b8c17665028a6eb8a498b6cac2f295"
    )
    worker = (
        PROJECT_ROOT
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r12_"
        "qualification_execution_v1/role_worker.py"
    ).read_text(encoding="utf-8")
    replay = (PACKAGE / "replay.py").read_text(encoding="utf-8")
    assert "V3_DESIGN_LOCK_RAW_SHA256" in worker
    assert "V3_REPLAY_INVENTORY_COMBINED_SHA256" in worker
    assert "_comparator_python_command" in replay
    assert '"-I"' in replay and '"-B"' in replay
    assert "sealed_grandchild_environment" not in replay
    assert "exact_python_command" not in replay
