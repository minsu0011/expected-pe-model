"""Score-free source/contract attacks for the isolated V2 R6 repair."""

from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6 import authority
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.artifacts import (
    canonical_json_bytes,
    seal_payload,
    sha256_file,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.contracts import (
    AUTHORIZED_WINDOWS_TOKEN,
    LEGACY_LOCK_RELATIVE,
    PRECOMMIT_FILENAMES,
    REQUIRED_NAMED_PROBES,
    R6_SOURCE_FILENAMES,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.design import (
    CANDIDATE_CONTRACT,
    CANDIDATE_CONTRACT_SHA256,
    EXPECTED_LIVE_REGISTRY_INVARIANT,
    HELDOUT_GATE,
    QUALIFICATION_GATE,
    expected_design_payload,
    frozen_registry_prestate,
    validate_design_semantics,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.executable import (
    executable_manifest_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.identity import (
    process_token_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.lineage import (
    R5_GO_AUDIT_SEMANTIC,
    R5_GO_SEAL_SEMANTIC,
    R5_TRANSACTION_RAW_SHA256,
    r5_post_go_supersession_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.path_guard import (
    R6PathError,
    require_clean_tree,
    require_lexically_exact_path,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.signature import (
    R6SignatureError,
    verify_detached_approval_signature,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.transaction import (
    _BOUND_BOOTSTRAP_CAPABILITY,
    _execute_authenticated_reservation,
    R6TransactionError,
    _grant_bound_bootstrap_capability,
    transaction_contract_payload,
    verify_live_registry_read_only,
)


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r6"
BOOTSTRAP = ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r6/"
    "trusted_bootstrap.py"
)
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="R6 is Windows-fixed")


def _design() -> dict[str, object]:
    return expected_design_payload(
        source_manifest_semantic_sha256="1" * 64,
        executable_manifest_semantic_sha256="2" * 64,
        authority_contract_semantic_sha256="3" * 64,
        smoke_binding_semantic_sha256="4" * 64,
        supersession_semantic_sha256="5" * 64,
        path_contract_semantic_sha256="6" * 64,
        transaction_contract_semantic_sha256="7" * 64,
        registry=frozen_registry_prestate(),
    )


def test_live_registry_exact_read_only_invariant() -> None:
    registry = ROOT / "outputs/v04_spent_seed_registry.json"
    before = registry.read_bytes()
    receipt = verify_live_registry_read_only(registry)
    assert {
        name: receipt[name] for name in EXPECTED_LIVE_REGISTRY_INVARIANT
    } == EXPECTED_LIVE_REGISTRY_INVARIANT
    assert receipt["fresh_seed_derivation_performed"] is False
    assert receipt["registry_mutated"] is False
    assert registry.read_bytes() == before


def _reseal(payload: dict[str, object]) -> dict[str, object]:
    candidate = copy.deepcopy(payload)
    candidate.pop("design_semantic_sha256")
    return seal_payload(candidate, "design_semantic_sha256")


def _valid_audit(context: dict[str, object]) -> dict[str, object]:
    return seal_payload(
        {
            "schema_version": authority.R6_AUDIT_SCHEMA,
            "audit_revision": "R6",
            "generated_at_utc": "2026-08-21T00:00:00+00:00",
            "status": authority.R6_AUDIT_STATUS,
            "verdict": authority.R6_AUDIT_VERDICT,
            "audit_nonce_hex": "a" * 64,
            "bindings": context,
            "access_state": copy.deepcopy(authority.FORBIDDEN_ACCESS_ZERO),
            "execution_state": copy.deepcopy(authority.EXECUTION_ZERO),
            "severity_counts": copy.deepcopy(authority.SEVERITY_ZERO),
            "checks": {name: "PASS" for name in REQUIRED_NAMED_PROBES},
            "findings": [],
            "authorization_boundary": copy.deepcopy(authority.AUDIT_AUTHORITY),
        },
        "audit_semantic_sha256",
    )


def _valid_approval(bindings: dict[str, object]) -> dict[str, object]:
    return seal_payload(
        {
            "schema_version": authority.R6_APPROVAL_SCHEMA,
            "status": authority.R6_APPROVAL_STATUS,
            "action": authority.R6_APPROVAL_ACTION,
            "decision": authority.R6_APPROVAL_DECISION,
            "created_at_utc": "2026-08-21T00:01:00+00:00",
            "expires_at_utc": "2026-08-21T01:01:00+00:00",
            "bindings": bindings,
            "reservation_scope": copy.deepcopy(authority.APPROVAL_SCOPE),
            "authority_boundary": copy.deepcopy(authority.APPROVAL_BOUNDARY),
        },
        "approval_semantic_sha256",
    )


def test_bootstrap_rejects_pyc_pyd_dll_and_extra_file(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "bound.py").write_text("x = 1\n", encoding="utf-8")
    require_clean_tree(root, expected_files={"bound.py"}, expected_directories=set())
    for name in ("evil.py", "evil.pyc", "evil.pyd", "evil.dll", "evil.zip"):
        extra = root / name
        extra.write_bytes(b"evil")
        with pytest.raises(R6PathError):
            require_clean_tree(
                root, expected_files={"bound.py"}, expected_directories=set()
            )
        extra.unlink()


def test_bootstrap_rejects_extra_directory_and_reparse(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "bound.py").write_text("x = 1\n", encoding="utf-8")
    extra = root / "extra"
    extra.mkdir()
    with pytest.raises(R6PathError):
        require_clean_tree(root, expected_files={"bound.py"}, expected_directories=set())


def test_bootstrap_binds_all_initializers_origins_hashes_loaders() -> None:
    manifest = executable_manifest_payload()
    modules = {record["module"] for record in manifest["stage_files"].values()}
    assert {"research", "research.model_zoo"}.issubset(modules)
    assert "research.model_zoo.observable_state_bce_dgp_tournament_v2_r6" in modules
    assert manifest["governed_loader_required"] == "__main__.BoundSourceLoader"
    assert set(path.name for path in PACKAGE.iterdir()) == set(R6_SOURCE_FILENAMES)


def test_bootstrap_isolated_flags_path_cwd_site_environment_exact() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    assert '"-I", "-S", "-B", "-E"' in source
    assert "class BoundSourceLoader" in source
    assert "class BoundSourceFinder" in source
    assert "PYTHONPATH" not in source
    assert "rglob" not in source
    assert "SourceFileLoader" not in source


def test_bootstrap_verified_bytes_import_attestation_executes_before_action() -> None:
    trusted = runpy.run_path(str(BOOTSTRAP))
    manifest = executable_manifest_payload()
    manifest_raw = canonical_json_bytes(manifest)
    with tempfile.TemporaryDirectory(prefix="r6_unit_source_only_") as temporary:
        stage = Path(temporary)
        trusted["_stage"](manifest, manifest_raw, stage)
        parent = os.environ
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "R6_BOOTSTRAP_COMMAND": "attest_import_only",
            "R6_BOOTSTRAP_PARENT_NONCE": "a" * 64,
            "R6_EXECUTABLE_MANIFEST_RAW_SHA256": __import__("hashlib")
            .sha256(manifest_raw)
            .hexdigest(),
            "R6_STAGE_ROOT": str(stage),
            "SYSTEMROOT": parent["SYSTEMROOT"],
            "TEMP": parent["TEMP"],
            "TMP": parent["TMP"],
            "WINDIR": parent["WINDIR"],
        }
        completed = subprocess.run(
            [
                str(trusted["PINNED_LAUNCHER_TEXT"]),
                "-I",
                "-S",
                "-B",
                "-E",
                "-c",
                str(trusted["CHILD_CODE"]),
            ],
            cwd=stage,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["pre_action_attestation_completed"] is True
    assert receipt["target_result"]["registry_mutated"] is False


def test_lexical_case_alias_rejected_before_resolve() -> None:
    exact = str(PACKAGE / "contracts.py")
    alias = exact[0].lower() + exact[1:]
    with pytest.raises(R6PathError):
        require_lexically_exact_path(alias, exact, require_directory=False)


@pytest.mark.parametrize(
    "alias",
    [
        r"C:\Users\minsu\Documents\EPS\..\EPS\file.txt",
        "C:/Users/minsu/file.txt",
        r"\\server\share\file.txt",
        r"\\?\C:\Users\minsu\file.txt",
        r"C:\Users\minsu\file.txt:stream",
        r"C:\Users\MINSU~1\file.txt",
        r"C:\Users\minsu\file. ",
    ],
)
def test_lexical_dotdot_forward_slash_UNC_device_ADS_8dot3_rejected(
    alias: str,
) -> None:
    with pytest.raises(R6PathError):
        require_lexically_exact_path(alias, alias, must_exist=False)


def test_component_symlink_junction_reparse_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "target"
    target.mkdir()
    link = root / "link"
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    with pytest.raises(R6PathError):
        require_clean_tree(root, expected_files=set(), expected_directories={"target"})


def test_R5_POST_GO_recovery_blocker_supersession_exact() -> None:
    payload = r5_post_go_supersession_payload()
    assert payload["R5_GO_audit"]["audit_semantic_sha256"] == R5_GO_AUDIT_SEMANTIC
    assert payload["R5_GO_audit"]["seal_semantic_sha256"] == R5_GO_SEAL_SEMANTIC
    assert payload["R5_GO_audit"]["reservation_authority_superseded"] is True
    assert (
        payload["R5_POST_GO_RECOVERY_BLOCKER"]["frozen_transaction_raw_sha256"]
        == R5_TRANSACTION_RAW_SHA256
    )
    assert payload["R5_POST_GO_RECOVERY_BLOCKER"]["severity"] == "P0"
    assert payload["fresh_seed_derivation_or_reservation_performed"] is False


@pytest.mark.parametrize(
    "attack",
    ("candidate", "qualification", "heldout", "seed", "authority"),
)
def test_candidate_gate_geometry_schema_and_zero_states_exact(attack: str) -> None:
    expected = _design()
    attacked = copy.deepcopy(expected)
    if attack == "candidate":
        attacked["candidate_contract"]["ids_in_fixed_order"][0] = "evil"
    elif attack == "qualification":
        attacked["qualification"]["gate"]["pooled_mae_relative_gain_min"] = -1.0
    elif attack == "heldout":
        attacked["heldout"]["gate"]["worst_dgp_mean_harm_max"] = 1.0
    elif attack == "seed":
        attacked["reservation_plan"]["qualification_seed_ids"] = [2, 3, 5, 7, 11]
    else:
        attacked["root_approval_created"] = True
    with pytest.raises(Exception):
        validate_design_semantics(_reseal(attacked), expected)
    assert expected["candidate_contract"] == CANDIDATE_CONTRACT
    assert expected["candidate_contract_sha256"] == CANDIDATE_CONTRACT_SHA256
    assert expected["qualification"]["gate"] == QUALIFICATION_GATE
    assert expected["heldout"]["gate"] == HELDOUT_GATE


def test_transaction_lock_is_process_lifetime_OS_lock() -> None:
    source = inspect.getsource(
        __import__(
            "research.model_zoo.observable_state_bce_dgp_tournament_v2_r6.transaction",
            fromlist=["transaction"],
        )
    )
    assert "LockFileEx" in source
    assert 'open("xb")' in source
    assert LEGACY_LOCK_RELATIVE.endswith("v04_spent_seed_registry.json.lock")
    with pytest.raises(R6TransactionError):
        _grant_bound_bootstrap_capability()
    with pytest.raises(R6TransactionError):
        _execute_authenticated_reservation(
            "RESERVE_OBSERVABLE_STATE_BCE_DGP_TOURNAMENT_V2_R6_TRANSACTIONALLY_ONCE",
            _BOUND_BOOTSTRAP_CAPABILITY,
        )


def test_transaction_lock_spans_verify_read_derive_append_reread_receipt() -> None:
    contract = transaction_contract_payload()
    production = inspect.getsource(_execute_authenticated_reservation)
    assert production.index("recovery = _journal_present") < production.index(
        "approval = ("
    )
    assert "verify_root_reservation_approval_bundle_for_recovery()" in production
    assert "_execute_locked_live_authority_flow" in production
    assert contract["single_lock_span"] == [
        "journal_presence_classification_NEW_or_RECOVERY",
        "immutable_precommit_audit_and_signed_approval_verify",
        "journal_semantic_and_authority_cross_binding_before_registry_state",
        "registry_verify_read",
        "NEW_only_seed_derivation_once",
        "entry_and_receipt_build",
        "PREPARED_journal",
        "registry_replace_and_reread",
        "runtime_root_create_after_append",
        "receipt_no_replace_publish_and_reread",
        "COMPLETED_journal",
    ]
    assert contract["registry_before_validation"].startswith("exact_canonical")
    assert contract["registry_after_validation"].startswith("exact_before_prefix")
    assert contract["hash_equal_recovery"].startswith("exact_planned_entry")
    assert set(contract["plan_cross_bindings"]) == {
        "transaction_id",
        "request_semantic_sha256",
        "request_payload_semantic_sha256",
        "transaction_context_semantic_sha256",
        "authorization_semantic_sha256",
        "authorization_verified_at_utc",
        "approval_created_and_expires_at_utc",
        "audit_nonce_and_raw_sha256",
        "approval_raw_semantic_and_signature_sha256",
        "precommit_checksums_raw_sha256",
        "registry_before_raw_sha256",
        "registry_after_raw_sha256",
        "entry_semantic_sha256",
        "receipt_raw_sha256",
        "receipt_semantic_sha256",
    }
    assert contract["registry_mutated"] is False


def test_named_test_results_and_raw_logs_bound() -> None:
    assert len(REQUIRED_NAMED_PROBES) == 28
    assert len(set(REQUIRED_NAMED_PROBES)) == 28
    assert "named_test_results_and_raw_logs_bound" in REQUIRED_NAMED_PROBES
    assert "QUALITY_EVIDENCE.json" in PRECOMMIT_FILENAMES


def test_approver_token_identity_authenticated() -> None:
    identity = process_token_identity()
    assert {key: identity[key] for key in AUTHORIZED_WINDOWS_TOKEN} == AUTHORIZED_WINDOWS_TOKEN
    assert len(identity["identity_sha256"]) == 64


def test_audit_before_approval_and_freshness_enforced() -> None:
    source = inspect.getsource(authority._verify_root_reservation_approval_bundle)
    assert "audit_generated_at" in source
    assert "st_ctime_ns" in source
    assert "APPROVAL_MAX_AGE_SECONDS" in source
    assert "verify_detached_approval_signature" in source


@pytest.mark.parametrize(
    "attack",
    (
        "minimal",
        "unbound",
        "extra",
        "missing",
        "wrong_hash",
        "P0",
        "state",
        "probe",
        "authority",
    ),
)
def test_audit_minimal_unbound_extra_missing_wrong_hash_resealed_attacks_reject(
    attack: str,
) -> None:
    context: dict[str, object] = {
        "authority_context_semantic_sha256": "1" * 64,
        "precommit_raw_sha256": {"DESIGN_LOCK.json": "2" * 64},
    }
    payload = _valid_audit(context)
    if attack == "minimal":
        payload = seal_payload(
            {
                "schema_version": authority.R6_AUDIT_SCHEMA,
                "verdict": authority.R6_AUDIT_VERDICT,
            },
            "audit_semantic_sha256",
        )
    else:
        payload.pop("audit_semantic_sha256")
        if attack == "unbound":
            payload["bindings"] = {}
        elif attack == "extra":
            payload["unexpected"] = True
        elif attack == "missing":
            payload.pop("findings")
        elif attack == "wrong_hash":
            payload["bindings"] = copy.deepcopy(payload["bindings"])
            payload["bindings"]["authority_context_semantic_sha256"] = "0" * 64
        elif attack == "P0":
            payload["severity_counts"] = {"P0": 1, "P1": 0, "P2": 0}
        elif attack == "state":
            payload["execution_state"] = copy.deepcopy(payload["execution_state"])
            payload["execution_state"]["fresh_seed_ids_derived"] = True
        elif attack == "probe":
            payload["checks"] = copy.deepcopy(payload["checks"])
            payload["checks"].pop(REQUIRED_NAMED_PROBES[0])
        else:
            payload["authorization_boundary"] = copy.deepcopy(
                payload["authorization_boundary"]
            )
            payload["authorization_boundary"]["qualification_launch_authorized"] = True
        payload = seal_payload(payload, "audit_semantic_sha256")
    with pytest.raises(authority.R6ContractError):
        authority._validate_audit_payload(payload, context)


@pytest.mark.parametrize(
    "attack",
    ("minimal", "unbound", "extra", "missing", "wrong_hash", "scope", "state"),
)
def test_approval_minimal_unbound_extra_missing_wrong_hash_resealed_attacks_reject(
    attack: str,
) -> None:
    bindings: dict[str, object] = {
        "audit_raw_sha256": "1" * 64,
        "authority_context_semantic_sha256": "2" * 64,
    }
    payload = _valid_approval(bindings)
    if attack == "minimal":
        payload = seal_payload(
            {
                "schema_version": authority.R6_APPROVAL_SCHEMA,
                "decision": authority.R6_APPROVAL_DECISION,
            },
            "approval_semantic_sha256",
        )
    else:
        payload.pop("approval_semantic_sha256")
        if attack == "unbound":
            payload["bindings"] = {}
        elif attack == "extra":
            payload["unexpected"] = True
        elif attack == "missing":
            payload.pop("reservation_scope")
        elif attack == "wrong_hash":
            payload["bindings"] = copy.deepcopy(payload["bindings"])
            payload["bindings"]["audit_raw_sha256"] = "0" * 64
        elif attack == "scope":
            payload["reservation_scope"] = copy.deepcopy(
                payload["reservation_scope"]
            )
            payload["reservation_scope"]["qualification_seed_count"] = 6
        else:
            payload["authority_boundary"] = copy.deepcopy(
                payload["authority_boundary"]
            )
            payload["authority_boundary"][
                "generation_prediction_truth_or_score_authorized"
            ] = True
        payload = seal_payload(payload, "approval_semantic_sha256")
    with pytest.raises(authority.R6ContractError):
        authority._validate_approval_payload(payload, bindings)


def test_minimal_unbound_extra_missing_wrong_hash_audit_approval_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError):
        authority.build_authority_context(expected_context={})
    with pytest.raises(TypeError):
        authority.verify_independent_audit_bundle(audit_root=tmp_path)
    content = tmp_path / "approval.json"
    signature = tmp_path / "approval.p7s"
    content.write_bytes(b"{}\n")
    signature.write_bytes(b"not-a-signature")
    with pytest.raises(R6SignatureError):
        verify_detached_approval_signature(content, signature)
    registry_before = sha256_file(ROOT / "outputs/v04_spent_seed_registry.json")
    with pytest.raises(R6TransactionError):
        _grant_bound_bootstrap_capability()
    assert sha256_file(ROOT / "outputs/v04_spent_seed_registry.json") == registry_before
