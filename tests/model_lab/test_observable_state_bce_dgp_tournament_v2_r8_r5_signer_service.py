from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_signer_service import (
    custody_service as service,
)


TOKEN = "0123456789abcdef" * 4
FIXED_NOW = datetime(2026, 8, 21, 13, 0, 0, tzinfo=timezone.utc)


def _write_json(path: Path, payload: object) -> bytes:
    raw = service.canonical_json_bytes(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _write_checksums(root: Path) -> bytes:
    lines = []
    for path in sorted(root.iterdir(), key=lambda value: value.name):
        if path.name != "CHECKSUMS.sha256":
            lines.append(f"{service.sha256_bytes(path.read_bytes())}  {path.name}\n")
    raw = "".join(lines).encode("ascii")
    (root / "CHECKSUMS.sha256").write_bytes(raw)
    return raw


def _seal_records(root: Path, names: tuple[str, ...]) -> list[dict[str, object]]:
    result = []
    for name in names:
        raw = (root / name).read_bytes()
        result.append(
            {
                "raw_sha256": service.sha256_bytes(raw),
                "relative_path": name,
                "size_bytes": len(raw),
            }
        )
    return result


@dataclass
class Fixture:
    core: service.R5SignerCore
    seed: bytearray
    policy: service.ArtifactPolicy
    binding: dict[str, object]
    claim: dict[str, object]
    design_root: Path
    audit_root: Path
    anchor_path: Path

    def begin(self) -> dict[str, object]:
        raw = service.build_begin_request("1" * 64)
        return dict(self.core.begin_sign(raw))

    def sign_raw(self, challenge: dict[str, object]) -> bytes:
        return service.build_sign_request(
            challenge=challenge,
            authority_claim=self.claim,
            activation_token=TOKEN,
        )


def _make_fixture(tmp_path: Path) -> Fixture:
    policy = service.ArtifactPolicy(
        project_root=tmp_path,
        design_root_relative="outputs/design",
        audit_root_relative="outputs/audit",
        anchor_relative="outputs/anchor.json",
        readiness_relative="outputs/readiness/READINESS.json",
        production=False,
    )
    seed = bytearray(range(32))
    core = service.R5SignerCore(
        seed=seed,
        policy=policy,
        clock=lambda: FIXED_NOW,
        service_source_raw_sha256="a" * 64,
    )
    readiness_raw = _write_json(
        tmp_path / policy.readiness_relative,
        {"fixture_public_key_hex": core.public_key_hex, "fixture_only": True},
    )
    readiness_hash = service.sha256_bytes(readiness_raw)
    core.bind_readiness_hash(readiness_hash)
    binding = {
        "key_id": core.key_id,
        "public_key_hex": core.public_key_hex,
        "readiness_raw_sha256": readiness_hash,
        "readiness_root_relative": "outputs/readiness",
        "service_source_raw_sha256": "a" * 64,
    }

    design_root = tmp_path / policy.design_root_relative
    design_root.mkdir(parents=True)
    source_raw = _write_json(design_root / "SOURCE_LOCK.json", {"fixture": "source"})
    runtime_raw = _write_json(design_root / "RUNTIME_TCB.json", {"fixture": "runtime"})
    archive_raw = b"fixture-source-archive"
    (design_root / "SOURCE_ARCHIVE.zip").write_bytes(archive_raw)
    _write_json(
        design_root / "AUTHORITY_STATE.json",
        {
            "activation_authority_file_present": False,
            "heldout_generation_authorized": False,
            "model_fit_prediction_evaluation_score_authorized": False,
            "private_key_received_or_persisted": False,
            "production_promotion_authorized": False,
            "qualification_generation_authorized": False,
            "r5_signer_service_binding": binding,
            "registry_mutation_authorized": False,
            "schema_version": "expected_pe.r8.r5.qualification.authority_state.v1",
            "status": "FROZEN_SCORE_FREE_AWAITING_INDEPENDENT_AUTHORITY",
        },
    )
    _write_json(
        design_root / "DESIGN_LOCK.json",
        {
            "design_root_relative": policy.design_root_relative,
            "dgp_ids": list(service.DGPS),
            "heldout_access_count": 0,
            "heldout_seed_ids": list(service.HELDOUT_SEEDS),
            "model_fit_prediction_evaluation_score_count": 0,
            "payload_generation_count": 0,
            "qualification_seed_ids": list(service.QUALIFICATION_SEEDS),
            "r5_signer_service_binding": binding,
            "registry_mutation_count": 0,
            "revision": "R8_R5",
            "runtime_tcb_raw_sha256": service.sha256_bytes(runtime_raw),
            "schema_version": "expected_pe.r8.r5.qualification.design_lock.v1",
            "source_archive_raw_sha256": service.sha256_bytes(archive_raw),
            "source_lock_raw_sha256": service.sha256_bytes(source_raw),
            "status": "FROZEN_SCORE_FREE_PRE_GENERATION",
            "truth_vault_latent_open_count": 0,
        },
    )
    design_checksums = _write_checksums(design_root)
    design_checksums_hash = service.sha256_bytes(design_checksums)

    anchor_path = tmp_path / policy.anchor_relative
    anchor_raw = _write_json(
        anchor_path,
        {
            "design_checksums_raw_sha256": design_checksums_hash,
            "design_root_relative": policy.design_root_relative,
            "r5_signer_service_binding": binding,
            "runtime_tcb_raw_sha256": service.sha256_bytes(runtime_raw),
            "schema_version": "expected_pe.r8.r5.external_launcher_anchor.v1",
            "source_archive_raw_sha256": service.sha256_bytes(archive_raw),
            "source_lock_raw_sha256": service.sha256_bytes(source_raw),
            "status": "FROZEN_EXTERNAL_PIN_REPORT_HASH_OUT_OF_BAND",
        },
    )

    audit_root = tmp_path / policy.audit_root_relative
    audit_root.mkdir(parents=True)
    registry = {"entry_count": 10, "raw_sha256": service.REGISTRY_RAW_SHA256}
    zero_raw = _write_json(
        audit_root / "ZERO_ACCESS_RECEIPT.json",
        {
            **{key: 0 for key in service.ZERO_ACCESS_COUNT_KEYS},
            "generation_roots_after": [],
            "generation_roots_before": [],
            "registry_after": registry,
            "registry_before": registry,
            "schema_version": "expected_pe.r8.r5.independent_zero_access_receipt.v1",
            "status": "PASS_ZERO_ACCESS_AND_ZERO_MUTATION",
        },
    )
    audit_raw = _write_json(
        audit_root / "AUDIT.json",
        {
            "audit_root_relative": policy.audit_root_relative,
            "capability_issued": False,
            "design_checksums_raw_sha256": design_checksums_hash,
            "design_root_relative": policy.design_root_relative,
            "dgp_ids": list(service.DGPS),
            "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
            "generated_at_utc": service._utc_text(FIXED_NOW),
            "heldout_generation_authorized": False,
            "heldout_seed_ids": list(service.HELDOUT_SEEDS),
            "model_fit_prediction_score_evaluation_authorized": False,
            "production_promotion_authorized": False,
            "qualification_generation_authorized": True,
            "qualification_seed_ids": list(service.QUALIFICATION_SEEDS),
            "r5_signer_service_binding": binding,
            "registry_mutation_authorized": False,
            "registry_raw_sha256": service.REGISTRY_RAW_SHA256,
            "runtime_tcb_raw_sha256": service.sha256_bytes(runtime_raw),
            "schema_version": (
                "expected_pe.r8.r5.qualification.independent_pre_generation_audit.v1"
            ),
            "source_lock_raw_sha256": service.sha256_bytes(source_raw),
            "status": "SEALED_INDEPENDENT_GO",
            "verdict": "GO",
            "zero_access_receipt_raw_sha256": service.sha256_bytes(zero_raw),
        },
    )
    seal_raw = _write_json(
        audit_root / "SEAL.json",
        {
            "audit_json_raw_sha256": service.sha256_bytes(audit_raw),
            "design_checksums_raw_sha256": design_checksums_hash,
            "file_records": _seal_records(
                audit_root, ("AUDIT.json", "ZERO_ACCESS_RECEIPT.json")
            ),
            "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
            "heldout_generation_authorized": False,
            "qualification_generation_authorized": True,
            "schema_version": "expected_pe.r8.r5.qualification.independent_audit_seal.v1",
            "status": "SEALED_INDEPENDENT_GO_ZERO_FINDINGS",
        },
    )
    _write_checksums(audit_root)

    claim: dict[str, object] = {
        "action": "ACTIVATE_ONCE",
        "activation_token_sha256": service.sha256_bytes(TOKEN.encode("ascii")),
        "audit_json_raw_sha256": service.sha256_bytes(audit_raw),
        "audit_seal_raw_sha256": service.sha256_bytes(seal_raw),
        "authority_domain": service.AUTHORITY_DOMAIN_TEXT,
        "custody_signer_key_id": core.key_id,
        "design_checksums_raw_sha256": design_checksums_hash,
        "dgp_ids": list(service.DGPS),
        "external_anchor_raw_sha256": service.sha256_bytes(anchor_raw),
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "heldout_seed_ids": list(service.HELDOUT_SEEDS),
        "permissions": {
            "heldout_generation": False,
            "model_fit_prediction_evaluation_score": False,
            "production_promotion": False,
            "qualification_generation": True,
            "registry_mutation": False,
        },
        "qualification_seed_ids": list(service.QUALIFICATION_SEEDS),
        "registry_raw_sha256": service.REGISTRY_RAW_SHA256,
        "runtime_tcb_raw_sha256": service.sha256_bytes(runtime_raw),
        "schema_version": service.CLAIM_SCHEMA,
        "signer_readiness_raw_sha256": readiness_hash,
        "source_archive_raw_sha256": service.sha256_bytes(archive_raw),
        "source_lock_raw_sha256": service.sha256_bytes(source_raw),
        "stage": "QUALIFICATION",
    }
    return Fixture(
        core=core,
        seed=seed,
        policy=policy,
        binding=binding,
        claim=claim,
        design_root=design_root,
        audit_root=audit_root,
        anchor_path=anchor_path,
    )


def _refresh_audit(fixture: Fixture) -> None:
    audit_raw = (fixture.audit_root / "AUDIT.json").read_bytes()
    seal = json.loads((fixture.audit_root / "SEAL.json").read_bytes())
    seal["audit_json_raw_sha256"] = service.sha256_bytes(audit_raw)
    seal["file_records"] = _seal_records(
        fixture.audit_root, ("AUDIT.json", "ZERO_ACCESS_RECEIPT.json")
    )
    seal_raw = _write_json(fixture.audit_root / "SEAL.json", seal)
    _write_checksums(fixture.audit_root)
    fixture.claim["audit_json_raw_sha256"] = service.sha256_bytes(audit_raw)
    fixture.claim["audit_seal_raw_sha256"] = service.sha256_bytes(seal_raw)


def test_fixture_ed25519_public_key_pop_and_authority_signature(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    receipt = fixture.core.readiness_receipt(process_id=1234)
    assert service.verify_ed25519(
        bytes.fromhex(fixture.core.public_key_hex),
        service.POP_CHALLENGE,
        bytes.fromhex(receipt["pop_signature_ed25519_hex"]),
    )
    challenge = fixture.begin()
    result = fixture.core.complete_sign(fixture.sign_raw(challenge))
    authority = dict(result["authority"])
    signature = bytes.fromhex(authority.pop("signature_ed25519_hex"))
    assert service.verify_ed25519(
        bytes.fromhex(fixture.core.public_key_hex),
        service.AUTHORITY_DOMAIN + service.canonical_json_bytes(authority),
        signature,
    )
    assert result["signing_count"] == 1
    assert fixture.seed == bytearray(32)


def test_status_is_read_only_and_zero_count(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    first = fixture.core.status()
    second = fixture.core.status()
    assert first == second
    assert first["sign_request_count"] == first["signing_count"] == 0


def test_authority_time_is_internal_and_request_time_keys_are_absent(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    assert "issued_at_utc" not in fixture.claim and "expires_at_utc" not in fixture.claim
    result = fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))
    authority = result["authority"]
    assert authority["issued_at_utc"] == service._utc_text(FIXED_NOW)
    assert "run_id" not in authority and "output_path" not in authority


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("authority_domain", "EXPECTED_PE_FIXTURE_AUTHORITY_V1"),
        ("custody_signer_key_id", "f" * 64),
        ("qualification_seed_ids", [7573, 7577, 7583, 7589, 7603]),
        ("heldout_seed_ids", [7603, 7607, 7621, 7639]),
        ("dgp_ids", list("ABCDEFGHI")),
        ("finding_counts", {"P0": 0, "P1": 1, "P2": 0}),
        ("registry_raw_sha256", "f" * 64),
        ("signer_readiness_raw_sha256", "f" * 64),
        ("stage", "HELDOUT"),
    ],
)
def test_exact_claim_policy_rejects_substitutes(
    tmp_path: Path, key: str, value: object
) -> None:
    fixture = _make_fixture(tmp_path)
    fixture.claim[key] = value
    with pytest.raises(service.CustodyError):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))
    assert fixture.seed == bytearray(32)


@pytest.mark.parametrize(
    "extra_key",
    ["run_id", "output_path", "audit_root_relative", "public_key_hex", "now", "issued_at_utc"],
)
def test_paths_key_time_and_canonical_schema_aliases_are_rejected(
    tmp_path: Path, extra_key: str
) -> None:
    fixture = _make_fixture(tmp_path)
    fixture.claim[extra_key] = "caller-substitute"
    with pytest.raises(service.CustodyError, match="SCHEMA"):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


@pytest.mark.parametrize(
    "permission",
    [
        "heldout_generation",
        "model_fit_prediction_evaluation_score",
        "production_promotion",
        "registry_mutation",
    ],
)
def test_every_nonqualification_permission_must_remain_false(
    tmp_path: Path, permission: str
) -> None:
    fixture = _make_fixture(tmp_path)
    fixture.claim["permissions"][permission] = True
    with pytest.raises(service.CustodyError):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_qualification_permission_cannot_be_false(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    fixture.claim["permissions"]["qualification_generation"] = False
    with pytest.raises(service.CustodyError):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


@pytest.mark.parametrize("token", ["A" * 64, "0" * 63, "g" * 64])
def test_plaintext_token_is_exact_lower_64_hex_and_hash_bound(tmp_path: Path, token: str) -> None:
    fixture = _make_fixture(tmp_path)
    challenge = fixture.begin()
    request = service.build_sign_request(
        challenge=challenge,
        authority_claim=fixture.claim,
        activation_token=token,
    )
    with pytest.raises(service.CustodyError):
        fixture.core.complete_sign(request)


def test_challenge_response_tamper_is_terminal(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    request = json.loads(fixture.sign_raw(fixture.begin()))
    request["challenge_response_sha256"] = "f" * 64
    with pytest.raises(service.CustodyError, match="CHALLENGE_RESPONSE_INVALID"):
        fixture.core.complete_sign(service.canonical_json_bytes(request))
    assert fixture.seed == bytearray(32)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"client_nonce":"' + b"1" * 64 + b'", "command":"BEGIN_R8_R5_AUTHORITY_SIGN",'
        b'"schema_version":"expected_pe.r8.r5.signer.begin.v1"}',
        b'{"client_nonce":"' + b"1" * 64 + b'","client_nonce":"' + b"1" * 64
        + b'","command":"BEGIN_R8_R5_AUTHORITY_SIGN",'
        b'"schema_version":"expected_pe.r8.r5.signer.begin.v1"}',
    ],
)
def test_noncanonical_and_duplicate_begin_aliases_fail_closed(tmp_path: Path, raw: bytes) -> None:
    fixture = _make_fixture(tmp_path)
    with pytest.raises(service.CustodyError):
        fixture.core.begin_sign(raw)
    assert fixture.seed == bytearray(32)


def test_second_begin_and_post_signature_replay_are_rejected(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    challenge = fixture.begin()
    request = fixture.sign_raw(challenge)
    fixture.core.complete_sign(request)
    with pytest.raises(service.CustodyError, match="SECOND_OR_REPLAY"):
        fixture.core.begin_sign(service.build_begin_request("2" * 64))
    with pytest.raises(service.CustodyError, match="NO_ACTIVE_OR_REPLAYED"):
        fixture.core.complete_sign(request)


def test_design_source_runtime_and_anchor_pins_are_reopened(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    fixture.claim["source_lock_raw_sha256"] = "f" * 64
    with pytest.raises(service.CustodyError):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_anchor_service_identity_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    anchor = json.loads(fixture.anchor_path.read_bytes())
    anchor["r5_signer_service_binding"]["key_id"] = "f" * 64
    raw = _write_json(fixture.anchor_path, anchor)
    fixture.claim["external_anchor_raw_sha256"] = service.sha256_bytes(raw)
    with pytest.raises(service.CustodyError, match="SUBSTITUTE"):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_independent_audit_nonzero_finding_is_rejected_even_when_resealed(
    tmp_path: Path,
) -> None:
    fixture = _make_fixture(tmp_path)
    audit = json.loads((fixture.audit_root / "AUDIT.json").read_bytes())
    audit["finding_counts"]["P1"] = 1
    _write_json(fixture.audit_root / "AUDIT.json", audit)
    _refresh_audit(fixture)
    with pytest.raises(service.CustodyError, match="ZERO_FINDING"):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_independent_audit_nonzero_access_is_rejected_even_when_resealed(
    tmp_path: Path,
) -> None:
    fixture = _make_fixture(tmp_path)
    zero = json.loads((fixture.audit_root / "ZERO_ACCESS_RECEIPT.json").read_bytes())
    zero["heldout_access_count"] = 1
    zero_raw = _write_json(fixture.audit_root / "ZERO_ACCESS_RECEIPT.json", zero)
    audit = json.loads((fixture.audit_root / "AUDIT.json").read_bytes())
    audit["zero_access_receipt_raw_sha256"] = service.sha256_bytes(zero_raw)
    _write_json(fixture.audit_root / "AUDIT.json", audit)
    _refresh_audit(fixture)
    with pytest.raises(service.CustodyError, match="ZERO_ACCESS"):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_audit_json_whitespace_alias_is_rejected_even_if_claim_hash_matches(
    tmp_path: Path,
) -> None:
    fixture = _make_fixture(tmp_path)
    payload = json.loads((fixture.audit_root / "AUDIT.json").read_bytes())
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    (fixture.audit_root / "AUDIT.json").write_bytes(raw)
    _refresh_audit(fixture)
    with pytest.raises(service.CustodyError, match="NON_CANONICAL"):
        fixture.core.complete_sign(fixture.sign_raw(fixture.begin()))


def test_production_source_has_no_secret_cli_env_or_generic_signing_surface() -> None:
    source = Path(service.__file__).read_text(encoding="utf-8")
    bootstrap = (
        service.PROJECT_ROOT
        / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r5_signer_service/bootstrap.py"
    ).read_text(encoding="utf-8")
    assert "--serve-production" in source
    assert "SIGN_EXACT_R8_R5_AUTHORITY_ONCE" in source
    assert "GENERIC_SIGN" not in source
    assert "os.environ" not in source
    assert "BCryptGenRandom" in bootstrap
    assert "stdin=subprocess.PIPE" in bootstrap
    assert "DETACHED_PROCESS" in bootstrap and "CREATE_NO_WINDOW" in bootstrap
    assert "activation_token" not in " ".join(
        line for line in bootstrap.splitlines() if "Popen" in line or "sys.argv" in line
    )


def test_readiness_receipt_contains_public_pop_and_zero_access_only(tmp_path: Path) -> None:
    fixture = _make_fixture(tmp_path)
    receipt = fixture.core.readiness_receipt(process_id=4321)
    assert receipt["access_counts"] == {
        "authority_signature_count": 0,
        "heldout_access_count": 0,
        "qualification_payload_generation_count": 0,
        "sign_request_count": 0,
        "signing_count": 0,
        "truth_vault_latent_open_count": 0,
    }
    assert receipt["endpoint"].startswith(r"\\.\pipe\expected_pe_r8_r5_")
    forbidden = {"seed", "private_key", "activation_token", "authkey"}
    assert forbidden.isdisjoint(receipt)
    assert receipt["private_seed_persisted"] is False
