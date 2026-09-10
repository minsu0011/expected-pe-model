from __future__ import annotations

import ast
import ctypes
import csv
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation import (
    capability,
    publication,
    vault_finalizer,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.authority import (
    AUTHORITY_KEYS,
    authenticate_authority,
    authority_signing_bytes,
    verify_ed25519,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.capability import (
    CAPABILITY_ENV,
    SECURITY_ATTRIBUTES,
    _build_capability,
    _create_inheritable_pipe,
    _read_inherited_capability,
    _validate_inherited_capability,
    _write_capability_handle,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.contracts import (
    AUDITOR_KEY_ID,
    AUDITOR_POSSESSION_CHALLENGE,
    AUDITOR_POSSESSION_SIGNATURE_HEX,
    AUDITOR_PUBLIC_KEY_HEX,
    AUTHORITY_DOMAIN,
    AUTHORITY_DOMAIN_TEXT,
    DGPS,
    HELDOUT_SEEDS,
    LATENT_COLUMNS_BY_DGP,
    QUALIFICATION_SEEDS,
    REGISTRY_RAW_SHA256,
    R8QualificationGenerationError,
    ROWS_PER_TASK,
    SCHEDULED_TASK_COUNT,
    SIGNER_READINESS_RAW_SHA256,
    TRUTH_COLUMNS,
    canonical_json_bytes,
    child_capability_id,
    expected_child_capability_ids,
    expected_tasks,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.paths import (
    plan_paths,
    validate_initial_plan,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.publication import (
    PublicationJournal,
    durably_fsync_tree,
    exact_tree_metadata,
    exact_tree_sha256,
    publish_or_recover,
    recover_authenticated_publication,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.scheduler import (
    TaskSpec,
    admit_scheduler,
    canonical_task_specs,
    run_deterministic_bounded,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.source_custody import (
    capture_source_lock,
    source_archive_bytes,
    verify_source_archive,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = PROJECT_ROOT / (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation"
)
SCRIPT = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation"
)
RUN_ID = "20260821T120000"
TOKEN = "ab" * 32
CAPABILITY_SECRETS = {
    identity: sha256_bytes(f"R8-R5-FIXTURE-SECRET:{identity}".encode("ascii"))
    for identity in expected_child_capability_ids()
}
CAPABILITY_SECRET_HASHES = {
    identity: sha256_bytes(secret.encode("ascii"))
    for identity, secret in CAPABILITY_SECRETS.items()
}


def _fixture_authority() -> tuple[dict[str, object], str, str]:
    cryptography = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private = cryptography.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = sha256_bytes(public)
    issued = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
    payload: dict[str, object] = {
        "schema_version": "expected_pe.r8.r5.qualification.signed_authority.v1",
        "action": "ACTIVATE_ONCE",
        "stage": "QUALIFICATION",
        "activation_token_sha256": sha256_bytes(TOKEN.encode("ascii")),
        "audit_json_raw_sha256": "1" * 64,
        "audit_seal_raw_sha256": "2" * 64,
        "authority_domain": AUTHORITY_DOMAIN_TEXT,
        "custody_signer_key_id": key_id,
        "design_checksums_raw_sha256": "3" * 64,
        "source_lock_raw_sha256": "4" * 64,
        "runtime_tcb_raw_sha256": "5" * 64,
        "source_archive_raw_sha256": "6" * 64,
        "external_anchor_raw_sha256": "7" * 64,
        "signer_readiness_raw_sha256": SIGNER_READINESS_RAW_SHA256,
        "registry_raw_sha256": REGISTRY_RAW_SHA256,
        "qualification_seed_ids": list(QUALIFICATION_SEEDS),
        "heldout_seed_ids": list(HELDOUT_SEEDS),
        "dgp_ids": list(DGPS),
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "permissions": {
            "heldout_generation": False,
            "model_fit_prediction_evaluation_score": False,
            "production_promotion": False,
            "qualification_generation": True,
            "registry_mutation": False,
        },
        "issued_at_utc": issued.isoformat(timespec="microseconds"),
        "expires_at_utc": (issued + timedelta(minutes=10)).isoformat(
            timespec="microseconds"
        ),
        "signature_ed25519_hex": "",
    }
    payload["signature_ed25519_hex"] = private.sign(authority_signing_bytes(payload)).hex()
    return payload, public.hex(), key_id


def _authenticate_fixture(payload: dict[str, object], public_hex: str, key_id: str) -> None:
    authenticate_authority(
        payload,
        activation_token=TOKEN,
        run_id=RUN_ID,
        design_checksums_raw_sha256="3" * 64,
        source_lock_raw_sha256="4" * 64,
        runtime_tcb_raw_sha256="5" * 64,
        source_archive_raw_sha256="6" * 64,
        external_anchor_raw_sha256="7" * 64,
        signer_readiness_raw_sha256=SIGNER_READINESS_RAW_SHA256,
        public_key_hex=public_hex,
        expected_key_id=key_id,
        now=datetime(2026, 8, 21, 12, 1, 0, tzinfo=timezone.utc),
        reopen_audit=False,
    )


def test_exact_fresh_geometry_is_bound_without_seed_reservation() -> None:
    assert QUALIFICATION_SEEDS == (7573, 7577, 7583, 7589, 7591)
    assert HELDOUT_SEEDS == (7603, 7607, 7621, 7639, 7643)
    assert set(QUALIFICATION_SEEDS).isdisjoint(HELDOUT_SEEDS)
    assert DGPS == tuple("ABCDEFGHIJ")
    assert ROWS_PER_TASK == 1_800
    assert len(expected_tasks()) == SCHEDULED_TASK_COUNT == 100


def test_custodian_public_key_id_and_non_authorizing_proof_are_exact() -> None:
    public = bytes.fromhex(AUDITOR_PUBLIC_KEY_HEX)
    assert sha256_bytes(public) == AUDITOR_KEY_ID
    assert verify_ed25519(
        public,
        AUDITOR_POSSESSION_CHALLENGE,
        bytes.fromhex(AUDITOR_POSSESSION_SIGNATURE_HEX),
    )
    assert AUTHORITY_DOMAIN != AUDITOR_POSSESSION_CHALLENGE
    assert not verify_ed25519(
        public,
        AUTHORITY_DOMAIN + AUDITOR_POSSESSION_CHALLENGE,
        bytes.fromhex(AUDITOR_POSSESSION_SIGNATURE_HEX),
    )


def test_r5_canonical_json_matches_signer_service_without_trailing_bytes() -> None:
    raw = canonical_json_bytes({"z": 1, "a": "ascii"})
    assert raw == b'{"a":"ascii","z":1}'
    assert not raw.endswith(b"\n")


def test_r5_only_issuance_path_is_stdin_pipe_and_memory_handoff() -> None:
    issuance = (SCRIPT / "issuance_launch.py").read_text(encoding="utf-8")
    launcher = (SCRIPT / "external_launcher.py").read_text(encoding="utf-8")
    assert "stdin must contain one fresh 64-lowercase-hex token line" in issuance
    assert "BEGIN_R8_R5_AUTHORITY_SIGN" not in issuance
    assert "build_begin_request" in issuance and "build_sign_request" in issuance
    assert "input=envelope" in issuance
    assert "--authority" not in launcher
    assert "--run-id" not in launcher
    assert "in_memory_activation_envelope" in launcher
    assert "authority_path" not in launcher


def test_r5_public_signer_binding_is_exact_and_not_a_private_key() -> None:
    assert AUDITOR_KEY_ID == (
        "7282e82347c420158799e7941db9b000f5b3db4fd5b10262cd9d533ab50e6431"
    )
    assert AUDITOR_PUBLIC_KEY_HEX == (
        "98ad0326c8bcd90e3764105577297b73ab8653ef50f2cf6e700808e7ea46d179"
    )
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (*PACKAGE.glob("*.py"), *SCRIPT.glob("*.py"))
    )
    assert "private_seed" not in combined
    assert "build_sign_request" in combined


def test_valid_fixture_signed_exact_key_authority_passes() -> None:
    payload, public, key_id = _fixture_authority()
    assert set(payload) == AUTHORITY_KEYS
    _authenticate_fixture(payload, public, key_id)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("authority_domain", "CALLER_SELECTED_DOMAIN"),
        ("stage", "HELDOUT"),
        ("qualification_seed_ids", [7603]),
        ("finding_counts", {"P0": 0, "P1": 1, "P2": 0}),
    ],
)
def test_signed_authority_binding_mutations_fail(mutation: str, value: object) -> None:
    payload, public, key_id = _fixture_authority()
    payload[mutation] = value
    with pytest.raises(R8QualificationGenerationError):
        _authenticate_fixture(payload, public, key_id)


def test_authority_extra_key_fails_before_signature_acceptance() -> None:
    payload, public, key_id = _fixture_authority()
    payload["caller_asserted_authority"] = True
    with pytest.raises(R8QualificationGenerationError, match="exact-key"):
        _authenticate_fixture(payload, public, key_id)


def test_authority_signature_and_token_mutations_fail() -> None:
    payload, public, key_id = _fixture_authority()
    payload["signature_ed25519_hex"] = "00" * 64
    with pytest.raises(R8QualificationGenerationError, match="signature"):
        _authenticate_fixture(payload, public, key_id)
    payload, public, key_id = _fixture_authority()
    with pytest.raises(R8QualificationGenerationError, match="binding"):
        authenticate_authority(
            payload,
            activation_token="cd" * 32,
            run_id=RUN_ID,
            design_checksums_raw_sha256="3" * 64,
            source_lock_raw_sha256="4" * 64,
            runtime_tcb_raw_sha256="5" * 64,
            source_archive_raw_sha256="6" * 64,
            external_anchor_raw_sha256="7" * 64,
            signer_readiness_raw_sha256=SIGNER_READINESS_RAW_SHA256,
            public_key_hex=public,
            expected_key_id=key_id,
            now=datetime(2026, 8, 21, 12, 1, 0, tzinfo=timezone.utc),
            reopen_audit=False,
        )


def test_direct_child_invocation_fails_without_inherited_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CAPABILITY_ENV, raising=False)
    with pytest.raises(R8QualificationGenerationError, match="before protected generator import"):
        _read_inherited_capability()


@pytest.mark.skipif(os.name != "nt", reason="R8 custody target is Windows")
def test_windows_capability_pipe_abi_and_os_handle_allowlist() -> None:
    assert ctypes.sizeof(SECURITY_ATTRIBUTES) == 24
    frame = b"EPS-R8-R4-ALLOWLISTED-PIPE-OBJECT-MARKER-v1\n"
    unrelated_marker = b"EPS-R8-R4-UNRELATED-PIPE-OBJECT-MARKER-v1\n"
    read_handle, write_handle = _create_inheritable_pipe(frame)
    unrelated_read, unrelated_write = _create_inheritable_pipe(b"")
    # Queue an object-identity marker before spawning.  The unrelated read end
    # remains inheritable but is intentionally absent from PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
    _write_capability_handle(unrelated_write, unrelated_marker)
    environment = os.environ.copy()
    environment["R8_PROBE_READ_HANDLE"] = str(read_handle)
    environment["R8_PROBE_UNRELATED_HANDLE"] = str(unrelated_read)
    environment["R8_PROBE_FRAME_SIZE"] = str(len(frame))
    environment["R8_PROBE_UNRELATED_MARKER_HEX"] = unrelated_marker.hex()
    child = """
import ctypes,json,os
from ctypes import wintypes
read_handle=int(os.environ['R8_PROBE_READ_HANDLE'])
unrelated=int(os.environ['R8_PROBE_UNRELATED_HANDLE'])
frame_size=int(os.environ['R8_PROBE_FRAME_SIZE'])
marker=bytes.fromhex(os.environ['R8_PROBE_UNRELATED_MARKER_HEX'])
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetHandleInformation.argtypes=(wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD))
k.GetHandleInformation.restype=wintypes.BOOL
k.ReadFile.argtypes=(wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p)
k.ReadFile.restype=wintypes.BOOL
k.PeekNamedPipe.argtypes=(wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD))
k.PeekNamedPipe.restype=wintypes.BOOL

frame_buffer=ctypes.create_string_buffer(frame_size)
frame_read=wintypes.DWORD()
allowed_readfile_succeeded=bool(k.ReadFile(wintypes.HANDLE(read_handle),frame_buffer,frame_size,ctypes.byref(frame_read),None))
frame=frame_buffer.raw[:frame_read.value]

flags=wintypes.DWORD()
numeric_alias_visible=bool(k.GetHandleInformation(wintypes.HANDLE(unrelated),ctypes.byref(flags)))
peek_buffer=ctypes.create_string_buffer(len(marker))
peeked=wintypes.DWORD()
available=wintypes.DWORD()
left=wintypes.DWORD()
ctypes.set_last_error(0)
peek_succeeded=bool(k.PeekNamedPipe(wintypes.HANDLE(unrelated),peek_buffer,len(marker),ctypes.byref(peeked),ctypes.byref(available),ctypes.byref(left)))
peek_last_error=ctypes.get_last_error()
peek_bytes=peek_buffer.raw[:peeked.value] if peek_succeeded else b''
marker_visible=peek_bytes==marker
marker_read_confirmed=False
marker_read_attempted=False
if marker_visible:
    marker_read_attempted=True
    read_buffer=ctypes.create_string_buffer(len(marker))
    marker_read=wintypes.DWORD()
    marker_read_ok=bool(k.ReadFile(wintypes.HANDLE(unrelated),read_buffer,len(marker),ctypes.byref(marker_read),None))
    marker_read_confirmed=marker_read_ok and read_buffer.raw[:marker_read.value]==marker
print(json.dumps({
    'allowed_read_method':'WIN32_READFILE',
    'allowed_readfile_succeeded':allowed_readfile_succeeded,
    'frame_hex':frame.hex(),
    'unrelated_numeric_alias_visible':numeric_alias_visible,
    'unrelated_peek_succeeded':peek_succeeded,
    'unrelated_peek_last_error':peek_last_error,
    'unrelated_peek_bytes_hex':peek_bytes.hex(),
    'unrelated_marker_visible':marker_visible,
    'unrelated_marker_read_attempted':marker_read_attempted,
    'unrelated_marker_read_confirmed':marker_read_confirmed,
},sort_keys=True))
"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.lpAttributeList = {"handle_list": [read_handle]}
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-E", "-c", child],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        startupinfo=startupinfo,
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    assert kernel32.CloseHandle(ctypes.c_void_p(read_handle))
    assert kernel32.CloseHandle(ctypes.c_void_p(unrelated_read))
    _write_capability_handle(write_handle, frame)
    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    receipt = json.loads(stdout)
    assert receipt["allowed_read_method"] == "WIN32_READFILE"
    assert receipt["allowed_readfile_succeeded"] is True
    assert bytes.fromhex(receipt["frame_hex"]) == frame
    assert isinstance(receipt["unrelated_numeric_alias_visible"], bool)
    assert receipt["unrelated_marker_visible"] is False
    assert receipt["unrelated_marker_read_confirmed"] is False


def test_protected_generator_import_is_below_capability_validation() -> None:
    source = (PACKAGE / "activation.py").read_text(encoding="utf-8")
    validation = source.index("validate_inherited_capability(")
    protected_import = source.index("protected_role,", validation)
    assert validation < protected_import
    launcher_tree = ast.parse((SCRIPT / "external_launcher.py").read_text(encoding="utf-8"))
    parser_choices = [
        node
        for node in ast.walk(launcher_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_subparsers"
    ]
    assert parser_choices == []


@pytest.mark.parametrize(
    "run_id",
    [
        "../../../R8_ESCAPE",
        "20260821T120000/../../x",
        "20260821T12000",
        "20260230T120000",
        "20260821T246000",
        "R8",
    ],
)
def test_run_id_path_escape_is_rejected_before_plan(run_id: str, tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    with pytest.raises(R8QualificationGenerationError):
        plan_paths(run_id, outputs_root=outputs)


def test_four_paths_are_distinct_absent_direct_children(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    plan = plan_paths(RUN_ID, outputs_root=outputs)
    validate_initial_plan(plan)
    assert len({path.resolve() for path in plan.four_roots}) == 4
    assert all(path.parent == outputs.resolve() and not path.exists() for path in plan.four_roots)
    plan.public_final.mkdir()
    with pytest.raises(R8QualificationGenerationError, match="already has custody"):
        validate_initial_plan(plan)


def test_capability_paths_are_derived_not_caller_supplied(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    plan = plan_paths(RUN_ID, outputs_root=outputs)
    payload, _public, _key_id = _fixture_authority()
    capability = _build_capability(
        role="PUBLIC_RUN",
        authority=payload,
        activation_token=TOKEN,
        plan=plan,
        claim_raw_sha256="6" * 64,
        capability_secret_hex=CAPABILITY_SECRETS[
            child_capability_id("PUBLIC_RUN", seed=7573, dgp="A", replay_pass=1)
        ],
        cpu_ids=(0, 1),
        seed=7573,
        dgp="A",
        replay_pass=1,
    )
    serialized = canonical_json_bytes(capability).decode("ascii")
    assert str(outputs.resolve()) not in serialized
    assert capability["public_root_name"] == plan.public_staging.name
    assert capability["vault_root_name"] == plan.vault_staging.name


def test_one_shot_claim_persists_only_role_bound_child_secret_hashes(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    journal = PublicationJournal(plan_paths(RUN_ID, outputs_root=outputs))
    claim = journal.claim(
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
        controller_pid=12345,
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    raw = canonical_json_bytes(claim)
    assert all(secret.encode("ascii") not in raw for secret in CAPABILITY_SECRETS.values())
    assert claim["child_capability_secret_sha256"] == CAPABILITY_SECRET_HASHES
    assert len(set(CAPABILITY_SECRET_HASHES.values())) == len(CAPABILITY_SECRET_HASHES) == 202
    assert claim["controller_pid"] == 12345


def test_role_bound_child_secret_cannot_be_reused_for_another_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    plan = plan_paths(RUN_ID, outputs_root=outputs)
    journal = PublicationJournal(plan)
    authority, _public, _key_id = _fixture_authority()
    journal.claim(
        authority_raw_sha256=sha256_bytes(canonical_json_bytes(authority)),
        activation_token_sha256=sha256_bytes(TOKEN.encode("ascii")),
        controller_pid=os.getpid(),
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    claim_payload = json.loads((plan.journal / "00_CLAIMED.json").read_bytes())
    identity = child_capability_id("PUBLIC_RUN", seed=7573, dgp="A", replay_pass=1)
    frame = _build_capability(
        role="PUBLIC_RUN",
        authority=authority,
        activation_token=TOKEN,
        plan=plan,
        claim_raw_sha256=sha256_bytes(canonical_json_bytes(claim_payload)),
        capability_secret_hex=CAPABILITY_SECRETS[identity],
        cpu_ids=(0, 1),
        seed=7573,
        dgp="A",
        replay_pass=1,
    )
    monkeypatch.setattr(capability, "plan_paths", lambda _run_id: plan)
    monkeypatch.setattr(capability.os, "getppid", os.getpid)
    monkeypatch.setattr(capability, "authenticate_authority", lambda *_args, **_kwargs: {})
    _validate_inherited_capability(
        frame,
        design_checksums_raw_sha256="3" * 64,
        source_lock_raw_sha256="4" * 64,
        runtime_tcb_raw_sha256="5" * 64,
        source_archive_raw_sha256="6" * 64,
        external_anchor_raw_sha256="7" * 64,
        signer_readiness_raw_sha256=SIGNER_READINESS_RAW_SHA256,
        claim_payload=claim_payload,
    )
    forged = dict(frame)
    forged["capability_secret_hex"] = CAPABILITY_SECRETS["PROTECTED_FINALIZE"]
    with pytest.raises(R8QualificationGenerationError, match="binding drifted"):
        _validate_inherited_capability(
            forged,
            design_checksums_raw_sha256="3" * 64,
            source_lock_raw_sha256="4" * 64,
            runtime_tcb_raw_sha256="5" * 64,
            source_archive_raw_sha256="6" * 64,
            external_anchor_raw_sha256="7" * 64,
            signer_readiness_raw_sha256=SIGNER_READINESS_RAW_SHA256,
            claim_payload=claim_payload,
        )


def test_scheduler_admission_partitions_cpu0_31_without_overlap() -> None:
    admission = admit_scheduler(
        logical_cpu_count=32,
        total_physical_gib=95.0,
        available_physical_gib=90.0,
    )
    assert admission.admitted_workers == 16
    assert [cpu for part in admission.partitions for cpu in part.cpu_ids] == list(range(32))
    assert all(len(part.cpu_ids) == 2 for part in admission.partitions)
    assert admission.inner_threads == 1


def test_scheduler_result_order_is_stable_despite_partition_queues() -> None:
    admission = admit_scheduler(
        logical_cpu_count=32,
        total_physical_gib=95.0,
        available_physical_gib=45.0,
    )
    tasks = tuple(TaskSpec(index, 1, 7573, chr(65 + index)) for index in range(10))
    results = run_deterministic_bounded(
        admission,
        lambda task, partition: (task.ordinal, partition.worker_index),
        tasks=tasks,
    )
    assert [row[0] for row in results] == list(range(10))
    assert [task.ordinal for task in canonical_task_specs()] == list(range(100))


def test_runtime_tcb_code_verifies_every_record_member_and_child_flags() -> None:
    source = (PACKAGE / "runtime_tcb.py").read_text(encoding="utf-8")
    launcher = (SCRIPT / "external_launcher.py").read_text(encoding="utf-8")
    assert 'for record in distribution["members"].values()' in source
    assert 'for record in expected["stdlib_members"].values()' in source
    assert "_verify_python_native_inventory(expected)" in source
    assert 'base_root / "DLLs"' in source
    assert 'base_root / "Library" / "bin"' in source
    assert 'for record in expected["startup_modules"].values()' in source
    assert "verify_loaded_origin_closure" in launcher
    startup_probe = (SCRIPT / "runtime_startup_probe.py").read_text(encoding="utf-8")
    assert "PASS_NO_UNSEALED_STARTUP_OR_NATIVE_MODULE_ORIGIN" in startup_probe
    assert "protected_generator_import_count" in startup_probe
    activation = (PACKAGE / "activation.py").read_text(encoding="utf-8")
    assert all(f'"{flag}"' in activation for flag in ("-I", "-S", "-B", "-E"))
    assert "pycache_prefix=" in activation
    nested = (PACKAGE / "isolated_child_replay.py").read_text(encoding="utf-8")
    semantic_check = nested.index("nested R8 replay runtime TCB logical seal drifted")
    site_insertion = nested.index("sys.path.append(str(site_root))")
    assert semantic_check < site_insertion
    assert "externally pinned RUNTIME_TCB" in nested


def test_governed_r8_namespaces_forbid_pycache_and_archive_every_source() -> None:
    for root in (PACKAGE, SCRIPT):
        forbidden = [
            path
            for path in root.rglob("*")
            if "__pycache__" in path.parts or path.suffix.casefold() in {".pyc", ".pyo"}
        ]
        assert forbidden == []
    lock = capture_source_lock()
    archive = source_archive_bytes(lock)
    receipt = verify_source_archive(lock, archive)
    assert receipt["record_count"] == lock["record_count"]
    assert receipt["pycache_member_count"] == receipt["pyc_member_count"] == 0


def _csv_bytes(columns: tuple[str, ...], rows: list[list[object]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(columns)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _build_small_vault(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault_finalizer, "QUALIFICATION_SEEDS", (7573,))
    monkeypatch.setattr(vault_finalizer, "DGPS", ("A",))
    monkeypatch.setattr(vault_finalizer, "REPLAY_PASSES", (1, 2))
    monkeypatch.setattr(vault_finalizer, "ROWS_PER_TASK", 3)
    dates = ["2020-01-01", "2020-01-02", "2020-01-03"]
    truth_rows = [[value, 20, 3, 1, 1, 20, "True"] for value in dates]
    latent_rows = [[value, 3, 0, 0] for value in dates]
    truth_raw = _csv_bytes(TRUTH_COLUMNS, truth_rows)
    latent_raw = _csv_bytes(LATENT_COLUMNS_BY_DGP["A"], latent_rows)
    _rows, truth_logical = vault_finalizer._parse_csv(truth_raw, expected_columns=TRUTH_COLUMNS)
    _rows, latent_logical = vault_finalizer._parse_csv(
        latent_raw, expected_columns=LATENT_COLUMNS_BY_DGP["A"]
    )
    hashes = {"truth": sha256_bytes(truth_raw), "latent_events": sha256_bytes(latent_raw)}
    logical = {"truth": truth_logical, "latent_events": latent_logical}
    for replay_pass in (1, 2):
        task = root / f"pass_{replay_pass}" / "seed_7573" / "dgp_A"
        task.mkdir(parents=True)
        (task / "truth.csv").write_bytes(truth_raw)
        (task / "latent_events.csv").write_bytes(latent_raw)
        metadata = {
            "schema_version": "expected_pe.r7.qualification.private_task_metadata.v1",
            "status": "PASS_PROTECTED_BYTES_FROZEN",
            "stage": "QUALIFICATION",
            "seed": 7573,
            "dgp": "A",
            "replay_pass": replay_pass,
            "rows": 3,
            "truth_header_raw_sha256": sha256_bytes(
                (",".join(TRUTH_COLUMNS) + "\n").encode("ascii")
            ),
            "protected_raw_sha256": hashes,
            "protected_logical_sha256": logical,
            "public_logical_sha256": {
                name: "7" * 64
                for name in (
                    "price",
                    "benchmark",
                    "eps_events",
                    "public_factors",
                    "corporate_actions",
                )
            },
            "public_path_received": False,
            "score_fit_prediction_evaluation": False,
        }
        (task / "METADATA.json").write_bytes(canonical_json_bytes(metadata))
        if replay_pass == 2:
            proof = {
                "schema_version": "expected_pe.r7.qualification.protected_parity_proof.v1",
                "status": "PASS_INDEPENDENT_PROTECTED_BYTES_EXACT",
                "seed": 7573,
                "dgp": "A",
                "first_pass_protected_raw_sha256": hashes,
                "second_pass_protected_raw_sha256": hashes,
                "byte_hashes_equal": True,
            }
            (task / "INDEPENDENT_HASH_PROOF.json").write_bytes(canonical_json_bytes(proof))


def test_protected_finalizer_reopens_both_passes_and_seals_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _build_small_vault(vault, monkeypatch)
    receipt = vault_finalizer.finalize_protected_vault(vault)
    assert receipt["task_count"] == 1
    assert (vault / "CHECKSUMS.sha256").is_file()
    parity = json.loads((vault / "VAULT_PARITY_RECEIPT.json").read_bytes())
    assert parity["tasks"][0]["both_passes_reopened"] is True
    assert parity["tasks"][0]["raw_parity"] is parity["tasks"][0]["logical_parity"] is True


@pytest.mark.parametrize(
    "corruption",
    [
        "pass_bytes",
        "metadata_seed",
        "metadata_schema",
        "metadata_status",
        "metadata_public_keys",
        "metadata_producer_logical",
        "extra_file",
        "proof",
        "proof_schema",
        "proof_status",
    ],
)
def test_protected_finalizer_corruption_fails_closed(
    corruption: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _build_small_vault(vault, monkeypatch)
    second = vault / "pass_2/seed_7573/dgp_A"
    if corruption == "pass_bytes":
        raw = (second / "truth.csv").read_bytes().replace(b",20,", b",21,", 1)
        (second / "truth.csv").write_bytes(raw)
    elif corruption == "metadata_seed":
        payload = json.loads((second / "METADATA.json").read_bytes())
        payload["seed"] = 7603
        (second / "METADATA.json").write_bytes(canonical_json_bytes(payload))
    elif corruption.startswith("metadata_"):
        payload = json.loads((second / "METADATA.json").read_bytes())
        if corruption == "metadata_schema":
            payload["schema_version"] = "forged"
        elif corruption == "metadata_status":
            payload["status"] = "forged"
        elif corruption == "metadata_public_keys":
            payload["public_logical_sha256"].pop("corporate_actions")
        else:
            payload["protected_logical_sha256"]["truth"] = "f" * 64
        (second / "METADATA.json").write_bytes(canonical_json_bytes(payload))
    elif corruption == "extra_file":
        (second / "EXTRA").write_bytes(b"x")
    else:
        payload = json.loads((second / "INDEPENDENT_HASH_PROOF.json").read_bytes())
        if corruption == "proof":
            payload["byte_hashes_equal"] = False
        elif corruption == "proof_schema":
            payload["schema_version"] = "forged"
        else:
            payload["status"] = "forged"
        (second / "INDEPENDENT_HASH_PROOF.json").write_bytes(canonical_json_bytes(payload))
    with pytest.raises(R8QualificationGenerationError):
        vault_finalizer.finalize_protected_vault(vault)


@pytest.mark.parametrize(
    "crash_phase",
    ["STAGING_SEALED", "VAULT_PUBLISHED", "PUBLIC_PUBLISHED"],
)
def test_publication_recovers_idempotently_from_each_commit_crash_phase(
    crash_phase: str, tmp_path: Path
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    plan = plan_paths(RUN_ID, outputs_root=outputs)
    journal = PublicationJournal(plan)
    journal.claim(
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
        controller_pid=12345,
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    journal.create_staging()
    (plan.public_staging / "public.txt").write_bytes(b"public")
    (plan.vault_staging / "vault.txt").write_bytes(b"vault")
    public_hash = exact_tree_sha256(plan.public_staging)
    vault_hash = exact_tree_sha256(plan.vault_staging)

    def crash(phase: str) -> None:
        if phase == crash_phase:
            raise RuntimeError("synthetic crash")

    with pytest.raises(RuntimeError, match="synthetic crash"):
        publish_or_recover(
            journal,
            public_tree_sha256=public_hash,
            vault_tree_sha256=vault_hash,
            crash_hook=crash,
        )
    receipt = publish_or_recover(
        journal,
        public_tree_sha256=public_hash,
        vault_tree_sha256=vault_hash,
    )
    assert receipt["phase"] == "COMMITTED"
    assert plan.public_final.is_dir() and plan.vault_final.is_dir()
    assert not plan.public_staging.exists() and not plan.vault_staging.exists()


def _publication_fixture(tmp_path: Path) -> tuple[PublicationJournal, str, str]:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    journal = PublicationJournal(plan_paths(RUN_ID, outputs_root=outputs))
    journal.claim(
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
        controller_pid=12345,
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    journal.create_staging()
    (journal.plan.public_staging / "public.txt").write_bytes(b"public")
    (journal.plan.vault_staging / "vault.txt").write_bytes(b"vault")
    return (
        journal,
        exact_tree_sha256(journal.plan.public_staging),
        exact_tree_sha256(journal.plan.vault_staging),
    )


@pytest.mark.parametrize(
    "crash_phase",
    ["STAGING_SEALED", "VAULT_PUBLISHED", "PUBLIC_PUBLISHED", "COMMITTED"],
)
def test_authenticated_top_level_reentry_recovers_without_generator_import(
    crash_phase: str, tmp_path: Path
) -> None:
    journal, public_hash, vault_hash = _publication_fixture(tmp_path)

    def crash(phase: str) -> None:
        if phase == crash_phase:
            raise RuntimeError("synthetic process death")

    with pytest.raises(RuntimeError, match="synthetic process death"):
        publish_or_recover(
            journal,
            public_tree_sha256=public_hash,
            vault_tree_sha256=vault_hash,
            crash_hook=crash,
        )
    protected_before = {
        name for name in sys.modules if name.endswith(".protected_role")
    }
    receipt = recover_authenticated_publication(
        journal,
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
    )
    assert receipt is not None and receipt["phase"] == "COMMITTED"
    assert receipt["payload_generation_resumed"] is False
    assert {name for name in sys.modules if name.endswith(".protected_role")} == protected_before


@pytest.mark.parametrize("preseal_phase", ["CLAIMED", "STAGING_CREATED", "ABORTED_PRESERVED"])
def test_authenticated_top_level_reentry_rejects_preseal_generation_state(
    preseal_phase: str, tmp_path: Path
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    journal = PublicationJournal(plan_paths(RUN_ID, outputs_root=outputs))
    journal.claim(
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
        controller_pid=12345,
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    if preseal_phase != "CLAIMED":
        journal.create_staging()
    if preseal_phase == "ABORTED_PRESERVED":
        journal.abort_preserved(failure_class="SyntheticFailure")
    with pytest.raises(R8QualificationGenerationError, match="non-resumable"):
        recover_authenticated_publication(
            journal,
            authority_raw_sha256="8" * 64,
            activation_token_sha256="9" * 64,
        )


def test_authenticated_reentry_rejects_wrong_original_claim_token(tmp_path: Path) -> None:
    journal, public_hash, vault_hash = _publication_fixture(tmp_path)
    with pytest.raises(RuntimeError):
        publish_or_recover(
            journal,
            public_tree_sha256=public_hash,
            vault_tree_sha256=vault_hash,
            crash_hook=lambda phase: (_ for _ in ()).throw(RuntimeError())
            if phase == "STAGING_SEALED"
            else None,
        )
    with pytest.raises(R8QualificationGenerationError, match="claim binding"):
        recover_authenticated_publication(
            journal,
            authority_raw_sha256="8" * 64,
            activation_token_sha256="a" * 64,
        )


@pytest.mark.parametrize("phase_index", range(6))
def test_every_journal_ancestry_record_semantics_and_hash_link_are_reopened(
    phase_index: int, tmp_path: Path
) -> None:
    journal, public_hash, vault_hash = _publication_fixture(tmp_path)
    publish_or_recover(
        journal,
        public_tree_sha256=public_hash,
        vault_tree_sha256=vault_hash,
    )
    path = journal.plan.journal / f"{phase_index:02d}_{publication.PHASES[phase_index]}.json"
    payload = json.loads(path.read_bytes())
    payload["run_id"] = "20260821T120001"
    semantic = dict(payload)
    semantic.pop("record_semantic_sha256")
    payload["record_semantic_sha256"] = sha256_bytes(canonical_json_bytes(semantic))
    path.chmod(0o660)
    path.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(R8QualificationGenerationError):
        journal.current()


@pytest.mark.parametrize("target", ["vault", "public"])
def test_reentry_recovers_rename_completed_before_directory_fsync(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal, public_hash, vault_hash = _publication_fixture(tmp_path)
    original = publication.fsync_directory

    def interrupted(path: Path) -> None:
        state = journal.current()
        phase = None if state is None else state[0]
        renamed = (
            journal.plan.vault_final.exists()
            if target == "vault"
            else journal.plan.public_final.exists()
        )
        expected_phase = "STAGING_SEALED" if target == "vault" else "VAULT_PUBLISHED"
        if Path(path).resolve() == journal.plan.outputs_root and renamed and phase == expected_phase:
            raise RuntimeError("synthetic directory fsync interruption")
        original(path)

    monkeypatch.setattr(publication, "fsync_directory", interrupted)
    with pytest.raises(RuntimeError, match="fsync interruption"):
        publish_or_recover(
            journal,
            public_tree_sha256=public_hash,
            vault_tree_sha256=vault_hash,
        )
    monkeypatch.setattr(publication, "fsync_directory", original)
    receipt = recover_authenticated_publication(
        journal,
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
    )
    assert receipt is not None and receipt["phase"] == "COMMITTED"


@pytest.mark.parametrize(
    ("phase_index", "phase_name"),
    [
        (2, "STAGING_SEALED"),
        (3, "VAULT_PUBLISHED"),
        (4, "PUBLIC_PUBLISHED"),
        (5, "COMMITTED"),
    ],
)
def test_reentry_recovers_phase_file_written_before_journal_directory_fsync(
    phase_index: int,
    phase_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal, public_hash, vault_hash = _publication_fixture(tmp_path)
    original = publication.fsync_directory
    target = journal.plan.journal / f"{phase_index:02d}_{phase_name}.json"

    def interrupted(path: Path) -> None:
        if Path(path).resolve() == journal.plan.journal and target.exists():
            raise RuntimeError("synthetic journal-directory fsync interruption")
        original(path)

    monkeypatch.setattr(publication, "fsync_directory", interrupted)
    with pytest.raises(RuntimeError, match="journal-directory fsync interruption"):
        publish_or_recover(
            journal,
            public_tree_sha256=public_hash,
            vault_tree_sha256=vault_hash,
        )
    monkeypatch.setattr(publication, "fsync_directory", original)
    assert journal.current() is not None and journal.current()[0] == phase_name
    receipt = recover_authenticated_publication(
        journal,
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
    )
    assert receipt is not None and receipt["phase"] == "COMMITTED"


def test_durable_tree_reopens_every_file_and_binds_full_metadata(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "nested/deep").mkdir(parents=True)
    (root / "a.bin").write_bytes(b"a")
    (root / "nested/b.bin").write_bytes(b"bb")
    (root / "nested/deep/c.bin").write_bytes(b"ccc")
    receipt = durably_fsync_tree(root)
    assert receipt == exact_tree_metadata(root)
    assert receipt["file_count"] == 3
    assert receipt["directory_count"] == 2
    assert receipt["total_file_bytes"] == 6


def test_prepublication_abort_is_preserved_and_not_resumable(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    journal = PublicationJournal(plan_paths(RUN_ID, outputs_root=outputs))
    journal.claim(
        authority_raw_sha256="8" * 64,
        activation_token_sha256="9" * 64,
        controller_pid=12345,
        child_capability_secret_sha256=CAPABILITY_SECRET_HASHES,
    )
    journal.create_staging()
    journal.abort_preserved(failure_class="SyntheticFailure")
    state = journal.current()
    assert state is not None and state[0] == "ABORTED_PRESERVED"
    assert state[1]["retry_or_resume_allowed"] is False


def test_pytest_receipt_plugin_records_collection_and_executed_items() -> None:
    source = (SCRIPT / "pytest_receipt_plugin.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert {"pytest_collection_finish", "pytest_runtest_logreport", "pytest_sessionfinish"}.issubset(
        functions
    )
    assert "collected_item_count" in source and "executed_item_count" in source


def test_no_truth_heldout_fit_prediction_score_or_registry_action_occurred() -> None:
    assert not any(
        path.exists()
        for path in PROJECT_ROOT.joinpath("outputs").glob(
            "model_zoo_observable_state_bce_dgp_tournament_v2_r8_qualification_generation_20*"
        )
    )
    source = (SCRIPT / "external_launcher.py").read_text(encoding="utf-8")
    assert "--heldout" not in source
    assert "--score" not in source
    assert "--role" not in source
