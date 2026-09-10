from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "model_lab"
    / "pe_four_model_heldout_r3_post_generation_native_identity_adjudicator.py"
)
BASE_SCRIPT = (
    PROJECT_ROOT / "scripts" / "model_lab" / "pe_four_model_heldout_r3_post_generation_audit.py"
)
BASE_TEST = (
    PROJECT_ROOT / "tests" / "model_lab" / "test_pe_four_model_heldout_r3_post_generation_audit.py"
)


def _module():
    name = "r3_native_identity_adjudicator_test_subject"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _base_test_module():
    name = "r3_original_auditor_test_fixture_provider"
    spec = importlib.util.spec_from_file_location(name, BASE_TEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _state_and_validator(module):
    base = module._load_frozen_auditor(PROJECT_ROOT)
    telemetry = module.ReadTelemetry(
        authority_path=PROJECT_ROOT / "build" / "synthetic_authority.json",
        public_root=PROJECT_ROOT / "build" / "synthetic_public",
        vault_manifest_path=PROJECT_ROOT / "build" / "synthetic_vault.json",
    )
    _, register, validate = module._patched_hooks(base, telemetry)
    return base, base.State(), register, validate


def _fake_info(module, *, volume: int, file_id: bytes):
    return module.NativeFileInfo(
        volume_serial_number=volume,
        file_id_128=file_id,
        size_bytes=7,
        last_write_time=11,
        change_time=13,
        file_attributes=0x80,
        number_of_links=1,
    )


def _ref(module, *, volume: int, file_id: bytes, raw: bytes = b"payload"):
    return {
        "file_id_128": file_id.hex(),
        "raw_sha256": module.sha256(raw),
        "relative_path": "outputs/synthetic/payload.bin",
        "size_bytes": len(raw),
        "volume_serial_number": volume,
    }


def _valid_review(module, *, source_hash: str, test_hash: str):
    review = {
        "schema_version": module.REVIEW_SCHEMA,
        "status": module.REVIEW_STATUS,
        "run_id": module.FORMAL_RUN_ID,
        "adjudication_id": module.ADJUDICATION_ID,
        "reviewed_source_raw_sha256": source_hash,
        "reviewed_test_raw_sha256": test_hash,
        "frozen_original_source_raw_sha256": (module.ORIGINAL_AUDITOR_RAW_SHA256),
        "frozen_original_test_raw_sha256": module.ORIGINAL_TEST_RAW_SHA256,
        "independent_reviewer_count": 2,
        "reviews": [
            {
                "review_id": "r3_formal_migration_audit",
                "status": "GO",
                "blocking_findings": [],
            },
            {
                "review_id": "r3_reservation_redteam",
                "status": "GO",
                "blocking_findings": [],
            },
        ],
        "test_evidence": {
            "focused_tests_status": "PASS",
            "focused_pass_count": 1,
            "focused_skip_count": 0,
            "privilege_skip_scope": "none",
            "full_synthetic_50_task_status": "PASS",
            "full_synthetic_public_file_count": 201,
            "ruff_check_status": "PASS",
            "ruff_format_check_status": "PASS",
        },
        "preuse_access_evidence": {
            "formal_public_root_access_count": 0,
            "vault_manifest_access_count": 0,
            "protected_payload_enumeration_count": 0,
            "protected_payload_stat_or_open_count": 0,
            "truth_open_count": 0,
            "score_open_count": 0,
            "prediction_invocation_count": 0,
        },
    }
    review["review_semantic_sha256"] = module.semantic_sha256(review)
    return review


def test_source_is_stdlib_only_and_binds_both_frozen_and_corrected_sources() -> None:
    module = _module()
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported <= {
        "__future__",
        "argparse",
        "ctypes",
        "hashlib",
        "importlib",
        "json",
        "ntpath",
        "os",
        "pathlib",
        "sys",
        "typing",
    }
    assert "secure_publication" not in source
    assert hashlib.sha256(BASE_SCRIPT.read_bytes()).hexdigest() == (
        module.ORIGINAL_AUDITOR_RAW_SHA256
    )
    assert hashlib.sha256(BASE_TEST.read_bytes()).hexdigest() == (module.ORIGINAL_TEST_RAW_SHA256)
    assert "frozen_full_audit_report" in source
    assert "explicit_two_source_envelope_with_three_hook_replacement" in source


def test_frozen_auditor_executes_the_exact_bytes_that_were_hashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    frozen = (
        tmp_path / "scripts" / "model_lab" / "pe_four_model_heldout_r3_post_generation_audit.py"
    )
    frozen.parent.mkdir(parents=True)
    frozen.write_bytes(BASE_SCRIPT.read_bytes())
    original_read_bytes = Path.read_bytes
    reads = 0

    def guarded_read_bytes(path: Path) -> bytes:
        nonlocal reads
        if path == frozen:
            reads += 1
            if reads > 1:
                raise AssertionError("loader reread the source after hashing")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    loaded = module._load_frozen_auditor(tmp_path)
    assert reads == 1
    assert loaded.sha256(b"payload") == hashlib.sha256(b"payload").hexdigest()


def test_independent_review_schema_and_zero_access_are_exact() -> None:
    module = _module()
    source_hash = "a" * 64
    test_hash = "b" * 64
    review = _valid_review(module, source_hash=source_hash, test_hash=test_hash)
    observed = module._validate_review(
        module.pretty_bytes(review),
        run_id=module.FORMAL_RUN_ID,
        adjudication_id=module.ADJUDICATION_ID,
        source_hash=source_hash,
        test_hash=test_hash,
    )
    assert observed["status"] == module.REVIEW_STATUS
    for mutation in ("extra_key", "truth_access", "source_drift"):
        attacked = json.loads(json.dumps(review))
        if mutation == "extra_key":
            attacked["extra"] = True
        elif mutation == "truth_access":
            attacked["preuse_access_evidence"]["truth_open_count"] = 1
        else:
            attacked["reviewed_source_raw_sha256"] = "c" * 64
        core = dict(attacked)
        core.pop("review_semantic_sha256", None)
        attacked["review_semantic_sha256"] = module.semantic_sha256(core)
        with pytest.raises(module.NativeIdentityError):
            module._validate_review(
                module.pretty_bytes(attacked),
                run_id=module.FORMAL_RUN_ID,
                adjudication_id=module.ADJUDICATION_ID,
                source_hash=source_hash,
                test_hash=test_hash,
            )


def test_full64_volume_exact_and_same_low32_changed_high32_fails() -> None:
    module = _module()
    base, state, _, validate = _state_and_validator(module)
    raw = b"payload"
    file_id = bytes.fromhex("0123456789abcdeffedcba9876543210")
    exact_volume = 0xB8EC13DFEC13972A
    info = _fake_info(module, volume=exact_volume, file_id=file_id)
    validate(
        _ref(module, volume=exact_volume, file_id=file_id),
        expected_relative_path="outputs/synthetic/payload.bin",
        raw=raw,
        info=info,
        state=state,
    )
    changed_high32 = 0x11111111EC13972A
    assert (changed_high32 & 0xFFFFFFFF) == (exact_volume & 0xFFFFFFFF)
    with pytest.raises(base.AuditFailure) as caught:
        validate(
            _ref(module, volume=changed_high32, file_id=file_id),
            expected_relative_path="outputs/synthetic/payload.bin",
            raw=raw,
            info=info,
            state=base.State(),
        )
    assert caught.value.code == "ARTIFACT_VOLUME"


@pytest.mark.parametrize(
    "changed",
    [
        bytes.fromhex("0123456789abcdef0000000000000001"),
        bytes.fromhex("0123456789abcdeffedcba9876543210")[::-1],
    ],
)
def test_full128_file_id_exact_and_byte_order(changed: bytes) -> None:
    module = _module()
    base, _, _, validate = _state_and_validator(module)
    raw = b"payload"
    exact = bytes.fromhex("0123456789abcdeffedcba9876543210")
    info = _fake_info(module, volume=0xB8EC13DFEC13972A, file_id=exact)
    with pytest.raises(base.AuditFailure) as caught:
        validate(
            _ref(module, volume=info.volume_serial_number, file_id=changed),
            expected_relative_path="outputs/synthetic/payload.bin",
            raw=raw,
            info=info,
            state=base.State(),
        )
    assert caught.value.code == "ARTIFACT_FILE_ID"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("raw_sha256", "0" * 64, "ARTIFACT_SHA"),
        ("size_bytes", 8, "ARTIFACT_SIZE"),
        ("relative_path", "outputs/synthetic/other.bin", "ARTIFACT_PATH"),
    ],
)
def test_hash_size_and_path_remain_exact(field: str, value: object, code: str) -> None:
    module = _module()
    base, _, _, validate = _state_and_validator(module)
    raw = b"payload"
    file_id = bytes.fromhex("0123456789abcdeffedcba9876543210")
    info = _fake_info(module, volume=17, file_id=file_id)
    ref = _ref(module, volume=17, file_id=file_id)
    ref[field] = value
    with pytest.raises(base.AuditFailure) as caught:
        validate(
            ref,
            expected_relative_path="outputs/synthetic/payload.bin",
            raw=raw,
            info=info,
            state=base.State(),
        )
    assert caught.value.code == code


def test_real_native_round_trip_and_producer_wire_contract(tmp_path: Path) -> None:
    module = _module()
    project = tmp_path / "project"
    leaf = project / "public" / "leaf.bin"
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(b"native-round-trip")
    raw, info = module.native_read(leaf)
    ref = module.producer_artifact_ref(leaf, project)
    assert raw == b"native-round-trip"
    assert ref["volume_serial_number"] == info.volume_serial_number
    assert ref["file_id_128"] == info.file_id_128.hex()
    assert len(info.file_id_128) == 16
    assert info.volume_serial_number > 0xFFFFFFFF
    assert (info.volume_serial_number & 0xFFFFFFFF) == leaf.stat().st_dev


def test_native_api_failure_has_no_stat_or_read_bytes_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    leaf = tmp_path / "leaf.bin"
    leaf.write_bytes(b"payload")
    calls = {"stat": 0, "read_bytes": 0}

    def fail_identity(*_args, **_kwargs):
        raise module.NativeIdentityError("injected FileIdInfo failure")

    def forbidden_stat(*_args, **_kwargs):
        calls["stat"] += 1
        raise AssertionError("stat fallback used")

    def forbidden_read(*_args, **_kwargs):
        calls["read_bytes"] += 1
        raise AssertionError("Path.read_bytes fallback used")

    monkeypatch.setattr(module, "_query_identity", fail_identity)
    monkeypatch.setattr(os, "stat", forbidden_stat)
    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    with pytest.raises(module.NativeIdentityError, match="FileIdInfo"):
        module.native_read(leaf)
    assert calls == {"stat": 0, "read_bytes": 0}


def test_allowlist_rejects_before_native_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    base = module._load_frozen_auditor(PROJECT_ROOT)
    allowed = tmp_path / "public"
    allowed.mkdir()
    outside = tmp_path / "protected" / "truth.csv"
    opened = 0

    def forbidden_open(_path):
        nonlocal opened
        opened += 1
        raise AssertionError("out-of-allowlist path reached native_read")

    telemetry = module.ReadTelemetry(
        authority_path=tmp_path / "authority.json",
        public_root=allowed,
        vault_manifest_path=tmp_path / "vault" / "VAULT_MANIFEST.json",
    )
    stable_read, _, _ = module._patched_hooks(base, telemetry)
    monkeypatch.setattr(module, "native_read", forbidden_open)
    with pytest.raises(base.AuditFailure) as caught:
        stable_read(outside, state=base.State())
    assert caught.value.code == "NATIVE_SAME_HANDLE_READ"
    assert opened == 0
    assert telemetry.unauthorized_read_attempt_count == 1
    assert telemetry.other_read_count == 0


def test_exact_scoped_read_rejects_escape_before_native_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    project = tmp_path / "project"
    project.mkdir()
    opened = 0

    def forbidden_open(_path):
        nonlocal opened
        opened += 1
        raise AssertionError("escaped path reached native_read")

    monkeypatch.setattr(module, "native_read", forbidden_open)
    for supplied in (
        tmp_path / "outside.json",
        project / "build" / ".." / "escape.json",
    ):
        with pytest.raises(module.NativeIdentityError, match="exact scope"):
            module._read_exact_project_file(
                project=project,
                supplied_path=supplied,
                expected_relative="build/exact.json",
                label="synthetic",
            )
    assert opened == 0


def test_preuse_authority_escape_stops_before_any_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    project = tmp_path / "project"
    project.mkdir()
    opened = 0

    def forbidden_open(_path):
        nonlocal opened
        opened += 1
        raise AssertionError("pre-use scope failure reached native_read")

    monkeypatch.setattr(module, "native_read", forbidden_open)
    with pytest.raises(module.NativeIdentityError, match="formal scope"):
        module.verify_preuse_authority(
            project=project,
            authority_path=tmp_path / "attacker.json",
            expected_raw_sha256="a" * 64,
            expected_semantic_sha256="b" * 64,
            run_id=module.FORMAL_RUN_ID,
            adjudication_id=module.ADJUDICATION_ID,
            execution_authority=project / module.EXECUTION_AUTHORITY_RELATIVE,
            execution_authority_raw_sha256=(module.EXPECTED_EXECUTION_AUTHORITY_RAW_SHA256),
            execution_authority_semantic_sha256=(
                module.EXPECTED_EXECUTION_AUTHORITY_SEMANTIC_SHA256
            ),
            public_replay_root=project / module.PUBLIC_REPLAY_RELATIVE,
            vault_manifest_path=project / module.VAULT_MANIFEST_RELATIVE,
            output_root=project / module.ADJUDICATION_OUTPUT_RELATIVE,
        )
    assert opened == 0


def test_reparse_point_is_rejected(tmp_path: Path) -> None:
    module = _module()
    target = tmp_path / "target.bin"
    link = tmp_path / "link.bin"
    target.write_bytes(b"payload")
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"Windows symlink creation unavailable: {exc}")
    with pytest.raises(module.NativeIdentityError, match="ordinary stable file"):
        module.native_read(link)


@pytest.mark.parametrize(
    ("attributes", "tag", "directory", "delete_pending"),
    [
        (0x80 | 0x400, 0, False, False),
        (0x80, 0xA000000C, False, False),
        (0x80 | 0x10, 0, True, False),
        (0x80, 0, False, True),
    ],
)
def test_snapshot_rejects_reparse_directory_tag_and_delete_pending(
    attributes: int,
    tag: int,
    directory: bool,
    delete_pending: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(
        module,
        "_query_identity",
        lambda _library, _handle: (17, bytes(range(16))),
    )
    monkeypatch.setattr(
        module,
        "_query_attributes",
        lambda _library, _handle: (attributes, tag),
    )
    monkeypatch.setattr(
        module,
        "_query_basic",
        lambda _library, _handle: (11, 13, attributes),
    )
    monkeypatch.setattr(
        module,
        "_query_standard",
        lambda _library, _handle: (7, 1, delete_pending, directory),
    )
    with pytest.raises(module.NativeIdentityError, match="ordinary stable file"):
        module._snapshot(object(), 1234)


def test_all_native_observations_and_bytes_use_the_single_created_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    leaf = tmp_path / "leaf.bin"
    leaf.write_bytes(b"payload")
    observed_handles: list[tuple[str, int]] = []

    class FakeLibrary:
        @staticmethod
        def CreateFileW(*_args):
            return 9876

        @staticmethod
        def CloseHandle(handle):
            observed_handles.append(("close", int(handle.value)))
            return True

    info = _fake_info(module, volume=17, file_id=bytes(range(16)))

    def snapshot(_library, handle):
        observed_handles.append(("snapshot", handle))
        return info

    def final_path(_library, handle):
        observed_handles.append(("final_path", handle))
        return str(leaf.absolute())

    def read_exact(_library, handle, size):
        observed_handles.append(("read", handle))
        assert size == 7
        return b"payload"

    monkeypatch.setattr(module, "_kernel32", lambda: FakeLibrary())
    monkeypatch.setattr(module, "_snapshot", snapshot)
    monkeypatch.setattr(module, "_final_path", final_path)
    monkeypatch.setattr(module, "_read_exact", read_exact)
    assert module.native_read(leaf) == (b"payload", info)
    assert observed_handles == [
        ("snapshot", 9876),
        ("final_path", 9876),
        ("read", 9876),
        ("snapshot", 9876),
        ("final_path", 9876),
        ("close", 9876),
    ]


def test_pre_post_identity_mutation_and_final_path_swap_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    leaf = tmp_path / "leaf.bin"
    leaf.write_bytes(b"payload")
    original_snapshot = module._snapshot
    calls = 0

    def changed_snapshot(library, handle):
        nonlocal calls
        calls += 1
        observed = original_snapshot(library, handle)
        if calls == 2:
            return _fake_info(
                module,
                volume=observed.volume_serial_number ^ (1 << 48),
                file_id=observed.file_id_128,
            )
        return observed

    monkeypatch.setattr(module, "_snapshot", changed_snapshot)
    with pytest.raises(module.NativeIdentityError, match="changed"):
        module.native_read(leaf)
    monkeypatch.setattr(module, "_snapshot", original_snapshot)
    monkeypatch.setattr(module, "_final_path", lambda *_args: str(tmp_path / "swap.bin"))
    with pytest.raises(module.NativeIdentityError, match="final path differs"):
        module.native_read(leaf)


def test_share_mode_denies_concurrent_write_and_delete(tmp_path: Path) -> None:
    module = _module()
    leaf = tmp_path / "leaf.bin"
    leaf.write_bytes(b"payload")
    library = module._kernel32()
    handle = library.CreateFileW(
        str(leaf.absolute()),
        module._GENERIC_READ | module._FILE_READ_ATTRIBUTES | module._SYNCHRONIZE,
        module._FILE_SHARE_READ,
        None,
        module._OPEN_EXISTING,
        module._FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    numeric = int(handle or 0)
    assert numeric not in (0, module._INVALID_HANDLE_VALUE)
    try:
        with pytest.raises(PermissionError):
            leaf.write_bytes(b"mutated")
        with pytest.raises(PermissionError):
            leaf.unlink()
    finally:
        assert library.CloseHandle(module.wintypes.HANDLE(numeric))
    assert leaf.read_bytes() == b"payload"


def test_duplicate_native_identity_is_rejected_as_public_hardlink(
    tmp_path: Path,
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    alias = tmp_path / "alias.bin"
    source.write_bytes(b"payload")
    os.link(source, alias)
    _, first = module.native_read(source)
    _, second = module.native_read(alias)
    assert first.volume_serial_number == second.volume_serial_number
    assert first.file_id_128 == second.file_id_128
    base, state, register, _ = _state_and_validator(module)
    register(first, state=state)
    with pytest.raises(base.AuditFailure) as caught:
        register(second, state=state)
    assert caught.value.code == "PUBLIC_HARDLINK"


def test_frozen_hooks_are_restored_even_when_full_audit_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()

    def original_stable(*_args, **_kwargs):
        return None

    def original_register(*_args, **_kwargs):
        return None

    def original_validate(*_args, **_kwargs):
        return None

    fake = SimpleNamespace(
        stable_read=original_stable,
        _register_public=original_register,
        validate_ref=original_validate,
        run_audit=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic failure")
        ),
    )
    monkeypatch.setattr(module, "_load_frozen_auditor", lambda _project: fake)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        module.run_corrected_base_audit(
            tmp_path,
            run_id="r3_synthetic",
            execution_authority=tmp_path / "authority.json",
            authority_semantic_sha256="a" * 64,
            authority_raw_sha256="b" * 64,
            public_replay_root=tmp_path / "public",
            vault_manifest_path=tmp_path / "vault" / "VAULT_MANIFEST.json",
        )
    assert fake.stable_read is original_stable
    assert fake._register_public is original_register
    assert fake.validate_ref is original_validate


def test_full_synthetic_50_task_201_file_audit_passes_native_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    fixture_provider = _base_test_module()
    base = fixture_provider._module()
    monkeypatch.setattr(
        fixture_provider,
        "_artifact_ref",
        lambda _base, path, project: module.producer_artifact_ref(path, project),
    )
    fixture = fixture_provider._write_full_synthetic_tree(tmp_path, base)
    frozen_source = (
        fixture["project"]
        / "scripts"
        / "model_lab"
        / "pe_four_model_heldout_r3_post_generation_audit.py"
    )
    frozen_source.parent.mkdir(parents=True)
    frozen_source.write_bytes(BASE_SCRIPT.read_bytes())
    report, telemetry = module.run_corrected_base_audit(
        fixture["project"],
        run_id=fixture["run_id"],
        execution_authority=fixture["authority_path"],
        authority_semantic_sha256=fixture["authority"]["execution_authority_semantic_sha256"],
        authority_raw_sha256=base.sha256(fixture["authority_raw"]),
        public_replay_root=fixture["public_root"],
        vault_manifest_path=fixture["vault_manifest_path"],
    )
    evidence = telemetry.evidence()
    assert report["status"] == "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"
    assert report["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0}
    assert report["public_evidence"]["task_count"] == 50
    assert report["public_evidence"]["public_file_count"] == 201
    assert evidence == {
        "authority_native_read_count": 1,
        "public_native_read_count": 201,
        "unique_public_path_count": 201,
        "vault_manifest_native_read_count": 1,
        "other_native_read_count": 0,
        "unauthorized_read_attempt_count": 0,
        "allowlist_authorization_preceded_native_open": True,
        "protected_payload_directories_enumerated": False,
        "protected_payload_refs_resolved_or_statted": 0,
        "protected_payload_leaves_opened": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
    }


def test_duplicate_json_and_create_new_invocation_are_fail_closed(
    tmp_path: Path,
) -> None:
    module = _module()
    with pytest.raises(module.NativeIdentityError, match="invalid JSON"):
        module._parse_pretty_json(b'{"a":1,"a":2}\n', label="synthetic")
    project = tmp_path / "project"
    (project / "build").mkdir(parents=True)
    root = project / module.ADJUDICATION_OUTPUT_RELATIVE
    root, claim, claim_raw = module.claim_invocation(
        project=project,
        output_root=root,
        run_id="r3_synthetic",
        adjudication_id="synthetic",
        authority_relative="build/authority.json",
        authority_raw_sha256="a" * 64,
        authority_semantic_sha256="b" * 64,
    )
    assert claim["consumed_invocation_count"] == 1
    assert claim["formal_generation_read_count_at_claim"] == 0
    assert (
        hashlib.sha256(claim_raw).hexdigest()
        == hashlib.sha256((root / module.CLAIM_NAME).read_bytes()).hexdigest()
    )
    assert (root / module.CLAIM_NAME).is_file()
    with pytest.raises(module.NativeIdentityError, match="create-new"):
        module.claim_invocation(
            project=project,
            output_root=root,
            run_id="r3_synthetic",
            adjudication_id="synthetic",
            authority_relative="build/authority.json",
            authority_raw_sha256="a" * 64,
            authority_semantic_sha256="b" * 64,
        )


def test_original_no_go_is_still_exact_and_not_reclassified() -> None:
    module = _module()
    path = PROJECT_ROOT / module.ORIGINAL_NO_GO_RELATIVE
    raw = path.read_bytes()
    report = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == module.ORIGINAL_NO_GO_RAW_SHA256
    assert report["audit_semantic_sha256"] == (module.ORIGINAL_NO_GO_SEMANTIC_SHA256)
    assert report["status"] == "NO_GO_R3_POST_GENERATION_AUDIT"
    assert report["finding_counts"] == {"P0": 1, "P1": 0, "P2": 0}
    assert [item["code"] for item in report["findings"]] == ["ARTIFACT_VOLUME"]
    assert module.REPORT_SCHEMA != report["schema_version"]
    assert module.GO_STATUS != "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"


def test_report_binds_live_claim_raw_bytes_and_exact_two_leaf_output(
    tmp_path: Path,
) -> None:
    module = _module()
    claim = {
        "schema_version": module.CLAIM_SCHEMA,
        "status": module.CLAIM_STATUS,
        "run_id": module.FORMAL_RUN_ID,
        "adjudication_id": module.ADJUDICATION_ID,
        "preuse_authority_relative_path": module.PREUSE_AUTHORITY_RELATIVE,
        "preuse_authority_raw_sha256": "b" * 64,
        "preuse_authority_semantic_sha256": "c" * 64,
        "authorized_invocation_count": 1,
        "consumed_invocation_count": 1,
        "retry_allowed": False,
        "formal_generation_read_count_at_claim": 0,
        "formal_generation_read_permitted_only_after_claim": True,
    }
    claim["claim_semantic_sha256"] = module.semantic_sha256(claim)
    claim_raw = module.pretty_bytes(claim)
    authority = {
        "status": module.AUTHORITY_STATUS,
        "run_id": module.FORMAL_RUN_ID,
        "adjudication_id": module.ADJUDICATION_ID,
        "original_no_go_binding": {},
        "generation_binding": {},
        "identity_correction": {},
        "corrected_auditor_binding": {},
    }
    telemetry = module.ReadTelemetry(
        authority_path=tmp_path / "authority.json",
        public_root=tmp_path / "public",
        vault_manifest_path=tmp_path / "vault" / "VAULT_MANIFEST.json",
    )
    postuse = {
        "status": "PASS_ALL_PREUSE_AND_CLAIM_BYTES_REVERIFIED_POST_AUDIT",
        "file_count": 8,
        "files": {},
    }
    base_report = {
        "status": "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0",
        "audit_check_count": 1,
        "audit_semantic_sha256": "a" * 64,
    }
    report = module.build_report(
        authority=authority,
        authority_relative=module.PREUSE_AUTHORITY_RELATIVE,
        authority_raw_sha256="b" * 64,
        authority_semantic_sha256="c" * 64,
        claim=claim,
        claim_raw=claim_raw,
        base_report=base_report,
        telemetry=telemetry,
        findings=[],
        postuse_evidence=postuse,
    )
    assert report["invocation_claim"]["raw_sha256"] == hashlib.sha256(claim_raw).hexdigest()
    assert report["invocation_claim"]["size_bytes"] == len(claim_raw)
    assert report["invocation_claim"]["live_bytes_reverified_after_full_audit"]
    root = tmp_path / "published"
    root.mkdir()
    (root / module.CLAIM_NAME).write_bytes(claim_raw)
    raw_hash = module.publish_report(root, report)
    assert raw_hash == hashlib.sha256((root / module.REPORT_NAME).read_bytes()).hexdigest()
    assert {path.name for path in root.iterdir()} == {
        module.CLAIM_NAME,
        module.REPORT_NAME,
    }
    claim_attack_root = tmp_path / "claim_attack"
    claim_attack_root.mkdir()
    (claim_attack_root / module.CLAIM_NAME).write_bytes(claim_raw + b"tampered")
    with pytest.raises(module.NativeIdentityError, match="claim raw bytes"):
        module.publish_report(claim_attack_root, report)
    attacked_root = tmp_path / "attacked"
    attacked_root.mkdir()
    (attacked_root / module.CLAIM_NAME).write_bytes(claim_raw)
    (attacked_root / "EXTRA.json").write_bytes(b"extra")
    with pytest.raises(module.NativeIdentityError, match="leaf universe"):
        module.publish_report(attacked_root, report)


def test_postuse_reverification_rejects_claim_raw_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    authority_raw = b"authority"
    claim_raw = b"claim"
    corrected_source = b"corrected-source"
    corrected_test = b"corrected-test"
    review_raw = b"review"
    original_no_go = (PROJECT_ROOT / module.ORIGINAL_NO_GO_RELATIVE).read_bytes()
    original_source = (PROJECT_ROOT / module.ORIGINAL_AUDITOR_RELATIVE).read_bytes()
    original_test = (PROJECT_ROOT / module.ORIGINAL_TEST_RELATIVE).read_bytes()
    authority = {
        "corrected_auditor_binding": {
            "new_source_raw_sha256": module.sha256(corrected_source),
            "test_raw_sha256": module.sha256(corrected_test),
        },
        "required_preuse_review": {"independent_review_raw_sha256": module.sha256(review_raw)},
    }
    mapping = {
        module.PREUSE_AUTHORITY_RELATIVE: authority_raw,
        module.ORIGINAL_NO_GO_RELATIVE: original_no_go,
        module.ORIGINAL_AUDITOR_RELATIVE: original_source,
        module.ORIGINAL_TEST_RELATIVE: original_test,
        module.CORRECTED_AUDITOR_RELATIVE: corrected_source,
        module.CORRECTED_TEST_RELATIVE: corrected_test,
        module.PREUSE_REVIEW_RELATIVE: review_raw,
        f"{module.ADJUDICATION_OUTPUT_RELATIVE}/{module.CLAIM_NAME}": b"tampered",
    }

    def fake_read(*, expected_relative: str, **_kwargs):
        return mapping[expected_relative]

    monkeypatch.setattr(module, "_read_exact_project_file", fake_read)
    with pytest.raises(module.NativeIdentityError, match="invocation_claim"):
        module.postuse_reverify(
            project=tmp_path,
            authority=authority,
            authority_raw=authority_raw,
            claim_path=tmp_path / module.CLAIM_NAME,
            claim_raw=claim_raw,
        )


def test_main_claims_before_formal_read_and_retains_failure_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    project = tmp_path / "project"
    project.mkdir()
    order: list[str] = []
    args = SimpleNamespace(
        project_root=project,
        run_id=module.FORMAL_RUN_ID,
        adjudication_id=module.ADJUDICATION_ID,
        preuse_authority=project / module.PREUSE_AUTHORITY_RELATIVE,
        preuse_authority_raw_sha256="a" * 64,
        preuse_authority_semantic_sha256="b" * 64,
        execution_authority=project / module.EXECUTION_AUTHORITY_RELATIVE,
        execution_authority_raw_sha256=(module.EXPECTED_EXECUTION_AUTHORITY_RAW_SHA256),
        execution_authority_semantic_sha256=(module.EXPECTED_EXECUTION_AUTHORITY_SEMANTIC_SHA256),
        public_replay_root=project / module.PUBLIC_REPLAY_RELATIVE,
        vault_manifest=project / module.VAULT_MANIFEST_RELATIVE,
        output_root=project / module.ADJUDICATION_OUTPUT_RELATIVE,
    )
    parser = SimpleNamespace(parse_args=lambda: args)
    authority = {
        "status": module.AUTHORITY_STATUS,
        "run_id": module.FORMAL_RUN_ID,
        "adjudication_id": module.ADJUDICATION_ID,
    }
    claim = {
        "status": module.CLAIM_STATUS,
        "claim_semantic_sha256": "c" * 64,
    }
    root = args.output_root

    def verify(**_kwargs):
        order.append("verify")
        return authority, b"authority"

    def claim_call(**_kwargs):
        order.append("claim")
        return root, claim, b"claim"

    def formal_read(*_args, **_kwargs):
        order.append("formal_read")
        assert order.index("claim") < order.index("formal_read")
        raise RuntimeError("terminal synthetic failure")

    def postuse(**_kwargs):
        order.append("postuse")
        return {"status": "PASS", "file_count": 8, "files": {}}

    def build(**kwargs):
        order.append("build_report")
        assert kwargs["telemetry"] is not None
        assert kwargs["telemetry"].evidence()["truth_open_count"] == 0
        assert kwargs["findings"][0]["severity"] == "P0"
        return {
            "status": module.NO_GO_STATUS,
            "audit_semantic_sha256": "d" * 64,
            "finding_counts": {"P0": 1, "P1": 0, "P2": 0},
        }

    monkeypatch.setattr(module, "_parser", lambda: parser)
    monkeypatch.setattr(module, "verify_preuse_authority", verify)
    monkeypatch.setattr(module, "claim_invocation", claim_call)
    monkeypatch.setattr(module, "run_corrected_base_audit", formal_read)
    monkeypatch.setattr(module, "postuse_reverify", postuse)
    monkeypatch.setattr(module, "build_report", build)
    monkeypatch.setattr(module, "publish_report", lambda *_args: "e" * 64)
    assert module.main() == 2
    assert order == [
        "verify",
        "claim",
        "formal_read",
        "postuse",
        "build_report",
    ]


def test_formal_execution_authority_pins_are_copied_exactly() -> None:
    module = _module()
    authority_path = (
        PROJECT_ROOT / "build" / "pe_four_model_heldout_execution_authority_r3_20260824T134417.json"
    )
    raw = authority_path.read_bytes()
    authority = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == (module.EXPECTED_EXECUTION_AUTHORITY_RAW_SHA256)
    assert authority["execution_authority_semantic_sha256"] == (
        module.EXPECTED_EXECUTION_AUTHORITY_SEMANTIC_SHA256
    )
    assert authority["generation_plan_semantic_sha256"] == (
        module.EXPECTED_GENERATION_PLAN_SEMANTIC_SHA256
    )
