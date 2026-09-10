from __future__ import annotations

import ast
import io
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_phase2_role_archives_v4_source_v1 import (  # noqa: E501
    contracts,
    freezer,
)


def _build(role: str) -> bytes:
    return freezer.build_role_archive(role)[0]


def _rewrite(raw: bytes, changes: dict[str, bytes], *, extra: tuple[str, bytes] | None = None) -> bytes:
    with zipfile.ZipFile(io.BytesIO(raw), "r") as source:
        members = {name: source.read(name) for name in source.namelist()}
    members.update(changes)
    if extra is not None:
        members[extra[0]] = extra[1]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            archive.writestr(freezer._zip_info(name), members[name])
    return buffer.getvalue()


def _clean_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.upper().startswith("PYTHON")}


def _run_archive(tmp_path: Path, role: str, *, data: bytes, args: tuple[str, ...] = (), env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    path = tmp_path / f"{role}.pyz"
    path.write_bytes(_build(role))
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(path), *args],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_clean_environment() if env is None else env,
        check=False,
        timeout=30,
    )


def test_all_six_archives_double_build_bitwise_and_are_distinct() -> None:
    receipt = freezer.run_tmp_only_double_build()
    assert receipt["status"] == "PASS_TMP_ONLY_DOUBLE_BUILD_SOURCE_ONLY_DENY"
    assert receipt["archive_count"] == 6
    assert receipt["archive_build_count"] == 12
    assert receipt["unique_archive_hash_count"] == 6
    assert receipt["temporary_artifact_count_after_cleanup"] == 0
    assert all(row["double_build_bit_equal"] is True for row in receipt["records"])


@pytest.mark.parametrize("role", contracts.ROLE_NAMES)
def test_archive_has_exact_members_metadata_and_entry_hashes(role: str) -> None:
    raw, receipt = freezer.build_role_archive(role)
    assert receipt["role"] == role
    assert receipt["entry_count"] == 3
    assert set(receipt["entry_raw_sha256"]) == set(contracts.ARCHIVE_MEMBERS)
    assert receipt["final_binding_present"] is False
    freezer.verify_archive_bytes(raw, expected_role=role)


def test_public_archive_absence_is_raw_member_and_ast_closed() -> None:
    raw = _build("PUBLIC")
    lowered = raw.lower()
    assert all(token not in lowered for token in contracts.PUBLIC_FORBIDDEN_TOKENS)
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        main = archive.read("__main__.py")
        assert all(token not in main.lower() for token in contracts.PUBLIC_FORBIDDEN_TOKENS)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(ast.parse(main))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
    assert imports == {"os", "sys"}


@pytest.mark.parametrize("bad", ["../x.py", "/x.py", "x\\y.py", "a/./b", "a/../b", "x\x00y"])
def test_archive_member_name_traversal_is_rejected(bad: str) -> None:
    with pytest.raises(contracts.RoleArchiveSourceError):
        freezer.validate_member_payloads({bad: b"x"})


def test_duplicate_casefold_member_and_extra_member_are_rejected() -> None:
    with pytest.raises(contracts.RoleArchiveSourceError, match="duplicate"):
        freezer.validate_member_payloads({"A.py": b"x", "a.py": b"y"})
    raw = _rewrite(_build("MONITOR"), {}, extra=("EXTRA.txt", b"x"))
    with pytest.raises(contracts.RoleArchiveSourceError, match="universe"):
        freezer.verify_archive_bytes(raw, expected_role="MONITOR")


def test_recursive_embed_and_cycle_field_are_rejected() -> None:
    with pytest.raises(contracts.RoleArchiveSourceError, match="recursive"):
        freezer.validate_member_payloads({"nested.pyz": b"not even a zip"})
    raw = _build("AUDITOR")
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        contract = archive.read("ARCHIVE_CONTRACT.json")
    tampered = contract[:-1] + b',"archive_raw_sha256":"' + b"1" * 64 + b'"}'
    altered = _rewrite(raw, {"ARCHIVE_CONTRACT.json": tampered})
    with pytest.raises(contracts.RoleArchiveSourceError):
        freezer.verify_archive_bytes(altered, expected_role="AUDITOR")


def test_zero_hash_and_bool_as_int_are_rejected() -> None:
    with pytest.raises(contracts.RoleArchiveSourceError, match="nonzero"):
        contracts.validate_nonzero_sha256("0" * 64, label="test")
    with pytest.raises(contracts.RoleArchiveSourceError, match="integer"):
        contracts.role_name_from_ordinal(True)


def test_source_snapshot_detects_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"x = 1\n")
    monkeypatch.setattr(freezer, "PROJECT_ROOT", tmp_path)
    snapshot = freezer.snapshot_source(source)
    source.write_bytes(b"x = 2\n")
    with pytest.raises(contracts.RoleArchiveSourceError, match="mutated"):
        freezer.assert_source_snapshot_current(snapshot)


def test_symlink_source_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.py"
    link = tmp_path / "link.py"
    source.write_bytes(b"x = 1\n")
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("file symlink privilege unavailable")
    monkeypatch.setattr(freezer, "PROJECT_ROOT", tmp_path)
    with pytest.raises(contracts.RoleArchiveSourceError, match="symlink|reparse"):
        freezer.snapshot_source(link)


@pytest.mark.parametrize("role", contracts.ROLE_NAMES)
def test_each_bootstrap_accepts_only_exact_frame_then_denies(tmp_path: Path, role: str) -> None:
    result = _run_archive(tmp_path, role, data=contracts.ACTIVATION_FRAME)
    assert result.returncode == contracts.SOURCE_ONLY_DENY_EXIT
    assert result.stdout == f'{{"role":"{role}","status":"SOURCE_ONLY_DENY"}}\n'.encode()
    assert result.stderr == b""


def test_bootstrap_rejects_argv_before_reading_or_denying(tmp_path: Path) -> None:
    result = _run_archive(tmp_path, "SUPERVISOR", data=contracts.ACTIVATION_FRAME, args=("caller-path",))
    assert result.returncode == contracts.BOOTSTRAP_ARGV_REJECT_EXIT
    assert result.stdout == result.stderr == b""


def test_bootstrap_rejects_python_environment_before_denying(tmp_path: Path) -> None:
    environment = _clean_environment()
    environment["PyThOnPaTh"] = "caller-control"
    result = _run_archive(tmp_path, "MONITOR", data=contracts.ACTIVATION_FRAME, env=environment)
    assert result.returncode == contracts.BOOTSTRAP_ENV_REJECT_EXIT
    assert result.stdout == result.stderr == b""


@pytest.mark.parametrize("attack", [b"", b"{}\n", contracts.ACTIVATION_FRAME + b"x"])
def test_bootstrap_rejects_input_before_source_only_deny(tmp_path: Path, attack: bytes) -> None:
    result = _run_archive(tmp_path, "PUBLIC", data=attack)
    assert result.returncode == contracts.BOOTSTRAP_FRAME_REJECT_EXIT
    assert result.stdout == b""
    assert result.stderr == b"SOURCE_ONLY_BOOTSTRAP_REJECT\n"


def test_source_contract_has_no_paths_records_grants_or_live_counts() -> None:
    raw = _build("SIGNER")
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        contract = freezer._parse_canonical_object(archive.read("ARCHIVE_CONTRACT.json"), label="contract")
    assert contract["caller_archive_path_count"] == 0
    assert contract["caller_record_count"] == 0
    assert contract["caller_grant_count"] == 0
    assert contract["final_binding_present"] is False
    assert all(contract[key] == 0 for key in freezer.CONTRACT_KEYS if key.endswith("_count"))


def test_no_final_archive_or_authority_api_exists() -> None:
    assert not hasattr(freezer, "publish")
    assert not hasattr(freezer, "issue_authority")
    assert not hasattr(freezer, "sign_grant")
    assert contracts.SOURCE_ONLY_BLOCKERS
