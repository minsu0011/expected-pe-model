from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import re
from argparse import Namespace
import importlib.util

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (
    R8R7DesignError,
    SupervisorDirectoryCustody,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
    R7QualificationGenerationError,
)

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.contracts import (
    LEGACY_TERMINATOR_INCLUSIVE_SHA256,
    PROJECT_ROOT,
    PUBLIC_HEADER_CONTENT_SHA256,
    R4_REFERENCE_RAW_SHA256,
    R4_REFERENCE_ROOT_RELATIVE,
    R4_REFERENCE_TASK_RELATIVE,
    R8_R7_STATIC_LOCAL_FILES,
    R8_R7_STATIC_PACKAGE_RELATIVE,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.controller import (
    validate_planned_public_path,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.no_bytecode import (
    HeldExistingNoBytecodeWindow,
    HeldNoBytecodeWindow,
    NoBytecodeContractError,
    exact_python_command,
    require_postrun_pycache_zero,
    sealed_environment,
    sealed_grandchild_environment,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.raw_header import (
    RawHeaderContractError,
    UTF8_BOM,
    raw_header_content_without_terminator,
    raw_header_sha256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_evidence import (
    capture_static_source_revision_evidence,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (
    BUILDER_SCRIPT_RELATIVE,
    DESIGN_FILE_UNIVERSE,
    FREEZER_SCRIPT_RELATIVE,
    FUTURE_SOURCE_LOCK_RELATIVE,
    OUTER_BOOTSTRAP_RELATIVE,
    PACKAGE_FILES,
    SCRIPT_EXACT_UNIVERSE,
    build_in_memory_receipt,
    build_source_lock_bytes,
    build_static_bundle_bytes,
    verify_static_bundle_bytes,
    _plain_directory_records,
)


def _reference(name: str) -> bytes:
    return (
        PROJECT_ROOT / R4_REFERENCE_ROOT_RELATIVE / R4_REFERENCE_TASK_RELATIVE / name
    ).read_bytes()


def _base_environment_without_python_controls() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }


def test_actual_r4_child_surfaces_match_content_without_terminator_contract() -> None:
    for name, expected in PUBLIC_HEADER_CONTENT_SHA256.items():
        raw = _reference(name)
        assert hashlib.sha256(raw).hexdigest() == R4_REFERENCE_RAW_SHA256[name]
        assert raw.startswith(UTF8_BOM)
        assert b"\r\n" in raw
        assert raw_header_sha256(raw) == expected
        assert raw_header_sha256(raw) != LEGACY_TERMINATOR_INCLUSIVE_SHA256[name]


def test_all_three_r8_r8_execution_consumers_call_the_central_helper() -> None:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation import (
        controller,
        public_role,
        replay,
    )

    modules = (replay, public_role, controller)
    for name, expected in PUBLIC_HEADER_CONTENT_SHA256.items():
        raw = _reference(name)
        assert all(module._raw_header_sha256(raw) == expected for module in modules)
    for module in modules:
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert 'split(b"\\n", 1)[0] + b"\\n"' not in source
        assert "return raw_header_sha256(content)" in source


def test_lf_and_crlf_spellings_have_the_same_bom_preserving_contract() -> None:
    header = UTF8_BOM + b"date,observed_pe"
    lf = header + b"\n2020-01-01,7\n"
    crlf = header + b"\r\n2020-01-01,7\r\n"
    assert raw_header_content_without_terminator(lf) == header
    assert raw_header_content_without_terminator(crlf) == header
    assert raw_header_sha256(lf) == raw_header_sha256(crlf)
    assert raw_header_sha256(lf) == hashlib.sha256(header).hexdigest()


@pytest.mark.parametrize(
    "attacked",
    [
        b"date,observed_pe",
        UTF8_BOM + b"date,observed_pe",
        b"",
        b"\n",
        UTF8_BOM + b"\n",
    ],
)
def test_truncated_no_lf_and_empty_headers_are_rejected(attacked: bytes) -> None:
    with pytest.raises(RawHeaderContractError):
        raw_header_sha256(attacked)


@pytest.mark.parametrize(
    "attacked",
    [
        b"date\robserved_pe\n1,2\n",
        b"date,observed_pe\r\r\n1,2\r\n",
        UTF8_BOM + b"date\r,observed_pe\r\n1,2\r\n",
    ],
)
def test_embedded_or_multiple_cr_bytes_are_rejected(attacked: bytes) -> None:
    with pytest.raises(RawHeaderContractError, match="embedded CR"):
        raw_header_sha256(attacked)


def test_non_bytes_input_is_rejected_without_coercion() -> None:
    with pytest.raises(RawHeaderContractError, match="exact bytes"):
        raw_header_content_without_terminator("date\n")  # type: ignore[arg-type]


def test_static_evidence_reopens_predecessors_and_actual_spent_bytes() -> None:
    receipt = capture_static_source_revision_evidence()
    assert receipt["evidence_class"] == "STATIC_SOURCE_REVISION_NO_AUTHORITY"
    assert receipt["authority_or_generation_executed"] is False
    assert receipt["requires_new_static_freeze_and_independent_audit"] is True
    assert receipt["header_contract"] == {
        "bom_preserved": True,
        "mandatory_lf": True,
        "optional_single_cr_immediately_before_lf_removed": True,
        "terminator_hashed": False,
        "embedded_cr_rejected": True,
        "lf_and_crlf_same_contract_hash": True,
    }
    assert set(receipt["spent_reference"]) == {"canonical150.csv", "v04_overlay.csv"}
    assert all(
        row["legacy_equal"] is False for row in receipt["spent_reference"].values()
    )
    c1 = receipt["cross_package_findings"]["pe_c1_c3_fresh_qualification_service_v1"]
    assert c1["audited_pre_revision_actual_crlf_common_bytes_callable"] is False
    assert c1["c1_files_modified_by_r8_r8"] is False
    assert c1["dynamic_current_workspace_hash_count"] == 0
    assert c1["stable_successor_checksums_raw_sha256"] == (
        "d04bca7d5d46da28c3042dec4accf9dd7fabcb625a23f7999cfd5dedd87dd22f"
    )


def test_exact_child_command_and_environment_require_empty_prefix(tmp_path: Path) -> None:
    entry = tmp_path / "probe.py"
    entry.write_text("print('ok')\n", encoding="utf-8")
    prefix = tmp_path / "pc"
    prefix.mkdir()
    command = exact_python_command(
        python=Path(sys.executable), entry=entry, pycache_prefix=prefix
    )
    assert command[1:8] == (
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={prefix}",
        str(entry.resolve()),
    )
    environment = sealed_environment(
        base=_base_environment_without_python_controls(), pycache_prefix=prefix
    )
    assert not any(key.upper().startswith("PYTHON") for key in environment)
    (prefix / "preexisting.pyc").write_bytes(b"attack")
    with pytest.raises(NoBytecodeContractError, match="empty before launch"):
        sealed_environment(base=_base_environment_without_python_controls(), pycache_prefix=prefix)


def test_hostile_python_environment_is_rejected(tmp_path: Path) -> None:
    prefix = tmp_path / "pc"
    prefix.mkdir()
    with pytest.raises(NoBytecodeContractError, match="contains PYTHON variables"):
        sealed_environment(base={"PYTHONPATH": "attack"}, pycache_prefix=prefix)


@pytest.mark.parametrize(
    "relative,module_name",
    [
        (BUILDER_SCRIPT_RELATIVE, "r8r8_builder_entry_environment_test"),
        (FREEZER_SCRIPT_RELATIVE, "r8r8_freezer_entry_environment_test"),
    ],
)
def test_static_entries_detect_every_case_insensitive_python_prefix(
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    module_name: str,
) -> None:
    path = PROJECT_ROOT / relative
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("pYtHoN_future_hostile_control", "attack")
    assert "python_future_hostile_control" in {
        name.casefold() for name in module._python_environment_names()
    }


def test_grandchild_environment_strips_two_e_ignored_diagnostic_controls(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "pc"
    prefix.mkdir()
    environment = sealed_grandchild_environment(
        base={"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1", "SYSTEMROOT": "x"},
        pycache_prefix=prefix,
    )
    assert not any(key.upper().startswith("PYTHON") for key in environment)
    with pytest.raises(NoBytecodeContractError, match="grandchild Python environment drifted"):
        sealed_grandchild_environment(
            base={"PYTHONHASHSEED": "1", "PYTHONNOUSERSITE": "1"},
            pycache_prefix=prefix,
        )


def test_actual_isolated_child_produces_no_bytecode(tmp_path: Path) -> None:
    entry = tmp_path / "probe.py"
    entry.write_text(
        "import json,os,sys\n"
        "print(json.dumps({'dont':sys.dont_write_bytecode,'isolated':sys.flags.isolated,"
        "'ignore_environment':sys.flags.ignore_environment,'no_site':sys.flags.no_site,"
        "'prefix':sys.pycache_prefix,'python_env':sorted(k for k in os.environ "
        "if k.upper().startswith('PYTHON'))}))\n",
        encoding="utf-8",
    )
    prefix = tmp_path / "pc"
    prefix.mkdir()
    command = exact_python_command(
        python=Path(sys.executable), entry=entry, pycache_prefix=prefix
    )
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        env=sealed_environment(
            base=_base_environment_without_python_controls(), pycache_prefix=prefix
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "dont": True,
        "ignore_environment": 1,
        "isolated": 1,
        "no_site": 1,
        "prefix": str(prefix),
        "python_env": [],
    }
    require_postrun_pycache_zero(prefix)


def test_postrun_pycache_write_is_fail_closed(tmp_path: Path) -> None:
    prefix = tmp_path / "pc"
    prefix.mkdir()
    (prefix / "unexpected.pyc").write_bytes(b"not allowed")
    with pytest.raises(NoBytecodeContractError, match="entry count drifted: 1"):
        require_postrun_pycache_zero(prefix)


def test_postrun_empty_directory_is_not_invisible(tmp_path: Path) -> None:
    prefix = tmp_path / "pc"
    prefix.mkdir()
    (prefix / "empty_but_mutated").mkdir()
    with pytest.raises(NoBytecodeContractError, match="entry count drifted: 1"):
        require_postrun_pycache_zero(prefix)


def test_held_create_new_prefix_binds_file_id_and_stays_empty(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    entry = tmp_path / "probe.py"
    entry.write_text("import sys\nassert sys.dont_write_bytecode\n", encoding="utf-8")
    with HeldNoBytecodeWindow(
        parent=parent, child_name="pc_exact_once", ancestry_root=tmp_path
    ) as window:
        command = exact_python_command(
            python=Path(sys.executable),
            entry=entry,
            pycache_prefix=window.path,
        )
        completed = subprocess.run(
            command,
            cwd=tmp_path,
            env=window.environment(base=_base_environment_without_python_controls()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        receipt = window.receipt()
        assert receipt["postrun_file_count"] == 0
        assert receipt["held_before"]["file_id_128"] == receipt["held_after"]["file_id_128"]
        assert receipt["held_before"]["volume_serial_number"] == receipt["held_after"]["volume_serial_number"]


def test_preexisting_empty_prefix_is_not_reused(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "pc_exact_once").mkdir()
    with pytest.raises(R8R7DesignError, match="already exists"):
        with HeldNoBytecodeWindow(
            parent=parent, child_name="pc_exact_once", ancestry_root=tmp_path
        ):
            raise AssertionError("preexisting prefix must prevent context entry")


def test_parent_created_prefix_and_bootstrap_reopen_share_exact_file_id(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    with HeldNoBytecodeWindow(
        parent=parent, child_name="pc_parent_owned", ancestry_root=tmp_path
    ) as owner:
        owner_before = owner.receipt()["held_before"]
        with HeldExistingNoBytecodeWindow(
            path=owner.path, ancestry_root=tmp_path
        ) as borrower:
            borrowed = borrower.receipt()
            assert borrowed["held_before"]["file_id_128"] == owner_before["file_id_128"]
            assert (
                borrowed["held_before"]["volume_serial_number"]
                == owner_before["volume_serial_number"]
            )
        assert owner.receipt()["held_after"]["file_id_128"] == owner_before["file_id_128"]


def test_original_symlink_prefix_is_rejected_before_resolve(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(NoBytecodeContractError, match="reparse"):
        sealed_environment(base={}, pycache_prefix=link)


def test_original_junction_prefix_is_rejected_before_resolve(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    completed = subprocess.run(
        ("cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"junction creation unavailable: {completed.stderr}")
    with pytest.raises(NoBytecodeContractError, match="reparse"):
        sealed_environment(base={}, pycache_prefix=junction)


def test_governed_snapshot_rejects_empty_directory_and_descendant_link(
    tmp_path: Path,
) -> None:
    root = tmp_path / "governed"
    root.mkdir()
    (root / "source.py").write_text("x = 1\n", encoding="utf-8")
    empty = root / "empty"
    empty.mkdir()
    with pytest.raises(RuntimeError, match="empty directory"):
        _plain_directory_records(root)
    empty.rmdir()
    target = tmp_path / "target"
    target.mkdir()
    link = root / "nested_link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as exc:
        completed = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            text=True,
        )
        if completed.returncode != 0:
            pytest.skip(f"symlink/junction creation unavailable: {exc}; {completed.stderr}")
    with pytest.raises(RuntimeError, match="reparse entry"):
        _plain_directory_records(root)


def test_public_check_path_is_source_owned_r8_prefix_and_r7_prefix_is_rejected() -> None:
    outputs = PROJECT_ROOT / "outputs"
    r8 = outputs / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation_check_only_probe"
    )
    receipt = validate_planned_public_path(r8, outputs_root=outputs)
    assert receipt["planned_name"] == r8.name
    r7 = outputs / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_r7_"
        "qualification_generation_check_only_probe"
    )
    with pytest.raises(
        R7QualificationGenerationError, match="planned public output name drifted"
    ):
        validate_planned_public_path(r7, outputs_root=outputs)


def test_live_bootstrap_commands_are_source_literal_denied_without_dispatch() -> None:
    path = PROJECT_ROOT / OUTER_BOOTSTRAP_RELATIVE
    spec = importlib.util.spec_from_file_location("r8r8_trusted_bootstrap_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for command in (
        "execute",
        "role-protected-generate",
        "role-public-run",
        "role-public-finalize",
    ):
        with pytest.raises(
            module.BootstrapError,
            match="DENIED_PENDING_SEPARATE_AUDITED_MEMORY_ONLY_CHILD_CAPABILITY_REVISION",
        ):
            module.dispatch(Namespace(command=command), {}, None)


def test_source_lock_and_design_evidence_build_twice_in_memory_without_publish() -> None:
    future = PROJECT_ROOT / FUTURE_SOURCE_LOCK_RELATIVE
    assert not future.exists()
    first = build_source_lock_bytes()
    second = build_source_lock_bytes()
    assert first == second
    payload = json.loads(first)
    assert payload["script_exact_universe"] == list(SCRIPT_EXACT_UNIVERSE)
    assert payload["outer_bootstrap_relative"] == OUTER_BOOTSTRAP_RELATIVE
    assert payload["outer_bootstrap_excluded_from_inner_hash_map_to_avoid_self_reference"] is True
    assert OUTER_BOOTSTRAP_RELATIVE not in {row[0] for row in payload["source_sha256"]}
    source_relatives = {row[0] for row in payload["source_sha256"]}
    assert {
        f"{R8_R7_STATIC_PACKAGE_RELATIVE}/{name}"
        for name in R8_R7_STATIC_LOCAL_FILES
    }.issubset(source_relatives)
    assert FREEZER_SCRIPT_RELATIVE in source_relatives
    assert set(payload["governed_directory_files"][
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation"
    ]) == set(PACKAGE_FILES)
    receipt = build_in_memory_receipt()
    assert receipt["status"] == "PASS_TWO_IDENTICAL_IN_MEMORY_BUILDS_NO_PUBLISH"
    assert receipt["source_count"] == 117
    assert receipt["static_bundle_file_count"] == 19
    assert receipt["source_lock_raw_sha256"] == hashlib.sha256(first).hexdigest()
    assert receipt["future_source_lock_exists"] is False
    assert receipt["production_freeze_or_publish"] is False
    assert not future.exists()


def test_exact_19_file_static_bundle_builds_and_cross_seals_in_memory() -> None:
    source_lock = build_source_lock_bytes()
    first = build_static_bundle_bytes(source_lock)
    second = build_static_bundle_bytes(source_lock)
    assert first == second
    assert tuple(sorted(first)) == DESIGN_FILE_UNIVERSE
    receipt = verify_static_bundle_bytes(first)
    assert receipt["file_count"] == 19
    assert first["SOURCE_LOCK.json"] == source_lock
    assert receipt["authority_generation_fresh_truth_signer_counts"] == {
        "authority": 0,
        "generation": 0,
        "fresh": 0,
        "truth": 0,
        "signer": 0,
    }
    authority = json.loads(first["AUTHORITY_STATE.json"])
    assert authority["activation_authorized"] is False
    assert authority["live_child_capability_present"] is False


def test_trusted_bootstrap_pins_in_memory_lock_and_dispatches_new_public_revision() -> None:
    bootstrap = (PROJECT_ROOT / OUTER_BOOTSTRAP_RELATIVE).read_text(encoding="utf-8")
    source_lock_sha = hashlib.sha256(build_source_lock_bytes()).hexdigest()
    match = re.search(r'^PINNED_SOURCE_LOCK_RAW_SHA256 = "([0-9a-f]{64})"$', bootstrap, re.M)
    assert match is not None and match.group(1) == source_lock_sha
    assert (
        "observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.public_role"
        in bootstrap
    )
    assert (
        "observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.controller"
        in bootstrap
    )
    assert (
        "observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.custodian"
        in bootstrap
    )
    assert (
        "observable_state_bce_dgp_tournament_v2_r7_qualification_generation.protected_role"
        in bootstrap
    )
    assert "__R8_R8_SOURCE_LOCK_RAW_SHA256_PENDING__" not in bootstrap


def test_one_shot_freezer_is_fixed_create_new_and_not_invoked_by_tests() -> None:
    freezer = (PROJECT_ROOT / FREEZER_SCRIPT_RELATIVE).read_text(encoding="utf-8")
    assert "--freeze-r8-r8-static-source-no-authority-no-generation-no-fresh" in freezer
    assert '"SOURCE_LOCK.json": source_lock_raw' in (
        PROJECT_ROOT
        / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation/static_builder.py"
    ).read_text(encoding="utf-8")
    assert "create_held_direct_child_directory(STAGING_NAME)" in freezer
    assert "create_new_direct_child_artifact(name, bundle[name])" in freezer
    assert "rename_held_direct_child_no_replace(staging, OUTPUT_ROOT.name)" in freezer
    assert "reopen_after_parent_rename()" in freezer
    assert "held source changed across final publication" in freezer
    assert "published artifact or staging custody cleanup was incomplete" in freezer
    assert "tuple(sys.orig_argv) != expected_orig_argv" in freezer
    assert "sys.orig_argv[:" not in freezer
    assert "str(PINNED_BASE_PYTHON)," in freezer
    assert 'name.upper().startswith("PYTHON")' in freezer
    assert not (PROJECT_ROOT / FUTURE_SOURCE_LOCK_RELATIVE).exists()
    design_root = PROJECT_ROOT / (
        "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
        "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
    )
    assert not design_root.exists()


def test_held_19_file_publisher_is_atomic_in_disposable_namespace(
    tmp_path: Path,
) -> None:
    path = PROJECT_ROOT / FREEZER_SCRIPT_RELATIVE
    spec = importlib.util.spec_from_file_location("r8r8_freezer_atomic_test", path)
    assert spec is not None and spec.loader is not None
    freezer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(freezer)
    bundle = build_static_bundle_bytes(build_source_lock_bytes())
    outputs_path = tmp_path / "outputs"
    outputs_path.mkdir()
    with SupervisorDirectoryCustody(
        path=outputs_path,
        ancestry_root=tmp_path,
        rename_capable=False,
    ) as outputs:
        receipt = freezer._publish_held_bundle(outputs=outputs, bundle=bundle)
    final = outputs_path / freezer.OUTPUT_ROOT.name
    assert receipt["status"] == "PASS_HELD_19_FILE_ATOMIC_NO_REPLACE_PUBLICATION"
    assert receipt["file_count"] == 19
    assert receipt["unexpected_outputs_namespace_delta_count"] == 0
    assert receipt["handle_based_no_replace_rename"] is True
    assert final.is_dir()
    assert not (outputs_path / freezer.STAGING_NAME).exists()
    assert {child.name for child in final.iterdir()} == set(DESIGN_FILE_UNIVERSE)
    assert all((final / name).read_bytes() == raw for name, raw in bundle.items())


def test_source_revision_contains_no_rglob_or_dynamic_current_c1_hashing() -> None:
    package = PROJECT_ROOT / (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation"
    )
    governed = {
        "controller.py",
        "no_bytecode.py",
        "static_builder.py",
        "static_evidence.py",
    }
    text = "\n".join((package / name).read_text(encoding="utf-8") for name in governed)
    assert ".rglob(" not in text
    evidence = (package / "static_evidence.py").read_text(encoding="utf-8")
    assert "current_core_raw_sha256" not in evidence
    assert "current_contracts_raw_sha256" not in evidence


def test_exact_no_publish_script_changes_no_source_lock_file(tmp_path: Path) -> None:
    script = PROJECT_ROOT / (
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation/build_static_evidence.py"
    )
    future = PROJECT_ROOT / FUTURE_SOURCE_LOCK_RELATIVE
    assert not future.exists()
    parent = tmp_path / "parent"
    parent.mkdir()
    with HeldNoBytecodeWindow(
        parent=parent, child_name="pc", ancestry_root=tmp_path
    ) as owner:
        command = exact_python_command(
            python=Path(sys.executable),
            entry=script,
            pycache_prefix=owner.path,
            arguments=("--verify-two-in-memory-builds-no-publish-no-authority",),
        )
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=owner.environment(base=_base_environment_without_python_controls()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=180,
            text=True,
        )
        owner_receipt = owner.receipt()
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["production_freeze_or_publish"] is False
    assert receipt["future_source_lock_exists"] is False
    assert (
        receipt["no_bytecode_custody"]["held_before"]["file_id_128"]
        == owner_receipt["held_before"]["file_id_128"]
    )
    assert not future.exists()
