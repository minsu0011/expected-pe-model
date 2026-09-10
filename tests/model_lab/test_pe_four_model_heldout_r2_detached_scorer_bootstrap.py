from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest


PROJECT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (
    PROJECT
    / "scripts/model_lab/pe_four_model_heldout_r2_detached_scorer_bootstrap.py"
)
SCORER = (
    PROJECT
    / "scripts/model_lab/pe_model_portfolio_heldout_certification_evaluator_v1/run_once.py"
)


def _load_bootstrap():
    spec = importlib.util.spec_from_file_location("r2_detached_bootstrap_test", BOOTSTRAP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bootstrap_has_exact_minimal_cli_and_remains_outside_source_closure() -> None:
    module = _load_bootstrap()
    parser = module._argument_parser()
    options = {
        option
        for action in parser._actions
        for option in action.option_strings
        if option not in {"-h", "--help"}
    }
    assert options == {
        "--launcher",
        "--launcher-raw-sha256",
        "--repository-root",
        "--activation",
        "--activation-raw-sha256",
    }
    assert all("truth" not in option and "vault" not in option for option in options)
    assert BOOTSTRAP.name not in SCORER.read_text(encoding="utf-8")

    imports: set[str] = set()
    for node in ast.walk(ast.parse(BOOTSTRAP.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.add(node.module.split(".")[0])
    assert imports <= {
        "__future__",
        "argparse",
        "ctypes",
        "hashlib",
        "os",
        "pathlib",
        "sys",
        "typing",
    }


def test_exact_isolated_help_invocation_keeps_pycache_prefix_absent(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "heldout_eval_pycache_absent_bootstrap_help"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-E",
            "-X",
            f"pycache_prefix={prefix}",
            str(BOOTSTRAP),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--launcher-raw-sha256" in completed.stdout
    assert not os.path.lexists(prefix)


def test_nonisolated_invocation_fails_before_cli_or_artifact_access(
    tmp_path: Path,
) -> None:
    nonexistent_activation = tmp_path / "activation_must_not_be_opened.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(BOOTSTRAP),
            "--launcher",
            str(SCORER),
            "--launcher-raw-sha256",
            "0" * 64,
            "--repository-root",
            str(PROJECT),
            "--activation",
            str(nonexistent_activation),
            "--activation-raw-sha256",
            "1" * 64,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "exact python -I -S -B -E" in completed.stderr
    assert not nonexistent_activation.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows held-handle semantics")
def test_held_launcher_bytes_block_write_and_rename_until_close(tmp_path: Path) -> None:
    module = _load_bootstrap()
    launcher = tmp_path / "synthetic_launcher.py"
    launcher.write_bytes(b"SYNTHETIC_RESULT = 7\n")
    digest = hashlib.sha256(launcher.read_bytes()).hexdigest()

    handle, held_raw, absolute = module._hold_launcher(
        launcher, expected_sha256=digest
    )
    try:
        assert held_raw == b"SYNTHETIC_RESULT = 7\n"
        assert absolute == launcher.absolute()
        with pytest.raises(OSError):
            launcher.write_bytes(b"changed\n")
        with pytest.raises(OSError):
            launcher.rename(tmp_path / "renamed.py")
        assert launcher.read_bytes() == held_raw
    finally:
        module._close_handle(handle)

    launcher.write_bytes(b"closed\n")
    assert launcher.read_bytes() == b"closed\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows held-handle semantics")
def test_synthetic_launcher_receives_anchor_and_exact_scorer_argv_then_closes(
    tmp_path: Path,
) -> None:
    module = _load_bootstrap()
    activation = tmp_path / "nonexistent_activation_never_opened.json"
    launcher = tmp_path / "synthetic_launcher.py"
    raw = (
        b"import ctypes, sys\n"
        b"SYNTHETIC_RESULT = {\n"
        b"    'sha': _HELDOUT_VERIFIED_LAUNCHER_RAW_SHA256,\n"
        b"    'handle_type': ctypes.windll.kernel32.GetFileType(\n"
        b"        _HELDOUT_VERIFIED_LAUNCHER_HANDLE\n"
        b"    ),\n"
        b"    'file': __file__,\n"
        b"    'name': __name__,\n"
        b"    'argv': tuple(sys.argv),\n"
        b"}\n"
    )
    launcher.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    activation_digest = "a" * 64

    namespace = module._launch_held(
        launcher=launcher,
        launcher_raw_sha256=digest,
        repository_root=str(PROJECT),
        activation=str(activation),
        activation_raw_sha256=activation_digest,
    )

    result = namespace["SYNTHETIC_RESULT"]
    assert result["sha"] == digest
    assert result["handle_type"] != 0
    assert result["file"] == str(launcher.absolute())
    assert result["name"] == "__main__"
    assert result["argv"] == (
        str(launcher.absolute()),
        "--repository-root",
        str(PROJECT),
        "--activation",
        str(activation),
        "--activation-raw-sha256",
        activation_digest,
    )
    assert not activation.exists()
    launcher.write_bytes(b"handle was closed\n")


@pytest.mark.skipif(os.name != "nt", reason="Windows held-handle semantics")
def test_directory_and_wrong_hash_fail_closed_without_activation_access(
    tmp_path: Path,
) -> None:
    module = _load_bootstrap()
    with pytest.raises(module.DetachedScorerBootstrapError):
        module._hold_launcher(tmp_path, expected_sha256="0" * 64)

    launcher = tmp_path / "synthetic_launcher.py"
    launcher.write_bytes(b"raise AssertionError('must not execute')\n")
    activation = tmp_path / "activation_must_not_be_opened.json"
    with pytest.raises(
        module.DetachedScorerBootstrapError, match="held-byte hash drifted"
    ):
        module._launch_held(
            launcher=launcher,
            launcher_raw_sha256="0" * 64,
            repository_root=str(PROJECT),
            activation=str(activation),
            activation_raw_sha256="1" * 64,
        )
    assert not activation.exists()
    launcher.write_bytes(b"wrong-hash handle was closed\n")
