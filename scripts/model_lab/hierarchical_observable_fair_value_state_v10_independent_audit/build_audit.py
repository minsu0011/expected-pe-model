"""Build and verify the independent H-OFS V10 score-free NO_GO audit bundle."""

from __future__ import annotations

import argparse
import ast
import copy
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping, Sequence


def _resolve_project_root() -> Path:
    script = Path(__file__).resolve()
    candidates = [Path.cwd().resolve()]
    candidates.extend(parent.resolve() for parent in script.parents)
    sentinel = Path(
        "research/model_zoo/hierarchical_observable_fair_value_state_v10/"
        "contracts.py"
    )
    matches: list[Path] = []
    for candidate in candidates:
        if (candidate / sentinel).is_file() and candidate not in matches:
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError("independent V10 audit project root is ambiguous or absent")
    return matches[0]


PROJECT_ROOT = _resolve_project_root()
AUDITED_RELATIVE = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v10_"
    "dgp_r4_design_preflight_20260821"
)
AUDIT_RELATIVE = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v10_"
    "independent_prelaunch_audit_20260821"
)
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / AUDIT_RELATIVE
LIVE_BUILDER = (
    PROJECT_ROOT
    / "scripts/model_lab/"
    "hierarchical_observable_fair_value_state_v10_independent_audit/build_audit.py"
)
LIVE_PROBE = (
    PROJECT_ROOT
    / "scripts/model_lab/"
    "hierarchical_observable_fair_value_state_v10_independent_audit/"
    "independent_probe.py"
)
V10_CHECKSUMS_SHA256 = (
    "2f7a4e093612335124d2ff1bcbe64d39fbbd4d8c9a0b455dd7b4581859bd0384"
)
V10_CONTRACT_SHA256 = (
    "ba0a57c7cc94ef2527faa0982c13c41af840970ddbe430912c79850b951fa304"
)
V10_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT_CLOSURE.json",
    "CHECKSUMS.sha256",
    "DESIGN_LOCK.json",
    "INPUT_CLOSURE.json",
    "MANIFEST.json",
    "PREDICTION_LAUNCHER.py",
    "PREDICTION_LAUNCH_CONTRACT.json",
    "PREFLIGHT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "RESOURCE_RECEIPT.json",
    "SEAL_RECEIPT.json",
    "SOURCE_CLOSURE.json",
)
V9_DESIGN_RELATIVE = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v9_"
    "dgp_r4_design_preflight_20260821"
)
V9_DESIGN_CHECKSUMS_SHA256 = (
    "9bea4ec60d87e72063ab6856b07cd26e7ffb86c652ee5cad668e648ff654fb33"
)
V9_AUDIT_RELATIVE = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v9_"
    "independent_prelaunch_audit_20260821"
)
V9_AUDIT_CHECKSUMS_SHA256 = (
    "cede6dc9cc1253687cb265f36f45ef9fab0d0da235f4fdf787c922e90c8eff51"
)
V9_AUDIT_RAW_SHA256 = (
    "0256335703313e550234607ab2968fc94c794f593a8aafa2390ad3fe1c7533a7"
)
V9_AUDIT_SEMANTIC_SHA256 = (
    "c215c6d8f505bbce69ff522953f923d2b93ed1c38eafaba82c1eac5df1efb9e4"
)
V9_AUDIT_SEAL_SHA256 = (
    "ac341e2710633112bb6bd1a98e89e9050c00985dc70f1e7e87e5cfa526502dd9"
)
V8_STAGING_RELATIVE = (
    "outputs/.model_zoo_hierarchical_observable_fair_value_state_v8_"
    "dgp_r4_prediction_only_20260821T075500.staging"
)
V8_FINAL_RELATIVE = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v8_"
    "dgp_r4_prediction_only_20260821T075500"
)
V8_STAGING_CTIME_NS = 1_787_298_916_351_775_400
V8_FAILURE_EVIDENCE_SHA256 = (
    "151425ff324aa2e650c0b58c05f3cc56348fa7d129cbbfadd2e2efbcf984fed3"
)
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PINNED_PYTHON_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
FINAL_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT.json",
    "CHECKSUMS.sha256",
    "MANIFEST.json",
    "PROBE_RECEIPT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "SEAL_RECEIPT.json",
    "build_audit.py",
    "independent_probe.py",
)
SEVERITY_COUNTS = {"P0": 2, "P1": 2, "P2": 1}
VERDICT = "NO_GO_REQUIRES_HOFS_V11_TRUST_CUSTODY_REPAIR"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _sealed(payload: Mapping[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(dict(payload))
    output.pop("semantic_sha256", None)
    output["semantic_sha256"] = _sha256(_canonical(output))
    return output


def _parse_json_exact(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in output:
                raise RuntimeError(f"duplicate or invalid JSON key: {label}:{key}")
            output[key] = value
        return output

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RuntimeError(f"non-finite JSON token: {label}:{token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid ASCII JSON: {label}") from error
    if type(value) is not dict:
        raise RuntimeError(f"JSON root is not an object: {label}")
    return value


def _verify_seal(payload: Mapping[str, Any], *, field: str) -> str:
    unsigned = copy.deepcopy(dict(payload))
    expected = unsigned.pop(field, None)
    actual = _sha256(_canonical(unsigned))
    if expected != actual:
        raise RuntimeError(f"logical seal drifted: {field}")
    return actual


def _is_reparse(path: Path) -> bool:
    stat_result = path.stat()
    return path.is_symlink() or bool(
        int(getattr(stat_result, "st_file_attributes", 0)) & 0x00000400
    )


def _require_regular(path: Path, *, root: Path) -> bytes:
    if _is_reparse(path) or not path.is_file():
        raise RuntimeError(f"non-regular file: {path}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"file escaped root: {path}") from error
    return path.read_bytes()


def _verify_ledger_directory(
    root: Path,
    *,
    universe: Sequence[str],
    expected_checksums_sha256: str | None = None,
) -> dict[str, bytes]:
    expected_names = tuple(sorted(universe))
    if _is_reparse(root) or not root.is_dir():
        raise RuntimeError(f"non-regular ledger directory: {root}")
    children = tuple(root.iterdir())
    if any(_is_reparse(path) or not path.is_file() for path in children):
        raise RuntimeError(f"ledger directory has a non-file child: {root}")
    names = tuple(sorted(path.name for path in children))
    if names != expected_names or len({name.casefold() for name in names}) != len(names):
        raise RuntimeError(f"exact file universe drifted: {root}")
    contents = {name: _require_regular(root / name, root=root) for name in names}
    checksums_sha256 = _sha256(contents["CHECKSUMS.sha256"])
    if (
        expected_checksums_sha256 is not None
        and checksums_sha256 != expected_checksums_sha256
    ):
        raise RuntimeError(f"external checksum pin drifted: {root}")
    ledger_names = tuple(name for name in expected_names if name != "CHECKSUMS.sha256")
    lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    if len(lines) != len(ledger_names):
        raise RuntimeError(f"checksum ledger count drifted: {root}")
    for position, line in enumerate(lines):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError(f"malformed checksum ledger line: {root}:{position}")
        digest, name = parts
        if name != ledger_names[position] or digest != _sha256(contents[name]):
            raise RuntimeError(f"checksum ledger entry drifted: {root}:{position}")
    return contents


def _tree_sha256(contents: Mapping[str, bytes]) -> str:
    rows = [
        [name, _sha256(content), len(content)]
        for name, content in sorted(contents.items())
    ]
    return _sha256(_canonical(rows))


def _cache_inventory() -> list[str]:
    roots = (
        PROJECT_ROOT / AUDITED_RELATIVE,
        PROJECT_ROOT
        / "research/model_zoo/hierarchical_observable_fair_value_state_v10",
        PROJECT_ROOT
        / "scripts/model_lab/hierarchical_observable_fair_value_state_v10",
        LIVE_BUILDER.parent,
    )
    found: list[str] = []
    for root in roots:
        for path in root.rglob("*"):
            if (
                path.name in {"__pycache__", ".pytest_cache"}
                or path.suffix in {".pyc", ".pyo"}
            ):
                found.append(path.relative_to(PROJECT_ROOT).as_posix())
    return sorted(found)


def _subject_closure() -> dict[str, Any]:
    from scripts.model_lab.hierarchical_observable_fair_value_state_v10.freeze_design import (
        verify_design_bundle,
    )

    target = PROJECT_ROOT / AUDITED_RELATIVE
    contents = _verify_ledger_directory(
        target,
        universe=V10_FILE_UNIVERSE,
        expected_checksums_sha256=V10_CHECKSUMS_SHA256,
    )
    parsed = {
        name: _parse_json_exact(content, label=f"V10:{name}")
        for name, content in contents.items()
        if name.endswith(".json")
    }
    semantic = {
        name: _verify_seal(payload, field="manifest_sha256")
        for name, payload in parsed.items()
    }
    official = verify_design_bundle(
        target,
        expected_checksums_raw_sha256=V10_CHECKSUMS_SHA256,
    )
    if (
        official["design_contract_sha256"] != V10_CONTRACT_SHA256
        or official["file_count"] != 14
        or official["checksum_ledger_entry_count"] != 13
        or official["execution_authority"] is not False
        or official["real_fit_count"] != 0
        or official["real_prediction_count"] != 0
    ):
        raise RuntimeError("official V10 frozen verification drifted")
    source = parsed["SOURCE_CLOSURE.json"]["source_audit"]
    source_rows = source["source_sha256"]
    for relative, expected in source_rows:
        content = _require_regular(PROJECT_ROOT / relative, root=PROJECT_ROOT)
        if _sha256(content) != expected:
            raise RuntimeError(f"V10 source closure drifted: {relative}")

    v9_design = _verify_ledger_directory(
        PROJECT_ROOT / V9_DESIGN_RELATIVE,
        universe=V10_FILE_UNIVERSE,
        expected_checksums_sha256=V9_DESIGN_CHECKSUMS_SHA256,
    )
    v9_audit_universe = (
        "ACCESS_RECEIPT.json",
        "AUDIT.json",
        "CHECKSUMS.sha256",
        "MANIFEST.json",
        "PROBE_RECEIPT.json",
        "QUALITY_RECEIPT.json",
        "REPORT.md",
        "SEAL_RECEIPT.json",
        "build_audit.py",
        "independent_probe.py",
    )
    v9_audit = _verify_ledger_directory(
        PROJECT_ROOT / V9_AUDIT_RELATIVE,
        universe=v9_audit_universe,
        expected_checksums_sha256=V9_AUDIT_CHECKSUMS_SHA256,
    )
    v9_audit_payload = _parse_json_exact(v9_audit["AUDIT.json"], label="V9 audit")
    v9_audit_semantic = _verify_seal(v9_audit_payload, field="manifest_sha256")
    if (
        _sha256(v9_audit["AUDIT.json"]) != V9_AUDIT_RAW_SHA256
        or v9_audit_semantic != V9_AUDIT_SEMANTIC_SHA256
        or _sha256(v9_audit["SEAL_RECEIPT.json"]) != V9_AUDIT_SEAL_SHA256
        or v9_audit_payload["severity_counts"] != {"P0": 1, "P1": 1, "P2": 0}
        or v9_audit_payload["verdict"]
        != "NO_GO_REQUIRES_HOFS_V10_AUTHORITY_CAPABILITY_REPAIR"
    ):
        raise RuntimeError("immutable V9 NO_GO audit drifted")

    staging = PROJECT_ROOT / V8_STAGING_RELATIVE
    final = PROJECT_ROOT / V8_FINAL_RELATIVE
    if (
        _is_reparse(staging)
        or not staging.is_dir()
        or tuple(staging.iterdir())
        or final.exists()
        or staging.stat().st_ctime_ns != V8_STAGING_CTIME_NS
    ):
        raise RuntimeError("immutable V8 empty failed staging evidence drifted")

    source_private_seed_hits: list[str] = []
    for relative, _expected in source_rows:
        if not relative.endswith(".py"):
            continue
        tree = ast.parse((PROJECT_ROOT / relative).read_text("utf-8"), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name)
                and target.id == "_TEST_FIXTURE_PRIVATE_SEED"
                for target in node.targets
            ):
                source_private_seed_hits.append(relative)
    if source_private_seed_hits != [
        "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py"
    ]:
        raise RuntimeError("V10 fixture/private-seed location drifted")
    staging_sibling = target.parent / f".{target.name}.staging"
    if staging_sibling.exists() or _cache_inventory():
        raise RuntimeError("V10 staging or cache residue is present")
    return {
        "relative_root": AUDITED_RELATIVE,
        "file_count": len(contents),
        "checksum_ledger_entry_count": len(contents) - 1,
        "checksums_raw_sha256": V10_CHECKSUMS_SHA256,
        "tree_sha256": _tree_sha256(contents),
        "design_contract_sha256": V10_CONTRACT_SHA256,
        "manifest_raw_sha256": _sha256(contents["MANIFEST.json"]),
        "manifest_semantic_sha256": semantic["MANIFEST.json"],
        "seal_raw_sha256": _sha256(contents["SEAL_RECEIPT.json"]),
        "seal_semantic_sha256": semantic["SEAL_RECEIPT.json"],
        "launcher_raw_sha256": _sha256(contents["PREDICTION_LAUNCHER.py"]),
        "source_closure_raw_sha256": _sha256(contents["SOURCE_CLOSURE.json"]),
        "source_file_count": len(source_rows),
        "source_tree_sha256": _sha256(_canonical(source_rows)),
        "staging_sibling_absent": True,
        "cache_item_count": 0,
        "production_private_key_present": False,
        "production_public_key_value_present": False,
        "production_public_key_pin_present": False,
        "execution_authority": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
        "v9_design": {
            "relative_root": V9_DESIGN_RELATIVE,
            "checksums_raw_sha256": _sha256(v9_design["CHECKSUMS.sha256"]),
            "tree_sha256": _tree_sha256(v9_design),
            "immutable": True,
        },
        "v9_no_go_audit": {
            "relative_root": V9_AUDIT_RELATIVE,
            "checksums_raw_sha256": V9_AUDIT_CHECKSUMS_SHA256,
            "audit_raw_sha256": V9_AUDIT_RAW_SHA256,
            "audit_semantic_sha256": V9_AUDIT_SEMANTIC_SHA256,
            "seal_raw_sha256": V9_AUDIT_SEAL_SHA256,
            "severity_counts": {"P0": 1, "P1": 1, "P2": 0},
            "immutable": True,
        },
        "v8_failed_run": {
            "staging_relative": V8_STAGING_RELATIVE,
            "staging_exists": True,
            "staging_child_count": 0,
            "staging_creation_time_utc_ns": V8_STAGING_CTIME_NS,
            "staging_reparse": False,
            "final_relative": V8_FINAL_RELATIVE,
            "final_exists": False,
            "failure_evidence_sha256": V8_FAILURE_EVIDENCE_SHA256,
            "retry_count_by_auditor": 0,
        },
    }


def _command_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": os.pathsep.join(
                (str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))
            ),
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "CUDA_VISIBLE_DEVICES": "-1",
        }
    )
    return environment


def _run(command: Sequence[str], *, timeout: int = 600) -> dict[str, Any]:
    completed = subprocess.run(
        list(command),
        cwd=PROJECT_ROOT,
        env=_command_environment(),
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    receipt = {
        "command": list(command),
        "returncode": completed.returncode,
        "stdout_raw_sha256": _sha256(stdout),
        "stderr_raw_sha256": _sha256(stderr),
        "stdout_size_bytes": len(stdout),
        "stderr_size_bytes": len(stderr),
    }
    if completed.returncode != 0:
        raise RuntimeError(
            f"independent command failed: {command!r}\n"
            f"stdout={stdout.decode('utf-8', errors='replace')}\n"
            f"stderr={stderr.decode('utf-8', errors='replace')}"
        )
    receipt["stdout"] = stdout
    receipt["stderr"] = stderr
    return receipt


def _json_stdout(receipt: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    stdout = bytes(receipt["stdout"]).strip()
    return _parse_json_exact(stdout, label=label)


def _public_command_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key not in {"stdout", "stderr"}
    }


def _quality_and_probe() -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        ".".join(str(value) for value in sys.version_info[:3]) != "3.10.19"
        or Path(sys.executable).resolve() != PINNED_PYTHON.resolve()
        or _sha256(Path(sys.executable).read_bytes()) != PINNED_PYTHON_SHA256
    ):
        raise RuntimeError("independent audit controller is not pinned Python 3.10.19")
    if _cache_inventory():
        raise RuntimeError("cache residue existed before independent commands")
    python = str(PINNED_PYTHON)
    frozen_check = _run(
        (
            python,
            str(PROJECT_ROOT / AUDITED_RELATIVE / "PREDICTION_LAUNCHER.py"),
            "--check",
        )
    )
    frozen_check_json = _json_stdout(frozen_check, label="frozen launcher check")
    canonical_check = _run(
        (
            python,
            "-m",
            "scripts.model_lab.hierarchical_observable_fair_value_state_v10."
            "freeze_design",
            "--check",
        )
    )
    canonical_check_json = _json_stdout(canonical_check, label="canonical check")
    collect = _run(
        (
            python,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "--collect-only",
            "-q",
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py",
        )
    )
    if b": 18" not in collect["stdout"]:
        raise RuntimeError("focused V10 pytest collection count drifted")
    pytest_run = _run(
        (
            python,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py",
        )
    )
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError("ruff executable is absent")
    ruff_version = _run((ruff, "--version"))
    ruff_run = _run(
        (
            ruff,
            "check",
            "--no-cache",
            "research/model_zoo/hierarchical_observable_fair_value_state_v10",
            "scripts/model_lab/hierarchical_observable_fair_value_state_v10",
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py",
            "scripts/model_lab/"
            "hierarchical_observable_fair_value_state_v10_independent_audit",
        )
    )
    fixture = _run(
        (
            python,
            "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py",
            "--fixture-benchmark",
        )
    )
    fixture_json = _json_stdout(fixture, label="fixture benchmark")
    probe_run = _run((python, str(LIVE_PROBE)))
    probe = _json_stdout(probe_run, label="independent V10 probe")
    if (
        frozen_check_json["run_mode_present"] is not False
        or frozen_check_json["real_fit_count"] != 0
        or frozen_check_json["real_prediction_count"] != 0
        or canonical_check_json["execution_authority"] is not False
        or fixture_json["production_equivalent"]["worker_count"] != 32
        or fixture_json["production_equivalent"]["task_count"] != 50
        or fixture_json["targeted_same_pid"]["worker_count"] != 1
        or fixture_json["targeted_same_pid"]["task_count"] != 7
        or fixture_json["targeted_same_pid"]["maximum_reuse_count"] != 7
        or probe["status"] != "PASS_INDEPENDENT_SCORE_FREE_FAILURE_REPRODUCTIONS"
        or not probe["authority_root_probe"][
            "caller_selected_design_pin_differs_from_actual"
        ]
        or not probe["clock_probe"]["accepted_using_caller_supplied_time"]
        or probe["clock_probe"]["actual_wall_clock_inside_signed_window"]
        or not probe["fresh_ledger_replay_probe"][
            "same_capability_accepted_by_two_fresh_ledgers"
        ]
        or not probe["initializer_and_duck_ledger_probe"][
            "forged_guard_accepted_with_numpy_preloaded"
        ]
        or not probe["initializer_and_duck_ledger_probe"][
            "same_task_replay_accepted"
        ]
        or not probe["task_path_probe"]["contains_parent_traversal"]
    ):
        raise RuntimeError("independent positive or failure probe semantics drifted")
    caches_after = _cache_inventory()
    if caches_after:
        raise RuntimeError(f"independent commands created cache residue: {caches_after}")
    quality = {
        "schema_version": "expected_pe.hofs_v10.independent_quality.v1",
        "status": "PASS_INDEPENDENT_CHECKS_AND_FAILURE_REPRODUCTIONS",
        "runtime": {
            "python_version": "3.10.19",
            "python_executable": PINNED_PYTHON.as_posix(),
            "python_executable_sha256": PINNED_PYTHON_SHA256,
            "bytecode_disabled": True,
            "pytest_cache_provider_disabled": True,
            "inner_threads": 1,
            "gpu_environment": [["CUDA_VISIBLE_DEVICES", "-1"]],
        },
        "commands": {
            "frozen_launcher_check": _public_command_receipt(frozen_check),
            "canonical_preflight_check": _public_command_receipt(canonical_check),
            "pytest_collect_18": _public_command_receipt(collect),
            "pytest_focused_18": _public_command_receipt(pytest_run),
            "ruff_version": {
                **_public_command_receipt(ruff_version),
                "value": ruff_version["stdout"].decode("ascii").strip(),
            },
            "ruff": _public_command_receipt(ruff_run),
            "fixture_32x50_and_same_pid_7": _public_command_receipt(fixture),
            "independent_failure_probe": _public_command_receipt(probe_run),
        },
        "fixture_benchmark": {
            "production_equivalent": {
                key: fixture_json["production_equivalent"][key]
                for key in (
                    "worker_count",
                    "task_count",
                    "reused_worker_count",
                    "maximum_reuse_count",
                    "initializer_count_per_pid",
                    "absence_guard_count_per_pid",
                    "signature_reverification_count",
                    "atomic_consumption_count",
                    "public_input_open_count",
                    "real_fit_count",
                    "real_prediction_count",
                )
            },
            "targeted_same_pid": {
                key: fixture_json["targeted_same_pid"][key]
                for key in (
                    "worker_count",
                    "task_count",
                    "maximum_reuse_count",
                    "initializer_count_per_pid",
                    "absence_guard_count_per_pid",
                    "signature_reverification_count",
                    "atomic_consumption_count",
                    "public_input_open_count",
                    "real_fit_count",
                    "real_prediction_count",
                )
            },
        },
        "cache_item_count_before": 0,
        "cache_item_count_after": 0,
        "real_fit_count": 0,
        "real_prediction_count": 0,
        "public_input_open_count": 0,
        "protected_or_score_open_count": 0,
    }
    return _sealed(quality), _sealed(probe)


def _findings() -> list[dict[str, Any]]:
    return [
        {
            "finding_id": "HOFS_V10_P0_CALLER_CONTROLLED_TRUST_ROOT_AND_CLOCK",
            "severity": "P0",
            "title": "The authority trust root and verification clock are caller-controlled",
            "evidence": {
                "source": [
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/capability.py:318-406",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:348-381",
                    "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py:106-155",
                ],
                "probe": [
                    "authority_root_probe.caller_selected_design_pin_differs_from_actual=true",
                    "authority_root_probe.caller_selected_audit_hashes_accepted=true",
                    "authority_root_probe.fixture_key_and_fixture_signature_accepted_by_gate=true",
                    "clock_probe.actual_wall_clock_inside_signed_window=false",
                    "clock_probe.accepted_using_caller_supplied_time=true",
                ],
            },
            "impact": (
                "CapabilityPolicy, the public key and its hash pin, audit hashes, and "
                "now_unix all enter through the same caller. The verifier compares the "
                "signed payload only with those caller values and never reopens an "
                "externally anchored V10 audit or obtains time internally. The fixture "
                "signer therefore authorizes a payload whose design pin is 64 '1' bytes "
                "rather than the frozen V10 contract, and a not-yet-valid payload is "
                "accepted using a supplied in-window time. The current check-only CLI "
                "has no model callback, but this gate cannot authenticate a future "
                "independent GO or bounded authority lifetime."
            ),
            "required_v11_repair": (
                "Freeze one externally anchored launcher that independently reopens the "
                "exact V10/V11 design and audit bundles, verifies raw and semantic seals "
                "and zero findings, pins the independently selected custodian public key, "
                "constructs policy internally, obtains current time from the trusted "
                "launcher, and rejects the fixture key and every caller-supplied trust pin "
                "or clock."
            ),
        },
        {
            "finding_id": "HOFS_V10_P0_NON_GLOBAL_ONE_SHOT_AND_REPLAYABLE_LEDGER",
            "severity": "P0",
            "title": "One-shot consumption is per ephemeral ledger and replayable",
            "evidence": {
                "source": [
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:162-262",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:382-429",
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/lifecycle.py:91-119",
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/lifecycle.py:196-310",
                    "tests/model_lab/test_hierarchical_observable_fair_value_state_v10.py:391-410",
                ],
                "probe": [
                    "fresh_ledger_replay_probe.same_capability_accepted_by_two_fresh_ledgers=true",
                    "fresh_ledger_replay_probe.first_launch_submitted_task_count=2",
                    "fresh_ledger_replay_probe.second_launch_submitted_task_count=1",
                    "initializer_and_duck_ledger_probe.duck_typed_replay_ledger_accepted=true",
                    "initializer_and_duck_ledger_probe.same_task_replay_accepted=true",
                ],
            },
            "impact": (
                "Every public benchmark invocation creates a new Manager ledger, so the "
                "same envelope and custodian_consumption_id can be consumed again after "
                "completion or controller crash. A signed two-task manifest can also be "
                "reported PASS after submitting only one task. The lifecycle accepts any "
                "duck-typed object returning expected dictionaries; an adversarial ledger "
                "accepted the same task twice. The one_shot field is therefore an "
                "assertion, not global durable custody."
            ),
            "required_v11_repair": (
                "Use a non-caller-controlled durable external custodian with atomic "
                "compare-and-set of the canonical capability/run consumption ID, exact "
                "full-manifest task claims, durable crash journal and defined abort/resume "
                "semantics. Bind every worker to a non-forgeable inherited handle for that "
                "claim; remove duck-typed ledger injection and the partial task_count API."
            ),
        },
        {
            "finding_id": "HOFS_V10_P1_FORGEABLE_INITIALIZER_GUARD_DIRECT_IMPORT",
            "severity": "P1",
            "title": "The initializer absence guard remains forgeable through direct module access",
            "evidence": {
                "source": [
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/lifecycle.py:35-88",
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/lifecycle.py:122-193",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:104-159",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:265-312",
                ],
                "probe": [
                    "initializer_and_duck_ledger_probe.actual_guard_rejected_preloaded_numpy=true",
                    "initializer_and_duck_ledger_probe.none_guard_rejected=true",
                    "initializer_and_duck_ledger_probe.module_private_marker_directly_importable=true",
                    "initializer_and_duck_ledger_probe.forged_guard_accepted_with_numpy_preloaded=true",
                ],
            },
            "impact": (
                "The optional None path is removed and the intended initializer calls the "
                "real guard, but Python underscore names are not access control. A caller "
                "can import _INITIALIZER_MARKER and _install_worker_state and submit a "
                "plain dictionary asserting no preloaded modules. The installer accepted "
                "that dictionary while NumPy was already present, preserving the V9 "
                "forgeable-receipt defect through a different route."
            ),
            "required_v11_repair": (
                "Perform the live sys.modules/runtime absence checks inside the final "
                "state installer itself with no receipt parameter or bypass branch. If a "
                "receipt crosses a process boundary, authenticate it with a non-exported "
                "OS-inherited launch capability and recheck live process state before "
                "installing authority."
            ),
        },
        {
            "finding_id": "HOFS_V10_P1_TASK_MANIFEST_PATH_AND_COMPLETENESS_OPEN",
            "severity": "P1",
            "title": "The signed task manifest is not closed to the exact R4 public tree",
            "evidence": {
                "source": [
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/capability.py:176-219",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:365-374",
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v10/prediction_launcher.py:415-423",
                ],
                "probe": [
                    "task_path_probe.accepted_relative=../../outside/dgp_A/canonical150.csv",
                    "task_path_probe.accepted_by_signed_manifest_validator=true",
                    "fresh_ledger_replay_probe.partial_manifest_launch_accepted=true",
                ],
            },
            "impact": (
                "Validation checks only a filename suffix and hash shape. It accepts parent "
                "traversal, arbitrary positive seeds and arbitrary nonempty task counts; "
                "the launcher can execute a strict subset. No file was opened in this "
                "score-free audit, but a future public-input callback would not be "
                "transitively constrained to the frozen R4 input closure by this gate."
            ),
            "required_v11_repair": (
                "Derive the complete task manifest internally from the reopened frozen R4 "
                "input closure. Require exact seed/DGP/count/order/relative paths and raw "
                "hashes; reject absolute, parent, alternate-separator, reparse and escaped "
                "paths before any open; remove caller-selected subsets."
            ),
        },
        {
            "finding_id": "HOFS_V10_P2_NONCANONICAL_ENVELOPE_RAW_IDENTITY",
            "severity": "P2",
            "title": "Equivalent signed capability envelopes have multiple raw identities",
            "evidence": {
                "source": [
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/capability.py:133-154",
                    "research/model_zoo/hierarchical_observable_fair_value_state_v10/capability.py:318-416",
                ],
                "probe": [
                    "authority_root_probe.noncanonical_envelope_encoding_accepted=true",
                    "authority_root_probe.canonical_and_noncanonical_raw_hashes_differ=true",
                    "authority_root_probe.canonical_and_noncanonical_signed_message_hashes_equal=true",
                ],
            },
            "impact": (
                "The parser rejects duplicate keys but does not require the envelope bytes "
                "to equal canonical JSON. Whitespace/key-order variants share one signed "
                "message while producing different envelope_raw_sha256 values used in "
                "attestations and receipts, weakening exact identity and diagnostics."
            ),
            "required_v11_repair": (
                "Require envelope_bytes == canonical_json_bytes(parsed_envelope), or use a "
                "single canonical signed-message/capability ID everywhere and reject every "
                "alternate encoding before ledger lookup."
            ),
        },
    ]


def build_bundle() -> dict[str, bytes]:
    subject = _subject_closure()
    quality, probe = _quality_and_probe()
    findings = _findings()
    if len(findings) != sum(SEVERITY_COUNTS.values()):
        raise RuntimeError("finding count drifted")
    observed_counts = {
        severity: sum(row["severity"] == severity for row in findings)
        for severity in ("P0", "P1", "P2")
    }
    if observed_counts != SEVERITY_COUNTS:
        raise RuntimeError("finding severity counts drifted")
    generated_at = datetime.now(timezone.utc).isoformat()
    audit = _sealed(
        {
            "schema_version": "expected_pe.hofs_v10.independent_prelaunch_audit.v1",
            "status": "SEALED_TERMINAL_INDEPENDENT_PRELAUNCH_AUDIT_NO_GO",
            "verdict": VERDICT,
            "generated_at_utc": generated_at,
            "audited_target": AUDITED_RELATIVE,
            "subject": subject,
            "severity_counts": copy.deepcopy(SEVERITY_COUNTS),
            "finding_count": len(findings),
            "findings": findings,
            "positive_evidence": [
                "Exact 14-file/13-ledger V10 bundle, all raw hashes, every JSON logical seal, manifest/seal cross-closure, canonical rebuild, and nine-file source closure match.",
                "The immutable V9 design and terminal 1/1/0 NO_GO audit hashes match; V8 final remains absent and its exact empty staging timestamp remains unchanged.",
                "No V10 staging sibling, cache bytecode, production private key, production public-key value/pin, run mode, execution authority, real fit, real prediction, score, evaluator, or registry path is present.",
                "Frozen launcher --check and canonical preflight --check pass under pinned Python 3.10.19 with bytecode/cache disabled and GPU hidden.",
                "All 18 focused tests and Ruff pass. Independent fixture execution reproduced 32x50 fanout and seven tasks in one PID with zero public input, callbacks, fits, or predictions.",
                "The honest live in-memory ledger admits exactly one of two concurrent duplicate attempts; a wrong key pin alone is rejected; the intended guard rejects preloaded NumPy.",
                "Independent negative probes expose trust-root, clock, global replay, forged-guard, manifest path/completeness, and raw-envelope identity gaps without any real data or model execution.",
            ],
            "failed_checks": {
                "trusted_noncaller_audit_key_and_clock_root": False,
                "global_durable_one_shot_and_crash_semantics": False,
                "initializer_guard_unforgeable_on_every_import_route": False,
                "task_manifest_exact_r4_path_and_completeness": False,
                "canonical_unique_envelope_identity": False,
            },
            "authority": {
                "prediction_only_launch": False,
                "real_fit": False,
                "real_prediction": False,
                "truth_qualification_heldout_evaluator_or_score": False,
                "registry_or_champion": False,
                "portfolio_admission": False,
                "promotion": False,
            },
            "execution_boundary": {
                "launcher_run_invoked": False,
                "public_input_open_count": 0,
                "protected_or_score_open_count": 0,
                "downstream_callback_invocation_count": 0,
                "real_fit_count": 0,
                "real_prediction_count": 0,
                "registry_or_champion_mutation_count": 0,
            },
            "required_next_step": (
                "Keep V10/V9/V8 immutable. Build an isolated H-OFS V11 repair for "
                "all five findings and obtain a new independent 0/0/0 score-free "
                "prelaunch audit before any public input access, fit, prediction, "
                "qualification integration, or Model Portfolio admission."
            ),
        }
    )
    access = _sealed(
        {
            "schema_version": "expected_pe.hofs_v10.independent_zero_access.v1",
            "status": "PASS_ZERO_REAL_MODEL_OR_PROTECTED_ACCESS",
            "audited_target_file_read_count": 14,
            "v10_source_file_read_count": 9,
            "v9_design_file_read_count": 14,
            "v9_audit_file_read_count": 10,
            "v8_empty_staging_metadata_read_count": 1,
            "test_fixture_source_used_for_score_free_probe": True,
            "public_input_payload_open_count": 0,
            "public_input_header_open_count": 0,
            "truth_qualification_heldout_evaluator_or_score_open_count": 0,
            "model_registry_file_read_count": 0,
            "launcher_run_invocation_count": 0,
            "downstream_callback_invocation_count": 0,
            "score_call_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
        }
    )
    report = (
        "# H-OFS V10 independent score-free prelaunch audit\n\n"
        "Verdict: NO_GO_REQUIRES_HOFS_V11_TRUST_CUSTODY_REPAIR\n\n"
        "Severity: P0=2, P1=2, P2=1.\n\n"
        "The frozen V10 bundle, hashes, semantic seals, V9 NO_GO lineage, and "
        "V8 empty failed staging are intact. The launcher remains check-only and "
        "this audit performed zero real input access, fit, prediction, score, "
        "evaluation, or registry mutation.\n\n"
        "V10 is not safe to promote into a prediction launcher. Its trust policy, "
        "key pin and clock are caller supplied; one-shot state is ephemeral and "
        "replayable across ledgers; direct module access accepts a forged absence "
        "guard with NumPy preloaded; task paths/completeness are not closed to R4; "
        "and equivalent envelopes have multiple raw identities.\n\n"
        "Keep V10/V9/V8 immutable. Repair only in isolated V11 and require a fresh "
        "independent P0/P1/P2=0/0/0 audit before any execution authority.\n"
    ).encode("ascii")
    builder_bytes = _require_regular(LIVE_BUILDER, root=PROJECT_ROOT)
    probe_bytes = _require_regular(LIVE_PROBE, root=PROJECT_ROOT)
    core_payloads = {
        "ACCESS_RECEIPT.json": access,
        "AUDIT.json": audit,
        "PROBE_RECEIPT.json": probe,
        "QUALITY_RECEIPT.json": quality,
    }
    core_files = {name: _json_bytes(payload) for name, payload in core_payloads.items()}
    core_files.update(
        {
            "REPORT.md": report,
            "build_audit.py": builder_bytes,
            "independent_probe.py": probe_bytes,
        }
    )
    manifest = _sealed(
        {
            "schema_version": "expected_pe.hofs_v10.independent_manifest.v1",
            "status": "SEALED_INDEPENDENT_NO_GO_READY_TO_PUBLISH",
            "audit_root": AUDIT_RELATIVE,
            "audited_target": AUDITED_RELATIVE,
            "audited_checksums_raw_sha256": V10_CHECKSUMS_SHA256,
            "audited_tree_sha256": subject["tree_sha256"],
            "audited_design_contract_sha256": V10_CONTRACT_SHA256,
            "verdict": VERDICT,
            "severity_counts": copy.deepcopy(SEVERITY_COUNTS),
            "finding_count": len(findings),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {
                    "raw_sha256": _sha256(content),
                    "size_bytes": len(content),
                    **(
                        {
                            "semantic_sha256": core_payloads[name][
                                "semantic_sha256"
                            ]
                        }
                        if name in core_payloads
                        else {}
                    ),
                }
                for name, content in sorted(core_files.items())
            },
            "execution_authority": False,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "score_evaluator_registry_authority": False,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal = _sealed(
        {
            "schema_version": "expected_pe.hofs_v10.independent_seal.v1",
            "status": "SEALED_TERMINAL_NO_GO_HOFS_V10_EXECUTION_DENIED",
            "audit_root": AUDIT_RELATIVE,
            "audited_target": AUDITED_RELATIVE,
            "audited_checksums_raw_sha256": V10_CHECKSUMS_SHA256,
            "audited_tree_sha256": subject["tree_sha256"],
            "audited_design_contract_sha256": V10_CONTRACT_SHA256,
            "verdict": VERDICT,
            "severity_counts": copy.deepcopy(SEVERITY_COUNTS),
            "finding_count": len(findings),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {"raw_sha256": _sha256(content), "size_bytes": len(content)}
                for name, content in sorted(payload_files.items())
            },
            "authority": {
                "prediction_only_launch": False,
                "real_fit": False,
                "real_prediction": False,
                "score_evaluator_registry_or_champion": False,
                "portfolio_admission": False,
                "promotion": False,
            },
        }
    )
    seal_bytes = _json_bytes(seal)
    checksummed = {**payload_files, "SEAL_RECEIPT.json": seal_bytes}
    checksums = "".join(
        f"{_sha256(checksummed[name])}  {name}\n"
        for name in FINAL_FILE_UNIVERSE
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    bundle = {**checksummed, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(bundle)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("independent audit final file universe drifted")
    return bundle


def verify_audit_bundle(root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    contents = _verify_ledger_directory(root, universe=FINAL_FILE_UNIVERSE)
    parsed = {
        name: _parse_json_exact(content, label=f"audit:{name}")
        for name, content in contents.items()
        if name.endswith(".json")
    }
    semantic = {
        name: _verify_seal(payload, field="semantic_sha256")
        for name, payload in parsed.items()
    }
    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL_RECEIPT.json"]
    audit = parsed["AUDIT.json"]
    expected_core = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "MANIFEST.json", "SEAL_RECEIPT.json"}
    )
    if (
        tuple(sorted(manifest["core_files"])) != expected_core
        or tuple(sorted(seal["artifact_hashes"]))
        != tuple(
            name
            for name in FINAL_FILE_UNIVERSE
            if name not in {"CHECKSUMS.sha256", "SEAL_RECEIPT.json"}
        )
        or manifest["expected_final_file_universe"] != list(FINAL_FILE_UNIVERSE)
        or seal["expected_final_file_universe"] != list(FINAL_FILE_UNIVERSE)
        or audit["severity_counts"] != SEVERITY_COUNTS
        or seal["severity_counts"] != SEVERITY_COUNTS
        or audit["finding_count"] != sum(SEVERITY_COUNTS.values())
        or audit["verdict"] != VERDICT
        or manifest["verdict"] != VERDICT
        or seal["verdict"] != VERDICT
    ):
        raise RuntimeError("independent audit manifest/seal semantics drifted")
    for name in expected_core:
        expected = manifest["core_files"][name]
        if (
            expected["raw_sha256"] != _sha256(contents[name])
            or expected["size_bytes"] != len(contents[name])
        ):
            raise RuntimeError(f"independent manifest core hash drifted: {name}")
        if name.endswith(".json") and expected["semantic_sha256"] != semantic[name]:
            raise RuntimeError(f"independent manifest semantic hash drifted: {name}")
    for name, expected in seal["artifact_hashes"].items():
        if expected != {
            "raw_sha256": _sha256(contents[name]),
            "size_bytes": len(contents[name]),
        }:
            raise RuntimeError(f"independent seal artifact hash drifted: {name}")
    return {
        "status": "PASS_EXACT_IMMUTABLE_HOFS_V10_INDEPENDENT_NO_GO_AUDIT",
        "file_count": len(contents),
        "checksum_ledger_entry_count": len(contents) - 1,
        "checksums_raw_sha256": _sha256(contents["CHECKSUMS.sha256"]),
        "tree_sha256": _tree_sha256(contents),
        "audit_raw_sha256": _sha256(contents["AUDIT.json"]),
        "audit_semantic_sha256": semantic["AUDIT.json"],
        "manifest_raw_sha256": _sha256(contents["MANIFEST.json"]),
        "manifest_semantic_sha256": semantic["MANIFEST.json"],
        "seal_raw_sha256": _sha256(contents["SEAL_RECEIPT.json"]),
        "seal_semantic_sha256": semantic["SEAL_RECEIPT.json"],
        "probe_raw_sha256": _sha256(contents["PROBE_RECEIPT.json"]),
        "quality_raw_sha256": _sha256(contents["QUALITY_RECEIPT.json"]),
        "severity_counts": copy.deepcopy(SEVERITY_COUNTS),
        "finding_count": sum(SEVERITY_COUNTS.values()),
        "verdict": VERDICT,
        "execution_authority": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def _fsync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    create_file = ctypes.windll.kernel32.CreateFileW  # type: ignore[attr-defined]
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise RuntimeError("independent audit directory fsync handle failed")
    try:
        if not ctypes.windll.kernel32.FlushFileBuffers(handle):  # type: ignore[attr-defined]
            raise RuntimeError("independent audit directory fsync failed")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def freeze_audit_bundle() -> dict[str, Any]:
    target = DEFAULT_OUTPUT_ROOT.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root:
        raise RuntimeError("independent audit target escaped outputs")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists() or _is_reparse(outputs_root):
        raise FileExistsError("independent audit target or staging already exists")
    bundle = build_bundle()
    staging.mkdir(exist_ok=False)
    for name in FINAL_FILE_UNIVERSE:
        with (staging / name).open("xb") as handle:
            handle.write(bundle[name])
            handle.flush()
            os.fsync(handle.fileno())
    _fsync_directory(staging)
    verify_audit_bundle(staging)
    os.replace(staging, target)
    _fsync_directory(outputs_root)
    if staging.exists() or not target.is_dir():
        raise RuntimeError("independent audit atomic publication failed")
    return verify_audit_bundle(target)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    if arguments.verify:
        result = verify_audit_bundle()
    elif arguments.write:
        result = freeze_audit_bundle()
    else:
        bundle = build_bundle()
        result = {
            "status": "PASS_INDEPENDENT_AUDIT_BUILD_CHECK_NO_WRITE",
            "file_count": len(bundle),
            "checksums_raw_sha256": _sha256(bundle["CHECKSUMS.sha256"]),
            "audit_raw_sha256": _sha256(bundle["AUDIT.json"]),
            "seal_raw_sha256": _sha256(bundle["SEAL_RECEIPT.json"]),
            "severity_counts": copy.deepcopy(SEVERITY_COUNTS),
            "verdict": VERDICT,
            "execution_authority": False,
            "real_fit_count": 0,
            "real_prediction_count": 0,
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
