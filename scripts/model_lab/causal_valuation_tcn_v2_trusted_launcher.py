"""Stdlib-only trusted launcher; governed imports occur only after full attestation."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any


PROJECT_ROOT_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
PINNED_PYTHON_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_torch_py310\\Scripts\\python.exe"
)
PINNED_PYTHON_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_BASE_PYTHON_TEXT = "C:\\Users\\minsu\\anaconda3\\envs\\myenv\\python.exe"
PINNED_BASE_PYTHON_SHA256 = "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
PINNED_PYTHON_DLL_TEXT = "C:\\Users\\minsu\\anaconda3\\envs\\myenv\\python310.dll"
PINNED_PYTHON_DLL_SHA256 = "30603a60efae9ea611cbf8ed8d681b991a3b16122f494d734f2ab496d2fea4f4"
PINNED_NVIDIA_SMI_TEXT = "C:\\Windows\\System32\\nvidia-smi.exe"
PINNED_NVIDIA_SMI_SHA256 = "74348eb0bee800304ef5214d1fe8e643d7220ef8585a4e60c564fc24a06d3939"
PINNED_DRIVER_ROW = "596.49, NVIDIA GeForce RTX 5080, 12.0"
EXPECTED_CONTRACT_SHA256 = (
    "e9dcf1b0c16d3d6df236399b592178d776899e18cd7ca7711074552971f80b97"
)
SITE_PACKAGES_TEXT = (
    "C:\\Users\\minsu\\Documents\\EPS\\.venv_pe_model_lab_torch_py310\\Lib\\site-packages"
)
PINNED_DISTRIBUTIONS = {
    "Jinja2": "3.1.6",
    "MarkupSafe": "3.0.3",
    "filelock": "3.32.3",
    "fsspec": "2026.7.0",
    "mpmath": "1.3.0",
    "networkx": "3.4.2",
    "numpy": "1.26.4",
    "packaging": "26.3",
    "pip": "26.2.1",
    "setuptools": "81.0.0",
    "sympy": "1.14.0",
    "torch": "2.12.1+cu130",
    "typing_extensions": "4.16.0",
    "wheel": "0.48.0",
}
SOURCE_PATHS = tuple(
    sorted(
        (
            *(
                "research/model_zoo/causal_valuation_tcn_v2/" + name
                for name in (
                    "DESIGN.md",
                    "MODEL_HYPOTHESIS.md",
                    "REFERENCE_LICENSE_REGISTRY.json",
                    "__init__.py",
                    "artifacts.py",
                    "contracts.py",
                    "custody.py",
                    "models.py",
                    "path_guard.py",
                    "runtime.py",
                    "safe_json.py",
                    "smoke.py",
                    "smoke_worker.py",
                    "source_audit.py",
                    "training.py",
                )
            ),
            "scripts/model_lab/build_causal_valuation_tcn_v2_preflight.py",
            "scripts/model_lab/causal_valuation_tcn_v2_trusted_launcher.py",
            "tests/model_lab/causal_valuation_tcn_v2_torch_checks.py",
        )
    )
)
SPEC_FIELDS = {
    "schema_version",
    "status",
    "project_root",
    "contract_sha256",
    "source_records",
    "authority",
}
SOURCE_RECORD_FIELDS = {"path", "bytes", "raw_sha256"}
AUTHORITY_ZERO = {
    "real_fit": False,
    "real_prediction": False,
    "evaluation": False,
    "truth_or_vault": False,
    "heldout": False,
    "score": False,
    "registry_or_champion": False,
    "seed_derivation_or_reservation": False,
    "promotion": False,
}
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class PreimportError(RuntimeError):
    pass


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(8 * 1024 * 1024)
            if not block:
                return hasher.hexdigest()
            hasher.update(block)


def _require_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PreimportError(f"{label} is not lowercase SHA-256")
    return value


def _parse_object(path: Path, label: str) -> dict[str, Any]:
    content = path.read_bytes()

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in values:
            if type(key) is not str or key in output:
                raise PreimportError(f"{label} duplicate/invalid JSON key")
            output[key] = value
        return output

    try:
        text = content.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PreimportError(f"{label} non-finite JSON token")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreimportError(f"{label} malformed JSON") from error
    if type(payload) is not dict:
        raise PreimportError(f"{label} JSON root is not an object")
    return payload


def _ordinary(path: Path, *, directory: bool | None, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise PreimportError(f"{label} contains a reparse/symlink component")
    metadata = os.lstat(absolute)
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise PreimportError(f"{label} is not a directory")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise PreimportError(f"{label} is not a regular file")
    return absolute


def _verify_spec(spec_path: Path, project_root: Path) -> tuple[dict[str, Any], str]:
    _ordinary(spec_path, directory=False, label="preimport spec")
    spec = _parse_object(spec_path, "preimport spec")
    if set(spec) != SPEC_FIELDS:
        raise PreimportError("preimport spec exact field universe drifted")
    if spec["schema_version"] != "expected_pe.causal_valuation_tcn_v2.preimport_spec.v1":
        raise PreimportError("preimport spec schema drifted")
    if spec["status"] != "SOURCE_BYTES_READY_FOR_STDLIB_ATTESTATION":
        raise PreimportError("preimport spec status drifted")
    if spec["project_root"] != PROJECT_ROOT_TEXT or project_root != Path(PROJECT_ROOT_TEXT):
        raise PreimportError("project root is not the hard-coded trusted root")
    if spec["contract_sha256"] != EXPECTED_CONTRACT_SHA256:
        raise PreimportError("contract hash differs from trusted launcher constant")
    if spec["authority"] != AUTHORITY_ZERO:
        raise PreimportError("preimport spec grants forbidden authority")
    records = spec["source_records"]
    if type(records) is not list or [record.get("path") for record in records] != list(SOURCE_PATHS):
        raise PreimportError("source record exact universe/order drifted")
    for record in records:
        if type(record) is not dict or set(record) != SOURCE_RECORD_FIELDS:
            raise PreimportError("source record schema drifted")
        relative = record["path"]
        path = _ordinary(project_root / relative, directory=False, label=relative)
        content_size = path.stat().st_size
        digest = _sha256_file(path)
        if record["bytes"] != content_size or record["raw_sha256"] != digest:
            raise PreimportError(f"source bytes drifted: {relative}")
        if path.suffix.casefold() in {".pyc", ".pyo", ".dll", ".pyd"}:
            raise PreimportError(f"executable/bytecode source member forbidden: {relative}")
    source_root = hashlib.sha256(_canonical(records)).hexdigest()
    return spec, source_root


def _decode_record_hash(value: str, label: str) -> str:
    if not value.startswith("sha256="):
        raise PreimportError(f"{label} RECORD hash algorithm drifted")
    encoded = value[7:]
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as error:
        raise PreimportError(f"{label} RECORD hash malformed") from error
    if len(raw) != 32:
        raise PreimportError(f"{label} RECORD hash length drifted")
    return raw.hex()


def _verify_record_closure() -> dict[str, Any]:
    if sys.dont_write_bytecode is not True or sys.pycache_prefix is None:
        raise PreimportError("dependency bytecode quarantine is not active")
    redirected_cache = Path(sys.pycache_prefix)
    if redirected_cache.exists():
        raise PreimportError("redirected dependency bytecode cache is not empty/absent")
    site = Path(SITE_PACKAGES_TEXT)
    _ordinary(site, directory=True, label="site-packages")
    distributions = tuple(importlib.metadata.distributions(path=[SITE_PACKAGES_TEXT]))
    by_name: dict[str, importlib.metadata.Distribution] = {}
    for distribution in distributions:
        name = distribution.metadata.get("Name")
        if type(name) is not str or name in by_name:
            raise PreimportError("distribution universe is ambiguous")
        by_name[name] = distribution
    if set(by_name) != set(PINNED_DISTRIBUTIONS):
        raise PreimportError("exact distribution universe drifted")
    closure = hashlib.sha256(b"expected_pe.causal_valuation_tcn_v2.record_closure.v1\0")
    binaries: list[dict[str, Any]] = []
    receipts: dict[str, Any] = {}
    for name in sorted(PINNED_DISTRIBUTIONS):
        distribution = by_name[name]
        if distribution.version != PINNED_DISTRIBUTIONS[name]:
            raise PreimportError(f"distribution version drifted: {name}")
        text = distribution.read_text("RECORD")
        if type(text) is not str:
            raise PreimportError(f"RECORD absent: {name}")
        rows = list(csv.reader(io.StringIO(text, newline="")))
        seen: set[str] = set()
        duplicate_paths = 0
        members = hashlib.sha256(b"expected_pe.causal_valuation_tcn_v2.record_members.v1\0")
        hashed = 0
        unhashed = 0
        present_unhashed = 0
        nonexecuted_pyc_members = 0
        nonexecuted_pyc_mismatches = 0
        for row in rows:
            if len(row) != 3 or not row[0]:
                raise PreimportError(f"RECORD row drifted: {name}")
            relative, encoded_hash, encoded_size = row
            if relative in seen:
                duplicate_paths += 1
            seen.add(relative)
            path = Path(os.path.abspath(distribution.locate_file(relative)))
            exists = path.exists()
            actual_hash = ""
            actual_size = -1
            record_content_matches: bool | None = None
            is_nonexecuted_pyc = Path(relative).suffix.casefold() in {".pyc", ".pyo"}
            if is_nonexecuted_pyc:
                nonexecuted_pyc_members += 1
            if encoded_hash:
                expected_hash = _decode_record_hash(encoded_hash, f"{name}:{relative}")
                _ordinary(path, directory=False, label=f"{name}:{relative}")
                actual_size = path.stat().st_size
                try:
                    expected_size = int(encoded_size)
                except ValueError as error:
                    raise PreimportError(f"RECORD size malformed: {name}:{relative}") from error
                actual_hash = _sha256_file(path)
                record_content_matches = (
                    expected_size == actual_size and actual_hash == expected_hash
                )
                if not record_content_matches and not is_nonexecuted_pyc:
                    raise PreimportError(f"RECORD member bytes drifted: {name}:{relative}")
                if not record_content_matches:
                    nonexecuted_pyc_mismatches += 1
                hashed += 1
                if path.suffix.casefold() in {".dll", ".pyd"}:
                    binaries.append(
                        {
                            "distribution": name,
                            "path": relative.replace("\\", "/"),
                            "bytes": actual_size,
                            "raw_sha256": actual_hash,
                        }
                    )
            else:
                if encoded_size:
                    raise PreimportError(f"unhashed RECORD size drifted: {name}:{relative}")
                unhashed += 1
                if exists:
                    _ordinary(path, directory=False, label=f"{name}:{relative}")
                    actual_size = path.stat().st_size
                    actual_hash = _sha256_file(path)
                    present_unhashed += 1
            members.update(
                _canonical(
                    {
                        "path": relative.replace("\\", "/"),
                        "record_hash": encoded_hash,
                        "record_size": encoded_size,
                        "present": exists,
                        "actual_size": actual_size,
                        "actual_sha256": actual_hash,
                        "record_content_matches": record_content_matches,
                        "dependency_bytecode_executable": False,
                    }
                )
            )
        receipt = {
            "version": distribution.version,
            "record_raw_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "record_row_count": len(rows),
            "hashed_member_count": hashed,
            "unhashed_member_count": unhashed,
            "present_unhashed_member_count": present_unhashed,
            "duplicate_record_path_count": duplicate_paths,
            "nonexecuted_pyc_member_count": nonexecuted_pyc_members,
            "nonexecuted_pyc_mismatch_count": nonexecuted_pyc_mismatches,
            "exact_member_universe_sha256": members.hexdigest(),
        }
        receipts[name] = receipt
        closure.update(_canonical({"name": name, **receipt}))
    binaries.sort(key=lambda value: (value["distribution"], value["path"]))
    return {
        "distribution_universe": PINNED_DISTRIBUTIONS,
        "distributions": receipts,
        "distribution_count": len(receipts),
        "record_member_closure_sha256": closure.hexdigest(),
        "binary_member_count": len(binaries),
        "binary_member_closure_sha256": hashlib.sha256(_canonical(binaries)).hexdigest(),
    }


def _verify_interpreter_driver() -> dict[str, Any]:
    expected = {
        PINNED_PYTHON_TEXT: PINNED_PYTHON_SHA256,
        PINNED_BASE_PYTHON_TEXT: PINNED_BASE_PYTHON_SHA256,
        PINNED_PYTHON_DLL_TEXT: PINNED_PYTHON_DLL_SHA256,
        PINNED_NVIDIA_SMI_TEXT: PINNED_NVIDIA_SMI_SHA256,
    }
    files: dict[str, Any] = {}
    for raw, digest in expected.items():
        path = _ordinary(Path(raw), directory=False, label=raw)
        actual = _sha256_file(path)
        if actual != digest:
            raise PreimportError(f"pinned interpreter/driver file drifted: {raw}")
        files[path.as_posix()] = {"bytes": path.stat().st_size, "raw_sha256": actual}
    if Path(sys.executable) != Path(PINNED_PYTHON_TEXT):
        raise PreimportError("trusted launcher used the wrong Python executable")
    process = subprocess.run(
        [
            PINNED_NVIDIA_SMI_TEXT,
            "--query-gpu=driver_version,name,compute_cap",
            "--format=csv,noheader,nounits",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    rows = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    if process.returncode != 0 or rows != [PINNED_DRIVER_ROW]:
        raise PreimportError("pinned driver/GPU/SM identity drifted")
    return {"files": files, "nvidia_smi_row": rows[0]}


def _copy_source_stage(project_root: Path, stage: Path, spec: dict[str, Any]) -> None:
    if stage.exists():
        raise PreimportError("source stage already exists")
    stage.mkdir()
    for record in spec["source_records"]:
        relative = record["path"]
        source = project_root / relative
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    expected_files = set(SOURCE_PATHS)
    actual_files: set[str] = set()
    for path in stage.rglob("*"):
        if path.is_symlink() or bool(
            int(getattr(os.lstat(path), "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise PreimportError("source stage contains a reparse point")
        if path.is_file():
            relative = path.relative_to(stage).as_posix()
            actual_files.add(relative)
            if path.suffix.casefold() in {".pyc", ".pyo", ".dll", ".pyd"}:
                raise PreimportError("source stage contains bytecode/binary content")
    if actual_files != expected_files:
        raise PreimportError("source stage exact file universe drifted")


def _controlled_environment(
    *, spec_path: Path, stage: Path, preimport_receipt: dict[str, Any]
) -> dict[str, str]:
    keep = (
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    )
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    receipt_json = _canonical(preimport_receipt).decode("ascii")
    receipt_sha = hashlib.sha256(receipt_json.encode("ascii")).hexdigest()
    environment.update(
        {
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "2026082107",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "CVTCN_V2_LIVE_PROJECT_ROOT": PROJECT_ROOT_TEXT,
            "CVTCN_V2_SOURCE_STAGE": str(stage),
            "CVTCN_V2_PREIMPORT_SPEC": str(spec_path),
            "CVTCN_V2_PREIMPORT_ATTESTATION_SHA256": receipt_sha,
            "CVTCN_V2_PREIMPORT_RECEIPT_JSON": receipt_json,
        }
    )
    if "CVTCN_V2_TEST_OUTPUT_CONTAINER" in os.environ:
        environment["CVTCN_V2_TEST_OUTPUT_CONTAINER"] = os.environ[
            "CVTCN_V2_TEST_OUTPUT_CONTAINER"
        ]
    return environment


def _preimport_attestation(
    *, project_root: Path, spec_path: Path, stage: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    if any(
        name == "research"
        or name.startswith("research.")
        or name in {"numpy", "torch", "pytest"}
        or name.startswith("_pytest")
        for name in sys.modules
    ):
        raise PreimportError("governed/numeric/test module imported before attestation")
    spec, source_root = _verify_spec(spec_path, project_root)
    interpreter = _verify_interpreter_driver()
    records = _verify_record_closure()
    _copy_source_stage(project_root, stage, spec)
    receipt = {
        "schema_version": "expected_pe.causal_valuation_tcn_v2.preimport_attestation.v1",
        "status": "PASS_BEFORE_ANY_GOVERNED_IMPORT",
        "source_manifest_sha256": source_root,
        "interpreter_driver_closure": interpreter,
        "distribution_record_closure": records,
        "stage": str(stage),
        "stage_exact_file_universe": list(SOURCE_PATHS),
        "bytecode_allowed": False,
        "reparse_allowed": False,
        "pytest_plugin_universe": [],
        "authority": AUTHORITY_ZERO,
    }
    return spec, receipt


def _worker(args: argparse.Namespace) -> int:
    project_root = _ordinary(Path(PROJECT_ROOT_TEXT), directory=True, label="project root")
    stage = _ordinary(Path(args.stage), directory=True, label="source stage")
    spec_path = _ordinary(Path(args.spec), directory=False, label="preimport spec")
    spec, source_root = _verify_spec(spec_path, project_root)
    interpreter = _verify_interpreter_driver()
    records = _verify_record_closure()
    actual_files = {
        path.relative_to(stage).as_posix()
        for path in stage.rglob("*")
        if path.is_file()
    }
    if actual_files != set(SOURCE_PATHS):
        raise PreimportError("worker source stage universe drifted")
    for record in spec["source_records"]:
        path = _ordinary(stage / record["path"], directory=False, label="staged source")
        if path.stat().st_size != record["bytes"] or _sha256_file(path) != record["raw_sha256"]:
            raise PreimportError(f"staged source bytes drifted: {record['path']}")
    if any(
        name == "research"
        or name.startswith("research.")
        or name in {"numpy", "torch", "pytest"}
        or name.startswith("_pytest")
        for name in sys.modules
    ):
        raise PreimportError("governed module loaded before worker attestation")
    receipt = {
        "schema_version": "expected_pe.causal_valuation_tcn_v2.preimport_attestation.v1",
        "status": "PASS_BEFORE_ANY_GOVERNED_IMPORT",
        "source_manifest_sha256": source_root,
        "interpreter_driver_closure": interpreter,
        "distribution_record_closure": records,
        "stage": str(stage),
        "stage_exact_file_universe": list(SOURCE_PATHS),
        "bytecode_allowed": False,
        "reparse_allowed": False,
        "pytest_plugin_universe": [],
        "authority": AUTHORITY_ZERO,
    }
    receipt_json = _canonical(receipt).decode("ascii")
    receipt_sha = hashlib.sha256(receipt_json.encode("ascii")).hexdigest()
    if os.environ.get("CVTCN_V2_PREIMPORT_ATTESTATION_SHA256") != receipt_sha:
        raise PreimportError("parent/worker preimport attestation differs")
    if os.environ.get("CVTCN_V2_PREIMPORT_RECEIPT_JSON") != receipt_json:
        raise PreimportError("parent/worker preimport receipt bytes differ")
    base_paths = list(sys.path)
    sys.path[:] = [str(stage), SITE_PACKAGES_TEXT, *base_paths]
    if args.task == "smoke":
        from research.model_zoo.causal_valuation_tcn_v2.smoke_worker import _run

        payload = _run(args.device)
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    if args.task == "tests":
        import runpy

        test_path = stage / "tests/model_lab/causal_valuation_tcn_v2_torch_checks.py"
        runpy.run_path(str(test_path), run_name="__main__")
        return 0
    raise PreimportError("unknown worker task")


def _run_child(
    *, task: str, device: str | None, spec: Path, stage: Path, receipt: dict[str, Any]
) -> dict[str, Any]:
    launcher = stage / "scripts/model_lab/causal_valuation_tcn_v2_trusted_launcher.py"
    command = [
        PINNED_PYTHON_TEXT,
        "-I",
        "-B",
        "-S",
        "-X",
        f"pycache_prefix={stage / 'forbidden_bytecode_sink'}",
        str(launcher),
        "--worker",
        "--task",
        task,
        "--spec",
        str(spec),
        "--stage",
        str(stage),
    ]
    if device is not None:
        command.extend(("--device", device))
    environment = _controlled_environment(
        spec_path=spec, stage=stage, preimport_receipt=receipt
    )
    process = subprocess.run(
        command,
        cwd=stage,
        env=environment,
        check=False,
        capture_output=True,
        timeout=1800,
    )
    stdout_bytes = process.stdout or b""
    stderr_bytes = process.stderr or b""
    try:
        stdout_text = stdout_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PreimportError("isolated worker stdout is not strict UTF-8") from error
    result = {
        "command": command,
        "return_code": process.returncode,
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "stdout": stdout_text,
        "stderr_tail": stderr_bytes[-4000:].decode(
            "utf-8", errors="backslashreplace"
        ),
    }
    if process.returncode != 0:
        raise PreimportError(
            f"isolated {task}/{device or 'none'} worker failed: {result['stderr_tail']}"
        )
    return result


def _preflight(args: argparse.Namespace) -> int:
    project_root = _ordinary(Path(PROJECT_ROOT_TEXT), directory=True, label="project root")
    spec_path = _ordinary(Path(args.spec), directory=False, label="preimport spec")
    stage = project_root / "outputs/.causal_valuation_tcn_v2_source_stage"
    spec, receipt = _preimport_attestation(
        project_root=project_root, spec_path=spec_path, stage=stage
    )
    try:
        test_result = _run_child(
            task="tests", device=None, spec=spec_path, stage=stage, receipt=receipt
        )
        cpu_result = _run_child(
            task="smoke", device="cpu", spec=spec_path, stage=stage, receipt=receipt
        )
        gpu_first_result = _run_child(
            task="smoke", device="cuda", spec=spec_path, stage=stage, receipt=receipt
        )
        gpu_second_result = _run_child(
            task="smoke", device="cuda", spec=spec_path, stage=stage, receipt=receipt
        )
        workers = {
            "cpu": json.loads(cpu_result["stdout"]),
            "gpu_process_1": json.loads(gpu_first_result["stdout"]),
            "gpu_process_2": json.loads(gpu_second_result["stdout"]),
        }
        payload = {
            "schema_version": "expected_pe.causal_valuation_tcn_v2.trusted_preflight.v1",
            "status": "PASS_TRUSTED_TEST_CPU_TWO_GPU_PREFLIGHT",
            "preimport_attestation": receipt,
            "test": {key: value for key, value in test_result.items() if key != "stdout"},
            "test_stdout": test_result["stdout"],
            "worker_process_receipts": {
                "cpu": {key: value for key, value in cpu_result.items() if key != "stdout"},
                "gpu_process_1": {
                    key: value for key, value in gpu_first_result.items() if key != "stdout"
                },
                "gpu_process_2": {
                    key: value for key, value in gpu_second_result.items() if key != "stdout"
                },
            },
            "workers": workers,
            "authority": AUTHORITY_ZERO,
        }
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _tests_only(args: argparse.Namespace) -> int:
    project_root = _ordinary(Path(PROJECT_ROOT_TEXT), directory=True, label="project root")
    spec_path = _ordinary(Path(args.spec), directory=False, label="preimport spec")
    stage = project_root / "outputs/.causal_valuation_tcn_v2_source_stage"
    _, receipt = _preimport_attestation(
        project_root=project_root, spec_path=spec_path, stage=stage
    )
    try:
        result = _run_child(
            task="tests", device=None, spec=spec_path, stage=stage, receipt=receipt
        )
        payload = {
            "schema_version": "expected_pe.causal_valuation_tcn_v2.trusted_tests_only.v1",
            "status": "PASS_TRUSTED_ADVERSARIAL_TESTS_ONLY",
            "preimport_attestation": receipt,
            "test": {key: value for key, value in result.items() if key != "stdout"},
            "test_stdout": result["stdout"],
            "authority": AUTHORITY_ZERO,
        }
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--tests-only", action="store_true")
    mode.add_argument("--worker", action="store_true")
    parser.add_argument("--task", choices=("tests", "smoke"))
    parser.add_argument("--device", choices=("cpu", "cuda"))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--stage", type=Path)
    args = parser.parse_args()
    if args.worker:
        if args.task is None or args.stage is None:
            raise PreimportError("worker task/stage arguments are required")
        if args.task == "smoke" and args.device is None:
            raise PreimportError("smoke worker device is required")
        return _worker(args)
    if args.task is not None or args.device is not None or args.stage is not None:
        raise PreimportError("parent preflight accepts only the fixed spec")
    if args.tests_only:
        return _tests_only(args)
    return _preflight(args)


if __name__ == "__main__":
    raise SystemExit(main())
