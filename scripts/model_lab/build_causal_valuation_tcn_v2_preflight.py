"""Build and atomically freeze the isolated score-free Causal Valuation TCN V2."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping


PROJECT_ROOT = Path(
    "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
PINNED_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_torch_py310/Scripts/python.exe"
)
PINNED_PYTHON_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
RUFF_EXECUTABLE = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
RUFF_EXECUTABLE_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)
TRUSTED_LAUNCHER = (
    PROJECT_ROOT / "scripts/model_lab/causal_valuation_tcn_v2_trusted_launcher.py"
)
EXPECTED_CONTRACT_SHA256 = (
    "e9dcf1b0c16d3d6df236399b592178d776899e18cd7ca7711074552971f80b97"
)
SOURCE_STAGE = OUTPUTS_ROOT / ".causal_valuation_tcn_v2_source_stage"
FINAL_OUTPUT = (
    OUTPUTS_ROOT
    / "model_zoo_causal_valuation_tcn_v2_"
    "score_free_design_environment_preflight_20260821"
)
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
RUFF_PATHS = (
    "research/model_zoo/causal_valuation_tcn_v2",
    "scripts/model_lab/build_causal_valuation_tcn_v2_preflight.py",
    "scripts/model_lab/causal_valuation_tcn_v2_trusted_launcher.py",
    "tests/model_lab/causal_valuation_tcn_v2_torch_checks.py",
)
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
FINDING_IDS = (
    "P0-001",
    "P0-002",
    "P0-003",
    "P1-001",
    "P1-002",
    "P1-003",
    "P1-004",
    "P2-001",
    "P2-002",
)
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class V2BuildError(RuntimeError):
    """Raised when the score-free freeze cannot be proven complete."""


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


def _ordinary(path: Path, *, directory: bool, label: str) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        ):
            raise V2BuildError(f"{label} contains a reparse component")
    metadata = os.lstat(absolute)
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected:
        raise V2BuildError(f"{label} is not an ordinary {'directory' if directory else 'file'}")
    return absolute


def _clean_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTEST_ADDOPTS",
        "CVTCN_V2_PREIMPORT_ATTESTATION_SHA256",
        "CVTCN_V2_PREIMPORT_RECEIPT_JSON",
        "CVTCN_V2_PREIMPORT_SPEC",
        "CVTCN_V2_SOURCE_STAGE",
        "CVTCN_V2_TEST_OUTPUT_CONTAINER",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "2026082107",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
    )
    if extra:
        environment.update(extra)
    return environment


def _run_command(
    command: list[str],
    *,
    environment: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    combined = (process.stdout + process.stderr).encode("utf-8")
    return {
        "command": command,
        "return_code": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "output_sha256": hashlib.sha256(combined).hexdigest(),
        "output_tail": (process.stdout + process.stderr)[-6000:],
    }


def _parse_single_object(text: str, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise V2BuildError(f"{label} did not emit one JSON object") from error
    if type(payload) is not dict:
        raise V2BuildError(f"{label} JSON root is not an object")
    return payload


def _test_summary(payload: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    text = payload.get("test_stdout")
    if type(text) is not str:
        raise V2BuildError(f"{label} test stdout is absent")
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise V2BuildError(f"{label} test stdout is not one canonical receipt")
    receipt = _parse_single_object(lines[0], label=f"{label} test receipt")
    if (
        receipt.get("status")
        != "PASS_CAUSAL_VALUATION_TCN_V2_ADVERSARIAL_TESTS"
        or receipt.get("tests_run") != 13
        or receipt.get("v1_findings_covered") != list(FINDING_IDS)
        or type(receipt.get("skipped")) is not int
    ):
        raise V2BuildError(f"{label} test receipt drifted")
    return receipt


def _source_spec() -> dict[str, Any]:
    records = []
    for relative in SOURCE_PATHS:
        path = _ordinary(PROJECT_ROOT / relative, directory=False, label=relative)
        records.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "raw_sha256": _sha256_file(path),
            }
        )
    return {
        "schema_version": "expected_pe.causal_valuation_tcn_v2.preimport_spec.v1",
        "status": "SOURCE_BYTES_READY_FOR_STDLIB_ATTESTATION",
        "project_root": str(PROJECT_ROOT).replace("/", "\\"),
        "contract_sha256": EXPECTED_CONTRACT_SHA256,
        "source_records": records,
        "authority": AUTHORITY_ZERO,
    }


def _write_spec() -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".causal_valuation_tcn_v2_preimport_spec.",
        suffix=".json",
        dir=OUTPUTS_ROOT,
    )
    os.close(descriptor)
    path = Path(raw_path)
    path.write_bytes(_canonical(_source_spec()) + b"\n")
    return path


def _launcher_command(mode: str, spec: Path) -> list[str]:
    return [
        str(PINNED_PYTHON),
        "-I",
        "-B",
        "-S",
        "-X",
        f"pycache_prefix={OUTPUTS_ROOT / '.causal_valuation_tcn_v2_forbidden_cache'}",
        str(TRUSTED_LAUNCHER),
        mode,
        "--spec",
        str(spec),
    ]


def _sealed_quality(payload: Mapping[str, Any]) -> dict[str, Any]:
    if "semantic_sha256" in payload:
        raise V2BuildError("quality payload was already sealed")
    output = dict(payload)
    output["semantic_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return output


def _quality_payload(
    *,
    test_payload: Mapping[str, Any],
    test_summary: Mapping[str, Any],
    ruff_result: Mapping[str, Any],
    trusted_result: Mapping[str, Any],
    provisional: bool,
) -> dict[str, Any]:
    test_process = test_payload.get("test")
    if type(test_process) is not dict:
        raise V2BuildError("trusted test process receipt is absent")
    return _sealed_quality(
        {
            "schema_version": "expected_pe.causal_valuation_tcn_v2.quality_receipt.v1",
            "status": "PASS_V2_ADVERSARIAL_QUALITY_SURFACE",
            "test_command": test_process["command"],
            "test_return_code": test_process["return_code"],
            "test_output_sha256": test_process["stdout_sha256"],
            "tests_run": test_summary["tests_run"],
            "adversarial_v1_findings": {
                finding: not (provisional and finding == "P0-001")
                for finding in FINDING_IDS
            },
            "ruff_command": ruff_result["command"],
            "ruff_return_code": ruff_result["return_code"],
            "ruff_output_sha256": ruff_result["output_sha256"],
            "trusted_launcher_command": trusted_result["command"],
            "trusted_launcher_return_code": trusted_result["return_code"],
            "trusted_launcher_output_sha256": trusted_result["output_sha256"],
            "executed_test_files": [
                "tests/model_lab/causal_valuation_tcn_v2_torch_checks.py"
            ],
            "executed_config_files": [],
            "pytest_plugin_universe": [],
            "real_fit_or_prediction_run": False,
        }
    )


def _make_provisional_container(
    *, bundle: Mapping[str, bytes], anchor: bytes, anchor_ledger: bytes
) -> Path:
    raw = tempfile.mkdtemp(
        prefix=".causal_valuation_tcn_v2_provisional.", dir=OUTPUTS_ROOT
    )
    container = Path(raw)
    bundle_root = container / "bundle"
    bundle_root.mkdir()
    for name, content in bundle.items():
        (bundle_root / name).write_bytes(content)
    (container / "EXTERNAL_ANCHOR.json").write_bytes(anchor)
    (container / "EXTERNAL_ANCHOR.sha256").write_bytes(anchor_ledger)
    return container


def _remove_owned_tree(path: Path, *, prefix: str) -> None:
    if not path.exists():
        return
    absolute = path.absolute()
    if absolute.parent != OUTPUTS_ROOT or not absolute.name.startswith(prefix):
        raise V2BuildError(f"refused cleanup outside owned temporary surface: {absolute}")
    if stat.S_ISLNK(os.lstat(absolute).st_mode) or bool(
        int(getattr(os.lstat(absolute), "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
    ):
        raise V2BuildError("refused cleanup of reparse temporary surface")
    shutil.rmtree(absolute)


def main() -> int:
    _ordinary(PROJECT_ROOT, directory=True, label="project root")
    _ordinary(OUTPUTS_ROOT, directory=True, label="outputs root")
    _ordinary(PINNED_PYTHON, directory=False, label="pinned Python")
    _ordinary(RUFF_EXECUTABLE, directory=False, label="pinned Ruff")
    _ordinary(TRUSTED_LAUNCHER, directory=False, label="trusted launcher")
    if Path(sys.executable).absolute() != PINNED_PYTHON.absolute():
        raise V2BuildError("builder must run under the pinned Python executable")
    if _sha256_file(PINNED_PYTHON) != PINNED_PYTHON_SHA256:
        raise V2BuildError("pinned Python bytes drifted")
    if _sha256_file(RUFF_EXECUTABLE) != RUFF_EXECUTABLE_SHA256:
        raise V2BuildError("pinned Ruff bytes drifted")
    if FINAL_OUTPUT.exists() or SOURCE_STAGE.exists():
        raise V2BuildError("final output or trusted source stage already exists")

    spec: Path | None = None
    provisional: Path | None = None
    try:
        spec = _write_spec()
        trusted_result = _run_command(
            _launcher_command("--preflight", spec),
            environment=_clean_environment(),
            timeout=7200,
        )
        if trusted_result["return_code"] != 0:
            raise V2BuildError(
                "trusted CPU/two-GPU preflight failed:\n"
                + str(trusted_result["output_tail"])
            )
        trusted_payload = _parse_single_object(
            str(trusted_result["stdout"]), label="trusted preflight"
        )
        if (
            trusted_payload.get("status")
            != "PASS_TRUSTED_TEST_CPU_TWO_GPU_PREFLIGHT"
            or trusted_payload.get("authority") != AUTHORITY_ZERO
            or set(trusted_payload.get("workers", {}))
            != {"cpu", "gpu_process_1", "gpu_process_2"}
        ):
            raise V2BuildError("trusted preflight receipt drifted")
        initial_summary = _test_summary(trusted_payload, label="initial preflight")
        if initial_summary["skipped"] != 2:
            raise V2BuildError("initial artifact-test skip count drifted")

        sys.path.insert(0, str(PROJECT_ROOT))
        from research.model_zoo.causal_valuation_tcn_v2.artifacts import (
            build_design_bundle_bytes,
            freeze_design_bundle,
        )
        from research.model_zoo.causal_valuation_tcn_v2.contracts import (
            contract_sha256,
        )
        from research.model_zoo.causal_valuation_tcn_v2.smoke import (
            validate_cross_device_synthetic_smoke,
        )
        from research.model_zoo.causal_valuation_tcn_v2.source_audit import (
            run_source_audit,
        )

        if contract_sha256() != EXPECTED_CONTRACT_SHA256:
            raise V2BuildError("live contract differs from preimport anchor")
        smoke = validate_cross_device_synthetic_smoke(**trusted_payload["workers"])
        source_audit = run_source_audit(PROJECT_ROOT)
        if not source_audit.passed:
            raise V2BuildError(
                "source audit failed:\n" + json.dumps(source_audit.payload(), indent=2)
            )

        ruff_result = _run_command(
            [str(RUFF_EXECUTABLE), "check", "--isolated", *RUFF_PATHS],
            environment=_clean_environment(),
            timeout=600,
        )
        if ruff_result["return_code"] != 0:
            raise V2BuildError("Ruff failed:\n" + str(ruff_result["output_tail"]))

        provisional_quality = _quality_payload(
            test_payload=trusted_payload,
            test_summary=initial_summary,
            ruff_result=ruff_result,
            trusted_result=trusted_result,
            provisional=True,
        )
        bundle, anchor, anchor_ledger = build_design_bundle_bytes(
            project_root=PROJECT_ROOT,
            smoke_payload=smoke,
            source_audit=source_audit,
            quality_payload=provisional_quality,
        )
        provisional = _make_provisional_container(
            bundle=bundle, anchor=anchor, anchor_ledger=anchor_ledger
        )

        tests_result = _run_command(
            _launcher_command("--tests-only", spec),
            environment=_clean_environment(
                {"CVTCN_V2_TEST_OUTPUT_CONTAINER": str(provisional)}
            ),
            timeout=3600,
        )
        if tests_result["return_code"] != 0:
            raise V2BuildError(
                "complete adversarial tests failed:\n" + str(tests_result["output_tail"])
            )
        tests_payload = _parse_single_object(
            str(tests_result["stdout"]), label="trusted tests-only"
        )
        if (
            tests_payload.get("status") != "PASS_TRUSTED_ADVERSARIAL_TESTS_ONLY"
            or tests_payload.get("authority") != AUTHORITY_ZERO
        ):
            raise V2BuildError("trusted tests-only receipt drifted")
        final_summary = _test_summary(tests_payload, label="complete adversarial")
        if final_summary["skipped"] != 0:
            raise V2BuildError("complete adversarial suite skipped governed tests")

        quality = _quality_payload(
            test_payload=tests_payload,
            test_summary=final_summary,
            ruff_result=ruff_result,
            trusted_result=trusted_result,
            provisional=False,
        )
        _remove_owned_tree(
            provisional, prefix=".causal_valuation_tcn_v2_provisional."
        )
        provisional = None
        verification = freeze_design_bundle(
            smoke_payload=smoke,
            source_audit=source_audit,
            quality_payload=quality,
        )
        output = {
            "status": "FROZEN_V2_SCORE_FREE_DESIGN_AWAITING_INDEPENDENT_AUDIT",
            "output_directory": FINAL_OUTPUT.relative_to(PROJECT_ROOT).as_posix(),
            "contract_sha256": contract_sha256(),
            "source_audit_sha256": source_audit.sha256(),
            "synthetic_smoke_semantic_sha256": smoke["semantic_sha256"],
            "tests_run": final_summary["tests_run"],
            "tests_skipped": final_summary["skipped"],
            "gpu_processes": 2,
            "verification": verification,
            "authority": AUTHORITY_ZERO,
            "required_next_step": "independent_score_free_prelaunch_audit",
        }
        sys.stdout.write(json.dumps(output, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
        return 0
    finally:
        if provisional is not None:
            _remove_owned_tree(
                provisional, prefix=".causal_valuation_tcn_v2_provisional."
            )
        if SOURCE_STAGE.exists():
            _remove_owned_tree(
                SOURCE_STAGE, prefix=".causal_valuation_tcn_v2_source_stage"
            )
        if spec is not None and spec.exists():
            spec.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
