from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _run(command: list[str], *, cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed.stdout.replace("\r\n", "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze dedicated NGBoost environment evidence")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--model-lab-python",
        type=Path,
        default=_root().parent / ".venv_pe_model_lab_py310/Scripts/python.exe",
    )
    parser.add_argument(
        "--dedicated-python",
        type=Path,
        default=_root().parent / ".venv_pe_probabilistic_py310/Scripts/python.exe",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        base_artifact_payload,
        immutable_write_json,
        immutable_write_text,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_file
    from pe_regime_v04.model_lab.probabilistic.environment import (
        MODEL_LAB_LOCK_SHA256,
        OFFICIAL_LICENSE_URL,
        OFFICIAL_METADATA_URL,
        verify_dedicated_freeze,
        verify_dry_run_report,
    )

    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    dry_run_path = output / "NGBOOST_PIP_DRY_RUN.json"
    dry_run = verify_dry_run_report(dry_run_path)
    model_lock = root / "outputs/model_lab_environment_20260819/fully_resolved_environment.lock.txt"
    if sha256_file(model_lock) != MODEL_LAB_LOCK_SHA256:
        raise RuntimeError("original Model Lab lock drifted")
    model_freeze = _run(
        [str(args.model_lab_python), "-m", "pip", "freeze", "--all"],
        cwd=args.model_lab_python.resolve().parents[1],
    )
    dedicated_freeze = _run(
        [str(args.dedicated_python), "-m", "pip", "freeze", "--all"],
        cwd=args.dedicated_python.resolve().parents[1],
    )
    packages = verify_dedicated_freeze(dedicated_freeze)
    model_packages = {
        line.split("==", 1)[0].casefold().replace("_", "-"): line.split("==", 1)[1]
        for line in model_freeze.splitlines()
        if "==" in line
    }
    resolver_changes = {
        name: {"existing": model_packages[name], "resolved": version}
        for name, version in dry_run["resolved_additions"].items()
        if name in model_packages and model_packages[name] != version
    }
    if resolver_changes:
        raise RuntimeError(
            f"pip resolver would alter existing Model Lab packages: {resolver_changes}"
        )
    pip_check = _run(
        [str(args.dedicated_python), "-m", "pip", "check"],
        cwd=args.dedicated_python.resolve().parents[1],
    )
    if pip_check.strip() != "No broken requirements found.":
        raise RuntimeError("dedicated pip check did not return the exact clean status")
    probe_code = (
        "import importlib.metadata as m,json,platform,sys;"
        "d=m.distribution('ngboost');"
        "f=next(x for x in d.files if x.name.upper()=='LICENSE');p=d.locate_file(f);"
        "print(json.dumps({'python':platform.python_version(),"
        "'implementation':platform.python_implementation(),"
        "'license':d.metadata.get('License'),"
        "'license_classifier':[x for x in d.metadata.get_all('Classifier',[]) if 'License' in x],"
        "'requires_python':d.metadata.get('Requires-Python'),"
        "'license_path':str(p)},sort_keys=True))"
    )
    probe = json.loads(
        _run(
            [str(args.dedicated_python), "-c", probe_code],
            cwd=args.dedicated_python.resolve().parents[1],
        )
    )
    license_path = Path(probe.pop("license_path"))
    freeze_path = output / "NGBOOST_PACKAGE_FREEZE.txt"
    check_path = output / "NGBOOST_PIP_CHECK.txt"
    immutable_write_text(freeze_path, dedicated_freeze)
    immutable_write_text(check_path, pip_check)
    environment = base_artifact_payload(artifact_type="NGBOOST_DEDICATED_ENVIRONMENT")
    environment.update(
        {
            "status": "PASS_DEDICATED_ENVIRONMENT_REQUIRED",
            "strategy": "dedicated_venv_preserves_original_model_lab_inventory",
            "dedicated_interpreter": str(args.dedicated_python.resolve()),
            "model_lab_interpreter": str(args.model_lab_python.resolve()),
            "python": probe["python"],
            "implementation": probe["implementation"],
            "exact_packages": packages,
            "package_freeze_sha256": sha256_file(freeze_path),
            "pip_check_sha256": sha256_file(check_path),
            "original_model_lab_lock_sha256": MODEL_LAB_LOCK_SHA256,
            "original_model_lab_lock_unchanged": True,
            "model_lab_dry_run_existing_version_changes": resolver_changes,
            "model_lab_dry_run_add_only": not resolver_changes,
            "dry_run": dry_run,
        }
    )
    immutable_write_json(output / "NGBOOST_ENVIRONMENT.json", environment)
    package_manifest = base_artifact_payload(artifact_type="NGBOOST_PACKAGE_MANIFEST")
    package_manifest.update(
        {
            "status": "PASS_EXACT_PINS_AND_RESOLVER_ARTIFACTS",
            "dedicated_exact_packages": packages,
            "dedicated_package_freeze_sha256": sha256_file(freeze_path),
            "model_lab_dry_run_resolved_artifacts": dry_run["resolved_artifacts"],
            "model_lab_existing_package_version_changes": resolver_changes,
            "resolver_result": "ADD_ONLY_NO_UPGRADE_NO_DOWNGRADE",
        }
    )
    immutable_write_json(output / "NGBOOST_PACKAGE_MANIFEST.json", package_manifest)
    license_evidence = base_artifact_payload(artifact_type="NGBOOST_LICENSE_EVIDENCE")
    license_evidence.update(
        {
            "status": "PASS",
            "package": "ngboost==0.5.11",
            "installed_wheel_license_field": probe["license"],
            "installed_wheel_license_classifiers": probe["license_classifier"],
            "installed_license_file_sha256": sha256_file(license_path),
            "requires_python": probe["requires_python"],
            "official_tagged_license_url": OFFICIAL_LICENSE_URL,
            "official_pypi_metadata_url": OFFICIAL_METADATA_URL,
            "wheel_sha256": dry_run["ngboost_wheel_sha256"],
            "notice": (
                "No NGBoost source is copied or vendored; preserve applicable notices on "
                "redistribution."
            ),
        }
    )
    immutable_write_json(output / "NGBOOST_LICENSE_EVIDENCE.json", license_evidence)
    print(json.dumps({"status": "PASS", "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
