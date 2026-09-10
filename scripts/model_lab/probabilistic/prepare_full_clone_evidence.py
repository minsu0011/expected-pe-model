from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _freeze(interpreter: Path, *, root: Path) -> tuple[str, dict[str, str]]:
    completed = subprocess.run(
        [str(interpreter), "-m", "pip", "freeze", "--all"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = sorted(line.strip() for line in completed.stdout.splitlines() if line.strip())
    rendered = "\n".join(lines) + "\n"
    values = {}
    for line in lines:
        name, version = line.split("==", 1)
        values[name.casefold().replace("_", "-")] = version
    return rendered, values


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal dedicated NGBoost full-clone evidence")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--model-lab-python",
        type=Path,
        default=_root().parent / ".venv_pe_model_lab_py310/Scripts/python.exe",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        immutable_write_bytes,
        immutable_write_json,
        immutable_write_text,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_bytes, sha256_file

    output = root / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    model_freeze, model_packages = _freeze(args.model_lab_python, root=root)
    dedicated_freeze, dedicated_packages = _freeze(Path(sys.executable), root=root)
    drift = {
        name: {"model_lab": version, "dedicated": dedicated_packages.get(name)}
        for name, version in model_packages.items()
        if dedicated_packages.get(name) != version
    }
    extras = {
        name: version for name, version in dedicated_packages.items() if name not in model_packages
    }
    expected_extras = {
        "autograd": "1.9.1",
        "autograd-gamma": "0.4.2",
        "formulaic": "1.2.2",
        "interface-meta": "2.0.1",
        "lifelines": "0.30.0",
        "mpmath": "1.3.0",
        "ngboost": "0.5.11",
        "sympy": "1.14.0",
        "tqdm": "4.70.0",
        "wrapt": "2.3.0",
    }
    if drift or extras != expected_extras:
        raise RuntimeError(
            f"dedicated environment is not exact base-plus-NGBoost: {drift=} {extras=}"
        )
    pip_check = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if pip_check.returncode != 0:
        raise RuntimeError(f"dedicated pip check failed: {pip_check.stdout} {pip_check.stderr}")
    clone_packages = [
        "catboost==1.2.10",
        "graphviz==0.21",
        "lightgbm==4.6.0",
        "patsy==1.0.2",
        "plotly==6.9.0",
        "PyYAML==6.0.2",
        "statsmodels==0.14.6",
        "xgboost==3.2.0",
    ]
    with tempfile.TemporaryDirectory(prefix="prob_full_clone_dry_run_") as temporary:
        report_path = Path(temporary) / "report.json"
        dry_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--no-deps",
                "--report",
                str(report_path),
                *clone_packages,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if dry_run.returncode != 0:
            raise RuntimeError(f"full-clone pip dry-run failed: {dry_run.stdout} {dry_run.stderr}")
        report_raw = report_path.read_bytes()
    report = json.loads(report_raw)
    resolved = {
        item["metadata"]["name"].casefold().replace("_", "-"): item["metadata"]["version"]
        for item in report["install"]
    }
    expected_clone = {
        item.split("==", 1)[0].casefold(): item.split("==", 1)[1] for item in clone_packages
    }
    if resolved != expected_clone:
        raise RuntimeError("full-clone dry-run resolved unexpected packages")
    license_records = []
    for distribution in sorted(
        importlib.metadata.distributions(),
        key=lambda item: (item.metadata.get("Name", "").casefold(), item.version),
    ):
        name = distribution.metadata.get("Name", "")
        files = []
        for relative in distribution.files or ():
            basename = Path(str(relative)).name.upper()
            if not basename.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                continue
            path = Path(distribution.locate_file(relative))
            if path.is_file():
                files.append(
                    {
                        "relative_path": str(relative).replace("\\", "/"),
                        "sha256": sha256_file(path),
                        "bytes": path.stat().st_size,
                    }
                )
        classifiers = sorted(
            value
            for value in distribution.metadata.get_all("Classifier", [])
            if value.startswith("License ::")
        )
        license_records.append(
            {
                "name": name,
                "version": distribution.version,
                "license_expression": distribution.metadata.get("License-Expression"),
                "license_metadata": distribution.metadata.get("License"),
                "license_classifiers": classifiers,
                "license_notice_files": files,
                "metadata_home_page": distribution.metadata.get("Home-page"),
                "metadata_project_urls": sorted(distribution.metadata.get_all("Project-URL", [])),
            }
        )
    if any(
        not (
            record["license_expression"]
            or record["license_metadata"]
            or record["license_classifiers"]
            or record["license_notice_files"]
        )
        for record in license_records
    ):
        raise RuntimeError("a dedicated transitive package has no installed license evidence")
    model_freeze_path = output / "MODEL_LAB_FULL_PACKAGE_FREEZE.txt"
    dedicated_freeze_path = output / "NGBOOST_FULL_PACKAGE_FREEZE.txt"
    pip_check_path = output / "NGBOOST_FULL_PIP_CHECK.txt"
    report_output_path = output / "NGBOOST_FULL_CLONE_PIP_DRY_RUN.json"
    immutable_write_text(model_freeze_path, model_freeze)
    immutable_write_text(dedicated_freeze_path, dedicated_freeze)
    immutable_write_text(
        pip_check_path,
        pip_check.stdout.replace("\r\n", "\n") + pip_check.stderr.replace("\r\n", "\n"),
    )
    immutable_write_bytes(report_output_path, report_raw)
    license_path = output / "NGBOOST_TRANSITIVE_LICENSE_INVENTORY.json"
    immutable_write_json(
        license_path,
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_license_inventory.v2",
            "status": "PASS_INSTALLED_METADATA_AND_NOTICE_BYTES_BOUND",
            "records": license_records,
        },
    )
    immutable_write_json(
        output / "NGBOOST_FULL_CLONE_EVIDENCE.json",
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_full_clone.v2",
            "status": "PASS_EXACT_MODEL_LAB_PLUS_NGBOOST_DEPENDENCIES",
            "model_lab_freeze_sha256": sha256_bytes(model_freeze.encode()),
            "dedicated_freeze_sha256": sha256_bytes(dedicated_freeze.encode()),
            "common_package_count": len(model_packages),
            "common_package_version_drift": drift,
            "dedicated_additions": extras,
            "pip_check": "PASS_NO_BROKEN_REQUIREMENTS",
            "pip_dry_run_report_sha256": sha256_bytes(report_raw),
            "pip_dry_run_exact_no_deps_additions": resolved,
            "license_inventory_sha256": sha256_file(license_path),
            "base_environment_modified": False,
        },
    )
    print("PASS_EXACT_MODEL_LAB_PLUS_NGBOOST_DEPENDENCIES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
