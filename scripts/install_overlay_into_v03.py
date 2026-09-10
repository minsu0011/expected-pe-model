from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Copy the v0.4 overlay into a v0.3 repository as an isolated experiment"
    )
    parser.add_argument("--target", required=True, help="Path to the v0.3 repository")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    source = Path(__file__).resolve().parents[1]
    target_root = Path(args.target).expanduser().resolve()
    if not target_root.is_dir():
        raise SystemExit(f"Target repository does not exist: {target_root}")
    destination = target_root / "experiments" / "pe_regime_v04_overlay"
    if destination.exists():
        if not args.overwrite:
            raise SystemExit(
                f"Destination exists: {destination}\nUse --overwrite to replace it."
            )
        shutil.rmtree(destination)

    ignore = shutil.ignore_patterns(
        ".venv",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
        "*.pyc",
        "reports/sample_run*",
    )
    shutil.copytree(source, destination, ignore=ignore)
    print(f"Overlay copied to: {destination}")
    print("No v0.3 core source file was modified.")
    print("Next: read INTEGRATION_GUIDE.md in the copied directory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
