from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "model_lab" / "real_market" / "run_public_pit_pilot.py"


def test_live_pilot_requires_explicit_ack_before_any_read_or_write(tmp_path: Path) -> None:
    output = tmp_path / "must_not_exist"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--user-agent",
            "PE-Regime-PIT research@example.org",
            "--sessions-file",
            str(tmp_path / "intentionally_missing.txt"),
            "--output-dir",
            str(output),
            "--cik",
            "0000320193",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 2
    assert "live network is disabled" in result.stderr
    assert not output.exists()
