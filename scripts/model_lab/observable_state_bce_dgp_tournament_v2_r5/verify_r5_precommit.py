"""Invoke the one exact standalone R5 bootstrap and print its sealed receipt."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


SELF = (
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
    r"\scripts\model_lab\observable_state_bce_dgp_tournament_v2_r5"
    r"\verify_r5_precommit.py"
)
BOOTSTRAP = (
    r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
    r"\scripts\model_lab\observable_state_bce_dgp_tournament_v2_r5"
    r"\trusted_bootstrap.py"
)
PINNED = (
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
ROOT = r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        nargs="?",
        default="verify_precommit",
        choices=("verify_precommit", "verify_authority_context"),
    )
    args = parser.parse_args()
    if sys.argv[0] != SELF or str(Path(__file__)) != SELF:
        raise RuntimeError("R5 verifier must be called by its exact absolute path")
    parent = os.environ
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "SYSTEMROOT": parent["SYSTEMROOT"],
        "TEMP": parent["TEMP"],
        "TMP": parent["TMP"],
        "WINDIR": parent["WINDIR"],
    }
    completed = subprocess.run(
        [PINNED, "-I", "-S", "-B", "-E", BOOTSTRAP, args.command],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-12000:])
    receipt = json.loads(completed.stdout)
    if (
        not isinstance(receipt, dict)
        or receipt.get("command") != args.command
        or receipt.get("status")
        != "PASS_TRUSTED_VERIFIED_BYTES_ISOLATED_BOOTSTRAP"
    ):
        raise RuntimeError("R5 bootstrap receipt differs")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
