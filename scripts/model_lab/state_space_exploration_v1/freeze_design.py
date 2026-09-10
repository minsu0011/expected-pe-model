"""Freeze the score-blind state-space research design and source inventory."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

# ruff: noqa: E402


ROOT = Path(__file__).resolve().parents[3]
for item in (ROOT, ROOT / "src"):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from research.model_zoo.state_space_exploration_v1.spec import DESIGN_OUTPUT, design_payload
from research.model_zoo.state_space_exploration_v1.runner import _runtime_snapshot


SOURCES = (
    "research/model_zoo/state_space_exploration_v1/__init__.py",
    "research/model_zoo/state_space_exploration_v1/adapters.py",
    "research/model_zoo/state_space_exploration_v1/evaluation.py",
    "research/model_zoo/state_space_exploration_v1/runner.py",
    "research/model_zoo/state_space_exploration_v1/spec.py",
    "scripts/model_lab/state_space_exploration_v1/evaluate.py",
    "scripts/model_lab/state_space_exploration_v1/freeze_design.py",
    "scripts/model_lab/state_space_exploration_v1/run_predictions.py",
    "tests/model_lab/test_state_space_exploration_v1.py",
)
DEPENDENCIES = (
    "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json",
    "outputs/model_zoo_aggressive_full_load_20260820/DESIGN_LOCK.json",
    "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
    "research/model_zoo/aggressive_lab/__init__.py",
    "research/model_zoo/aggressive_lab/artifacts.py",
    "research/model_zoo/aggressive_lab/contracts.py",
    "research/model_zoo/aggressive_lab/evaluation.py",
    "research/model_zoo/aggressive_lab/full_load_resources.py",
    "research/model_zoo/aggressive_lab/resources.py",
    "src/pe_regime_v04/__init__.py",
    "src/pe_regime_v04/model_lab/__init__.py",
    "src/pe_regime_v04/model_lab/analysis.py",
    "src/pe_regime_v04/model_lab/baselines.py",
    "src/pe_regime_v04/model_lab/contracts.py",
    "src/pe_regime_v04/model_lab/dataset.py",
    "src/pe_regime_v04/model_lab/evaluator.py",
    "src/pe_regime_v04/model_lab/experiment.py",
    "src/pe_regime_v04/model_lab/folds.py",
    "src/pe_regime_v04/model_lab/matrices.py",
    "src/pe_regime_v04/model_lab/models/__init__.py",
    "src/pe_regime_v04/model_lab/models/wave1/__init__.py",
    "src/pe_regime_v04/model_lab/models/wave1/adapters.py",
    "src/pe_regime_v04/model_lab/models/wave1/artifacts.py",
    "src/pe_regime_v04/model_lab/models/wave1/resources.py",
    "src/pe_regime_v04/model_lab/models/wave1/runner.py",
    "src/pe_regime_v04/model_lab/models/wave1/spec.py",
    "src/pe_regime_v04/model_lab/registry.py",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    output = ROOT / DESIGN_OUTPUT
    if output.exists():
        raise SystemExit("state-space design output already exists")
    payload = design_payload()
    payload["source_sha256"] = {name: sha(ROOT / name) for name in SOURCES}
    payload["dependency_sha256"] = {name: sha(ROOT / name) for name in DEPENDENCIES}
    payload["runtime"] = _runtime_snapshot()
    raw = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
    output.mkdir(parents=True)
    (output / "DESIGN_LOCK.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (output / "DESIGN_LOCK.sha256").write_text(
        f"{digest}  DESIGN_LOCK.json\n", encoding="utf-8", newline="\n"
    )
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
