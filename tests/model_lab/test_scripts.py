from __future__ import annotations

import json
from pathlib import Path

from pe_regime_v04.model_lab import RegistryPaths, load_model_registry
from registry_test_support import assert_checked_in_registry_history
from scripts.model_lab.register_baseline_example import main as register_main
from scripts.model_lab.validate_registries import main as validate_main


def test_checked_in_registry_validation_script(capsys) -> None:  # type: ignore[no-untyped-def]
    state = assert_checked_in_registry_history()
    assert validate_main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    assert payload["model_records"] == len(state.latest)
    assert payload["feature_records"] == len(state.features)
    assert payload["true_fair_evaluation_only"] is True


def test_baseline_registration_script_writes_no_model_outputs(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    output = tmp_path / "registry"
    assert register_main([str(output)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    records = load_model_registry(
        RegistryPaths(output / "model_registry.csv", output / "model_registry.json")
    )
    assert len(records) == 1
    assert records[0].model_id == "historical_geometric_mean_pe"
    assert sorted(path.name for path in output.iterdir()) == [
        "model_registry.csv",
        "model_registry.json",
    ]
