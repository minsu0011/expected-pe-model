from __future__ import annotations

import importlib.util
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "model_lab" / "pe_c4_r3_recovery_admissibility_audit_v1.py"


def _module():
    spec = importlib.util.spec_from_file_location("r3_admissibility", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_three_way_verdict() -> None:
    module = _module()
    assert module.decide_verdict(
        statistical_valid=True, preterminal_same_identity_retry_allowed=True
    ) == "FORMALLY_ADMISSIBLE_FOR_PROMOTION"
    assert module.decide_verdict(
        statistical_valid=True, preterminal_same_identity_retry_allowed=False
    ) == "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE"
    assert module.decide_verdict(
        statistical_valid=False, preterminal_same_identity_retry_allowed=True
    ) == "EVIDENCE_INVALID"


def test_serializer_contract_distinguishes_raw_but_preserves_object() -> None:
    module = _module()
    value = {"z": [1, 2], "a": "한글"}
    compact = module.compact_json_bytes(value) + b"\n"
    pretty = module.pretty_json_bytes(value)
    assert compact != pretty
    assert json.loads(compact.decode("utf-8")) == json.loads(pretty.decode("utf-8")) == value


def test_live_audit_is_read_only_and_reaches_conservative_branch() -> None:
    module = _module()
    result = module.audit(REPO)
    assert result["statistical_evidence"] == "VALID"
    assert result["formal_admissibility"] == "FAIL"
    assert result["verdict"] == "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE"
    assert result["next_authority"]["pristine_confirmation_required"] is True
    assert result["next_authority"]["registry_mutation_authorized"] is False
    assert all(row["passed"] for row in result["statistical_checks"])
    assert all(row["passed"] for row in result["governance_checks"])
