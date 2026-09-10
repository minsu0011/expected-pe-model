"""Independent, read-only admissibility audit for the recovered R3 heldout evidence.

This auditor intentionally separates statistical/model validity from formal custody
admissibility.  It never opens a truth or latent payload.  It reads only public/spent
evidence, the protected vault *manifest metadata* leaf, and the frozen prediction CSV.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


RUN_ID = "r3_20260824T134417"
MODEL_IDS = [
    "v04_expected_pe",
    "hofs_v4_expected_pe",
    "bce_v1_d_observable_state_confidence_shrinkage",
    "bce_tournament_v1_fixed_alpha_040_directional_consensus",
]
EXPECTED_RAW = {
    "terminal": "59376b65a2c39322818ad1ccda97bbb0fb876fca3e265168e67259659fa7e387",
    "recovery_authority": "21215ac8efc2c683c502c1efb8333de6b0340fa65e361d934e60a53886464c07",
    "normalization_claim": "35f69111bc6990ea8566625df53d5c678b377b254d0dc4d7110ff39c52f99e4d",
    "normalization_receipt": "05dfd9f8a975cd8e23458026e4d128bf0c7c83f9ce1d1d950ae8fdc64363f419",
    "bridge": "ec105ff2cee6d95b86d3063c38cfd0135ec48fe682fed6117577a0e293f03346",
    "activation_preuse": "7593c3c2a26ff33ac8ff1b2d52777cc226dfcafec5d4622bbaa6334da544f245",
    "activation_claim": "b2f37a2c5dddcba2efab7dbe57c5cc65eef557970a1ffe86052ae28eb5e89c63",
    "activation_success": "3b62f39ed9d9d652d2421189cb75202ea57ba2dbcfa3871d14bddbe4cc78831b",
    "prediction": "ade847f02fc5f025f665ca023c4d537ee371dc199fbe43780fb70e31d2251099",
    "prediction_seal": "93e2697e289acf8496061be7f0d3ea1fdc1e84c177459550443c17b62d25e9fb",
    "activation": "f52d0ddd60abacf03479884d869bb03a597f5f86642f69e021c52d2bd4ae42f3",
    "marker": "93d21a46b4f811ae65d428c3d958892989a37ac1a1cd53022f3ba79bd38a0cea",
    "result": "5f0a3b85c75a59ac4ee714cfcd570687abd6907aff9db48439563b0c1be93064",
    "old_manifest": "731efc61fe7469bb6b9efd9ab517bbc7ea6699d2896234d4a1ca9373c755dc87",
    "new_manifest": "d0a3ac148f153c7c726c132012045b9837f3390a7bccd4ba634bf2a9c3df2d4e",
    "manifest_semantic": "877be05224a3b8c85020a56a2ad80afba4d18c9976194199c2690db36da33893",
}


class AuditFailure(RuntimeError):
    """Raised when an input cannot be audited safely."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def pretty_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def semantic_sha256(value: Any) -> str:
    return sha256_bytes(compact_json_bytes(value))


def load_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditFailure(f"invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AuditFailure(f"top-level JSON object required: {path}")
    return raw, value


def _check(checks: list[dict[str, Any]], check_id: str, passed: bool, detail: Any) -> None:
    checks.append({"check_id": check_id, "passed": bool(passed), "detail": detail})


def decide_verdict(*, statistical_valid: bool, preterminal_same_identity_retry_allowed: bool) -> str:
    """Return the three-way verdict required by the governing prompt."""

    if not statistical_valid:
        return "EVIDENCE_INVALID"
    if preterminal_same_identity_retry_allowed:
        return "FORMALLY_ADMISSIBLE_FOR_PROMOTION"
    return "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE"


def _source_records(source_manifest: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for key in (
        "adapter_source_records",
        "c2_c3_frozen_numeric_source_records",
        "c4_source_tree_records",
        "c4_source_file_records",
    ):
        records = source_manifest.get(key)
        if not isinstance(records, list):
            raise AuditFailure(f"source manifest record group missing: {key}")
        for record in records:
            if not isinstance(record, dict):
                raise AuditFailure(f"invalid source record in {key}")
            yield record


def _paths(repo: Path) -> dict[str, Path]:
    recovery = repo / "build" / f"pe_four_model_heldout_r3_activation_recovery_{RUN_ID}"
    prediction = repo / "outputs" / f"model_zoo_pe_four_model_heldout_predictions_{RUN_ID}"
    scoring = repo / "outputs" / f"model_zoo_pe_model_portfolio_heldout_certification_result_{RUN_ID}"
    return {
        "terminal": repo / "build" / f"pe_four_model_heldout_r3_activation_terminal_{RUN_ID}" / "R3_ACTIVATION_TERMINAL.json",
        "recovery_authority": recovery / "R3_VAULT_MANIFEST_RECOVERY_AUTHORITY.json",
        "normalization_claim": recovery / "NORMALIZATION_INVOCATION_CLAIM.json",
        "normalization_receipt": recovery / "NORMALIZATION_RECEIPT.json",
        "bridge": recovery / "R3_RECOVERY_SUPERSESSION_BRIDGE.json",
        "activation_preuse": recovery / "R3_RECOVERY_ACTIVATION_PREUSE_AUTHORITY.json",
        "activation_claim": recovery / "ACTIVATION_INVOCATION_CLAIM.json",
        "activation_success": recovery / "ACTIVATION_SUCCESS_RECEIPT.json",
        "old_manifest": recovery / "VAULT_MANIFEST_PRE_NORMALIZATION.json",
        "new_manifest": repo / "outputs" / f".model_zoo_pe_four_model_heldout_vault_{RUN_ID}" / "VAULT_MANIFEST.json",
        "prediction": prediction / "PREDICTIONS.csv",
        "prediction_manifest": prediction / "PREDICTION_MANIFEST.json",
        "prediction_receipt": prediction / "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
        "prediction_audit": prediction / "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
        "prediction_seal": prediction / "AUDIT_SEAL.json",
        "source_manifest": prediction / "SOURCE_MANIFEST.json",
        "activation": repo / "outputs" / f"model_zoo_pe_model_portfolio_heldout_activation_{RUN_ID}" / "HELDOUT_EVALUATION_ACTIVATION.json",
        "marker": scoring / "HELDOUT_CONSUMPTION_MARKER.json",
        "result": scoring / "HELDOUT_CERTIFICATION_RESULT.json",
        "project_direction": repo / "research" / "model_zoo" / "portfolio_governance_v1" / "PROJECT_DIRECTION.md",
        "execution_authority": repo / "build" / f"pe_four_model_heldout_execution_authority_{RUN_ID}.json",
    }


def audit(repo: Path) -> dict[str, Any]:
    paths = _paths(repo)
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise AuditFailure(f"required artifacts missing: {missing}")

    loaded: dict[str, dict[str, Any]] = {}
    raw: dict[str, bytes] = {}
    json_names = [name for name in paths if name not in {"prediction", "project_direction"}]
    for name in json_names:
        raw[name], loaded[name] = load_json(paths[name])

    statistical: list[dict[str, Any]] = []
    governance: list[dict[str, Any]] = []

    for name in (
        "terminal",
        "recovery_authority",
        "normalization_claim",
        "normalization_receipt",
        "bridge",
        "activation_preuse",
        "activation_claim",
        "activation_success",
        "prediction_seal",
        "activation",
        "marker",
        "result",
    ):
        actual = sha256_bytes(raw[name])
        _check(statistical, f"raw_hash.{name}", actual == EXPECTED_RAW[name], actual)

    terminal = loaded["terminal"]
    terminal_access = terminal["access"]
    terminal_zero = (
        terminal_access["heldout_truth_payload_open_count"] == 0
        and terminal_access["protected_latent_payload_open_count"] == 0
        and terminal_access["score_open_count"] == 0
        and terminal_access["certification_scorer_invoked"] is False
        and terminal_access["activation_output_claimed"] is False
        and terminal["activation_attempt"]["failed_before_claim_output_root"] is True
    )
    _check(statistical, "first_terminal.preperformance_boundary", terminal_zero, terminal_access)

    old_raw, old_manifest = raw["old_manifest"], loaded["old_manifest"]
    new_raw, new_manifest = raw["new_manifest"], loaded["new_manifest"]
    old_unsigned = dict(old_manifest)
    new_unsigned = dict(new_manifest)
    old_declared_semantic = old_unsigned.pop("vault_manifest_semantic_sha256", None)
    new_declared_semantic = new_unsigned.pop("vault_manifest_semantic_sha256", None)
    serializer_exact = (
        sha256_bytes(old_raw) == EXPECTED_RAW["old_manifest"]
        and sha256_bytes(new_raw) == EXPECTED_RAW["new_manifest"]
        and old_raw == compact_json_bytes(old_manifest) + b"\n"
        and new_raw == pretty_json_bytes(new_manifest)
        and old_manifest == new_manifest
        and old_declared_semantic == EXPECTED_RAW["manifest_semantic"]
        and new_declared_semantic == EXPECTED_RAW["manifest_semantic"]
        and semantic_sha256(old_unsigned) == EXPECTED_RAW["manifest_semantic"]
        and semantic_sha256(new_unsigned) == EXPECTED_RAW["manifest_semantic"]
        and old_manifest.get("truth_refs") == new_manifest.get("truth_refs")
    )
    _check(
        statistical,
        "recovery.serialization_only_exact",
        serializer_exact,
        {
            "old_raw_sha256": sha256_bytes(old_raw),
            "new_raw_sha256": sha256_bytes(new_raw),
            "semantic_sha256": old_declared_semantic,
            "decoded_json_exact_equal": old_manifest == new_manifest,
            "truth_ref_count": len(old_manifest.get("truth_refs", [])),
        },
    )

    receipt = loaded["normalization_receipt"]
    bridge = loaded["bridge"]
    mutation_zero = (
        receipt["candidate_or_model_mutation_count"] == 0
        and receipt["prediction_mutation_count"] == 0
        and receipt["frozen_source_mutation_count"] == 0
        and receipt["registry_or_seed_mutation_count"] == 0
        and receipt["other_vault_mutation_count"] == 0
        and receipt["vault_manifest_mutation_count"] == 1
        and receipt["vault_atomic_replace_count"] == 1
        and receipt["truth_payload_open_count"] == 0
        and receipt["latent_payload_open_count"] == 0
        and receipt["score_open_count"] == 0
        and receipt["truth_ref_resolve_or_stat_count"] == 0
        and receipt["truth_ref_inventory_exact_equal"] is True
        and receipt["decoded_json_exact_equal"] is True
    )
    _check(statistical, "recovery.mutation_and_access_scope", mutation_zero, {
        "manifest_mutations": receipt["vault_manifest_mutation_count"],
        "prediction_mutations": receipt["prediction_mutation_count"],
        "model_mutations": receipt["candidate_or_model_mutation_count"],
        "source_mutations": receipt["frozen_source_mutation_count"],
        "seed_or_registry_mutations": receipt["registry_or_seed_mutation_count"],
        "truth_opens": receipt["truth_payload_open_count"],
        "latent_opens": receipt["latent_payload_open_count"],
        "score_opens": receipt["score_open_count"],
    })
    bridge_zero = (
        bridge["access"]["heldout_performance_information_observed"] is False
        and bridge["access"]["truth_payload_open_count"] == 0
        and bridge["access"]["latent_payload_open_count"] == 0
        and bridge["access"]["score_open_count"] == 0
        and bridge["scope"]["model_formula_seed_prediction_identity_unchanged"] is True
        and bridge["scope"]["pristine_first_attempt_claim"] is False
    )
    _check(statistical, "recovery.no_performance_conditioning", bridge_zero, bridge["access"])

    prediction_hash = file_sha256(paths["prediction"])
    line_count = 0
    with paths["prediction"].open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            line_count += block.count(b"\n")
    prediction_manifest = loaded["prediction_manifest"]
    prediction_receipt = loaded["prediction_receipt"]
    prediction_audit = loaded["prediction_audit"]
    prediction_seal = loaded["prediction_seal"]
    prediction_exact = (
        prediction_hash == EXPECTED_RAW["prediction"]
        and prediction_manifest["prediction_raw_sha256"] == prediction_hash
        and prediction_receipt["prediction_raw_sha256"] == prediction_hash
        and prediction_audit["prediction_raw_sha256"] == prediction_hash
        and prediction_seal["prediction_raw_sha256"] == prediction_hash
        and prediction_manifest["prediction_row_count"] == 259_200
        and line_count == 259_201
        and prediction_audit["checks"]["prediction_recomputed_exact"] is True
    )
    _check(statistical, "prediction.full_byte_immutability", prediction_exact, {
        "raw_sha256": prediction_hash,
        "data_rows": line_count - 1,
        "independent_recomputation_exact": prediction_audit["checks"]["prediction_recomputed_exact"],
    })

    activation = loaded["activation"]
    result = loaded["result"]
    scorecard_path = repo / "build" / f"pe_four_model_heldout_r3_final_scorecard_{RUN_ID}" / "R3_FINAL_SCORECARD.json"
    _, scorecard = load_json(scorecard_path)
    result_candidates = [
        result["score"]["champion"]["model_id"],
        *[row["candidate_id"] for row in result["score"]["candidate_results_in_qualification_rank_order"]],
    ]
    candidate_exact = (
        prediction_manifest["model_ids_in_fixed_adjacent_order"] == MODEL_IDS
        and prediction_receipt["model_ids_in_order"] == MODEL_IDS
        and prediction_audit["model_ids_in_order"] == MODEL_IDS
        and activation["model_ids_in_order"] == MODEL_IDS
        and result_candidates == MODEL_IDS
        and [row["candidate_id"] for row in scorecard["rows"]] == MODEL_IDS
    )
    _check(statistical, "candidate.identity_and_order_unchanged", candidate_exact, result_candidates)

    formula_hash = prediction_manifest["formula_lock_semantic_sha256"]
    formula_exact = (
        formula_hash == "0f0a0fca901252d2e128a3ee4ab63bc9f20a7f76ead170171f4ec6af0472ce30"
        and prediction_receipt["formula_lock_semantic_sha256"] == formula_hash
        and activation["formula_lock_semantic_sha256"] == formula_hash
        and loaded["marker"]["formula_lock_semantic_sha256"] == formula_hash
    )
    _check(statistical, "candidate.formula_lock_unchanged", formula_exact, formula_hash)

    source_manifest = loaded["source_manifest"]
    source_drift: list[dict[str, str]] = []
    source_count = 0
    for record in _source_records(source_manifest):
        source_count += 1
        rel = str(record.get("relative_path"))
        path = repo / Path(rel)
        actual = file_sha256(path) if path.is_file() else "MISSING"
        if actual != record.get("raw_sha256"):
            source_drift.append({"relative_path": rel, "expected": str(record.get("raw_sha256")), "actual": actual})
    _check(statistical, "source.frozen_closure", source_count == 137 and not source_drift, {
        "record_count": source_count,
        "drift_count": len(source_drift),
        "drift": source_drift,
    })

    marker = loaded["marker"]
    scorer_exact = (
        marker["status"] == "CONSUMED_DURABLY_BEFORE_FIRST_HELDOUT_TRUTH_OPEN"
        and marker["truth_open_count_at_publication"] == 0
        and marker["candidate_tuning_count"] == 0
        and marker["heldout_reranking_count"] == 0
        and marker["prediction_raw_sha256"] == prediction_hash
        and result["prediction_binding"]["prediction_raw_sha256"] == prediction_hash
        and result["prediction_binding"]["consumption_marker_raw_sha256"] == EXPECTED_RAW["marker"]
        and result["candidate_tuning_count"] == 0
        and result["heldout_reranking_count"] == 0
        and result["truth_custody"]["exact_pass_1_truth_leaf_count"] == 50
        and result["truth_custody"]["pass_2_open_count"] == 0
        and result["truth_custody"]["latent_open_count"] == 0
        and result["retry_allowed"] is False
        and result["production_promotion_authority"] is False
    )
    _check(statistical, "scoring.one_shot_custody", scorer_exact, {
        "marker_before_truth": marker["truth_open_count_at_publication"] == 0,
        "pass_1_truth_leaves": result["truth_custody"]["exact_pass_1_truth_leaf_count"],
        "pass_2_opens": result["truth_custody"]["pass_2_open_count"],
        "latent_opens": result["truth_custody"]["latent_open_count"],
        "candidate_tuning": result["candidate_tuning_count"],
        "reranking": result["heldout_reranking_count"],
    })

    c4 = result["score"]["candidate_results_in_qualification_rank_order"][0]
    c4_exact = (
        c4["candidate_id"] == "hofs_v4_expected_pe"
        and c4["candidate_tuned"] is False
        and c4["heldout_reranked"] is False
        and c4["fallback_or_substitution_used"] is False
        and c4["gate"]["all_heldout_gates_pass"] is True
        and c4["seed_wins"] == 5
        and c4["tail_metrics"]["systematic_dgp_joint_tail_failure_count"] == 0
    )
    _check(statistical, "c4.heldout_result_exact", c4_exact, {
        "mae_gain": c4["pooled_metrics"]["mae_relative_gain_vs_v04"],
        "rmse_gain": c4["pooled_metrics"]["rmse_relative_gain_vs_v04"],
        "seed_wins": c4["seed_wins"],
        "dgp_wins": sum(row["dgp_mean_gain"] > 0.0 for row in c4["dgp_mean_metrics"]),
        "joint_tail_failures": c4["tail_metrics"]["systematic_dgp_joint_tail_failure_count"],
        "bootstrap_lower_5pct": c4["bootstrap"]["mae_relative_gain_lower_5pct"],
    })

    direction_raw = paths["project_direction"].read_text(encoding="utf-8")
    terminal_policy_exact = (
        terminal["activation_attempt"]["formal_retry_allowed"] is False
        and terminal["scope"]["terminalize_exact_r3_identity"] is True
        and terminal["next_authority"]["new_fresh_seed_identity_required"] is True
        and terminal["next_authority"]["reuse_r3_predictions"] is False
        and terminal["next_authority"]["reuse_r3_seeds"] is False
        and terminal["next_authority"]["run_r3_activation_again"] is False
        and "해당 identity는 terminal `NO_GO`이며 같은 identity를 재실행하지 않는다." in direction_raw
    )
    _check(governance, "preterminal.fail_closed_policy", terminal_policy_exact, {
        "formal_retry_allowed": terminal["activation_attempt"]["formal_retry_allowed"],
        "terminalize_exact_r3_identity": terminal["scope"]["terminalize_exact_r3_identity"],
        "new_fresh_seed_identity_required": terminal["next_authority"]["new_fresh_seed_identity_required"],
        "reuse_r3_predictions": terminal["next_authority"]["reuse_r3_predictions"],
        "reuse_r3_seeds": terminal["next_authority"]["reuse_r3_seeds"],
        "run_r3_activation_again": terminal["next_authority"]["run_r3_activation_again"],
        "project_direction_raw_sha256": file_sha256(paths["project_direction"]),
    })

    execution_raw = paths["execution_authority"].read_bytes()
    recovery_authority_hash = EXPECTED_RAW["recovery_authority"].encode("ascii")
    no_preterminal_waiver = (
        recovery_authority_hash not in execution_raw
        and recovery_authority_hash not in raw["terminal"]
        and bridge["scope"]["metadata_serialization_recovered_r3_evidence_revision"] is True
        and bridge["scope"]["production_promotion_authority"] is False
        and any(
            item.get("field_path") == "prepublication terminal.next_authority"
            for item in bridge["supersedes"]
        )
    )
    _check(governance, "recovery.no_preterminal_waiver_or_promotion_authority", no_preterminal_waiver, {
        "recovery_authority_bound_by_preterminal_execution_authority": recovery_authority_hash in execution_raw,
        "recovery_authority_bound_by_terminal": recovery_authority_hash in raw["terminal"],
        "bridge_attempts_to_supersede_terminal_next_authority": True,
        "bridge_production_promotion_authority": bridge["scope"]["production_promotion_authority"],
    })

    statistical_valid = all(item["passed"] for item in statistical)
    preterminal_same_identity_retry_allowed = not terminal_policy_exact
    verdict = decide_verdict(
        statistical_valid=statistical_valid,
        preterminal_same_identity_retry_allowed=preterminal_same_identity_retry_allowed,
    )
    formal_pass = verdict == "FORMALLY_ADMISSIBLE_FOR_PROMOTION"
    governance_pass = all(item["passed"] for item in governance)

    core: dict[str, Any] = {
        "schema_version": "expected_pe.c4.r3_recovery_admissibility_audit.v1",
        "run_id": RUN_ID,
        "status": "AUDIT_COMPLETE",
        "evidence_class": "SERIALIZATION_RECOVERED_R3_NOT_PRISTINE_FIRST_ACTIVATION_ATTEMPT",
        "statistical_evidence": "VALID" if statistical_valid else "INVALID",
        "formal_admissibility": "PASS" if formal_pass else "FAIL",
        "verdict": verdict,
        "reason": (
            "The performance evidence is statistically intact: the first failure preceded output/truth/score, "
            "the only recovery mutation was a semantic-identical manifest serialization transition, and frozen "
            "prediction/model/formula/seed identities remained exact. Formal promotion admissibility nevertheless "
            "fails because the pre-existing terminal record and governing policy explicitly prohibited same-identity "
            "retry/reuse and required a new fresh-seed identity; the later bridge had no preterminal waiver and grants "
            "no production-promotion authority."
            if statistical_valid and not formal_pass
            else "One or more statistical integrity checks failed."
            if not statistical_valid
            else "Both statistical validity and the preterminal formal policy permit promotion evidence use."
        ),
        "c4_current_status": (
            "STRONGLY_VALIDATED_MODEL_EVIDENCE__PROMOTION_AUTHORITY_INSUFFICIENT__PRISTINE_CONFIRMATION_REQUIRED"
            if verdict == "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE"
            else "FORMAL_PROMOTION_CANDIDATE"
            if verdict == "FORMALLY_ADMISSIBLE_FOR_PROMOTION"
            else "EVIDENCE_INVALID"
        ),
        "statistical_checks": statistical,
        "governance_checks": governance,
        "governance_evidence_consistent": governance_pass,
        "artifact_hashes": {name: file_sha256(paths[name]) for name in EXPECTED_RAW if name in paths},
        "access_statement": {
            "auditor_truth_payload_open_count": 0,
            "auditor_latent_payload_open_count": 0,
            "auditor_protected_payload_directory_enumeration_count": 0,
            "auditor_read_vault_manifest_metadata_only": True,
            "auditor_read_spent_performance_result": True,
        },
        "next_authority": {
            "modify_c4": False,
            "reuse_r3_as_formal_promotion_evidence": formal_pass,
            "pristine_confirmation_required": verdict == "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE",
            "same_c4_source_formula_coefficient_features": True,
            "new_fresh_execution_identity_required": verdict == "STATISTICALLY_VALID_BUT_NOT_FORMALLY_ADMISSIBLE",
            "release_validation_may_prepare_but_final_promotion_requires_pristine_confirmation": not formal_pass,
            "registry_mutation_authorized": False,
        },
    }
    return {**core, "audit_semantic_sha256": semantic_sha256(core)}


def render_report(audit_result: Mapping[str, Any]) -> str:
    failed_stat = [row["check_id"] for row in audit_result["statistical_checks"] if not row["passed"]]
    failed_gov = [row["check_id"] for row in audit_result["governance_checks"] if not row["passed"]]
    return f"""# C4 R3 Recovery Admissibility Independent Audit

## 최종 판정

```text
R3 RECOVERY ADMISSIBILITY

Statistical evidence: {audit_result['statistical_evidence']}
Formal admissibility: {audit_result['formal_admissibility']}
Verdict: {audit_result['verdict']}
C4 current status: {audit_result['c4_current_status']}
```

## 이유

R3 첫 activation failure는 output claim, truth, latent, score 및 performance summary가 생기기 전에
발생했다. Recovery는 vault manifest 한 leaf의 compact+LF bytes를 같은 JSON object의 pretty+LF
bytes로 정확히 한 번 바꿨으며, semantic hash·truth-ref inventory·prediction·candidate·formula·seed·
source identity는 유지됐다. 따라서 모델 성능 증거는 통계적으로 유효하다.

그러나 첫 terminal evidence는 `formal_retry_allowed=false`, `reuse_r3_predictions=false`,
`reuse_r3_seeds=false`, `run_r3_activation_again=false`, `new_fresh_seed_identity_required=true`를
명시했다. 상위 PROJECT_DIRECTION도 terminal identity의 동일 identity 재실행을 금지한다. 뒤에
생성된 recovery bridge는 그 terminal next-authority를 사후 supersede했지만, preterminal execution
authority에 그러한 waiver가 없고 bridge 자체도 `production_promotion_authority=false`다.

따라서 정확한 분류는 **통계적으로 유효하지만 formal Champion promotion evidence로는 불충분**이다.
C4를 바꾸지 않은 새 pristine confirmation identity가 필요하다.

## 검증 범위

- statistical checks: {len(audit_result['statistical_checks'])}개, 실패 {len(failed_stat)}개
- governance checks: {len(audit_result['governance_checks'])}개, 증거 불일치 {len(failed_gov)}개
- 전체 prediction CSV SHA-256 및 259,200행 확인
- frozen source closure 137개 확인
- truth/latent payload open 및 protected payload directory enumeration: 0
- recovery evidence class: `{audit_result['evidence_class']}`

## 다음 단계

1. C4 source/formula/coefficient/features를 변경하지 않는다.
2. serializer writer/reader를 하나의 canonical contract로 통일하고 실제 writer→activation rehearsal을 통과한다.
3. 새 fresh seed execution identity에서 v04와 unchanged C4를 pristine confirmation한다.
4. 동시에 release package의 determinism/PIT/input/fallback/runtime/dependency validation은 준비할 수 있다.
5. pristine confirmation과 release validation이 모두 PASS하기 전 registry를 변경하지 않는다.
"""


def write_outputs(output_root: Path, audit_result: Mapping[str, Any]) -> None:
    if output_root.exists():
        raise AuditFailure(f"output root already exists: {output_root}")
    output_root.mkdir(parents=True)
    audit_path = output_root / "R3_RECOVERY_ADMISSIBILITY_AUDIT.json"
    report_path = output_root / "R3_RECOVERY_ADMISSIBILITY_REPORT_KO.md"
    audit_path.write_bytes(pretty_json_bytes(dict(audit_result)))
    report_path.write_text(render_report(audit_result), encoding="utf-8", newline="\n")
    lines = [
        f"{file_sha256(path)}  {path.stat().st_size:12d}  {path.name}"
        for path in (audit_path, report_path)
    ]
    (output_root / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo_root.resolve(strict=True)
    result = audit(repo)
    write_outputs(args.output_root.resolve(), result)
    print(json.dumps({
        "verdict": result["verdict"],
        "statistical_evidence": result["statistical_evidence"],
        "formal_admissibility": result["formal_admissibility"],
        "audit_semantic_sha256": result["audit_semantic_sha256"],
        "output_root": str(args.output_root.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
