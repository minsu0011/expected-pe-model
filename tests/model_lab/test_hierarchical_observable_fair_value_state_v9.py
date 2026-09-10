from __future__ import annotations

import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
from typing import Any, Callable

import pytest

from research.model_zoo.hierarchical_observable_fair_value_state_v7.contracts import (
    FORBIDDEN_INFERENCE_COLUMNS as V7_FORBIDDEN_INFERENCE_COLUMNS,
    PREDICTION_OUTPUT_FILE_UNIVERSE as V7_PREDICTION_OUTPUT_FILE_UNIVERSE,
    R4_INPUT_BINDING as V7_R4_INPUT_BINDING,
    RUNTIME_PLAN as V7_RUNTIME_PLAN,
    contract_sha256 as v7_contract_sha256,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v9 import (
    BOOTSTRAP_IMPORT_REQUIREMENTS,
    BOOTSTRAP_SAMPLE_TASK,
    BOOTSTRAP_TASK_COUNT,
    V7_SINGLE_RUN_FAILURE_EVIDENCE,
    V8_SINGLE_RUN_FAILURE_EVIDENCE,
    attest_import_surface,
    bootstrap_contract_payload,
    build_worker_attestation,
    contract_payload,
    failure_evidence_sha256,
    require_failure_staging,
    run_source_audit_v9,
    sealed_payload,
    validate_execute_task_import_ast,
    validate_fanout_receipts,
    validate_lifecycle_task_receipts,
    validate_metadata_task_and_public_header,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v9 import (
    bootstrap as bootstrap_v9,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v9.contracts import (
    BOOTSTRAP_CONSTANT_ATTESTATIONS,
    BOOTSTRAP_MODULE_ORIGINS,
    BOOTSTRAP_SYMBOL_ORIGINS,
    DECLARED_SOURCE_PATHS,
    EXECUTE_TASK_IMPORT_REQUIREMENTS,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v9 import (
    freeze_design as freeze_design_v9,
)
from scripts.model_lab.hierarchical_observable_fair_value_state_v9 import (
    prediction_launcher as prediction_launcher_v9,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_PATH = PROJECT_ROOT / (
    "scripts/model_lab/hierarchical_observable_fair_value_state_v9/"
    "prediction_launcher.py"
)
V7_LAUNCHER_PATH = PROJECT_ROOT / (
    "scripts/model_lab/hierarchical_observable_fair_value_state_v7/"
    "prediction_launcher.py"
)


def _source_hashes() -> dict[str, str]:
    return dict(run_source_audit_v9(PROJECT_ROOT)["source_sha256"])


def test_bootstrap_import_remains_numeric_free_in_fresh_interpreter() -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": os.pathsep.join((str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))),
        }
    )
    command = (
        "import sys; "
        "import research.model_zoo."
        "hierarchical_observable_fair_value_state_v9.bootstrap; "
        "unexpected=sorted(n for n in ('numpy','pandas','threadpoolctl') "
        "if n in sys.modules); "
        "assert not unexpected, unexpected"
    )
    completed = subprocess.run(
        [sys.executable, "-c", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _fake_module_without_symbol(
    target_module: str,
    target_symbol: str,
) -> Callable[[str], Any]:
    def importer(module_name: str) -> Any:
        module = importlib.import_module(module_name)
        if module_name != target_module:
            return module
        fake = types.ModuleType(module_name)
        fake.__dict__.update(vars(module))
        delattr(fake, target_symbol)
        return fake

    return importer


def _fake_module_with_relocated_callable(
    target_module: str,
    target_symbol: str,
) -> Callable[[str], Any]:
    def relocated(*_args: Any, **_kwargs: Any) -> None:
        return None

    relocated.__name__ = target_symbol
    relocated.__qualname__ = target_symbol
    relocated.__module__ = target_module

    def importer(module_name: str) -> Any:
        module = importlib.import_module(module_name)
        if module_name != target_module:
            return module
        fake = types.ModuleType(module_name)
        fake.__dict__.update(vars(module))
        setattr(fake, target_symbol, relocated)
        return fake

    return importer


IMPORTED_SYMBOLS = tuple(
    (module, symbol)
    for module, symbols in BOOTSTRAP_IMPORT_REQUIREMENTS
    for symbol in symbols
)
EXECUTE_IMPORTED_SYMBOLS = tuple(
    (module, symbol)
    for module, symbols in EXECUTE_TASK_IMPORT_REQUIREMENTS
    for symbol in symbols
)
CALLABLE_SYMBOLS = tuple(
    (module, symbol)
    for module, symbol in IMPORTED_SYMBOLS
    if symbol
    in {
        "adapt_r4_canonical_source_v7",
        "build_hierarchical_state_features_v7",
        "build_r4_fold_plan_v7",
        "fit_chronological_prefix_v7",
        "run_frozen_decision_block_v7",
        "capture_runtime_receipt_v7",
    }
)
CONSTANT_SYMBOLS = tuple(
    (module, symbol)
    for module, symbol in IMPORTED_SYMBOLS
    if f"{module}:{symbol}" in BOOTSTRAP_CONSTANT_ATTESTATIONS
)


def test_v9_contract_binds_exact_v8_worker_reuse_failure_and_v7_semantics() -> None:
    payload = contract_payload()
    failure = payload["v8_single_run_failure_evidence"]
    assert payload["v7_contract_sha256"] == v7_contract_sha256()
    assert payload["v7_single_run_failure_evidence"] == V7_SINGLE_RUN_FAILURE_EVIDENCE
    assert failure == V8_SINGLE_RUN_FAILURE_EVIDENCE
    assert failure["run_id"] == "20260821T075500"
    assert failure["attempt_count"] == 1
    assert failure["retry_count"] == 0
    assert failure["controller_acknowledged_task_count"] == 1
    assert failure["published_completed_fit_count"] == 0
    assert failure["published_completed_prediction_row_count"] == 0
    assert failure["failure"]["failed_guard"].startswith("absence_style")
    assert payload["inherited_v7_semantics"]["fit_count"] == 3100
    assert payload["inherited_v7_semantics"]["decision_row_count"] == 64800
    assert payload["inherited_v7_semantics"][
        "first_prefix_requested_nonwarm_warm"
    ] == [504, 3, 501]
    assert payload["r4_public_input_binding"] == V7_R4_INPUT_BINDING
    assert payload["inherited_v7_semantics"]["runtime_plan"] == V7_RUNTIME_PLAN
    assert payload["inherited_v7_semantics"][
        "prediction_output_file_universe"
    ] == list(V7_PREDICTION_OUTPUT_FILE_UNIVERSE)
    assert payload["inherited_v7_semantics"][
        "forbidden_inference_columns"
    ] == sorted(V7_FORBIDDEN_INFERENCE_COLUMNS)


def test_exact_v8_failed_run_empty_staging_is_preserved() -> None:
    receipt = require_failure_staging(PROJECT_ROOT)
    assert receipt["status"].startswith("PASS_")
    assert receipt["staging_root_exists"] is True
    assert receipt["staging_child_count"] == 0
    assert receipt["controller_acknowledged_task_count"] == 1
    assert receipt["published_completed_fit_count"] == 0
    assert receipt["usable_prediction_row_count"] == 0
    assert receipt["failure_evidence_sha256"] == failure_evidence_sha256()


def test_v9_source_closure_includes_launcher_frozen_v8_and_inherited_v7() -> None:
    receipt = run_source_audit_v9(PROJECT_ROOT)
    assert receipt["passed"] is True
    assert receipt["source_file_count"] == len(DECLARED_SOURCE_PATHS) == 30
    assert receipt["v9_primary_source_file_count"] == 8
    assert receipt["inherited_v7_source_file_count"] == 14
    assert receipt["inherited_v8_source_file_count"] == 8
    assert receipt["forbidden_import_hits"] == []
    assert receipt["forbidden_call_hits"] == []
    assert dict(receipt["source_sha256"])[
        "scripts/model_lab/hierarchical_observable_fair_value_state_v9/"
        "prediction_launcher.py"
    ]


def test_v9_execute_task_ast_imports_authoritative_dgp_constant() -> None:
    source = LAUNCHER_PATH.read_text("utf-8")
    receipt = validate_execute_task_import_ast(source)
    assert receipt["status"] == "PASS_EXACT_EXECUTE_TASK_IMPORT_AST_BOUND"
    assert (
        "research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4",
        ("R4_CANONICAL_COLUMNS",),
    ) in EXECUTE_TASK_IMPORT_REQUIREMENTS


def test_absence_guard_is_initializer_only_and_task_uses_loaded_closure() -> None:
    source = LAUNCHER_PATH.read_text("utf-8")
    initializer = source[
        source.index("def v9_worker_bootstrap_initializer(") : source.index(
            "\ndef validate_worker_task_lifecycle("
        )
    ]
    execute = source[
        source.index("def execute_task(") : source.index(
            "\ndef serialize_predictions("
        )
    ]
    assert initializer.count("preimport_guard()") == 1
    assert "preimport_guard()" not in execute
    assert "validate_worker_task_lifecycle(task_ordinal)" in execute


def test_v7_failed_launcher_import_surface_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="import surface drifted"):
        validate_execute_task_import_ast(V7_LAUNCHER_PATH.read_text("utf-8"))


@pytest.mark.parametrize(("module_name", "symbol"), IMPORTED_SYMBOLS)
def test_every_bootstrap_imported_symbol_missing_fails_closed(
    module_name: str,
    symbol: str,
) -> None:
    with pytest.raises(RuntimeError, match="symbol missing"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            importer=_fake_module_without_symbol(module_name, symbol),
        )


@pytest.mark.parametrize(("module_name", "symbol"), CALLABLE_SYMBOLS)
def test_every_execute_callable_relocation_fails_closed(
    module_name: str,
    symbol: str,
) -> None:
    with pytest.raises(RuntimeError, match="callable source origin drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            importer=_fake_module_with_relocated_callable(module_name, symbol),
        )


@pytest.mark.parametrize(("module_name", "symbol"), CONSTANT_SYMBOLS)
@pytest.mark.parametrize("attack", ("semantic", "type"))
def test_every_imported_constant_type_or_semantic_drift_fails_closed(
    module_name: str,
    symbol: str,
    attack: str,
) -> None:
    def importer(requested: str) -> Any:
        module = importlib.import_module(requested)
        if requested != module_name:
            return module
        fake = types.ModuleType(requested)
        fake.__dict__.update(vars(module))
        original = getattr(module, symbol)
        if attack == "type":
            attacked = list(original.items()) if isinstance(original, dict) else list(original)
        elif isinstance(original, dict):
            attacked = {**original, "ATTACK": 1}
        else:
            attacked = (*original, "ATTACK")
        setattr(fake, symbol, attacked)
        return fake

    with pytest.raises(RuntimeError, match="constant type or semantic drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            importer=importer,
        )


@pytest.mark.parametrize("module_name", tuple(BOOTSTRAP_MODULE_ORIGINS))
def test_every_bootstrap_module_shadow_origin_fails_closed(
    module_name: str,
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow.py"
    shadow.write_text("SHADOW = True\n", encoding="ascii")

    def importer(requested: str) -> Any:
        if requested != module_name:
            return importlib.import_module(requested)
        fake = types.ModuleType(requested)
        fake.__file__ = str(shadow)
        return fake

    with pytest.raises(RuntimeError, match="module origin drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            importer=importer,
        )


@pytest.mark.parametrize("module_name", tuple(BOOTSTRAP_MODULE_ORIGINS))
def test_every_bootstrap_module_source_hash_change_fails_closed(
    module_name: str,
) -> None:
    origins = copy.deepcopy(BOOTSTRAP_MODULE_ORIGINS)
    origins[module_name]["raw_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="module origin contract drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            module_origins=origins,
        )


@pytest.mark.parametrize(
    "token",
    (
        "numpy",
        "pandas",
        *tuple(symbol for _module, symbol in EXECUTE_IMPORTED_SYMBOLS),
    ),
)
def test_every_execute_task_import_rename_fails_ast_gate(token: str) -> None:
    source = LAUNCHER_PATH.read_text("utf-8")
    start = source.index("def execute_task(")
    end = source.index("\ndef serialize_predictions(", start)
    fragment = source[start:end]
    assert token in fragment
    attacked = source[:start] + fragment.replace(
        token,
        f"{token}_RENAMED",
        1,
    ) + source[end:]
    with pytest.raises(RuntimeError, match="import surface drifted"):
        validate_execute_task_import_ast(attacked)


def test_r4_canonical_import_relocation_back_to_contracts_fails_ast_gate() -> None:
    source = LAUNCHER_PATH.read_text("utf-8")
    start = source.index("def execute_task(")
    end = source.index("\ndef serialize_predictions(", start)
    fragment = source[start:end]
    attacked_fragment = fragment.replace(
        (
            "research.model_zoo.hierarchical_observable_fair_value_state_v7."
            "dgp_r4 import"
        ),
        (
            "research.model_zoo.hierarchical_observable_fair_value_state_v7."
            "contracts import"
        ),
        1,
    )
    with pytest.raises(RuntimeError, match="import surface drifted"):
        validate_execute_task_import_ast(
            source[:start] + attacked_fragment + source[end:]
        )


def test_symbol_origin_declaration_change_fails_closed() -> None:
    origins = dict(BOOTSTRAP_SYMBOL_ORIGINS)
    key = next(
        key for key in origins if key.endswith(":fit_chronological_prefix_v7")
    )
    origins[key] = (
        "research/model_zoo/hierarchical_observable_fair_value_state_v7/"
        "features.py"
    )
    with pytest.raises(RuntimeError, match="symbol origin contract drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            symbol_origins=origins,
        )


@pytest.mark.parametrize("attack", ("requirements_subset", "constant_pin_drop"))
def test_attestation_contract_subset_bypasses_fail_closed(attack: str) -> None:
    keyword: dict[str, Any] = {}
    if attack == "requirements_subset":
        keyword["requirements"] = BOOTSTRAP_IMPORT_REQUIREMENTS[:-1]
    else:
        constants = copy.deepcopy(BOOTSTRAP_CONSTANT_ATTESTATIONS)
        constants.pop(next(iter(constants)))
        keyword["constant_attestations"] = constants
    with pytest.raises(RuntimeError, match="contract drifted"):
        attest_import_surface(
            project_root=PROJECT_ROOT,
            allowed_source_hashes=_source_hashes(),
            **keyword,
        )


def test_metadata_only_task_and_public_header_pass_without_rows() -> None:
    serialized = json.dumps(
        BOOTSTRAP_SAMPLE_TASK,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    receipt = validate_metadata_task_and_public_header(
        serialized,
        project_root=PROJECT_ROOT,
    )
    assert receipt["header_column_count"] == 150
    assert receipt["required_column_count"] == 22
    assert receipt["public_payload_deserialized"] is False


def test_metadata_task_duplicate_key_path_and_header_attacks_fail() -> None:
    serialized = json.dumps(
        BOOTSTRAP_SAMPLE_TASK,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    duplicate = serialized.replace(
        b"{",
        b'{"status":"DUPLICATE",',
        1,
    )
    with pytest.raises(RuntimeError, match="duplicate"):
        validate_metadata_task_and_public_header(
            duplicate,
            project_root=PROJECT_ROOT,
        )
    for field, value in (
        ("canonical_relative", "../canonical150.csv"),
        ("expected_header_raw_sha256", "0" * 64),
    ):
        attacked = dict(BOOTSTRAP_SAMPLE_TASK)
        attacked[field] = value
        with pytest.raises(RuntimeError):
            validate_metadata_task_and_public_header(
                json.dumps(
                    attacked,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
                project_root=PROJECT_ROOT,
            )


def _fanout_receipts() -> list[dict[str, Any]]:
    serialized = json.dumps(
        BOOTSTRAP_SAMPLE_TASK,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    base = build_worker_attestation(
        serialized,
        project_root=PROJECT_ROOT,
        allowed_source_hashes=_source_hashes(),
    )
    return [
        sealed_payload(
            {
                **{
                    key: copy.deepcopy(value)
                    for key, value in base.items()
                    if key not in {"manifest_sha256", "worker_pid"}
                },
                "worker_pid": 10_000 + position,
            }
        )
        for position in range(32)
    ]


def test_exact_32_worker_fanout_receipt_passes() -> None:
    receipt = validate_fanout_receipts(_fanout_receipts())
    assert receipt["worker_count"] == 32
    assert len(receipt["worker_pids"]) == 32
    assert receipt["real_fit_count"] == 0
    assert receipt["real_prediction_count"] == 0


@pytest.mark.parametrize(
    "attack",
    ("only_31", "duplicate_pid", "unsealed", "resealed_bypass"),
)
def test_spawn_bootstrap_bypass_attacks_fail_closed(attack: str) -> None:
    receipts = _fanout_receipts()
    if attack == "only_31":
        receipts.pop()
    elif attack == "duplicate_pid":
        receipts[-1] = sealed_payload(
            {
                **{
                    key: value
                    for key, value in receipts[-1].items()
                    if key != "manifest_sha256"
                },
                "worker_pid": receipts[0]["worker_pid"],
            }
        )
    elif attack == "unsealed":
        receipts[-1]["status"] = "BYPASS"
    else:
        receipts[-1] = sealed_payload(
            {
                **{
                    key: value
                    for key, value in receipts[-1].items()
                    if key != "manifest_sha256"
                },
                "status": "BYPASS",
            }
        )
    with pytest.raises(RuntimeError):
        validate_fanout_receipts(receipts)


def _task_receipts(
    initializer_receipts: list[dict[str, Any]],
    task_count: int,
) -> list[dict[str, Any]]:
    per_pid: dict[int, int] = {
        int(receipt["worker_pid"]): 0 for receipt in initializer_receipts
    }
    output: list[dict[str, Any]] = []
    for position in range(task_count):
        initializer = initializer_receipts[position % len(initializer_receipts)]
        pid = int(initializer["worker_pid"])
        per_pid[pid] += 1
        loaded = initializer["loaded_closure"]
        output.append(
            sealed_payload(
                {
                    "schema_version": (
                        "expected_pe.hofs_v9.worker_task_validation.v1"
                    ),
                    "status": "PASS_REUSED_TASK_LOADED_CLOSURE_REVALIDATED",
                    "task_position": position,
                    "worker_pid": pid,
                    "worker_task_sequence_number": per_pid[pid],
                    "initializer_count_per_pid": 1,
                    "absence_guard_count_per_pid": 1,
                    "preimport_guard_receipt": loaded["preimport_guard_receipt"],
                    "loaded_closure_sha256": loaded["loaded_closure_sha256"],
                    "runtime_receipt_sha256": loaded["runtime_receipt_sha256"],
                    "stable_module_origins_and_source_hashes": True,
                    "real_fit_count": 0,
                    "real_prediction_count": 0,
                    "protected_or_score_access_count": 0,
                }
            )
        )
    return output


@pytest.mark.parametrize("reuse_count", (1, 2, 7, BOOTSTRAP_TASK_COUNT))
def test_arbitrary_same_pid_reuse_counts_validate(reuse_count: int) -> None:
    initializers = _fanout_receipts()[:1]
    receipt = validate_lifecycle_task_receipts(
        initializers,
        _task_receipts(initializers, reuse_count),
        expected_worker_count=1,
        expected_task_count=reuse_count,
    )
    assert receipt["maximum_reuse_count"] == reuse_count
    assert receipt["initializer_count_per_pid"] == 1
    assert receipt["absence_guard_count_per_pid"] == 1


def test_production_equivalent_50_task_32_worker_schedule_validates() -> None:
    initializers = _fanout_receipts()
    receipt = validate_lifecycle_task_receipts(
        initializers,
        _task_receipts(initializers, 50),
        expected_worker_count=32,
        expected_task_count=50,
    )
    assert receipt["worker_count"] == 32
    assert receipt["task_count"] == 50
    assert receipt["reused_worker_count"] == 18


@pytest.mark.parametrize(
    "attack",
    ("task_count_spoof", "worker_replacement", "stale_closure", "sequence_spoof"),
)
def test_lifecycle_schedule_attacks_fail_closed(attack: str) -> None:
    initializers = _fanout_receipts()[:1]
    tasks = _task_receipts(initializers, 2)
    if attack == "task_count_spoof":
        tasks.pop()
    else:
        unsigned = {key: value for key, value in tasks[-1].items() if key != "manifest_sha256"}
        if attack == "worker_replacement":
            unsigned["worker_pid"] = 999_999
        elif attack == "stale_closure":
            unsigned["loaded_closure_sha256"] = "0" * 64
        else:
            unsigned["worker_task_sequence_number"] = 99
        tasks[-1] = sealed_payload(unsigned)
    with pytest.raises(RuntimeError):
        validate_lifecycle_task_receipts(
            initializers,
            tasks,
            expected_worker_count=1,
            expected_task_count=2,
        )


class _OnePartyBarrier:
    def __init__(self) -> None:
        self.wait_count = 0

    def wait(self, timeout: float) -> int:
        assert timeout == 90.0
        self.wait_count += 1
        return 0


def _install_controller_lifecycle(monkeypatch: pytest.MonkeyPatch) -> _OnePartyBarrier:
    serialized = json.dumps(
        BOOTSTRAP_SAMPLE_TASK,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    source_hashes = _source_hashes()
    initializer = build_worker_attestation(
        serialized,
        project_root=PROJECT_ROOT,
        allowed_source_hashes=source_hashes,
    )
    barrier = _OnePartyBarrier()
    monkeypatch.setattr(
        bootstrap_v9,
        "_WORKER_LIFECYCLE",
        {
            "worker_pid": os.getpid(),
            "project_root": PROJECT_ROOT,
            "allowed_source_hashes": source_hashes,
            "preimport_guard_receipt": initializer["loaded_closure"][
                "preimport_guard_receipt"
            ],
            "initializer_receipt": initializer,
            "loaded_closure": copy.deepcopy(initializer["loaded_closure"]),
            "first_task_barrier": barrier,
            "validated_task_count": 0,
        },
    )
    return barrier


def test_reuse_after_imported_numeric_stack_revalidates_without_absence_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    barrier = _install_controller_lifecycle(monkeypatch)
    first = bootstrap_v9.validate_loaded_worker_closure(0)
    second = bootstrap_v9.validate_loaded_worker_closure(1)
    assert first["worker_pid"] == second["worker_pid"] == os.getpid()
    assert first["worker_task_sequence_number"] == 1
    assert second["worker_task_sequence_number"] == 2
    assert first["absence_guard_count_per_pid"] == 1
    assert second["absence_guard_count_per_pid"] == 1
    assert barrier.wait_count == 1


@pytest.mark.parametrize("attack", ("missing_symbol", "shadow_module", "stale_state"))
def test_live_loaded_closure_attacks_fail_closed(
    attack: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_controller_lifecycle(monkeypatch)
    module_name = (
        "research.model_zoo.hierarchical_observable_fair_value_state_v7.runtime"
    )
    if attack == "stale_state":
        bootstrap_v9._WORKER_LIFECYCLE["loaded_closure"][
            "loaded_closure_sha256"
        ] = "0" * 64
    else:
        original = sys.modules[module_name]
        fake = types.ModuleType(module_name)
        fake.__dict__.update(vars(original))
        if attack == "missing_symbol":
            delattr(fake, "capture_runtime_receipt_v7")
        else:
            fake.__file__ = str(PROJECT_ROOT / "tests/model_lab/conftest.py")
        monkeypatch.setitem(sys.modules, module_name, fake)
    with pytest.raises(RuntimeError):
        bootstrap_v9.validate_loaded_worker_closure(0)


def test_reinitializer_attempt_fails_before_any_second_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap_v9, "_WORKER_LIFECYCLE", {"already": "initialized"})
    with pytest.raises(RuntimeError, match="reinitializer"):
        bootstrap_v9.worker_bootstrap_initializer(
            b"",
            "",
            {},
            None,
            None,
            None,
            {},
        )


def test_launcher_check_and_run_both_require_lifecycle_before_output_root() -> None:
    source = LAUNCHER_PATH.read_text("utf-8")
    check_start = source.index("def check_only(")
    run_start = source.index("def run_authorized(")
    main_start = source.index("def _parser(")
    check_source = source[check_start:run_start]
    run_source = source[run_start:main_start]
    assert "run_worker_bootstrap_check(" in check_source
    assert "run_worker_bootstrap_check(" in run_source
    assert run_source.index("run_worker_bootstrap_check(") < run_source.index(
        "_output_roots("
    )
    assert "initializer=v9_worker_bootstrap_initializer" in source
    assert "initializer_barrier = context.Barrier(worker_count)" in source
    assert "first_task_barrier = context.Barrier(worker_count)" in source
    assert "initializer=v9_worker_bootstrap_initializer" in run_source


def test_bootstrap_contract_is_exact_metadata_only_and_zero_fit() -> None:
    payload = bootstrap_contract_payload()
    assert payload["process_start_method"] == "spawn"
    assert payload["required_worker_count"] == 32
    assert payload["production_equivalent_task_count"] == 50
    assert payload["targeted_single_worker_reuse_task_count"] == 7
    assert payload["initializer_barrier_parties"] == 32
    assert payload["first_task_barrier_parties"] == 32
    assert payload["initializer_count_per_pid"] == 1
    assert payload["absence_guard_count_per_pid"] == 1
    assert payload["metadata_only_task"] == BOOTSTRAP_SAMPLE_TASK
    assert payload["real_fit_count"] == 0
    assert payload["real_prediction_count"] == 0
    assert payload["public_header_path_validation"] is True


def test_live_worker_attestation_in_controller_has_zero_execution() -> None:
    serialized = json.dumps(
        BOOTSTRAP_SAMPLE_TASK,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    receipt = build_worker_attestation(
        serialized,
        project_root=PROJECT_ROOT,
        allowed_source_hashes=_source_hashes(),
    )
    assert receipt["status"].startswith("PASS_")
    assert receipt["real_fit_count"] == 0
    assert receipt["real_prediction_count"] == 0
    assert receipt["metadata_and_header"]["public_payload_deserialized"] is False


def test_design_bundle_builds_exactly_and_embeds_same_launcher() -> None:
    bundle = freeze_design_v9.build_design_bundle_bytes(PROJECT_ROOT)
    assert tuple(sorted(bundle)) == freeze_design_v9.FINAL_FILE_UNIVERSE
    assert len(bundle) == 14
    assert bundle["PREDICTION_LAUNCHER.py"] == LAUNCHER_PATH.read_bytes()
    failure = json.loads(bundle["AUDIT_CLOSURE.json"].decode("ascii"))
    assert failure["controller_acknowledged_task_count"] == 1
    assert failure["published_completed_fit_count"] == 0
    assert failure["usable_prediction_row_count"] == 0
    launch = json.loads(
        bundle["PREDICTION_LAUNCH_CONTRACT.json"].decode("ascii")
    )
    assert launch["formal_check_worker_lifecycle"][
        "exact_initializer_worker_count"
    ] == 32
    assert launch["formal_check_worker_lifecycle"][
        "production_equivalent_task_count"
    ] == 50
    assert launch["required_audit_verdict"].endswith("FROZEN_V9_ONLY")


@pytest.mark.parametrize("attack", ("output_bytes", "staging_extra_child"))
def test_output_and_staging_tamper_fail_closed(
    attack: str,
    tmp_path: Path,
) -> None:
    bundle = freeze_design_v9.build_design_bundle_bytes(PROJECT_ROOT)
    root = tmp_path / "v9_bundle.staging"
    root.mkdir()
    for name, content in bundle.items():
        (root / name).write_bytes(content)
    expected = freeze_design_v9._sha256(bundle["CHECKSUMS.sha256"])
    freeze_design_v9.verify_design_bundle(
        root,
        expected_checksums_raw_sha256=expected,
    )
    if attack == "output_bytes":
        (root / "PREDICTION_LAUNCHER.py").write_bytes(b"TAMPER")
    else:
        (root / "UNDECLARED.tmp").write_bytes(b"TAMPER")
    with pytest.raises(RuntimeError):
        freeze_design_v9.verify_design_bundle(
            root,
            expected_checksums_raw_sha256=expected,
        )


def test_launcher_contract_payload_matches_freezer_surface() -> None:
    launcher_bytes = LAUNCHER_PATH.read_bytes()
    payload = prediction_launcher_v9.launch_contract_payload(
        launcher_raw_sha256=freeze_design_v9._sha256(launcher_bytes),
        design_contract_sha256=freeze_design_v9.contract_sha256(),
    )
    assert payload["source_path"].endswith(
        "hierarchical_observable_fair_value_state_v9/prediction_launcher.py"
    )
    assert payload["formal_check_worker_lifecycle"][
        "all_imported_modules_symbols_origins_and_hashes_attested"
    ] is True
    assert payload["authority"]["registry_champion_promotion"] is False
