"""Frozen H-OFS V7 parameter bundle serialization and fail-closed loader."""

from __future__ import annotations

from dataclasses import fields
import ctypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    CANDIDATE_ID,
    CONTEXT_COLUMNS,
    STANDARDIZED_COLUMNS,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
    contract_sha256,
    sealed_payload,
)
from .estimator import (
    FitReceiptV7,
    FrozenHierarchicalParametersV7,
    HierarchicalFitResultV7,
)
from .runtime import ResourceReceiptV7
from .validation import (
    require_exact_bool,
    require_exact_dict,
    require_exact_float,
    require_exact_int,
    require_exact_str,
    require_json_float_list,
    require_json_list,
    require_sha256,
)


PARAMETER_BUNDLE_FILES = (
    "CHECKSUMS.sha256",
    "FIT_RECEIPT.json",
    "MANIFEST.json",
    "PARAMETERS.json",
    "RESOURCE_RECEIPT.json",
)
_PAYLOAD_FILES = (
    "FIT_RECEIPT.json",
    "MANIFEST.json",
    "PARAMETERS.json",
    "RESOURCE_RECEIPT.json",
)
_MAX_ARTIFACT_BYTES = 5_000_000
_FORBIDDEN_PARAMETER_KEYS = frozenset(
    {
        "dgp_id",
        "research_dgp_id",
        "seed",
        "dgp_effects",
        "dgp_intercepts",
        "dgp_persistence",
        "dgp_innovation",
        "dgp_scale_effects",
        "seed_effects",
    }
)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _raw_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_dataclass_payload(cls: type[Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_dict(payload, label=f"{cls.__name__} payload")
    expected = {item.name for item in fields(cls)}
    actual = set(payload)
    if actual != expected:
        raise HierarchicalStateV7ContractError(
            f"{cls.__name__} fields drifted: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return dict(payload)


def _find_forbidden_parameter_keys(value: Any, path: str = "parameters") -> list[str]:
    hits: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in _FORBIDDEN_PARAMETER_KEYS:
                hits.append(f"{path}.{key}")
            hits.extend(_find_forbidden_parameter_keys(nested, f"{path}.{key}"))
    elif isinstance(value, list):
        for position, nested in enumerate(value):
            hits.extend(_find_forbidden_parameter_keys(nested, f"{path}[{position}]"))
    return hits


def build_frozen_parameter_bundle_bytes(
    result: HierarchicalFitResultV7,
) -> dict[str, bytes]:
    """Create one deterministic in-memory five-file parameter bundle."""

    if type(result) is not HierarchicalFitResultV7:
        raise HierarchicalStateV7ContractError("bundle creation requires a validated fit result")
    # Re-run every cross-object semantic validator at the serialization edge.
    result = HierarchicalFitResultV7(
        parameters=result.parameters,
        fit_receipt=result.fit_receipt,
        resource_receipt=result.resource_receipt,
    )
    parameters_bytes = _json_bytes(result.parameters.payload())
    fit_receipt_bytes = _json_bytes(result.fit_receipt.payload())
    resource_receipt_bytes = _json_bytes(result.resource_receipt.payload())
    base_files = {
        "FIT_RECEIPT.json": fit_receipt_bytes,
        "PARAMETERS.json": parameters_bytes,
        "RESOURCE_RECEIPT.json": resource_receipt_bytes,
    }
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v7.frozen_parameter_bundle.v1",
            "status": "FROZEN_PARAMETERS_DGP_MARGINALIZED",
            "candidate_id": CANDIDATE_ID,
            "design_contract_sha256": contract_sha256(),
            "parameter_sha256": result.parameters.sha256(),
            "fit_receipt_sha256": result.fit_receipt.sha256(),
            "resource_receipt_sha256": result.resource_receipt.sha256(),
            "fit_end_date": result.parameters.fit_end_date,
            "decision_block_start_date": result.parameters.decision_block_start_date,
            "decision_block_end_date": result.parameters.decision_block_end_date,
            "decision_block_first_entity_id": (result.parameters.decision_block_first_entity_id),
            "decision_block_last_entity_id": (result.parameters.decision_block_last_entity_id),
            "decision_block_ordered_membership_sha256": (
                result.parameters.decision_block_ordered_membership_sha256
            ),
            "decision_block_set_membership_sha256": result.parameters.decision_block_set_membership_sha256,
            "decision_source_positions_sha256": (
                result.parameters.decision_source_positions_sha256
            ),
            "decision_source_state_sha256": (result.parameters.decision_source_state_sha256),
            "decision_source_row_count": result.parameters.decision_source_row_count,
            "decision_row_count": result.parameters.decision_row_count,
            "decision_distinct_date_count": (result.parameters.decision_distinct_date_count),
            "within_block_parameter_update_count": 0,
            "fit_row_count": result.parameters.fit_row_count,
            "file_raw_sha256": {
                name: _raw_sha256(content) for name, content in sorted(base_files.items())
            },
            "research_dgp_effects_marginalized": True,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**base_files, "MANIFEST.json": manifest_bytes}
    checksums = "".join(
        f"{_raw_sha256(content)}  {name}\n" for name, content in sorted(payload_files.items())
    ).encode("ascii")
    return {
        "CHECKSUMS.sha256": checksums,
        **payload_files,
    }


def _parse_json_bytes(content: bytes, name: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise HierarchicalStateV7ContractError(
                    f"duplicate JSON key in artifact {name}: {key}"
                )
            output[key] = value
        return output

    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                HierarchicalStateV7ContractError(
                    f"non-finite JSON constant in artifact {name}: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HierarchicalStateV7ContractError(f"invalid JSON artifact: {name}") from error
    if type(payload) is not dict:
        raise HierarchicalStateV7ContractError(f"artifact root must be an object: {name}")
    return payload


def _verify_manifest_seal(manifest: Mapping[str, Any]) -> None:
    expected = manifest.get("manifest_sha256")
    require_sha256(expected, label="parameter manifest seal")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != expected:
        raise HierarchicalStateV7ContractError("parameter manifest semantic seal drifted")


def _windows_reparse_point(path: Path) -> bool:
    """Detect Windows reparse roots/children without resolving away the evidence."""

    if os.name != "nt":
        return path.is_symlink()
    get_attributes = ctypes.windll.kernel32.GetFileAttributesW  # type: ignore[attr-defined]
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    attributes = int(get_attributes(str(path.absolute())))
    return attributes != 0xFFFFFFFF and bool(attributes & 0x00000400)


_PARAMETER_FLOAT_LIST_FIELDS = {
    "robust_centers": len(STANDARDIZED_COLUMNS),
    "robust_scales": len(STANDARDIZED_COLUMNS),
    "context_coefficients": len(CONTEXT_COLUMNS),
    "regime_intercept_deviations": 3,
    "regime_persistence_deviations": 3,
    "regime_innovation_deviations": 3,
    "regime_log_scale_deviations": 3,
}
_PARAMETER_FLOAT_FIELDS = {
    "global_intercept",
    "global_persistence",
    "global_innovation",
    "global_log_scale",
}
_PARAMETER_INT_FIELDS = {
    "fit_row_count",
    "decision_row_count",
    "decision_distinct_date_count",
    "within_block_parameter_update_count",
    "decision_source_row_count",
}
_PARAMETER_BOOL_FIELDS = {"research_dgp_effects_marginalized"}

_FIT_FLOAT_FIELDS = {
    "final_coefficient_delta",
    "final_weight_delta",
    "final_huber_objective",
    "final_conditional_huber_scale",
    "deploy_marginalized_scale",
    "final_kkt_violation",
}
_FIT_INT_FIELDS = {
    "requested_row_count",
    "fit_row_count",
    "dropped_nonwarm_row_count",
    "causal_prefix_nonwarm_row_count",
    "decision_row_count",
    "decision_distinct_date_count",
    "within_block_parameter_update_count",
    "prefix_entity_count",
    "dgp_group_count",
    "missing_context_cell_count",
    "source_regime_fallback_count",
    "source_regime_renormalized_count",
    "expected_regime_warmup_prefix_count",
    "irls_iterations",
    "active_bound_count",
    "total_qp_coordinate_sweeps",
    "decision_source_row_count",
}
_FIT_BOOL_FIELDS = {"irls_converged", "dgp_effects_marginalized_for_deploy"}
_DECISION_CUSTODY_SEQUENCE_FIELDS = {
    "decision_ordered_identity_rows",
    "decision_source_positions",
}


def _typed_decision_custody_sequences(
    values: dict[str, Any],
    *,
    label: str,
) -> None:
    identity_rows = require_json_list(
        values["decision_ordered_identity_rows"],
        label=f"{label} decision ordered identity rows",
    )
    converted_rows: list[tuple[str, str]] = []
    for position, row in enumerate(identity_rows):
        items = require_json_list(
            row,
            label=f"{label} decision ordered identity rows[{position}]",
            length=2,
        )
        require_exact_str(items[0], label=f"{label} identity[{position}].entity")
        require_exact_str(items[1], label=f"{label} identity[{position}].date")
        converted_rows.append((items[0], items[1]))
    values["decision_ordered_identity_rows"] = tuple(converted_rows)
    positions = require_json_list(
        values["decision_source_positions"],
        label=f"{label} decision source positions",
    )
    for position, value in enumerate(positions):
        require_exact_int(
            value,
            label=f"{label} decision source positions[{position}]",
            minimum=0,
        )
    values["decision_source_positions"] = tuple(positions)


def _typed_parameter_payload(payload: dict[str, Any]) -> dict[str, Any]:
    values = _strict_dataclass_payload(FrozenHierarchicalParametersV7, payload)
    _typed_decision_custody_sequences(values, label="parameter")
    for name, length in _PARAMETER_FLOAT_LIST_FIELDS.items():
        values[name] = tuple(
            require_json_float_list(values[name], label=f"parameter {name}", length=length)
        )
    for name in _PARAMETER_FLOAT_FIELDS:
        require_exact_float(values[name], label=f"parameter {name}")
    for name in _PARAMETER_INT_FIELDS:
        require_exact_int(values[name], label=f"parameter {name}", minimum=0)
    for name in _PARAMETER_BOOL_FIELDS:
        require_exact_bool(values[name], label=f"parameter {name}")
    for name in set(values) - (
        set(_PARAMETER_FLOAT_LIST_FIELDS)
        | _PARAMETER_FLOAT_FIELDS
        | _PARAMETER_INT_FIELDS
        | _PARAMETER_BOOL_FIELDS
        | _DECISION_CUSTODY_SEQUENCE_FIELDS
    ):
        require_exact_str(values[name], label=f"parameter {name}")
    return values


def _typed_fit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    values = _strict_dataclass_payload(FitReceiptV7, payload)
    _typed_decision_custody_sequences(values, label="fit receipt")
    prefix_rows = require_json_list(
        values["prefix_entity_row_counts"],
        label="fit receipt prefix entity row counts",
    )
    converted_rows: list[tuple[str, int, int, int]] = []
    for position, row in enumerate(prefix_rows):
        items = require_json_list(
            row,
            label=f"fit receipt prefix entity row counts[{position}]",
            length=4,
        )
        require_exact_str(
            items[0],
            label=f"fit receipt prefix entity row counts[{position}].entity",
        )
        for item_position in range(1, 4):
            require_exact_int(
                items[item_position],
                label=(f"fit receipt prefix entity row counts[{position}][{item_position}]"),
                minimum=0,
            )
        converted_rows.append(tuple(items))  # type: ignore[arg-type]
    values["prefix_entity_row_counts"] = tuple(converted_rows)
    invalid_rows = require_json_list(
        values["prefix_entity_causal_invalid_positions"],
        label="fit receipt prefix entity causal invalid positions",
    )
    converted_invalid_rows: list[tuple[str, tuple[int, ...]]] = []
    for position, row in enumerate(invalid_rows):
        items = require_json_list(
            row,
            label=f"fit receipt prefix entity causal invalid positions[{position}]",
            length=2,
        )
        entity = require_exact_str(
            items[0],
            label=f"fit receipt prefix entity causal invalid positions[{position}].entity",
        )
        positions = require_json_list(
            items[1],
            label=f"fit receipt prefix entity causal invalid positions[{position}].positions",
        )
        for item_position, value in enumerate(positions):
            require_exact_int(
                value,
                label=(
                    "fit receipt prefix entity causal invalid positions"
                    f"[{position}].positions[{item_position}]"
                ),
                minimum=0,
            )
        converted_invalid_rows.append((entity, tuple(positions)))
    values["prefix_entity_causal_invalid_positions"] = tuple(converted_invalid_rows)
    for name in _FIT_FLOAT_FIELDS:
        require_exact_float(values[name], label=f"fit receipt {name}")
    for name in _FIT_INT_FIELDS:
        require_exact_int(values[name], label=f"fit receipt {name}", minimum=0)
    for name in _FIT_BOOL_FIELDS:
        require_exact_bool(values[name], label=f"fit receipt {name}")
    for name in (
        set(values)
        - _FIT_FLOAT_FIELDS
        - _FIT_INT_FIELDS
        - _FIT_BOOL_FIELDS
        - {
            "prefix_entity_row_counts",
            "prefix_entity_causal_invalid_positions",
        }
        - _DECISION_CUSTODY_SEQUENCE_FIELDS
    ):
        require_exact_str(values[name], label=f"fit receipt {name}")
    return values


def _typed_resource_payload(payload: dict[str, Any]) -> dict[str, Any]:
    values = _strict_dataclass_payload(ResourceReceiptV7, payload)
    string_fields = {
        "purpose",
        "python_version",
        "python_executable",
        "python_executable_sha256",
        "numpy_version",
        "pandas_version",
        "affinity_mask_hex",
        "estimator_device",
    }
    for name in string_fields:
        require_exact_str(values[name], label=f"resource {name}")
    require_exact_int(values["logical_cpu_count"], label="resource CPU count", minimum=1)
    require_exact_int(values["outer_workers"], label="resource outer workers", minimum=1)
    require_exact_int(values["inner_threads"], label="resource inner threads", minimum=1)
    for name in ("deterministic_row_accumulation", "gpu_used"):
        require_exact_bool(values[name], label=f"resource {name}")
    cpu_ids = require_json_list(values["cpu_ids"], label="resource CPU IDs")
    for position, value in enumerate(cpu_ids):
        require_exact_int(value, label=f"resource CPU IDs[{position}]", minimum=0)
    values["cpu_ids"] = tuple(cpu_ids)
    for name, width, terminal_int in (
        ("thread_environment", 2, False),
        ("threadpool_backends", 5, True),
        ("gpu_environment", 2, False),
    ):
        rows = require_json_list(values[name], label=f"resource {name}")
        converted: list[tuple[Any, ...]] = []
        for row_position, row in enumerate(rows):
            items = require_json_list(row, label=f"resource {name}[{row_position}]", length=width)
            for item_position, item in enumerate(items):
                if terminal_int and item_position == width - 1:
                    require_exact_int(
                        item,
                        label=f"resource {name}[{row_position}][{item_position}]",
                        minimum=1,
                    )
                else:
                    require_exact_str(
                        item,
                        label=f"resource {name}[{row_position}][{item_position}]",
                    )
            converted.append(tuple(items))
        values[name] = tuple(converted)
    return values


def _validate_manifest_types(manifest: dict[str, Any]) -> None:
    string_fields = {
        "schema_version",
        "status",
        "candidate_id",
        "design_contract_sha256",
        "parameter_sha256",
        "fit_receipt_sha256",
        "resource_receipt_sha256",
        "fit_end_date",
        "decision_block_start_date",
        "decision_block_end_date",
        "decision_block_first_entity_id",
        "decision_block_last_entity_id",
        "decision_block_ordered_membership_sha256",
        "decision_block_set_membership_sha256",
        "decision_source_positions_sha256",
        "decision_source_state_sha256",
        "manifest_sha256",
    }
    for name in string_fields:
        require_exact_str(manifest[name], label=f"parameter manifest {name}")
    for name in (
        "design_contract_sha256",
        "parameter_sha256",
        "fit_receipt_sha256",
        "resource_receipt_sha256",
        "decision_block_ordered_membership_sha256",
        "decision_block_set_membership_sha256",
        "decision_source_positions_sha256",
        "decision_source_state_sha256",
        "manifest_sha256",
    ):
        require_sha256(manifest[name], label=f"parameter manifest {name}")
    require_exact_int(manifest["fit_row_count"], label="manifest fit rows", minimum=0)
    require_exact_int(
        manifest["decision_source_row_count"],
        label="manifest decision source rows",
        minimum=1,
    )
    for name in (
        "decision_row_count",
        "decision_distinct_date_count",
        "within_block_parameter_update_count",
    ):
        require_exact_int(manifest[name], label=f"parameter manifest {name}", minimum=0)
    if manifest["within_block_parameter_update_count"] != 0:
        raise HierarchicalStateV7ContractError("manifest within-block update count drifted")
    require_exact_bool(
        manifest["research_dgp_effects_marginalized"],
        label="manifest DGP marginalization",
    )
    file_hashes = require_exact_dict(manifest["file_raw_sha256"], label="manifest file hashes")
    expected_names = {
        "FIT_RECEIPT.json",
        "PARAMETERS.json",
        "RESOURCE_RECEIPT.json",
    }
    if set(file_hashes) != expected_names:
        raise HierarchicalStateV7ContractError("manifest file hash universe drifted")
    for name, digest in file_hashes.items():
        require_sha256(digest, label=f"manifest file hash {name}")


def load_frozen_parameter_bundle(
    bundle_directory: str | Path,
    *,
    expected_checksums_raw_sha256: str,
) -> HierarchicalFitResultV7:
    """Load and fully verify one exact-universe frozen parameter directory."""

    raw_directory = Path(bundle_directory)
    if raw_directory.is_symlink() or _windows_reparse_point(raw_directory):
        raise HierarchicalStateV7ContractError("parameter bundle reparse root is forbidden")
    directory = raw_directory.resolve()
    if not directory.is_dir() or _windows_reparse_point(directory):
        raise HierarchicalStateV7ContractError("parameter bundle directory is missing")
    children = tuple(directory.iterdir())
    if any(path.is_symlink() or _windows_reparse_point(path) for path in children):
        raise HierarchicalStateV7ContractError("parameter bundle reparse child is forbidden")
    if any(not path.is_file() for path in children):
        raise HierarchicalStateV7ContractError("parameter bundle contains a non-file entry")
    if any(path.resolve().parent != directory for path in children):
        raise HierarchicalStateV7ContractError("parameter bundle child escaped its root")
    actual_names = tuple(sorted(path.name for path in children))
    if len({name.casefold() for name in actual_names}) != len(actual_names):
        raise HierarchicalStateV7ContractError("parameter bundle names are not unique")
    if actual_names != PARAMETER_BUNDLE_FILES:
        raise HierarchicalStateV7ContractError("parameter bundle file universe drifted")
    contents: dict[str, bytes] = {}
    for name in PARAMETER_BUNDLE_FILES:
        content = (directory / name).read_bytes()
        if len(content) > _MAX_ARTIFACT_BYTES:
            raise HierarchicalStateV7ContractError(f"parameter artifact is oversized: {name}")
        contents[name] = content
    if (
        type(expected_checksums_raw_sha256) is not str
        or len(expected_checksums_raw_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_checksums_raw_sha256)
        or _raw_sha256(contents["CHECKSUMS.sha256"]) != expected_checksums_raw_sha256
    ):
        raise HierarchicalStateV7ContractError("parameter bundle checksum receipt drifted")

    lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    expected_checksum_names = tuple(sorted(_PAYLOAD_FILES))
    if len(lines) != len(expected_checksum_names):
        raise HierarchicalStateV7ContractError("parameter checksum entry count drifted")
    recorded: dict[str, str] = {}
    ordered_names: list[str] = []
    for line in lines:
        parts = line.split("  ", maxsplit=1)
        if (
            len(parts) != 2
            or len(parts[0]) != 64
            or any(character not in "0123456789abcdef" for character in parts[0])
        ):
            raise HierarchicalStateV7ContractError("parameter checksum syntax drifted")
        digest, name = parts
        if name in recorded or name not in _PAYLOAD_FILES:
            raise HierarchicalStateV7ContractError("parameter checksum file universe drifted")
        recorded[name] = digest
        ordered_names.append(name)
    if tuple(ordered_names) != expected_checksum_names:
        raise HierarchicalStateV7ContractError("parameter checksum coverage drifted")
    for name, digest in recorded.items():
        if _raw_sha256(contents[name]) != digest:
            raise HierarchicalStateV7ContractError(f"parameter artifact checksum drifted: {name}")

    parameter_payload = _parse_json_bytes(contents["PARAMETERS.json"], "PARAMETERS.json")
    forbidden = _find_forbidden_parameter_keys(parameter_payload)
    if forbidden:
        raise HierarchicalStateV7ContractError(f"deployable DGP/seed effect leaked: {forbidden}")
    fit_payload = _parse_json_bytes(contents["FIT_RECEIPT.json"], "FIT_RECEIPT.json")
    resource_payload = _parse_json_bytes(contents["RESOURCE_RECEIPT.json"], "RESOURCE_RECEIPT.json")
    manifest = _parse_json_bytes(contents["MANIFEST.json"], "MANIFEST.json")
    expected_manifest_fields = {
        "schema_version",
        "status",
        "candidate_id",
        "design_contract_sha256",
        "parameter_sha256",
        "fit_receipt_sha256",
        "resource_receipt_sha256",
        "fit_end_date",
        "decision_block_start_date",
        "decision_block_end_date",
        "decision_block_first_entity_id",
        "decision_block_last_entity_id",
        "decision_block_ordered_membership_sha256",
        "decision_block_set_membership_sha256",
        "decision_source_positions_sha256",
        "decision_source_state_sha256",
        "decision_source_row_count",
        "decision_row_count",
        "decision_distinct_date_count",
        "within_block_parameter_update_count",
        "fit_row_count",
        "file_raw_sha256",
        "research_dgp_effects_marginalized",
        "manifest_sha256",
    }
    if set(manifest) != expected_manifest_fields:
        raise HierarchicalStateV7ContractError("parameter manifest fields drifted")
    _validate_manifest_types(manifest)
    _verify_manifest_seal(manifest)

    parameter_values = _typed_parameter_payload(parameter_payload)
    parameters = FrozenHierarchicalParametersV7(**parameter_values)
    fit_receipt = FitReceiptV7(**_typed_fit_payload(fit_payload))
    resource_values = _typed_resource_payload(resource_payload)
    resource_receipt = ResourceReceiptV7(**resource_values)
    result = HierarchicalFitResultV7(
        parameters=parameters,
        fit_receipt=fit_receipt,
        resource_receipt=resource_receipt,
    )

    required_manifest = {
        "schema_version": "expected_pe.hofs_v7.frozen_parameter_bundle.v1",
        "status": "FROZEN_PARAMETERS_DGP_MARGINALIZED",
        "candidate_id": CANDIDATE_ID,
        "design_contract_sha256": contract_sha256(),
        "parameter_sha256": parameters.sha256(),
        "fit_receipt_sha256": fit_receipt.sha256(),
        "resource_receipt_sha256": resource_receipt.sha256(),
        "fit_end_date": parameters.fit_end_date,
        "decision_block_start_date": parameters.decision_block_start_date,
        "decision_block_end_date": parameters.decision_block_end_date,
        "decision_block_first_entity_id": parameters.decision_block_first_entity_id,
        "decision_block_last_entity_id": parameters.decision_block_last_entity_id,
        "decision_block_ordered_membership_sha256": (
            parameters.decision_block_ordered_membership_sha256
        ),
        "decision_block_set_membership_sha256": parameters.decision_block_set_membership_sha256,
        "decision_source_positions_sha256": parameters.decision_source_positions_sha256,
        "decision_source_state_sha256": parameters.decision_source_state_sha256,
        "decision_source_row_count": parameters.decision_source_row_count,
        "decision_row_count": parameters.decision_row_count,
        "decision_distinct_date_count": parameters.decision_distinct_date_count,
        "within_block_parameter_update_count": 0,
        "fit_row_count": parameters.fit_row_count,
        "research_dgp_effects_marginalized": True,
    }
    for key, expected in required_manifest.items():
        if manifest.get(key) != expected:
            raise HierarchicalStateV7ContractError(f"parameter manifest binding drifted: {key}")
    if manifest.get("file_raw_sha256") != {
        name: _raw_sha256(contents[name])
        for name in ("FIT_RECEIPT.json", "PARAMETERS.json", "RESOURCE_RECEIPT.json")
    }:
        raise HierarchicalStateV7ContractError("parameter manifest file hashes drifted")
    return result


__all__ = [
    "PARAMETER_BUNDLE_FILES",
    "build_frozen_parameter_bundle_bytes",
    "load_frozen_parameter_bundle",
]
