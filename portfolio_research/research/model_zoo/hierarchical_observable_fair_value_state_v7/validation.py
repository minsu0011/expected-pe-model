"""Exact, non-coercing semantic type validators for H-OFS V7."""

from __future__ import annotations

import math
from typing import Any

from .contracts import HierarchicalStateV7ContractError


def require_exact_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact bool")
    return value


def require_exact_int(
    value: object,
    *,
    label: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact non-Boolean int")
    if minimum is not None and value < minimum:
        raise HierarchicalStateV7ContractError(f"{label} is below its fixed domain")
    if maximum is not None and value > maximum:
        raise HierarchicalStateV7ContractError(f"{label} is above its fixed domain")
    return value


def require_exact_float(
    value: object,
    *,
    label: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise HierarchicalStateV7ContractError(f"{label} must be an exact finite float")
    if minimum is not None and value < minimum:
        raise HierarchicalStateV7ContractError(f"{label} is below its fixed domain")
    if maximum is not None and value > maximum:
        raise HierarchicalStateV7ContractError(f"{label} is above its fixed domain")
    return value


def require_exact_str(
    value: object,
    *,
    label: str,
    nonempty: bool = True,
) -> str:
    if type(value) is not str:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact str")
    if nonempty and not value:
        raise HierarchicalStateV7ContractError(f"{label} cannot be empty")
    return value


def require_sha256(value: object, *, label: str) -> str:
    text = require_exact_str(value, label=label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise HierarchicalStateV7ContractError(f"{label} must be lowercase SHA-256")
    return text


def require_exact_tuple(
    value: object,
    *,
    label: str,
    length: int | None = None,
) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact tuple")
    if length is not None and len(value) != length:
        raise HierarchicalStateV7ContractError(f"{label} length drifted")
    return value


def require_json_list(
    value: object,
    *,
    label: str,
    length: int | None = None,
) -> list[Any]:
    if type(value) is not list:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact JSON array")
    if length is not None and len(value) != length:
        raise HierarchicalStateV7ContractError(f"{label} length drifted")
    return value


def require_exact_dict(value: object, *, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HierarchicalStateV7ContractError(f"{label} must be an exact object")
    if any(type(key) is not str for key in value):
        raise HierarchicalStateV7ContractError(f"{label} keys must be exact strings")
    return value


def require_float_tuple(
    value: object,
    *,
    label: str,
    length: int,
    minimum: float | None = None,
    maximum: float | None = None,
) -> tuple[float, ...]:
    values = require_exact_tuple(value, label=label, length=length)
    for position, item in enumerate(values):
        require_exact_float(
            item,
            label=f"{label}[{position}]",
            minimum=minimum,
            maximum=maximum,
        )
    return values  # type: ignore[return-value]


def require_json_float_list(
    value: object,
    *,
    label: str,
    length: int,
) -> list[float]:
    values = require_json_list(value, label=label, length=length)
    for position, item in enumerate(values):
        require_exact_float(item, label=f"{label}[{position}]")
    return values  # type: ignore[return-value]


__all__ = [
    "require_exact_bool",
    "require_exact_dict",
    "require_exact_float",
    "require_exact_int",
    "require_exact_str",
    "require_exact_tuple",
    "require_float_tuple",
    "require_json_float_list",
    "require_json_list",
    "require_sha256",
]
