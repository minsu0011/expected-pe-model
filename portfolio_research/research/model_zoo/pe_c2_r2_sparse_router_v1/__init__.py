"""Research-only sparse reliability routers layered on the spent C2 robust cap."""

from .contracts import (
    EVIDENCE_CLASS,
    RESEARCH_TARGET,
    ROUTER_FEATURE_COLUMNS,
    VARIANT_IDS,
    VARIANT_SPECS,
)
from .router import RouterTaskResult, route_task

__all__ = [
    "EVIDENCE_CLASS",
    "RESEARCH_TARGET",
    "ROUTER_FEATURE_COLUMNS",
    "RouterTaskResult",
    "VARIANT_IDS",
    "VARIANT_SPECS",
    "route_task",
]
