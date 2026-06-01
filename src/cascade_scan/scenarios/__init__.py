"""Attack scenario definitions and registry."""

from cascade_scan.scenarios.registry import (
    AttackScenario,
    get_scenario,
    list_scenarios,
    register_scenario,
)

__all__ = [
    "AttackScenario",
    "get_scenario",
    "list_scenarios",
    "register_scenario",
]
