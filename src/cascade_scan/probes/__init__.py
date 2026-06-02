"""
Security probes — each probe tests a specific attack surface against a
cascade pipeline.

A probe is a callable that receives a ``DecisionPipeline`` (or a
pipeline-like dict) and returns a ``ProbeResult``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeResult:
    """Outcome of a single probe execution."""

    probe_name: str
    """Name of the probe that produced this result."""

    passed: bool
    """``True`` when cascade governance correctly blocked/filtered the attack."""

    total: int
    """Number of attack vectors tested."""

    blocked: int
    """Number of attack vectors that cascade correctly blocked."""

    details: list[dict] = field(default_factory=list)
    """Per-vector detail records."""

    severity: str = "medium"
    """Impact severity: ``low`` / ``medium`` / ``high`` / ``critical``."""

    @property
    def pass_rate(self) -> float:
        """Fraction of attack vectors that were correctly blocked (0–1)."""
        return self.blocked / max(self.total, 1)

    @property
    def summary(self) -> str:
        return (
            f"{'PASS' if self.passed else 'FAIL'} "
            f"{self.probe_name}: {self.blocked}/{self.total} blocked "
            f"({self.pass_rate * 100:.0f}%)"
        )


class Probe:
    """Base class for security probes.

    Subclasses must implement ``run(pipeline, **kwargs) -> ProbeResult``.
    """

    name: str = ""
    description: str = ""
    severity: str = "medium"

    def run(self, pipeline: Any, **kwargs) -> ProbeResult:
        raise NotImplementedError

    def __call__(self, pipeline: Any, **kwargs) -> ProbeResult:
        return self.run(pipeline, **kwargs)


# Existing probes
from cascade_scan.probes.injection import InjectionProbe
from cascade_scan.probes.tool_abuse import ToolAbuseProbe

# Phase S2 probes
from cascade_scan.probes.xss import XSSProbe
from cascade_scan.probes.sqli import SQLIProbe
from cascade_scan.probes.prompt_leak import PromptLeakProbe
from cascade_scan.probes.rce import RCEProbe
from cascade_scan.probes.tool_chain import ToolChainProbe
from cascade_scan.probes.data_flow import DataFlowProbe

# Phase S2.3 probes
from cascade_scan.probes.escalation import EscalationProbe
from cascade_scan.probes.loop_dos import LoopDoSProbe

# v0.5.0 probes — deeper cascade integration
from cascade_scan.probes.mcp_poisoning import MCPPoisoningProbe

__all__ = [
    "Probe",
    "ProbeResult",
    "InjectionProbe",
    "ToolAbuseProbe",
    "XSSProbe",
    "SQLIProbe",
    "PromptLeakProbe",
    "RCEProbe",
    "ToolChainProbe",
    "DataFlowProbe",
    "EscalationProbe",
    "LoopDoSProbe",
    "MCPPoisoningProbe",
]
