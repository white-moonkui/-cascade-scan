"""
cascade-scan — AI Agent security evaluation framework.

Automated red-teaming for LLM tool-call governance.  Scans agent
pipelines against attack scenarios, scores security posture, and
generates compliance-grade reports.

Built on cascade's C₁–C₄ governance engine.
"""

from cascade_scan.engine import ScanEngine, ScanResult
from cascade_scan.probes import (
    Probe,
    InjectionProbe,
    ToolAbuseProbe,
    XSSProbe,
    SQLIProbe,
    PromptLeakProbe,
    RCEProbe,
    ToolChainProbe,
    DataFlowProbe,
    EscalationProbe,
    LoopDoSProbe,
    MCPPoisoningProbe,
    PolicyComplianceProbe,
    StrategyEvalProbe,
)
from cascade_scan.scorer import SecurityScorer
from cascade_scan.report import export_html, export_json
from cascade_scan.evolve import Evolver, EvolutionResult
from cascade_scan.baseline import BaselineManager, BaselineData, ComparisonResult

__all__ = [
    "ScanEngine",
    "ScanResult",
    "Probe",
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
    "PolicyComplianceProbe",
    "StrategyEvalProbe",
    "SecurityScorer",
    "export_html",
    "export_json",
    "Evolver",
    "EvolutionResult",
    "BaselineManager",
    "BaselineData",
    "ComparisonResult",
]
