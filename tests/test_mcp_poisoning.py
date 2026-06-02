"""Tests for the MCPPoisoningProbe (MCP-specific attack vectors)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import MCPPoisoningProbe


def test_mcp_poisoning_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(MCPPoisoningProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "mcp-poisoning"
    # 5 desc-poisoning + 5 name-spoofing + 2 schema-injection = 12
    assert pr.total == 12


def test_mcp_poisoning_probe_categories():
    """Probe produces per-category details."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(MCPPoisoningProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    categories = {d.get("category", "").split("/")[0] for d in pr.details}
    assert "description_poisoning" in categories
    assert "name_spoofing" in categories
    assert "schema_injection" in categories


def test_mcp_poisoning_probe_severity():
    """Probe is critical severity."""
    pr = MCPPoisoningProbe()
    assert pr.severity == "critical"
    assert pr.name == "mcp-poisoning"
