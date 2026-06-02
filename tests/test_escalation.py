"""Tests for the EscalationProbe (privilege-escalation chain detection)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import EscalationProbe


def test_escalation_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(EscalationProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "escalation"
    assert pr.total == 4  # 4 attack chains
    assert isinstance(pr.passed, bool)


def test_escalation_probe_details():
    """Probe produces per-chain details with stop info."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(EscalationProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    assert len(pr.details) == 4
    for d in pr.details:
        assert "chain_id" in d
        assert "steps" in d
        assert "blocked_steps" in d
        assert "chain_stopped" in d


def test_escalation_probe_severity():
    """Probe is critical severity."""
    pr = EscalationProbe()
    assert pr.severity == "critical"
    assert pr.name == "escalation"
