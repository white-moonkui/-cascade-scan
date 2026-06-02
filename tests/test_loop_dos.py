"""Tests for the LoopDoSProbe (burst / self-reference / deep-nesting)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import LoopDoSProbe


def test_loop_dos_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(LoopDoSProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "loop-dos"
    assert pr.total == 3  # 3 attack modes


def test_loop_dos_probe_burst_test():
    """Burst test produces throughput measurement."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(LoopDoSProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    burst = next((d for d in pr.details if d.get("test") == "burst"), None)
    assert burst is not None
    assert burst["count"] == 100
    assert "elapsed_sec" in burst
    assert "calls_per_sec" in burst


def test_loop_dos_probe_self_reference():
    """Self-reference test rejects pipeline-execution tools."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(LoopDoSProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    sr = next((d for d in pr.details if d.get("test") == "self_reference"), None)
    assert sr is not None
    assert sr["blocked"] is True


def test_loop_dos_probe_deep_nesting():
    """Deep-nesting test handles large nested argument payloads."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(LoopDoSProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    dn = next((d for d in pr.details if d.get("test") == "deep_nesting"), None)
    assert dn is not None
    assert dn["depths"] == [10, 50, 100, 200]


def test_loop_dos_probe_severity():
    """Probe is critical severity."""
    pr = LoopDoSProbe()
    assert pr.severity == "critical"
    assert pr.name == "loop-dos"
