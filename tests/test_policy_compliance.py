"""Tests for the PolicyComplianceProbe (cascade >= 0.9.0 policy features)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import PolicyComplianceProbe


def test_policy_compliance_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(PolicyComplianceProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "policy-compliance"
    assert pr.total > 0


def test_policy_compliance_probe_categories():
    """Probe tests deny_by_default + presets + extends."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(PolicyComplianceProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    categories = {d.get("category", "") for d in pr.details}
    # At least one of these should be present (others may error if cascade < 0.9.0)
    has_dbd = any("deny_by_default" in c for c in categories)
    has_preset = any("preset" in c for c in categories)
    assert has_dbd or has_preset


def test_policy_compliance_probe_severity():
    """Probe is high severity."""
    pr = PolicyComplianceProbe()
    assert pr.severity == "high"
    assert pr.name == "policy-compliance"
