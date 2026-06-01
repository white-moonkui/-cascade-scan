"""Tests for ScanEngine."""

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import Probe, ProbeResult


class _PassProbe(Probe):
    name = "pass-test"
    description = "Always passes"
    severity = "low"

    def run(self, pipeline, **kwargs):
        return ProbeResult(
            probe_name=self.name,
            passed=True,
            total=10,
            blocked=10,
            severity=self.severity,
        )


class _FailProbe(Probe):
    name = "fail-test"
    description = "Always fails"
    severity = "critical"

    def run(self, pipeline, **kwargs):
        return ProbeResult(
            probe_name=self.name,
            passed=False,
            total=5,
            blocked=0,
            severity=self.severity,
        )


class TestScanEngine:
    def test_empty_engine(self):
        engine = ScanEngine()
        pipe = DecisionPipeline()
        result = engine.run(pipe)
        assert result.score == 0.0
        assert result.passed is False
        assert result.total_probes == 0

    def test_single_pass_probe(self):
        engine = ScanEngine()
        engine.add_probe(_PassProbe())
        pipe = DecisionPipeline()
        result = engine.run(pipe, min_score=50)
        assert result.passed is True
        assert result.score == 100.0
        assert result.passed_probes == 1

    def test_single_fail_probe(self):
        engine = ScanEngine()
        engine.add_probe(_FailProbe())
        pipe = DecisionPipeline()
        result = engine.run(pipe, min_score=50)
        assert result.passed is False
        assert result.score == 0.0
        assert result.passed_probes == 0

    def test_mixed_probes(self):
        engine = ScanEngine()
        engine.add_probe(_PassProbe())  # weight 0.5, pass_rate 1.0
        engine.add_probe(_FailProbe())  # weight 2.0, pass_rate 0.0
        pipe = DecisionPipeline()
        result = engine.run(pipe, min_score=0)
        # Score = (1.0 * 0.5 + 0.0 * 2.0) / (0.5 + 2.0) * 100 = 20
        assert result.score == 20.0
        assert result.passed_probes == 1

    def test_add_remove_probe(self):
        engine = ScanEngine()
        engine.add_probe(_PassProbe())
        assert len(engine.probes) == 1
        engine.remove_probe("pass-test")
        assert len(engine.probes) == 0
        assert engine.remove_probe("nonexistent") is False

    def test_summary_output(self):
        engine = ScanEngine()
        engine.add_probe(_PassProbe())
        pipe = DecisionPipeline()
        result = engine.run(pipe)
        summary = result.summary()
        assert "cascade-scan results" in summary
        assert "PASS" in summary or "FAIL" in summary
