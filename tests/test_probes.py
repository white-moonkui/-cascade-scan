"""Tests for security probes."""

from cascade import DecisionPipeline
from cascade_scan.probes import InjectionProbe, ToolAbuseProbe, ProbeResult


class TestInjectionProbe:
    def test_probe_metadata(self):
        probe = InjectionProbe()
        assert probe.name == "injection-detection"
        assert probe.severity == "critical"

    def test_probe_with_injection_enabled(self):
        pipe = DecisionPipeline(enable_injection_detection=True)
        probe = InjectionProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        # Should block a meaningful number
        assert result.blocked > 0

    def test_probe_with_injection_disabled(self):
        pipe = DecisionPipeline(enable_injection_detection=False)
        probe = InjectionProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        # With injection disabled, patterns will NOT be detected
        # by injection detection. The probe may still show low block rate
        # since guard() with no rules will pass everything.
        # This is expected — injection_disabled = weak security
        assert result.total > 0

    def test_probe_result_properties(self):
        result = ProbeResult(
            probe_name="test",
            passed=True,
            total=20,
            blocked=18,
            severity="high",
        )
        assert result.pass_rate == 0.9
        assert "PASS" in result.summary
        assert "90%" in result.summary


class TestToolAbuseProbe:
    def test_probe_metadata(self):
        probe = ToolAbuseProbe()
        assert probe.name == "tool-abuse"
        assert probe.severity == "high"

    def test_probe_blocks_dangerous_tools(self):
        pipe = DecisionPipeline()
        probe = ToolAbuseProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        # The probe passes rules explicitly, so it should block
        # most dangerous tools
        assert result.blocked > 0
        assert result.total == len(ToolAbuseProbe.DEFAULT_BLOCKED_TOOLS)

    def test_pass_rate_calculation(self):
        result = ProbeResult(
            probe_name="test",
            passed=False,
            total=10,
            blocked=3,
            severity="medium",
        )
        assert result.pass_rate == 0.3
        assert "FAIL" in result.summary
