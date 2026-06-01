"""Tests for XSS probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import XSSProbe, ProbeResult


class TestXSSProbe:
    def test_probe_metadata(self):
        probe = XSSProbe()
        assert probe.name == "xss"
        assert probe.severity == "high"

    def test_blocks_xss_vectors_with_injection(self):
        pipe = DecisionPipeline(enable_injection_detection=True)
        probe = XSSProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        # Should block at least some XSS vectors
        assert result.blocked > 0, (
            "Expected XSS probe to block at least one vector "
            "with injection detection enabled"
        )

    def test_metadata_properties(self):
        probe = XSSProbe()
        assert probe.name == "xss"
        assert "script" in probe.description.lower()

    def test_all_vectors_have_unique_ids(self):
        probe = XSSProbe()
        ids = [v["id"] for v in probe.VECTORS]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs detected"
