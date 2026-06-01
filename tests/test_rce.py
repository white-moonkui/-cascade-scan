"""Tests for RCE probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import RCEProbe, ProbeResult


class TestRCEProbe:
    def test_probe_metadata(self):
        probe = RCEProbe()
        assert probe.name == "rce"
        assert probe.severity == "critical"

    def test_blocks_rce_vectors_with_rules(self):
        pipe = DecisionPipeline()
        probe = RCEProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        assert result.blocked > 0, (
            "Expected RCE probe to block at least one vector "
            "with rule-based blocking"
        )

    def test_blocks_rce_vectors_count(self):
        pipe = DecisionPipeline()
        probe = RCEProbe()
        result = probe.run(pipe)
        assert result.total == len(RCEProbe.VECTORS)

    def test_metadata_properties(self):
        probe = RCEProbe()
        assert "code execution" in probe.description.lower()

    def test_all_vectors_have_unique_ids(self):
        probe = RCEProbe()
        ids = [v["id"] for v in probe.VECTORS]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs detected"
