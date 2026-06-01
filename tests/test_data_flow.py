"""Tests for DataFlow probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import DataFlowProbe, ProbeResult


class TestDataFlowProbe:
    def test_probe_metadata(self):
        probe = DataFlowProbe()
        assert probe.name == "data-flow"
        assert probe.severity == "high"

    def test_blocks_exfiltration_vectors_with_rules(self):
        pipe = DecisionPipeline()
        probe = DataFlowProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        assert result.blocked > 0, (
            "Expected DataFlow probe to block at least one vector"
        )

    def test_blocks_exfiltration_count(self):
        pipe = DecisionPipeline()
        probe = DataFlowProbe()
        result = probe.run(pipe)
        assert result.total == len(DataFlowProbe.VECTORS)

    def test_metadata_properties(self):
        probe = DataFlowProbe()
        assert "exfiltration" in probe.description.lower()

    def test_all_vectors_have_unique_ids(self):
        probe = DataFlowProbe()
        ids = [v["id"] for v in probe.VECTORS]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs detected"
