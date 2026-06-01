"""Tests for ToolChain probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import ToolChainProbe, ProbeResult


class TestToolChainProbe:
    def test_probe_metadata(self):
        probe = ToolChainProbe()
        assert probe.name == "tool-chain"
        assert probe.severity == "critical"

    def test_blocks_tool_chains_with_rules(self):
        pipe = DecisionPipeline()
        probe = ToolChainProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        assert result.blocked > 0, (
            "Expected ToolChain probe to block at least one chain"
        )

    def test_chain_count(self):
        pipe = DecisionPipeline()
        probe = ToolChainProbe()
        result = probe.run(pipe)
        assert result.total == len(ToolChainProbe.CHAINS)

    def test_metadata_properties(self):
        probe = ToolChainProbe()
        assert "tool" in probe.description.lower()

    def test_all_chains_have_unique_ids(self):
        probe = ToolChainProbe()
        ids = [c["id"] for c in probe.CHAINS]
        assert len(ids) == len(set(ids)), "Duplicate chain IDs detected"
