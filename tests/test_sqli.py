"""Tests for SQLi probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import SQLIProbe, ProbeResult


class TestSQLIProbe:
    def test_probe_metadata(self):
        probe = SQLIProbe()
        assert probe.name == "sqli"
        assert probe.severity == "high"

    def test_blocks_sqli_vectors_with_rules(self):
        pipe = DecisionPipeline()
        probe = SQLIProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0
        assert result.blocked > 0, (
            "Expected SQLi probe to block at least one vector "
            "with rule-based blocking"
        )

    def test_metadata_properties(self):
        probe = SQLIProbe()
        assert probe.name == "sqli"
        assert "sql" in probe.description.lower()

    def test_all_vectors_have_unique_ids(self):
        probe = SQLIProbe()
        ids = [v["id"] for v in probe.VECTORS]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs detected"
