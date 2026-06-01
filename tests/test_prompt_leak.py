"""Tests for PromptLeak probe."""

from cascade import DecisionPipeline
from cascade_scan.probes import PromptLeakProbe, ProbeResult


class TestPromptLeakProbe:
    def test_probe_metadata(self):
        probe = PromptLeakProbe()
        assert probe.name == "prompt-leak"
        assert probe.severity == "critical"

    def test_blocks_prompt_leak_vectors_with_injection(self):
        pipe = DecisionPipeline(enable_injection_detection=True)
        probe = PromptLeakProbe()
        result = probe.run(pipe)
        assert isinstance(result, ProbeResult)
        assert result.total > 0

    def test_metadata_properties(self):
        probe = PromptLeakProbe()
        assert "prompt" in probe.description.lower()

    def test_all_vectors_have_unique_ids(self):
        probe = PromptLeakProbe()
        ids = [v["id"] for v in probe.VECTORS]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs detected"
