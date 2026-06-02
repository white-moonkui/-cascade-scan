"""Tests for the FeedbackLoopProbe (C3-C4 Linkage reward poisoning)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import FeedbackLoopProbe


def test_feedback_loop_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(FeedbackLoopProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "feedback-loop"
    # 5 attack vectors
    assert pr.total == 5


def test_feedback_loop_probe_all_categories():
    """Probe tests all feedback-loop attack categories."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(FeedbackLoopProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    categories = {d.get("category") for d in pr.details}
    expected = {
        "reward_poisoning",
        "score_drift",
        "adaptive_threshold",
        "reset_attack",
        "report_visibility",
    }
    assert expected.issubset(categories)


def test_feedback_loop_probe_severity():
    """Probe is critical severity."""
    pr = FeedbackLoopProbe()
    assert pr.severity == "critical"
    assert pr.name == "feedback-loop"
