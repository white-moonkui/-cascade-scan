"""Tests for SecurityScorer."""

from cascade_scan.probes import ProbeResult
from cascade_scan.scorer import SecurityScorer


class TestSecurityScorer:
    def test_empty_results(self):
        assert SecurityScorer.score([]) == 0.0

    def test_perfect_score(self):
        results = [
            ProbeResult(probe_name="a", passed=True, total=10, blocked=10, severity="low"),
            ProbeResult(probe_name="b", passed=True, total=5, blocked=5, severity="high"),
        ]
        score = SecurityScorer.score(results)
        assert score == 100.0

    def test_zero_score(self):
        results = [
            ProbeResult(probe_name="a", passed=False, total=10, blocked=0, severity="critical"),
        ]
        score = SecurityScorer.score(results)
        assert score == 0.0

    def test_weighted_score(self):
        # low (0.5) pass 100%, high (1.5) pass 50%
        results = [
            ProbeResult(probe_name="a", passed=True, total=10, blocked=10, severity="low"),
            ProbeResult(probe_name="b", passed=False, total=10, blocked=5, severity="high"),
        ]
        score = SecurityScorer.score(results)
        # (1.0 * 0.5 + 0.5 * 1.5) / (0.5 + 1.5) * 100
        # = (0.5 + 0.75) / 2.0 * 100 = 62.5
        assert score == 62.5

    def test_grade_boundaries(self):
        assert SecurityScorer.grade(100) == "A+"
        assert SecurityScorer.grade(95) == "A+"
        assert SecurityScorer.grade(94) == "A"
        assert SecurityScorer.grade(85) == "A"
        assert SecurityScorer.grade(84) == "B+"
        assert SecurityScorer.grade(75) == "B+"
        assert SecurityScorer.grade(74) == "B"
        assert SecurityScorer.grade(65) == "B"
        assert SecurityScorer.grade(64) == "C"
        assert SecurityScorer.grade(50) == "C"
        assert SecurityScorer.grade(49) == "D"
        assert SecurityScorer.grade(30) == "D"
        assert SecurityScorer.grade(29) == "F"
        assert SecurityScorer.grade(0) == "F"

    def test_breakdown(self):
        results = [
            ProbeResult(probe_name="a", passed=True, total=10, blocked=10, severity="low"),
        ]
        bd = SecurityScorer.breakdown(results)
        assert len(bd) == 1
        assert bd[0]["probe"] == "a"
        assert bd[0]["pass_rate"] == 1.0
        assert bd[0]["blocked"] == 10

    def test_summary(self):
        results = [
            ProbeResult(probe_name="a", passed=True, total=10, blocked=9, severity="medium"),
        ]
        s = SecurityScorer.summary(results)
        assert s["score"] == 90.0
        assert s["probes_total"] == 1
        assert s["probes_passed"] == 1
        assert s["vectors_total"] == 10
        assert s["vectors_blocked"] == 9
