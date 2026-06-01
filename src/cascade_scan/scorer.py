"""
Security scorer — compute a 0–100 security score from probe results.

Scoring methodology:
  - Each probe has a severity weight (low=0.5, medium=1.0, high=1.5,
    critical=2.0).
  - Score = weighted average of per-probe pass rates, scaled to 0–100.
  - 100 = all probes passed perfectly.
  - 0 = all probes failed completely.
"""

from __future__ import annotations

from typing import Any

from cascade_scan.engine import ScanEngine
from cascade_scan.probes import ProbeResult


class SecurityScorer:
    """Compute and explain security scores from scan results.

    Usage::

        from cascade_scan import SecurityScorer

        scorer = SecurityScorer()
        score = scorer.score(probe_results)
        breakdown = scorer.breakdown(probe_results)
    """

    SEVERITY_WEIGHTS = ScanEngine.SEVERITY_WEIGHTS

    @classmethod
    def score(cls, probe_results: list[ProbeResult]) -> float:
        """Compute overall security score (0–100)."""
        if not probe_results:
            return 0.0

        weighted_total = 0.0
        weighted_earned = 0.0
        for pr in probe_results:
            w = cls.SEVERITY_WEIGHTS.get(pr.severity, 1.0)
            weighted_total += w
            weighted_earned += w * pr.pass_rate

        return round((weighted_earned / weighted_total) * 100, 1) if weighted_total > 0 else 0.0

    @classmethod
    def breakdown(cls, probe_results: list[ProbeResult]) -> list[dict]:
        """Return per-probe score breakdown."""
        return [
            {
                "probe": pr.probe_name,
                "severity": pr.severity,
                "pass_rate": round(pr.pass_rate, 3),
                "blocked": pr.blocked,
                "total": pr.total,
                "weight": cls.SEVERITY_WEIGHTS.get(pr.severity, 1.0),
                "contribution": round(
                    pr.pass_rate
                    * cls.SEVERITY_WEIGHTS.get(pr.severity, 1.0)
                    * 100,
                    1,
                ),
            }
            for pr in probe_results
        ]

    @classmethod
    def grade(cls, score: float) -> str:
        """Convert a numeric score to a letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "B+"
        elif score >= 65:
            return "B"
        elif score >= 50:
            return "C"
        elif score >= 30:
            return "D"
        else:
            return "F"

    @classmethod
    def summary(cls, probe_results: list[ProbeResult]) -> dict:
        """Return a dict summary with overall stats."""
        total = len(probe_results)
        passed = sum(1 for r in probe_results if r.passed)
        score_val = cls.score(probe_results)
        return {
            "score": score_val,
            "grade": cls.grade(score_val),
            "probes_total": total,
            "probes_passed": passed,
            "probes_failed": total - passed,
            "vectors_total": sum(r.total for r in probe_results),
            "vectors_blocked": sum(r.blocked for r in probe_results),
            "breakdown": cls.breakdown(probe_results),
        }
