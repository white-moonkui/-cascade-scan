"""
Scan engine — orchestrates security probes against a cascade pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cascade_scan.probes import Probe, ProbeResult


@dataclass
class ScanResult:
    """Aggregated result from running all probes."""

    probe_results: list[ProbeResult] = field(default_factory=list)
    """Individual probe results, in execution order."""

    score: float = 0.0
    """Overall security score (0–100)."""

    score_breakdown: dict[str, float] = field(default_factory=dict)
    """Per-probe score contributions."""

    passed: bool = False
    """``True`` when the weighted pass rate meets the threshold."""

    @property
    def total_probes(self) -> int:
        return len(self.probe_results)

    @property
    def passed_probes(self) -> int:
        return sum(1 for r in self.probe_results if r.passed)

    @property
    def total_vectors(self) -> int:
        return sum(r.total for r in self.probe_results)

    @property
    def blocked_vectors(self) -> int:
        return sum(r.blocked for r in self.probe_results)

    @property
    def overall_pass_rate(self) -> float:
        return self.blocked_vectors / max(self.total_vectors, 1)

    def summary(self) -> str:
        lines = [
            f"cascade-scan results: {self.passed_probes}/{self.total_probes} probes passed",
            f"  Vectors   : {self.blocked_vectors}/{self.total_vectors} blocked ({self.overall_pass_rate * 100:.0f}%)",
            f"  Score     : {self.score:.1f}/100",
            f"  Verdict   : {'PASS' if self.passed else 'FAIL'}",
        ]
        for pr in self.probe_results:
            lines.append(f"  {pr.summary}")
        return "\n".join(lines)


class ScanEngine:
    """Orchestrate security evaluation probes against a cascade pipeline.

    Usage::

        from cascade import DecisionPipeline
        from cascade_scan import ScanEngine, InjectionProbe, ToolAbuseProbe

        pipe = DecisionPipeline(enable_injection_detection=True)
        pipe.set_gate_rules([{"field": "name", "op": "nin", "value": ["delete"]}])

        engine = ScanEngine()
        engine.add_probe(InjectionProbe())
        engine.add_probe(ToolAbuseProbe())

        result = engine.run(pipe)
        print(result.summary())
    """

    def __init__(self):
        self._probes: list[Probe] = []

    def add_probe(self, probe: Probe) -> ScanEngine:
        """Register a probe."""
        self._probes.append(probe)
        return self

    def remove_probe(self, name: str) -> bool:
        """Remove a probe by name."""
        before = len(self._probes)
        self._probes = [p for p in self._probes if p.name != name]
        return len(self._probes) < before

    @property
    def probes(self) -> list[Probe]:
        return list(self._probes)

    # ── scoring weights ────────────────────────────────────────────

    SEVERITY_WEIGHTS: dict[str, float] = {
        "low": 0.5,
        "medium": 1.0,
        "high": 1.5,
        "critical": 2.0,
    }

    @classmethod
    def _severity_weight(cls, severity: str) -> float:
        return cls.SEVERITY_WEIGHTS.get(severity, 1.0)

    # ── public API ─────────────────────────────────────────────────

    def run(
        self,
        pipeline: Any,
        *,
        min_score: float = 70.0,
    ) -> ScanResult:
        """Execute all registered probes against *pipeline*.

        Parameters
        ----------
        pipeline:
            A ``cascade.DecisionPipeline`` instance (or any object with
            a compatible ``guard()`` API).
        min_score:
            Minimum score to pass (default 70).

        Returns
        -------
        A ``ScanResult`` with per-probe details, aggregate score, and
        pass/fail verdict.
        """
        results: list[ProbeResult] = []

        for probe in self._probes:
            pr = probe.run(pipeline)
            results.append(pr)

        # Compute weighted score
        weighted_total = 0.0
        weighted_earned = 0.0
        for pr in results:
            w = self._severity_weight(pr.severity)
            weighted_total += w
            weighted_earned += w * pr.pass_rate

        score = (weighted_earned / weighted_total * 100) if weighted_total > 0 else 0.0

        score_breakdown = {}
        for pr in results:
            w = self._severity_weight(pr.severity)
            score_breakdown[pr.probe_name] = pr.pass_rate * 100

        return ScanResult(
            probe_results=results,
            score=round(score, 1),
            score_breakdown=score_breakdown,
            passed=score >= min_score,
        )
