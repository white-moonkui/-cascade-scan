"""
Evolve mode — iterative security evaluation with score tracking.

Run multiple scan iterations and report min/max/avg/std deviation
of security scores across iterations. Useful for:
  - Assessing scan stability / variance
  - Tuning pipeline rules across runs
  - Detecting flaky governance behaviour
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from cascade import DecisionPipeline

from cascade_scan import ScanEngine, SecurityScorer


@dataclass
class EvolutionResult:
    """Result of an evolution run."""

    iterations: int
    scores: list[float] = field(default_factory=list)
    probe_results_per_iteration: list[list[dict]] = field(default_factory=list)

    @property
    def scores_min(self) -> float:
        return min(self.scores) if self.scores else 0.0

    @property
    def scores_max(self) -> float:
        return max(self.scores) if self.scores else 0.0

    @property
    def scores_avg(self) -> float:
        return statistics.mean(self.scores) if self.scores else 0.0

    @property
    def scores_std(self) -> float:
        if len(self.scores) < 2:
            return 0.0
        return statistics.stdev(self.scores)

    @property
    def grade(self) -> str:
        return SecurityScorer.grade(self.scores_avg)


class Evolver:
    """Iterative security evaluator.

    Usage::

        from cascade import DecisionPipeline
        from cascade_scan import ScanEngine
        from cascade_scan.evolve import Evolver

        engine = ScanEngine()
        # ... add probes ...

        def build_pipe():
            return DecisionPipeline(enable_injection_detection=True)

        evolver = Evolver(engine, build_pipe, iterations=5)
        result = evolver.run()
        print(result.scores_avg, result.grade)
    """

    def __init__(
        self,
        engine: ScanEngine,
        pipe_builder: callable,
        iterations: int = 5,
        probe_names: list[str] | None = None,
    ) -> None:
        self.engine = engine
        self.pipe_builder = pipe_builder
        self.iterations = max(iterations, 1)
        self.probe_names = probe_names

    def run(self) -> EvolutionResult:
        """Run *iterations* scans and return aggregated results."""
        result = EvolutionResult(iterations=self.iterations)

        for i in range(self.iterations):
            pipe = self.pipe_builder()
            scan_result = self.engine.run(pipe)

            score = SecurityScorer.score(scan_result.probe_results)
            result.scores.append(score)

            result.probe_results_per_iteration.append(
                [
                    {
                        "probe_name": pr.probe_name,
                        "passed": pr.passed,
                        "pass_rate": pr.pass_rate,
                        "blocked": pr.blocked,
                        "total": pr.total,
                        "severity": pr.severity,
                    }
                    for pr in scan_result.probe_results
                ]
            )

        return result

    @staticmethod
    def summary(result: EvolutionResult) -> dict[str, Any]:
        """Return a formatted summary dict for CLI display."""
        return {
            "iterations": result.iterations,
            "scores": [round(s, 1) for s in result.scores],
            "min": round(result.scores_min, 1),
            "max": round(result.scores_max, 1),
            "avg": round(result.scores_avg, 1),
            "std": round(result.scores_std, 2),
            "grade": result.grade,
        }
