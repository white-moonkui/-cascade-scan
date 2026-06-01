"""Tests for Evolver."""
from __future__ import annotations

from typing import Any

import pytest

from cascade_scan.probes import ProbeResult
from cascade_scan.evolve import Evolver


class MockScanResult:
    """Minimal mock that quacks like ScanResult."""

    def __init__(self, probe_results: list[ProbeResult]) -> None:
        self._probe_results = probe_results

    @property
    def probe_results(self) -> list[ProbeResult]:
        return self._probe_results


class MockScanEngine:
    """Minimal mock that quacks like ScanEngine."""

    def __init__(self, scores: list[float] | None = None) -> None:
        self.scores = scores or [0.9, 0.7, 0.5]
        self._index = 0

    def add_probe(self, probe: Any) -> None:
        pass

    def run(self, pipe: Any, min_score: float = 70.0) -> MockScanResult:
        if self._index >= len(self.scores):
            raise RuntimeError("No more scores — test overran mock data")
        s = self.scores[self._index]
        self._index += 1
        passed = s >= 0.5
        return MockScanResult([
            ProbeResult(
                probe_name="injection",
                severity="critical",
                passed=passed,
                total=10,
                blocked=int(10 * s),
            ),
        ])


def _build_pipe():
    from cascade import DecisionPipeline

    return DecisionPipeline(enable_injection_detection=True)


class TestEvolver:
    def test_single_iteration(self):
        engine = MockScanEngine(scores=[0.85])
        evolver = Evolver(engine, _build_pipe, iterations=1)
        result = evolver.run()

        assert result.iterations == 1
        assert len(result.scores) == 1
        assert isinstance(result.scores[0], float)
        assert len(result.probe_results_per_iteration) == 1

    def test_multiple_iterations(self):
        engine = MockScanEngine(scores=[0.9, 0.7, 0.5])
        evolver = Evolver(engine, _build_pipe, iterations=3)
        result = evolver.run()

        assert result.iterations == 3
        assert len(result.scores) == 3
        assert result.scores_min == pytest.approx(50.0, abs=0.1)
        assert result.scores_max == pytest.approx(90.0, abs=0.1)
        assert result.scores_avg == pytest.approx(70.0, abs=0.1)

    def test_iteration_count(self):
        engine = MockScanEngine(scores=[0.8, 0.8, 0.8, 0.8, 0.8])
        evolver = Evolver(engine, _build_pipe, iterations=5)
        result = evolver.run()

        assert len(result.scores) == 5
        assert all(s == pytest.approx(80.0, abs=0.1) for s in result.scores)

    def test_summary_format(self):
        engine = MockScanEngine(scores=[0.95, 0.85])
        evolver = Evolver(engine, _build_pipe, iterations=2)
        result = evolver.run()

        summary = Evolver.summary(result)
        assert summary["iterations"] == 2
        assert isinstance(summary["min"], float)
        assert isinstance(summary["max"], float)
        assert isinstance(summary["avg"], float)
        assert isinstance(summary["std"], float)
        assert isinstance(summary["grade"], str)

    def test_zero_iterations_defaults_to_one(self):
        engine = MockScanEngine(scores=[0.8])
        evolver = Evolver(engine, _build_pipe, iterations=0)
        result = evolver.run()
        assert result.iterations == 1
        assert len(result.scores) == 1

    def test_per_iteration_probe_data(self):
        engine = MockScanEngine(scores=[0.9, 0.5])
        evolver = Evolver(engine, _build_pipe, iterations=2)
        result = evolver.run()

        assert len(result.probe_results_per_iteration) == 2
        for iteration_data in result.probe_results_per_iteration:
            for pr_dict in iteration_data:
                assert "probe_name" in pr_dict
                assert "pass_rate" in pr_dict
                assert "blocked" in pr_dict
                assert "total" in pr_dict
