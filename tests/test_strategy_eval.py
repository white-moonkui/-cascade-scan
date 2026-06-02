"""Tests for the StrategyEvalProbe (C3 selection pressure under attack)."""

from __future__ import annotations

from cascade import DecisionPipeline
from cascade_scan import ScanEngine
from cascade_scan.probes import StrategyEvalProbe


def test_strategy_eval_probe_runs():
    """Probe runs and returns a ProbeResult."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(StrategyEvalProbe())
    result = engine.run(pipe, min_score=0)
    assert result.total_probes == 1
    pr = result.probe_results[0]
    assert pr.probe_name == "strategy-eval"
    # 5 strategies x 5 cases = 25
    assert pr.total == 25


def test_strategy_eval_probe_covers_all_strategies():
    """Probe covers all 5 built-in strategies."""
    pipe = DecisionPipeline()
    engine = ScanEngine()
    engine.add_probe(StrategyEvalProbe())
    result = engine.run(pipe, min_score=0)
    pr = result.probe_results[0]
    strategies = {d.get("strategy") for d in pr.details}
    assert {"softmax", "linear", "uniform", "threshold", "ucb1"}.issubset(strategies)


def test_strategy_eval_probe_severity():
    """Probe is medium severity."""
    pr = StrategyEvalProbe()
    assert pr.severity == "medium"
    assert pr.name == "strategy-eval"
