"""
Baseline management — save, load, and compare scan results.

Allows teams to:
  - Save a known-good scan result as a baseline
  - Detect score regression over time (CI integration)
  - Track per-probe regressions/improvements version-to-version
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from cascade_scan.probes import ProbeResult
from cascade_scan.scorer import SecurityScorer


@dataclass
class BaselineData:
    """Serialised snapshot of a scan result."""

    score: float
    grade: str
    timestamp: str
    version: str = "0.3.0"
    probe_results: list[dict] = field(default_factory=list)
    total_vectors_blocked: int = 0
    total_vectors: int = 0


@dataclass
class ComparisonResult:
    """Difference between a current scan and a stored baseline."""

    baseline: BaselineData
    current: BaselineData
    score_diff: float
    grade_changed: bool
    regressions: list[dict] = field(default_factory=list)
    improvements: list[dict] = field(default_factory=list)
    verdict: str = "PASS"


def _probe_to_dict(pr: ProbeResult) -> dict:
    return {
        "probe_name": pr.probe_name,
        "severity": pr.severity,
        "passed": pr.passed,
        "pass_rate": round(pr.pass_rate, 3),
        "blocked": pr.blocked,
        "total": pr.total,
    }


class BaselineManager:
    """Static methods for baseline save/load/compare."""

    @staticmethod
    def save(probe_results: list[ProbeResult], path: str | Path) -> None:
        """Save current scan results as a baseline JSON file."""
        score = SecurityScorer.score(probe_results)
        grade = SecurityScorer.grade(score)

        data = BaselineData(
            score=round(score, 1),
            grade=grade,
            timestamp=datetime.now().isoformat(),
            probe_results=[_probe_to_dict(pr) for pr in probe_results],
            total_vectors_blocked=sum(pr.blocked for pr in probe_results),
            total_vectors=sum(pr.total for pr in probe_results),
        )

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(data), indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> BaselineData:
        """Load a baseline from a JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Baseline file not found: {path}")

        raw = json.loads(path.read_text(encoding="utf-8"))
        return BaselineData(**raw)

    @staticmethod
    def compare(
        current_probe_results: list[ProbeResult],
        baseline_path: str | Path,
    ) -> ComparisonResult:
        """Compare current scan results against a stored baseline."""
        baseline = BaselineManager.load(baseline_path)

        current_score = SecurityScorer.score(current_probe_results)
        current_grade = SecurityScorer.grade(current_score)

        current_data = BaselineData(
            score=round(current_score, 1),
            grade=current_grade,
            timestamp=datetime.now().isoformat(),
            probe_results=[_probe_to_dict(pr) for pr in current_probe_results],
            total_vectors_blocked=sum(pr.blocked for pr in current_probe_results),
            total_vectors=sum(pr.total for pr in current_probe_results),
        )

        score_diff = round(current_data.score - baseline.score, 1)
        grade_changed = current_data.grade != baseline.grade

        # Per-probe comparison
        baseline_map = {p["probe_name"]: p for p in baseline.probe_results}

        regressions: list[dict] = []
        improvements: list[dict] = []

        for pr in current_probe_results:
            bp = baseline_map.get(pr.probe_name)
            if bp is None:
                continue
            diff = round(pr.pass_rate - bp["pass_rate"], 3)
            if diff < -0.05:
                regressions.append({
                    "probe": pr.probe_name,
                    "baseline_pass_rate": bp["pass_rate"],
                    "current_pass_rate": round(pr.pass_rate, 3),
                    "diff": diff,
                })
            elif diff > 0.05:
                improvements.append({
                    "probe": pr.probe_name,
                    "baseline_pass_rate": bp["pass_rate"],
                    "current_pass_rate": round(pr.pass_rate, 3),
                    "diff": diff,
                })

        if regressions:
            verdict = "REGRESSION"
        elif improvements and score_diff >= 0:
            verdict = "IMPROVED"
        else:
            verdict = "PASS"

        return ComparisonResult(
            baseline=baseline,
            current=current_data,
            score_diff=score_diff,
            grade_changed=grade_changed,
            regressions=regressions,
            improvements=improvements,
            verdict=verdict,
        )

    @staticmethod
    def summarize(cr: ComparisonResult) -> dict[str, Any]:
        """Return a formatted summary dict for CLI display."""
        return {
            "verdict": cr.verdict,
            "baseline_score": cr.baseline.score,
            "current_score": cr.current.score,
            "score_diff": cr.score_diff,
            "baseline_grade": cr.baseline.grade,
            "current_grade": cr.current.grade,
            "grade_changed": cr.grade_changed,
            "n_regressions": len(cr.regressions),
            "n_improvements": len(cr.improvements),
            "regressions": cr.regressions,
            "improvements": cr.improvements,
        }
