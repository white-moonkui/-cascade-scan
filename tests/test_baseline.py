"""Tests for BaselineManager."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cascade_scan.probes import ProbeResult
from cascade_scan.baseline import BaselineManager, BaselineData


class TestBaselineManager:
    def make_results(self) -> list[ProbeResult]:
        return [
            ProbeResult(
                probe_name="injection",
                severity="critical",
                passed=True,
                total=20,
                blocked=18,
            ),
            ProbeResult(
                probe_name="tool-abuse",
                severity="high",
                passed=True,
                total=10,
                blocked=8,
            ),
        ]

    def test_save_creates_file(self):
        results = self.make_results()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp = Path(f.name)

        try:
            BaselineManager.save(results, tmp)
            assert tmp.exists()
            data = json.loads(tmp.read_text(encoding="utf-8"))
            assert "score" in data
            assert "grade" in data
            assert "timestamp" in data
            assert "probe_results" in data
            assert len(data["probe_results"]) == 2
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_load_returns_baseline_data(self):
        results = self.make_results()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp = Path(f.name)

        try:
            BaselineManager.save(results, tmp)
            loaded = BaselineManager.load(tmp)
            assert isinstance(loaded, BaselineData)
            assert loaded.score > 0
            assert loaded.grade in ("A+", "A", "B+", "B", "C", "D", "F")
            assert len(loaded.probe_results) == 2
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_load_missing_file_raises(self):
        import pytest

        with pytest.raises(FileNotFoundError):
            BaselineManager.load(Path("nonexistent_baseline.json"))

    def test_compare_no_regression(self):
        results = self.make_results()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp = Path(f.name)

        try:
            BaselineManager.save(results, tmp)
            cr = BaselineManager.compare(results, tmp)
            assert cr.verdict in ("PASS", "IMPROVED")
            assert isinstance(cr.score_diff, float)
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_compare_detects_regression(self):
        baseline_results = [
            ProbeResult(
                probe_name="injection",
                severity="critical",
                passed=True,
                total=20,
                blocked=18,
            ),
        ]
        regressed_results = [
            ProbeResult(
                probe_name="injection",
                severity="critical",
                passed=False,
                total=20,
                blocked=8,
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp = Path(f.name)

        try:
            BaselineManager.save(baseline_results, tmp)
            cr = BaselineManager.compare(regressed_results, tmp)
            assert cr.verdict == "REGRESSION"
            assert len(cr.regressions) >= 1
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_summarize(self):
        results = self.make_results()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp = Path(f.name)

        try:
            BaselineManager.save(results, tmp)
            cr = BaselineManager.compare(results, tmp)
            s = BaselineManager.summarize(cr)
            assert "verdict" in s
            assert "score_diff" in s
            assert "baseline_score" in s
            assert "current_score" in s
        finally:
            if tmp.exists():
                tmp.unlink()
