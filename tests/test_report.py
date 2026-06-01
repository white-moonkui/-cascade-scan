"""Tests for scan report export."""

import json
from pathlib import Path
from tempfile import mkdtemp

from cascade_scan import export_html, export_json
from cascade_scan.engine import ScanResult
from cascade_scan.probes import ProbeResult


def _sample_result() -> ScanResult:
    return ScanResult(
        score=85.0,
        passed=True,
        score_breakdown={"injection": 90.0, "tool-abuse": 80.0},
        probe_results=[
            ProbeResult(
                probe_name="injection-detection",
                passed=True,
                total=20,
                blocked=18,
                severity="critical",
                details=[
                    {"pattern": "eval", "vector": 'eval("print(1)")', "blocked": True, "injection_detected": True, "correctly_blocked": True},
                    {"pattern": "exec", "vector": 'exec("x=1")', "blocked": True, "injection_detected": True, "correctly_blocked": True},
                ],
            ),
            ProbeResult(
                probe_name="tool-abuse",
                passed=True,
                total=10,
                blocked=8,
                severity="high",
                details=[
                    {"tool": "delete_file", "blocked": True},
                    {"tool": "exec_command", "blocked": True},
                    {"tool": "run_shell", "blocked": False},
                ],
            ),
        ],
    )


class TestExportJSON:
    def test_export_json_content(self):
        result = _sample_result()
        report = export_json(result)
        assert report["scan"]["score"] == 85.0
        assert report["scan"]["passed"] is True
        assert len(report["probes"]) == 2
        assert report["probes"][0]["name"] == "injection-detection"
        assert report["probes"][0]["blocked"] == 18

    def test_export_json_to_file(self):
        tmpdir = Path(mkdtemp())
        out = tmpdir / "scan.json"
        result = _sample_result()
        export_json(result, output=out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["scan"]["score"] == 85.0

    def test_export_json_with_metadata(self):
        result = _sample_result()
        report = export_json(result, metadata={"target": "test-pipeline"})
        assert report["metadata"]["target"] == "test-pipeline"


class TestExportHTML:
    def test_export_html_content(self):
        result = _sample_result()
        html = export_html(result)
        assert "<!DOCTYPE html>" in html
        assert "cascade-scan" in html
        assert "85" in html  # score
        assert "injection-detection" in html
        assert "tool-abuse" in html

    def test_export_html_to_file(self):
        tmpdir = Path(mkdtemp())
        out = tmpdir / "scan.html"
        result = _sample_result()
        export_html(result, output=out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "PASS" in content

    def test_export_html_grade_color(self):
        result = _sample_result()  # score 85 → grade A
        html = export_html(result)
        assert "A" in html
