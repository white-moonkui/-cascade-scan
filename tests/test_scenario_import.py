"""Tests for custom scenario import."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cascade_scan.scenarios.registry import (
    AttackScenario,
    load_scenarios_from_file,
    custom_scenarios_dir,
    get_scenario,
)

VALID_SCENARIOS = {
    "scenarios": [
        {
            "name": "custom-test",
            "description": "A custom test scenario",
            "severity": "critical",
            "expected_blocked": 2,
            "rules": [
                {"field": "name", "op": "nin", "value": ["bad_tool"]},
            ],
            "tool_calls": [
                {"id": "t1", "name": "bad_tool", "arguments": {"target": "x"}, "confidence": 0.9},
                {"id": "t2", "name": "read_file", "arguments": {"path": "/tmp"}, "confidence": 0.8},
            ],
        },
    ],
}


class TestLoadScenariosFromFile:
    def test_load_valid_json(self):
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(VALID_SCENARIOS, f)
            tmp = Path(f.name)

        try:
            loaded = load_scenarios_from_file(tmp)
            assert len(loaded) == 1
            assert loaded[0].name == "custom-test"
            assert loaded[0].severity == "critical"
            assert len(loaded[0].tool_calls) == 2
            assert loaded[0].expected_blocked == 2
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_auto_registers_scenario(self):
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(VALID_SCENARIOS, f)
            tmp = Path(f.name)

        try:
            load_scenarios_from_file(tmp)
            retrieved = get_scenario("custom-test")
            assert retrieved is not None
            assert retrieved.name == "custom-test"
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_scenarios_from_file("nonexistent_scenarios.json")

    def test_missing_name_raises(self):
        bad = {"scenarios": [{"tool_calls": [{"id": "t1"}]}]}
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(bad, f)
            tmp = Path(f.name)

        try:
            with pytest.raises(ValueError, match="missing required field 'name'"):
                load_scenarios_from_file(tmp)
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_missing_tool_calls_raises(self):
        bad = {"scenarios": [{"name": "no-calls"}]}
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(bad, f)
            tmp = Path(f.name)

        try:
            with pytest.raises(ValueError, match="missing required field 'tool_calls'"):
                load_scenarios_from_file(tmp)
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_unsupported_format_raises(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            f.write("a,b,c")
            tmp = Path(f.name)
        try:
            with pytest.raises(ValueError, match="Unsupported file format"):
                load_scenarios_from_file(tmp)
        finally:
            if tmp.exists():
                tmp.unlink()

    def test_yaml_unavailable_raises(self):
        # Mock to ensure yaml is not importable
        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return original_import(name, *args, **kwargs)

        with tempfile.NamedTemporaryFile(
            suffix=".yaml", delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write("scenarios: []")
            tmp = Path(f.name)

        try:
            builtins.__import__ = mock_import
            with pytest.raises(ImportError, match="PyYAML is required"):
                load_scenarios_from_file(tmp)
        finally:
            builtins.__import__ = original_import
            if tmp.exists():
                tmp.unlink()


class TestCustomScenariosDir:
    def test_creates_directory_with_example(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "my_scenarios"
            custom_scenarios_dir(target)
            assert target.is_dir()
            example = target / "example.json"
            assert example.exists()
            content = example.read_text(encoding="utf-8")
            assert "example-scenario" in content
