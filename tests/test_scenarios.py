"""Tests for attack scenario registry."""

from cascade_scan.scenarios import get_scenario, list_scenarios, register_scenario, AttackScenario


class TestScenarioRegistry:
    def test_get_builtin(self):
        sc = get_scenario("file-deletion")
        assert sc is not None
        assert sc.name == "file-deletion"
        assert len(sc.tool_calls) == 4
        assert sc.expected_blocked == 3

    def test_get_case_insensitive(self):
        sc = get_scenario("CODE-EXECUTION")
        assert sc is not None
        assert sc.name == "code-execution"

    def test_get_nonexistent(self):
        assert get_scenario("nonexistent") is None

    def test_list_scenarios(self):
        scenarios = list_scenarios()
        assert len(scenarios) >= 5
        names = [s["name"] for s in scenarios]
        assert "file-deletion" in names
        assert "code-execution" in names
        assert "injection-lite" in names

    def test_register_custom(self):
        custom = AttackScenario(
            name="custom-test",
            description="A custom scenario",
            severity="low",
            tool_calls=[
                {"id": "t1", "name": "test_tool", "arguments": {}, "confidence": 0.5},
            ],
            rules=[],
            expected_blocked=0,
        )
        register_scenario(custom)
        retrieved = get_scenario("custom-test")
        assert retrieved is not None
        assert retrieved.name == "custom-test"
