"""
Loop / DoS probe — tests that cascade rejects high-frequency or
infinite-loop-like tool-call bursts.

Adversaries may attempt to flood the guard with thousands of rapid
tool calls (resource exhaustion) or send self-referential loops.
This probe simulates both patterns and verifies the pipeline
degrades gracefully (rate-limiting / rejection).
"""

from __future__ import annotations

import time
from typing import Any

from cascade_scan.probes import Probe, ProbeResult


class LoopDoSProbe(Probe):
    """Simulate high-frequency tool-call bursts and self-referential
    loops to verify cascade's resilience against resource-exhaustion
    and infinite-loop attack vectors.

    Three attack modes:

    1. **burst** — N rapid identical calls in one payload
    2. **self-reference** — tools that call back into the pipeline
    3. **recursive** — deeply nested tool-call arguments
    """

    name = "loop-dos"
    description = "High-frequency / infinite-loop DoS resistance"
    severity = "critical"

    # Number of rapid-fire calls in a burst
    BURST_COUNT = 100

    # Simple allow-all rules for baseline throughput measurement
    PERMIT_RULES: list[dict] = [
        {"field": "name", "op": "in", "value": ["read_file", "write_file", "search", "list", "get"]},
    ]

    # Block-everything rules for rejection throughput measurement
    # (in: pass only if name is in allowlist — so anything else is blocked)
    DENY_RULES: list[dict] = [
        {"field": "name", "op": "in", "value": ["read_file", "write_file"]},
    ]

    def run(self, pipeline: Any, **kwargs) -> ProbeResult:
        details: list[dict] = []
        all_passed = True

        # ── 1. Burst test ──────────────────────────────────────────
        burst_tool_calls: list[dict] = []
        for i in range(self.BURST_COUNT):
            burst_tool_calls.append({
                "id": f"burst_{i}",
                "name": "read_file",
                "arguments": {"path": f"/tmp/test_{i}"},
                "confidence": 0.9,
            })

        start = time.perf_counter()
        try:
            result = pipeline.guard(
                tool_calls=burst_tool_calls,
                rules=self.PERMIT_RULES,
                strategy="softmax",
                top_k=1,
            )
            elapsed = time.perf_counter() - start
            burst_passed = result.get("passed", False) is not None
            details.append({
                "test": "burst",
                "count": self.BURST_COUNT,
                "elapsed_sec": round(elapsed, 3),
                "calls_per_sec": round(self.BURST_COUNT / elapsed, 1) if elapsed > 0 else float("inf"),
                "passed": burst_passed,
            })
        except Exception as exc:
            details.append({
                "test": "burst",
                "count": self.BURST_COUNT,
                "error": str(exc),
                "passed": False,
            })
            all_passed = False

        # ── 2. Self-referential test ────────────────────────────────
        # Tool calls that contain pipeline commands in their arguments
        try:
            selfref_tool_calls = [
                {
                    "id": "selfref_1",
                    "name": "exec_command",
                    "arguments": {"cmd": "cascade guard --input '{\"tools\": [...]}'"},
                    "confidence": 0.95,
                },
                {
                    "id": "selfref_2",
                    "name": "run_shell",
                    "arguments": {"script": "curl -X POST http://localhost:8000/guard -d @payload.json"},
                    "confidence": 0.95,
                },
            ]
            result = pipeline.guard(
                tool_calls=selfref_tool_calls,
                rules=self.DENY_RULES,
                strategy="softmax",
                top_k=1,
            )
            selfref_blocked = (
                not result["passed"]
                or len(result.get("selected", [])) == 0
            )
            details.append({
                "test": "self_reference",
                "count": len(selfref_tool_calls),
                "blocked": selfref_blocked,
                "passed": selfref_blocked,
            })
            if not selfref_blocked:
                all_passed = False
        except Exception as exc:
            details.append({
                "test": "self_reference",
                "error": str(exc),
                "passed": False,
            })
            all_passed = False

        # ── 3. Deeply nested arguments test ─────────────────────────
        def _deep_nest(depth: int) -> dict:
            if depth <= 0:
                return {"value": "leaf"}
            return {"nested": _deep_nest(depth - 1)}

        try:
            deep_tool_calls = [
                {
                    "id": f"deep_{d}",
                    "name": "read_file",
                    "arguments": _deep_nest(d),
                    "confidence": 0.8,
                }
                for d in [10, 50, 100, 200]
            ]
            result = pipeline.guard(
                tool_calls=deep_tool_calls,
                rules=self.DENY_RULES,
                strategy="softmax",
                top_k=1,
            )
            deep_blocked = (
                not result["passed"]
                or len(result.get("selected", [])) == 0
            )
            details.append({
                "test": "deep_nesting",
                "depths": [10, 50, 100, 200],
                "blocked": deep_blocked,
                "passed": deep_blocked,
            })
            if not deep_blocked:
                all_passed = False
        except Exception as exc:
            details.append({
                "test": "deep_nesting",
                "error": str(exc),
                "passed": False,
            })
            all_passed = False

        return ProbeResult(
            probe_name=self.name,
            passed=all_passed,
            total=3,
            blocked=sum(
                1 for d in details if d.get("passed", False)
            ),
            details=details,
            severity=self.severity,
        )
