"""
Shared data models for cascade-scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackVector:
    """A single attack test case."""

    id: str
    """Unique identifier for this vector."""

    name: str
    """Short human-readable name (e.g. ``'xss-script-tag'``)."""

    tool_name: str
    """Name of the tool being invoked in the test."""

    arguments: dict[str, Any]
    """Arguments passed to the tool (may contain the attack payload)."""

    expected_blocked: bool = True
    """Whether cascade **should** block this vector."""

    description: str = ""
    """Optional human-readable explanation."""

    extra_rules: list[dict] | None = None
    """Optional extra guard rules to apply for this vector."""

    confidence: float = 0.9
    """Confidence score for the tool call."""


@dataclass
class ScanConfig:
    """Global scan configuration."""

    min_score: float = 70.0
    """Minimum score to pass (0–100)."""

    pass_threshold: float = 0.8
    """Minimum fraction of vectors that must be blocked per probe."""

    rules: list[dict] | None = None
    """Default rule set for rule-based probes."""

    enable_injection_detection: bool = True
    """Enable cascade's runtime injection detection for all probes."""

    strategy: str = "softmax"
    """Selection strategy: ``softmax``, ``threshold``, ``linear``, ``uniform``."""

    top_k: int = 1
    """Number of top tool calls to select."""


# ── convenience constants ─────────────────────────────────────────

SEVERITY_WEIGHTS: dict[str, float] = {
    "low": 0.5,
    "medium": 1.0,
    "high": 1.5,
    "critical": 2.0,
}
