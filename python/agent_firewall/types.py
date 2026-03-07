"""Types for the Agent Firewall Python client."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaintLabel:
    """Data provenance label attached to a tool call."""

    source: str
    origin: str
    confidence: float = 1.0


@dataclass
class Grant:
    """A capability token issued by the firewall."""

    granted: bool
    grant_id: str | None
    reason: str
    expires_at: str | None = None
    max_calls: int | None = None
    constraints: dict[str, Any] | None = None


@dataclass
class ExecuteResult:
    """Result of a tool call decision check that was allowed."""

    verdict: str
    success: bool
    data: Any = None
    duration_ms: float | None = None


class ToolCallDenied(Exception):
    """Raised when the firewall denies a tool call."""

    def __init__(self, reason: str, verdict: str = "deny", rule: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.verdict = verdict
        self.rule = rule
