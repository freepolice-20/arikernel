"""Policy engine: capability check, constraint check, rule evaluation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .taint_tracking import TaintLabel


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


DENY_ALL_RULE: dict[str, Any] = {
    "id": "__builtin_deny_all",
    "name": "Deny All (default)",
    "priority": 999,
    "match": {},
    "decision": "deny",
    "reason": "No matching policy (deny-by-default)",
    "tags": ["builtin"],
}


class PolicyEngine:
    """Evaluates tool calls against capabilities and policy rules."""

    def __init__(self, rules: list[dict[str, Any]] | None = None):
        self._rules: list[dict[str, Any]] = [DENY_ALL_RULE]
        if rules:
            self._rules = rules + self._rules
        self._rules.sort(key=lambda r: r.get("priority", 999))

    @property
    def rules(self) -> list[dict[str, Any]]:
        return list(self._rules)

    def evaluate(
        self,
        tool_call: dict[str, Any],
        taint_labels: list[TaintLabel],
        capabilities: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Evaluate a tool call and return a decision dict."""
        timestamp = _now()
        tool_class = tool_call["toolClass"]
        action = tool_call["action"]
        labels_dicts = [t.to_dict() for t in taint_labels]

        # Step 1: capability check
        capability = next((c for c in capabilities if c["toolClass"] == tool_class), None)
        if capability is None:
            return {
                "verdict": "deny",
                "matchedRule": None,
                "reason": f"No capability grant for tool class: {tool_class}",
                "taintLabels": labels_dicts,
                "timestamp": timestamp,
            }

        # Step 2: action check
        cap_actions = capability.get("actions", [])
        if cap_actions and action not in cap_actions:
            return {
                "verdict": "deny",
                "matchedRule": None,
                "reason": f"Action '{action}' not allowed. Permitted: {', '.join(cap_actions)}",
                "taintLabels": labels_dicts,
                "timestamp": timestamp,
            }

        # Step 3: constraint check
        violation = _check_constraints(tool_call, capability)
        if violation:
            return {
                "verdict": "deny",
                "matchedRule": None,
                "reason": violation,
                "taintLabels": labels_dicts,
                "timestamp": timestamp,
            }

        # Step 4: policy rules (first match wins)
        for rule in self._rules:
            if _matches_rule(rule.get("match", {}), tool_call, taint_labels):
                return {
                    "verdict": rule["decision"],
                    "matchedRule": rule,
                    "reason": rule["reason"],
                    "taintLabels": labels_dicts,
                    "timestamp": timestamp,
                }

        # Step 5: implicit deny
        return {
            "verdict": "deny",
            "matchedRule": None,
            "reason": "No matching policy (deny-by-default)",
            "taintLabels": labels_dicts,
            "timestamp": timestamp,
        }


def _check_constraints(tool_call: dict[str, Any], capability: dict[str, Any]) -> str | None:
    constraints = capability.get("constraints")
    if not constraints:
        return None

    # HTTP host constraints
    if constraints.get("allowedHosts") and tool_call["toolClass"] == "http":
        url = str(tool_call.get("parameters", {}).get("url", ""))
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            return f"Invalid URL: {url}"
        allowed = constraints["allowedHosts"]
        if "*" not in allowed and hostname not in allowed:
            return f"Host '{hostname}' not in allowed hosts: {', '.join(allowed)}"

    # Shell command constraints
    if constraints.get("allowedCommands") and tool_call["toolClass"] == "shell":
        command = str(tool_call.get("parameters", {}).get("command", ""))
        binary = command.split()[0] if command.strip() else ""
        if binary not in constraints["allowedCommands"]:
            return f"Command '{binary}' not in allowed commands: {', '.join(constraints['allowedCommands'])}"

    # File path constraints
    if constraints.get("allowedPaths") and tool_call["toolClass"] == "file":
        path = str(tool_call.get("parameters", {}).get("path", ""))
        allowed = any(_path_matches(pattern, path) for pattern in constraints["allowedPaths"])
        if not allowed:
            return f"Path '{path}' not in allowed paths: {', '.join(constraints['allowedPaths'])}"

    return None


def _path_matches(pattern: str, path: str) -> bool:
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3])
    return path == pattern


def _matches_rule(
    match: dict[str, Any],
    tool_call: dict[str, Any],
    taint_labels: list[TaintLabel],
) -> bool:
    # toolClass
    expected_tc = match.get("toolClass")
    if expected_tc is not None:
        if isinstance(expected_tc, list):
            if tool_call["toolClass"] not in expected_tc:
                return False
        elif tool_call["toolClass"] != expected_tc:
            return False

    # action
    expected_action = match.get("action")
    if expected_action is not None:
        if isinstance(expected_action, list):
            if tool_call["action"] not in expected_action:
                return False
        elif tool_call["action"] != expected_action:
            return False

    # principalId
    expected_principal = match.get("principalId")
    if expected_principal is not None and tool_call.get("principalId") != expected_principal:
        return False

    # taintSources
    expected_taint = match.get("taintSources")
    if expected_taint:
        if not any(
            label.source in expected_taint for label in taint_labels
        ):
            return False

    # parameters (regex/in/notIn matching)
    param_matchers = match.get("parameters")
    if param_matchers:
        params = tool_call.get("parameters", {})
        for key, matcher in param_matchers.items():
            value = str(params.get(key, ""))
            if matcher.get("pattern"):
                if not re.search(matcher["pattern"], value):
                    return False
            if matcher.get("in"):
                if value not in matcher["in"]:
                    return False
            if matcher.get("notIn"):
                if value in matcher["notIn"]:
                    return False

    return True
