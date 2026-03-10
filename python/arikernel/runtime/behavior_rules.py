"""Behavioral sequence rules for run-state enforcement.

Six explicit rules that detect suspicious multi-step patterns
in the recent-event window and trigger immediate quarantine.
"""

from __future__ import annotations

import re
from typing import Any

from .spec_loader import get_behavioral_rules_config


_config: dict[str, Any] | None = None


def _get_config() -> dict[str, Any]:
    global _config
    if _config is None:
        _config = get_behavioral_rules_config()
    return _config


def evaluate_behavioral_rules(state: Any) -> dict[str, Any] | None:
    """Evaluate all behavioral sequence rules against the recent-event window.

    Args:
        state: RunStateTracker instance

    Returns:
        Match dict with ruleId, reason, matchedEvents — or None if no match.
    """
    if state.restricted:
        return None

    events = state.recent_events
    if len(events) < 2:
        return None

    return (
        _check_web_taint_sensitive_probe(events)
        or _check_denied_capability_then_escalation(events)
        or _check_sensitive_read_then_egress(events)
        or _check_tainted_database_write(events)
        or _check_tainted_shell_with_data(events)
        or _check_secret_access_then_any_egress(events)
    )


def apply_behavioral_rule(state: Any, match: dict[str, Any]) -> dict[str, Any] | None:
    """Apply a behavioral rule match to quarantine the run."""
    return state.quarantine_by_rule(
        match["ruleId"], match["reason"], match["matchedEvents"]
    )


# ── Rule 1: web_taint_sensitive_probe ──────────────────────────────

def _check_web_taint_sensitive_probe(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["web_taint_sensitive_probe"]
    taint_sources = set(rule_cfg["taintSources"])

    taint_event = _find_recent(
        events,
        lambda e: (
            e["type"] == "taint_observed"
            and any(s in taint_sources for s in (e.get("taintSources") or []))
        ),
    )
    if taint_event is None:
        return None

    taint_idx = events.index(taint_event)

    dangerous = _find_after(
        events,
        taint_idx,
        lambda e: (
            e["type"] == "sensitive_read_attempt"
            or (e["type"] == "tool_call_denied" and e.get("toolClass") == "shell")
            or (e["type"] == "tool_call_allowed" and e.get("toolClass") == "shell")
            or e["type"] == "egress_attempt"
        ),
    )
    if dangerous is None:
        return None

    tc = dangerous.get("toolClass", "")
    action = dangerous.get("action", "*")
    action_desc = f"{tc}.{action}" if tc else dangerous["type"]

    return {
        "ruleId": "web_taint_sensitive_probe",
        "reason": f"Untrusted web input was followed by {action_desc} attempt",
        "matchedEvents": [taint_event, dangerous],
    }


# ── Rule 2: denied_capability_then_escalation ──────────────────────

def _check_denied_capability_then_escalation(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["denied_capability_then_escalation"]
    risk_map: dict[str, int] = rule_cfg["toolClassRisk"]
    dangerous_classes = set(rule_cfg["dangerousClasses"])

    denied = _find_recent(events, lambda e: e["type"] == "capability_denied")
    if denied is None:
        return None

    denied_idx = events.index(denied)
    denied_risk = risk_map.get(denied.get("toolClass", ""), 0)

    escalation = _find_after(
        events,
        denied_idx,
        lambda e: (
            e["type"] in ("capability_requested", "capability_granted")
            and (
                risk_map.get(e.get("toolClass", ""), 0) > denied_risk
                or e.get("toolClass", "") in dangerous_classes
            )
        ),
    )
    if escalation is None:
        return None

    return {
        "ruleId": "denied_capability_then_escalation",
        "reason": (
            f"Denied {denied.get('toolClass', 'unknown')} capability was followed by "
            f"escalation to {escalation.get('toolClass', 'unknown')}"
        ),
        "matchedEvents": [denied, escalation],
    }


# ── Rule 3: sensitive_read_then_egress ─────────────────────────────

def _check_sensitive_read_then_egress(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["sensitive_read_then_egress"]

    sensitive_read = _find_recent(
        events,
        lambda e: e["type"] in ("sensitive_read_attempt", "sensitive_read_allowed"),
    )
    if sensitive_read is None:
        return None

    read_idx = events.index(sensitive_read)
    egress = _find_after(events, read_idx, lambda e: e["type"] == "egress_attempt")
    if egress is None:
        return None

    path = (sensitive_read.get("metadata") or {}).get("path", "sensitive file")

    return {
        "ruleId": "sensitive_read_then_egress",
        "reason": f"Read of {path} was followed by outbound {egress.get('action', 'write')} attempt",
        "matchedEvents": [sensitive_read, egress],
    }


# ── Rule 4: tainted_database_write ─────────────────────────────────

def _check_tainted_database_write(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["tainted_database_write"]
    taint_sources = set(rule_cfg["taintSources"])
    db_write_actions = set(rule_cfg["dbWriteActions"])

    taint_event = _find_recent(
        events,
        lambda e: (
            e["type"] == "taint_observed"
            and any(s in taint_sources for s in (e.get("taintSources") or []))
        ),
    )
    if taint_event is None:
        return None

    taint_idx = events.index(taint_event)

    db_write = _find_after(
        events,
        taint_idx,
        lambda e: (
            e.get("toolClass") == "database"
            and e.get("action", "") in db_write_actions
        ),
    )
    if db_write is None:
        return None

    return {
        "ruleId": "tainted_database_write",
        "reason": f"Untrusted input was followed by database {db_write.get('action')} attempt",
        "matchedEvents": [taint_event, db_write],
    }


# ── Rule 5: tainted_shell_with_data ────────────────────────────────

def _check_tainted_shell_with_data(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["tainted_shell_with_data"]
    taint_sources = set(rule_cfg["taintSources"])
    cmd_length_threshold = rule_cfg["shellDataCmdLength"]

    taint_event = _find_recent(
        events,
        lambda e: (
            e["type"] == "taint_observed"
            and any(s in taint_sources for s in (e.get("taintSources") or []))
        ),
    )
    if taint_event is None:
        return None

    taint_idx = events.index(taint_event)

    shell_with_data = _find_after(
        events,
        taint_idx,
        lambda e: (
            e.get("toolClass") == "shell"
            and (e.get("metadata") or {}).get("commandLength", 0) > cmd_length_threshold
        ),
    )
    if shell_with_data is None:
        return None

    cmd_len = (shell_with_data.get("metadata") or {}).get("commandLength", "?")

    return {
        "ruleId": "tainted_shell_with_data",
        "reason": f"Untrusted input was followed by shell exec with long command ({cmd_len} chars)",
        "matchedEvents": [taint_event, shell_with_data],
    }


# ── Rule 6: secret_access_then_any_egress ──────────────────────────

def _check_secret_access_then_any_egress(events: list[dict]) -> dict[str, Any] | None:
    config = _get_config()
    rule_cfg = config["secret_access_then_any_egress"]
    secrets_db_re = re.compile(rule_cfg["secretsDbPattern"], re.IGNORECASE)
    secrets_url_re = re.compile(rule_cfg["secretsUrlPattern"], re.IGNORECASE)

    def _is_secret_access(e: dict) -> bool:
        if e.get("toolClass") == "database" and e.get("action") == "query":
            query = (e.get("metadata") or {}).get("query", "")
            return bool(secrets_db_re.search(query))
        if e.get("toolClass") == "http" and e.get("action") in ("get", "head"):
            url = (e.get("metadata") or {}).get("url", "")
            return bool(secrets_url_re.search(url))
        return False

    secret_access = _find_recent(events, _is_secret_access)
    if secret_access is None:
        return None

    access_idx = events.index(secret_access)
    egress = _find_after(events, access_idx, lambda e: e["type"] == "egress_attempt")
    if egress is None:
        return None

    if secret_access.get("toolClass") == "database":
        resource = "database query"
    else:
        url = (secret_access.get("metadata") or {}).get("url", "unknown")
        resource = f"HTTP {secret_access.get('action')} to {url}"

    return {
        "ruleId": "secret_access_then_any_egress",
        "reason": f"{resource} accessing secrets was followed by {egress.get('action', 'egress')} attempt",
        "matchedEvents": [secret_access, egress],
    }


# ── Helpers ────────────────────────────────────────────────────────

def _find_recent(events: list[dict], predicate) -> dict | None:
    for i in range(len(events) - 1, -1, -1):
        if predicate(events[i]):
            return events[i]
    return None


def _find_after(events: list[dict], after_index: int, predicate) -> dict | None:
    for i in range(after_index + 1, len(events)):
        if predicate(events[i]):
            return events[i]
    return None
