"""Run-level state tracker for stateful enforcement.

Tracks cumulative behavior counters and a recent-event window
across an entire agent run. When thresholds are exceeded or
behavioral sequence rules match, the run enters "restricted mode".
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .spec_loader import get_constants, get_behavioral_rules_config


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunStateTracker:
    def __init__(
        self,
        max_denied_sensitive_actions: int = 5,
        behavioral_rules_enabled: bool = True,
    ):
        constants = get_constants()
        self._max_window = constants.get("maxEventWindow", 20)
        self._threshold = max_denied_sensitive_actions
        self.behavioral_rules_enabled = behavioral_rules_enabled

        self.counters = {
            "deniedActions": 0,
            "capabilityRequests": 0,
            "deniedCapabilityRequests": 0,
            "externalEgressAttempts": 0,
            "sensitiveFileReadAttempts": 0,
        }

        self._event_window: list[dict[str, Any]] = []
        self._restricted = False
        self._restricted_at: str | None = None
        self._quarantine_info: dict[str, Any] | None = None

        # Load sensitive path patterns from spec
        config = get_behavioral_rules_config()
        patterns = config["sensitive_read_then_egress"]["sensitivePathPatterns"]
        self._sensitive_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]

        # Load safe readonly actions from spec
        safe_actions = constants.get("safeReadonlyActions", {})
        self._safe_readonly: dict[str, set[str]] = {
            k: set(v) for k, v in safe_actions.items()
        }

        # Egress actions
        egress_cfg = config["sensitive_read_then_egress"]["egressActions"]
        self._egress_actions = set(egress_cfg)

    @property
    def restricted(self) -> bool:
        return self._restricted

    @property
    def restricted_at(self) -> str | None:
        return self._restricted_at

    @property
    def quarantine_info(self) -> dict[str, Any] | None:
        return self._quarantine_info

    @property
    def recent_events(self) -> list[dict[str, Any]]:
        return list(self._event_window)

    def is_allowed_in_restricted_mode(self, tool_class: str, action: str) -> bool:
        safe = self._safe_readonly.get(tool_class)
        return action in safe if safe else False

    def push_event(self, event: dict[str, Any]) -> None:
        self._event_window.append(event)
        if len(self._event_window) > self._max_window:
            self._event_window.pop(0)

    def quarantine_by_rule(
        self,
        rule_id: str,
        reason: str,
        matched_events: list[dict],
    ) -> dict[str, Any] | None:
        if self._restricted:
            return None
        ts = _now()
        info: dict[str, Any] = {
            "triggerType": "behavioral_rule",
            "ruleId": rule_id,
            "reason": reason,
            "countersSnapshot": dict(self.counters),
            "matchedEvents": matched_events,
            "timestamp": ts,
        }
        self._restricted = True
        self._restricted_at = ts
        self._quarantine_info = info
        self.push_event({
            "timestamp": ts,
            "type": "quarantine_entered",
            "metadata": {"ruleId": rule_id, "reason": reason},
        })
        return info

    def record_denied_action(self) -> None:
        self.counters["deniedActions"] += 1
        self._check_threshold()

    def record_capability_request(self, granted: bool) -> None:
        self.counters["capabilityRequests"] += 1
        if not granted:
            self.counters["deniedCapabilityRequests"] += 1

    def record_egress_attempt(self) -> None:
        self.counters["externalEgressAttempts"] += 1

    def record_sensitive_file_attempt(self) -> None:
        self.counters["sensitiveFileReadAttempts"] += 1

    def is_sensitive_path(self, path: str) -> bool:
        return any(p.search(path) for p in self._sensitive_patterns)

    def is_egress_action(self, action: str) -> bool:
        return action in self._egress_actions

    def _check_threshold(self) -> None:
        if self._restricted:
            return
        if self.counters["deniedActions"] >= self._threshold:
            ts = _now()
            self._restricted = True
            self._restricted_at = ts
            denied = self.counters["deniedActions"]
            self._quarantine_info = {
                "triggerType": "threshold",
                "reason": f"Denied actions ({denied}) exceeded threshold ({self._threshold})",
                "countersSnapshot": dict(self.counters),
                "timestamp": ts,
            }
            self.push_event({
                "timestamp": ts,
                "type": "quarantine_entered",
                "metadata": {"triggerType": "threshold"},
            })
