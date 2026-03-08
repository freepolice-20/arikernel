"""Capability token issuance, storage, and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from .spec_loader import get_capability_classes, get_constants
from .taint_tracking import TaintLabel


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


_CAPABILITY_CLASSES: dict[str, dict[str, Any]] | None = None


def _get_cap_classes() -> dict[str, dict[str, Any]]:
    global _CAPABILITY_CLASSES
    if _CAPABILITY_CLASSES is None:
        _CAPABILITY_CLASSES = get_capability_classes()
    return _CAPABILITY_CLASSES


UNTRUSTED_SOURCES = {"web", "rag", "email", "retrieved-doc"}
TAINT_BLOCKED_CLASSES = {"shell.exec", "database.write", "file.write", "database.read"}


@dataclass
class CapabilityGrant:
    grant_id: str
    principal_id: str
    capability_class: str
    tool_class: str
    actions: list[str]
    constraints: dict[str, Any] | None
    expires_at: str
    max_calls: int
    calls_used: int = 0
    revoked: bool = False

    @property
    def granted(self) -> bool:
        return True

    def is_valid(self) -> bool:
        if self.revoked:
            return False
        if self.calls_used >= self.max_calls:
            return False
        now = _now_dt()
        try:
            expires = datetime.fromisoformat(self.expires_at)
            if now > expires:
                return False
        except ValueError:
            return False
        return True

    def consume(self) -> bool:
        if not self.is_valid():
            return False
        self.calls_used += 1
        return True


class TokenStore:
    """In-memory store for capability grants."""

    def __init__(self):
        self._grants: dict[str, CapabilityGrant] = {}

    def store(self, grant: CapabilityGrant) -> None:
        self._grants[grant.grant_id] = grant

    def validate(self, grant_id: str) -> bool:
        grant = self._grants.get(grant_id)
        if grant is None:
            return False
        return grant.is_valid()

    def consume(self, grant_id: str) -> bool:
        grant = self._grants.get(grant_id)
        if grant is None:
            return False
        return grant.consume()

    def revoke(self, grant_id: str) -> None:
        grant = self._grants.get(grant_id)
        if grant:
            grant.revoked = True

    def get(self, grant_id: str) -> CapabilityGrant | None:
        return self._grants.get(grant_id)

    def active_grants(self, principal_id: str) -> list[CapabilityGrant]:
        return [
            g for g in self._grants.values()
            if g.principal_id == principal_id and g.is_valid()
        ]


class CapabilityIssuer:
    """Issues capability tokens based on base capabilities and taint state."""

    def __init__(
        self,
        capabilities: list[dict[str, Any]],
        token_store: TokenStore,
        generate_id: Any,
    ):
        self._capabilities = capabilities
        self._token_store = token_store
        self._generate_id = generate_id
        constants = get_constants()
        self._ttl_ms = constants.get("capabilityLeaseTtlMs", 300000)
        self._max_calls = constants.get("capabilityMaxCalls", 10)

    def evaluate(
        self,
        capability_class: str,
        principal_id: str,
        taint_labels: list[TaintLabel] | None = None,
    ) -> dict[str, Any]:
        """Evaluate a capability request. Returns grant info dict."""
        taint_labels = taint_labels or []

        cap_classes = _get_cap_classes()
        cap_def = cap_classes.get(capability_class)
        if cap_def is None:
            return {
                "granted": False,
                "grant_id": None,
                "reason": f"Unknown capability class: {capability_class}",
            }

        tool_class = cap_def["toolClass"]
        actions = cap_def["actions"]

        # Check base capability
        base_cap = next(
            (c for c in self._capabilities if c["toolClass"] == tool_class),
            None,
        )
        if base_cap is None:
            return {
                "granted": False,
                "grant_id": None,
                "reason": f"No base capability for tool class: {tool_class}",
            }

        # Check at least one action overlaps
        base_actions = base_cap.get("actions", [])
        if base_actions:
            overlap = [a for a in actions if a in base_actions]
            if not overlap:
                return {
                    "granted": False,
                    "grant_id": None,
                    "reason": f"Actions {actions} not covered by base capability actions: {base_actions}",
                }

        # Taint risk check
        if capability_class in TAINT_BLOCKED_CLASSES and taint_labels:
            untrusted = [t for t in taint_labels if t.source in UNTRUSTED_SOURCES]
            if untrusted:
                sources = ", ".join(t.source for t in untrusted)
                return {
                    "granted": False,
                    "grant_id": None,
                    "reason": f"Capability denied: untrusted taint [{sources}] in provenance chain",
                }

        # Issue grant
        grant_id = self._generate_id()
        expires_at_dt = _now_dt() + timedelta(milliseconds=self._ttl_ms)
        expires_at = expires_at_dt.isoformat()

        grant = CapabilityGrant(
            grant_id=grant_id,
            principal_id=principal_id,
            capability_class=capability_class,
            tool_class=tool_class,
            actions=actions,
            constraints=base_cap.get("constraints"),
            expires_at=expires_at,
            max_calls=self._max_calls,
        )
        self._token_store.store(grant)

        return {
            "granted": True,
            "grant_id": grant_id,
            "reason": f"Capability {capability_class} granted",
            "expires_at": expires_at,
            "max_calls": self._max_calls,
            "constraints": base_cap.get("constraints"),
        }
