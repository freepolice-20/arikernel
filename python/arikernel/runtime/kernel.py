"""AriKernel Python runtime — create_kernel() and enforcement classes.

Default mode is sidecar-authoritative: all security decisions and tool execution
are delegated to the TypeScript sidecar process, providing process-boundary
isolation for mediated calls. Python code that bypasses the kernel (direct OS API
calls) is not mediated.

Usage (sidecar — default, production):
    kernel = create_kernel(preset="safe-research")
    # Requires: TypeScript sidecar running at localhost:8787

Usage (local — dev/testing only):
    kernel = create_kernel(preset="safe-research", mode="local")
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .spec_loader import get_preset, get_defaults, get_autoscope_config
from .policy_engine import PolicyEngine
from .taint_tracking import TaintLabel, TaintTracker, merge_labels
from .capability_tokens import CapabilityIssuer, TokenStore
from .run_state import RunStateTracker
from .behavior_rules import evaluate_behavioral_rules, apply_behavioral_rule
from .audit_logger import AuditStore

# We use uuid-based IDs that sort roughly by time (not ULID, but compatible)
try:
    from ulid import ULID
    def _generate_id() -> str:
        return str(ULID())
except ImportError:
    def _generate_id() -> str:
        return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ToolCallDenied(Exception):
    """Raised when the kernel denies a tool call."""

    def __init__(self, reason: str, verdict: str = "deny", rule: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.verdict = verdict
        self.rule = rule


class ApprovalRequiredError(ToolCallDenied):
    """Raised when a tool call requires approval but no handler is registered or approval is denied."""

    def __init__(self, reason: str, rule: str | None = None):
        super().__init__(reason=reason, verdict="require-approval", rule=rule)


class Kernel:
    """Native Python AriKernel runtime.

    Provides the full enforcement pipeline:
    - Capability token issuance
    - Policy evaluation
    - Taint tracking
    - Behavioral sequence detection
    - Run-level quarantine
    - SHA-256 hash-chained audit logging
    """

    def __init__(
        self,
        capabilities: list[dict[str, Any]],
        policies: list[dict[str, Any]],
        preset_name: str = "default",
        auto_scope: bool = False,
        principal: str = "agent",
        audit_log: str | None = None,
        max_denied_sensitive_actions: int = 5,
        behavioral_rules: bool = True,
        on_approval: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
    ):
        self._preset_name = preset_name
        self._auto_scope = auto_scope
        self._capabilities = capabilities
        self._policies = policies
        self._principal = principal
        self._principal_id = _generate_id()

        self._on_approval = on_approval

        # Subsystems
        self._policy_engine = PolicyEngine(policies)
        self._taint_tracker = TaintTracker()
        self._token_store = TokenStore()
        self._issuer = CapabilityIssuer(
            capabilities, self._token_store, _generate_id
        )
        self._run_state = RunStateTracker(
            max_denied_sensitive_actions=max_denied_sensitive_actions,
            behavioral_rules_enabled=behavioral_rules,
        )

        # Audit
        self._audit_store: AuditStore | None = None
        if audit_log:
            self._audit_store = AuditStore(audit_log)

        # Run lifecycle
        self._run_id = _generate_id()
        self._sequence = 0
        self._closed = False

        if self._audit_store:
            self._audit_store.start_run(
                self._run_id,
                self._principal_id,
                {
                    "principal": principal,
                    "preset": preset_name,
                    "capabilities": capabilities,
                    "policies": [p.get("id", "?") for p in policies],
                },
            )

    @property
    def preset(self) -> str:
        return self._preset_name

    @property
    def auto_scope(self) -> bool:
        return self._auto_scope

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def restricted(self) -> bool:
        return self._run_state.restricted

    def select_scope(self, task: str) -> dict[str, Any]:
        """Classify a task and optionally update the kernel preset."""
        from .autoscope import classify_scope

        result = classify_scope(task)
        if self._auto_scope and result["confidence"] > 0:
            preset_data = get_preset(result["preset"])
            self._capabilities = preset_data["capabilities"]
            self._policies = preset_data["policies"]
            self._preset_name = result["preset"]
            self._policy_engine = PolicyEngine(self._policies)
            self._issuer = CapabilityIssuer(
                self._capabilities, self._token_store, _generate_id
            )
        return result

    def request_capability(
        self,
        capability_class: str,
        taint_labels: list[TaintLabel] | None = None,
    ) -> dict[str, Any]:
        """Request a capability token."""
        result = self._issuer.evaluate(
            capability_class, self._principal_id, taint_labels
        )
        granted = result.get("granted", False)
        self._run_state.record_capability_request(granted)

        # Push event to run state
        event_type = "capability_granted" if granted else "capability_denied"
        # Parse tool class from capability class
        tool_class = capability_class.split(".")[0] if "." in capability_class else ""
        self._run_state.push_event({
            "timestamp": _now(),
            "type": event_type,
            "toolClass": tool_class,
        })

        # Check behavioral rules after event push
        if self._run_state.behavioral_rules_enabled:
            match = evaluate_behavioral_rules(self._run_state)
            if match:
                q_info = apply_behavioral_rule(self._run_state, match)
                if q_info and self._audit_store:
                    self._audit_store.append_system_event(
                        _generate_id(),
                        self._run_id,
                        self._principal_id,
                        "quarantine",
                        q_info["reason"],
                        {
                            "triggerType": q_info["triggerType"],
                            "ruleId": q_info.get("ruleId"),
                        },
                        _generate_id(),
                    )

        return result

    def execute_tool(
        self,
        tool_class: str,
        action: str,
        parameters: dict[str, Any] | None = None,
        grant_id: str | None = None,
        taint_labels: list[TaintLabel] | None = None,
        execute_fn: Callable[..., Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool call through the full enforcement pipeline.

        Returns:
            {"verdict": "allow", "result": <tool output>} on success.
            Raises ToolCallDenied on denial.
        """
        if self._closed:
            raise RuntimeError("Kernel session is closed")

        parameters = parameters or {}
        taint_labels = taint_labels or []
        sequence = self._sequence
        self._sequence += 1

        # Build tool call object (matches TS format for audit compatibility)
        tool_call: dict[str, Any] = {
            "id": _generate_id(),
            "runId": self._run_id,
            "sequence": sequence,
            "timestamp": _now(),
            "principalId": self._principal_id,
            "toolClass": tool_class,
            "action": action,
            "parameters": parameters,
            "taintLabels": [t.to_dict() for t in taint_labels],
        }
        if grant_id:
            tool_call["grantId"] = grant_id

        # Step 1: Restricted mode check
        if self._run_state.restricted:
            if not self._run_state.is_allowed_in_restricted_mode(tool_class, action):
                decision = {
                    "verdict": "deny",
                    "matchedRule": None,
                    "reason": "Run is in restricted mode - only safe read-only actions allowed",
                    "taintLabels": [t.to_dict() for t in taint_labels],
                    "timestamp": _now(),
                }
                self._log_event(tool_call, decision)
                raise ToolCallDenied(
                    reason=decision["reason"], verdict="deny"
                )

        # Step 1.5a: Signal tracking
        if taint_labels:
            self._run_state.push_event({
                "timestamp": _now(),
                "type": "taint_observed",
                "toolClass": tool_class,
                "action": action,
                "taintSources": [t.source for t in taint_labels],
            })

        if tool_class == "http" and self._run_state.is_egress_action(action):
            self._run_state.record_egress_attempt()
            self._run_state.push_event({
                "timestamp": _now(),
                "type": "egress_attempt",
                "toolClass": tool_class,
                "action": action,
            })

        if tool_class == "file":
            path = str(parameters.get("path", ""))
            if self._run_state.is_sensitive_path(path):
                self._run_state.record_sensitive_file_attempt()
                self._run_state.push_event({
                    "timestamp": _now(),
                    "type": "sensitive_read_attempt",
                    "toolClass": tool_class,
                    "action": action,
                    "metadata": {"path": path},
                })

        # Step 1.5b: Capability token validation
        if grant_id:
            grant = self._token_store.get(grant_id)
            if not grant or not grant.consume():
                decision = {
                    "verdict": "deny",
                    "matchedRule": None,
                    "reason": "Invalid or exhausted capability token",
                    "taintLabels": [t.to_dict() for t in taint_labels],
                    "timestamp": _now(),
                }
                self._run_state.record_denied_action()
                self._log_event(tool_call, decision)
                raise ToolCallDenied(reason=decision["reason"])

        # Step 3: Evaluate policy
        decision = self._policy_engine.evaluate(
            tool_call, taint_labels, self._capabilities
        )

        # Step 3.5: Enforce decision
        if decision["verdict"] == "deny":
            self._run_state.record_denied_action()
            self._run_state.push_event({
                "timestamp": _now(),
                "type": "tool_call_denied",
                "toolClass": tool_class,
                "action": action,
                "verdict": "deny",
            })
            self._check_behavioral_rules()
            self._log_event(tool_call, decision)
            raise ToolCallDenied(
                reason=decision["reason"],
                verdict="deny",
                rule=decision["matchedRule"]["id"] if decision.get("matchedRule") else None,
            )

        if decision["verdict"] == "require-approval":
            # Fail closed: if no approval handler is registered, deny.
            # This matches TypeScript pipeline.ts behavior exactly.
            if self._on_approval is None:
                import warnings
                warnings.warn(
                    f"[arikernel] Policy returned 'require-approval' for "
                    f"{tool_class}.{action} but no on_approval handler is "
                    f"registered. Action will be denied by default. Register "
                    f"an on_approval callback to handle approval requests.",
                    stacklevel=2,
                )
                denied_decision = {
                    "verdict": "deny",
                    "matchedRule": decision.get("matchedRule"),
                    "reason": f"require-approval denied: no approval handler registered for {tool_class}.{action}",
                    "taintLabels": decision.get("taintLabels", []),
                    "timestamp": _now(),
                }
                self._run_state.record_denied_action()
                self._log_event(tool_call, denied_decision)
                raise ApprovalRequiredError(
                    reason=denied_decision["reason"],
                    rule=decision["matchedRule"]["id"] if decision.get("matchedRule") else None,
                )

            approved = self._on_approval(tool_call, decision)
            if not approved:
                denied_decision = {
                    "verdict": "deny",
                    "matchedRule": decision.get("matchedRule"),
                    "reason": f"require-approval denied by handler for {tool_class}.{action}",
                    "taintLabels": decision.get("taintLabels", []),
                    "timestamp": _now(),
                }
                self._run_state.record_denied_action()
                self._log_event(tool_call, denied_decision)
                raise ApprovalRequiredError(
                    reason=denied_decision["reason"],
                    rule=decision["matchedRule"]["id"] if decision.get("matchedRule") else None,
                )

        # Step 4: Execute tool
        result_data = None
        duration_ms = 0
        tool_result = None

        if execute_fn:
            start = time.monotonic()
            try:
                result_data = execute_fn(**parameters)
                duration_ms = int((time.monotonic() - start) * 1000)
                tool_result = {
                    "callId": tool_call["id"],
                    "success": True,
                    "data": result_data,
                    "taintLabels": [],
                    "durationMs": duration_ms,
                }
            except Exception as e:
                duration_ms = int((time.monotonic() - start) * 1000)
                tool_result = {
                    "callId": tool_call["id"],
                    "success": False,
                    "error": str(e),
                    "taintLabels": [],
                    "durationMs": duration_ms,
                }

        # Step 5: Propagate taint
        output_labels = self._taint_tracker.propagate(taint_labels, tool_call["id"])

        # Step 6: Push execution event
        self._run_state.push_event({
            "timestamp": _now(),
            "type": "tool_call_allowed",
            "toolClass": tool_class,
            "action": action,
            "verdict": "allow",
        })

        # Step 7: Check behavioral rules
        self._check_behavioral_rules()

        # Step 8: Audit log
        self._log_event(tool_call, decision, tool_result)

        return {
            "verdict": decision["verdict"],
            "result": result_data,
            "duration_ms": duration_ms,
        }

    def _check_behavioral_rules(self) -> None:
        if not self._run_state.behavioral_rules_enabled:
            return
        match = evaluate_behavioral_rules(self._run_state)
        if match:
            q_info = apply_behavioral_rule(self._run_state, match)
            if q_info and self._audit_store:
                self._audit_store.append_system_event(
                    _generate_id(),
                    self._run_id,
                    self._principal_id,
                    "quarantine",
                    q_info["reason"],
                    {
                        "triggerType": q_info["triggerType"],
                        "ruleId": q_info.get("ruleId"),
                    },
                    _generate_id(),
                )

    def _log_event(
        self,
        tool_call: dict[str, Any],
        decision: dict[str, Any],
        result: dict[str, Any] | None = None,
    ) -> None:
        if self._audit_store:
            self._audit_store.append(
                _generate_id(), tool_call, decision, result
            )

    def close(self) -> None:
        """End the run and close resources."""
        if self._closed:
            return
        self._closed = True
        if self._audit_store:
            self._audit_store.end_run(self._run_id)
            self._audit_store.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def create_kernel(
    preset: str | None = None,
    auto_scope: bool = False,
    allow: dict[str, Any] | None = None,
    principal: str = "agent",
    audit_log: str | None = None,
    max_denied_sensitive_actions: int = 5,
    behavioral_rules: bool = True,
    on_approval: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
    *,
    mode: str = "sidecar",
    sidecar_url: str = "http://localhost:8787",
) -> "Kernel | Any":
    """Create a new AriKernel instance.

    By default, creates a sidecar-authoritative kernel that delegates all
    security decisions and tool execution to the TypeScript sidecar process.
    This provides process-boundary isolation for mediated calls — Python code
    that bypasses the kernel (direct OS API calls) is not mediated.

    Args:
        preset: Named preset (safe-research, rag-reader, workspace-assistant, etc.)
        auto_scope: Enable AutoScope (keyword-based task-to-preset classifier)
        allow: Custom allow overrides dict
        principal: Principal name
        audit_log: Path to SQLite audit log (only used in local mode)
        max_denied_sensitive_actions: Threshold for quarantine (only used in local mode)
        behavioral_rules: Enable behavioral sequence rules (only used in local mode)
        on_approval: Callback for require-approval verdicts
        mode: "sidecar" (default, recommended) or "local" (dev/testing only).
              Sidecar mode requires the TypeScript server to be running.
        sidecar_url: URL of the TypeScript sidecar (default: http://localhost:8787)

    Returns:
        Kernel instance (SidecarKernel or local Kernel) ready for tool protection.
    """
    # Resolve capabilities for sidecar mode
    if allow:
        caps, pols = _allow_to_config(allow)
        preset_name = "custom"
    elif preset:
        data = get_preset(preset)
        caps = data["capabilities"]
        pols = data["policies"]
        preset_name = preset
    else:
        data = get_defaults()
        caps = data["capabilities"]
        pols = data["policies"]
        preset_name = "default"

    if mode == "sidecar":
        from ..sidecar import SidecarKernel
        return SidecarKernel(
            url=sidecar_url,
            principal=principal,
            capabilities=caps,
            preset_name=preset_name,
            on_approval=on_approval,
        )

    if mode != "local":
        raise ValueError(
            f'Invalid mode: {mode!r}. Use "sidecar" (default) or "local" (dev/testing only).'
        )

    import warnings
    warnings.warn(
        "[arikernel] Using local enforcement mode. This is intended for "
        "development and testing only. In production, use mode='sidecar' "
        "to delegate security decisions and tool execution to the TypeScript "
        "sidecar, which provides process-boundary isolation for mediated calls.",
        stacklevel=2,
    )

    return Kernel(
        capabilities=caps,
        policies=pols,
        preset_name=preset_name,
        auto_scope=auto_scope,
        principal=principal,
        audit_log=audit_log,
        max_denied_sensitive_actions=max_denied_sensitive_actions,
        behavioral_rules=behavioral_rules,
        on_approval=on_approval,
    )


def _allow_to_config(allow: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    """Convert allow overrides to capabilities and policies."""
    capabilities: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []

    if allow.get("http_get", True):
        capabilities.append({
            "toolClass": "http",
            "actions": ["get"],
            "constraints": {"allowedHosts": ["*"]},
        })
        policies.append({
            "id": "allow-http-get",
            "name": "Allow HTTP GET",
            "priority": 100,
            "match": {"toolClass": "http", "action": "get"},
            "decision": "allow",
            "reason": "HTTP GET allowed",
        })

    if allow.get("http_post"):
        capabilities.append({
            "toolClass": "http",
            "actions": ["post"],
            "constraints": {"allowedHosts": ["*"]},
        })
        policies.append({
            "id": "allow-http-post",
            "name": "Allow HTTP POST",
            "priority": 100,
            "match": {"toolClass": "http", "action": "post"},
            "decision": "allow",
            "reason": "HTTP POST allowed",
        })
    else:
        policies.append({
            "id": "deny-http-write",
            "name": "Deny HTTP writes",
            "priority": 20,
            "match": {"toolClass": "http", "action": ["post", "put", "patch", "delete"]},
            "decision": "deny",
            "reason": "Outbound HTTP writes are blocked",
        })

    file_read = allow.get("file_read", True)
    if file_read is not False:
        paths = file_read if isinstance(file_read, list) else ["./data/**", "./docs/**", "./workspace/**"]
        capabilities.append({
            "toolClass": "file",
            "actions": ["read"],
            "constraints": {"allowedPaths": paths},
        })
        policies.append({
            "id": "allow-file-read",
            "name": "Allow file reads",
            "priority": 100,
            "match": {"toolClass": "file", "action": "read"},
            "decision": "allow",
            "reason": "File reads allowed",
        })

    if allow.get("file_write"):
        paths = allow["file_write"] if isinstance(allow["file_write"], list) else ["./**"]
        capabilities.append({
            "toolClass": "file",
            "actions": ["write"],
            "constraints": {"allowedPaths": paths},
        })
        policies.append({
            "id": "allow-file-write",
            "name": "Allow file writes",
            "priority": 100,
            "match": {"toolClass": "file", "action": "write"},
            "decision": "allow",
            "reason": "File writes allowed",
        })
    else:
        policies.append({
            "id": "deny-file-write",
            "name": "Deny file writes",
            "priority": 20,
            "match": {"toolClass": "file", "action": "write"},
            "decision": "deny",
            "reason": "File writes are blocked",
        })

    if allow.get("shell"):
        capabilities.append({"toolClass": "shell", "actions": ["exec"]})
        policies.append({
            "id": "approve-shell",
            "name": "Shell requires approval",
            "priority": 50,
            "match": {"toolClass": "shell"},
            "decision": "require-approval",
            "reason": "Shell commands require approval",
        })
    else:
        policies.append({
            "id": "deny-shell",
            "name": "Deny shell",
            "priority": 10,
            "match": {"toolClass": "shell"},
            "decision": "deny",
            "reason": "Shell execution is blocked",
        })

    if allow.get("database"):
        capabilities.append({"toolClass": "database", "actions": ["query"]})
        policies.append({
            "id": "allow-db-query",
            "name": "Allow DB queries",
            "priority": 100,
            "match": {"toolClass": "database", "action": "query"},
            "decision": "allow",
            "reason": "Database queries allowed",
        })

    return capabilities, policies
