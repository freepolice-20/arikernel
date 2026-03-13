"""Sidecar-authoritative kernel — delegates ALL security decisions to the TypeScript sidecar.

This is the primary enforcement mode for Python. The TypeScript sidecar runs as a
separate process on port 8787, providing process-boundary isolation that cannot be
bypassed by the Python runtime. This eliminates the "weaker runtime" problem
identified in security reviews: Python code physically cannot skip or alter
enforcement logic because it lives in a different process.

The sidecar manages per-principal firewalls automatically. No session management
is needed — the Python client sends principalId with each request and the sidecar
creates/reuses firewalls as needed.

API endpoints used:
    POST /execute           — tool execution with full policy enforcement
    POST /request-capability — request capability grants
    POST /status            — query principal quarantine state
    GET  /health            — liveness check

Usage:
    from arikernel import create_kernel

    kernel = create_kernel(preset="safe-research")
    # → connects to TypeScript sidecar at localhost:8787

    kernel.execute_tool("file", "read", {"path": "./data/report.csv"})
"""

from __future__ import annotations

import warnings
from typing import Any, Callable

import httpx

from .runtime.kernel import ToolCallDenied, ApprovalRequiredError


class SidecarKernel:
    """Kernel that delegates all security decisions to the TypeScript sidecar.

    Connects to the sidecar server on port 8787 (packages/sidecar), NOT the
    legacy decision server on port 9099 (apps/server). The sidecar owns the
    executors, audit state, and behavioral quarantine — it is the single
    authoritative enforcement boundary.

    Exposes the same interface as the native Kernel class, but every call
    goes through the sidecar over HTTP. This guarantees:

    - Complete mediation: every tool call is checked by the TS runtime
    - Tamper resistance: Python cannot modify enforcement logic
    - Audit integrity: the TS sidecar owns the audit log
    - Full parity: same policy engine, same behavioral rules, same taint tracking
    """

    def __init__(
        self,
        *,
        url: str = "http://localhost:8787",
        principal: str = "python-agent",
        capabilities: list[dict[str, Any]] | None = None,
        preset_name: str = "default",
        on_approval: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
        timeout: float = 30.0,
        auth_token: str | None = None,
    ):
        self._url = url.rstrip("/")
        self._principal = principal
        self._preset_name = preset_name
        self._on_approval = on_approval
        self._closed = False
        self._sequence = 0

        headers: dict[str, str] = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        self._http = httpx.Client(base_url=self._url, timeout=timeout, headers=headers)

        # Verify the sidecar is reachable
        try:
            resp = self._http.get("/health")
            resp.raise_for_status()
        except httpx.ConnectError:
            self._http.close()
            raise ConnectionError(
                f"Cannot connect to AriKernel sidecar at {self._url}. "
                "The sidecar is REQUIRED for Python enforcement. "
                "Start it with: pnpm build && node packages/sidecar/dist/main.js"
            ) from None
        except httpx.TimeoutException:
            self._http.close()
            raise ConnectionError(
                f"Timeout connecting to AriKernel sidecar at {self._url}. "
                "The sidecar is REQUIRED for Python enforcement."
            ) from None

        health = resp.json()
        self._run_id: str = f"py-{principal}-{id(self)}"

        # Verify it's the real sidecar (port 8787), not the legacy server (port 9099)
        service = health.get("service", "")
        if service and service != "arikernel-sidecar":
            self._http.close()
            raise ConnectionError(
                f"Connected to '{service}' but expected 'arikernel-sidecar'. "
                f"Ensure the sidecar server (port 8787) is running, not the "
                f"legacy decision server (port 9099)."
            )

    @property
    def preset(self) -> str:
        return self._preset_name

    @property
    def run_id(self) -> str:
        return self._run_id

    def request_capability(
        self,
        capability_class: str,
        taint_labels: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Request a capability grant from the sidecar."""
        self._check_open()

        resp = self._http.post(
            "/request-capability",
            json={
                "principalId": self._principal,
                "capabilityClass": capability_class,
            },
        )

        data = resp.json()

        return {
            "granted": data.get("granted", False),
            "grant_id": data.get("grantId"),
            "reason": data.get("reason"),
            "capability_token": data.get("capabilityToken"),
        }

    def execute_tool(
        self,
        tool_class: str,
        action: str,
        parameters: dict[str, Any] | None = None,
        grant_id: str | None = None,
        taint_labels: list[Any] | None = None,
        execute_fn: Callable[..., Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool call through the sidecar enforcement pipeline.

        The sidecar evaluates policy, checks capabilities, tracks taint,
        evaluates behavioral rules, and logs the audit event. Only if the
        sidecar returns "allow" does execute_fn run locally.

        Returns:
            {"verdict": "allow", "result": <tool output>} on success.
            Raises ToolCallDenied on denial.
        """
        self._check_open()

        parameters = parameters or {}
        taint_labels = taint_labels or []
        self._sequence += 1

        labels_dicts = _serialize_taint_labels(taint_labels)

        body: dict[str, Any] = {
            "principalId": self._principal,
            "toolClass": tool_class,
            "action": action,
            "params": parameters,
        }
        if labels_dicts:
            body["taint"] = labels_dicts
        if grant_id:
            body["grantId"] = grant_id

        resp = self._http.post("/execute", json=body)
        data = resp.json()

        # Handle denial — sidecar returns 403 for denials
        if resp.status_code == 403 or not data.get("allowed", False):
            error = data.get("error", "Denied by sidecar")
            call_id = data.get("callId")

            # Check for approval-required pattern
            if isinstance(error, str) and error.startswith("Approval required:"):
                if self._on_approval is not None:
                    tool_call = {
                        "toolClass": tool_class,
                        "action": action,
                        "parameters": parameters,
                    }
                    approved = self._on_approval(tool_call, data)
                    if not approved:
                        raise ApprovalRequiredError(reason=error)
                    # If approved, fall through — but sidecar doesn't support
                    # re-submission with approval yet, so we raise for now
                    raise ApprovalRequiredError(reason=error)
                else:
                    warnings.warn(
                        f"[arikernel] Sidecar returned 'require-approval' for "
                        f"{tool_class}.{action} but no on_approval handler is "
                        f"registered. Action denied.",
                        stacklevel=2,
                    )
                    raise ApprovalRequiredError(reason=error)

            raise ToolCallDenied(reason=error, verdict="deny")

        # Sidecar said allow — execute locally if execute_fn provided
        result_data = None
        duration_ms = 0

        if execute_fn:
            import time
            start = time.monotonic()
            result_data = execute_fn(**parameters)
            duration_ms = int((time.monotonic() - start) * 1000)

        return {
            "verdict": "allow",
            "result": result_data,
            "call_id": data.get("callId"),
            "result_taint": data.get("resultTaint"),
            "duration_ms": duration_ms,
        }

    def status(self) -> dict[str, Any]:
        """Query principal's quarantine state and run counters from the sidecar."""
        self._check_open()
        resp = self._http.post(
            "/status",
            json={"principalId": self._principal},
        )
        if resp.status_code == 404:
            return {"restricted": False, "counters": {}}
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, Any]:
        """Check sidecar health."""
        resp = self._http.get("/health")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client. No session cleanup needed — sidecar manages firewalls."""
        if self._closed:
            return
        self._closed = True
        self._http.close()

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("Kernel session is closed")

    # Compatibility properties to match Kernel interface
    @property
    def restricted(self) -> bool:
        """Check if the principal is in quarantine on the sidecar."""
        try:
            data = self.status()
            return data.get("restricted", False)
        except Exception:
            return False

    def __enter__(self) -> SidecarKernel:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _serialize_taint_labels(taint_labels: list[Any]) -> list[dict[str, Any]]:
    """Serialize taint labels to dicts for JSON transport."""
    result = []
    for t in taint_labels:
        if hasattr(t, "to_dict"):
            result.append(t.to_dict())
        elif hasattr(t, "source"):
            result.append({
                "source": t.source,
                "origin": t.origin,
                "confidence": t.confidence,
            })
        elif isinstance(t, dict):
            result.append(t)
    return result
