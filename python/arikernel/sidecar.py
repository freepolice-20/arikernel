"""Sidecar-authoritative kernel — delegates all security decisions and tool
execution to the TypeScript sidecar.

This is the primary enforcement mode for Python. The TypeScript sidecar runs as a
separate process on port 8787 and owns the full enforcement pipeline including
tool executors. Python acts as a thin client: it sends tool call requests to the
sidecar and receives results (or denials). The decorated function body is NOT
executed in sidecar mode — the sidecar's own executors handle tool execution.

Enforcement is stronger than embedded/local mode because the policy engine,
taint state, behavioral rules, and audit log all live in a separate process.
However, Python code that calls OS APIs directly (e.g., ``open()``,
``subprocess.run()``, ``httpx.get()``) without going through the kernel is
not mediated. Sidecar mode provides process-boundary isolation for mediated
calls only.

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
    """Kernel that delegates all security decisions and tool execution to the
    TypeScript sidecar.

    Connects to the sidecar server on port 8787 (packages/sidecar), NOT the
    legacy decision server on port 9099 (apps/server). The sidecar owns the
    executors, audit state, and behavioral quarantine — it is the single
    authoritative enforcement boundary for mediated calls.

    Exposes the same interface as the native Kernel class, but every call
    goes through the sidecar over HTTP. This provides:

    - Mediation of routed calls: every tool call sent through this client
      is evaluated by the TypeScript runtime
    - Process isolation: Python cannot modify enforcement logic in the
      sidecar process
    - Audit integrity: the sidecar owns the hash-chained audit log
    - Full parity: same policy engine, same behavioral rules, same taint
      tracking as TypeScript

    Important: calls that bypass this client (e.g., direct ``open()`` or
    ``subprocess.run()``) are not mediated. Sidecar mode isolates the
    enforcement state, not the Python process itself.
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
        evaluates behavioral rules, executes the tool via its own executors,
        and logs the audit event. The ``execute_fn`` parameter is ignored in
        sidecar mode — the sidecar owns tool execution. If you need local
        execution, use ``mode="local"`` instead.

        Returns:
            {"verdict": "allow", "result": <sidecar result>, "success": bool}
            on allow. Raises ToolCallDenied on denial (HTTP 403).

        Tool execution failures (e.g. file not found) are returned as
        ``{"verdict": "allow", "success": False, "error": "..."}`` — the
        policy allowed the call but the executor encountered an error.
        """
        self._check_open()

        if execute_fn is not None:
            warnings.warn(
                "[arikernel] execute_fn is ignored in sidecar mode. "
                "The sidecar executes tools via its own executors. "
                "Use mode='local' if you need local tool execution.",
                stacklevel=2,
            )

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

        # Handle denial — sidecar returns 403 for policy denials
        if resp.status_code == 403:
            error = data.get("error", "Denied by sidecar")

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
                    # Sidecar doesn't support re-submission with approval yet
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

        # Non-403 but allowed=false is unexpected; treat as denial
        if not data.get("allowed", False):
            error = data.get("error", "Denied by sidecar")
            raise ToolCallDenied(reason=error, verdict="deny")

        # Sidecar allowed and executed the tool — return sidecar's result.
        # The sidecar's executors handle the actual tool execution; we do
        # NOT run execute_fn locally.
        return {
            "verdict": "allow",
            "success": data.get("success", True),
            "result": data.get("result"),
            "error": data.get("error"),
            "call_id": data.get("callId"),
            "result_taint": data.get("resultTaint"),
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
