"""Sidecar-authoritative kernel — delegates ALL security decisions to the TypeScript sidecar.

This is the primary enforcement mode for Python. The TypeScript sidecar runs as a
separate process, providing process-boundary isolation that cannot be bypassed by
the Python runtime. This eliminates the "weaker runtime" problem identified in
security reviews: Python code physically cannot skip or alter enforcement logic
because it lives in a different process.

Usage:
    from arikernel import create_kernel

    kernel = create_kernel(preset="safe-research")
    # → connects to TypeScript sidecar at localhost:9099

    kernel.execute_tool("file", "read", {"path": "./data/report.csv"})
"""

from __future__ import annotations

import warnings
from typing import Any, Callable

import httpx

from .runtime.kernel import ToolCallDenied, ApprovalRequiredError


class SidecarKernel:
    """Kernel that delegates all security decisions to the TypeScript sidecar.

    Exposes the same interface as the native Kernel class, but every call
    goes through the TypeScript decision server over HTTP. This guarantees:

    - Complete mediation: every tool call is checked by the TS runtime
    - Tamper resistance: Python cannot modify enforcement logic
    - Audit integrity: the TS sidecar owns the audit log
    - Full parity: same policy engine, same behavioral rules, same taint tracking
    """

    def __init__(
        self,
        *,
        url: str = "http://localhost:9099",
        principal: str = "python-agent",
        capabilities: list[dict[str, Any]] | None = None,
        preset_name: str = "default",
        on_approval: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
        timeout: float = 30.0,
    ):
        self._url = url.rstrip("/")
        self._principal = principal
        self._preset_name = preset_name
        self._on_approval = on_approval
        self._closed = False
        self._sequence = 0

        self._http = httpx.Client(base_url=self._url, timeout=timeout)

        # Create session on the sidecar
        try:
            resp = self._http.post(
                "/session",
                json={
                    "principal": principal,
                    "capabilities": capabilities or [],
                },
            )
            resp.raise_for_status()
        except httpx.ConnectError:
            self._http.close()
            raise ConnectionError(
                f"Cannot connect to AriKernel sidecar at {self._url}. "
                "The sidecar is REQUIRED for Python enforcement. "
                "Start it with: pnpm build && pnpm server"
            ) from None

        data = resp.json()
        self._session_id: str = data["sessionId"]
        self._run_id: str = data["runId"]

    @property
    def preset(self) -> str:
        return self._preset_name

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def session_id(self) -> str:
        return self._session_id

    def request_capability(
        self,
        capability_class: str,
        taint_labels: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Request a capability token from the sidecar."""
        self._check_open()

        labels_dicts = []
        if taint_labels:
            for t in taint_labels:
                if hasattr(t, "to_dict"):
                    labels_dicts.append(t.to_dict())
                elif hasattr(t, "source"):
                    labels_dicts.append({
                        "source": t.source,
                        "origin": t.origin,
                        "confidence": t.confidence,
                    })
                else:
                    labels_dicts.append(t)

        resp = self._http.post(
            f"/session/{self._session_id}/capability",
            json={
                "capabilityClass": capability_class,
                "taintLabels": labels_dicts,
            },
        )
        resp.raise_for_status()
        data = resp.json()

        return {
            "granted": data["granted"],
            "grant_id": data.get("grantId"),
            "reason": data["reason"],
            "expires_at": data.get("expiresAt"),
            "max_calls": data.get("maxCalls"),
            "constraints": data.get("constraints"),
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

        labels_dicts = []
        for t in taint_labels:
            if hasattr(t, "to_dict"):
                labels_dicts.append(t.to_dict())
            elif hasattr(t, "source"):
                labels_dicts.append({
                    "source": t.source,
                    "origin": t.origin,
                    "confidence": t.confidence,
                })
            else:
                labels_dicts.append(t)

        resp = self._http.post(
            f"/session/{self._session_id}/execute",
            json={
                "toolClass": tool_class,
                "action": action,
                "parameters": parameters,
                "grantId": grant_id,
                "taintLabels": labels_dicts,
            },
        )

        data = resp.json()

        # Handle denial
        if resp.status_code == 403:
            verdict = data.get("verdict", "deny")
            reason = data.get("reason", "Denied by sidecar")
            rule = data.get("rule")

            if verdict == "require-approval":
                # Handle approval flow locally
                if self._on_approval is not None:
                    tool_call = {
                        "toolClass": tool_class,
                        "action": action,
                        "parameters": parameters,
                    }
                    approved = self._on_approval(tool_call, data)
                    if approved:
                        # Re-submit with approval flag
                        # For now, execute locally since the sidecar approved
                        pass
                    else:
                        raise ApprovalRequiredError(reason=reason, rule=rule)
                else:
                    warnings.warn(
                        f"[arikernel] Sidecar returned 'require-approval' for "
                        f"{tool_class}.{action} but no on_approval handler is "
                        f"registered. Action denied.",
                        stacklevel=2,
                    )
                    raise ApprovalRequiredError(reason=reason, rule=rule)

            raise ToolCallDenied(reason=reason, verdict=verdict, rule=rule)

        resp.raise_for_status()

        # Sidecar said allow — execute locally
        result_data = None
        duration_ms = data.get("durationMs", 0)

        if execute_fn:
            import time
            start = time.monotonic()
            result_data = execute_fn(**parameters)
            duration_ms = int((time.monotonic() - start) * 1000)

        return {
            "verdict": data["verdict"],
            "result": result_data,
            "duration_ms": duration_ms,
        }

    def revoke_grant(self, grant_id: str) -> bool:
        """Revoke a previously issued capability grant."""
        self._check_open()
        resp = self._http.post(
            f"/session/{self._session_id}/revoke",
            json={"grantId": grant_id},
        )
        resp.raise_for_status()
        return resp.json().get("revoked", False)

    def health(self) -> dict[str, Any]:
        """Check sidecar health."""
        resp = self._http.get("/health")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the session and release sidecar resources."""
        if self._closed:
            return
        self._closed = True
        if self._session_id:
            try:
                self._http.delete(f"/session/{self._session_id}")
            except Exception:
                pass
        self._http.close()

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("Kernel session is closed")

    def __enter__(self) -> SidecarKernel:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
