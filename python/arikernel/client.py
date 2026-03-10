"""Synchronous HTTP client for the AriKernel decision server.

This v1 client is a decision/enforcement API layer over the TypeScript core.
Actual tool execution still occurs in Python after an allow verdict.
"""

from __future__ import annotations

from typing import Any

import httpx

from .types import ExecuteResult, Grant, TaintLabel
from .runtime.kernel import ToolCallDenied


def _taint_to_dict(label: TaintLabel) -> dict[str, Any]:
    return {
        "source": label.source,
        "origin": label.origin,
        "confidence": label.confidence,
    }


class FirewallClient:
    """Client for the AriKernel HTTP decision server.

    This is a v1 integration layer. It asks the server for allow/deny
    decisions and audits every call, but does NOT execute tools server-side.
    Your Python code executes the actual tool after receiving an allow verdict.

    Usage::

        with FirewallClient(
            url="http://localhost:9099",
            principal="my-agent",
            capabilities=[
                {"toolClass": "http", "actions": ["get"],
                 "constraints": {"allowedHosts": ["api.github.com"]}},
            ],
        ) as fw:
            grant = fw.request_capability("http.read")
            if grant.granted:
                result = fw.execute("http", "get",
                    {"url": "https://api.github.com/repos/example"},
                    grant_id=grant.grant_id)
                # result.verdict == "allow" -> execute the actual HTTP call
    """

    def __init__(
        self,
        url: str = "http://localhost:9099",
        principal: str = "python-agent",
        capabilities: list[dict[str, Any]] | None = None,
    ):
        self.base_url = url.rstrip("/")
        self._http = httpx.Client(base_url=self.base_url, timeout=30)
        self.session_id: str | None = None
        self.run_id: str | None = None

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
                f"Cannot connect to AriKernel decision server at {self.base_url}. "
                "Start it with: pnpm build && pnpm server"
            ) from None
        data = resp.json()
        self.session_id = data["sessionId"]
        self.run_id = data["runId"]

    def request_capability(
        self,
        capability_class: str,
        taint_labels: list[TaintLabel] | None = None,
    ) -> Grant:
        """Request a capability token from the firewall."""
        resp = self._http.post(
            f"/session/{self.session_id}/capability",
            json={
                "capabilityClass": capability_class,
                "taintLabels": [_taint_to_dict(t) for t in (taint_labels or [])],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return Grant(
            granted=data["granted"],
            grant_id=data.get("grantId"),
            reason=data["reason"],
            expires_at=data.get("expiresAt"),
            max_calls=data.get("maxCalls"),
            constraints=data.get("constraints"),
        )

    def execute(
        self,
        tool_class: str,
        action: str,
        parameters: dict[str, Any],
        grant_id: str | None = None,
        taint_labels: list[TaintLabel] | None = None,
    ) -> ExecuteResult:
        """Submit a tool call for decision.

        If allowed, returns an ExecuteResult. Your code should then execute
        the actual tool (HTTP request, file read, etc.) itself.

        If denied, raises ToolCallDenied.
        """
        resp = self._http.post(
            f"/session/{self.session_id}/execute",
            json={
                "toolClass": tool_class,
                "action": action,
                "parameters": parameters,
                "grantId": grant_id,
                "taintLabels": [_taint_to_dict(t) for t in (taint_labels or [])],
            },
        )

        data = resp.json()

        if resp.status_code == 403:
            raise ToolCallDenied(
                reason=data.get("reason", "Denied"),
                verdict=data.get("verdict", "deny"),
                rule=data.get("rule"),
            )

        resp.raise_for_status()

        return ExecuteResult(
            verdict=data["verdict"],
            success=data.get("success", True),
            data=data.get("data"),
            duration_ms=data.get("durationMs"),
        )

    def revoke_grant(self, grant_id: str) -> bool:
        """Revoke a previously issued capability grant."""
        resp = self._http.post(
            f"/session/{self.session_id}/revoke",
            json={"grantId": grant_id},
        )
        resp.raise_for_status()
        return resp.json().get("revoked", False)

    def close(self) -> None:
        """Close the session and release server resources."""
        if self.session_id:
            try:
                self._http.delete(f"/session/{self.session_id}")
            except Exception:
                pass
            self.session_id = None
        self._http.close()

    def health(self) -> dict[str, Any]:
        """Check server health."""
        resp = self._http.get("/health")
        resp.raise_for_status()
        return resp.json()

    def __enter__(self) -> "FirewallClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
