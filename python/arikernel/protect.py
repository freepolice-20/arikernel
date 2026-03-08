"""Helper decorator for protecting Python tool functions with AriKernel.

Usage::

    from arikernel import FirewallClient
    from arikernel.protect import protect_tool

    fw = FirewallClient(url="http://localhost:9099", principal="my-agent", capabilities=[...])

    @protect_tool(fw, tool_class="http", action="get", capability="http.read")
    def fetch_url(url: str) -> str:
        import httpx
        return httpx.get(url).text

    # Now every call to fetch_url() goes through AriKernel first:
    result = fetch_url("https://example.com")
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from .client import FirewallClient
from .types import TaintLabel, ToolCallDenied

F = TypeVar("F", bound=Callable[..., Any])


def protect_tool(
    client: FirewallClient,
    *,
    tool_class: str,
    action: str,
    capability: str | None = None,
    taint_labels: list[TaintLabel] | None = None,
) -> Callable[[F], F]:
    """Decorator that routes a tool function through AriKernel enforcement.

    Args:
        client: An active FirewallClient connected to the decision server.
        tool_class: AriKernel tool class (e.g. "http", "file", "shell").
        action: Tool action (e.g. "get", "read", "exec").
        capability: Capability class to request (e.g. "http.read").
            Defaults to ``{tool_class}.read`` for read actions, ``{tool_class}.write`` otherwise.
        taint_labels: Optional taint labels to attach to every call.
    """
    read_actions = {"get", "read", "query", "list", "search", "fetch"}
    cap_class = capability or f"{tool_class}.{'read' if action in read_actions else 'write'}"

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Request capability
            grant = client.request_capability(cap_class, taint_labels=taint_labels)
            if not grant.granted:
                raise ToolCallDenied(reason=grant.reason)

            # Build parameters dict from kwargs for the decision check
            params = dict(kwargs)
            if args:
                params["_args"] = list(args)

            # Submit for decision
            result = client.execute(
                tool_class=tool_class,
                action=action,
                parameters=params,
                grant_id=grant.grant_id,
                taint_labels=taint_labels,
            )

            if result.verdict != "allow":
                raise ToolCallDenied(reason=f"Tool call denied: {result.verdict}")

            # Allowed — execute the actual function
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
