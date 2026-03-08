"""Helper decorator for protecting Python tool functions with AriKernel.

Supports two modes:

1. Native runtime (no server required):

    from arikernel import create_kernel, protect_tool

    kernel = create_kernel(preset="safe-research")

    @protect_tool("file.read")
    def read_file(path: str) -> str:
        return open(path).read()

2. HTTP decision server (legacy):

    from arikernel import FirewallClient
    from arikernel.protect import protect_tool_remote

    fw = FirewallClient(url="http://localhost:9099", ...)

    @protect_tool_remote(fw, tool_class="http", action="get")
    def fetch_url(url: str) -> str: ...
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# Global default kernel (set by create_kernel or protect_tool)
_default_kernel = None


def set_default_kernel(kernel) -> None:
    """Set the global default kernel for protect_tool decorators."""
    global _default_kernel
    _default_kernel = kernel


def get_default_kernel():
    """Get or lazily create the default kernel."""
    global _default_kernel
    if _default_kernel is None:
        from .runtime.kernel import create_kernel
        _default_kernel = create_kernel()
    return _default_kernel


def protect_tool(
    capability_class: str,
    *,
    kernel=None,
    taint_labels=None,
) -> Callable[[F], F]:
    """Decorator that routes a tool function through AriKernel native enforcement.

    Args:
        capability_class: Capability class string (e.g. "file.read", "http.get").
        kernel: Optional Kernel instance. Uses global default if not provided.
        taint_labels: Optional taint labels to attach to every call.

    Usage::

        @protect_tool("file.read")
        def read_file(path: str) -> str:
            return open(path).read()
    """
    # Resolve tool_class and action from capability class using the spec
    from .runtime.spec_loader import get_capability_classes
    cap_classes = get_capability_classes()
    cap_def = cap_classes.get(capability_class)
    if cap_def:
        tool_class = cap_def["toolClass"]
        action = cap_def["actions"][0]  # primary action
    else:
        # Fallback: parse from capability_class string
        parts = capability_class.split(".")
        tool_class = parts[0]
        action = parts[1] if len(parts) > 1 else "read"

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            k = kernel or get_default_kernel()

            # Convert taint labels if provided
            native_labels = None
            if taint_labels:
                from .runtime.taint_tracking import TaintLabel as NativeTaintLabel
                native_labels = [
                    NativeTaintLabel(source=t.source, origin=t.origin, confidence=t.confidence)
                    if hasattr(t, "source") else t
                    for t in taint_labels
                ]

            # Request capability
            grant = k.request_capability(capability_class, native_labels)
            if not grant.get("granted"):
                from .runtime.kernel import ToolCallDenied
                raise ToolCallDenied(reason=grant.get("reason", "Capability denied"))

            # Build parameters
            params = dict(kwargs)
            if args:
                params["_args"] = list(args)

            # Execute through kernel enforcement pipeline
            result = k.execute_tool(
                tool_class=tool_class,
                action=action,
                parameters=params,
                grant_id=grant.get("grant_id"),
                taint_labels=native_labels,
                execute_fn=lambda **_kw: fn(*args, **kwargs),
            )

            return result.get("result")

        return wrapper  # type: ignore[return-value]

    return decorator


# ── Legacy HTTP client decorator ──────────────────────────────────────

def protect_tool_remote(
    client,
    *,
    tool_class: str,
    action: str,
    capability: str | None = None,
    taint_labels=None,
) -> Callable[[F], F]:
    """Decorator that routes a tool function through AriKernel HTTP decision server.

    This is the legacy mode that requires a running TypeScript server.
    Prefer protect_tool() for native Python enforcement.
    """
    from .types import TaintLabel, ToolCallDenied

    read_actions = {"get", "read", "query", "list", "search", "fetch"}
    cap_class = capability or f"{tool_class}.{'read' if action in read_actions else 'write'}"

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            grant = client.request_capability(cap_class, taint_labels=taint_labels)
            if not grant.granted:
                raise ToolCallDenied(reason=grant.reason)

            params = dict(kwargs)
            if args:
                params["_args"] = list(args)

            result = client.execute(
                tool_class=tool_class,
                action=action,
                parameters=params,
                grant_id=grant.grant_id,
                taint_labels=taint_labels,
            )

            if result.verdict != "allow":
                raise ToolCallDenied(reason=f"Tool call denied: {result.verdict}")

            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
