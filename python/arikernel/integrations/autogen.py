"""Microsoft AutoGen integration for AriKernel.

Wraps AutoGen tool/function callables so every execution routes through
AriKernel's enforcement pipeline before the tool runs.

Usage:

    from arikernel import create_kernel
    from arikernel.integrations.autogen import protect_autogen_tool

    kernel = create_kernel(preset="safe-research")

    @protect_autogen_tool("http.read", kernel=kernel)
    def web_search(query: str) -> str:
        return httpx.get(f"https://api.example.com/search?q={query}").text

    # Use web_search as a normal AutoGen tool — AriKernel enforces on every call.

Support level: first-class Python integration
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def protect_autogen_tool(
    capability_class: str,
    *,
    kernel=None,
    taint_labels=None,
    tool_class: str | None = None,
    action: str | None = None,
) -> Callable[[F], F]:
    """Decorator that wraps an AutoGen tool function with AriKernel enforcement.

    This is the primary integration point for Microsoft AutoGen. Decorate any
    Python callable that AutoGen uses as a tool, and AriKernel will enforce
    capability checks, policy evaluation, taint tracking, behavioral detection,
    quarantine, and audit logging on every invocation.

    Args:
        capability_class: Capability class (e.g. "file.read", "http.get").
        kernel: Optional Kernel instance. Uses global default if omitted.
        taint_labels: Optional taint labels to attach to every call.
        tool_class: Override tool class (otherwise parsed from capability_class).
        action: Override action (otherwise parsed from capability_class).
    """
    # Resolve tool_class and action from capability_class via spec
    from arikernel.runtime.spec_loader import get_capability_classes
    cap_classes = get_capability_classes()
    cap_def = cap_classes.get(capability_class)
    _tool_class = tool_class
    _action = action
    if cap_def:
        _tool_class = _tool_class or cap_def["toolClass"]
        _action = _action or cap_def["actions"][0]
    if not _tool_class or not _action:
        parts = capability_class.split(".")
        _tool_class = _tool_class or parts[0]
        _action = _action or (parts[1] if len(parts) > 1 else "read")

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from arikernel.protect import get_default_kernel
            from arikernel.runtime.kernel import ToolCallDenied

            k = kernel or get_default_kernel()

            # Convert taint labels
            native_labels = None
            if taint_labels:
                from arikernel.runtime.taint_tracking import TaintLabel as NativeTaintLabel
                native_labels = [
                    NativeTaintLabel(source=t.source, origin=t.origin, confidence=t.confidence)
                    if hasattr(t, "source") else t
                    for t in taint_labels
                ]

            # Request capability
            grant = k.request_capability(capability_class, native_labels)
            if not grant.get("granted"):
                raise ToolCallDenied(reason=grant.get("reason", "Capability denied"))

            # Build parameters from args/kwargs
            params = dict(kwargs)
            if args:
                params["_args"] = list(args)

            # Execute through kernel enforcement pipeline
            result = k.execute_tool(
                tool_class=_tool_class,
                action=_action,
                parameters=params,
                grant_id=grant.get("grant_id"),
                taint_labels=native_labels,
                execute_fn=lambda **_kw: fn(*args, **kwargs),
            )

            return result.get("result")

        return wrapper  # type: ignore[return-value]

    return decorator


class AutoGenToolWrapper:
    """Wrapper that protects multiple AutoGen tools through a single kernel.

    Usage:
        wrapper = AutoGenToolWrapper(kernel)
        wrapper.register("web_search", "http.read", web_search_fn)
        wrapper.register("read_file", "file.read", read_file_fn)

        # Get protected functions for AutoGen registration
        protected = wrapper.get_tools()
    """

    def __init__(self, kernel=None):
        from arikernel.protect import get_default_kernel
        self._kernel = kernel or get_default_kernel()
        self._tools: dict[str, Callable] = {}

    def register(
        self,
        name: str,
        capability_class: str,
        fn: Callable,
        taint_labels=None,
    ) -> "AutoGenToolWrapper":
        """Register a tool function with AriKernel protection."""
        protected = protect_autogen_tool(
            capability_class, kernel=self._kernel, taint_labels=taint_labels
        )(fn)
        self._tools[name] = protected
        return self

    def get_tools(self) -> dict[str, Callable]:
        """Return all registered protected tools."""
        return dict(self._tools)

    def execute(self, tool_name: str, **kwargs) -> Any:
        """Execute a named tool through AriKernel enforcement."""
        fn = self._tools.get(tool_name)
        if fn is None:
            raise ValueError(f"Unknown tool: {tool_name}. Registered: {list(self._tools.keys())}")
        return fn(**kwargs)

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())
