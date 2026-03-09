"""AutoGPT compatibility layer for AriKernel.

Wraps AutoGPT-style command/skill execution at the tool boundary so
AriKernel can enforce security policies on every action.

AutoGPT commands are Python callables with a name, description, and
parameters. This module provides a decorator and wrapper class that
intercept command execution and route it through AriKernel.

Usage:

    from arikernel import create_kernel
    from arikernel.integrations.autogpt import protect_autogpt_command

    kernel = create_kernel(preset="safe-research")

    @protect_autogpt_command("file.read", kernel=kernel)
    def read_file(filename: str) -> str:
        return open(filename).read()

Support level: experimental compatibility layer
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def protect_autogpt_command(
    capability_class: str,
    *,
    kernel=None,
    taint_labels=None,
    tool_class: str | None = None,
    action: str | None = None,
) -> Callable[[F], F]:
    """Decorator that wraps an AutoGPT command with AriKernel enforcement.

    This provides a compatibility layer for protecting AutoGPT-style commands.
    The command execution boundary is the most stable seam for integration:
    every command call is intercepted before the actual function runs.

    Args:
        capability_class: Capability class (e.g. "file.read", "shell.exec").
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

            # Build parameters
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

        # Preserve AutoGPT command metadata if present
        wrapper.command_name = getattr(fn, "command_name", fn.__name__)  # type: ignore
        wrapper.command_description = getattr(fn, "command_description", fn.__doc__ or "")  # type: ignore

        return wrapper  # type: ignore[return-value]

    return decorator


class AutoGPTCommandWrapper:
    """Wrapper that protects multiple AutoGPT commands through a single kernel.

    Provides a command registry compatible with AutoGPT's execution model.

    Usage:
        wrapper = AutoGPTCommandWrapper(kernel)
        wrapper.register("read_file", "file.read", read_file_fn)
        wrapper.register("browse_web", "http.read", browse_web_fn)

        # Execute through AriKernel enforcement
        result = wrapper.execute("read_file", filename="./data/report.txt")
    """

    def __init__(self, kernel=None):
        from arikernel.protect import get_default_kernel
        self._kernel = kernel or get_default_kernel()
        self._commands: dict[str, Callable] = {}
        self._metadata: dict[str, dict[str, str]] = {}

    def register(
        self,
        name: str,
        capability_class: str,
        fn: Callable,
        *,
        description: str = "",
        taint_labels=None,
    ) -> "AutoGPTCommandWrapper":
        """Register a command with AriKernel protection."""
        protected = protect_autogpt_command(
            capability_class, kernel=self._kernel, taint_labels=taint_labels
        )(fn)
        self._commands[name] = protected
        self._metadata[name] = {
            "description": description or fn.__doc__ or "",
            "capability": capability_class,
        }
        return self

    def execute(self, name: str, **kwargs) -> Any:
        """Execute a named command through AriKernel enforcement."""
        fn = self._commands.get(name)
        if fn is None:
            raise ValueError(f"Unknown command: {name}. Available: {list(self._commands.keys())}")
        return fn(**kwargs)

    @property
    def command_names(self) -> list[str]:
        return list(self._commands.keys())

    def get_command_info(self) -> list[dict[str, str]]:
        """Return metadata for all registered commands."""
        return [
            {"name": name, **meta}
            for name, meta in self._metadata.items()
        ]
