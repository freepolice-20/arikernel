"""Drop-in middleware wrappers for securing AI agents with Ari Kernel.

Provides single-function wrappers that automatically route tool execution
through the Ari Kernel enforcement pipeline.

Usage:

    from arikernel.middleware import protect_langchain_agent

    agent = protect_langchain_agent(agent, preset="safe-research")

    from arikernel.middleware import protect_autogen_agent

    protected = protect_autogen_agent(tools, preset="safe-research")
"""

from __future__ import annotations

import functools
import re
from typing import Any, Callable

from .runtime.kernel import Kernel, ToolCallDenied, create_kernel


# ── Tool name inference ──────────────────────────────────────────────

_TOOL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^(web_search|web_fetch|http_get|fetch_url|browse|scrape|search_web)$", re.I), "http", "get"),
    (re.compile(r"^(http_post|send_request|post_data|web_post)$", re.I), "http", "post"),
    (re.compile(r"^(read_file|file_read|load_file|get_file|read_document)$", re.I), "file", "read"),
    (re.compile(r"^(write_file|file_write|save_file|create_file)$", re.I), "file", "write"),
    (re.compile(r"^(run_shell|shell_exec|exec_command|run_command|terminal|bash|execute)$", re.I), "shell", "exec"),
    (re.compile(r"^(query_db|sql_query|db_query|database_read|db_read|run_query)$", re.I), "database", "query"),
    (re.compile(r"^(db_write|sql_insert|db_insert|database_write|db_update)$", re.I), "database", "write"),
    (re.compile(r"^(send_email|email_send|send_message)$", re.I), "http", "post"),
]


def infer_tool_mapping(tool_name: str) -> tuple[str, str] | None:
    """Infer (tool_class, action) from a tool name. Returns None if unknown."""
    for pattern, tool_class, action in _TOOL_PATTERNS:
        if pattern.match(tool_name):
            return (tool_class, action)
    return None


def _resolve_capability_class(tool_class: str, action: str) -> str:
    read_actions = {"get", "read", "query", "list", "search", "fetch"}
    if tool_class == "shell":
        return "shell.exec"
    return f"{tool_class}.{'read' if action in read_actions else 'write'}"


def _create_middleware_kernel(
    preset: str | None = None,
    principal: str = "agent",
    audit_log: str = ":memory:",
    max_denied: int = 10,
) -> Kernel:
    return create_kernel(
        preset=preset,
        principal=principal,
        audit_log=audit_log,
        max_denied_sensitive_actions=max_denied,
    )


# ── LangChain middleware ─────────────────────────────────────────────

def protect_langchain_agent(
    agent: Any,
    *,
    preset: str | None = None,
    principal: str = "agent",
    audit_log: str = ":memory:",
    tool_mappings: dict[str, tuple[str, str]] | None = None,
) -> Any:
    """Protect a LangChain agent by wrapping its tools with Ari Kernel enforcement.

    Args:
        agent: A LangChain agent or any object with a `.tools` attribute.
        preset: Security preset (e.g. "safe-research").
        principal: Principal name for audit.
        audit_log: Audit log path. Default in-memory.
        tool_mappings: Explicit {tool_name: (tool_class, action)} mappings.
            Auto-inferred from naming patterns if omitted.

    Returns:
        The same agent with protected tools. Access kernel via `agent._arikernel`.
    """
    kernel = _create_middleware_kernel(preset=preset, principal=principal, audit_log=audit_log)

    tools = getattr(agent, "tools", None)
    if tools is None:
        raise TypeError("Agent must have a 'tools' attribute (list of tool objects)")

    for tool in tools:
        name = getattr(tool, "name", None)
        if name is None:
            continue

        # Resolve mapping
        if tool_mappings and name in tool_mappings:
            tool_class, action = tool_mappings[name]
        else:
            inferred = infer_tool_mapping(name)
            if inferred is None:
                continue
            tool_class, action = inferred

        cap_class = _resolve_capability_class(tool_class, action)

        # Wrap _run or func
        for attr in ("_run", "func"):
            original = getattr(tool, attr, None)
            if original is None or not callable(original):
                continue

            @functools.wraps(original)
            def make_wrapper(orig_fn, tc=tool_class, act=action, cc=cap_class):
                def wrapper(*args, **kwargs):
                    grant = kernel.request_capability(cc)
                    if not grant.get("granted"):
                        raise ToolCallDenied(reason=grant.get("reason", "Capability denied"))

                    params = dict(kwargs)
                    if args:
                        params["_args"] = list(args)

                    kernel.execute_tool(
                        tool_class=tc,
                        action=act,
                        parameters=params,
                        grant_id=grant.get("grant_id"),
                        execute_fn=lambda **_kw: None,
                    )
                    return orig_fn(*args, **kwargs)
                return wrapper

            setattr(tool, attr, make_wrapper(original))

    agent._arikernel = kernel
    return agent


# ── OpenAI Agents middleware ─────────────────────────────────────────

def protect_openai_agent(
    tools: list[dict[str, Any]],
    *,
    preset: str | None = None,
    principal: str = "agent",
    audit_log: str = ":memory:",
    tool_mappings: dict[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Protect OpenAI Agents SDK-style tool definitions.

    Args:
        tools: List of tool definition dicts with 'function.name' and 'execute'.
        preset: Security preset.
        tool_mappings: Explicit {tool_name: (tool_class, action)} mappings.

    Returns:
        Dict with 'tools' (protected list) and 'kernel' (Kernel instance).
    """
    kernel = _create_middleware_kernel(preset=preset, principal=principal, audit_log=audit_log)
    protected = []

    for tool in tools:
        func_def = tool.get("function", {})
        name = func_def.get("name", "")
        original_execute = tool.get("execute")

        if tool_mappings and name in tool_mappings:
            tool_class, action = tool_mappings[name]
        else:
            inferred = infer_tool_mapping(name)
            if inferred is None:
                protected.append(tool)
                continue
            tool_class, action = inferred

        cap_class = _resolve_capability_class(tool_class, action)

        def make_execute(orig, tc=tool_class, act=action, cc=cap_class):
            def execute(args):
                grant = kernel.request_capability(cc)
                if not grant.get("granted"):
                    raise ToolCallDenied(reason=grant.get("reason", "Capability denied"))
                kernel.execute_tool(
                    tool_class=tc,
                    action=act,
                    parameters=args if isinstance(args, dict) else {"input": args},
                    grant_id=grant.get("grant_id"),
                    execute_fn=lambda **_kw: None,
                )
                return orig(args)
            return execute

        protected.append({**tool, "execute": make_execute(original_execute)})

    return {"tools": protected, "kernel": kernel}


# ── CrewAI middleware ────────────────────────────────────────────────

def protect_crewai_agent(
    tools: dict[str, Callable],
    *,
    preset: str | None = None,
    principal: str = "agent",
    audit_log: str = ":memory:",
    tool_mappings: dict[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Protect CrewAI-style tool functions.

    Args:
        tools: Dict of {tool_name: callable}.
        preset: Security preset.
        tool_mappings: Explicit {tool_name: (tool_class, action)} mappings.

    Returns:
        Dict with 'execute' function, 'tools' dict, and 'kernel'.
    """
    kernel = _create_middleware_kernel(preset=preset, principal=principal, audit_log=audit_log)
    protected: dict[str, Callable] = {}

    for name, fn in tools.items():
        if tool_mappings and name in tool_mappings:
            tool_class, action = tool_mappings[name]
        else:
            inferred = infer_tool_mapping(name)
            if inferred is None:
                protected[name] = fn
                continue
            tool_class, action = inferred

        cap_class = _resolve_capability_class(tool_class, action)

        def make_wrapper(orig_fn, tc=tool_class, act=action, cc=cap_class):
            def wrapper(**kwargs):
                grant = kernel.request_capability(cc)
                if not grant.get("granted"):
                    raise ToolCallDenied(reason=grant.get("reason", "Capability denied"))
                kernel.execute_tool(
                    tool_class=tc,
                    action=act,
                    parameters=kwargs,
                    grant_id=grant.get("grant_id"),
                    execute_fn=lambda **_kw: None,
                )
                return orig_fn(**kwargs)
            return wrapper

        protected[name] = make_wrapper(fn)

    def execute(tool_name: str, **kwargs):
        fn = protected.get(tool_name)
        if fn is None:
            raise ValueError(f"Unknown tool: {tool_name}. Registered: {list(protected.keys())}")
        return fn(**kwargs)

    return {"execute": execute, "tools": protected, "kernel": kernel}


# ── AutoGen middleware ───────────────────────────────────────────────

def protect_autogen_agent(
    tools: dict[str, Callable],
    *,
    preset: str | None = None,
    principal: str = "agent",
    audit_log: str = ":memory:",
    tool_mappings: dict[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Protect AutoGen-style tool functions. Same API as protect_crewai_agent."""
    return protect_crewai_agent(
        tools,
        preset=preset,
        principal=principal,
        audit_log=audit_log,
        tool_mappings=tool_mappings,
    )
