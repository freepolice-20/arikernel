#!/usr/bin/env python3
"""AriKernel Python + OpenAI tool calling example (local mode).

Demonstrates how AriKernel protects tools in an OpenAI-style agent loop.
The model picks which tool to call, AriKernel enforces security.

No actual OpenAI API call is made — this simulates the agent loop.
Uses local mode so the decorated function bodies execute in-process.
For production, prefer sidecar mode (the default).

Usage:
    pip install -e python/
    python examples/python-openai-tools.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import create_kernel, ToolCallDenied


def main():
    kernel = create_kernel(
        preset="safe-research",
        principal="openai-agent",
        audit_log="python-openai-audit.db",
        mode="local",
    )

    print("AriKernel + OpenAI tool calling example")
    print(f"  Preset: {kernel.preset}")
    print()

    # Define tools the model can call
    tools = {
        "web_search": {"capability": "http.read", "tool_class": "http", "action": "get"},
        "read_file": {"capability": "file.read", "tool_class": "file", "action": "read"},
        "run_shell": {"capability": "shell.exec", "tool_class": "shell", "action": "exec"},
    }

    # Simulated model tool call sequence
    model_calls = [
        {"tool": "web_search", "args": {"url": "https://api.github.com/repos"}},
        {"tool": "read_file", "args": {"path": "./data/notes.txt"}},
        {"tool": "run_shell", "args": {"command": "rm -rf /"}},  # should be blocked
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},  # should be blocked
    ]

    for i, call in enumerate(model_calls, 1):
        tool_name = call["tool"]
        tool_def = tools[tool_name]
        args = call["args"]

        print(f"{i}. Model calls {tool_name}({args})")

        # Request capability
        grant = kernel.request_capability(tool_def["capability"])
        if not grant["granted"]:
            print(f"   BLOCKED (capability denied): {grant['reason']}")
            continue

        # Execute through kernel
        try:
            result = kernel.execute_tool(
                tool_class=tool_def["tool_class"],
                action=tool_def["action"],
                parameters=args,
                grant_id=grant["grant_id"],
                execute_fn=lambda **kw: f"[simulated result for {kw}]",
            )
            print(f"   ALLOWED: {result['result']}")
        except ToolCallDenied as e:
            print(f"   BLOCKED: {e.reason}")

    kernel.close()
    print(f"\nAudit log: python-openai-audit.db")


if __name__ == "__main__":
    # Clean up
    if os.path.exists("python-openai-audit.db"):
        os.remove("python-openai-audit.db")
    main()
