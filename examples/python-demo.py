"""
AriKernel — Python Integration Demo

Demonstrates using the Python client to execute tool calls through the
AriKernel sidecar. The sidecar evaluates policy, enforces capabilities,
executes tools via its own executors, and logs every decision to the
audit trail.

Prerequisites:
  1. pnpm build
  2. pnpm sidecar  (in another terminal)
  3. pip install -e python/
  4. python examples/python-demo.py
"""

import sys
import os

# Allow running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import create_kernel, ToolCallDenied


def main():
    print("=" * 56)
    print(" AriKernel — Python Integration Demo")
    print("=" * 56)
    print()
    print("  Sidecar-authoritative mode: the TypeScript sidecar")
    print("  enforces policy and executes tools. Python is a thin client.")
    print()

    # ── Connect to the sidecar ────────────────────────────────

    try:
        kernel = create_kernel(preset="safe-research")
    except ConnectionError as e:
        print(f"  ERROR: Cannot connect to sidecar: {e}")
        print("  Make sure the sidecar is running: pnpm sidecar")
        sys.exit(1)

    print(f"  Preset: {kernel.preset}")
    print()

    # ── Phase 1: Allowed action ───────────────────────────────

    print("[Phase 1] Allowed action: HTTP GET to api.github.com")

    grant = kernel.request_capability("http.read")
    print(f"  Capability: {'GRANTED' if grant['granted'] else 'DENIED'}")

    if grant["granted"]:
        result = kernel.execute_tool(
            tool_class="http",
            action="get",
            parameters={"url": "https://api.github.com/repos/example"},
            grant_id=grant.get("grant_id"),
        )
        print(f"  Verdict:    {result['verdict']}")
        print(f"  Success:    {result.get('success', 'N/A')}")
        print()
    else:
        print(f"  Reason: {grant.get('reason')}")
        print()

    # ── Phase 2: Denied action — shell.exec ───────────────────

    print("[Phase 2] Denied action: shell.exec without capability")

    try:
        kernel.execute_tool(
            tool_class="shell",
            action="exec",
            parameters={"command": "rm -rf /"},
        )
        print("  Verdict: ALLOW — THIS SHOULD NOT HAPPEN!")
    except ToolCallDenied as e:
        print(f"  Verdict:    DENY")
        print(f"  Reason:     {e.reason}")
        print(f"  → Sidecar blocked execution. No shell command run.")
        print()

    # ── Phase 3: Allowed but failed — read nonexistent file ───

    print("[Phase 3] Allowed but failed: read nonexistent file")

    result = kernel.execute_tool(
        tool_class="file",
        action="read",
        parameters={"path": "/nonexistent/file.txt"},
    )
    print(f"  Verdict:    {result['verdict']}")
    print(f"  Success:    {result.get('success')}")
    print(f"  Error:      {result.get('error', 'none')}")
    print(f"  → Policy allowed the call, but FileExecutor could not find it.")
    print()

    # ── Summary ───────────────────────────────────────────────

    print("=" * 56)
    print(" Summary")
    print("=" * 56)
    print()
    print("  The Python client sent tool call requests to the sidecar.")
    print("  The sidecar evaluated policies, enforced capabilities,")
    print("  executed tools, and logged every decision to the audit trail.")
    print()
    print("  Replay the audit trail:")
    print(f"    pnpm ari replay --db ./audit.db --latest")
    print()

    kernel.close()


if __name__ == "__main__":
    main()
