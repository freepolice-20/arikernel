"""
AriKernel — Python Integration Demo

Demonstrates using the Python client to request decisions from the
AriKernel server. This v1 adapter is a decision/enforcement API
layer: the server decides allow/deny and audits every call, but the
actual tool execution happens here in Python.

Prerequisites:
  1. pnpm build
  2. pnpm server  (in another terminal)
  3. pip install -e python/
  4. python examples/python-demo.py
"""

import sys
import os

# Allow running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import FirewallClient, TaintLabel, ToolCallDenied


def main():
    print("=" * 56)
    print(" AriKernel — Python Integration Demo")
    print("=" * 56)
    print()
    print("  This v1 adapter is a decision layer over the TS core.")
    print("  The server decides allow/deny. Python executes the tool.")
    print()

    # ── Connect to the firewall server ────────────────────────

    try:
        fw = FirewallClient(
            url="http://localhost:9099",
            principal="python-demo-agent",
            capabilities=[
                {
                    "toolClass": "http",
                    "actions": ["get"],
                    "constraints": {"allowedHosts": ["api.github.com"]},
                },
                {
                    "toolClass": "file",
                    "actions": ["read"],
                    "constraints": {"allowedPaths": ["./data/**"]},
                },
            ],
        )
    except Exception as e:
        print(f"  ERROR: Cannot connect to server: {e}")
        print("  Make sure the server is running: pnpm server")
        sys.exit(1)

    print(f"  Session: {fw.session_id}")
    print(f"  Run ID:  {fw.run_id}")
    print()

    # ── Phase 1: Allowed action ───────────────────────────────

    print("[Phase 1] Allowed action: HTTP GET to api.github.com")

    grant = fw.request_capability("http.read")
    print(f"  Capability: {'GRANTED' if grant.granted else 'DENIED'}")

    if grant.granted:
        result = fw.execute(
            tool_class="http",
            action="get",
            parameters={"url": "https://api.github.com/repos/example"},
            grant_id=grant.grant_id,
        )
        print(f"  Decision:   ALLOW (verdict={result.verdict})")
        print(f"  → Python would now execute the actual HTTP GET")
        print()
    else:
        print(f"  Reason: {grant.reason}")
        print()

    # ── Phase 2: Denied action — wrong host ───────────────────

    print("[Phase 2] Denied action: HTTP GET to evil.com (constraint violation)")

    try:
        fw.execute(
            tool_class="http",
            action="get",
            parameters={"url": "https://evil.com/steal"},
            grant_id=grant.grant_id if grant.granted else None,
        )
        print("  Decision: ALLOW — THIS SHOULD NOT HAPPEN!")
    except ToolCallDenied as e:
        print(f"  Decision:   DENY")
        print(f"  Reason:     {e.reason}")
        print(f"  → Python skips execution. No HTTP call made.")
        print()

    # ── Phase 3: Denied action — no capability ────────────────

    print("[Phase 3] Denied action: shell.exec without capability")

    try:
        fw.execute(
            tool_class="shell",
            action="exec",
            parameters={"command": "rm -rf /"},
        )
        print("  Decision: ALLOW — THIS SHOULD NOT HAPPEN!")
    except ToolCallDenied as e:
        print(f"  Decision:   DENY")
        print(f"  Reason:     {e.reason}")
        print(f"  → Python skips execution. No shell command run.")
        print()

    # ── Phase 4: Guarded tool wrapper pattern ─────────────────

    print("[Phase 4] Guarded tool wrapper pattern")

    def guarded_http_get(url: str) -> str:
        """A tool wrapper that checks the firewall before executing."""
        g = fw.request_capability("http.read")
        if not g.granted:
            return f"DENIED: {g.reason}"
        try:
            fw.execute("http", "get", {"url": url}, grant_id=g.grant_id)
            return f"ALLOWED: would fetch {url}"
        except ToolCallDenied as e:
            return f"DENIED: {e.reason}"

    result1 = guarded_http_get("https://api.github.com/users")
    result2 = guarded_http_get("https://evil.com/payload")
    print(f"  github.com: {result1}")
    print(f"  evil.com:   {result2}")
    print()

    # ── Summary ───────────────────────────────────────────────

    print("=" * 56)
    print(" Summary")
    print("=" * 56)
    print()
    print("  The Python client sent 5 tool call decisions to the server.")
    print("  The TypeScript core evaluated policies, enforced capability")
    print("  tokens, and wrote every decision to the audit log.")
    print()
    print("  Replay the audit trail:")
    print(f"    pnpm ari replay --db ./audit.db --latest")
    print()

    fw.close()


if __name__ == "__main__":
    main()
