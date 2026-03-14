"""
Microsoft AutoGen — AriKernel Integration Example (local mode)

Demonstrates how AriKernel protects AutoGen-style tool functions.
Every tool call routes through capability checks, policy evaluation,
taint tracking, behavioral detection, and audit logging.

Uses local mode so the decorated function bodies execute in-process.
For production, prefer sidecar mode (the default) where the TypeScript
sidecar handles enforcement and tool execution.

Run:  python examples/autogen-agent.py
"""

import sys
import os

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Add python/ to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from arikernel import create_kernel
from arikernel.runtime.kernel import ToolCallDenied
from arikernel.integrations.autogen import protect_autogen_tool, AutoGenToolWrapper

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def main():
    kernel = create_kernel(
        preset="safe-research",
        audit_log=":memory:",
        max_denied_sensitive_actions=3,
        mode="local",
    )

    print(f"\n{CYAN}{BOLD}{'═' * 60}{RESET}")
    print(f"{CYAN}{BOLD}  AutoGen — AriKernel Protection Demo{RESET}")
    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}")
    print(f"{DIM}  Preset: safe-research{RESET}\n")

    # Register tools using the wrapper class
    wrapper = AutoGenToolWrapper(kernel)
    wrapper.register("web_search", "http.read", lambda query="": f"Results for: {query}")
    wrapper.register("read_file", "file.read", lambda path="": f"Contents of {path}")
    wrapper.register("run_shell", "shell.exec", lambda cmd="": f"Output: {cmd}")

    # Step 1: Allowed — web search
    print(f"{YELLOW}{BOLD}Step 1{RESET} {BOLD}web_search (allowed){RESET}")
    try:
        result = wrapper.execute("web_search", query="AriKernel security")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 2: Allowed — read safe file
    print(f"{YELLOW}{BOLD}Step 2{RESET} {BOLD}read_file (safe path){RESET}")
    try:
        result = wrapper.execute("read_file", path="./data/report.csv")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 3: Denied — read sensitive file
    print(f"{YELLOW}{BOLD}Step 3{RESET} {BOLD}read_file (~/.ssh/id_rsa){RESET}")
    try:
        result = wrapper.execute("read_file", path="~/.ssh/id_rsa")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 4: Denied — shell exec (not in safe-research preset)
    print(f"{YELLOW}{BOLD}Step 4{RESET} {BOLD}run_shell (no capability){RESET}")
    try:
        result = wrapper.execute("run_shell", cmd="whoami")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}")
    print(f"  Restricted: {kernel.restricted}")
    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}\n")

    kernel.close()


if __name__ == "__main__":
    main()
