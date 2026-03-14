"""
AutoGPT — AriKernel Compatibility Layer Example (local mode)

Demonstrates how AriKernel protects AutoGPT-style commands at the
execution boundary. Every command call routes through capability checks,
policy evaluation, taint tracking, and behavioral detection.

Uses local mode so the command functions execute in-process.
For production, prefer sidecar mode (the default).

Support level: experimental compatibility layer

Run:  python examples/autogpt-agent.py
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
from arikernel.integrations.autogpt import AutoGPTCommandWrapper

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
    print(f"{CYAN}{BOLD}  AutoGPT — AriKernel Compatibility Demo{RESET}")
    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}")
    print(f"{DIM}  Preset: safe-research{RESET}")
    print(f"{DIM}  Support: experimental compatibility layer{RESET}\n")

    # Register AutoGPT-style commands
    commands = AutoGPTCommandWrapper(kernel)
    commands.register(
        "browse_website", "http.read",
        lambda url="": f"Page content from {url}",
        description="Browse a website and return content",
    )
    commands.register(
        "read_file", "file.read",
        lambda path="": f"File contents: {path}",
        description="Read a local file",
    )
    commands.register(
        "write_file", "file.write",
        lambda path="", content="": f"Wrote to {path}",
        description="Write content to a file",
    )
    commands.register(
        "execute_shell", "shell.exec",
        lambda command_line="": f"Output: {command_line}",
        description="Execute a shell command",
    )

    print(f"  Registered commands: {', '.join(commands.command_names)}\n")

    # Step 1: Allowed — browse website
    print(f"{YELLOW}{BOLD}Step 1{RESET} {BOLD}browse_website (allowed){RESET}")
    try:
        result = commands.execute("browse_website", url="https://example.com")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 2: Denied — read sensitive file
    print(f"{YELLOW}{BOLD}Step 2{RESET} {BOLD}read_file (~/.env){RESET}")
    try:
        result = commands.execute("read_file", path="~/.env")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 3: Denied — write file (not in safe-research)
    print(f"{YELLOW}{BOLD}Step 3{RESET} {BOLD}write_file (no capability){RESET}")
    try:
        result = commands.execute("write_file", filename="./pwned.txt", content="data")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    # Step 4: Denied — shell exec
    print(f"{YELLOW}{BOLD}Step 4{RESET} {BOLD}execute_shell (no capability){RESET}")
    try:
        result = commands.execute("execute_shell", command_line="cat /etc/passwd")
        print(f"  {GREEN}{BOLD}ALLOWED{RESET} {DIM}{result}{RESET}\n")
    except ToolCallDenied as e:
        print(f"  {RED}{BOLD}BLOCKED{RESET} {DIM}{e.reason}{RESET}\n")

    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}")
    print(f"  Restricted: {kernel.restricted}")
    print(f"{CYAN}{BOLD}{'═' * 60}{RESET}\n")

    kernel.close()


if __name__ == "__main__":
    main()
