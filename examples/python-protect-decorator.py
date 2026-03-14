"""
Python @protect_tool Decorator — AriKernel Integration Example

Demonstrates how to protect Python tool functions with AriKernel's
@protect_tool decorator. Every call is routed through the sidecar,
which enforces policy and executes the tool via its own executors.

Prerequisites:
    # Start the sidecar
    pnpm build && pnpm sidecar

    # Install the Python client
    pip install -e python/

Run:
    python examples/python-protect-decorator.py
"""

from arikernel import create_kernel, ToolCallDenied
from arikernel.protect import protect_tool


def main():
    # Connect to the AriKernel sidecar (port 8787)
    kernel = create_kernel(preset="safe-research")

    # Wrap tool functions with AriKernel enforcement.
    # In sidecar mode, the decorated function body is NOT called —
    # the sidecar's own executors handle tool execution.

    @protect_tool("http.read", kernel=kernel)
    def fetch_url(url: str) -> str:
        """Fetch a URL — sidecar executes this via HttpExecutor."""
        # This body is NOT called in sidecar mode.
        return f"<response from {url}>"

    @protect_tool("file.read", kernel=kernel)
    def read_file(path: str) -> str:
        """Read a file — sidecar executes this via FileExecutor."""
        # This body is NOT called in sidecar mode.
        return f"<contents of {path}>"

    print("=" * 50)
    print("  Python @protect_tool — AriKernel Demo")
    print("=" * 50)

    # Call 1: Allowed HTTP GET
    print("\nCall 1: fetch_url('https://api.example.com/data')")
    try:
        result = fetch_url(url="https://api.example.com/data")
        print(f"  ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"  BLOCKED — {e.reason}")

    # Call 2: Allowed file read
    print("\nCall 2: read_file('./data/config.json')")
    try:
        result = read_file(path="./data/config.json")
        print(f"  ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"  BLOCKED — {e.reason}")

    # Call 3: Blocked file read (outside allowed paths)
    print("\nCall 3: read_file('/etc/passwd')")
    try:
        result = read_file(path="/etc/passwd")
        print(f"  ALLOWED — {result}")
    except ToolCallDenied as e:
        print(f"  BLOCKED — {e.reason}")

    kernel.close()

    print("\nAll decisions are recorded in the sidecar's audit log.")
    print("Use 'arikernel trace --latest' to review.\n")


if __name__ == "__main__":
    try:
        main()
    except ConnectionError as e:
        print(f"\nERROR: {e}")
        print("The sidecar must be running for Python enforcement.")
        print("Start it with: pnpm build && pnpm sidecar\n")
