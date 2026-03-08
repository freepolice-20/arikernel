"""
Python @protect_tool Decorator — AriKernel Integration Example

Demonstrates how to protect Python tool functions with AriKernel's
@protect_tool decorator. Every call is checked against the firewall
decision server before the actual function executes.

Prerequisites:
    # Start the decision server
    pnpm build && pnpm server

    # Install the Python client
    pip install -e python/

Run:
    python examples/python-protect-decorator.py
"""

from arikernel import FirewallClient, ToolCallDenied
from arikernel.protect import protect_tool


def main():
    # Connect to the AriKernel decision server
    fw = FirewallClient(
        url="http://localhost:9099",
        principal="python-agent",
        capabilities=[
            {
                "toolClass": "http",
                "actions": ["get"],
                "constraints": {"allowedHosts": ["api.example.com"]},
            },
            {
                "toolClass": "file",
                "actions": ["read"],
                "constraints": {"allowedPaths": ["./data/**"]},
            },
        ],
    )

    # Wrap tool functions with AriKernel enforcement

    @protect_tool(fw, tool_class="http", action="get")
    def fetch_url(url: str) -> str:
        """Fetch a URL — only executes if AriKernel allows it."""
        # In production, this would do the actual HTTP request
        return f"<response from {url}>"

    @protect_tool(fw, tool_class="file", action="read")
    def read_file(path: str) -> str:
        """Read a file — only executes if AriKernel allows it."""
        # In production, this would read the actual file
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

    fw.close()

    print("\nAll decisions are recorded in the server's audit log.")
    print("Use 'arikernel trace --latest' to review.\n")


if __name__ == "__main__":
    main()
