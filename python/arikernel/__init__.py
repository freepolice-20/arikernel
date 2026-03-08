"""AriKernel — runtime security layer for AI agents.

Native Python runtime (no server required):

    from arikernel import create_kernel, protect_tool

    kernel = create_kernel(preset="safe-research")

    @protect_tool("file.read")
    def read_file(path: str) -> str: ...

HTTP decision server client (legacy):

    from arikernel import FirewallClient
"""

# Native runtime API
from .runtime.kernel import create_kernel, Kernel, ToolCallDenied
from .protect import protect_tool, set_default_kernel

# Legacy HTTP client API
from .types import TaintLabel, Grant, ExecuteResult
from .client import FirewallClient
from .protect import protect_tool_remote

__all__ = [
    # Native runtime
    "create_kernel",
    "Kernel",
    "protect_tool",
    "set_default_kernel",
    "ToolCallDenied",
    # Legacy HTTP client
    "FirewallClient",
    "TaintLabel",
    "Grant",
    "ExecuteResult",
    "protect_tool_remote",
]
