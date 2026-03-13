"""AriKernel — runtime security layer for AI agents.

Sidecar-authoritative enforcement (default — production):

    from arikernel import create_kernel, protect_tool

    kernel = create_kernel(preset="safe-research")
    # → connects to TypeScript sidecar at localhost:8787
    # → ALL security decisions delegated to the sidecar

    @protect_tool("file.read", kernel=kernel)
    def read_file(path: str) -> str: ...

Local enforcement (dev/testing only):

    kernel = create_kernel(preset="safe-research", mode="local")
"""

# Primary API — works with both sidecar and local kernels
from .runtime.kernel import create_kernel, Kernel, ToolCallDenied, ApprovalRequiredError
from .protect import protect_tool, set_default_kernel

# Sidecar kernel (the default enforcement path)
from .sidecar import SidecarKernel

# Types
from .types import TaintLabel, Grant, ExecuteResult

# Low-level HTTP client (use SidecarKernel via create_kernel() instead)
from .client import FirewallClient
from .protect import protect_tool_remote

__all__ = [
    # Primary API
    "create_kernel",
    "protect_tool",
    "set_default_kernel",
    "ToolCallDenied",
    "ApprovalRequiredError",
    # Kernel classes
    "SidecarKernel",
    "Kernel",
    # Types
    "TaintLabel",
    "Grant",
    "ExecuteResult",
    # Low-level
    "FirewallClient",
    "protect_tool_remote",
]
