# Ari Kernel — Python Runtime

Python runtime for [Ari Kernel](https://github.com/petermanrique101-sys/AriKernel). Delegates **all security decisions and tool execution** to the TypeScript sidecar process, providing process-boundary isolation for mediated tool calls.

## Architecture: Sidecar-First by Design

Python support is sidecar-first by design. This ensures Python agents use the same enforcement authority as the primary Ari Kernel runtime — a single enforcement authority with multi-language clients, not multiple runtimes with drift risk.

The Python runtime uses a **sidecar-authoritative** enforcement model:

1. Python calls `create_kernel()` which connects to the TypeScript sidecar over HTTP
2. Every `execute_tool()` / `request_capability()` call is sent to the sidecar
3. The sidecar evaluates policy, checks capabilities, tracks taint, runs behavioral rules, **executes the tool via its own executors**, and logs the audit event
4. The sidecar returns the result (or a denial) — **the decorated Python function body is not called**

This provides:
- **Mediation of routed calls** — every tool call sent through the kernel is checked by the TypeScript runtime
- **Process isolation** — Python cannot modify enforcement logic (it lives in a separate process)
- **Audit integrity** — the sidecar owns the hash-chained audit log
- **Full parity** — same policy engine, same behavioral rules, same taint tracking as TypeScript

**Important:** Python code that calls OS APIs directly (e.g., `open()`, `subprocess.run()`, `httpx.get()`) without going through `protect_tool` or `execute_tool` is **not mediated**. Sidecar mode isolates the enforcement state, not the Python process itself.

## Install

```bash
pip install arikernel
```

## Quick Start

**Step 1: Start the TypeScript sidecar**

```bash
pnpm build
node -e "import('@arikernel/sidecar').then(m => m.createSidecarServer({}).listen().then(() => console.log('Sidecar listening on http://localhost:8787')))"
# → listening on http://localhost:8787
```

**Step 2: Use from Python**

```python
from arikernel import create_kernel, protect_tool

kernel = create_kernel(preset="safe-research")

@protect_tool("file.read", kernel=kernel)
def read_file(path: str) -> str:
    # In sidecar mode, this body is NOT called.
    # The sidecar's FileExecutor handles the read.
    return open(path).read()

@protect_tool("http.read", kernel=kernel)
def fetch_url(url: str) -> str:
    # In sidecar mode, this body is NOT called.
    # The sidecar's HttpExecutor handles the fetch.
    return httpx.get(url).text

read_file(path="./data/report.csv")    # ALLOWED — sidecar reads the file
read_file(path="/etc/shadow")          # DENIED by sidecar (path constraint)
fetch_url(url="https://example.com")   # ALLOWED — sidecar fetches the URL
```

### Handling `require-approval` verdicts

```python
def my_approval_handler(tool_call: dict, decision: dict) -> bool:
    """Return True to approve, False to deny."""
    print(f"Approval requested for {tool_call['toolClass']}.{tool_call['action']}")
    return input("Approve? [y/N] ").lower() == "y"

kernel = create_kernel(
    preset="safe-research",
    on_approval=my_approval_handler,
)
```

## API

- `create_kernel(preset, principal, on_approval, ...)` — connect to the TypeScript sidecar (default)
- `create_kernel(..., mode="local")` — local enforcement for dev/testing only (emits warning)
- `@protect_tool("capability.class", kernel=kernel)` — decorator to protect a tool function
- `kernel.execute_tool(tool_class, action, parameters, ...)` — direct execution with enforcement
- `kernel.request_capability(capability_class)` — request a capability token
- `kernel.close()` — end session, release sidecar resources
- Context manager support (`with create_kernel(...) as kernel:`)

## Exceptions

- `ToolCallDenied` — raised on policy denial
- `ApprovalRequiredError(ToolCallDenied)` — raised when `require-approval` verdict is denied (no handler or handler returns `False`)
- `ConnectionError` — raised when the TypeScript sidecar is not reachable

## Deployment Modes

| Mode | Usage | Isolation |
|------|-------|-----------|
| **Sidecar** (default) | `create_kernel(preset="safe-research")` | Process boundary for mediated calls — Python code that bypasses the kernel (direct OS API calls) is not mediated |
| **Local** (dev/testing) | `create_kernel(preset="safe-research", mode="local")` | In-process — cooperative enforcement, can be bypassed by Python code |
| **High assurance** | Sidecar + container egress controls + network policies | Process + OS-level isolation |

**There is no silent fallback.** If the sidecar is unreachable, `create_kernel()` raises `ConnectionError` immediately. It does not fall back to local enforcement.

### Local Mode (Dev/Testing Only)

For development and testing without running the sidecar:

```python
kernel = create_kernel(preset="safe-research", mode="local")
# ⚠️ Emits warning: local enforcement can be bypassed by Python code
```

Local mode runs the same policy engine in-process but **does not provide process-boundary isolation**. It should never be used in production.

## Audit Compatibility

The sidecar writes audit logs using the same SQLite schema and SHA-256 hash chain as the TypeScript runtime. Trace and replay with the CLI:

```bash
pnpm ari trace --latest --db ./audit.db
pnpm ari replay --latest --verbose --db ./audit.db
```

See the main [README](../README.md) for full documentation.
