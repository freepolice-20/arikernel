# Ari Kernel — Python Runtime

Native Python runtime for [Ari Kernel](https://github.com/petermanrique101-sys/AriKernel). Enforces capability tokens, taint-aware policies, behavioral quarantine, and tamper-evident audit logging — all in-process, no TypeScript server required.

## Install

```bash
pip install -e python/
```

## Usage

```python
from arikernel import create_kernel, protect_tool

kernel = create_kernel(preset="safe-research", audit_log="./audit.db")

@protect_tool("file.read", kernel=kernel)
def read_file(path: str) -> str:
    return open(path).read()

@protect_tool("http.read", kernel=kernel)
def fetch_url(url: str) -> str:
    return httpx.get(url).text

read_file(path="./data/report.csv")    # ALLOWED
read_file(path="/etc/shadow")          # DENIED (path constraint)
fetch_url(url="https://example.com")   # ALLOWED
```

## API

- `create_kernel(preset, principal, audit_log, ...)` — create enforcement kernel
- `@protect_tool("capability.class", kernel=kernel)` — decorator to protect a tool function
- `kernel.execute_tool(tool_class, action, parameters, ...)` — direct execution with enforcement
- `kernel.request_capability(capability_class)` — request a capability token
- `kernel.close()` — end session, finalize audit log
- Context manager support (`with create_kernel(...) as kernel:`)

## Audit Compatibility

Python audit logs use the same SQLite schema and SHA-256 hash chain as the TypeScript runtime. Trace and replay with the CLI:

```bash
pnpm ari trace --latest --db ./audit.db
pnpm ari replay --latest --verbose --db ./audit.db
```

## Alternative: HTTP Decision Server

For environments that need centralized enforcement via the TypeScript server:

```bash
pip install -e "python/[server]"
```

```python
from arikernel import FirewallClient

fw = FirewallClient(url="http://localhost:9099", principal="my-agent", capabilities=[...])
```

See the main [README](../README.md) for full documentation.
