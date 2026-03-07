# Agent Firewall — Python Client

Python client for [Agent Firewall](https://github.com/petermanrique101-sys/Agent-Firewall), a runtime security layer for AI agents.

## v1 Scope — Important

This v1 Python adapter is a **decision/enforcement API layer** over the TypeScript core:

- The server decides **allow or deny** and writes every decision to a tamper-evident audit log
- **Actual tool execution still occurs in your Python code** after receiving an allow verdict
- This is a first integration step, not a full mediation model
- A future version may add server-side tool execution for full runtime mediation

## Install

```bash
pip install -e python/
```

## Usage

Start the server (from repo root):

```bash
pnpm build && pnpm server
```

Use the client:

```python
from agent_firewall import FirewallClient, ToolCallDenied

with FirewallClient(
    url="http://localhost:9099",
    principal="my-agent",
    capabilities=[
        {"toolClass": "http", "actions": ["get"],
         "constraints": {"allowedHosts": ["api.github.com"]}},
    ],
) as fw:
    grant = fw.request_capability("http.read")
    if grant.granted:
        result = fw.execute("http", "get",
            {"url": "https://api.github.com/repos/example"},
            grant_id=grant.grant_id)
        # result.verdict == "allow" -> now execute your actual HTTP call
```

## API

- `FirewallClient(url, principal, capabilities)` — create session
- `.request_capability(class, taint_labels)` — request token
- `.execute(tool_class, action, parameters, grant_id, taint_labels)` — check decision
- `.revoke_grant(grant_id)` — revoke a token
- `.close()` — end session
- Context manager support (`with` statement)
