# MCP Integration

AriKernel provides a first-class adapter for the **Model Context Protocol (MCP)** — the standard Anthropic tool-call interface used by Claude and compatible agent frameworks.

`protectMCPTools()` wraps a set of MCP tools and routes every `callTool()` invocation through the full AriKernel enforcement pipeline before the tool executes.

---

## Why this matters

Without enforcement, an MCP tool set has no security boundary. An agent (or injected instruction) can call any registered tool with any arguments. AriKernel interposes at the execution boundary: capability token check → taint/provenance check → policy evaluation → behavioral rule evaluation → audit log append.

The MCP adapter does not inspect the model's text output. It operates on typed, schema-validated tool calls. The agent cannot reason its way around enforcement because enforcement happens _after_ reasoning and _before_ execution.

---

## Quick start

```ts
import { createFirewall } from '@arikernel/runtime';
import { protectMCPTools } from '@arikernel/mcp-adapter';
import type { MCPTool } from '@arikernel/mcp-adapter';

// 1. Define your MCP tools
const searchTool: MCPTool = {
  name: 'web_search',
  description: 'Search the web',
  inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
  async execute(args) {
    // ... real implementation
    return { results: [] };
  },
};

// 2. Create an AriKernel firewall
const firewall = createFirewall({
  principal: { name: 'my-agent', capabilities: [] },
  policies: './policies/safe-defaults.yaml',
  auditLog: './audit.db',
});

// 3. Protect your tools
const mcp = protectMCPTools(firewall, [searchTool]);

// 4. Call tools through the protected surface
const result = await mcp.callTool('web_search', { query: 'AI safety' });
```

---

## API

### `protectMCPTools(firewall, tools)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `firewall` | `Firewall` | An initialised AriKernel `Firewall` instance. |
| `tools`    | `MCPTool[]` | MCP tools to register and protect. |

Returns an `MCPAdapter`:

```ts
interface MCPAdapter {
  callTool(name: string, args: Record<string, unknown>): Promise<unknown>;
  listTools(): Array<Omit<MCPTool, 'execute'>>;
}
```

`callTool` throws if:
- The call is **denied** by policy (policy decision is `deny`)
- The call requires an **unmet capability** (token not held or expired)
- The session is in **restricted mode** (behavioral quarantine)
- The **tool itself throws** during execution

### `MCPTool`

```ts
interface MCPTool {
  name: string;           // maps to toolCall.action
  description?: string;
  inputSchema?: Record<string, unknown>;
  execute(args: Record<string, unknown>): Promise<unknown>;
}
```

---

## Tool call mapping

Each `callTool(name, args)` invocation is mapped to an AriKernel `ToolCallRequest`:

| MCP field | AriKernel field |
|-----------|-----------------|
| (adapter) | `toolClass: 'mcp'` |
| `name`    | `action: name` |
| `args`    | `parameters: args` |

This means policy rules can target MCP tools by `toolClass: mcp` (all MCP tools) or by action name for finer-grained control.

---

## Automatic taint labeling

MCP tool outputs are automatically tainted based on input arguments, without any manual annotation required:

| Argument present | Taint applied |
|-----------------|---------------|
| `url` or `endpoint` | `web:<hostname>` |
| `source` or `collection` | `rag:<source>` |
| Neither | `tool-output:mcp` |

This ensures that data flowing from MCP tools carries accurate provenance labels for downstream enforcement. A subsequent write or shell call carrying a `web` taint will be blocked by the `deny-tainted-shell` and `deny-tainted-file-write` rules in `safe-defaults.yaml`.

---

## Policy configuration

The `safe-defaults.yaml` policy includes an `allow-mcp` rule (priority 250) that permits all MCP tool calls by default. You can override this with your own rules:

```yaml
rules:
  # Deny MCP tools that appear to fetch external URLs
  - id: deny-mcp-web-tainted
    priority: 5
    match:
      toolClass: mcp
      taintSources: [web]
    decision: deny
    reason: "Deny MCP calls with web taint"

  # Allow only specific MCP tools
  - id: allow-known-mcp
    priority: 10
    match:
      toolClass: mcp
      action: [web_search, rag_lookup]
    decision: allow
    reason: "Only whitelisted MCP tools allowed"

  # Deny everything else
  - id: deny-unknown-mcp
    priority: 999
    match:
      toolClass: mcp
    decision: deny
    reason: "Unknown MCP tool"
```

---

## Behavioral quarantine

MCP tool calls participate in the same behavioral rule evaluation as all other tool calls. If the session has entered **restricted mode** (e.g., via the `sensitive_read_then_egress` rule), all non-read-only MCP tool calls are denied for the remainder of the session.

The MCP adapter does not require any special configuration for this — it is automatic, because `callTool` routes through `firewall.execute()`, which passes through the full enforcement pipeline including run-level state.

---

## Audit trail

Every MCP tool call — allowed or denied — is recorded in the tamper-evident audit log with:

- Tool name (`action`)
- Arguments (`parameters`)
- Decision (`allow` / `deny` / `quarantine`)
- Taint labels
- Timestamp and SHA-256 hash chain position

Use `arikernel replay --db ./audit.db` to inspect the full decision history.

---

## Advanced: custom executor

`McpDispatchExecutor` is exported for use cases where you need to register tools incrementally or integrate with an existing executor registry:

```ts
import { McpDispatchExecutor } from '@arikernel/mcp-adapter';

const executor = new McpDispatchExecutor();
executor.register(myTool);
firewall.registerExecutor(executor);
```

Note: `protectMCPTools()` calls `firewall.registerExecutor()` internally. Only register one `McpDispatchExecutor` per firewall instance.
