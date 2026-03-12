# Middleware — Drop-in Agent Protection

Ari Kernel middleware provides single-function wrappers that secure any AI agent framework with zero architecture changes. Wrap your agent, keep your code.

> See also: [Security Model](security-model.md) | [Architecture](../ARCHITECTURE.md)

> **Note:** Python middleware wrappers shown below are experimental and not part of the v0.1.0 release. See the main [README](../README.md#python-status) for known issues.

## Quickstart

### TypeScript

```bash
pnpm add @arikernel/middleware
```

```typescript
import { protectLangChainAgent } from "@arikernel/middleware"

const { agent, firewall } = protectLangChainAgent(myAgent, {
  preset: "safe",  // Production default — or "strict", "research"
})

// Use agent exactly as before — enforcement is transparent.
```

### Python

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
from arikernel.middleware import protect_langchain_agent

agent = protect_langchain_agent(agent, preset="safe")

# Use agent exactly as before — enforcement is transparent.
```

---

## Supported Frameworks

| Framework | TypeScript | Python | Status |
|-----------|-----------|--------|--------|
| LangChain | `protectLangChainAgent()` | `protect_langchain_agent()` | TS: stable, Python: experimental |
| OpenAI Agents SDK | `protectOpenAIAgent()` | `protect_openai_agent()` | TS: stable, Python: experimental |
| CrewAI | `protectCrewAITools()` | `protect_crewai_agent()` | TS: stable, Python: experimental |
| AutoGen | `protectAutoGenTools()` | `protect_autogen_agent()` | TS: stable, Python: experimental |

---

## LangChain

Wraps any agent with a `.tools` array. Each tool's `func` and `invoke` methods are intercepted.

### TypeScript

```typescript
import { protectLangChainAgent } from "@arikernel/middleware"

// Minimal — auto-infers tool mappings from naming patterns
const { agent, firewall } = protectLangChainAgent(myAgent)

// With explicit mappings and preset
const { agent, firewall } = protectLangChainAgent(myAgent, {
  preset: "safe-research",
  toolMappings: {
    web_search: { toolClass: "http", action: "get" },
    read_file:  { toolClass: "file", action: "read" },
  },
})
```

### Python

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
from arikernel.middleware import protect_langchain_agent

agent = protect_langchain_agent(agent, preset="safe-research")

# Or with explicit mappings
agent = protect_langchain_agent(agent,
    preset="safe-research",
    tool_mappings={
        "web_search": ("http", "get"),
        "read_file": ("file", "read"),
    },
)
```

---

## OpenAI Agents SDK

Wraps tool definitions — same schema, enforced `execute` functions.

### TypeScript

```typescript
import { protectOpenAIAgent } from "@arikernel/middleware"

const { tools, firewall } = protectOpenAIAgent(agentTools, {
  preset: "safe-research",
})

// Pass `tools` to your agent — enforcement is transparent.
```

### Python

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
from arikernel.middleware import protect_openai_agent

result = protect_openai_agent(tools, preset="safe-research")
protected_tools = result["tools"]
kernel = result["kernel"]
```

---

## CrewAI

Wraps a map of tool functions.

### TypeScript

```typescript
import { protectCrewAITools } from "@arikernel/middleware"

const { execute, firewall } = protectCrewAITools({
  web_search: async (args) => fetch(args.url).then(r => r.text()),
  read_file: async (args) => fs.readFile(args.path, "utf-8"),
}, {
  preset: "safe-research",
})

await execute("web_search", { url: "https://example.com" })  // Enforced
```

### Python

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
from arikernel.middleware import protect_crewai_agent

result = protect_crewai_agent({
    "web_search": lambda query="": search(query),
    "read_file": lambda path="": open(path).read(),
}, preset="safe-research")

result["execute"]("web_search", query="AI safety")
```

---

## AutoGen

Same API as CrewAI — wraps a map of tool functions.

### TypeScript

```typescript
import { protectAutoGenTools } from "@arikernel/middleware"

const { execute, tools, firewall } = protectAutoGenTools({
  web_search: async (args) => searchWeb(args.query),
  run_shell: async (args) => exec(args.cmd),
}, {
  preset: "safe-research",
})

await execute("web_search", { query: "test" })  // ALLOWED
await execute("run_shell", { cmd: "whoami" })    // BLOCKED
```

### Python

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
from arikernel.middleware import protect_autogen_agent

result = protect_autogen_agent({
    "web_search": lambda query="": search(query),
    "run_shell": lambda cmd="": os.popen(cmd).read(),
}, preset="safe-research")

result["execute"]("web_search", query="test")  # ALLOWED
result["execute"]("run_shell", cmd="whoami")    # BLOCKED
```

---

## Tool Mapping Inference

If `toolMappings` is omitted, the middleware auto-infers mappings from common naming patterns:

| Tool Name Pattern | Maps To |
|-------------------|---------|
| `web_search`, `web_fetch`, `http_get`, `fetch_url` | `http.get` |
| `read_file`, `file_read`, `load_file` | `file.read` |
| `write_file`, `file_write`, `save_file` | `file.write` |
| `run_shell`, `shell_exec`, `exec_command` | `shell.exec` |
| `query_db`, `sql_query`, `db_query` | `database.query` |
| `send_email`, `send_message` | `http.post` (egress) |

Tools with unrecognized names pass through unprotected unless explicitly mapped.

---

## Options

All middleware functions accept the same options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `preset` | string | zero-config defaults | Security preset (see [Security Presets](#security-presets) below) |
| `principal` | string | `"agent"` | Principal name for audit attribution |
| `auditLog` | string | `":memory:"` | Audit log path (SQLite) |
| `toolMappings` | object | auto-inferred | Explicit tool name → (toolClass, action) mapping |
| `autoTaint` | boolean | `false` | Derive taint labels from tool parameters in stub executors (e.g. hostname from URL for HTTP tools) |
| `hooks` | object | none | Firewall lifecycle hooks (TS only) |
| `allow` | object | none | Explicit capability overrides (TS only) |

---

## Security Presets

Presets are named security configurations that bundle capabilities, policy rules, and quarantine thresholds. Use them to match your agent's security posture to its deployment context.

| Preset | Use Case | Quarantine Threshold | Key Traits |
|--------|----------|---------------------|------------|
| `safe` | Production default | 5 denials | Read-only HTTP/file/DB. Blocks all tainted→shell, tainted→egress, file writes, DB mutations. |
| `strict` | High security | 3 denials | Empty HTTP host allowlist. Blocks all tainted actions at priority 5. No database access. |
| `research` | Experimentation | 20 denials | HTTP GET+POST, file read+write, DB query+exec. Shell requires approval. |
| `safe-research` | Research with guardrails | 10 denials | HTTP GET, file read, DB query. Blocks tainted shell/egress. |
| `rag-reader` | RAG pipelines | 10 denials | HTTP GET, file read. Minimal attack surface. |
| `workspace-assistant` | Dev assistants | 10 denials | HTTP GET, file read+write in workspace. DB query. |
| `automation-agent` | CI/CD automation | 10 denials | Full HTTP, file, DB, shell access with taint enforcement. |

### Usage

```typescript
// TypeScript — any middleware wrapper
const { agent, firewall } = protectLangChainAgent(myAgent, {
  preset: "safe",  // Production default
})
```

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
# Python — any middleware wrapper
agent = protect_langchain_agent(agent, preset="safe")
```

### CLI

```bash
# List all available presets
arikernel policy list

# Show details of a specific preset
arikernel policy show safe
```

---

## Firewall Access

Every middleware function returns the firewall (TS) or kernel (Python) for runtime inspection:

```typescript
const { agent, firewall } = protectLangChainAgent(myAgent)

// Check quarantine status
if (firewall.isRestricted) {
  console.log("Agent quarantined:", firewall.quarantineInfo)
}

// Replay audit trail
firewall.replay()

// Clean up
firewall.close()
```

```python
# EXPERIMENTAL — Python runtime is not part of v0.1.0 release
agent = protect_langchain_agent(agent, preset="safe-research")

if agent._arikernel.restricted:
    print("Agent quarantined")

agent._arikernel.close()
```

---

## How It Works

The middleware layer is a thin ergonomics wrapper over Ari Kernel's existing architecture:

1. Creates a kernel with the specified preset
2. Resolves tool mappings (explicit or auto-inferred)
3. Registers stub executors for each tool class
4. Wraps each tool's execution function to route through the firewall pipeline:
   - Capability check → Policy evaluation → Taint tracking → Behavioral detection → Audit logging
5. Returns the same agent interface with enforced tools

No runtime redesign. No new enforcement logic. Just developer ergonomics.

### Taint Boundary

By default, middleware wrappers enforce security policy (capabilities, taint-aware rules, behavioral detection, quarantine) but do not apply executor-level auto-taint labels because the actual tool executes outside the pipeline.

To enable taint inference in middleware mode, set `autoTaint: true`:

```typescript
const { agent, firewall } = protectLangChainAgent(myAgent, {
  preset: "safe-research",
  autoTaint: true,  // Derives web:<hostname> from HTTP URLs, etc.
})
```

With `autoTaint` enabled, stub executors derive taint labels from tool parameters:
- **HTTP tools**: extracts hostname from `url` parameter → `web:<hostname>` label
- **Database tools**: adds `tool-output:database` label
- **Other tools**: no auto-taint (supply explicit labels if needed)

This provides taint-driven behavioral detection (e.g., "web taint then sensitive read → quarantine") without requiring full pipeline integration.

For full taint propagation details, see [Security Model → Taint Propagation Boundaries](security-model.md#taint-propagation-boundaries).
