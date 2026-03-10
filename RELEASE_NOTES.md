# Ari Kernel v0.1.3 — Unknown Capability Class Guard

## What changed

### Runtime
- Unknown capability classes (e.g. `email.write`) now fail closed with a clean denial instead of crashing with a TypeError
- `requestCapability()` validates against `CAPABILITY_CLASS_MAP` before proceeding

### Adapters
- `wrapTool()` constructs complete `ToolCall` and `Decision` objects on denial instead of incomplete `as any` casts
- Denied tool calls now produce structured `ToolCallDeniedError` with valid `toolCall.id`, `toolCall.toolClass`, `decision.verdict` fields

## Package versions

| Package | Version |
|---------|---------|
| `@arikernel/runtime` | 0.1.3 |
| `@arikernel/adapters` | 0.1.1 |

---

# Ari Kernel v0.2.2 — Deterministic Forensic Demo Flow

## What changed

### Forensic pipeline alignment

`simulate`, `trace`, and `replay` now share the same default audit database (`./arikernel-audit.db`). Previously, `simulate` wrote to an in-memory database that was discarded after the process exited. Now the full chain works end-to-end:

```bash
# Global install
arikernel simulate prompt-injection   # writes to ./arikernel-audit.db
arikernel trace --latest              # reads from same DB
arikernel replay --latest --step      # replays from same DB

# Or from source
pnpm ari simulate prompt-injection
pnpm ari:trace
pnpm ari:replay:step
```

The events you see in `trace` and `replay` are exactly the events produced by `simulate`.

### Simulate output

After each simulation, the CLI prints the audit DB path and run ID:

```
Forensic data
  Audit DB: /absolute/path/to/arikernel-audit.db
  Run ID:   run_abc123
Replay this run:
  arikernel trace --latest --db ./arikernel-audit.db
  arikernel replay --latest --db ./arikernel-audit.db
```

### `--db` flag on simulate

All forensic commands now accept `--db <path>` to override the default database location, including `simulate`.

### LangChain integration example

New self-contained example at `examples/langchain-protected-agent/` demonstrating prompt injection blocked in real time with full forensic replay.

### Universal adapter layer

New framework adapters in `@arikernel/adapters` make Ari Kernel immediately usable across agent ecosystems:

- **`protectTools()`** — universal tool-map wrapper that works with any JS/TS agent loop
- **`protectOpenAITools()`** — convenience wrapper for OpenAI-style tool calling
- **`LangChainAdapter`** — polished adapter for LangChain DynamicTools
- **`CrewAIAdapter`** — adapter for CrewAI tool protection
- **`protectVercelTools()`** — adapter for Vercel AI SDK
- **`@protect_tool`** — Python decorator for protecting tool functions via the native Python runtime (no TypeScript server required). Legacy HTTP decision server mode also supported.

Ari Kernel is model-agnostic. It protects tool execution, not the model — so it works with OpenAI, Claude, Gemini, or any provider.

### New examples

- `examples/openai-tool-calling/` — OpenAI-style tool calling with Ari Kernel
- `examples/crewai-tool-protection/` — CrewAI tool protection
- `examples/generic-wrapper/` — Generic JS/TS wrapTool() pattern
- `examples/custom-agent-loop/` — Model-agnostic agent loop
- `examples/python-protect-decorator.py` — Python @protect_tool decorator

## Package versions

| Package | Version |
|---------|---------|
| `@arikernel/cli` | 0.2.2 |
| `@arikernel/runtime` | 0.1.2 |
| `@arikernel/attack-sim` | 0.1.2 |
| `@arikernel/audit-log` | 0.1.1 |

## Upgrading

```bash
npm install -g @arikernel/cli@0.2.2
```

If you have a stale `arikernel-audit.db` from a previous version, delete it before running simulations:

```bash
rm arikernel-audit.db
arikernel simulate prompt-injection
```
