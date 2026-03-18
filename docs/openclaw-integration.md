# ARI Kernel — OpenClaw Integration

Integrates ARI Kernel's runtime security enforcement into [OpenClaw](https://openclaw.ai) as a plugin.

## What it does

- **Sidecar security process** — ARI Kernel runs as a separate HTTP server (port 8787). Enforcement is out-of-process, so even a compromised agent cannot bypass it.
- **Policy injection** — Security rules are appended to the agent's system prompt every turn.
- **`ari_check` tool** — The agent calls this before sensitive actions (shell, file writes, HTTP mutations) to get an allow/deny decision from ARI Kernel before proceeding.
- **`/ari-status` command** — Check current security posture, counters, and quarantine state from any channel.
- **Audit log** — All decisions written to `~/.openclaw/ari-kernel/audit.db` (SQLite).

## Prerequisites

- [OpenClaw](https://openclaw.ai) installed and running
- Node.js **v20 or later** (v22 recommended)
- ARI Kernel cloned and dependencies installed:
  ```bash
  git clone <this repo>
  cd "Ari Kernel"
  pnpm install
  pnpm build
  ```

> **Important — Native module rebuild**
> `better-sqlite3` is a native Node addon. If you see `500 Internal server error` from the sidecar,
> run `pnpm rebuild better-sqlite3` from the repo root. This is required when your Node version
> differs from the one used to build the prebuilt binary. The `postinstall` script handles this
> automatically on a clean `pnpm install`.

## Installation

### 1. Copy the plugin to OpenClaw's extensions directory

```bash
# Windows
xcopy /E /I "openclaw-plugin" "%USERPROFILE%\.openclaw\extensions\ari-kernel"

# macOS / Linux
cp -r openclaw-plugin ~/.openclaw/extensions/ari-kernel
```

Or create `~/.openclaw/extensions/ari-kernel/` manually and copy:
- `index.ts`
- `openclaw.plugin.json`
- `package.json`

Then install plugin dependencies:
```bash
cd ~/.openclaw/extensions/ari-kernel
npm install
```

### 2. Edit `index.ts` — set your ARI Kernel path

Near the top of `index.ts`, update `ARI_KERNEL_DIR` to point at where you cloned this repo:

```ts
const ARI_KERNEL_DIR = "/path/to/Ari Kernel";  // ← change this
```

### 3. Enable the plugin in OpenClaw config

Add to your `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "allow": ["ari-kernel"],
    "entries": {
      "ari-kernel": {
        "enabled": true,
        "config": {
          "preset": "workspace-assistant",
          "port": 8787
        }
      }
    }
  }
}
```

### 4. Restart the Gateway

```bash
openclaw gateway restart
```

The sidecar starts automatically with the Gateway.

## Verify it's working

```bash
# Health check
curl http://127.0.0.1:8787/health
# → {"status":"ok","service":"arikernel-sidecar"}

# Or use the slash command in any channel:
/ari-status
```

## Security presets

| Preset | Shell | File write | HTTP GET | HTTP POST | Use case |
|--------|-------|------------|----------|-----------|----------|
| `workspace-assistant` | Approval required | Workspace only | ✅ | ❌ | Coding agents |
| `safe` | ❌ Blocked | ❌ Blocked | ✅ | ❌ | Read-only assistants |
| `strict` | ❌ Blocked | ❌ Blocked | Host-allowlisted | ❌ | High-security |
| `research` | Approval required | ✅ | ✅ | ✅ | Dev/testing |

Change `preset` in `openclaw.json` under `plugins.entries.ari-kernel.config`.

## How taint tracking works

ARI Kernel labels data that comes from untrusted sources (`web`, `email`, `rag`).
If tainted data flows into a shell command or file write, the action is automatically blocked —
even if the agent was instructed to do it. This stops prompt injection attacks cold.

The agent declares taint when calling `ari_check`:
```
toolClass: "shell"
action: "exec"
taint: ["web"]   ← input came from a web search result
```
ARI Kernel then enforces based on the policy.

## Troubleshooting

**Sidecar returns 500**
Run `pnpm rebuild better-sqlite3` in the ARI Kernel root. This is a Node version mismatch on the native SQLite module.

**Plugin shows `error` in `openclaw plugins list`**
Check that `@sinclair/typebox` is installed: `cd ~/.openclaw/extensions/ari-kernel && npm install`

**Plugin not discovered**
Ensure `plugins.allow` contains `"ari-kernel"` in your `openclaw.json`.

**Sidecar doesn't start**
Check that `ARI_KERNEL_DIR` in `index.ts` points at the correct path and `start-sidecar.mjs` exists there.
