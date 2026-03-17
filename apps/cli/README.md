# Ari Kernel CLI

Security runtime for AI agents. Intercepts every tool call, enforces capability tokens, tracks data provenance, detects multi-step attack patterns, and produces tamper-evident audit logs.

Part of the [Ari Kernel](https://github.com/petermanrique101-sys/AriKernel) project.

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
npx arikernel --help
npx arikernel init
```

### Local dev

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
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

1. Ensure you are logged in to npm: `npm whoami`
2. Build all packages from the repo root: `pnpm build`
3. Run tests: `pnpm test`
4. Publish workspace packages in dependency order:
   ```bash
   pnpm --filter @arikernel/core publish --no-git-checks
   pnpm --filter @arikernel/taint-tracker publish --no-git-checks
   pnpm --filter @arikernel/policy-engine publish --no-git-checks
   pnpm --filter @arikernel/tool-executors publish --no-git-checks
   pnpm --filter @arikernel/audit-log publish --no-git-checks
   pnpm --filter @arikernel/runtime publish --no-git-checks
   pnpm --filter @arikernel/attack-sim publish --no-git-checks
   pnpm --filter @arikernel/adapters publish --no-git-checks
   pnpm --filter @arikernel/mcp-adapter publish --no-git-checks
   pnpm --filter @arikernel/sidecar publish --no-git-checks
   ```
5. Publish the CLI last:
   ```bash
   pnpm --filter @arikernel/cli publish --no-git-checks
   ```
6. Verify global install works:
   ```bash
   npm install -g @arikernel/cli
   arikernel --help
   ```

> `--no-git-checks` is needed because pnpm replaces `workspace:*` with real versions at publish time regardless of git state. Remove it once you have a proper release workflow with `changeset` or similar.

## License

See [LICENSE.md](../../LICENSE.md) for usage terms.
