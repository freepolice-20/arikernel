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
| `arikernel run` | Start the firewall in run mode |
| `arikernel policy <file>` | Validate a policy YAML file |
| `arikernel init` | Generate a starter `arikernel.policy.yaml` |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

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
2. Ensure the `arikernel` package name is available: `npm view arikernel` (should 404)
3. Build all packages from the repo root: `pnpm build`
4. Run tests: `pnpm test`
5. Publish workspace packages in dependency order:
   ```bash
   pnpm --filter @arikernel/core publish --no-git-checks
   pnpm --filter @arikernel/taint-tracker publish --no-git-checks
   pnpm --filter @arikernel/policy-engine publish --no-git-checks
   pnpm --filter @arikernel/tool-executors publish --no-git-checks
   pnpm --filter @arikernel/audit-log publish --no-git-checks
   pnpm --filter @arikernel/runtime publish --no-git-checks
   pnpm --filter @arikernel/attack-sim publish --no-git-checks
   ```
6. Publish the CLI last:
   ```bash
   pnpm --filter @arikernel/cli publish --no-git-checks
   ```
7. Verify global install works:
   ```bash
   npm install -g arikernel
   arikernel --help
   ```

> `--no-git-checks` is needed because pnpm replaces `workspace:*` with real versions at publish time regardless of git state. Remove it once you have a proper release workflow with `changeset` or similar.

## License

Apache-2.0
