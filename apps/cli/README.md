# arikernel

Security runtime for AI agents. Intercepts every tool call, enforces capability tokens, tracks data provenance, detects multi-step attack patterns, and produces tamper-evident audit logs.

Part of the [AriKernel](https://github.com/petermanrique101-sys/AriKernel) project.

## Install

### Global (recommended)

```bash
npm install -g arikernel
```

Then use it anywhere:

```bash
arikernel --help
arikernel init
arikernel policy arikernel.policy.yaml
arikernel simulate --policy arikernel.policy.yaml
arikernel run --policy arikernel.policy.yaml
arikernel replay --latest --verbose --db ./audit.db
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
node apps/cli/dist/main.js --help
```

## Commands

| Command | Description |
|---------|-------------|
| `arikernel init` | Generate a starter `arikernel.policy.yaml` |
| `arikernel policy <file>` | Validate a policy YAML file |
| `arikernel run` | Start the firewall in run mode |
| `arikernel simulate` | Run attack simulations against a policy |
| `arikernel replay [runId]` | Replay a run from the audit log |

## Requirements

- Node.js >= 20

## Scoped package fallback

If `arikernel` is unavailable on npm, the package can be published as `@arikernel/cli` instead. The `bin` field ensures the command is still `arikernel`:

```json
{
  "name": "@arikernel/cli",
  "bin": { "arikernel": "dist/main.js" }
}
```

Users would install with:

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
   pnpm --filter arikernel publish --no-git-checks
   ```
7. Verify global install works:
   ```bash
   npm install -g arikernel
   arikernel --help
   ```

> `--no-git-checks` is needed because pnpm replaces `workspace:*` with real versions at publish time regardless of git state. Remove it once you have a proper release workflow with `changeset` or similar.

## License

Apache-2.0
