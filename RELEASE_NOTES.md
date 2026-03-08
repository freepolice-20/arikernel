# AriKernel v0.2.2 — Deterministic Forensic Demo Flow

## What changed

### Forensic pipeline alignment

`simulate`, `trace`, and `replay` now share the same default audit database (`./arikernel-audit.db`). Previously, `simulate` wrote to an in-memory database that was discarded after the process exited. Now the full chain works end-to-end:

```bash
arikernel simulate prompt-injection   # writes to ./arikernel-audit.db
arikernel trace --latest              # reads from same DB
arikernel replay --latest --step      # replays from same DB
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

## Package versions

| Package | Version |
|---------|---------|
| `arikernel` (CLI) | 0.2.2 |
| `@arikernel/runtime` | 0.1.2 |
| `@arikernel/attack-sim` | 0.1.2 |
| `@arikernel/audit-log` | 0.1.1 |

## Upgrading

```bash
npm install -g arikernel@0.2.2
```

If you have a stale `arikernel-audit.db` from a previous version, delete it before running simulations:

```bash
rm arikernel-audit.db
arikernel simulate prompt-injection
```
