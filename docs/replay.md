# Deterministic Attack Replay

> See also: [Security Model](security-model.md) | [Threat Model](threat-model.md) | [Benchmarks](benchmarks.md)

## Overview

Ari Kernel can record a full security-relevant run as a JSON trace file, then replay it through a fresh kernel instance to verify that every enforcement decision is deterministic. Same inputs, same policy, same decisions — every time.

This is useful for:

- **Forensic analysis** — replay a suspicious run and inspect every decision
- **Regression testing** — verify that policy changes don't alter expected decisions
- **What-if analysis** — replay a trace with a different policy or preset to see how decisions change
- **Compliance evidence** — prove that security decisions are consistent and reproducible

## What Replay Proves

Given a recorded trace and a policy, replay answers four questions:

1. **What happened** — the exact sequence of tool calls the agent made during the run
2. **Why it happened** — which policy rules matched, which capabilities were granted or denied, and which taint labels propagated
3. **Why it was denied or quarantined** — the specific rule, behavioral pattern, or threshold that triggered enforcement
4. **Whether a different policy changes the outcome** — swap the policy or preset and replay again to see which decisions diverge

This makes replay useful for post-incident forensics, policy regression testing, and compliance evidence.

## How It Works

### 1. Record a Trace

The `TraceRecorder` hooks into the kernel's `FirewallHooks` to capture events non-intrusively during a live run.

```typescript
import { createFirewall, TraceRecorder, writeTrace } from '@arikernel/runtime';

const recorder = new TraceRecorder({
  description: 'prompt injection test scenario',
  preset: 'safe-research',
});

const firewall = createFirewall({
  principal: { name: 'agent', capabilities: [...] },
  policies: './policy.yaml',
  hooks: recorder.hooks,
  runStatePolicy: { behavioralRules: true },
});

// ... run the scenario, calling firewall.execute() ...

// After each step, update counters for the trace
recorder.updateCounters(firewall.runStateCounters);

// Finalize and write
const trace = recorder.finalize(
  firewall.runId,
  firewall.quarantineInfo,
  firewall.runStateCounters,
);
writeTrace(trace, './traces/scenario-001.json');
firewall.close();
```

### 2. Replay the Trace

The replay engine creates a fresh kernel, feeds the recorded requests through it, and compares every decision.

```typescript
import { readTrace, replayTrace } from '@arikernel/runtime';

const trace = readTrace('./traces/scenario-001.json');
const result = await replayTrace(trace);

console.log(result.allMatched);        // true = deterministic
console.log(result.quarantineMatched); // true = same quarantine state
console.log(result.summary);          // { totalEvents, matched, mismatched, ... }
```

### 3. CLI Replay

```bash
# Replay a trace file
pnpm ari replay-trace ./traces/scenario-001.json --verbose

# What-if: replay with a different preset
pnpm ari replay-trace ./traces/scenario-001.json --preset workspace-assistant

# JSON output for scripting
pnpm ari replay-trace ./traces/scenario-001.json --json
```

## Trace Format

Traces are versioned JSON files. Current version: `1.0`.

```json
{
  "traceVersion": "1.0",
  "runId": "01JKXYZ...",
  "timestampStarted": "2026-03-08T...",
  "timestampCompleted": "2026-03-08T...",
  "metadata": {
    "description": "prompt injection test",
    "preset": "safe-research"
  },
  "events": [
    {
      "sequence": 0,
      "timestamp": "2026-03-08T...",
      "request": {
        "toolClass": "http",
        "action": "get",
        "parameters": { "url": "https://example.com" },
        "taintLabels": [{ "source": "web", "origin": "example.com" }]
      },
      "capabilityClass": "http.read",
      "capabilityGranted": true,
      "decision": {
        "verdict": "allow",
        "reason": "Allowed by policy",
        "taintLabels": []
      },
      "counters": { "deniedActions": 0, "..." : "..." }
    }
  ],
  "quarantines": [...],
  "outcome": {
    "totalEvents": 3,
    "allowed": 1,
    "denied": 2,
    "quarantined": true,
    "finalCounters": { "..." : "..." }
  }
}
```

## What Replay Does (and Does Not Do)

**Replays:** Security decisions — capability issuance, policy evaluation, behavioral rule matching, quarantine triggers.

**Does NOT replay:** External side effects. HTTP requests, file I/O, shell commands, and database queries are not re-executed. The replay engine stubs all executors. This means replay is safe, fast, and deterministic — it tests the enforcement logic, not the external world.

## What-If Analysis

Replay with policy or preset overrides to test how decisions would change:

```typescript
const result = await replayTrace(trace, {
  preset: 'workspace-assistant',  // Different preset
});

// result.allMatched will be false if decisions differ
for (const m of result.mismatches) {
  console.log(`Event #${m.sequence}: ${m.field} changed from '${m.original}' to '${m.replayed}'`);
}
```

## Demo

```bash
pnpm demo:replay
```

Records a behavioral quarantine scenario (web taint → sensitive read → exfiltration), writes it to `demo-trace.json`, then replays it and shows a deterministic result.

## API Reference

### TraceRecorder

```typescript
class TraceRecorder {
  readonly hooks: FirewallHooks;
  constructor(metadata?: TraceMetadata);
  updateCounters(counters: RunStateCounters): void;
  finalize(runId: string, quarantineInfo: QuarantineInfo | null, finalCounters: RunStateCounters): ReplayTrace;
}
```

### writeTrace / readTrace

```typescript
function writeTrace(trace: ReplayTrace, filePath: string): void;
function readTrace(filePath: string): ReplayTrace;
```

### replayTrace

```typescript
function replayTrace(trace: ReplayTrace, options?: ReplayEngineOptions): Promise<ReplayResult>;

interface ReplayEngineOptions {
  policies?: string | PolicyRule[];
  preset?: string;
  auditLog?: string;
}
```

### ReplayResult

```typescript
interface ReplayResult {
  trace: ReplayTrace;
  replayedEvents: ReplayedEvent[];
  allMatched: boolean;
  mismatches: ReplayMismatch[];
  quarantineMatched: boolean;
  summary: ReplaySummary;
}
```
