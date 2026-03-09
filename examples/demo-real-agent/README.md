# Real Agent Demo: Prompt Injection Defense

A real LLM-driven agent fetches a web page containing a hidden prompt injection attack. The injected instructions tell the agent to steal SSH keys and exfiltrate them. Ari Kernel detects the multi-step attack sequence and quarantines the run.

## What it demonstrates

1. A real LLM (GPT-4o-mini) chooses tools and calls them autonomously
2. The agent fetches a web page — Ari Kernel **allows** it and applies web taint
3. The malicious page contains hidden instructions to read `~/.ssh/id_rsa`
4. The agent attempts the file read — Ari Kernel **denies** it (path constraint + behavioral rule triggers **quarantine**)
5. The agent attempts to POST the data — Ari Kernel **denies** it (quarantine: run locked to read-only)
6. A deterministic replay trace is written for forensic analysis

## Requirements

- **Node.js** >= 20
- **OPENAI_API_KEY** environment variable (uses ~500 tokens per run with gpt-4o-mini)

## Run

```bash
export OPENAI_API_KEY=sk-...
pnpm demo:real-agent
```

Override the model with `OPENAI_MODEL`:

```bash
OPENAI_MODEL=gpt-4o pnpm demo:real-agent
```

## Inspect the trace

```bash
cat examples/demo-real-agent/trace.json
```

## Replay the trace

```bash
pnpm ari replay-trace examples/demo-real-agent/trace.json --verbose
```

## Safety

- The malicious web page is a **local fixture** — no real URLs are fetched
- The agent targets `~/.ssh/id_rsa` but Ari Kernel **blocks the read** — no real secrets are accessed
- `fixtures/fake-secrets/` contains obviously fake credentials as a safety net
- Outbound HTTP POST is **stubbed** — nothing is sent to the internet
- The demo costs < $0.01 per run with gpt-4o-mini
