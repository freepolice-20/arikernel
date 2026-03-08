# LangChain Protected Agent — AriKernel Example

A minimal agent with web fetch and file read tools, where all tool calls are
routed through AriKernel via the adapter layer. Demonstrates a prompt injection
attack being blocked in real time, with full audit trail.

## What happens

1. Agent fetches a research webpage (allowed)
2. Page contains hidden prompt injection — agent processes tainted content
3. Injection causes agent to read `~/.ssh/id_rsa` — **blocked** by behavioral rule
4. Session enters quarantine — only read-only actions on safe paths are allowed
5. Full audit trail is written to `arikernel-audit.db`

## Run

```bash
# From this directory
npm install
npx tsx agent.ts

# View the security trace
arikernel trace --latest --db ./arikernel-audit.db

# Replay step by step
arikernel replay --latest --step --db ./arikernel-audit.db
```

Or from the monorepo root:

```bash
npx tsx examples/langchain-protected-agent/agent.ts
```

## How it works

The key pattern is `wrapTool()` — a thin wrapper that routes tool calls through
the firewall:

```typescript
import { createFirewall } from '@arikernel/runtime';

const firewall = createFirewall({ ... });

// Wrap each tool so calls go through the firewall
function wrapTool(firewall, toolClass, action, opts?) {
  return async (params) => {
    const grant = firewall.requestCapability(`${toolClass}.read`);
    if (!grant.granted) throw new Error(grant.reason);
    return firewall.execute({ toolClass, action, params, grantId: grant.grant.id, ...opts });
  };
}

const webFetch = wrapTool(firewall, 'http', 'get');
const fileRead = wrapTool(firewall, 'file', 'read');

// Use as LangChain DynamicTool functions:
// new DynamicTool({ name: "web_fetch", func: (url) => webFetch({ url }) })
```

For production use, install `@arikernel/adapters` which provides a full
`wrapTool()` and `LangChainAdapter` class.

Every call to `webFetch()` or `fileRead()` goes through AriKernel's full
enforcement pipeline: capability tokens, taint tracking, policy evaluation,
behavioral sequence detection, and audit logging.

The agent code never needs to know about AriKernel.
