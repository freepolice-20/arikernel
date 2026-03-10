# Execution Environment Hardening

Ari Kernel enforces policy at the tool-call layer. For defense-in-depth, the host environment should also be hardened. This guide covers OS and container-level recommendations.

## Container Isolation

- **Rootless mode**: Run agent containers in rootless mode (Podman, Docker rootless) to prevent container escapes from gaining host root.
- **Drop capabilities**: Use `--cap-drop=ALL` and only add back what's strictly needed. Most agents need no Linux capabilities.
- **Read-only filesystem**: Use `--read-only` with explicit `tmpfs` mounts for `/tmp` and working directories.
- **Seccomp profile**: Apply a restrictive seccomp profile. Block `ptrace`, `mount`, `reboot`, and other unnecessary syscalls.
- **No privileged mode**: Never run agent containers with `--privileged`.

## Network Segmentation

- **Egress filtering**: Use Kubernetes NetworkPolicy or Docker network rules to restrict outbound traffic to approved domains only. Ari Kernel's host allowlist is a second layer — network-level filtering is the first.
- **DNS filtering**: Use a DNS resolver that blocks resolution of known-malicious domains and internal-only hostnames from agent containers.
- **Separate networks**: Place agent containers on an isolated network segment, separate from databases, secrets stores, and management planes.

## Filesystem Hardening

- **Mount sensitive dirs read-only**: If the agent needs access to config files, mount them as read-only volumes.
- **AppArmor / SELinux**: Apply mandatory access control profiles that restrict file access beyond what Ari Kernel policies enforce.
- **No Docker socket**: Never mount the Docker socket (`/var/run/docker.sock`) into agent containers. This grants full host control.
- **No host PID namespace**: Use `--pid=container` to prevent agents from seeing host processes.

## Process Limits

- **PID limits**: Use `--pids-limit` to prevent fork bombs (e.g., `--pids-limit=100`).
- **Memory and CPU**: Set `--memory` and `--cpus` limits to prevent resource exhaustion.
- **Non-root user**: Run the agent process as a non-root user inside the container (`USER` directive in Dockerfile).

## Secrets Management

- **No file-mounted secrets**: Avoid mounting API keys, tokens, or credentials as files. Use a secrets manager (Vault, AWS Secrets Manager, K8s Secrets with sidecar injection).
- **Short-lived tokens**: Use tokens with short TTLs and automatic rotation. Ari Kernel's capability leases model this pattern at the tool-call level.
- **Environment variable hygiene**: If secrets must be in env vars, use init containers or entrypoint scripts that fetch and inject them, then clear the env after startup.

## Runtime Monitoring

- **Forward audit logs**: Ship Ari Kernel audit logs to an external SIEM or log aggregator. The audit chain provides tamper-evidence but is not tamper-proof without external anchoring.
- **Falco / runtime detection**: Use Falco or equivalent for real-time anomaly detection (unexpected network connections, file access patterns, privilege escalation).
- **Alert on quarantine**: Set up alerts for quarantine events — these indicate an active attack or severely misconfigured agent.
- **Hash chain anchoring**: Periodically checkpoint the audit log's hash chain root to an external, immutable store (e.g., append-only S3 bucket, blockchain timestamping service).

## MCP and Multi-Agent Deployments

- **Separate containers**: Run MCP tool servers in separate containers from the agent. Use network policies to restrict which agents can reach which tools.
- **Taint propagation**: Use Ari Kernel's taint bridge (`createTaintBridgeTool`) to ensure taint context propagates across agent boundaries.
- **Per-agent principals**: Each agent should have its own principal with minimal capabilities. Never share principals across agents.

## Quick Reference Checklist

```
[ ] Container runs rootless with --cap-drop=ALL
[ ] Filesystem is --read-only with explicit tmpfs
[ ] Network egress restricted to approved domains
[ ] No Docker socket, no --privileged
[ ] Memory/CPU/PID limits set
[ ] Agent runs as non-root user
[ ] Secrets fetched from secrets manager, not mounted
[ ] Audit logs forwarded to external SIEM
[ ] Quarantine alerts configured
[ ] MCP tools in separate containers with network policies
```

See also: [Security Model](security-model.md) for Ari Kernel's policy and quarantine design.
