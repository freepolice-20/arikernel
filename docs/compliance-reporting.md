# Compliance Reporting

Generate structured compliance and evidence reports for security reviews, release checklists, and customer security questionnaires.

## CLI Usage

```bash
# Human-readable summary (default)
arikernel compliance-report

# JSON output (for programmatic consumption)
arikernel compliance-report --json

# Markdown output (for documentation / reports)
arikernel compliance-report --markdown
```

## Report Sections

### Deployment

- **Mode**: `dev` or `secure` — detected from config files
- **Control Plane**: Whether `@arikernel/control-plane` is available
- **Sidecar Auth**: Authentication mode for sidecar enforcement proxy

### Policy

- **Files Found**: Policy files detected in the project
- **Version**: Policy version label (from YAML `version:` field)
- **Hash**: SHA-256 prefix of the policy content for integrity verification

### Security Protections

The report lists the status of each major protection:

| Protection | Description |
|------------|-------------|
| Taint Tracking | Cross-tool data flow tracking with auto-propagation |
| Behavioral Rules | Sequence detection for multi-step attacks |
| Audit Logging | Hash-chained audit trail of all decisions |
| Signed Receipts | Ed25519-signed decision receipts (requires control plane) |
| Replay Protection | Nonce-based replay attack prevention (requires control plane) |
| Output Filtering (DLP) | Secret pattern detection in tool outputs |
| SSRF Protection | Private IP blocking and redirect validation |
| Path Traversal Protection | Symlink resolution and path allowlist enforcement |
| Capability Tokens | Time/usage/scope-limited capability grants |
| Quarantine | Irrecoverable restricted mode after suspicious behavior |

### Benchmark Coverage

Reports whether the benchmark suite is available and, if run, the breakdown of blocked/partial/allowed attack scenarios.

### Attack Simulation

Reports the number of YAML attack scenarios available for testing.

## Programmatic Usage

```typescript
import { generateComplianceReport } from "@arikernel/cli";

const report = generateComplianceReport(process.cwd());
console.log(JSON.stringify(report, null, 2));
```

## Use Cases

- **Internal security review**: Verify all protections are enabled before deployment
- **Release checklist**: Confirm policy version and hash match expectations
- **Customer security questionnaire**: Export markdown for inclusion in security documentation
- **CI/CD gate**: Run `arikernel compliance-report --json` and check required fields
