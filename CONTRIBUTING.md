# Contributing to AriKernel

Thank you for your interest in contributing to AriKernel. This document covers guidelines for contributing code, reporting issues, and security considerations.

## Getting Started

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
cd AriKernel
pnpm install
pnpm build
pnpm test
```

### Requirements

- Node.js >= 20.0.0
- pnpm 9.x (corepack-managed)

## Development Workflow

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Ensure `pnpm build && pnpm test` passes
4. Run `pnpm lint` and fix any issues
5. Submit a pull request

## Code Style

- TypeScript strict mode, ESM only
- Biome for lint + format (tab indentation, 100 char line width)
- Keep files under 200-300 LOC
- No unnecessary abstractions or over-engineering

## Project Structure

```
packages/
  core/           # Types, presets, constants
  policy-engine/  # Policy rule evaluation
  taint-tracker/  # Taint propagation and labeling
  runtime/        # Kernel, firewall, pipeline, issuer
  audit-log/      # SQLite-backed audit trail
  adapters/       # Framework-specific tool adapters
  middleware/     # Drop-in middleware wrappers
  sidecar/        # HTTP enforcement proxy
  attack-sim/     # Attack simulation scenarios
apps/
  cli/            # CLI tool
```

## Testing

- Vitest for all tests
- Test files go in `__tests__/` directories within each package
- Run a specific package's tests: `pnpm test --filter=@arikernel/runtime`

## Security Contributions

AriKernel is a security tool. Contributions that affect enforcement behavior require extra care:

- **Constraint changes**: Grants must only narrow, never broaden. Intersection semantics are mandatory.
- **Taint propagation**: Ensure taint labels are never silently dropped in new code paths.
- **Policy evaluation**: Priority ordering must be deterministic and documented.
- **Sidecar changes**: The server must default to `127.0.0.1` binding. Network exposure requires explicit opt-in.

If you find a security vulnerability, **do not open a public issue**. Email [security@arikernel.dev](mailto:security@arikernel.dev) or see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Pull Request Guidelines

- Keep PRs focused on a single concern
- Include tests for new functionality
- Update docs if behavior changes
- Commit messages: concise, describe the "why" not the "what"

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

## Contact

- General questions: [contact@arikernel.dev](mailto:contact@arikernel.dev)
- Maintainers: [maintainers@arikernel.dev](mailto:maintainers@arikernel.dev)
- Security issues: [security@arikernel.dev](mailto:security@arikernel.dev)
