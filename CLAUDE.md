# Agent Firewall - Claude Code Instructions

## Git Commits
- NEVER include `Co-Authored-By` lines referencing Claude or Anthropic
- NEVER set git config user.name or user.email to Claude or Anthropic values
- Commit messages should be concise and describe the "why", not the "what"

## Code Style
- TypeScript strict mode, ESM only
- Biome for lint + format (tab indentation, 100 char line width)
- Files under 200-300 LOC
- No unnecessary abstractions or over-engineering

## Project Structure
- pnpm monorepo with Turborepo
- Packages: core, policy-engine, taint-tracker, audit-log, tool-executors, runtime, attack-sim
- Apps: cli
- All packages export from `src/index.ts`, build with tsup

## Testing
- Vitest for all tests
- Test files in `__tests__/` directories within each package
