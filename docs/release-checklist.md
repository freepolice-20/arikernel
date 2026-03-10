# Release Checklist

Pre-release verification steps for Ari Kernel. Complete every item before tagging a release.

---

## 1. Build and Test

```bash
# Clean build from scratch
pnpm clean && pnpm build

# All TypeScript tests
pnpm test

# Python tests
cd python && python -m pytest tests/ -v && cd ..

# Live integration tests (requires OPENAI_API_KEY)
pnpm test:live
```

**Pass criteria**: All build tasks succeed (currently 14). All test suites pass (currently 28 tasks). CI runs automatically on push/PR via `.github/workflows/ci.yml` (includes npm pack smoke test and Python pytest).

---

## 2. Benchmark

```bash
pnpm benchmark:agentdojo
```

**Pass criteria**: 5/5 attacks blocked, 100% exfiltration prevented. Results written to `benchmarks/results/latest.json`.

Review the Markdown report at `benchmarks/results/latest.md` and verify the environment metadata (git SHA, version) is correct.

---

## 3. Smoke Tests

Run the core demos and verify they complete without errors:

```bash
pnpm demo:behavioral
pnpm demo:attack
pnpm demo:run-state
pnpm demo:replay
```

If `OPENAI_API_KEY` is available:

```bash
pnpm demo:real-agent
```

---

## 4. Sidecar Security Check

```bash
# Start sidecar with auth
arikernel sidecar --policy policies/arikernel-policy.yaml --auth-token test-secret &
SIDECAR_PID=$!

# Verify localhost binding (should reject from external interfaces)
# Verify health endpoint is accessible without auth
curl -s http://localhost:8787/health

# Verify auth enforcement
curl -s -X POST http://localhost:8787/execute \
  -H "Content-Type: application/json" \
  -d '{"principalId":"test","toolClass":"http","action":"get","params":{"url":"https://example.com"}}'
# Expected: 401 Unauthorized

# Verify auth works
curl -s -X POST http://localhost:8787/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-secret" \
  -d '{"principalId":"test","toolClass":"http","action":"get","params":{"url":"https://example.com"}}'
# Expected: 200 or 403 (policy denial), NOT 401

kill $SIDECAR_PID
```

---

## 5. Documentation Sanity Check

Verify these files exist and are not stale:

- [ ] `README.md` — quickstart works, links resolve, no broken examples
- [ ] `LICENSE` — Apache-2.0
- [ ] `SECURITY.md` — vulnerability reporting process
- [ ] `CONTRIBUTING.md` — setup instructions match current tooling
- [ ] `docs/security-model.md` — matches implemented behavior
- [ ] `docs/middleware.md` — preset names and function signatures match code
- [ ] `docs/sidecar-mode.md` — auth and localhost defaults documented
- [ ] `docs/benchmark-agentdojo.md` — scenario count and results match

---

## 6. Package Publish

```bash
# Verify package versions
pnpm -r exec -- node -e "const p=require('./package.json'); console.log(p.name + '@' + p.version)"

# Dry run publish
pnpm -r --filter './packages/*' exec -- npm pack --dry-run

# Publish (requires npm auth)
pnpm -r --filter './packages/*' publish --access public

# CLI publish
cd apps/cli && npm publish --access public && cd ../..
```

---

## 7. Tag and Release

```bash
# Tag
VERSION=$(node -e "console.log(require('./packages/core/package.json').version)")
git tag -a "v$VERSION" -m "Release v$VERSION"
git push origin "v$VERSION"

# Create GitHub release
gh release create "v$VERSION" \
  --title "v$VERSION" \
  --notes-file CHANGELOG.md \
  benchmarks/results/latest.json \
  benchmarks/results/latest.md
```

---

## 8. Post-Release Verification

```bash
# Verify published packages are installable
npm install @arikernel/middleware@latest
npm install @arikernel/cli@latest

# Verify CLI works
npx @arikernel/cli --help
```
