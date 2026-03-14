#!/usr/bin/env bash
# CI guard: ensure user-facing docs don't steer users to the deprecated
# legacy server (pnpm server / port 9099) outside of clearly labeled
# deprecated sections.
#
# Allowed files (already deprecated or contain guards):
#   - apps/server/**          (the deprecated server itself)
#   - python/arikernel/client.py  (deprecated FirewallClient with runtime warning)
#   - python/arikernel/sidecar.py (guard code explaining what NOT to connect to)
#   - package.json            (pnpm server script already echoes DEPRECATED)
#   - CHANGELOG.md            (historical entries)
#   - pnpm-lock.yaml          (lockfile)
#   - node_modules/**         (dependencies)
#   - scripts/check-legacy-refs.sh (this script itself)
#
# Everything else must not contain "pnpm server" or "localhost:9099"
# in a way that directs users to the legacy server.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0

# Files allowed to reference legacy server
ALLOW_PATTERN='(apps/server/|node_modules/|pnpm-lock\.yaml|package\.json|CHANGELOG\.md|python/arikernel/client\.py|python/arikernel/sidecar\.py|scripts/check-legacy-refs\.sh)'

echo "Checking for legacy server references in user-facing docs..."

# Check for "pnpm server" (but not "pnpm sidecar" or "pnpm server:dev")
# Exclude lines that contain "DEPRECATED" or "deprecated" (allowed context)
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  if echo "$file" | grep -qE "$ALLOW_PATTERN"; then
    continue
  fi
  # Skip lines that contain "deprecated" or "DEPRECATED" (allowed context)
  content=$(echo "$line" | cut -d: -f2-)
  if echo "$content" | grep -qiE 'deprecated'; then
    continue
  fi
  echo "ERROR: $line"
  ERRORS=$((ERRORS + 1))
done < <(grep -rn --include='*.md' --include='*.py' --include='*.ts' --include='*.js' --include='*.yml' --include='*.yaml' --include='*.sh' 'pnpm server' "$REPO_ROOT" 2>/dev/null | grep -v 'pnpm sidecar' || true)

# Check for "localhost:9099" outside allowed files
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  if echo "$file" | grep -qE "$ALLOW_PATTERN"; then
    continue
  fi
  content=$(echo "$line" | cut -d: -f2-)
  if echo "$content" | grep -qiE 'deprecated|legacy'; then
    continue
  fi
  echo "ERROR: $line"
  ERRORS=$((ERRORS + 1))
done < <(grep -rn --include='*.md' --include='*.py' --include='*.ts' --include='*.js' --include='*.yml' --include='*.yaml' --include='*.sh' 'localhost:9099' "$REPO_ROOT" 2>/dev/null || true)

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "FAILED: Found $ERRORS legacy server reference(s) in user-facing docs."
  echo "Update them to use 'pnpm sidecar' / port 8787, or add to the allow-list"
  echo "in scripts/check-legacy-refs.sh if the reference is in a deprecated section."
  exit 1
fi

echo "OK: No legacy server references found in user-facing docs."
