#!/usr/bin/env bash
# check-env.sh — Sanity-check a fresh checkout before touching build/test scripts.
#
# Verified against the caliper repo on 2026-07-02. Read-only: makes no
# changes, runs no containers. Safe to run from repo root at any time.
#
# Usage:
#   bash .claude/skills/caliper-build-and-env/scripts/check-env.sh
#
# Exit code: 0 if every check passed, 1 if any check failed.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || exit 1

FAILED=0
pass() { printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m %s\n" "$1"; FAILED=1; }
info() { printf "  info %s\n" "$1"; }

echo "caliper dev-environment check — repo: $REPO_ROOT"
echo

# 1. uv present
if command -v uv &>/dev/null; then
    pass "uv found: $(uv --version)"
else
    fail "uv not found — install from https://docs.astral.sh/uv/"
fi

# 2. container engine present and running (either name is fine — see
#    CLAUDE.md "Container Builds": scripts auto-detect podman vs docker)
ENGINE=""
if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
fi

if [[ -z "$ENGINE" ]]; then
    fail "neither podman nor docker found on PATH"
else
    if "$ENGINE" info &>/dev/null; then
        pass "$ENGINE found and running ($("$ENGINE" --version))"
    else
        fail "$ENGINE found but not running — start the daemon/machine first"
    fi
fi

# 3. required top-level files this skill documents actually exist
for f in Dockerfile Dockerfile.test scripts/build.sh scripts/build-test.sh \
         scripts/build-push.sh scripts/verify-checksums.sh docker-compose.yml Makefile; do
    if [[ -f "$f" ]]; then
        pass "$f present"
    else
        fail "$f MISSING — this skill's guidance may be stale"
    fi
done

# 4. never run raw podman/docker build — warn if either script directory has
#    a stray manual build cached (best-effort heuristic, not authoritative)
if [[ -n "$ENGINE" ]] && "$ENGINE" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qx 'caliper:latest'; then
    info "caliper:latest image already present locally"
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
    echo "All checks passed. Next: uv sync --group dev && bash scripts/build-test.sh"
else
    echo "One or more checks failed — see FAIL lines above."
fi
exit "$FAILED"
