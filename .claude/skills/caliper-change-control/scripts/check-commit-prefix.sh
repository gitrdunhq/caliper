#!/usr/bin/env bash
# check-commit-prefix.sh — verify a commit subject uses an allowed conventional-commit
# prefix (per AGENTS.md "Commit Discipline" / CLAUDE.md "Commit Message Discipline").
#
# Usage:
#   bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh          # checks HEAD
#   bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh <ref>     # checks a ref
#   bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh -m "feat: add X"  # checks a literal message
#
# Exit 0 = allowed prefix found. Exit 1 = missing/disallowed prefix (prints why).
# This is advisory tooling for humans/agents drafting a commit — it is NOT wired
# into CI. release-please itself is the enforcement point for semver bumps.

set -euo pipefail

ALLOWED_PREFIXES="feat|fix|chore|test|docs|refactor|ci|build|perf|revert"
# ^ feat/fix/chore/test/docs are the five documented in AGENTS.md "Commit Discipline".
#   refactor/ci/build/perf/revert are standard Conventional Commits types release-please
#   also recognizes; caliper docs don't call them out explicitly but they never bump
#   semver by default the way feat/fix do, so they are safe to allow here.

usage() {
    echo "Usage: $0 [<git-ref>] | -m \"<literal message>\"" >&2
    exit 2
}

if [[ "${1:-}" == "-m" ]]; then
    [[ $# -ge 2 ]] || usage
    SUBJECT="$2"
elif [[ $# -eq 0 ]]; then
    SUBJECT="$(git log -1 --format=%s HEAD)"
elif [[ $# -eq 1 ]]; then
    SUBJECT="$(git log -1 --format=%s "$1")"
else
    usage
fi

echo "Subject: ${SUBJECT}"

if [[ "${SUBJECT}" =~ ^(${ALLOWED_PREFIXES})(\([a-zA-Z0-9_-]+\))?(!)?:\ .+ ]]; then
    PREFIX="${BASH_REMATCH[1]}"
    echo "OK: prefix '${PREFIX}:' recognized."
    if [[ "${PREFIX}" == "feat" ]]; then
        cat >&2 <<'EOF'

REMINDER (CLAUDE.md "Commit Message Discipline"):
  feat: triggers a MINOR version bump. Use it ONLY for new user-facing
  capabilities. Config tweaks, CI fixes, and internal refactors are
  fix: or chore: — not feat:. Be conservative.
EOF
    fi
    exit 0
else
    cat >&2 <<EOF
FAIL: subject does not start with an allowed conventional-commit prefix.

Allowed: ${ALLOWED_PREFIXES}
Format:  <prefix>[(<scope>)][!]: <description>

AGENTS.md "Commit Discipline" defines the five that matter for this repo:
  feat:  new user-facing capability   -> MINOR bump
  fix:   bug/config/CI/behavior fix   -> PATCH bump
  chore: refactor/housekeeping/deps   -> no bump
  test:  test-only commit (RED phase) -> no bump
  docs:  documentation only           -> no bump
EOF
    exit 1
fi
