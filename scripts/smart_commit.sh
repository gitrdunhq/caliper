#!/bin/bash
# Caliper — Smart Commit Script
# Single entry point for all git mutations. Never use manual git commands.
# Handles: staging, conventional commit message, push with -u
#
# Usage:
#   bash scripts/smart_commit.sh                    # auto-detect commit type + message
#   bash scripts/smart_commit.sh "feat: add SARIF"  # explicit message
#   bash scripts/smart_commit.sh --dry-run           # show what would be committed

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}→${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1" >&2; }

DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
info "Branch: $CURRENT_BRANCH"

if [ "$CURRENT_BRANCH" = "main" ] || [ "$CURRENT_BRANCH" = "master" ]; then
    error "Cannot commit directly to $CURRENT_BRANCH. Create a feature branch first."
    exit 1
fi

if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    warn "No changes to commit"
    exit 0
fi

# Stage all changes (respects .gitignore)
info "Staging changes..."
git add -A

STAGED_FILES=$(git diff --cached --name-only)
DIFF_STAT=$(git diff --cached --stat)
NUM_FILES=$(echo "$STAGED_FILES" | grep -c . || echo 0)

info "Files staged: $NUM_FILES"

# Auto-detect commit type from changed files
determine_type() {
    local files="$1"
    if echo "$files" | grep -q "^test"; then echo "test"; return; fi
    if echo "$files" | grep -qE "\.(md|txt|rst)$" && ! echo "$files" | grep -qE "\.(py|ts|js)$"; then echo "docs"; return; fi
    if echo "$files" | grep -qE "pyproject\.toml|uv\.lock|package\.json"; then echo "chore"; return; fi
    if echo "$files" | grep -qE "Dockerfile|\.yml$|\.yaml$" && ! echo "$files" | grep -qE "\.(py|ts|js)$"; then echo "ci"; return; fi
    if echo "$files" | grep -qE "^src/|^tests/"; then
        if git diff --cached | grep -qE "^\+.*def test_|^\+.*class Test"; then echo "test"; return; fi
    fi
    echo "feat"
}

determine_scope() {
    local files="$1"
    if echo "$files" | grep -q "plugins/"; then echo "plugins"; return; fi
    if echo "$files" | grep -q "agent/"; then echo "agent"; return; fi
    if echo "$files" | grep -q "core/"; then echo "core"; return; fi
    if echo "$files" | grep -q "cli/"; then echo "cli"; return; fi
    if echo "$files" | grep -q "Dockerfile"; then echo "docker"; return; fi
    echo ""
}

if [ -z "$1" ]; then
    COMMIT_TYPE=$(determine_type "$STAGED_FILES")
    SCOPE=$(determine_scope "$STAGED_FILES")

    case "$COMMIT_TYPE" in
        docs) DESC="update documentation" ;;
        test) DESC="update tests" ;;
        chore) DESC="update dependencies" ;;
        ci) DESC="update CI/build config" ;;
        *) DESC="update $NUM_FILES file(s)" ;;
    esac

    if [ -n "$SCOPE" ]; then
        COMMIT_MSG="${COMMIT_TYPE}(${SCOPE}): ${DESC}"
    else
        COMMIT_MSG="${COMMIT_TYPE}: ${DESC}"
    fi
    info "Generated message: $COMMIT_MSG"
else
    COMMIT_MSG="$1"
    info "Using message: $COMMIT_MSG"
fi

if [ "$DRY_RUN" = true ]; then
    warn "DRY RUN — would commit with message:"
    echo "  $COMMIT_MSG"
    echo ""
    echo "$DIFF_STAT"
    exit 0
fi

git commit -m "$COMMIT_MSG"

COMMIT_HASH=$(git rev-parse --short HEAD)
info "Committed: $COMMIT_HASH"

echo "$DIFF_STAT"
