#!/usr/bin/env bash
# Turn a `caliper part` cut into a stack of GitHub PRs.
#
# `caliper part` emits restack.sh, which builds one caliper-part-N branch per
# part. This takes those branches, pushes them under readable names, and opens
# one PR per part, each targeting the part below it — so every PR's diff shows
# only its own change.
#
# Purely additive: it creates new branches and new PRs. It never force-pushes,
# never rewrites the source branch, and never touches the original PR. That
# matters on a published branch, where rewriting history orphans inline review
# threads.
#
# Usage:
#   bash scripts/stack-part-prs.sh <repo-path> <owner/name> <prefix> [--dry-run]
#
# Example:
#   bash scripts/stack-part-prs.sh ~/repos/app acme/app feature-x
#   -> feature-x/01-infra, feature-x/02-deps, ... each with its own PR
#
# Prerequisites:
#   - restack.sh has already been run, so caliper-part-1..N exist
#   - gh is authenticated and <repo-path> has a GitHub remote. NOTE: running
#     this from a throwaway clone whose origin is a local path will push the
#     branches to that local repo, not to GitHub, and `gh pr create` will then
#     fail with "No commits between ...". Use the checkout that has the real
#     remote.
set -euo pipefail

REPO_PATH="${1:-}"
GH_REPO="${2:-}"
PREFIX="${3:-}"
DRY_RUN="${4:-}"

if [ -z "${REPO_PATH}" ] || [ -z "${GH_REPO}" ] || [ -z "${PREFIX}" ]; then
    echo "Usage: bash scripts/stack-part-prs.sh <repo-path> <owner/name> <prefix> [--dry-run]" >&2
    exit 1
fi

cd "${REPO_PATH}"
unset GITHUB_TOKEN

# Discover the parts restack.sh built, in order.
mapfile -t PARTS < <(git branch --list 'caliper-part-[0-9]*' --format='%(refname:short)' | sort -V)
TOTAL=${#PARTS[@]}
if [ "${TOTAL}" -eq 0 ]; then
    echo "No caliper-part-* branches found in ${REPO_PATH}. Run restack.sh first." >&2
    exit 1
fi

# The stack's base is the parent of part 1 — whatever the cut was taken against.
# `rev-parse --abbrev-ref` is NOT usable here: for a commit that is not a branch
# tip it prints nothing and still exits 0, so a `||` fallback never fires and the
# base silently becomes empty. name-rev resolves it to a real branch name.
BASE_SHA=$(git rev-parse "${PARTS[0]}^")
BASE_REF=$(git name-rev --name-only --refs='refs/remotes/origin/*' "${BASE_SHA}" 2>/dev/null || true)
BASE_REF="${BASE_REF#remotes/origin/}"
case "${BASE_REF}" in
    "" | undefined | *[\~\^]*)
        echo "Cannot resolve a branch for the stack base (${BASE_SHA})." >&2
        echo "A GitHub PR base must be a branch. Push that commit as a branch first." >&2
        exit 1
        ;;
esac

echo "=== ${TOTAL} parts, stacking onto ${BASE_REF} ==="

slug_for() {
    # Derive a branch slug from the conventional-commit scope or type.
    local subject="$1"
    local head="${subject%%:*}"
    local scope="${head##*(}"
    scope="${scope%)}"
    printf '%s' "${scope}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/-\{2,\}/-/g;s/^-//;s/-$//'
}

branches=()
titles=()
for i in "${!PARTS[@]}"; do
    n=$((i + 1))
    subject=$(git log -1 --format='%s' "${PARTS[$i]}")
    branches+=("$(printf '%s/%02d-%s' "${PREFIX}" "${n}" "$(slug_for "${subject}")")")
    titles+=("${subject}")
done

if [ "${DRY_RUN}" = "--dry-run" ]; then
    prev="${BASE_REF}"
    for i in "${!branches[@]}"; do
        printf '  %s -> %s\n      %s\n' "${branches[$i]}" "${prev}" "${titles[$i]}"
        prev="${branches[$i]}"
    done
    echo "(dry run: nothing pushed, no PRs opened)"
    exit 0
fi

for i in "${!PARTS[@]}"; do
    echo "--> push ${branches[$i]}"
    git push -q origin "${PARTS[$i]}:refs/heads/${branches[$i]}"
done
git fetch -q origin

prev="${BASE_REF}"
for i in "${!branches[@]}"; do
    n=$((i + 1))
    branch="${branches[$i]}"
    files=$(git diff --name-only "origin/${prev}...origin/${branch}" | sed 's/^/- `/;s/$/`/')
    count=$(git diff --name-only "origin/${prev}...origin/${branch}" | wc -l | tr -d ' ')

    body=$(cat <<BODY
Part ${n} of ${TOTAL} of a stacked split. Targets \`${prev}\`, so this diff shows only this part.

Produced by \`caliper part\`: the cut is deterministic and the final commit of the stack is byte-identical to the source branch. No content changed.

**${count} file(s):**

${files}

---

**Review order:** ${n} of ${TOTAL}. Merge bottom-up; each PR retargets automatically as the one below it merges.
BODY
)

    # A stacked PR must genuinely CONTAIN its base, not merely target it.
    # Retargeting a sibling branch produces a false stack: merge-base resolves
    # back to the repo root, both sides edit the same shared files, and GitHub
    # reports CONFLICTING — blocking every PR above it.
    # https://docs.github.com/en/pull-requests/how-tos/stacked-pull-requests
    if ! git merge-base --is-ancestor "origin/${prev}" "origin/${branch}"; then
        echo "REFUSING: ${branch} does not contain ${prev}." >&2
        echo "That would be a false stack. Rebase ${branch} onto ${prev} first." >&2
        exit 1
    fi

    echo "--> PR ${n}/${TOTAL}: ${branch} -> ${prev}"
    gh pr create --repo "${GH_REPO}" --base "${prev}" --head "${branch}" \
        --title "${titles[$i]}" --body "${body}" 2>&1 | tail -1
    prev="${branch}"
done
