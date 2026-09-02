#!/usr/bin/env bash
# Fetch the pinned caliper-community-rules snapshot for host-side runs (the container
# image bakes the same snapshot in at build time). The commit is read from the
# Dockerfile so there is exactly one pin. Only opengrep-loadable rule files are
# kept (rules/**/semgrep/*.yaml, rules/**/dockerfile-semgrep/*.yaml, no tests/).
#
# Usage: bash scripts/snapshot-community-rules.sh [dest]     (default: .temp/community-rules)
#        bash scripts/snapshot-community-rules.sh --bump     (rewrite the Dockerfile pin to origin/main)
# Then:  export CALIPER_SEMGREP_COMMUNITY_RULES_DIR="$PWD/.temp/community-rules"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM="https://github.com/gitrdunhq/caliper-community-rules"

if [ "${1:-}" = "--bump" ]; then
  LATEST="$(git ls-remote "${UPSTREAM}.git" refs/heads/main | cut -f1)"
  [ -n "${LATEST}" ] || { echo "could not resolve ${UPSTREAM} main" >&2; exit 1; }
  sed -i.bak -E "s/^(ARG COMMUNITY_RULES_COMMIT=)[0-9a-f]{40}/\1${LATEST}/" "${REPO_ROOT}/Dockerfile"
  rm -f "${REPO_ROOT}/Dockerfile.bak"
  echo "COMMUNITY_RULES_COMMIT -> ${LATEST}"
  exit 0
fi

DEST="${1:-${REPO_ROOT}/.temp/community-rules}"
COMMIT="$(sed -nE 's/^ARG COMMUNITY_RULES_COMMIT=([0-9a-f]{40}).*/\1/p' "${REPO_ROOT}/Dockerfile" | head -1)"
[ -n "${COMMIT}" ] || { echo "COMMUNITY_RULES_COMMIT not found in Dockerfile" >&2; exit 1; }

if [ -f "${DEST}/COMMIT" ] && [ "$(cat "${DEST}/COMMIT")" = "${COMMIT}" ]; then
  echo "community-rules snapshot already at ${COMMIT} in ${DEST}"
  exit 0
fi

echo "Fetching caliper-community-rules@${COMMIT} -> ${DEST}"
rm -rf "${DEST}"
mkdir -p "${DEST}"
WORK="$(mktemp -d -t community-rules.XXXXXX)"
curl -sSfL -o "${WORK}/src.tar.gz" "${UPSTREAM}/archive/${COMMIT}.tar.gz"
mkdir -p "${WORK}/src"
tar -xzf "${WORK}/src.tar.gz" -C "${WORK}/src" --strip-components=1
find "${WORK}/src/rules" -type f \( -path '*/semgrep/*.yaml' -o -path '*/dockerfile-semgrep/*.yaml' \) ! -path '*/tests/*' | while read -r f; do
  rel="${f#"${WORK}/src/"}"
  mkdir -p "${DEST}/$(dirname "${rel}")"
  cp "${f}" "${DEST}/${rel}"
done
rm -rf "${WORK}"
printf '%s\n' "${COMMIT}" > "${DEST}/COMMIT"
echo "Snapshot complete: $(find "${DEST}" -name '*.yaml' | wc -l | tr -d ' ') rule files"
echo "export CALIPER_SEMGREP_COMMUNITY_RULES_DIR=\"${DEST}\""
