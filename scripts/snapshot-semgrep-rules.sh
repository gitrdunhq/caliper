#!/usr/bin/env bash
# Fetch the pinned semgrep-rules snapshot for host-side runs. The published
# container image does NOT include it (Semgrep Rules License v1.0 permits
# internal use only); build your own image with INCLUDE_SEMGREP_RULES=1 to bake
# it in. The commit is read from the Dockerfile so there is exactly one pin.
#
# Usage: bash scripts/snapshot-semgrep-rules.sh [dest]   (default: .temp/semgrep-rules)
# Then:  export CALIPER_SEMGREP_RULES_DIR="$PWD/.temp/semgrep-rules"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-${REPO_ROOT}/.temp/semgrep-rules}"
COMMIT="$(sed -nE 's/^ARG SEMGREP_RULES_COMMIT=([0-9a-f]{40}).*/\1/p' "${REPO_ROOT}/Dockerfile" | head -1)"
[ -n "${COMMIT}" ] || { echo "SEMGREP_RULES_COMMIT not found in Dockerfile" >&2; exit 1; }
DIRS="bash csharp dockerfile generic go html java javascript json kotlin php python ruby rust swift terraform typescript yaml"

if [ -f "${DEST}/COMMIT" ] && [ "$(cat "${DEST}/COMMIT")" = "${COMMIT}" ]; then
  echo "semgrep-rules snapshot already at ${COMMIT} in ${DEST}"
  exit 0
fi

echo "Fetching semgrep-rules@${COMMIT} -> ${DEST}"
rm -rf "${DEST}"
mkdir -p "${DEST}"
TARBALL="$(mktemp -t semgrep-rules.XXXXXX).tar.gz"
curl -sSfL -o "${TARBALL}" "https://github.com/semgrep/semgrep-rules/archive/${COMMIT}.tar.gz"
# shellcheck disable=SC2086
tar -xzf "${TARBALL}" -C "${DEST}" --strip-components=1 $(for d in ${DIRS}; do printf 'semgrep-rules-%s/%s ' "${COMMIT}" "${d}"; done)
rm -f "${TARBALL}"
find "${DEST}" -type f ! -name '*.yaml' ! -name '*.yml' -delete
printf '%s\n' "${COMMIT}" > "${DEST}/COMMIT"
echo "Snapshot complete: $(find "${DEST}" -name '*.yaml' | wc -l | tr -d ' ') rule files"
echo "export CALIPER_SEMGREP_RULES_DIR=\"${DEST}\""
