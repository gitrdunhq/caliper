#!/usr/bin/env bash
#
# Install caliper as a uv tool from local source, appending a unique PEP 440
# *local* build id to the version (e.g. 0.2.26+dev.20260630T101500.gabc1234).
#
# Why: uv caches built wheels keyed by (name, version). When the static version
# in pyproject.toml hasn't changed, `uv tool install --reinstall` can serve a
# stale cached wheel instead of your new code. A unique local segment gives every
# build a distinct wheel filename, so the cache is always busted and the install
# reflects the current working tree. The +local segment is ignored by semver and
# release-please, so it never affects an actual release.
#
# Usage:
#   bash scripts/install-local.sh           # build current tree, install as `caliper`
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYPROJECT="${REPO_ROOT}/pyproject.toml"

# Guarantee pyproject.toml is restored to its committed state no matter how we
# exit (success, error, or Ctrl-C) — we only mutate the version transiently.
BACKUP="$(mktemp)"
cp "$PYPROJECT" "$BACKUP"
restore() { cp "$BACKUP" "$PYPROJECT"; rm -f "$BACKUP"; }
trap restore EXIT

# Base version, with any pre-existing local segment stripped so we never stack
# +dev.+dev across runs. Read it from inside the [project] table only, so a
# `version = ` line in some other table (e.g. a tool config) can't be picked up.
BASE_VERSION="$(awk '/^\[project\]/{p=1;next} /^\[/{p=0} p && /^version = /{gsub(/^version = "|".*/,""); print; exit}' "$PYPROJECT")"
BASE_VERSION="${BASE_VERSION%%+*}"

SHORT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILD_ID="$(date +%Y%m%dT%H%M%S).g${SHORT_SHA}"
DEV_VERSION="${BASE_VERSION}+dev.${BUILD_ID}"

# Portable in-place edit (works on BSD/macOS and GNU sed via the .bak form).
# Anchored to the [project] table (range ends at the next `[` header) so a
# `version = ` in any other table is never touched; `|` delimiter avoids clashing
# with the dotted local segment.
sed -i.bak -E "/^\[project\]/,/^\[/ s|^version = \"[^\"]+\"|version = \"${DEV_VERSION}\"|" "$PYPROJECT"
rm -f "${PYPROJECT}.bak"

echo ">> building + installing caliper ${DEV_VERSION}"
uv tool install --reinstall --from "$REPO_ROOT" caliper
echo ">> installed caliper ${DEV_VERSION}  (run: caliper --version)"
