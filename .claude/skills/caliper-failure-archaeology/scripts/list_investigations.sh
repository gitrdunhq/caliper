#!/usr/bin/env bash
# List every recorded investigation in docs/solutions/** with its front-matter
# status/severity, so a reader can see at a glance what's live vs stale.
# Run from repo root: bash .claude/skills/caliper-failure-archaeology/scripts/list_investigations.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

printf '%-70s %-10s %-9s %s\n' "FILE" "STATUS" "SEVERITY" "TITLE"
printf '%-70s %-10s %-9s %s\n' "----" "------" "--------" "-----"

find docs/solutions -type f -name '*.md' | sort | while read -r f; do
  title=$(grep -m1 '^title:' "$f" | sed -E 's/^title: *"?//; s/"?$//' || true)
  status=$(grep -m1 '^status:' "$f" | sed -E 's/^status: *//' || true)
  sev=$(grep -m1 '^severity:' "$f" | sed -E 's/^severity: *//' || true)
  [ -z "$title" ] && title=$(grep -m1 '^# ' "$f" | sed -E 's/^# *//')
  printf '%-70s %-10s %-9s %s\n' "$f" "${status:-n/a}" "${sev:-n/a}" "$title"
done
