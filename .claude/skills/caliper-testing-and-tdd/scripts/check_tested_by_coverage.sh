#!/usr/bin/env bash
# check_tested_by_coverage.sh — audit `# tested-by:` annotation coverage under src/caliper.
#
# Usage (from repo root):
#   bash .claude/skills/caliper-testing-and-tdd/scripts/check_tested_by_coverage.sh
#
# Exit code is always 0 — this is an audit/report tool, not a CI gate. It does
# NOT fail the build; missing annotations on __init__.py files and a handful
# of known files are expected (see the skill's "Known gaps" section). Read the
# printed list and use judgment, don't wire this into a hard gate without
# triaging the list first.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

total=$(find src/caliper -name "*.py" | wc -l | tr -d ' ')
missing_files=$(find src/caliper -name "*.py" | xargs grep -L "# tested-by:" 2>/dev/null || true)
missing_count=$(printf '%s\n' "$missing_files" | grep -c . || true)
annotated_count=$((total - missing_count))

echo "=== tested-by coverage: src/caliper ==="
echo "Total .py files:      $total"
echo "Annotated:             $annotated_count"
echo "Missing annotation:    $missing_count"
echo ""
echo "--- Files missing '# tested-by:' ---"
if [ -n "$missing_files" ]; then
  printf '%s\n' "$missing_files"
else
  echo "(none)"
fi
