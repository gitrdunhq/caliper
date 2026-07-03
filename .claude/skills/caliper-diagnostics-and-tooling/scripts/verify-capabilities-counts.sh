#!/usr/bin/env bash
# Recompute the four counts docs/CAPABILITIES.md's "LAST VERIFIED" comment
# block claims, and print them next to what the file currently says, so a
# human/agent can eyeball drift before editing the doc.
#
# Usage (from repo root):
#   bash .claude/skills/caliper-diagnostics-and-tooling/scripts/verify-capabilities-counts.sh
#
# This does NOT edit docs/CAPABILITIES.md — it only reports. If the numbers
# differ, update the "Quick Numbers" table and the top-of-file VERIFICATION
# comment by hand, then re-run this script to confirm it now matches.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "=== docs/CAPABILITIES.md claims (top-of-file VERIFICATION comment) ==="
sed -n '/LAST VERIFIED/,/-->/p' docs/CAPABILITIES.md
echo

echo "=== Recomputed counts ==="

plugins=$(grep -rl '^@ANALYZERS\.register' src/caliper/plugins/*.py | wc -l | tr -d ' ')
echo "Scanner plugins (@ANALYZERS.register in src/caliper/plugins/*.py): ${plugins}"

detectors=$(grep -rhoE 'CAL-0[0-9]+' src/caliper/detectors/ --include='*.py' 2>/dev/null | sort -u | wc -l | tr -d ' ')
echo "Deterministic detectors (unique CAL-0NN ids under src/caliper/detectors/): ${detectors}"

semgrep_rules=$(grep -rhE '^\s*-\s*id:' policies/semgrep/*.yaml | wc -l | tr -d ' ')
echo "Custom semgrep rules ('- id:' lines in policies/semgrep/*.yaml): ${semgrep_rules}"

semgrep_files=$(ls policies/semgrep/*.yaml | wc -l | tr -d ' ')
echo "Semgrep rule files: ${semgrep_files}"

opa_rules=$(grep -cE '^(deny|warn)( contains| :=|\[)' policies/policy.rego)
opa_deny=$(grep -cE '^deny( contains| :=|\[)' policies/policy.rego)
opa_warn=$(grep -cE '^warn( contains| :=|\[)' policies/policy.rego)
echo "OPA Rego policy rules (policies/policy.rego): ${opa_rules} (${opa_deny} deny, ${opa_warn} warn)"

if command -v uv >/dev/null 2>&1; then
  cli_commands=$(uv run caliper --help 2>&1 | sed -n '/^Commands:/,$p' | tail -n +2 | grep -cE '^  [a-z]')
  echo "CLI commands (caliper --help): ${cli_commands}"
else
  echo "CLI commands: uv not on PATH, run 'uv run caliper --help' manually"
fi

echo
echo "Compare each number above to the 'Quick Numbers' table in docs/CAPABILITIES.md."
echo "This script does NOT edit the doc. If a number differs, that's real drift --"
echo "update docs/CAPABILITIES.md by hand (Quick Numbers table + the VERIFICATION"
echo "comment's LAST VERIFIED date) and re-run this script to confirm the fix."
