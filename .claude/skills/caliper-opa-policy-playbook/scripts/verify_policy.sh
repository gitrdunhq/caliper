#!/usr/bin/env bash
# Re-verify the volatile facts this skill states: rule count, test count,
# opa test pass count. Run from repo root. No mutation, no container needed
# (opa is a static binary, not part of the container test suite).
#
# Usage: bash .claude/skills/caliper-opa-policy-playbook/scripts/verify_policy.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "== opa version =="
opa version | head -1

echo
echo "== rule block count (deny + warn) in policies/policy.rego =="
deny_count=$(grep -c '^deny contains msg if {' policies/policy.rego)
warn_count=$(grep -c '^warn contains msg if {' policies/policy.rego)
total=$((deny_count + warn_count))
echo "deny rule blocks: ${deny_count}"
echo "warn rule blocks: ${warn_count}"
echo "total rule blocks: ${total}"

echo
echo "== test count in policies/*_test.rego =="
grep -c '^test_' policies/policy_test.rego policies/policy_supply_chain_test.rego || true

echo
echo "== opa test (with required --ignore flags) =="
opa test policies/ --ignore "*.yaml" --ignore "*.yml"

echo
echo "== confirming --ignore flags are load-bearing (expect failure without them) =="
if opa test policies/ >/dev/null 2>&1; then
  echo "UNEXPECTED: opa test succeeded without --ignore flags -- update the skill, the semgrep/swiftlint yaml configs may have been removed or fixed"
else
  echo "confirmed: opa test policies/ (no --ignore) fails to load semgrep/swiftlint yaml as Rego -- --ignore flags are required"
fi
