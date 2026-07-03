#!/usr/bin/env bash
# Re-verify the load-bearing counts and eval numbers cited in SKILL.md.
# Run from repo root: bash .claude/skills/caliper-research-frontier/scripts/reverify_evidence.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "== capability counts (compare against docs/CAPABILITIES.md and CLAUDE.md) =="
echo -n "scanner plugins (ScannerPlugin subclasses, excl. OpaPlugin/PartingPlugin): "
grep -l "class.*ScannerPlugin" src/caliper/plugins/*.py \
  | grep -v -E "_opa\.py|_parting\.py" | wc -l | tr -d ' '
echo -n "OPA policy plugin present (_opa.py OpaPlugin): "
grep -l "class OpaPlugin" src/caliper/plugins/_opa.py >/dev/null && echo yes || echo no
echo -n "deterministic detectors (unique CAL-NNN ids in docs/detectors.md): "
grep -oE "CAL-[0-9]{3}" docs/detectors.md | sort -u | wc -l | tr -d ' '
echo -n "custom semgrep rules (- id: entries under policies/semgrep): "
grep -rhE "^\s*- id:" policies/semgrep | wc -l | tr -d ' '
echo -n "code graph checks (checks.yaml '- name:' entries): "
grep -cE "^\s*- name:" src/caliper/plugins/_runners/checks.yaml
echo -n "OPA deny/warn rules (policy.rego 'X contains msg if' blocks): "
grep -cE "^(deny|warn) contains msg if" policies/policy.rego

echo
echo "== eval harness (docs/llm-review/eval-corpus, currently 2 illustrative cases) =="
uv run caliper eval --corpus docs/llm-review/eval-corpus --format json

echo
echo "== bare @lru_cache (no parens) behavior check: CAL cache_eviction correctly does NOT flag it =="
echo "   (bare @lru_cache defaults to maxsize=128 -- bounded, not a false negative)"
TMP_FILE="$(mktemp -t caliper-lru-check-XXXX).py"
trap 'rm -f "$TMP_FILE"' EXIT
cat > "$TMP_FILE" <<'PY'
from functools import lru_cache

@lru_cache
def bounded_bare(x):
    return x * 2
PY
uv run python -c "
from pathlib import Path
from caliper.detectors.reliability.cache_eviction import CacheEvictionDetector
findings = CacheEvictionDetector().detect(Path('$TMP_FILE'))
print('findings on bare @lru_cache fixture:', findings)
print('EXPECTED (correct, bare @lru_cache is bounded at maxsize=128 by default): []')
"
