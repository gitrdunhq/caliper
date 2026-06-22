#!/usr/bin/env bash
# Run caliper review against itself, log results, fail on HIGH/CRITICAL
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel)}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="${REPORT_DIR:-${REPO_ROOT}/.caliper/reports}"
REPORT_FILE="${REPORT_DIR}/dogfood-report-${TIMESTAMP}.md"
SARIF_FILE="${REPORT_DIR}/dogfood-${TIMESTAMP}.sarif"

mkdir -p "${REPORT_DIR}"

echo "=== Caliper Dogfood Run: ${TIMESTAMP} ==="
echo ""

# Run review in markdown mode for the human-readable report
uv run caliper review --repo-path "${REPO_ROOT}" --all --output "${REPORT_FILE}" 2>&1 || true

# Run review in SARIF mode for machine-readable severity counting
uv run caliper review --repo-path "${REPO_ROOT}" --all --format sarif --output "${SARIF_FILE}" 2>&1 || true

# Count error-level findings (critical + high) from SARIF
if [ -f "${SARIF_FILE}" ]; then
    CRITICAL=$(python3 -c "
import json, sys
with open('${SARIF_FILE}') as f:
    sarif = json.load(f)
count = sum(1 for run in sarif.get('runs', []) for r in run.get('results', []) if r.get('level') == 'error')
print(count)
" 2>/dev/null || echo "0")

    echo "Findings: ${CRITICAL} error-level (critical/high)"
    echo "Report: ${REPORT_FILE}"
    echo "SARIF:  ${SARIF_FILE}"

    if [ "${CRITICAL}" -gt 0 ]; then
        echo ""
        echo "BLOCKED: ${CRITICAL} error-level findings. Fix before shipping."
        exit 1
    fi
fi

echo ""
echo "CLEAR: No blocking findings."

# Update the latest symlinks
ln -sf "dogfood-report-${TIMESTAMP}.md" "${REPORT_DIR}/dogfood-report-latest.md"
ln -sf "dogfood-${TIMESTAMP}.sarif" "${REPORT_DIR}/dogfood-latest.sarif"
