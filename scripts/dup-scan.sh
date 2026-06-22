#!/usr/bin/env bash
# dup-scan.sh — blended deterministic duplication / dead-code dogfood harness.
#
# Runs the consolidation toolchain over caliper's own source and writes a report
# per tool under .temp/dup-scan/. Every tool is best-effort: a missing binary is
# reported and skipped, never fatal — so the harness is a repeatable signal, not
# a gate. Pairs with the detect-then-scribe CPD plugin (ADR-006): CPD is the
# in-product, language-agnostic clone detector; this is the broader dev-time sweep.
#
# Tools (install hints printed when absent):
#   - PMD CPD     (pmd)            N-way token clones, language-agnostic
#   - jscpd       (npx jscpd)      cross-language copy/paste %
#   - pylint      (R0801)          structural duplicate-code groups (Python)
#   - vulture     (uv tool)        dead/unused code
#   - grimp       (import graph)   cross-tier import edges (architecture drift)
#
# Usage:
#   bash scripts/dup-scan.sh                 # scan src/ (default)
#   bash scripts/dup-scan.sh src/caliper/core  # scan a subtree
#   MIN_TOKENS=80 bash scripts/dup-scan.sh   # tune CPD/jscpd sensitivity
set -uo pipefail

TARGET="${1:-src/caliper}"
MIN_TOKENS="${MIN_TOKENS:-50}"
OUT_DIR="${OUT_DIR:-.temp/dup-scan}"
mkdir -p "${OUT_DIR}"

echo "==> dup-scan: target=${TARGET} min_tokens=${MIN_TOKENS} out=${OUT_DIR}"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n----- %s -----\n' "$1"; }

# 1. PMD CPD — the same engine caliper's cpd plugin uses; N-way token clones.
section "PMD CPD (token clones)"
if have pmd; then
    pmd cpd --minimum-tokens "${MIN_TOKENS}" --dir "${TARGET}" --language python \
        --format text 2>/dev/null | tee "${OUT_DIR}/pmd-cpd.txt" | tail -n 5 || true
    echo "    full report: ${OUT_DIR}/pmd-cpd.txt"
else
    echo "    SKIP: pmd not installed (brew install pmd / https://pmd.github.io)"
fi

# 2. jscpd — cross-language copy/paste percentage.
section "jscpd (copy/paste %)"
if have npx; then
    npx --yes jscpd "${TARGET}" --min-tokens "${MIN_TOKENS}" --reporters console \
        --output "${OUT_DIR}/jscpd" 2>/dev/null | tee "${OUT_DIR}/jscpd.txt" | tail -n 15 || true
    echo "    full report: ${OUT_DIR}/jscpd.txt (html under ${OUT_DIR}/jscpd)"
else
    echo "    SKIP: npx not available (install Node.js)"
fi

# 3. pylint R0801 — structural duplicate-code groups (Python only).
section "pylint duplicate-code (R0801)"
if have uv; then
    uv run --with pylint pylint --disable=all --enable=duplicate-code \
        "${TARGET}" 2>/dev/null | tee "${OUT_DIR}/pylint-r0801.txt" | grep -A2 "R0801" | head -n 30 || true
    echo "    full report: ${OUT_DIR}/pylint-r0801.txt"
else
    echo "    SKIP: uv not installed"
fi

# 4. vulture — dead/unused code (a duplication-adjacent smell: copies left behind).
section "vulture (dead code)"
if have uv; then
    uv run --with vulture vulture "${TARGET}" --min-confidence 80 \
        2>/dev/null | tee "${OUT_DIR}/vulture.txt" | head -n 20 || true
    echo "    full report: ${OUT_DIR}/vulture.txt"
else
    echo "    SKIP: uv not installed"
fi

# 5. grimp — import graph (surface cross-tier edges / drift toward duplication).
section "grimp (import graph summary)"
if have uv; then
    uv run --with grimp python - "$TARGET" <<'PY' 2>/dev/null | tee "${OUT_DIR}/grimp.txt" || true
import sys, grimp
try:
    graph = grimp.build_graph("caliper")
    mods = sorted(graph.modules)
    print(f"modules: {len(mods)}")
    # Count importers of each top-level tier to spot consolidation opportunities.
    tiers = ("caliper.core", "caliper.plugins", "caliper.detectors", "caliper.data", "caliper.adapters")
    for t in tiers:
        members = [m for m in mods if m == t or m.startswith(t + ".")]
        importers = set()
        for m in members:
            importers |= graph.find_modules_that_directly_import(m)
        print(f"{t}: {len(members)} modules, {len(importers)} external importers")
except Exception as e:  # noqa: BLE001
    print(f"grimp error: {e}")
PY
    echo "    full report: ${OUT_DIR}/grimp.txt"
else
    echo "    SKIP: uv not installed"
fi

echo
echo "==> dup-scan complete. Reports in ${OUT_DIR}/"
