#!/usr/bin/env bash
# Fail-open erosion audit — run from repo root.
#
#   bash .claude/skills/caliper-fail-open-resilience/scripts/audit_fail_open.sh
#
# Checks the current tree for the exact erosion mechanisms documented in
# docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md,
# docs/solutions/runtime-errors/silent-safety-rule-bypasses.md, and commits
# de0d921 / 45cff43. Exits non-zero if any REQUIRED check fails. INFO-level
# findings (e.g. plugins not yet wired to CaliperSettings.scanner_timeout)
# are reported but do not fail the run — that gap is tracked as open, not a
# regression, as of 2026-07-02 (see SKILL.md "Known open gaps").
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1

fail=0
say()  { printf '%s\n' "$*"; }
ok()   { printf '  [OK]   %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=1; }
info() { printf '  [INFO] %s\n' "$*"; }

say "== 1. Exit-code taxonomy (crash vs. clean/degraded run) =="
if grep -qn "raise SystemExit(1)" src/caliper/cli/main.py 2>/dev/null; then
    ok "cli/main.py has an explicit SystemExit(1) path (unexpected crash != exit 0)"
else
    bad "No 'raise SystemExit(1)' found in cli/main.py — an unconditional exit(0) may have crept back in"
fi

say ""
say "== 2. Pipeline wall-clock timeout is enforced (not just loaded) =="
if grep -qn "config.pipeline_timeout" src/caliper/core/pipeline.py 2>/dev/null; then
    ok "core/pipeline.py compares elapsed time against config.pipeline_timeout"
else
    bad "core/pipeline.py does not reference config.pipeline_timeout — timeout may be configured but unenforced (F-007 regression)"
fi

say ""
say "== 3. No bare 'except:' (swallows SystemExit/KeyboardInterrupt too) =="
bare=$(grep -rnE "^\s*except\s*:\s*$" src/caliper/ 2>/dev/null)
if [ -z "$bare" ]; then
    ok "no bare 'except:' clauses in src/caliper/"
else
    bad "bare 'except:' found (should be 'except Exception' at minimum):"
    printf '%s\n' "$bare" | sed 's/^/         /'
fi

say ""
say "== 4. No silent 'pass' inside an except/fallback block =="
passes=$(grep -rn -A1 "except.*:\s*$" src/caliper/ 2>/dev/null | grep -B1 -E "^\s*[a-zA-Z0-9_./]+-\s*pass\s*$")
if [ -z "$passes" ]; then
    ok "no 'except ...: pass' fallbacks found in src/caliper/"
else
    bad "silent pass in except/fallback block found (the F-010 CVSS-no-op shape):"
    printf '%s\n' "$passes" | sed 's/^/         /'
fi

say ""
say "== 5. Degraded-plugin sentinel finding IDs are excluded from the PR-review blocking recount =="
if grep -qn "SENTINEL_RULE_IDS" src/caliper/core/sarif.py 2>/dev/null \
   && grep -qn "SENTINEL_RULE_IDS" src/caliper/core/pr_review.py 2>/dev/null; then
    ok "SENTINEL_RULE_IDS defined in core/sarif.py and consumed in core/pr_review.py (commit de0d921 still applied)"
else
    bad "SENTINEL_RULE_IDS missing from core/sarif.py or core/pr_review.py — a crashed plugin may flip PR review to REQUEST_CHANGES again"
fi

say ""
say "== 6. Every scanner subprocess call passes an explicit timeout =="
plugin_files=$(ls src/caliper/plugins/*.py 2>/dev/null | grep -v "^src/caliper/plugins/__init__.py$")
for f in $plugin_files; do
    name=$(basename "$f")
    if grep -qn "ToolInvocation(" "$f" 2>/dev/null; then
        if grep -q "timeout" "$f"; then
            if grep -q "CaliperSettings" "$f"; then
                ok "$name: subprocess call has a timeout, wired to CaliperSettings"
            else
                info "$name: subprocess call has a timeout, but it is a hardcoded/local default, NOT wired to CaliperSettings.scanner_timeout (open gap, see SKILL.md)"
            fi
        else
            bad "$name: calls ToolInvocation(...) with no visible timeout= argument"
        fi
    fi
done

say ""
say "== 7. Plugin exception handlers return a typed PluginResult(error=...), not a bare re-raise =="
for f in $plugin_files; do
    name=$(basename "$f")
    if grep -q "except Exception" "$f" 2>/dev/null; then
        if grep -A3 "except Exception" "$f" | grep -q "PluginResult(.*error="; then
            ok "$name: except Exception returns PluginResult(error=...)"
        else
            info "$name: has an 'except Exception' block — verify by eye it returns a typed PluginResult(error=...), not a swallow"
        fi
    fi
done

say ""
if [ "$fail" -eq 0 ]; then
    say "RESULT: all REQUIRED checks passed. INFO lines above are known/open gaps, not regressions — see SKILL.md 'Known open gaps'."
else
    say "RESULT: one or more REQUIRED checks FAILED. This looks like fail-open erosion recurring — do not merge until fixed."
fi
exit "$fail"
