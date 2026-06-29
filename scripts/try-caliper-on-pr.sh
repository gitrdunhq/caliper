#!/usr/bin/env bash
#
# try-caliper-on-pr.sh — run `caliper part` -> `caliper inspect` against a GitHub PR.
#
# Cuts a PR's diff into an ordered cut list (`caliper part`), then runs the three-tier
# per-part review (Screen -> Review -> Adjudicate) plus the cross-part integration pass
# (`caliper inspect`), writing reports you can read.
#
# PREREQUISITES
#   - git
#   - uv (https://astral.sh/uv) — the script installs caliper for you via `uv tool install`.
#   - jj / jujutsu (https://github.com/jj-vcs/jj) — `caliper part` runs the parting safety
#     gate, which needs a jj repo; the script `jj git init`s the clone for you. (macOS: brew install jj)
#   - For the LLM Review tier (optional): a local oMLX or any OpenAI-compatible endpoint.
#
# This script lives in the caliper repo, so by default it installs caliper as a uv tool
# from this checkout (CALIPER_SRC) and runs the global `caliper`. `uv tool install` gives
# caliper its own isolated venv, which satisfies caliper's "must run isolated" check — no
# manual venv needed. Re-run with REINSTALL=1 after changing caliper's source to pick it up.
#
# USAGE
#   ./scripts/try-caliper-on-pr.sh                  # installs caliper, then deterministic run
#   REINSTALL=1 ./scripts/try-caliper-on-pr.sh      # force-reinstall caliper first
#   USE_LLM=1 CALIPER_LLM_ENDPOINT=http://localhost:PORT/v1 CALIPER_LLM_MODEL=qwen3.6-35b \
#       ./scripts/try-caliper-on-pr.sh              # with the Review LLM tier enabled
#
#   ALLOW_MISSING_GAUGES=0 ./scripts/try-caliper-on-pr.sh   # strict: missing scanner = part fails
#
#   Override via env: REPO_URL, PR_NUM, BASE_BRANCH, WORKDIR, USE_LLM, ALLOW_MISSING_GAUGES,
#   INSTALL_DEPS, CALIPER_SRC, REINSTALL, or set CALIPER="my-wrapper" to skip auto-install.
#
set -euo pipefail

# ---- config (override via env) ----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="${REPO_URL:-https://github.com/farmcreditca/aws-infrastructure-operations-notifications.git}"
PR_NUM="${PR_NUM:-48}"
BASE_BRANCH="${BASE_BRANCH:-}"                       # autodetected from origin HEAD if empty
WORKDIR="${WORKDIR:-$HOME/.cache/caliper-tryout}"
CALIPER_SRC="${CALIPER_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)}"  # caliper checkout to install from
CALIPER="${CALIPER:-caliper}"                        # invocation; default auto-installs below
REINSTALL="${REINSTALL:-0}"                          # 1 = force `uv tool install --force`
USE_LLM="${USE_LLM:-0}"                              # 1 = enable the oMLX/OpenAI-compatible Review backend
ALLOW_MISSING_GAUGES="${ALLOW_MISSING_GAUGES:-1}"    # 1 = tolerate missing scanners (default); 0 = strict fail-closed
INSTALL_DEPS="${INSTALL_DEPS:-1}"                    # 1 = install the target's Python deps so type/import gauges resolve

NAME="$(basename "$REPO_URL" .git)"
SRC="$WORKDIR/$NAME"
OUT="$WORKDIR/${NAME}-pr${PR_NUM}-out"

# ---- ensure caliper is installed (only when using the default `caliper`) ----------
ensure_caliper() {
  # Make a uv-tool-installed caliper reachable this session.
  local bin
  bin="$(uv tool dir --bin 2>/dev/null || true)"
  [ -n "$bin" ] && export PATH="$bin:$PATH"
  export PATH="$HOME/.local/bin:$PATH"

  if command -v caliper >/dev/null 2>&1 && [ "$REINSTALL" != "1" ]; then
    return 0
  fi
  command -v uv >/dev/null 2>&1 || {
    echo "ERROR: uv not found. Install it: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
  }
  echo ">> installing caliper as a uv tool from $CALIPER_SRC"
  uv tool install --force "$CALIPER_SRC"
  bin="$(uv tool dir --bin 2>/dev/null || true)"
  [ -n "$bin" ] && export PATH="$bin:$PATH"
}

# ---- preflight --------------------------------------------------------------------
command -v git >/dev/null 2>&1 || { echo "ERROR: git not found"; exit 1; }
command -v jj >/dev/null 2>&1 || {
  echo "ERROR: jj (jujutsu) not found — caliper part needs it. Install: https://github.com/jj-vcs/jj"
  echo "       macOS: brew install jj"
  exit 1
}
[ "$CALIPER" = "caliper" ] && ensure_caliper
# $CALIPER is intentionally unquoted so a multi-word wrapper (e.g. "uv run ... caliper")
# word-splits into argv; quoting it would break that. Same below for $CALIPER / $NO_LLM.
# nosemgrep: unquoted-variable-expansion-in-command
if ! $CALIPER --version >/dev/null 2>&1; then
  echo "ERROR: cannot run caliper via CALIPER='$CALIPER'."
  echo "       Default auto-installs from $CALIPER_SRC via uv; or set CALIPER to your own wrapper."
  exit 1
fi
echo ">> using caliper: $(command -v caliper 2>/dev/null || echo "$CALIPER")"

# ---- clone / fetch the PR ---------------------------------------------------------
mkdir -p "$WORKDIR"
if [ ! -d "$SRC/.git" ]; then
  echo ">> cloning $REPO_URL"
  git clone "$REPO_URL" "$SRC"
fi
cd "$SRC"

echo ">> fetching PR #$PR_NUM head"
git fetch -q origin "+refs/pull/${PR_NUM}/head:refs/remotes/origin/pr/${PR_NUM}"
HEAD_SHA="$(git rev-parse "refs/remotes/origin/pr/${PR_NUM}")"

if [ -z "$BASE_BRANCH" ]; then
  BASE_BRANCH="$(git remote show origin | sed -n 's/.*HEAD branch: //p')"
fi
git fetch -q origin "$BASE_BRANCH"
BASE_SHA="$(git merge-base "origin/${BASE_BRANCH}" "$HEAD_SHA")"

echo ">> PR #$PR_NUM  base=$BASE_SHA  head=$HEAD_SHA  (base branch: $BASE_BRANCH)"

# Put the working tree at the PR head so the Screen analyzers scan the PR's real files.
git checkout -q --detach "$HEAD_SHA"

mkdir -p "$OUT"

# ---- resolve run settings (the .caliper.yaml is written AFTER `part`) -------------
# inspect reads config from the repo root, but `caliper part` runs the parting gate
# which aborts on a dirty working copy — so we must NOT add .caliper.yaml before part.
# We resolve the settings here and write the file just before `inspect` (below).
if [ "$ALLOW_MISSING_GAUGES" = "1" ]; then AMG="true"; else AMG="false"; fi
if [ "$USE_LLM" = "1" ]; then
  : "${CALIPER_LLM_ENDPOINT:?set CALIPER_LLM_ENDPOINT (your oMLX / OpenAI-compatible URL, e.g. http://localhost:PORT/v1)}"
  : "${CALIPER_LLM_MODEL:?set CALIPER_LLM_MODEL (e.g. qwen3.6-35b)}"
  export CALIPER_LLM_ENABLED=1
fi

NO_LLM="--no-llm"
[ "$USE_LLM" = "1" ] && NO_LLM=""
if [ "$USE_LLM" = "1" ]; then
  echo ">> Review tier: ENABLED (omlx -> $CALIPER_LLM_ENDPOINT, model $CALIPER_LLM_MODEL)"
else
  echo ">> Review tier: disabled (deterministic Screen + Adjudicate only). Re-run with USE_LLM=1 to enable."
fi
if [ "$AMG" = "true" ]; then
  echo ">> Screen: missing scanner binaries tolerated (allow_missing_gauges=true). Set ALLOW_MISSING_GAUGES=0 for strict."
else
  echo ">> Screen: strict (allow_missing_gauges=false) — a missing scanner hard-fails its part."
fi

# ---- 1) cut the PR diff into an ordered cut list ----------------------------------
# `caliper part` runs the parting safety gate, which needs a jj repo (jj is colocated
# on top of the git clone). Initialize it once; outputs go to $OUT (outside $SRC), so
# the working copy stays clean.
if ! (cd "$SRC" && jj root >/dev/null 2>&1); then
  echo ">> jj git init $SRC  (caliper part needs a jj repo)"
  (cd "$SRC" && jj git init --colocate >/dev/null 2>&1) \
    || (cd "$SRC" && jj git init >/dev/null 2>&1) \
    || { echo "ERROR: 'jj git init' failed in $SRC"; exit 1; }
fi

# A PR's commits are already pushed, so jj treats them as immutable (the branch is an
# untracked remote bookmark at/below head) and the parting gate refuses to rewrite
# immutable history ([immutable-overlap]). This is a throwaway analysis clone we never
# push, so neutralize immutability here — `caliper part` only needs to *read* the diff.
(cd "$SRC" && jj config set --repo "revset-aliases.'immutable_heads()'" "none()") \
  || echo "WARN: could not set immutable_heads=none(); part may refuse with immutable-overlap"

# Step 2 (below) writes $SRC/.caliper.yaml so `inspect` can read its settings. On a reused
# clone that file lingers, and on the NEXT run it dirties the working copy — tripping
# `part`'s dirty-tree gate before it does anything. Gitignore it (jj + the gate both honor
# .git/info/exclude, same trick as .venv/ below) and clear any stale copy before parting.
grep -qxF '.caliper.yaml' "$SRC/.git/info/exclude" 2>/dev/null \
  || echo '.caliper.yaml' >> "$SRC/.git/info/exclude"
rm -f "$SRC/.caliper.yaml"

echo
echo ">> caliper part  (base..head -> cut list of parts)"
# nosemgrep: unquoted-variable-expansion-in-command — $CALIPER must word-split (see above)
$CALIPER part --repo "$SRC" --base "$BASE_SHA" --head "$HEAD_SHA" --out "$OUT"

if [ ! -f "$OUT/cutlist.json" ]; then
  echo "ERROR: $OUT/cutlist.json was not produced; check the part output above."
  exit 1
fi

# ---- 1b) best-effort: install the target's Python deps so env-dependent Screen
#      gauges (pyright/mypy) resolve imports instead of false-positiving "Import X
#      could not be resolved" on a bare clone. pyright auto-detects $SRC/.venv. ----
if [ "$INSTALL_DEPS" = "1" ]; then
  printf '.venv/\npyrightconfig.json\n' >> "$SRC/.git/info/exclude" 2>/dev/null || true
  if [ -f "$SRC/pyproject.toml" ] || [ -f "$SRC/uv.lock" ]; then
    echo ">> installing target deps (uv sync) so type/import gauges resolve"
    (cd "$SRC" && { uv sync --frozen || uv sync; }) >/dev/null 2>&1 \
      || echo "   (uv sync failed; type/import gauges may report unresolved imports)"
  elif ls "$SRC"/requirements*.txt >/dev/null 2>&1; then
    echo ">> installing target deps (uv venv + requirements) so type/import gauges resolve"
    (cd "$SRC" && uv venv >/dev/null 2>&1 && for r in requirements*.txt; do uv pip install -r "$r"; done) \
      >/dev/null 2>&1 || echo "   (dependency install failed; type/import gauges may false-positive)"
  else
    echo ">> no Python deps manifest in target; skipping dep install (set INSTALL_DEPS=0 to silence)"
  fi
  # pyright runs with cwd=repo and auto-loads pyrightconfig.json; point it at the venv so
  # it resolves third-party imports (uv sync alone isn't enough — pyright doesn't detect it).
  if [ -d "$SRC/.venv" ]; then
    printf '{ "venvPath": ".", "venv": ".venv" }\n' > "$SRC/pyrightconfig.json"
  fi
fi

# ---- 2) inspect each part + the integration pass ---------------------------------
# Write the throwaway repo config now (after `part`, so the parting gate saw a clean
# tree). inspect has no dirty-tree gate, so the new file is fine here. It carries
# allow_missing_gauges and, when USE_LLM=1, the oMLX backend.
{
  echo "inspect:"
  echo "  allow_missing_gauges: $AMG"
  if [ "$USE_LLM" = "1" ]; then
    echo "  backend: omlx"
    echo "  model_id: ${CALIPER_LLM_MODEL}"
  fi
} > "$SRC/.caliper.yaml"

echo
echo ">> caliper inspect  (Screen / Review / Adjudicate per part, then integration)"
# shellcheck disable=SC2086
# nosemgrep: unquoted-variable-expansion-in-command — $CALIPER and $NO_LLM must word-split
$CALIPER inspect --repo "$SRC" --cutlist "$OUT/cutlist.json" --out "$OUT" $NO_LLM

# ---- results: per-part summary table ----------------------------------------------
_summary() {
  command -v python3 >/dev/null 2>&1 || {
    echo "  (install python3 for the summary table; raw reports are in $OUT/inspect/)"
    return 0
  }
  python3 - "$OUT" <<'PY'
import glob, json, os, sys

out = sys.argv[1]
cut = {}
try:
    cl = json.load(open(os.path.join(out, "cutlist.json")))
    for p in cl.get("parts", []):
        cut[p["id"]] = (len(p.get("files", [])), p.get("size", 0))
except Exception:
    pass

# integration report sorts last
paths = sorted(
    glob.glob(os.path.join(out, "inspect", "*.json")),
    key=lambda p: (os.path.basename(p) == "integration.json", p),
)
rows = [("PART", "BUCKET", "FILES", "SIZE", "GAUGES", "FIND", "CLAIMS", "DROP", "LLM")]
tot_parts = tot_claims = tot_fail = 0
for path in paths:
    try:
        r = json.load(open(path))
    except Exception:
        continue
    pid = r.get("part_id", "?")
    gauges = r.get("gauges", [])
    npass = sum(1 for g in gauges if g.get("verdict") == "pass")
    nfail = sum(1 for g in gauges if g.get("verdict") == "fail")
    nfnd = sum(len(g.get("findings", [])) for g in gauges)
    nclaims = len(r.get("claims", []))
    nfiles, size = cut.get(pid, ("-", "-"))
    short = "INTEGRATION" if pid == "integration" else pid.replace("part-", "")
    rows.append(
        (short, r.get("bucket", ""), str(nfiles), str(size), f"{npass}P/{nfail}F",
         str(nfnd), str(nclaims), str(len(r.get("dropped", []))),
         "skip" if r.get("skipped_llm") else "ran")
    )
    if pid != "integration":
        tot_parts += 1
    tot_claims += nclaims
    tot_fail += nfail

w = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
for i, row in enumerate(rows):
    print("  " + "  ".join(row[j].ljust(w[j]) for j in range(len(row))))
    if i == 0:
        print("  " + "  ".join("-" * w[j] for j in range(len(row))))
print(f"\n  {tot_parts} parts · {tot_claims} surviving claims · {tot_fail} failed gauge(s)")
print("  GAUGES = Screen pass/fail · FIND = Screen findings · DROP = claims filtered by Adjudicate")
PY
}

echo
echo "=================================================================="
echo "Per-part summary (deterministic Screen + Adjudicate; CLAIMS populate with USE_LLM=1):"
echo
_summary
echo
echo "Reports: $OUT/inspect/   ·   cut list: $OUT/cutlist.json"
# nosemgrep: unquoted-variable-expansion-in-command — $CALIPER must word-split (see above)
echo "Re-print any part:  $CALIPER inspect --explain $OUT/inspect/<part-id>.json"
echo "=================================================================="
