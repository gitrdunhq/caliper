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
#   Override via env: REPO_URL, PR_NUM, BASE_BRANCH, WORKDIR, USE_LLM, CALIPER_SRC, REINSTALL,
#   or set CALIPER="my-wrapper" to skip auto-install and use your own caliper invocation.
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
[ "$CALIPER" = "caliper" ] && ensure_caliper
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

# ---- optional: enable the Review (LLM) tier --------------------------------------
NO_LLM="--no-llm"
if [ "$USE_LLM" = "1" ]; then
  : "${CALIPER_LLM_ENDPOINT:?set CALIPER_LLM_ENDPOINT (your oMLX / OpenAI-compatible URL, e.g. http://localhost:PORT/v1)}"
  : "${CALIPER_LLM_MODEL:?set CALIPER_LLM_MODEL (e.g. qwen3.6-35b)}"
  export CALIPER_LLM_ENABLED=1
  # inspect reads the backend from repo config; write a throwaway one into the clone.
  cat > "$SRC/.caliper.yaml" <<YAML
inspect:
  backend: omlx
  model_id: ${CALIPER_LLM_MODEL}
YAML
  NO_LLM=""
  echo ">> Review tier: ENABLED (omlx -> $CALIPER_LLM_ENDPOINT, model $CALIPER_LLM_MODEL)"
else
  echo ">> Review tier: disabled (deterministic Screen + Adjudicate only). Re-run with USE_LLM=1 to enable."
fi

# ---- 1) cut the PR diff into an ordered cut list ----------------------------------
echo
echo ">> caliper part  (base..head -> cut list of parts)"
$CALIPER part --repo "$SRC" --base "$BASE_SHA" --head "$HEAD_SHA" --out "$OUT"

if [ ! -f "$OUT/cutlist.json" ]; then
  echo "ERROR: $OUT/cutlist.json was not produced; check the part output above."
  exit 1
fi

# ---- 2) inspect each part + the integration pass ---------------------------------
echo
echo ">> caliper inspect  (Screen / Review / Adjudicate per part, then integration)"
# shellcheck disable=SC2086
$CALIPER inspect --repo "$SRC" --cutlist "$OUT/cutlist.json" --out "$OUT" $NO_LLM

# ---- results ----------------------------------------------------------------------
echo
echo "=================================================================="
echo "Reports written to: $OUT/inspect/"
ls -1 "$OUT/inspect/" 2>/dev/null || true
echo
echo "Per-part + integration cut list: $OUT/cutlist.json"
echo
echo "Integration (cross-part) summary:"
$CALIPER inspect --explain "$OUT/inspect/integration.json" 2>/dev/null || \
  echo "  (no integration report — see $OUT/inspect/)"
echo "=================================================================="
echo "Tip: open any $OUT/inspect/<part-id>.json for the full per-part claims + dropped log,"
echo "     or re-print one with:  $CALIPER inspect --explain $OUT/inspect/<part-id>.json"
