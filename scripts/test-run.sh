#!/usr/bin/env bash
# Run pytest in a WARM caliper-test image: build once per dependency change, bind-mount the repo.
#
#   scripts/test-run.sh [pytest args...]        # default: tests/ -v
#   scripts/test-run.sh --affected [--base REV] # only tests mapped from the change set
#   scripts/test-run.sh --rebuild ...           # force an image rebuild
#   scripts/test-run.sh --amd64 ...             # cross-arch image (default: host arch)
#
# The image is labelled with a hash of pyproject.toml + uv.lock + Dockerfile.test;
# when the label matches, no build happens and the run starts in seconds. The
# repo is mounted read-only at /workspace (the venv lives at /opt/test-venv and
# caliper is installed editable from /workspace, so mounted source is what runs);
# pytest/hypothesis caches go to tmpfs. Never uses CALIPER_ALLOW_HOST_TESTS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
case "$(uname -m)" in arm64|aarch64) ARCH="arm64" ;; *) ARCH="amd64" ;; esac
IMAGE="caliper-test:${ARCH}"
if command -v podman &>/dev/null; then ENGINE=podman; elif command -v docker &>/dev/null; then ENGINE=docker; else echo "ERROR: neither podman nor docker found" >&2; exit 1; fi

REBUILD=false; AFFECTED=false; BASE=""; PYTEST_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild)  REBUILD=true; shift ;;
    --amd64)    ARCH=amd64; IMAGE="caliper-test:amd64"; shift ;;
    --arm64)    ARCH=arm64; IMAGE="caliper-test:arm64"; shift ;;
    --affected) AFFECTED=true; shift ;;
    --base)     BASE="$2"; shift 2 ;;
    --)         shift; PYTEST_ARGS=("$@"); break ;;
    *)          PYTEST_ARGS+=("$1"); shift ;;
  esac
done

DEPS_STAMP="$(cat "$REPO_ROOT/pyproject.toml" "$REPO_ROOT/uv.lock" "$REPO_ROOT/Dockerfile.test" | shasum -a 256 | cut -c1-16)"
CURRENT="$("$ENGINE" image inspect "$IMAGE" --format '{{ index .Config.Labels "caliper.test.deps" }}' 2>/dev/null || true)"
if "$REBUILD" || [[ "$CURRENT" != "$DEPS_STAMP" ]]; then
  echo "test image: building (deps stamp ${DEPS_STAMP}; had '${CURRENT:-none}')" >&2
  if [[ "$ENGINE" == "podman" ]]; then
    sed 's/--security=insecure //g' "$REPO_ROOT/Dockerfile.test" \
      | "$ENGINE" build --platform "linux/$ARCH" --label "caliper.test.deps=${DEPS_STAMP}" -t "$IMAGE" -f - "$REPO_ROOT" >&2
  else
    "$ENGINE" buildx build --allow security.insecure --platform "linux/$ARCH" --label "caliper.test.deps=${DEPS_STAMP}" -t "$IMAGE" -f "$REPO_ROOT/Dockerfile.test" --load "$REPO_ROOT" >&2
  fi
  "$ENGINE" image prune -f >/dev/null 2>&1 || true
else
  echo "test image: warm (deps stamp ${DEPS_STAMP})" >&2
fi

if "$AFFECTED"; then
  # In a datum lane worktree, target the lane's change set; in the root checkout
  # (validate, CI, humans) the mapper still fails safe to the full suite when the
  # diff touches dependency or harness files.
  ARGS=(); [[ -n "$BASE" ]] && ARGS=(--base "$BASE")
  SELECTED="$(cd "$REPO_ROOT" && uv run --no-sync python scripts/affected_tests.py --explain "${ARGS[@]}")"
  read -r -a PYTEST_ARGS <<< "$SELECTED"
  [[ ${#PYTEST_ARGS[@]} -eq 0 ]] && PYTEST_ARGS=("tests/")
  echo "affected tests: ${PYTEST_ARGS[*]}" >&2
fi
[[ ${#PYTEST_ARGS[@]} -eq 0 ]] && PYTEST_ARGS=("tests/" "-v")

SECURITY_OPTS=(); [[ "$ENGINE" == "podman" ]] && SECURITY_OPTS=("--security-opt" "apparmor=unconfined")
NAME="caliper-test-run-$$"
cleanup() { "$ENGINE" rm -f "$NAME" &>/dev/null || true; }
trap cleanup EXIT INT TERM
TIMEOUT_SECS="${CALIPER_TEST_TIMEOUT:-1200}"; RUN_PREFIX=()
for t in timeout gtimeout; do command -v "$t" &>/dev/null && { RUN_PREFIX=("$t" --signal=KILL "$TIMEOUT_SECS"); break; }; done
set +e
"${RUN_PREFIX[@]}" "$ENGINE" run --rm --name "$NAME" --platform "linux/$ARCH" "${SECURITY_OPTS[@]}" \
  --env CI --entrypoint "" \
  -v "$REPO_ROOT:/workspace:ro" \
  --tmpfs /workspace/.pytest_cache --tmpfs /workspace/.hypothesis --tmpfs /workspace/.temp --tmpfs /tmp \
  -w /workspace \
  "$IMAGE" /opt/test-venv/bin/python -u -m pytest -p no:cacheprovider "${PYTEST_ARGS[@]}"
rc=$?
set -e
[[ "$rc" == "137" ]] && echo "ERROR: test run hit the ${TIMEOUT_SECS}s timeout and was killed" >&2
exit "$rc"
