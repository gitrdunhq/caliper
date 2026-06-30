#!/usr/bin/env bash
set -euo pipefail

# Build and run the caliper test container.
# Auto-detects podman vs docker, strips --security=insecure for podman.
#
# Architecture defaults to the HOST arch. On Apple Silicon that is arm64 (native,
# no qemu). Emulating linux/amd64 here makes pyarrow's native extension segfault on
# import, which hangs the container so --rm never fires and orphans pile up. Use
# --amd64 only when you explicitly want a CI-parity (emulated) run.
#
# Usage:
#   bash scripts/build-test.sh                      # build + run all tests (host arch)
#   bash scripts/build-test.sh --build-only          # just build
#   bash scripts/build-test.sh --run-only            # just run (image must exist)
#   bash scripts/build-test.sh -- tests/unit/ -x     # pass args to pytest
#   bash scripts/build-test.sh --amd64               # force emulated amd64 (CI parity)
#   bash scripts/build-test.sh --fast                 # native host arch (default; kept for back-compat)
#
# Env: CALIPER_TEST_TIMEOUT (seconds, default 1200) caps a run so a hung/segfaulting
# container self-terminates and is force-removed instead of orphaning.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default to the host arch — emulated amd64 segfaults pyarrow on Apple Silicon.
case "$(uname -m)" in
    arm64|aarch64) ARCH="arm64" ;;
    *)             ARCH="amd64" ;;
esac
BUILD=true
RUN=true
PYTEST_ARGS=("tests/" "-v")

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only) RUN=false; shift ;;
        --run-only)   BUILD=false; shift ;;
        --fast)       ARCH="arm64"; shift ;;
        --amd64)      ARCH="amd64"; shift ;;
        --) shift; PYTEST_ARGS=("$@"); break ;;
        *) PYTEST_ARGS=("$@"); break ;;
    esac
done
IMAGE="caliper-test:${ARCH}"

if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

echo "Engine: $ENGINE | Image: $IMAGE"

if "$BUILD"; then
    echo "Building test image..."
    if [[ "$ENGINE" == "podman" ]]; then
        sed 's/--security=insecure //g' "$REPO_ROOT/Dockerfile.test" \
          | "$ENGINE" build \
              --platform "linux/$ARCH" \
              -t "$IMAGE" \
              -f - "$REPO_ROOT"
    else
        BUILDER="caliper-builder"
        if ! docker buildx inspect "$BUILDER" &>/dev/null; then
            echo "Creating buildx builder '$BUILDER'..."
            docker buildx create --name "$BUILDER" --driver docker-container \
                --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
        fi
        docker buildx build \
            --builder "$BUILDER" \
            --allow security.insecure \
            --load \
            --platform "linux/$ARCH" \
            -f "$REPO_ROOT/Dockerfile.test" \
            -t "$IMAGE" \
            "$REPO_ROOT"
    fi
    echo "Built: $IMAGE"
fi

if "$RUN"; then
    echo "Running pytest ${PYTEST_ARGS[*]}..."
    SECURITY_OPTS=()
    [[ "$ENGINE" == "podman" ]] && SECURITY_OPTS=("--security-opt" "apparmor=unconfined")

    # Named container + cleanup trap: if the run hangs (e.g. a native-ext segfault
    # under emulation) or is interrupted, force-remove it so it never orphans.
    CONTAINER_NAME="caliper-test-run-$$"
    cleanup() { "$ENGINE" rm -f "$CONTAINER_NAME" &>/dev/null || true; }
    trap cleanup EXIT INT TERM

    # Cap the run so a hung container self-terminates instead of living for hours.
    TIMEOUT_SECS="${CALIPER_TEST_TIMEOUT:-1200}"
    TIMEOUT_BIN=""
    for t in timeout gtimeout; do
        if command -v "$t" &>/dev/null; then TIMEOUT_BIN="$t"; break; fi
    done
    RUN_PREFIX=()
    if [[ -n "$TIMEOUT_BIN" ]]; then
        RUN_PREFIX=("$TIMEOUT_BIN" --signal=KILL "$TIMEOUT_SECS")
    else
        echo "WARN: no timeout binary found; run is uncapped" >&2
    fi

    # python -u keeps output unbuffered so partial diagnostics survive a crash.
    set +e
    "${RUN_PREFIX[@]}" "$ENGINE" run --rm \
        --name "$CONTAINER_NAME" \
        --platform "linux/$ARCH" \
        "${SECURITY_OPTS[@]}" \
        --entrypoint "" \
        "$IMAGE" \
        /opt/test-venv/bin/python -u -m pytest "${PYTEST_ARGS[@]}"
    rc=$?
    set -e
    if [[ "$rc" == "137" ]]; then
        echo "ERROR: test run hit the ${TIMEOUT_SECS}s timeout and was killed" >&2
    fi
    exit "$rc"
fi
