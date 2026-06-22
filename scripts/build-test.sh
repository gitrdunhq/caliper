#!/usr/bin/env bash
set -euo pipefail

# Build and run the caliper test container.
# Auto-detects podman vs docker, strips --security=insecure for podman.
#
# Usage:
#   bash scripts/build-test.sh                      # build + run all tests
#   bash scripts/build-test.sh --build-only          # just build
#   bash scripts/build-test.sh --run-only            # just run (image must exist)
#   bash scripts/build-test.sh -- tests/unit/ -x     # pass args to pytest
#   bash scripts/build-test.sh --fast                 # native arm64, no emulation

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARCH="amd64"
FAST=false
IMAGE="caliper-test:${ARCH}"
BUILD=true
RUN=true
PYTEST_ARGS=("tests/" "-v")

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only) RUN=false; shift ;;
        --run-only)   BUILD=false; shift ;;
        --fast) FAST=true; ARCH="arm64"; IMAGE="caliper-test:arm64"; shift ;;
        --) shift; PYTEST_ARGS=("$@"); break ;;
        *) PYTEST_ARGS=("$@"); break ;;
    esac
done

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
    "$ENGINE" run --rm \
        --platform "linux/$ARCH" \
        "${SECURITY_OPTS[@]}" \
        --entrypoint "" \
        "$IMAGE" \
        /opt/test-venv/bin/python -m pytest "${PYTEST_ARGS[@]}"
fi
