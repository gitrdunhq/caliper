#!/usr/bin/env bash
set -euo pipefail

# Build the caliper production container image.
# Auto-detects podman vs docker and applies the right flags.
# Defaults to the HOST's native architecture (no qemu emulation) — same
# convention as `make test-build`'s HOST_ARCH detection. Pass an explicit
# arch when you need the other one (e.g. building an amd64 image on an
# arm64 Mac for GHCR-parity testing).
#
# Usage:
#   bash scripts/build.sh                    # default: native host arch
#   bash scripts/build.sh arm64              # explicit arch
#   bash scripts/build.sh amd64              # explicit arch (e.g. GHCR parity on Apple Silicon)
#   bash scripts/build.sh --fast             # alias for native arch (kept for back-compat)
#   bash scripts/build.sh amd64 --no-cache   # force clean rebuild

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_ARCH="$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')"

FAST=""
ARCH="$HOST_ARCH"
EXTRA_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --fast) FAST=1; ARCH="$HOST_ARCH" ;;
        arm64|amd64) ARCH="$arg" ;;
        *) EXTRA_ARGS+=("$arg") ;;
    esac
done

IMAGE="caliper:${ARCH}"

if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

"$ENGINE" info >/dev/null 2>&1 || { echo "ERROR: $ENGINE is installed but not running" >&2; exit 1; }

echo "Engine: $ENGINE | Platform: linux/$ARCH | Image: $IMAGE${FAST:+ (fast — native arm64)}"

# Prepare Dockerfile: strip --security=insecure for podman
DOCKERFILE_CONTENT=$(cat "$REPO_ROOT/Dockerfile")

if [[ "$ENGINE" == "podman" ]]; then
    DOCKERFILE_CONTENT=$(echo "$DOCKERFILE_CONTENT" | sed 's/--security=insecure //g')
fi

if ! echo "$DOCKERFILE_CONTENT" | grep -q '^FROM '; then
    echo "ERROR: Dockerfile processing produced invalid output" >&2
    exit 1
fi

if [[ "$ENGINE" == "podman" ]]; then
    echo "$DOCKERFILE_CONTENT" \
      | "$ENGINE" build \
          --platform "linux/$ARCH" \
          --target runtime \
          -t "$IMAGE" \
          -t caliper:latest \
          "${EXTRA_ARGS[@]}" \
          -f - "$REPO_ROOT"
else
    BUILDER="caliper-builder"
    if ! docker buildx inspect "$BUILDER" &>/dev/null; then
        echo "Creating buildx builder '$BUILDER' with insecure entitlements..."
        docker buildx create --name "$BUILDER" --driver docker-container \
            --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
    fi
    echo "$DOCKERFILE_CONTENT" \
      | docker buildx build \
          --builder "$BUILDER" \
          --allow security.insecure \
          --load \
          --platform "linux/$ARCH" \
          --target runtime \
          -t "$IMAGE" \
          -t caliper:latest \
          "${EXTRA_ARGS[@]}" \
          -f - "$REPO_ROOT"
fi

echo "Built: $IMAGE"
"$ENGINE" run --rm --platform "linux/$ARCH" --entrypoint "" "$IMAGE" caliper --version 2>&1 | tail -1
