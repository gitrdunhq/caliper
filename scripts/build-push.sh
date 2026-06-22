#!/usr/bin/env bash
set -euo pipefail

# Build the caliper production image and push to GHCR.
# Tags with commit SHA only. The `latest` tag is applied by the release
# workflow (build-container.yml) after release-please cuts a version.
#
# Usage:
#   bash scripts/build-push.sh
#   REGISTRY=ghcr.io/gitrdunhq/caliper bash scripts/build-push.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REGISTRY="${REGISTRY:-ghcr.io/gitrdunhq/caliper}"
ARCH="amd64"
SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")

if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

TAG="${REGISTRY}:${SHA}"
echo "Engine: $ENGINE | Tag: ${TAG:0:60}..."

if [[ "$ENGINE" == "podman" ]]; then
    sed 's/--security=insecure //g' "$REPO_ROOT/Dockerfile" \
      | "$ENGINE" build \
          --platform "linux/$ARCH" \
          -t "$TAG" \
          -f - "$REPO_ROOT"
else
    BUILDER="caliper-builder"
    if ! docker buildx inspect "$BUILDER" &>/dev/null; then
        docker buildx create --name "$BUILDER" --driver docker-container \
            --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
    fi
    docker buildx build \
        --builder "$BUILDER" \
        --allow security.insecure \
        --load \
        --platform "linux/$ARCH" \
        -t "$TAG" \
        "$REPO_ROOT"
fi

echo "Pushing ${SHA:0:12}..."
"$ENGINE" push "$TAG"
echo "Pushed: $TAG"
