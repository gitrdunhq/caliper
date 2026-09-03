#!/usr/bin/env bash
# Tag the already-published container image for a release commit with its
# version. The build-container workflow pushes IMAGE:<sha> on every main push;
# this adds IMAGE:<version> and IMAGE:v<version> to that same digest (manifest
# copy, no rebuild, no pull), so a release SHA and its version tag are one image.
#
# Usage: bash scripts/tag-release-image.sh <commit-sha> <version> [image-repo]
#   e.g. bash scripts/tag-release-image.sh fe00ce1d... 0.2.32
# Env:   WAIT_SECONDS (default 1800) — how long to wait for IMAGE:<sha> to exist,
#        since build-container runs on the same push and may still be building.
# Needs: docker with buildx, logged in to the registry with packages:write.
set -euo pipefail

SHA="${1:?commit sha}"
VERSION="${2:?version, e.g. 0.2.32}"
IMAGE="${3:-ghcr.io/gitrdunhq/caliper}"
WAIT_SECONDS="${WAIT_SECONDS:-1800}"

SRC="${IMAGE}:${SHA}"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
until docker buildx imagetools inspect "${SRC}" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "ERROR: ${SRC} not found after ${WAIT_SECONDS}s (was build-container run for this sha?)" >&2
    exit 1
  fi
  echo "waiting for ${SRC} ..."
  sleep 30
done

docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:v${VERSION}" "${SRC}"
DIGEST="$(docker buildx imagetools inspect "${SRC}" --format '{{json .Manifest.Digest}}' | tr -d '"')"
echo "tagged ${SRC} as ${IMAGE}:${VERSION} and ${IMAGE}:v${VERSION} (digest ${DIGEST})"
