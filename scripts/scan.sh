#!/usr/bin/env bash
# Scan any repo with eedom using the local arm64 image.
#
# Usage:
#   bash scripts/scan.sh /path/to/repo
#   bash scripts/scan.sh ../my-project sarif
#   bash scripts/scan.sh ~/repos/sam/ba-pipeline-full_1
#
# Args:
#   $1  Path to the repo to scan (required)
#   $2  Output format: markdown (default) or sarif
set -euo pipefail

TARGET="${1:-}"
FORMAT="${2:-markdown}"
IMAGE="${EEDOM_IMAGE:-eedom:arm64}"
PLATFORM="${EEDOM_PLATFORM:-linux/arm64}"

if [ -z "${TARGET}" ]; then
    echo "Usage: bash scripts/scan.sh <repo-path> [markdown|sarif]" >&2
    exit 1
fi

# Resolve to absolute path
REPO="$(cd "${TARGET}" && pwd)"

if [ ! -d "${REPO}" ]; then
    echo "Error: '${REPO}' is not a directory" >&2
    exit 1
fi

TRIVY_CACHE="${HOME}/.cache/eedom/trivy"
mkdir -p "${TRIVY_CACHE}"

echo "=== Eagle Eyed Dom ==="
echo "Target : ${REPO}"
echo "Format : ${FORMAT}"
echo "Image  : ${IMAGE}"
echo ""

# Prune any crashed containers from previous runs before starting.
# A crashed scan leaves a leaked overlay layer that accumulates and fills the VM disk.
podman container prune -f >/dev/null 2>&1 || true

podman run --rm \
    --platform "${PLATFORM}" \
    --security-opt apparmor=unconfined \
    --tmpfs /workspace/.temp:rw,size=512m \
    -v "${REPO}:/workspace:ro" \
    -v "${TRIVY_CACHE}:/home/eedom/.cache/trivy" \
    "${IMAGE}" review --repo-path /workspace --all \
    ${FORMAT:+--format "${FORMAT}"} \
    "${@:3}"

# Prune dangling layers after a successful run.
podman system prune -f --volumes >/dev/null 2>&1 || true
