#!/usr/bin/env bash
# Resolve multi-arch INDEX (manifest-list) digests for the test image base layers.
#
# Dockerfile.test pins its base + uv layers by digest for supply-chain immutability.
# An *image* digest is single-arch; an *index* digest resolves per --platform, so it
# is both immutable AND arch-agnostic. This prints the index digest for a tag.
#
# Usage:
#   bash scripts/resolve-base-digests.sh dockerhub library/python 3.12.13-slim-bookworm
#   bash scripts/resolve-base-digests.sh ghcr astral-sh/uv latest
set -euo pipefail

registry="$1"   # dockerhub | ghcr
repo="$2"       # e.g. library/python, astral-sh/uv
ref="$3"        # tag or digest

case "$registry" in
    dockerhub)
        auth="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull"
        host="registry-1.docker.io"
        ;;
    ghcr)
        auth="https://ghcr.io/token?scope=repository:${repo}:pull"
        host="ghcr.io"
        ;;
    *) echo "unknown registry: $registry" >&2; exit 2 ;;
esac

token="$(curl -sSf "$auth" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[[ -n "$token" ]] || { echo "no token for $repo" >&2; exit 1; }

accept="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

# HEAD the manifest; the registry returns the digest of what THIS ref resolves to,
# preferring the manifest list when the Accept header offers it.
digest="$(curl -sSf -I \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: ${accept}" \
    "https://${host}/v2/${repo}/manifests/${ref}" \
    | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')"

[[ -n "$digest" ]] || { echo "no digest resolved for ${repo}:${ref}" >&2; exit 1; }
echo "$digest"
