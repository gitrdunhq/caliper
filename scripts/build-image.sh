#!/usr/bin/env bash
# build-image.sh — Multi-arch image build and validation.
#
# Usage:
#   bash scripts/build-image.sh                    # arm64 local only
#   bash scripts/build-image.sh --amd64            # arm64 local + amd64 remote
#   bash scripts/build-image.sh --amd64-only       # amd64 remote only
#   bash scripts/build-image.sh --compare          # build + compare size to previous
#
# Environment:
#   CALIPER_AMD64_HOST    Remote host for amd64 builds (default: sambou@192.168.0.210)
#   CALIPER_IMAGE_TAG     Image tag (default: caliper:latest)
#   CONTAINER_ENGINE    podman or docker (auto-detected)

set -euo pipefail

TAG="${CALIPER_IMAGE_TAG:-caliper:latest}"
AMD64_HOST="${CALIPER_AMD64_HOST:-sambou@192.168.0.210}"
ENGINE="${CONTAINER_ENGINE:-$(command -v podman 2>/dev/null || command -v docker 2>/dev/null)}"
REPO_ROOT="$(git rev-parse --show-toplevel)"

DO_ARM64=true
DO_AMD64=false
DO_COMPARE=false

for arg in "$@"; do
    case "$arg" in
        --amd64)      DO_AMD64=true ;;
        --amd64-only) DO_AMD64=true; DO_ARM64=false ;;
        --compare)    DO_COMPARE=true ;;
        *) echo "Unknown arg: $arg" >&2; exit 1 ;;
    esac
done

pass() { printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$1"; }
info() { printf "  → %s\n" "$1"; }

verify_image() {
    local engine="$1"
    local tag="$2"
    local arch="$3"
    local failed=0

    printf "\n=== Verifying %s (%s) ===\n" "$tag" "$arch"

    if "$engine" run --rm "$tag" --version >/dev/null 2>&1; then
        pass "caliper CLI + checksum verification"
    else
        fail "caliper CLI"; failed=1
    fi

    local tools="opengrep scancode lizard mypy"
    for tool in $tools; do
        if "$engine" run --rm --entrypoint="" "$tag" "$tool" --version >/dev/null 2>&1; then
            pass "$tool"
        else
            fail "$tool"; failed=1
        fi
    done

    local size
    size=$("$engine" images --format "{{.Size}}" "$tag" 2>/dev/null | head -1)
    info "Image size: $size"

    return $failed
}

build_arm64() {
    printf "\n=== Building arm64 (local) ===\n"
    "$ENGINE" build --platform linux/arm64 -t "$TAG" "$REPO_ROOT" 2>&1

    if [ $? -eq 0 ]; then
        pass "arm64 build succeeded"
        verify_image "$ENGINE" "$TAG" "arm64"
    else
        fail "arm64 build failed"
        return 1
    fi
}

build_amd64() {
    printf "\n=== Building amd64 (remote: %s) ===\n" "$AMD64_HOST"

    local remote_dir="/tmp/caliper-build-$$"
    info "Syncing repo to $AMD64_HOST:$remote_dir"

    ssh "$AMD64_HOST" "mkdir -p $remote_dir"
    rsync -az --exclude='.venv' --exclude='__pycache__' --exclude='.temp' \
        --exclude='.git' --exclude='node_modules' \
        "$REPO_ROOT/" "$AMD64_HOST:$remote_dir/"

    info "Building on remote host"
    ssh "$AMD64_HOST" "cd $remote_dir && docker buildx build --builder caliper-builder --allow security.insecure --platform linux/amd64 --load -t $TAG . 2>&1"

    if [ $? -eq 0 ]; then
        pass "amd64 build succeeded"
        info "Verifying on remote host"
        ssh "$AMD64_HOST" "cd $remote_dir && docker run --rm $TAG --version" 2>&1
        local tools="opengrep scancode lizard mypy"
        for tool in $tools; do
            if ssh "$AMD64_HOST" "docker run --rm --entrypoint='' $TAG $tool --version" >/dev/null 2>&1; then
                pass "$tool (amd64)"
            else
                fail "$tool (amd64)"
            fi
        done
        local size
        size=$(ssh "$AMD64_HOST" "docker images --format '{{.Size}}' $TAG" 2>/dev/null | head -1)
        info "Image size (amd64): $size"
    else
        fail "amd64 build failed"
    fi

    info "Cleaning up remote build dir"
    ssh "$AMD64_HOST" "rm -rf $remote_dir"
}

printf "caliper image build — %s\n" "$(date +%Y-%m-%d\ %H:%M:%S)"
printf "Engine: %s\n" "$ENGINE"
printf "Tag: %s\n" "$TAG"

if $DO_ARM64; then
    build_arm64
fi

if $DO_AMD64; then
    build_amd64
fi

printf "\n=== Done ===\n"
