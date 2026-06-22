# syntax=docker/dockerfile:1
# Caliper — DHI hardened multi-stage production image
#
# Build:  podman build --platform linux/amd64 --security-opt apparmor=unconfined -t caliper:amd64 .
# Test:   CALIPER_IMAGE=caliper:latest uv run pytest tests/integration/test_dockerfile.py -v

# ── Version pins ─────────────────────────────────────────────────────────────
ARG SYFT_VERSION=1.43.0
ARG TRIVY_VERSION=0.70.0
ARG OSV_VERSION=2.3.5
ARG OPA_VERSION=1.15.2
ARG GITLEAKS_VERSION=8.30.1
ARG JQ_VERSION=1.7.1
ARG KUBE_LINTER_VERSION=0.8.3
ARG OPENGREP_VERSION=1.20.0
ARG SCANCODE_VERSION=32.3.0
ARG LIZARD_VERSION=1.17.13
ARG MYPY_VERSION=1.15.0
ARG CSPELL_VERSION=8.18.1
ARG AWS_CDK_VERSION=2.1120.0
ARG CFN_NAG_VERSION=0.8.10
ARG LS_LINT_VERSION=2.3.1
ARG PMD_VERSION=7.24.0
ARG SWIFTLINT_VERSION=0.57.1
ARG SWIFTFORMAT_VERSION=0.61.1

# ── Source revision pins ─────────────────────────────────────────────────────
# GitHub release assets are still addressed by release version because that is
# how upstream publishes binaries; each asset is sha256-verified below and the
# dereferenced source commit is pinned here for auditability.
ARG SYFT_COMMIT=390cf6cce0463d44c20270dea637bcb3833eee02
ARG TRIVY_COMMIT=8a3177aedf7ee0864920eb1852eef031cd3742b8
ARG OSV_COMMIT=30bcc134e23fbc35731021ee43ec433c483715d7
ARG OPA_COMMIT=37b80cb7b620c82049fb5775fe83b841ff3677ba
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
ARG KUBE_LINTER_COMMIT=10ae003038c81855aca8489df5e35da150f4dc2e
ARG JQ_COMMIT=71c2ab509a8628dbbad4bc7b3f98a64aa90d3297
ARG LS_LINT_COMMIT=b530dd769e259aa9fc546cc3c0098e6a0c82870e

# ── SHA256 checksums — per architecture ──────────────────────────────────────
# Build fails hard if any hash mismatches — no silent pass.
# PMD is architecture-independent (Java).
ARG SYFT_SHA256_ARM64=afe92510c467f952a009b994f2d998ff8f9dd266dc26eca55d14a0dd46fec7f2
ARG TRIVY_SHA256_ARM64=2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d
ARG OSV_SHA256_ARM64=fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50
ARG OPA_SHA256_ARM64=6651bf5a80cfec6ba6a2d3b6a550b8f748d9cade1c74d54b5f854782f9bea67a
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG JQ_SHA256_ARM64=4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5
ARG KUBE_LINTER_SHA256_ARM64=802e1b09eabd08f6f0a060a6b8ab2bf7bc7e6bf4f673bb2692303704c84b3e22
ARG LS_LINT_SHA256_ARM64=2abdb71243c619f0bb29587be5c228bec84c107985f2c066139ef0ec35fd3a99
ARG PMD_SHA256=110934b36d39c19094d1b77386931978093f238f2c2f1851748822b69c7367ac
ARG OPENGREP_SHA256_ARM64=3bade33c9aee60edf88899cac2b58086bf728caf0a93aced97dd77c272a740f1
# SwiftLint — arm64 Linux binary not yet available; plugin degrades gracefully if missing
ARG SWIFTLINT_SHA256_AMD64=81cb02135897dc982b4d1049dba8510db3e982b0b0e8e138293982d77e4154e0
# SwiftFormat — linux binaries for both arches (0.61.1)
ARG SWIFTFORMAT_SHA256_AMD64=7bc8706e3fd51963f1f29eb99098ebdf482f3497fa527c68e6cf75cbee29c77a
ARG SWIFTFORMAT_SHA256_ARM64=42a35b557a6d56975fba3a48e78d39ab5388c8faac65d4819f25d3e20c7504c0

# AMD64 checksums
ARG SYFT_SHA256_AMD64=7b98251d2d08926bb5d4639b56b1f0996a58ef6667c5830e3fe3cd3ad5f4214a
ARG TRIVY_SHA256_AMD64=8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9
ARG OSV_SHA256_AMD64=bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b
ARG OPA_SHA256_AMD64=a9d9481e463e7af8cb1a2cd7c3deb764f0327b3281c54e632546c2f425fc0824
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG JQ_SHA256_AMD64=5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5
ARG KUBE_LINTER_SHA256_AMD64=1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df
ARG LS_LINT_SHA256_AMD64=b5a0d2e4427ad039fbc574551f17679f38f142b25d15e0e538769f8cf15af397
ARG OPENGREP_SHA256_AMD64=09cbb4c938df696246018a678823adaa8d651a774f321fd19fb5ad44c0129860
ARG UV_COMMIT=0e961dd9a2bb6f73493d9e8398b725ad2d3b3837

# ════════════════════════════════════════════════════════════════════════════
# Arch-aware Python base — select the right platform image before Stage 1.
# Each digest is the platform-specific manifest for python:3.12.13 on Debian 13 (trixie).
# TARGETARCH is injected by BuildKit from --platform (default: amd64).
# ════════════════════════════════════════════════════════════════════════════
ARG TARGETARCH=amd64
ARG PYTHON_SHA256_AMD64=sha256:4386a385d81dba9f72ed72a6fe4237755d7f5440c84b417650f38336bbc43117
ARG PYTHON_SHA256_ARM64=sha256:5ca4bfc4580d33083387dfc582569b7ec8cf12438961469c74b765c49780aa02

# docker-library/python revision:
# amd64: 3362634339580d3232e65a66dd5a36c47ae7ff14
FROM docker.io/library/python@${PYTHON_SHA256_AMD64} AS python_base_amd64
# arm64: 9420c53ba876a39b83e2f08732920b62782c33d94cd04860a13c3eaf9dc1a5b0
FROM docker.io/library/python@${PYTHON_SHA256_ARM64} AS python_base_arm64

# ════════════════════════════════════════════════════════════════════════════
# Stage 1: builder
# ════════════════════════════════════════════════════════════════════════════
FROM python_base_${TARGETARCH} AS builder

ARG SYFT_VERSION TRIVY_VERSION OSV_VERSION OPA_VERSION GITLEAKS_VERSION JQ_VERSION KUBE_LINTER_VERSION PMD_VERSION LS_LINT_VERSION SWIFTLINT_VERSION
ARG SYFT_COMMIT TRIVY_COMMIT OSV_COMMIT OPA_COMMIT GITLEAKS_COMMIT KUBE_LINTER_COMMIT JQ_COMMIT LS_LINT_COMMIT UV_COMMIT
ARG OPENGREP_VERSION SCANCODE_VERSION LIZARD_VERSION MYPY_VERSION
ARG SYFT_SHA256_ARM64 TRIVY_SHA256_ARM64 OSV_SHA256_ARM64 OPA_SHA256_ARM64 GITLEAKS_SHA256_ARM64 JQ_SHA256_ARM64 KUBE_LINTER_SHA256_ARM64 LS_LINT_SHA256_ARM64 PMD_SHA256
ARG SYFT_SHA256_AMD64 TRIVY_SHA256_AMD64 OSV_SHA256_AMD64 OPA_SHA256_AMD64 GITLEAKS_SHA256_AMD64 JQ_SHA256_AMD64 KUBE_LINTER_SHA256_AMD64 LS_LINT_SHA256_AMD64 SWIFTLINT_SHA256_AMD64
ARG TARGETARCH

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip pkg-config libicu-dev gcc g++ python3-dev

RUN mkdir -p /staging/gobin /staging/jq /staging/pmd /staging/scripts /staging/swiftbin

# ── All Go/native binaries — single layer, arch-aware ────────────────────────
# kube-linter uses no arch suffix for amd64, _arm64 suffix for arm64.
RUN set -eux; \
    case "${TARGETARCH}" in \
        "amd64") \
            SYFT_ARCH="amd64";       SYFT_SHA="${SYFT_SHA256_AMD64}"; \
            TRIVY_ARCH="64bit";      TRIVY_SHA="${TRIVY_SHA256_AMD64}"; \
            OSV_ARCH="amd64";        OSV_SHA="${OSV_SHA256_AMD64}"; \
            OPA_ARCH="amd64_static"; OPA_SHA="${OPA_SHA256_AMD64}"; \
            GITLEAKS_ARCH="x64";     GITLEAKS_SHA="${GITLEAKS_SHA256_AMD64}"; \
            JQ_ARCH="amd64";         JQ_SHA="${JQ_SHA256_AMD64}"; \
            KL_SUFFIX="";           KL_SHA="${KUBE_LINTER_SHA256_AMD64}"; \
            LL_ARCH="amd64";         LL_SHA="${LS_LINT_SHA256_AMD64}" ;; \
        "arm64") \
            SYFT_ARCH="arm64";       SYFT_SHA="${SYFT_SHA256_ARM64}"; \
            TRIVY_ARCH="ARM64";      TRIVY_SHA="${TRIVY_SHA256_ARM64}"; \
            OSV_ARCH="arm64";        OSV_SHA="${OSV_SHA256_ARM64}"; \
            OPA_ARCH="arm64_static"; OPA_SHA="${OPA_SHA256_ARM64}"; \
            GITLEAKS_ARCH="arm64";   GITLEAKS_SHA="${GITLEAKS_SHA256_ARM64}"; \
            JQ_ARCH="arm64";         JQ_SHA="${JQ_SHA256_ARM64}"; \
            KL_SUFFIX="_arm64";     KL_SHA="${KUBE_LINTER_SHA256_ARM64}"; \
            LL_ARCH="arm64";         LL_SHA="${LS_LINT_SHA256_ARM64}" ;; \
        *) echo "Fatal: unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz"; \
    echo "${SYFT_SHA}  /tmp/syft.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/syft.tar.gz -C /staging/gobin syft; \
    curl -sSfL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    echo "${TRIVY_SHA}  /tmp/trivy.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /staging/gobin trivy; \
    curl -sSfL -o /staging/gobin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH}"; \
    echo "${OSV_SHA}  /staging/gobin/osv-scanner" | sha256sum --strict -c -; \
    curl -sSfL -o /staging/gobin/opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${OPA_ARCH}"; \
    echo "${OPA_SHA}  /staging/gobin/opa" | sha256sum --strict -c -; \
    curl -sSfL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA}  /tmp/gitleaks.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /staging/gobin gitleaks; \
    curl -sSfL -o /tmp/kube-linter.tar.gz "https://github.com/stackrox/kube-linter/releases/download/v${KUBE_LINTER_VERSION}/kube-linter-linux${KL_SUFFIX}.tar.gz"; \
    echo "${KL_SHA}  /tmp/kube-linter.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/kube-linter.tar.gz -C /staging/gobin kube-linter; \
    curl -sSfL -o /staging/gobin/ls-lint "https://github.com/loeffel-io/ls-lint/releases/download/v${LS_LINT_VERSION}/ls-lint-linux-${LL_ARCH}"; \
    echo "${LL_SHA}  /staging/gobin/ls-lint" | sha256sum --strict -c -; \
    curl -sSfL -o /tmp/pmd.zip "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip"; \
    echo "${PMD_SHA256}  /tmp/pmd.zip" | sha256sum --strict -c -; \
    unzip -q /tmp/pmd.zip -d /staging/pmd; \
    curl -sSfL -o /staging/jq/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${JQ_ARCH}"; \
    echo "${JQ_SHA}  /staging/jq/jq" | sha256sum --strict -c -; \
    rm -f /tmp/*.tar.gz /tmp/*.zip; \
    chmod +x /staging/gobin/* /staging/jq/jq

# ── SwiftFormat (amd64 + arm64) + SwiftLint (amd64 only) → /staging/swiftbin ──
# SwiftFormat ships linux binaries for both arches. SwiftLint ships amd64 only;
# it is best-effort and its plugin degrades to NOT_INSTALLED when absent. Both
# land in /staging/swiftbin, which the runtime stage COPYs as a directory so a
# missing (arm64) swiftlint does not break the build.
ARG SWIFTFORMAT_VERSION SWIFTFORMAT_SHA256_AMD64 SWIFTFORMAT_SHA256_ARM64
RUN set -eux; \
    case "${TARGETARCH}" in \
        "amd64") SF_ASSET="swiftformat_linux.zip";         SF_BIN="swiftformat_linux";         SF_SHA="${SWIFTFORMAT_SHA256_AMD64}" ;; \
        "arm64") SF_ASSET="swiftformat_linux_aarch64.zip"; SF_BIN="swiftformat_linux_aarch64"; SF_SHA="${SWIFTFORMAT_SHA256_ARM64}" ;; \
        *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/swiftformat.zip \
        "https://github.com/nicklockwood/SwiftFormat/releases/download/${SWIFTFORMAT_VERSION}/${SF_ASSET}"; \
    echo "${SF_SHA}  /tmp/swiftformat.zip" | sha256sum --strict -c -; \
    unzip -q /tmp/swiftformat.zip "${SF_BIN}" -d /tmp/; \
    mv "/tmp/${SF_BIN}" /staging/swiftbin/swiftformat; \
    chmod +x /staging/swiftbin/swiftformat; \
    rm /tmp/swiftformat.zip; \
    if [ "${TARGETARCH}" = "amd64" ] && [ "${SWIFTLINT_SHA256_AMD64}" != "FIXME_verify_sha256_before_building" ]; then \
        curl -sSfL -o /tmp/swiftlint.zip \
            "https://github.com/realm/SwiftLint/releases/download/${SWIFTLINT_VERSION}/swiftlint_linux.zip"; \
        echo "${SWIFTLINT_SHA256_AMD64}  /tmp/swiftlint.zip" | sha256sum --strict -c -; \
        unzip -q /tmp/swiftlint.zip swiftlint -d /staging/swiftbin/; \
        chmod +x /staging/swiftbin/swiftlint; \
        rm /tmp/swiftlint.zip; \
    else \
        echo "SwiftLint: skipping (arm64 or SHA256 not yet verified)"; \
    fi

# ── Build-time checksums for runtime verification ────────────────────────────
RUN for b in syft trivy osv-scanner opa gitleaks kube-linter ls-lint; do \
      sha256sum "/staging/gobin/$b" | sed "s|/staging/gobin/$b|/usr/local/bin/$b|"; \
    done > /staging/scripts/checksums.txt \
    && sha256sum /staging/jq/jq | sed 's|/staging/jq/jq|/usr/bin/jq|' >> /staging/scripts/checksums.txt

RUN printf '%s\n' \
      "python=docker-library/python@3362634339580d3232e65a66dd5a36c47ae7ff14" \
      "uv=${UV_COMMIT}" \
      "syft=${SYFT_COMMIT}" \
      "trivy=${TRIVY_COMMIT}" \
      "osv-scanner=${OSV_COMMIT}" \
      "opa=${OPA_COMMIT}" \
      "gitleaks=${GITLEAKS_COMMIT}" \
      "kube-linter=${KUBE_LINTER_COMMIT}" \
      "jq=${JQ_COMMIT}" \
      "ls-lint=${LS_LINT_COMMIT}" \
    > /staging/scripts/release-revisions.txt

# ── Python: lockfile-based venv install ──────────────────────────────────────
# astral-sh/uv revision:
# 0e961dd9a2bb6f73493d9e8398b725ad2d3b3837
COPY --from=ghcr.io/astral-sh/uv@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 /uv /usr/local/bin/uv
WORKDIR /opt/caliper

COPY pyproject.toml uv.lock LICENSE README.md ./
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra all --no-editable --no-install-project

COPY src/ src/
COPY policies/ policies/
COPY migrations/ migrations/
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra all --no-editable

# Scanner tools — external CLIs installed into the same venv, version-pinned by ARG.
# scancode is intentionally ORPHANED (disabled): its transitive dep (extractcode-7z)
# lacks arm64 wheels and breaks cross-platform uv sync. To re-enable, add
# "scancode-toolkit==${SCANCODE_VERSION}" to this install, restore the deferred-import
# wrapper, and add "scancode" back to CALIPER_ENABLED_SCANNERS below.
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv pip install "lizard==${LIZARD_VERSION}" "mypy==${MYPY_VERSION}"

# opengrep — self-contained binary, sha256-verified
ARG OPENGREP_SHA256_ARM64 OPENGREP_SHA256_AMD64
RUN set -eux; \
    case "${TARGETARCH}" in \
        "amd64") OG_ARCH="x86";     OG_SHA="${OPENGREP_SHA256_AMD64}" ;; \
        "arm64") OG_ARCH="aarch64"; OG_SHA="${OPENGREP_SHA256_ARM64}" ;; \
        *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /usr/local/bin/opengrep \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${OG_ARCH}"; \
    echo "${OG_SHA}  /usr/local/bin/opengrep" | sha256sum --strict -c -; \
    chmod +x /usr/local/bin/opengrep; \
    sha256sum /usr/local/bin/opengrep >> /staging/scripts/checksums.txt

# scancode wrapper removed — scancode is orphaned (see install step above).

# ════════════════════════════════════════════════════════════════════════════
# Stage 2: runtime
# ════════════════════════════════════════════════════════════════════════════
ARG TARGETARCH=amd64
FROM python_base_${TARGETARCH}

ARG CSPELL_VERSION
ARG PMD_VERSION

LABEL org.opencontainers.image.title="Caliper" \
      org.opencontainers.image.description="DHI hardened multi-stage production scanner" \
      org.opencontainers.image.source="https://github.com/gitrdunhq/caliper" \
      org.opencontainers.image.base.revision.amd64="3362634339580d3232e65a66dd5a36c47ae7ff14" \
      org.opencontainers.image.base.revision.arm64="9420c53ba876a39b83e2f08732920b62782c33d94cd04860a13c3eaf9dc1a5b0"

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      git clamav clamav-freshclam libicu76 libarchive13t64 ca-certificates curl gnupg \
      default-jre-headless ruby ruby-dev build-essential

# ── Node.js 22 — GPG-verified repo, no curl|bash ─────────────────────────────
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
         | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
         > /etc/apt/sources.list.d/nodesource.list

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g \
         "cspell@${CSPELL_VERSION}" \
         "@cspell/cspell-json-reporter@${CSPELL_VERSION}" \
         "aws-cdk@${AWS_CDK_VERSION}" \
         --no-fund --no-audit \
    && npm cache clean --force \
    && gem install "cfn-nag" -v "${CFN_NAG_VERSION}" --no-document \
    && apt-get purge -y build-essential ruby-dev curl gnupg \
    && apt-get autoremove -y

# Non-root user — scanners must not run as root.
RUN groupadd -r caliper && useradd -r -g caliper -m -d /home/caliper -s /bin/false caliper \
    && mkdir -p /var/lib/clamav /var/log/clamav \
    && chown -R caliper:caliper /var/lib/clamav /var/log/clamav \
    && chmod 0750 /var/lib/clamav /var/log/clamav

# ── Staged artifacts from builder ────────────────────────────────────────────
COPY --from=builder /staging/gobin/syft        /usr/local/bin/syft
COPY --from=builder /staging/gobin/trivy       /usr/local/bin/trivy
COPY --from=builder /staging/gobin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /staging/gobin/opa         /usr/local/bin/opa
COPY --from=builder /staging/gobin/gitleaks    /usr/local/bin/gitleaks
COPY --from=builder /staging/gobin/kube-linter /usr/local/bin/kube-linter
COPY --from=builder /staging/gobin/ls-lint    /usr/local/bin/ls-lint
COPY --from=builder /usr/local/bin/opengrep   /usr/local/bin/opengrep
COPY --from=builder /staging/pmd/              /opt/pmd/
COPY --from=builder /staging/jq/jq             /usr/bin/jq
# Swift tools (swiftformat always; swiftlint on amd64) — dir COPY tolerates absence.
COPY --from=builder /staging/swiftbin/         /usr/local/bin/

# Venv with all Python deps + caliper itself — console_scripts are in .venv/bin/
COPY --from=builder /opt/caliper/.venv /opt/caliper/.venv
COPY --from=builder /opt/caliper/policies/ /opt/caliper/policies/

RUN mkdir -p /opt/caliper/scripts
COPY --from=builder /staging/scripts/checksums.txt /opt/caliper/scripts/checksums.txt
COPY --from=builder /staging/scripts/release-revisions.txt /opt/caliper/scripts/release-revisions.txt
COPY scripts/verify-checksums.sh /opt/caliper/scripts/verify-checksums.sh
RUN chmod +x /opt/caliper/scripts/verify-checksums.sh

# PMD wrapper — Java-based, not in the venv
RUN printf '#!/bin/sh\nexec /opt/pmd/pmd-bin-%s/bin/pmd "$@"\n' "${PMD_VERSION}" > /usr/local/bin/pmd \
    && chmod +x /usr/local/bin/pmd

# Entrypoint verifies binary integrity before running caliper
RUN printf '#!/bin/sh\n/opt/caliper/scripts/verify-checksums.sh || exit 1\nexec caliper "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

ENV PATH="/opt/caliper/.venv/bin:$PATH" \
    VIRTUAL_ENV="/opt/caliper/.venv" \
    TRIVY_CACHE_DIR=/home/caliper/.cache/trivy \
    MYPY_CACHE_DIR=/home/caliper/.cache/mypy \
    OPENGREP_USER_DATA_FOLDER=/home/caliper/.cache/opengrep \
    XDG_CACHE_HOME=/home/caliper/.cache \
    CALIPER_OPERATING_MODE=monitor \
    CALIPER_OPA_POLICY_PATH=/opt/caliper/policies \
    CALIPER_ENABLED_SCANNERS=syft,osv-scanner,trivy,semgrep,gitleaks,kube-linter,pmd,lizard,mypy,cspell,ls-lint,cdk-nag,cfn-nag

USER caliper
WORKDIR /home/caliper

HEALTHCHECK --interval=5m --timeout=30s --retries=3 \
  CMD caliper healthcheck || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
