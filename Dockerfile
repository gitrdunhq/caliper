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
ARG PYREFLY_VERSION=1.1.1
ARG RADON_VERSION=6.0.1
ARG LS_LINT_VERSION=2.3.1
ARG PMD_VERSION=7.24.0
ARG SWIFTLINT_VERSION=0.57.1
# semgrep/semgrep-rules has no release tags; pin the community rule snapshot by
# commit. Baked into the image so opengrep never fetches registry packs at scan
# time (no network in the scan path, no rule drift between runs).
ARG SEMGREP_RULES_COMMIT=40b8c63f75dc7c22c8a77482d73bfb864b146f7e
# The semgrep/semgrep-rules snapshot is licensed for internal use only (Semgrep
# Rules License v1.0 forbids distribution), so the PUBLISHED image excludes it.
# Build your own image with --build-arg INCLUDE_SEMGREP_RULES=1 to bake it in
# for your own internal use; host runs use scripts/snapshot-semgrep-rules.sh.
ARG INCLUDE_SEMGREP_RULES=0
# gitrdunhq/caliper-community-rules: shared Kirby-annotated org rules. Pinned by
# commit like semgrep-rules; bump with scripts/snapshot-community-rules.sh --bump.
ARG COMMUNITY_RULES_COMMIT=44bbf24ed311b2f95e03c703849237695d10b9eb
# MIT-licensed third-party rule sets, vendored as pinned snapshots under
# /opt/caliper/community-rules/vendor/<name>/ with their LICENSE files kept.
# GitLab's sast-rules mixes licenses per file; only files whose header says
# "License: MIT" are staged (the lgpl / lgpl-cc re-licensed upstream copies
# are dropped, which also avoids double-reporting the semgrep-rules snapshot).
ARG GITLAB_SAST_RULES_COMMIT=7051ea7602a210dfb0793916afedc9a0555addb7
ARG SEMGREP_GO_COMMIT=db0227c03f4b3c4e71d900188d51db4c81d66932
ARG SEMGREP_C_RULES_COMMIT=33155497b25b4639193db016962af2df46290b10

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
# Python base — one multi-arch index digest for python:3.12.13-slim-trixie.
# Tag + digest on a single FROM line is what Dependabot's `docker` ecosystem
# understands: it opens a PR whenever docker-library rebuilds the tag (Debian
# security updates), so the pin never silently goes stale again. BuildKit picks
# the platform manifest out of the index from --platform / TARGETARCH.
# ════════════════════════════════════════════════════════════════════════════
ARG TARGETARCH=amd64
FROM docker.io/library/python:3.14.7-slim-trixie@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS python_base

# ════════════════════════════════════════════════════════════════════════════
# Stage 1: builder
# ════════════════════════════════════════════════════════════════════════════
FROM python_base AS builder

ARG SYFT_VERSION TRIVY_VERSION OSV_VERSION OPA_VERSION GITLEAKS_VERSION JQ_VERSION KUBE_LINTER_VERSION PMD_VERSION LS_LINT_VERSION SWIFTLINT_VERSION
ARG SYFT_COMMIT TRIVY_COMMIT OSV_COMMIT OPA_COMMIT GITLEAKS_COMMIT KUBE_LINTER_COMMIT JQ_COMMIT LS_LINT_COMMIT UV_COMMIT
ARG OPENGREP_VERSION SCANCODE_VERSION LIZARD_VERSION PYREFLY_VERSION RADON_VERSION
ARG SEMGREP_RULES_COMMIT
ARG INCLUDE_SEMGREP_RULES
ARG COMMUNITY_RULES_COMMIT
ARG GITLAB_SAST_RULES_COMMIT
ARG SEMGREP_GO_COMMIT
ARG SEMGREP_C_RULES_COMMIT
ARG SYFT_SHA256_ARM64 TRIVY_SHA256_ARM64 OSV_SHA256_ARM64 OPA_SHA256_ARM64 GITLEAKS_SHA256_ARM64 JQ_SHA256_ARM64 KUBE_LINTER_SHA256_ARM64 LS_LINT_SHA256_ARM64 PMD_SHA256
ARG SYFT_SHA256_AMD64 TRIVY_SHA256_AMD64 OSV_SHA256_AMD64 OPA_SHA256_AMD64 GITLEAKS_SHA256_AMD64 JQ_SHA256_AMD64 KUBE_LINTER_SHA256_AMD64 LS_LINT_SHA256_AMD64 SWIFTLINT_SHA256_AMD64
ARG TARGETARCH

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip pkg-config libicu-dev gcc g++ python3-dev \
      openjdk-21-jdk-headless

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
    PMD_LIB="$(echo /staging/pmd/pmd-bin-*/lib)"; \
    KEEP=" core cli python java typescript javascript go ruby kotlin swift rust cpp cs php scala dart lua groovy perl "; \
    for j in "${PMD_LIB}"/pmd-*.jar; do \
        n="$(basename "$j" .jar)"; lang="${n#pmd-}"; lang="${lang%%-[0-9]*}"; \
        case "${KEEP}" in *" ${lang} "*) ;; *) rm -f "$j" ;; esac; \
    done; \
    rm -f "${PMD_LIB}"/apex-ls_* "${PMD_LIB}"/sobject-types-* "${PMD_LIB}"/trees2_* "${PMD_LIB}"/pmd-designer-*; \
    echo "PMD jars kept: $(ls "${PMD_LIB}" | wc -l) ($(du -sh "${PMD_LIB}" | cut -f1))"; \
    curl -sSfL -o /staging/jq/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${JQ_ARCH}"; \
    echo "${JQ_SHA}  /staging/jq/jq" | sha256sum --strict -c -; \
    rm -f /tmp/*.tar.gz /tmp/*.zip; \
    chmod +x /staging/gobin/* /staging/jq/jq

# ── Minimal JRE for PMD/CPD via jlink ────────────────────────────────────────
# default-jre-headless is ~200 MB; jlink keeps only the modules PMD's jars
# actually reference (jdeps, deterministic for the pinned PMD_VERSION) plus
# jdk.unsupported (guava/jna use sun.misc.Unsafe). Falls back to a fixed
# module list if jdeps cannot analyse a jar.
RUN set -eux; \
    PMD_LIB="$(echo /staging/pmd/pmd-bin-*/lib)"; \
    MODS="$(jdeps -R --multi-release 21 --ignore-missing-deps --print-module-deps \
              --class-path "${PMD_LIB}/*" "${PMD_LIB}"/*.jar 2>/dev/null \
            | grep -E '^[a-z][a-z0-9.]*(,[a-z][a-z0-9.]*)*$' | tail -1 || true)"; \
    MODS="${MODS:-java.base,java.desktop,java.logging,java.management,java.naming,java.sql,java.xml}"; \
    echo "jlink modules: ${MODS},jdk.unsupported"; \
    jlink --add-modules "${MODS},jdk.unsupported" --strip-debug --no-man-pages --no-header-files \
          --compress=2 --output /staging/jre; \
    /staging/jre/bin/java -version; \
    du -sh /staging/jre

# ── SwiftLint (amd64 only) → /staging/swiftbin ────────────────────────────────
# SwiftLint ships amd64 only; it is best-effort and its plugin degrades to
# NOT_INSTALLED when absent. It lands in /staging/swiftbin, which the runtime
# stage COPYs as a directory so a missing (arm64) swiftlint does not break the build.
RUN set -eux; \
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
      "semgrep-rules=$([ "${INCLUDE_SEMGREP_RULES}" = "1" ] && printf '%s' "${SEMGREP_RULES_COMMIT}" || printf excluded)" \
      "community-rules=${COMMUNITY_RULES_COMMIT}" \
      "gitlab-sast-rules=${GITLAB_SAST_RULES_COMMIT}" \
      "semgrep-go=${SEMGREP_GO_COMMIT}" \
      "semgrep-c-rules=${SEMGREP_C_RULES_COMMIT}" \
    > /staging/scripts/release-revisions.txt

# semgrep-rules snapshot — OPT-IN (see INCLUDE_SEMGREP_RULES above). When
# enabled it is fetched by commit (content-addressed) and reduced to the
# language directories the runner maps file types to (see
# plugins/_runners/semgrep_runner.py). When disabled the directory is left
# empty and the runner fails open to org + community + vendored rules only.
RUN set -eux; \
    mkdir -p /staging/semgrep-rules; \
    if [ "${INCLUDE_SEMGREP_RULES}" != "1" ]; then \
      printf '%s\n' "excluded: Semgrep Rules License v1.0 forbids redistribution; rebuild with --build-arg INCLUDE_SEMGREP_RULES=1 for internal use" > /staging/semgrep-rules/EXCLUDED; \
      exit 0; \
    fi; \
    curl -sSfL -o /tmp/semgrep-rules.tar.gz \
      "https://github.com/semgrep/semgrep-rules/archive/${SEMGREP_RULES_COMMIT}.tar.gz"; \
    tar -xzf /tmp/semgrep-rules.tar.gz -C /staging/semgrep-rules --strip-components=1 \
      $(for d in bash csharp dockerfile generic go html java javascript json kotlin php python ruby rust swift terraform typescript yaml; do printf 'semgrep-rules-%s/%s ' "${SEMGREP_RULES_COMMIT}" "$d"; done); \
    rm -f /tmp/semgrep-rules.tar.gz; \
    find /staging/semgrep-rules -type f ! -name '*.yaml' ! -name '*.yml' -delete; \
    printf '%s\n' "${SEMGREP_RULES_COMMIT}" > /staging/semgrep-rules/COMMIT; \
    test "$(find /staging/semgrep-rules -name '*.yaml' | wc -l)" -gt 100

# caliper-community-rules snapshot — only the opengrep-loadable rule files
# (rules/**/semgrep/*.yaml and rules/**/dockerfile-semgrep/*.yaml); fixtures
# under tests/ and every other scanner's config are dropped so opengrep never
# sees a non-rule YAML. Fetched by commit, so two builds of the same pin are
# byte-identical and the scan path stays offline.
RUN set -eux; \
    mkdir -p /staging/community-rules /tmp/community-rules; \
    curl -sSfL -o /tmp/community-rules.tar.gz \
      "https://github.com/gitrdunhq/caliper-community-rules/archive/${COMMUNITY_RULES_COMMIT}.tar.gz"; \
    tar -xzf /tmp/community-rules.tar.gz -C /tmp/community-rules --strip-components=1; \
    find /tmp/community-rules/rules -type f \( -path '*/semgrep/*.yaml' -o -path '*/dockerfile-semgrep/*.yaml' \) \
      ! -path '*/tests/*' -exec sh -c 'd="/staging/community-rules/${1#/tmp/community-rules/}"; mkdir -p "$(dirname "$d")"; cp "$1" "$d"' _ {} \; ; \
    rm -rf /tmp/community-rules /tmp/community-rules.tar.gz; \
    printf '%s\n' "${COMMUNITY_RULES_COMMIT}" > /staging/community-rules/COMMIT; \
    test "$(find /staging/community-rules -name '*.yaml' | wc -l)" -gt 5

# Vendored MIT rule sets (see the ARG block). Each lands as
# /staging/community-rules/vendor/<name>/ with LICENSE + COMMIT; only rule
# YAML is kept, tests/qa/mappings/ci trees are dropped.
RUN set -eux; \
    V=/staging/community-rules/vendor; mkdir -p "$V" /tmp/vr; \
    fetch() { curl -sSfL -o "/tmp/vr/$1.tar.gz" "$2"; mkdir -p "/tmp/vr/$1"; tar -xzf "/tmp/vr/$1.tar.gz" -C "/tmp/vr/$1" --strip-components=1; }; \
    fetch gitlab-sast-rules "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/${GITLAB_SAST_RULES_COMMIT}/sast-rules-${GITLAB_SAST_RULES_COMMIT}.tar.gz"; \
    fetch semgrep-go "https://github.com/dgryski/semgrep-go/archive/${SEMGREP_GO_COMMIT}.tar.gz"; \
    fetch semgrep-c-rules "https://github.com/0xdea/semgrep-rules/archive/${SEMGREP_C_RULES_COMMIT}.tar.gz"; \
    mkdir -p "$V/gitlab-sast-rules"; cp /tmp/vr/gitlab-sast-rules/LICENSE "$V/gitlab-sast-rules/LICENSE"; \
    grep -rl '^# License: MIT' --include='*.yml' /tmp/vr/gitlab-sast-rules | grep -v '/test\|/qa/\|/mappings/\|/ci/' \
      | while read -r f; do d="$V/gitlab-sast-rules/${f#/tmp/vr/gitlab-sast-rules/}"; mkdir -p "$(dirname "$d")"; cp "$f" "$d"; done; \
    for n in semgrep-go semgrep-c-rules; do mkdir -p "$V/$n"; cp /tmp/vr/$n/LICENSE* "$V/$n/"; \
      find /tmp/vr/$n -type f \( -name '*.yaml' -o -name '*.yml' \) ! -path '*/test*' ! -path '*/.github/*' ! -path '*/noisy/*' ! -name '.pre-commit*' \
        -exec sh -c 'd="$2/${1#/tmp/vr/$3/}"; mkdir -p "$(dirname "$d")"; cp "$1" "$d"' _ {} "$V/$n" "$n" \; ; done; \
    printf '%s\n' "${GITLAB_SAST_RULES_COMMIT}" > "$V/gitlab-sast-rules/COMMIT"; \
    printf '%s\n' "${SEMGREP_GO_COMMIT}" > "$V/semgrep-go/COMMIT"; \
    printf '%s\n' "${SEMGREP_C_RULES_COMMIT}" > "$V/semgrep-c-rules/COMMIT"; \
    rm -rf /tmp/vr; \
    test "$(find "$V/gitlab-sast-rules" -name '*.yml' | wc -l)" -gt 200; \
    test "$(find "$V/semgrep-go" -name '*.yml' -o -name '*.yaml' | wc -l)" -gt 30; \
    test "$(find "$V/semgrep-c-rules" -name '*.yaml' | wc -l)" -gt 30

# ── Python: lockfile-based venv install ──────────────────────────────────────
# astral-sh/uv revision:
# 0e961dd9a2bb6f73493d9e8398b725ad2d3b3837
COPY --from=ghcr.io/astral-sh/uv@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 /uv /usr/local/bin/uv
WORKDIR /opt/caliper

COPY pyproject.toml uv.lock LICENSE README.md ./
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra db --extra webhook --extra watch --no-editable --no-install-project

COPY src/ src/
COPY policies/ policies/
COPY migrations/ migrations/
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra db --extra webhook --extra watch --no-editable

# Scanner tools — external CLIs installed into the same venv, version-pinned by ARG.
# scancode is intentionally ORPHANED (disabled): its transitive dep (extractcode-7z)
# lacks arm64 wheels and breaks cross-platform uv sync. To re-enable, add
# "scancode-toolkit==${SCANCODE_VERSION}" to this install, restore the deferred-import
# wrapper, and add "scancode" back to CALIPER_ENABLED_SCANNERS below.
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    uv pip install "lizard==${LIZARD_VERSION}" "pyrefly==${PYREFLY_VERSION}" "radon==${RADON_VERSION}"

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
FROM python_base AS runtime

ARG PMD_VERSION
ARG TARGETARCH

LABEL org.opencontainers.image.title="Caliper" \
      org.opencontainers.image.description="DHI hardened multi-stage production scanner" \
      org.opencontainers.image.source="https://github.com/gitrdunhq/caliper" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.13-slim-trixie"

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates nodejs tini \
      $( [ "${TARGETARCH}" = "amd64" ] && echo libicu76 )  # swiftlint (amd64-only) links ICU
    # nodejs (no npm): runs the committed esbuild bundle behind the complexity
    # plugin's JS/TS maintainability index (plugins/_runners/complexity_helper_dist).

# Non-root user with a static UID/GID above 10,000: `chown 10000:10001` on the
# host always matches, and the id can never collide with a privileged host user.
RUN groupadd -r -g 10001 caliper \
    && useradd -r -u 10000 -g caliper -m -d /home/caliper -s /bin/false caliper

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
COPY --from=builder /staging/jre/              /opt/jre/
COPY --from=builder /staging/jq/jq             /usr/bin/jq
# Swift tools (swiftlint, amd64 only) — dir COPY tolerates absence.
COPY --from=builder /staging/swiftbin/         /usr/local/bin/

# Venv with all Python deps + caliper itself — console_scripts are in .venv/bin/
COPY --from=builder /opt/caliper/.venv /opt/caliper/.venv
COPY --from=builder /opt/caliper/policies/ /opt/caliper/policies/
COPY --from=builder /staging/semgrep-rules/ /opt/caliper/semgrep-rules/
COPY --from=builder /staging/community-rules/ /opt/caliper/community-rules/

RUN mkdir -p /opt/caliper/scripts
COPY --from=builder /staging/scripts/checksums.txt /opt/caliper/scripts/checksums.txt
COPY --from=builder /staging/scripts/release-revisions.txt /opt/caliper/scripts/release-revisions.txt
COPY scripts/verify-checksums.sh /opt/caliper/scripts/verify-checksums.sh
RUN chmod +x /opt/caliper/scripts/verify-checksums.sh

# PMD wrapper — Java-based, not in the venv
RUN printf '#!/bin/sh\nexport JAVA_HOME=/opt/jre\nexport PATH=/opt/jre/bin:$PATH\nexec /opt/pmd/pmd-bin-%s/bin/pmd "$@"\n' "${PMD_VERSION}" > /usr/local/bin/pmd \
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
    CALIPER_SEMGREP_RULES_DIR=/opt/caliper/semgrep-rules \
    CALIPER_SEMGREP_ORG_RULES_DIR=/opt/caliper/policies/semgrep \
    CALIPER_SEMGREP_COMMUNITY_RULES_DIR=/opt/caliper/community-rules \
    CALIPER_ENABLED_SCANNERS=syft,osv-scanner,trivy,semgrep,gitleaks,kube-linter,pmd,lizard,mypy,ls-lint,lockfile-drift

# /workspace is the conventional repo mount; making it the cwd means relative
# paths (e.g. --output .temp/report.json) land on the mount, not in the container.
RUN mkdir -p /workspace && chown caliper:caliper /workspace
USER caliper
WORKDIR /workspace

HEALTHCHECK --interval=5m --timeout=30s --retries=3 \
  CMD caliper healthcheck || exit 1

# tini is PID 1: reaps the scanners' child processes (java, node, opengrep)
# and forwards signals, so a stuck scanner can never leave zombies behind.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
# Arguments only: `podman run caliper review --repo-path /workspace` appends
# to the entrypoint; a bare `podman run caliper` prints the help.
CMD ["--help"]

# ════════════════════════════════════════════════════════════════════════════
# Stage 3: e2e-test — runtime + pytest, so tests/e2e/ can run against the full
# scanner toolchain. Dockerfile.test's image has no external scanner binaries
# (gitleaks, trivy, osv-scanner, etc.), so it can't exercise real findings;
# this stage layers just enough onto the production runtime to run pytest
# there instead. Never pushed/released — local/CI e2e verification only.
# See issue #461.
# ════════════════════════════════════════════════════════════════════════════
FROM runtime AS e2e-test

USER root
COPY --from=ghcr.io/astral-sh/uv@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 /uv /usr/local/bin/uv
# XDG_CACHE_HOME is already /home/caliper/.cache (inherited from the runtime
# stage's ENV, used by trivy/mypy/opengrep at scan time) — installing as root
# with that var set would create it root-owned and break the caliper user's
# later writes there, so uv's own cache is pinned elsewhere for this RUN only.
RUN --security=insecure --mount=type=cache,target=/root/.cache/uv \
    XDG_CACHE_HOME=/root/.cache \
    uv pip install --python /opt/caliper/.venv/bin/python pytest==9.1.0 pytest-asyncio==1.4.0
USER caliper
WORKDIR /workspace

ENTRYPOINT []
CMD []
