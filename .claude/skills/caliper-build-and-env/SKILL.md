---
name: caliper-build-and-env
description: >-
  How to stand up the caliper dev environment from a clean checkout, and how
  to build/rebuild the container images correctly. Covers `uv sync --group
  dev`, `docker-compose up -d` (Postgres on 12432), and the three build
  scripts (`scripts/build.sh`, `scripts/build-test.sh`,
  `scripts/build-push.sh`) plus `scripts/build-image.sh` — and WHY raw
  `podman build` / `docker build` on the repo's `Dockerfile`/`Dockerfile.test`
  is forbidden: podman on Mac rejects `--security=insecure` in `RUN`
  directives (scripts strip it via `sed`), while docker on Linux *requires*
  `--security=insecure` for uv's tokio runtime (AppArmor blocks
  `socketpair()`) and a `buildx` builder created with
  `--allow-insecure-entitlement security.insecure`. Also covers the x86 build
  host (`sambou@192.168.0.210`) used for amd64/GHCR builds, and
  `entrypoint.sh`'s binary-checksum verification
  (`scripts/verify-checksums.sh` / `sha256sum -c`) that runs before every
  containerized `caliper` invocation. Load this before running any
  `podman`/`docker build` command by hand, before debugging a build failure
  that mentions `--security=insecure`, `socketpair`, `buildx`, or checksum
  verification, before setting up a new machine/CI runner, or when asked "how
  do I build the image", "why can't I just docker build this", "how do I get
  a working dev environment", or "why did the entrypoint fail with a checksum
  error". Do NOT load this for running the test suite itself (see
  caliper-testing-and-tdd), for `caliper` CLI usage/flags once the binary
  exists (see caliper-config-and-flags or caliper-run-and-operate), or for
  debugging application-level scanner/plugin failures (see
  caliper-debugging-playbook).
---

# Caliper Build & Env

Recreating the caliper dev environment is a two-track problem: a host-side
**Python toolchain** (`uv`) for editing/linting/running code directly, and a
**container toolchain** (podman or docker) for the things that must match CI
byte-for-byte — tests, the production image, and anything that ships
binaries. Mixing the two up — editing with `uv` but testing on the host, or
building images by hand instead of via the scripts — is where almost every
"works on my machine" bug in this repo comes from.

**Jargon, defined once:**
- **Engine** — podman or docker. The scripts auto-detect whichever is on
  `PATH` and prefer podman if both are present (`command -v podman` is
  checked first in every script).
- **buildx** — docker's BuildKit-backed builder frontend. Needed only on the
  docker path; podman does not use it.
- **Insecure entitlement** — a BuildKit permission that lets a `RUN` step do
  things a sandboxed build normally can't (here: open a `socketpair()`).
  Docker requires you to opt a *builder* into granting it, then opt a
  specific `RUN` into using it (`--security=insecure`).
- **AppArmor** — Linux kernel security module that, under docker's default
  profile, blocks `socketpair()` syscalls — which is exactly what `uv`'s
  tokio async runtime needs during `uv sync`/`uv pip install` inside the
  build.
- **checksum verification** — the entrypoint script that runs *inside every
  container invocation*, before `caliper` itself starts, confirming none of
  the vendored scanner binaries (syft, trivy, osv-scanner, opa, gitleaks,
  etc.) were tampered with between build and run.

## When to use this skill vs. a sibling

| You're trying to... | Use |
|---|---|
| Get a clean checkout running for the first time | this skill |
| Build/rebuild `caliper:latest` or the test image | this skill |
| Debug a `--security=insecure` / `socketpair` / buildx error | this skill |
| Understand what `entrypoint.sh` / checksum verification does | this skill |
| Actually run the test suite once the image builds | `caliper-testing-and-tdd` |
| Debug a scanner/plugin/detector failure at runtime | `caliper-debugging-playbook` |
| Learn `caliper` CLI flags, config, operating modes | `caliper-config-and-flags` / `caliper-run-and-operate` |
| Understand the three-tier architecture | `caliper-architecture-contract` |

## Step 0 — Preflight check (optional but recommended)

Run this before anything else. It is read-only — no containers started, no
files changed:

```bash
bash .claude/skills/caliper-build-and-env/scripts/check-env.sh
```

Verified output on this machine, 2026-07-02 (podman path — yours will differ
by engine/version):

```
caliper dev-environment check — repo: /Volumes/Extra/repos/gitrdunhq/eedom

  PASS uv found: uv 0.10.4 (079e3fd05 2026-02-17)
  PASS podman found and running (podman version 5.8.2)
  PASS Dockerfile present
  PASS Dockerfile.test present
  PASS scripts/build.sh present
  PASS scripts/build-test.sh present
  PASS scripts/build-push.sh present
  PASS scripts/verify-checksums.sh present
  PASS docker-compose.yml present
  PASS Makefile present

All checks passed. Next: uv sync --group dev && bash scripts/build-test.sh
```

If any check fails, fix that before proceeding — every later step assumes a
working `uv` and a running container engine.

## Step 1 — Host-side Python environment

```bash
uv sync --group dev
```

Installs the `dev` dependency group from `pyproject.toml`'s
`[dependency-groups]` (linting, testing, and dev-only libs on top of runtime
deps) into `.venv/`. Idempotent — safe to re-run any time `pyproject.toml`
or `uv.lock` changes. Confirmed working on this checkout 2026-07-02
(`Resolved 53 packages`, then `Audited 38 packages` on the following re-run
once the lock was already satisfied).

Sanity check (from `CONTRIBUTING.md`):

```bash
uv run python -c "from caliper.core.pipeline import ReviewPipeline; print('ok')"
```

## Step 2 — Postgres (only if you need persistence)

```bash
docker-compose up -d
```

Starts Postgres 16 on **port 12432** (mapped from container 5432), database
`caliper`, user `caliper` (see `docker-compose.yml` — image `postgres:16`,
container name `caliper-postgres`, healthcheck `pg_isready`). This is a
`docker-compose.yml`, so it runs under whichever compose implementation you
have (`docker compose` or `podman-compose`/podman's compose shim) — not part
of the podman-vs-docker split below, which is specifically about *image
builds*. Without this running, caliper falls back to a `NullRepository` (see
`composition/bootstrap()` — no DB is a supported mode, not an error).

## Step 3 — Container images: use the scripts, never raw build commands

**Rule, verbatim from `CLAUDE.md`: NEVER run `podman build` or `docker
build` directly against `Dockerfile` or `Dockerfile.test`.** Always go
through one of these three scripts:

```bash
bash scripts/build.sh                    # production image, linux/amd64 (default)
bash scripts/build.sh arm64              # explicit arch
bash scripts/build.sh --fast             # native arm64, no emulation (local dev)
bash scripts/build.sh amd64 --no-cache   # force a clean rebuild

bash scripts/build-test.sh                     # build + run full test suite (host arch)
bash scripts/build-test.sh --build-only         # just build the test image
bash scripts/build-test.sh --run-only           # run only (image must already exist)
bash scripts/build-test.sh -- tests/unit/ -x    # pass args straight through to pytest
bash scripts/build-test.sh --amd64              # force emulated amd64 (CI parity — see warning below)

bash scripts/build-push.sh               # build production image + push to GHCR, tagged by commit SHA
```

There is also `scripts/build-image.sh` — a multi-arch build-and-verify
script (arm64 local + optional amd64 remote via SSH, plus a
`--compare`-size mode). It is not in the three commands `CLAUDE.md` calls
out as the primary workflow, but it drives the same podman/docker
detection and is useful for a full local+remote verification pass:

```bash
bash scripts/build-image.sh                # arm64 local only
bash scripts/build-image.sh --amd64        # arm64 local + amd64 on the remote x86 host
bash scripts/build-image.sh --amd64-only   # amd64 remote only
bash scripts/build-image.sh --compare      # build + compare image size to previous
```

### Why raw `podman build -f Dockerfile .` / `docker build -f Dockerfile .` are forbidden

Both `Dockerfile` and `Dockerfile.test` contain `RUN --security=insecure`
lines (`Dockerfile` lines 223, 229, 237 — all three `uv sync`/`uv pip`
steps in the builder stage; `Dockerfile.test` lines 60, 64, 76 — same
pattern). `--security=insecure` is needed because **uv's tokio async
runtime calls `socketpair()`**, and under a locked-down build sandbox that
syscall gets blocked. The two engines disagree on how to handle that flag,
so a single command line can't serve both:

| Engine | Behavior with `--security=insecure` present as-is | What the scripts do about it |
|---|---|---|
| **podman** (used on Mac in this repo) | Does **not** support `--security=insecure` in `RUN` directives at all — the build fails | The script `sed 's/--security=insecure //g'`-strips it from the Dockerfile content and pipes the result to `podman build -f -` (stdin), so podman never sees the flag |
| **docker** (used on Linux / the x86 build host) | *Requires* it — without it, AppArmor blocks uv's `socketpair()` call during `uv sync` and the build hangs/fails | The script ensures a `buildx` builder named `caliper-builder` exists with `--buildkitd-flags '--allow-insecure-entitlement security.insecure'`, creating it on first use via `docker buildx create --name caliper-builder --driver docker-container --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use`, then builds with `docker buildx build --builder caliper-builder --allow security.insecure ...` |

Concretely, in `scripts/build.sh`:

```bash
if [[ "$ENGINE" == "podman" ]]; then
    DOCKERFILE_CONTENT=$(echo "$DOCKERFILE_CONTENT" | sed 's/--security=insecure //g')
fi
```

...and later, on the docker branch:

```bash
BUILDER="caliper-builder"
if ! docker buildx inspect "$BUILDER" &>/dev/null; then
    docker buildx create --name "$BUILDER" --driver docker-container \
        --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
fi
```

Run either Dockerfile through a bare `build` command and you get one of two
failures depending on engine: podman rejects the unsupported flag outright;
docker without a properly-entitled buildx builder hangs or fails partway
through the `uv sync` `RUN` step with an AppArmor-flavored permission error.
Both look confusing from the error message alone — the flag/entitlement
mismatch is the root cause every time. **This is exactly the class of
mistake `CLAUDE.md`'s "Getting this wrong wastes tokens every time" line is
warning about — don't rediscover it.**

`scripts/build-test.sh` applies the identical podman-strip / docker-buildx
pattern to `Dockerfile.test`, and additionally passes
`--security-opt apparmor=unconfined` to the **run** step on podman (not the
build step — this is a separate, orthogonal need: letting the *test run*,
not the build, use unconfined syscalls).

### `scripts/build-test.sh` architecture note — do not force `--amd64` casually

`scripts/build-test.sh` defaults `ARCH` to the **host** architecture
(`uname -m`), not always `amd64`. On Apple Silicon that means native arm64,
no emulation. The script's own header comment explains why this default
exists and why you should think twice before overriding it with `--amd64`:

> Emulating linux/amd64 here makes pyarrow's native extension segfault on
> import, which hangs the container so `--rm` never fires and orphans pile
> up. Use `--amd64` only when you explicitly want a CI-parity (emulated)
> run.

The script also self-protects against exactly that failure mode: it runs
the container under a `timeout`/`gtimeout` wrapper
(`CALIPER_TEST_TIMEOUT`, default 1200s) with a named container and an
`EXIT`/`INT`/`TERM` cleanup trap that force-removes it, so a hung/segfaulting
emulated run can't orphan forever even if you do pass `--amd64`.

### The x86 build host

`CLAUDE.md` and `scripts/build-image.sh` both name the same machine:
**`sambou@192.168.0.210`** — used for Docker builds, GHCR pushes, and as a
CI runner. It has the `caliper-builder` buildx builder pre-configured
already, which is why `scripts/build-image.sh --amd64` rsyncs the repo
there and runs the build over SSH instead of emulating amd64 locally (see
the segfault warning above — emulation is actively avoided, not just
slower). Override the default via `CALIPER_AMD64_HOST` if you're pointing
at a different remote:

```bash
CALIPER_AMD64_HOST=other-host bash scripts/build-image.sh --amd64
```

`scripts/build-image.sh`'s remote path excludes `.venv`, `__pycache__`,
`.temp`, `.git`, and `node_modules` from the rsync, builds with
`docker buildx build --builder caliper-builder --allow security.insecure
--platform linux/amd64 --load`, verifies the CLI and a fixed tool list
(`opengrep scancode lizard mypy`) via `--version`, and cleans up the remote
scratch dir afterward.

## Step 4 — `entrypoint.sh` and binary-checksum verification

The production `Dockerfile` (lines 333-334) generates
`/usr/local/bin/entrypoint.sh` inline at build time:

```dockerfile
RUN printf '#!/bin/sh\n/opt/caliper/scripts/verify-checksums.sh || exit 1\nexec caliper "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh
...
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

So **every** `caliper:latest` invocation — `cal`, a raw `podman run`, a CI
job — runs `verify-checksums.sh` first and refuses to start `caliper` if it
fails. That script (`scripts/verify-checksums.sh`, copied verbatim into the
image at `/opt/caliper/scripts/verify-checksums.sh`) is short and exhaustive:

```sh
#!/bin/sh
set -e
CHECKSUMS="/opt/caliper/scripts/checksums.txt"
if [ ! -f "$CHECKSUMS" ]; then
  echo "FAIL: checksums.txt not found at $CHECKSUMS"
  exit 1
fi
sha256sum -c "$CHECKSUMS"
echo "All binary checksums verified."
```

`checksums.txt` itself is **generated during the build**, not checked into
the repo — the builder stage of `Dockerfile` runs `sha256sum` over every
vendored scanner binary it stages (syft, trivy, osv-scanner, opa, gitleaks,
kube-linter, ls-lint, typos, jq, opengrep, ...) and writes the results to
`/staging/scripts/checksums.txt`, which the final stage then `COPY
--from=builder`s alongside `release-revisions.txt` (pinned upstream release
tags/revisions for the same binaries) into `/opt/caliper/scripts/`. The
practical effect: if a binary gets swapped, corrupted, or modified anywhere
between build and run, the container **fails closed** before `caliper` ever
executes — this is a supply-chain integrity gate, not a debugging nicety.

If you ever see a container fail immediately with `FAIL: checksums.txt not
found` or a `sha256sum: ... FAILED` line, that is this gate working as
designed — do not bypass it by calling the venv binary directly unless
you're deliberately debugging the image build itself. (`--entrypoint ""`
already bypasses it — that's why `scripts/build.sh`'s own smoke test uses
`--entrypoint "" "$IMAGE" caliper --version`, and why the container-run
example in `CLAUDE.md` for actually *scanning* does **not** override the
entrypoint.)

## Running the built image

From `CLAUDE.md` — the `cal` shell alias, or manually:

```bash
podman run --rm --platform linux/amd64 \
  -v /path/to/repo:/workspace:ro \
  -v /path/to/repo/.temp:/workspace/.temp \
  caliper:latest review --repo-path /workspace --all
```

Key paths inside the image:

| Path | Purpose |
|---|---|
| `/opt/caliper/.venv/bin/python` | Python with all runtime deps (production image) |
| `/opt/test-venv/bin/python` | Test image Python — use this for pytest, not the production venv |
| `/workspace/` | Repo mount point (read-only) |
| `/usr/local/bin/entrypoint.sh` | Checksum-verifies binaries, then `exec caliper "$@"` |

## What NOT to do

- Do not run `podman build -f Dockerfile .` or `docker build -f Dockerfile .`
  directly — see "Why raw build commands are forbidden" above.
- Do not set `CALIPER_ALLOW_HOST_TESTS=1` to skip the container for tests —
  that's `make test-host`, an explicit escape hatch documented in
  `CLAUDE.md`, not a default. Use `caliper-testing-and-tdd` for the full
  test-running story; this skill only gets you to a buildable image.
- Do not force `scripts/build-test.sh --amd64` on Apple Silicon as a matter
  of habit — it trades native speed for an emulation path that is known to
  segfault pyarrow. Reach for it only when you specifically need CI parity.
- Do not hand-edit the generated `/usr/local/bin/entrypoint.sh` inside a
  running container to skip checksum verification — fix whatever broke the
  checksum instead (usually: rebuild instead of patching a running
  container).

## Provenance & maintenance

Everything above was verified against this checkout on **2026-07-02**. Facts
here will drift — re-verify with these commands rather than trusting the
prose if it's been a while:

```bash
# Re-confirm CLAUDE.md's Container Builds section still matches this skill
grep -n "Container Builds" -A 40 CLAUDE.md

# Re-confirm the three canonical build scripts still exist and are unchanged in shape
wc -l scripts/build.sh scripts/build-test.sh scripts/build-push.sh scripts/build-image.sh

# Re-confirm --security=insecure line numbers in the Dockerfiles (used in prose above)
grep -n -- "--security=insecure" Dockerfile Dockerfile.test

# Re-confirm the x86 build host default hasn't moved
grep -n "CALIPER_AMD64_HOST" scripts/build-image.sh

# Re-confirm the entrypoint/checksum chain
grep -n "entrypoint.sh\|checksums.txt" Dockerfile scripts/verify-checksums.sh

# Re-confirm the Postgres port/image
grep -n "image:\|ports:" docker-compose.yml

# Re-run the preflight script (read-only, no side effects)
bash .claude/skills/caliper-build-and-env/scripts/check-env.sh
```
