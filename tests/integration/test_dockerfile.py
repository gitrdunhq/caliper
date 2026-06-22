"""Integration tests for the DHI hardened container image.

# tested-by: tests/integration/test_dockerfile.py (infrastructure test — no source file)

Requires: podman (or docker) and a built caliper image.
Run: CALIPER_IMAGE=caliper:latest uv run pytest tests/integration/test_dockerfile.py -v

These tests verify the container meets the DHI hardening requirements:
1. All scanner binaries present and executable
2. No dynamic linking failures (ldd clean)
3. SHA256 checksums match pinned values
4. Python packages importable
5. caliper CLI functional
6. Multi-arch support

All tests in this module are expected to FAIL against the current Dockerfile
(wfc-dev:arm64 single-stage). The code eagle will harden the Dockerfile to
satisfy this contract.

Environment variables:
  CALIPER_IMAGE   — image tag to test against (default: caliper:latest)
  CONTAINER_RUNTIME — override runtime detection (podman | docker)
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------


def _detect_runtime() -> str | None:
    """Return 'podman', 'docker', or None if neither is in PATH."""
    forced = os.environ.get("CONTAINER_RUNTIME")
    if forced:
        return forced if shutil.which(forced) else None
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


RUNTIME = _detect_runtime()
IMAGE = os.environ.get("CALIPER_IMAGE", "caliper:latest")

_runtime_missing = pytest.mark.skipif(
    RUNTIME is None,
    reason="Neither podman nor docker found in PATH — skipping container tests",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def container_run():
    """Run a command inside the container; return CompletedProcess.

    Usage:
        result = container_run(["--version"], entrypoint="syft")
        result = container_run(["-m", "semgrep", "--version"], entrypoint="python3")
        result = container_run(["/usr/bin/git"], entrypoint="ldd")
    """

    def _run(
        cmd: list[str],
        entrypoint: str | None = None,
        extra_flags: list[str] | None = None,
    ) -> subprocess.CompletedProcess:
        assert RUNTIME is not None, "No container runtime available"
        base = [RUNTIME, "run", "--rm"]
        if extra_flags:
            base.extend(extra_flags)
        if entrypoint:
            base += ["--entrypoint", entrypoint]
        base.append(IMAGE)
        base.extend(cmd)
        return subprocess.run(base, capture_output=True, text=True, timeout=60)

    return _run


# ---------------------------------------------------------------------------
# TestScannerBinaries — all 8 CLIs must be present and executable
# ---------------------------------------------------------------------------


@_runtime_missing
class TestScannerBinaries:
    """Verify all 8 scanner CLIs are present and return a zero exit code.

    Each test runs the binary's --version (or equivalent) flag inside the
    hardened container to confirm the binary is present, executable, and
    dynamically links correctly at container startup.

    These tests FAIL on the current Dockerfile because:
    - The multi-stage DHI build is not implemented yet.
    - The wfc-dev:arm64 base image is ARM64-specific and not the DHI runtime.
    """

    def test_syft_version(self, container_run):
        """syft version exits 0 — SBOM generation scanner present."""
        result = container_run(["version"], entrypoint="syft")
        assert (
            result.returncode == 0
        ), f"syft not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_trivy_version(self, container_run):
        """trivy --version exits 0 — vulnerability scanner present."""
        result = container_run(["--version"], entrypoint="trivy")
        assert (
            result.returncode == 0
        ), f"trivy not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_osv_scanner_version(self, container_run):
        """osv-scanner --version exits 0 — OSV vulnerability scanner present."""
        result = container_run(["--version"], entrypoint="osv-scanner")
        assert (
            result.returncode == 0
        ), f"osv-scanner not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_opa_version(self, container_run):
        """opa version exits 0 — Open Policy Agent present."""
        result = container_run(["version"], entrypoint="opa")
        assert (
            result.returncode == 0
        ), f"opa not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_semgrep_version(self, container_run):
        """semgrep --version exits 0, invoked via python -m semgrep.

        IMPORTANT: semgrep must NOT be invoked via a copied console_script
        binary — those shebangs point to the builder's Python path and break
        in the DHI runtime. Always use 'python -m semgrep'.
        """
        result = container_run(["-m", "semgrep", "--version"], entrypoint="python3")
        assert result.returncode == 0, (
            f"semgrep (python -m semgrep) not found or failed.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # scancode is orphaned/disabled — no longer installed in the image, so its
    # version probe was removed. Re-add when scancode is re-enabled.

    def test_gitleaks_version(self, container_run):
        """gitleaks version exits 0 — secret detection scanner present."""
        result = container_run(["version"], entrypoint="gitleaks")
        assert (
            result.returncode == 0
        ), f"gitleaks not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_clamscan_version(self, container_run):
        """clamscan --version exits 0 — ClamAV malware scanner present."""
        result = container_run(["--version"], entrypoint="clamscan")
        assert (
            result.returncode == 0
        ), f"clamscan not found or failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"


# ---------------------------------------------------------------------------
# TestDynamicLinking — no missing shared libs
# ---------------------------------------------------------------------------


@_runtime_missing
class TestDynamicLinking:
    """Verify no 'not found' entries from ldd on copied binaries.

    The DHI runtime base image does not include the full Debian package tree.
    Any binary copied from the builder stage must have all its shared libs
    present — either by explicit COPY of the required .so files, or by using
    a statically compiled binary.

    These tests FAIL on the current Dockerfile because the DHI multi-stage
    build has not been implemented (binaries aren't copied to a clean runtime).

    The 'not found' pattern in ldd output signals a broken binary that will
    segfault or throw 'No such file or directory' at runtime.
    """

    @staticmethod
    def _assert_ldd_ran(result: subprocess.CompletedProcess, binary: str) -> None:
        """Guard: fail fast if the container itself couldn't start.

        ldd exits 0 (all libs found), 1 (static binary or missing lib), or
        non-zero if the binary doesn't exist. exit code 125 means the container
        runtime failed to start the container entirely (e.g. image not found).
        Any result code >= 125 indicates an infrastructure failure, not a
        successful ldd run — the test must fail in that case so it is not
        silently skipped due to an empty stdout.
        """
        assert result.returncode < 125, (
            f"Container failed to start when running ldd against {binary} "
            f"(exit {result.returncode}). Is the image built and tagged as "
            f"CALIPER_IMAGE={IMAGE}?\nstderr: {result.stderr}"
        )

    def test_no_missing_libs_git(self, container_run):
        """ldd /usr/bin/git shows no 'not found' — all git shared libs present.

        git requires pcre2, zlib, and openssl at minimum. These must be
        explicitly copied from the builder stage into the DHI runtime.
        """
        result = container_run(["/usr/bin/git"], entrypoint="ldd")
        self._assert_ldd_ran(result, "/usr/bin/git")
        assert (
            "not found" not in result.stdout
        ), f"git has missing shared libs:\n{result.stdout}\nstderr: {result.stderr}"

    def test_no_missing_libs_clamscan(self, container_run):
        """ldd /usr/bin/clamscan shows no 'not found' — all ClamAV libs present.

        ClamAV requires libclamav, libmspack, libjson-c, and their transitive
        deps. These must all be copied alongside the clamscan binary.
        """
        result = container_run(["/usr/bin/clamscan"], entrypoint="ldd")
        self._assert_ldd_ran(result, "/usr/bin/clamscan")
        assert (
            "not found" not in result.stdout
        ), f"clamscan has missing shared libs:\n{result.stdout}\nstderr: {result.stderr}"

    def test_no_missing_libs_jq(self, container_run):
        """ldd /usr/bin/jq shows no 'not found' OR jq is statically linked.

        The hardened Dockerfile should download the official jq static binary
        from GitHub releases to avoid dynamic linking issues entirely.
        """
        result = container_run(["/usr/bin/jq"], entrypoint="ldd")
        self._assert_ldd_ran(result, "/usr/bin/jq")
        # Two acceptable states:
        # 1. Static binary: ldd says "not a dynamic executable" or "statically linked"
        # 2. Dynamic binary: all libs present (no "not found")
        combined = result.stdout + result.stderr
        is_static = "not a dynamic executable" in combined or "statically linked" in combined
        has_missing = "not found" in result.stdout
        assert not has_missing, (
            f"jq has missing shared libs (should use static binary):\n"
            f"{result.stdout}\nstderr: {result.stderr}"
        )
        # Prefer static: emit a note if dynamically linked so the code eagle is aware
        if not is_static:
            pytest.fail(
                "jq is dynamically linked — the hardened Dockerfile must use "
                "the official static release binary from github.com/jqlang/jq/releases"
            )

    def test_static_binaries_need_no_libs(self, container_run):
        """syft, trivy, osv-scanner, opa, gitleaks are static Go binaries.

        Static binaries must not show 'not found' in ldd output. ldd may
        return 'not a dynamic executable' (exit 1) which is acceptable —
        the binary still runs. The critical check is no missing dependencies.
        """
        static_binaries = {
            "syft": "/usr/local/bin/syft",
            "trivy": "/usr/local/bin/trivy",
            "osv-scanner": "/usr/local/bin/osv-scanner",
            "opa": "/usr/local/bin/opa",
            "gitleaks": "/usr/local/bin/gitleaks",
        }
        failures: list[str] = []
        for name, path in static_binaries.items():
            result = container_run([path], entrypoint="ldd")
            if result.returncode >= 125:
                failures.append(
                    f"{name}: container failed to start (exit {result.returncode}) — "
                    f"image not built? stderr: {result.stderr.strip()}"
                )
            elif "not found" in result.stdout:
                failures.append(f"{name} ({path}) has missing shared libs:\n{result.stdout}")
        assert not failures, "Static Go binaries have missing shared libs:\n" + "\n---\n".join(
            failures
        )


# ---------------------------------------------------------------------------
# TestPythonPackages — verify imports work inside the container
# ---------------------------------------------------------------------------


@_runtime_missing
class TestPythonPackages:
    """Verify Python packages are importable inside the DHI runtime.

    The DHI image does not use the builder's pip install --target path
    out of the box. All packages must be present in the DHI Python's
    site-packages directory. This validates that the COPY of site-packages
    from builder → runtime succeeded and that PYTHONPATH is set correctly.

    These tests FAIL because the DHI multi-stage build is not yet implemented.
    """

    def test_caliper_importable(self, container_run):
        """import caliper succeeds — package source is on PYTHONPATH."""
        result = container_run(
            ["-c", "import caliper; print(caliper.__version__)"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"caliper not importable.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_semgrep_importable(self, container_run):
        """import semgrep succeeds — semgrep Python package in site-packages."""
        result = container_run(
            ["-c", "import semgrep"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"semgrep not importable.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_templates_exist(self, container_run):
        """caliper/templates/comment.md.j2 present — templates shipped with package."""
        result = container_run(
            [
                "-c",
                (
                    "from pathlib import Path; import caliper; "
                    "p = Path(caliper.__file__).parent / 'templates' / 'comment.md.j2'; "
                    "assert p.exists(), f'Template missing: {p}'"
                ),
            ],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"comment.md.j2 template missing.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_structlog_importable(self, container_run):
        """import structlog succeeds — structured logging package present."""
        result = container_run(
            ["-c", "import structlog"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"structlog not importable.\nstdout: {result.stdout}\nstderr: {result.stderr}"

    def test_pydantic_importable(self, container_run):
        """import pydantic succeeds — data validation package present."""
        result = container_run(
            ["-c", "import pydantic; print(pydantic.VERSION)"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"pydantic not importable.\nstdout: {result.stdout}\nstderr: {result.stderr}"


# ---------------------------------------------------------------------------
# TestCaliperCLI — verify the caliper CLI works end-to-end inside the container
# ---------------------------------------------------------------------------


@_runtime_missing
class TestCaliperCLI:
    """Verify the caliper CLI is functional inside the DHI hardened image.

    The DHI image runs caliper via the Python module entrypoint:
        ENTRYPOINT ["/opt/python/bin/python3", "-m", "caliper.cli.main"]

    Tests invoke the CLI by overriding the entrypoint so individual subcommands
    can be exercised without relying on the default CMD.

    These tests FAIL because the DHI multi-stage build is not yet implemented.
    """

    def test_help(self, container_run):
        """caliper --help exits 0 and output mentions 'review' subcommand."""
        result = container_run(
            ["-m", "caliper.cli.main", "--help"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"caliper --help failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert (
            "review" in result.stdout.lower()
        ), f"'review' not found in --help output:\n{result.stdout}"

    def test_plugins_list(self, container_run):
        """caliper plugins exits 0 and output includes 'semgrep' plugin."""
        result = container_run(
            ["-m", "caliper.cli.main", "plugins"],
            entrypoint="python3",
        )
        assert (
            result.returncode == 0
        ), f"caliper plugins failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert (
            "semgrep" in result.stdout.lower()
        ), f"'semgrep' not listed in plugins output:\n{result.stdout}"

    def test_review_empty_workspace(self, container_run):
        """caliper review --repo-path /tmp --all exits 0 on empty directory.

        An empty workspace should produce zero findings and a clean exit,
        not a crash or NOT_INSTALLED error. This verifies that all 15 plugins
        initialise cleanly and handle the no-files case gracefully.
        """
        result = container_run(
            ["-m", "caliper.cli.main", "review", "--repo-path", "/tmp", "--all"],
            entrypoint="python3",
        )
        assert result.returncode == 0, (
            f"caliper review on empty workspace failed.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# TestChecksumVerification — SHA256 of downloaded binaries must be pinned
# ---------------------------------------------------------------------------


@_runtime_missing
class TestChecksumVerification:
    """Verify the SHA256 checksum infrastructure is in place and passing.

    The hardened Dockerfile must pin SHA256 hashes for every downloaded
    binary so that a tampered upstream release fails the build immediately.

    scripts/verify-checksums.sh does not yet exist. TestChecksumVerification
    tests FAIL until:
    1. scripts/verify-checksums.sh is created with pinned hashes per binary
    2. The Dockerfile runs sha256sum --check after every curl download
    3. The script is copied into the image and passes when run against the
       installed binaries

    These tests are expected to FAIL on the current codebase.
    """

    @pytest.fixture(autouse=True)
    def _script_path(self):
        """Compute the absolute path to scripts/verify-checksums.sh."""
        import pathlib

        repo_root = pathlib.Path(__file__).parents[2]
        self._checksums_path = repo_root / "scripts" / "verify-checksums.sh"

    def test_checksums_file_exists(self):
        """scripts/verify-checksums.sh exists in the repo.

        This script must contain pinned SHA256 hashes for all downloaded
        scanner binaries (syft, trivy, osv-scanner, opa, gitleaks).
        """
        assert self._checksums_path.exists(), (
            f"scripts/verify-checksums.sh not found at {self._checksums_path}. "
            "The DHI hardened Dockerfile requires a checksum verification script "
            "with pinned SHA256 hashes per binary per version per arch."
        )
        import os

        assert os.access(
            self._checksums_path, os.X_OK
        ), "scripts/verify-checksums.sh exists but is not executable"

    def test_checksums_pass(self, container_run):
        """Running scripts/verify-checksums.sh inside the container exits 0.

        The script runs sha256sum --check against every installed binary.
        A tampered binary causes the script (and therefore this test) to fail.
        """
        result = container_run(
            ["/opt/caliper/scripts/verify-checksums.sh"],
            entrypoint="/bin/sh",
            extra_flags=[],
        )
        assert result.returncode == 0, (
            f"Checksum verification failed — a binary hash does not match.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# TestNoStaleSignatures — ClamAV DBs must NOT be baked into the image
# ---------------------------------------------------------------------------


@_runtime_missing
class TestNoStaleSignatures:
    """Verify ClamAV signature databases are fetched at runtime, not baked in.

    Baking freshclam output into the image creates a container with stale
    virus definitions that will never update unless the image is rebuilt.
    The hardened Dockerfile removes freshclam from the build stage and uses
    an entrypoint wrapper (scripts/entrypoint.sh) or an init-container to
    run freshclam on first start.

    This test FAILS on the current Dockerfile because freshclam IS run during
    the build (line 75 of Dockerfile: freshclam --quiet || ...) and the
    database files are baked into the image layer.
    """

    def test_no_clamav_db_in_image(self, container_run):
        """/var/lib/clamav/ is empty or absent in the image.

        Virus signatures must be fetched at container startup via an
        entrypoint script, not during the Docker build. Stale baked-in
        signatures provide false security — the DBs go stale within days.

        Acceptable states:
        - Directory does not exist (freshclam not run at build time)
        - Directory exists but contains no .cvd or .cld files
        """
        result = container_run(
            [
                "-c",
                (
                    "import os, sys\n"
                    "db_dir = '/var/lib/clamav'\n"
                    "if not os.path.exists(db_dir): sys.exit(0)\n"
                    "db_files = [f for f in os.listdir(db_dir) if f.endswith(('.cvd', '.cld'))]\n"
                    "print(f'Found DB files: {db_files}')\n"
                    "sys.exit(1 if db_files else 0)"
                ),
            ],
            entrypoint="python3",
        )
        assert result.returncode == 0, (
            f"ClamAV database files are baked into the image — they will go stale.\n"
            f"Remove freshclam from the Dockerfile build stage and use an entrypoint\n"
            f"wrapper (scripts/entrypoint.sh) to fetch signatures at container startup.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
