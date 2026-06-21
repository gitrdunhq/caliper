"""Tests for Dockerfile and Docker Compose latest-tag detection in SupplyChainPlugin.
# tested-by: tests/unit/test_supply_chain_latest.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.plugins.supply_chain import SupplyChainPlugin

# ── helpers ──────────────────────────────────────────────────────────────────


def _dockerfile_findings(content: str, tmp_path: Path) -> list[dict]:
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    plugin = SupplyChainPlugin()
    return plugin._check_dockerfile_latest(str(p))


def _compose_findings(content: str, tmp_path: Path) -> list[dict]:
    p = tmp_path / "docker-compose.yml"
    p.write_text(content)
    plugin = SupplyChainPlugin()
    return plugin._check_compose_latest(str(p))


# ── Dockerfile tests ──────────────────────────────────────────────────────────


class TestDockerfileLatestDetection:
    def test_explicit_latest_tag_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM python:latest\nRUN echo hi\n", tmp_path)
        assert len(findings) == 1
        assert "python:latest" in findings[0]["description"]
        assert findings[0]["severity"] == "medium"

    def test_pinned_tag_no_finding(self, tmp_path):
        findings = _dockerfile_findings("FROM python:3.12-slim\nRUN echo hi\n", tmp_path)
        assert findings == []

    def test_implicit_latest_no_tag_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM python\nRUN echo hi\n", tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_from_scratch_not_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM scratch\nCOPY . /app\n", tmp_path)
        assert findings == []

    def test_multi_stage_implicit_latest_image_is_flagged(self, tmp_path):
        # "FROM python AS builder" — the image has no tag (implicit latest); stage name is not a tag
        findings = _dockerfile_findings("FROM python AS builder\nFROM python:3.12-slim\n", tmp_path)
        assert len(findings) == 1
        assert findings[0]["line"] == 1

    def test_multi_stage_explicit_latest_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM node:latest AS build\nFROM nginx:1.25\n", tmp_path)
        assert len(findings) == 1
        assert "node:latest" in findings[0]["description"]

    def test_multiple_violations_all_reported(self, tmp_path):
        content = "FROM python:latest\nFROM node\nFROM nginx:1.25\n"
        findings = _dockerfile_findings(content, tmp_path)
        assert len(findings) == 2

    def test_finding_includes_file_and_line(self, tmp_path):
        findings = _dockerfile_findings("FROM alpine:latest\n", tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert "file" in f
        assert f["line"] == 1

    def test_sha_pinned_image_not_flagged(self, tmp_path):
        # digest-pinned images are properly fixed
        findings = _dockerfile_findings("FROM python@sha256:abc123def456\nRUN echo hi\n", tmp_path)
        assert findings == []

    def test_arg_based_from_not_flagged(self, tmp_path):
        # FROM $BASE_IMAGE — cannot statically determine, skip
        findings = _dockerfile_findings("ARG BASE_IMAGE\nFROM $BASE_IMAGE\n", tmp_path)
        assert findings == []


# ── Docker Compose tests ──────────────────────────────────────────────────────


class TestComposeLatestDetection:
    def test_explicit_latest_tag_flagged(self, tmp_path):
        content = "services:\n  cache:\n    image: redis:latest\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert "redis:latest" in findings[0]["description"]
        assert findings[0]["severity"] == "medium"

    def test_pinned_tag_no_finding(self, tmp_path):
        content = "services:\n  cache:\n    image: redis:7.2\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []

    def test_no_tag_implicit_latest_flagged(self, tmp_path):
        content = "services:\n  app:\n    image: myapp\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_multiple_services_mixed(self, tmp_path):
        content = (
            "services:\n"
            "  db:\n"
            "    image: postgres:16\n"
            "  cache:\n"
            "    image: redis:latest\n"
            "  app:\n"
            "    image: myapp\n"
        )
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 2

    def test_finding_includes_file(self, tmp_path):
        content = "services:\n  x:\n    image: busybox:latest\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert "file" in findings[0]

    def test_service_without_image_key_ignored(self, tmp_path):
        content = "services:\n  app:\n    build: .\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []


class TestUnpinnedWorktreeExclusion:
    """package.json files inside .claude/worktrees and .wfc must not be scanned."""

    def test_claude_worktrees_excluded(self, tmp_path):
        """package.json inside .claude/worktrees must not produce findings."""
        worktree = tmp_path / ".claude" / "worktrees" / "agent-abc" / "ba-pipeline"
        worktree.mkdir(parents=True)
        pkg = worktree / "package.json"
        pkg.write_text('{"dependencies": {"react": "^18.0.0"}}')

        plugin = SupplyChainPlugin()
        findings = plugin._check_unpinned(tmp_path)

        assert findings == [], f"Expected no findings from .claude worktree, got {findings}"

    def test_wfc_dir_excluded(self, tmp_path):
        """package.json inside .wfc must not produce findings."""
        wfc_dir = tmp_path / ".wfc" / "some" / "nested"
        wfc_dir.mkdir(parents=True)
        pkg = wfc_dir / "package.json"
        pkg.write_text('{"dependencies": {"lodash": "*"}}')

        plugin = SupplyChainPlugin()
        findings = plugin._check_unpinned(tmp_path)

        assert findings == [], f"Expected no findings from .wfc dir, got {findings}"

    def test_real_package_json_still_scanned(self, tmp_path):
        """package.json at the repo root is still scanned normally."""
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"express": "^4.18.0"}}')

        plugin = SupplyChainPlugin()
        findings = plugin._check_unpinned(tmp_path)

        assert len(findings) == 1
        assert findings[0]["package"] == "express"

    def test_digest_pinned_image_not_flagged(self, tmp_path):
        content = "services:\n  app:\n    image: redis@sha256:abc123\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []


class TestUnpinnedFileSourceExclusion:
    """Enumeration routes through FileSourcePort, so ignore rules apply uniformly."""

    def test_node_modules_package_json_excluded(self, tmp_path):
        nm = tmp_path / "node_modules" / "dep"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text('{"dependencies": {"react": "*"}}')

        findings = SupplyChainPlugin()._check_unpinned(tmp_path)
        assert findings == []

    def test_eedomignored_path_excluded(self, tmp_path):
        (tmp_path / ".eedomignore").write_text("third_party/\n")
        vendored = tmp_path / "third_party"
        vendored.mkdir()
        (vendored / "package.json").write_text('{"dependencies": {"react": "*"}}')

        findings = SupplyChainPlugin()._check_unpinned(tmp_path)
        assert findings == []

    def test_requirements_under_venv_excluded(self, tmp_path):
        # The old requirements*.txt loop had no exclusion at all — now it does.
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "requirements.txt").write_text("requests>=2\n")

        findings = SupplyChainPlugin()._check_unpinned(tmp_path)
        assert findings == []


# ── run() wiring tests ────────────────────────────────────────────────────────


class TestRunWiring:
    def test_run_picks_up_dockerfile_findings(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["Dockerfile"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_run_picks_up_compose_findings(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: redis:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["docker-compose.yml"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_run_no_docker_files_no_docker_findings(self, tmp_path):
        (tmp_path / "package.json").write_text('{"dependencies": {}}')
        plugin = SupplyChainPlugin()
        result = plugin.run(["package.json"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert docker_findings == []

    def test_dockerfile_variant_names_detected(self, tmp_path):
        (tmp_path / "Dockerfile.dev").write_text("FROM node:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["Dockerfile.dev"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_compose_yaml_extension_detected(self, tmp_path):
        (tmp_path / "docker-compose.yaml").write_text("services:\n  app:\n    image: nginx\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["docker-compose.yaml"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1


# ── Lockfile SHA path tests ───────────────────────────────────────────────────


class TestLockfileShaPath:
    """Verify _check_lockfiles uses per-directory paths, not repo root."""

    def test_lockfile_sha_uses_lockfile_directory(self, tmp_path):
        """When package-lock.json is at apps/web/, SHA should hash apps/web/package-lock.json not repo/package-lock.json."""
        import hashlib

        web_dir = tmp_path / "apps" / "web"
        web_dir.mkdir(parents=True)
        lockfile_content = b'{"lockfileVersion": 3}'
        lockfile = web_dir / "package-lock.json"
        lockfile.write_bytes(lockfile_content)

        files = [str(lockfile)]
        plugin = SupplyChainPlugin()
        result = plugin.run(files, tmp_path)

        assert not result.error
        lockfile_findings = [f for f in result.findings if f.get("type") == "lockfile"]
        assert (
            lockfile_findings
        ), "Expected a lockfile finding for package-lock.json without manifest"
        expected_sha = hashlib.sha256(lockfile_content).hexdigest()
        assert (
            lockfile_findings[0]["sha256"] == expected_sha
        ), f"SHA should come from apps/web/package-lock.json, got {lockfile_findings[0]['sha256']!r}"

    def test_lockfile_sha_uses_package_dir_not_repo_root(self, tmp_path):
        """_check_lockfiles: SHA is from the actual lock file in its subdirectory."""
        import hashlib

        pkg_dir = tmp_path / "apps" / "web"
        pkg_dir.mkdir(parents=True)
        lock_content = '{"lockfileVersion": 2, "name": "web"}'
        (pkg_dir / "package-lock.json").write_text(lock_content)

        files = [str(pkg_dir / "package-lock.json")]
        plugin = SupplyChainPlugin()
        findings = plugin._check_lockfiles(files, tmp_path)

        lockfile_findings = [
            f for f in findings if f.get("type") == "lockfile" and f.get("severity") == "high"
        ]
        assert (
            len(lockfile_findings) == 1
        ), f"Expected 1 high lockfile finding, got {lockfile_findings}"
        expected_sha = hashlib.sha256(lock_content.encode()).hexdigest()
        assert lockfile_findings[0]["sha256"] == expected_sha, (
            f"SHA computed from wrong path. "
            f"Expected {expected_sha}, got {lockfile_findings[0]['sha256']!r}"
        )


# ── Unpinned severity tests ──────────────────────────────────────────────────


def _npm_unpinned_findings(deps: dict, tmp_path: Path) -> list[dict]:
    pkg = tmp_path / "package.json"
    pkg.write_text(__import__("json").dumps({"dependencies": deps}))
    plugin = SupplyChainPlugin()
    return plugin._check_unpinned(tmp_path)


def _py_unpinned_findings(lines: list[str], tmp_path: Path) -> list[dict]:
    req = tmp_path / "requirements.txt"
    req.write_text("\n".join(lines))
    plugin = SupplyChainPlugin()
    return plugin._check_unpinned(tmp_path)


class TestUnpinnedSeverity:
    def test_completely_unpinned_npm_has_critical_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": "*"}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_caret_range_npm_has_high_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": "^1.2.3"}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_tilde_range_npm_has_high_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": "~1.2.3"}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_open_range_npm_has_high_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": ">=1.0.0"}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_latest_tag_npm_has_critical_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": "latest"}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_empty_version_npm_has_critical_severity(self, tmp_path):
        findings = _npm_unpinned_findings({"example-lib": ""}, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_no_version_py_has_critical_severity(self, tmp_path):
        findings = _py_unpinned_findings(["requests"], tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_minimum_bound_py_has_high_severity(self, tmp_path):
        findings = _py_unpinned_findings(["requests>=2.0.0"], tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_compatible_release_py_has_high_severity(self, tmp_path):
        findings = _py_unpinned_findings(["requests~=2.28"], tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_manifest_lockfile_check_uses_package_dir(self, tmp_path):
        """_check_lockfiles: manifest-changed check looks for lockfile in package dir."""
        import hashlib

        pkg_dir = tmp_path / "apps" / "api"
        pkg_dir.mkdir(parents=True)
        lock_content = "# uv.lock\nversion = 1\n"
        (pkg_dir / "uv.lock").write_text(lock_content)
        (pkg_dir / "pyproject.toml").write_text("[project]\nname = 'api'\n")

        files = [str(pkg_dir / "pyproject.toml")]
        plugin = SupplyChainPlugin()
        findings = plugin._check_lockfiles(files, tmp_path)

        uv_findings = [
            f for f in findings if f.get("type") == "lockfile" and f.get("lockfile") == "uv.lock"
        ]
        assert (
            len(uv_findings) == 1
        ), f"Expected 1 uv.lock medium finding (manifest changed, lock not updated), got {uv_findings}"
        expected_sha = hashlib.sha256(lock_content.encode()).hexdigest()
        assert uv_findings[0]["sha256"] == expected_sha, (
            f"SHA computed from wrong path. "
            f"Expected {expected_sha}, got {uv_findings[0]['sha256']!r}"
        )


class TestPathTraversalInRun:
    """run() must not process files that resolve outside repo_path."""

    def test_traversal_dockerfile_outside_repo_is_blocked(self, tmp_path):
        """A file path that traverses outside the repo must not be processed."""
        plugin = SupplyChainPlugin()

        # Create a Dockerfile OUTSIDE the repo with a floating tag
        outside_dir = tmp_path.parent / "outside_repo_sc_test"
        outside_dir.mkdir(exist_ok=True)
        outside_dockerfile = outside_dir / "Dockerfile"
        outside_dockerfile.write_text("FROM alpine:latest\n")

        # A relative path that resolves outside tmp_path
        traversal = "../outside_repo_sc_test/Dockerfile"

        result = plugin.run([traversal], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]

        # Must NOT find the outside Dockerfile's floating image
        assert len(docker_findings) == 0, (
            "Path traversal outside repo_path must be blocked — " f"got findings: {docker_findings}"
        )

    def test_traversal_compose_outside_repo_is_blocked(self, tmp_path):
        """A compose file that traverses outside the repo must not be processed."""
        plugin = SupplyChainPlugin()

        outside_dir = tmp_path.parent / "outside_repo_compose_test"
        outside_dir.mkdir(exist_ok=True)
        outside_compose = outside_dir / "docker-compose.yml"
        outside_compose.write_text("version: '3'\nservices:\n  app:\n    image: alpine:latest\n")

        traversal = "../outside_repo_compose_test/docker-compose.yml"

        result = plugin.run([traversal], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]

        assert len(docker_findings) == 0, "Compose path traversal outside repo_path must be blocked"

    def test_legitimate_dockerfile_inside_repo_still_works(self, tmp_path):
        """A Dockerfile inside repo_path continues to be checked normally."""
        plugin = SupplyChainPlugin()

        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:latest\n")

        result = plugin.run(["Dockerfile"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]

        assert (
            len(docker_findings) == 1
        ), "Legitimate Dockerfile inside repo should still be scanned"
