# tested-by: tests/unit/test_deterministic_cli_guards.py
"""Deterministic guards for CLI multi-ecosystem support (#252).

These tests detect when the CLI dependency review behavior does not match
the claimed multi-ecosystem support. The CLI claims 18 ecosystem support
but the file discovery only looks for specific extensions, missing key
manifest files.

Bug: #252 — CLI dependency review behavior lags multi-ecosystem claims
Parent: #218
Epic: #146
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

# The CLI's claimed 18 ecosystems and their key manifest/lockfile patterns
_CLAIMED_ECOSYSTEMS: dict[str, list[str]] = {
    # JavaScript/Node.js
    "npm": ["package.json", "package-lock.json"],
    "yarn": ["yarn.lock"],
    "pnpm": ["pnpm-lock.yaml"],
    # Python
    "pip": ["requirements.txt", "requirements*.txt"],
    "poetry": ["pyproject.toml", "poetry.lock"],
    "pipenv": ["Pipfile", "Pipfile.lock"],
    "uv": ["pyproject.toml", "uv.lock"],
    # Go
    "go": ["go.mod", "go.sum"],
    # Rust
    "cargo": ["Cargo.toml", "Cargo.lock"],
    # Java
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    # Ruby
    "bundler": ["Gemfile", "Gemfile.lock"],
    # PHP
    "composer": ["composer.json", "composer.lock"],
    # .NET
    "nuget": ["*.csproj", "packages.lock.json"],
    # Swift
    "swift": ["Package.swift", "Package.resolved"],
    # Elixir
    "mix": ["mix.exs", "mix.lock"],
    # Erlang
    "rebar": ["rebar.config", "rebar.lock"],
    # Haskell
    "cabal": ["*.cabal", "cabal.project"],
    # Dart/Flutter
    "pub": ["pubspec.yaml", "pubspec.lock"],
}

# Extensions currently searched by _all_repo_files() in cli/main.py line 331
_CURRENT_CLI_EXTENSIONS = ("*.py", "*.ts", "*.js", "*.tf", "*.yaml", "*.yml", "*.json")

# Key manifest files NOT covered by current extension globbing
_UNCOVERED_MANIFESTS: list[str] = [
    # Java - no .xml, .gradle extension in the glob
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    # Go - no .mod, .sum extension
    "go.mod",
    "go.sum",
    # Rust - .lock is not in the glob, .toml is not in the glob
    "Cargo.lock",
    # Ruby - no Gemfile extension
    "Gemfile",
    "Gemfile.lock",
    # PHP - composer.json is covered by *.json, but composer.lock is not
    "composer.lock",
    # .NET
    "packages.lock.json",  # partially covered by *.json but the lock suffix matters
    # Swift
    "Package.swift",  # not covered by glob
    "Package.resolved",  # not covered by glob
    # Elixir
    "mix.exs",  # not covered
    "mix.lock",  # not covered
    # Erlang
    "rebar.config",  # not covered
    "rebar.lock",  # not covered
    # Haskell
    "cabal.project",  # not covered
    # Dart/Flutter
    "pubspec.yaml",  # covered by *.yaml
    "pubspec.lock",  # not covered by glob
]


def _make_mock_registry() -> MagicMock:
    """Create a mock plugin registry for CLI tests."""
    mock_reg = MagicMock()
    mock_reg.run_all.return_value = []
    mock_reg.list.return_value = []
    return mock_reg


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_ecosystem_support_covers_claimed_ecosystems() -> None:
    """Detect when CLI file discovery doesn't support claimed 18 ecosystems.

    The README claims: "When a PR touches a dependency manifest — requirements.txt,
    package.json, Cargo.toml, go.mod, any of 18 ecosystems — caliper detects..."

    But the CLI's _all_repo_files() only searches:
    *.py, *.ts, *.js, *.tf, *.yaml, *.yml, *.json

    This misses: pom.xml, build.gradle, go.mod, Cargo.lock, Gemfile, etc.

    Issue #252: CLI dependency review behavior lags multi-ecosystem claims.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()

    # Track what files get discovered
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)

        # Create manifest files from all claimed ecosystems
        for ecosystem, manifests in _CLAIMED_ECOSYSTEMS.items():
            for manifest in manifests:
                # Skip wildcard patterns for this test
                if "*" in manifest:
                    continue
                manifest_path = fs_path / manifest
                manifest_path.write_text(f"# {ecosystem} manifest\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Check which manifests were discovered
        discovered_names = {Path(f).name for f in captured_files}
        missed_manifests: list[str] = []

        for ecosystem, manifests in _CLAIMED_ECOSYSTEMS.items():
            for manifest in manifests:
                if "*" in manifest:
                    continue  # Skip wildcards for this check
                if manifest not in discovered_names:
                    missed_manifests.append(f"{ecosystem}:{manifest}")

        # BUG DETECTOR: If we miss manifests, the CLI is not delivering on its claims
        assert len(missed_manifests) == 0, (
            f"BUG #252: CLI file discovery misses {len(missed_manifests)} manifest(s) "
            f"from claimed ecosystems: {missed_manifests[:10]}...\n\n"
            f"The CLI's _all_repo_files() only searches: {_CURRENT_CLI_EXTENSIONS}\n"
            f"This does not match the claimed 18 ecosystem support.\n"
            f"Missing: Java (pom.xml, build.gradle), Go (go.mod), Rust (Cargo.lock), "
            f"Ruby (Gemfile), PHP (composer.lock), etc.\n\n"
            f"See issue #252: CLI dependency review behavior lags multi-ecosystem claims."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_maven_pom_xml() -> None:
    """Detect when CLI does not discover Maven pom.xml files.

    Maven is a major JVM ecosystem build tool. pom.xml is its manifest.
    The CLI's current *.json, *.yaml, etc. glob does NOT match *.xml files.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create a Maven pom.xml
        (fs_path / "pom.xml").write_text("<project>...</project>")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: pom.xml should be discovered
        assert "pom.xml" in discovered_names, (
            "BUG #252: CLI does not discover Maven pom.xml files. "
            "The current glob pattern (*.py, *.ts, *.js, *.tf, *.yaml, *.yml, *.json) "
            "does not include *.xml, missing Maven ecosystem support."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_go_mod_files() -> None:
    """Detect when CLI does not discover Go go.mod files.

    Go modules are defined in go.mod files. The CLI's glob patterns don't cover .mod extension.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create a Go module file
        (fs_path / "go.mod").write_text("module example.com/foo\ngo 1.21\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: go.mod should be discovered
        assert "go.mod" in discovered_names, (
            "BUG #252: CLI does not discover Go go.mod files. "
            "The current glob pattern does not include go.mod files, "
            "missing Go ecosystem support despite claimed multi-ecosystem support."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_gradle_build_files() -> None:
    """Detect when CLI does not discover Gradle build files.

    Gradle uses build.gradle (Groovy) or build.gradle.kts (Kotlin) as manifests.
    Neither extension is in the CLI's current glob patterns.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create Gradle build files
        (fs_path / "build.gradle").write_text("plugins { id 'java' }\n")
        (fs_path / "build.gradle.kts").write_text("plugins { java }\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: Gradle files should be discovered
        assert "build.gradle" in discovered_names, (
            "BUG #252: CLI does not discover Gradle build.gradle files. "
            "The current glob pattern does not support Gradle ecosystem."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_cargo_lock_files() -> None:
    """Detect when CLI does not discover Rust Cargo.lock files.

    Cargo.lock is the lockfile for Rust's Cargo package manager.
    The .lock extension is not in the CLI's glob patterns.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create Rust lockfile
        (fs_path / "Cargo.lock").write_text("# This file is automatically @generated by Cargo.\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: Cargo.lock should be discovered
        assert "Cargo.lock" in discovered_names, (
            "BUG #252: CLI does not discover Rust Cargo.lock files. "
            "The current glob pattern does not include .lock extension, "
            "missing Rust ecosystem lockfile support."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_ruby_gemfile() -> None:
    """Detect when CLI does not discover Ruby Gemfile files.

    Bundler uses 'Gemfile' (no extension) as its manifest. The CLI's extension-based
    globbing completely misses this pattern.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create Ruby Gemfile
        (fs_path / "Gemfile").write_text("source 'https://rubygems.org'\ngem 'rails'\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: Gemfile should be discovered
        assert "Gemfile" in discovered_names, (
            "BUG #252: CLI does not discover Ruby Gemfile files. "
            "Extension-based globbing cannot match files without extensions like 'Gemfile'. "
            "Missing Ruby/Bundler ecosystem support."
        )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_252_cli_discovers_swift_package_files() -> None:
    """Detect when CLI does not discover Swift Package.swift files.

    Swift Package Manager uses Package.swift as its manifest.
    While Package.swift ends in .swift, it's a specific filename that should be recognized.
    """
    from caliper.cli.main import cli

    runner = CliRunner()
    mock_reg = _make_mock_registry()
    captured_files: list[str] = []

    def _capture_run_all(files: list[str], **kwargs: Any) -> list[Any]:
        captured_files.extend(files)
        return []

    mock_reg.run_all.side_effect = _capture_run_all

    with runner.isolated_filesystem() as fs:
        fs_path = Path(fs)
        # Create Swift manifest (should be discovered by *.swift if we add that extension)
        swift_dir = fs_path / "src"
        swift_dir.mkdir()
        # Note: .swift is NOT in current glob, so this won't be discovered
        (swift_dir / "app.swift").write_text('print("hello")\n')
        (fs_path / "Package.swift").write_text("// swift-tools-version:5.7\n")

        with patch("caliper.cli.main.get_default_registry", return_value=mock_reg):
            result = runner.invoke(cli, ["review", "--all", "--repo-path", fs])

        assert result.exit_code == 0

        discovered_names = {Path(f).name for f in captured_files}

        # BUG DETECTOR: Package.swift should be discovered
        # Note: .swift extension is not in current glob, so this will fail
        assert "Package.swift" in discovered_names, (
            "BUG #252: CLI does not discover Swift Package.swift files. "
            "The current glob pattern does not include *.swift extension, "
            "missing Swift Package Manager ecosystem support."
        )
