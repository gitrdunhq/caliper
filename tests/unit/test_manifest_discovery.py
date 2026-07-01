"""Tests for caliper.core.manifest_discovery — PackageUnit + discover_packages().

TDD red-green: every test was written before the implementation.

Property domains (DPS-12):
  (fail-open)     SAFETY   almost-but-not-quite manifest filenames never crash
                            discovery
  Non-repudiation INVARIANT a discovered unit's manifest filename is always an
                            exact MANIFEST_MAP key with the matching ecosystem
                            — no near-miss filename is ever misclassified
"""

# tested-by: tests/unit/test_manifest_discovery.py

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from caliper.core.manifest_discovery import MANIFEST_MAP, PackageUnit, discover_packages
from tests.unit._strategies import filesystem_safe_filename, near_miss_manifest_filename

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str = "") -> None:
    """Create parent dirs and write a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Test: single manifest at repo root
# ---------------------------------------------------------------------------


class TestSingleManifestAtRoot:
    def test_returns_one_package_unit(self, tmp_path: Path) -> None:
        """A single package.json at the repo root yields exactly one PackageUnit."""
        _write(tmp_path / "package.json", '{"name": "my-pkg"}')

        result = discover_packages(tmp_path)

        assert len(result) == 1
        unit = result[0]
        assert unit.root == tmp_path
        assert unit.manifest == tmp_path / "package.json"
        assert unit.ecosystem == "npm"
        assert unit.lockfile is None

    def test_single_pyproject_at_root(self, tmp_path: Path) -> None:
        """A single pyproject.toml at root yields one PackageUnit with python ecosystem."""
        _write(tmp_path / "pyproject.toml", "[tool.poetry]\nname = 'my-lib'\n")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].ecosystem == "python"


# ---------------------------------------------------------------------------
# Test: monorepo with multiple manifests
# ---------------------------------------------------------------------------


class TestMonorepoMultipleManifests:
    def test_two_manifests_in_different_dirs(self, tmp_path: Path) -> None:
        """Manifests at apps/web/package.json and libs/core/pyproject.toml → 2 units."""
        _write(tmp_path / "apps" / "web" / "package.json", "{}")
        _write(tmp_path / "libs" / "core" / "pyproject.toml", "")

        result = discover_packages(tmp_path)

        assert len(result) == 2
        roots = {unit.root for unit in result}
        assert tmp_path / "apps" / "web" in roots
        assert tmp_path / "libs" / "core" in roots

    def test_results_sorted_by_root(self, tmp_path: Path) -> None:
        """Results are sorted by root path for deterministic output."""
        _write(tmp_path / "z_pkg" / "package.json", "{}")
        _write(tmp_path / "a_pkg" / "package.json", "{}")

        result = discover_packages(tmp_path)

        roots = [unit.root for unit in result]
        assert roots == sorted(roots)


# ---------------------------------------------------------------------------
# Test: lockfile pairing
# ---------------------------------------------------------------------------


class TestLockfilePairing:
    def test_lockfile_paired_with_manifest(self, tmp_path: Path) -> None:
        """package-lock.json sibling of package.json → lockfile is set on the unit."""
        _write(tmp_path / "apps" / "web" / "package.json", "{}")
        _write(tmp_path / "apps" / "web" / "package-lock.json", "{}")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        unit = result[0]
        assert unit.lockfile == tmp_path / "apps" / "web" / "package-lock.json"

    def test_yarn_lock_paired(self, tmp_path: Path) -> None:
        """yarn.lock sibling of package.json is detected."""
        _write(tmp_path / "package.json", "{}")
        _write(tmp_path / "yarn.lock", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == tmp_path / "yarn.lock"

    def test_uv_lock_paired_with_pyproject(self, tmp_path: Path) -> None:
        """uv.lock sibling of pyproject.toml is detected."""
        _write(tmp_path / "pyproject.toml", "")
        _write(tmp_path / "uv.lock", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == tmp_path / "uv.lock"

    def test_poetry_lock_paired_with_pyproject(self, tmp_path: Path) -> None:
        """poetry.lock sibling of pyproject.toml is detected."""
        _write(tmp_path / "pyproject.toml", "")
        _write(tmp_path / "poetry.lock", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == tmp_path / "poetry.lock"

    def test_cargo_lock_paired(self, tmp_path: Path) -> None:
        """Cargo.lock sibling of Cargo.toml is detected."""
        _write(tmp_path / "Cargo.toml", "")
        _write(tmp_path / "Cargo.lock", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == tmp_path / "Cargo.lock"

    def test_go_sum_paired(self, tmp_path: Path) -> None:
        """go.sum sibling of go.mod is detected."""
        _write(tmp_path / "go.mod", "")
        _write(tmp_path / "go.sum", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == tmp_path / "go.sum"


# ---------------------------------------------------------------------------
# Test: no lockfile
# ---------------------------------------------------------------------------


class TestNoLockfile:
    def test_no_lockfile_gives_none(self, tmp_path: Path) -> None:
        """pyproject.toml with no adjacent lockfile → lockfile is None."""
        _write(tmp_path / "libs" / "core" / "pyproject.toml", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile is None


# ---------------------------------------------------------------------------
# Test: node_modules is skipped
# ---------------------------------------------------------------------------


class TestNodeModulesSkipped:
    def test_node_modules_pkg_not_discovered(self, tmp_path: Path) -> None:
        """package.json inside node_modules/ is not discovered."""
        _write(tmp_path / "node_modules" / "some-pkg" / "package.json", "{}")

        result = discover_packages(tmp_path)

        assert result == []

    def test_real_manifest_alongside_node_modules(self, tmp_path: Path) -> None:
        """Manifest at root is found; nested node_modules is ignored."""
        _write(tmp_path / "package.json", "{}")
        _write(tmp_path / "node_modules" / "dep" / "package.json", "{}")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].root == tmp_path


# ---------------------------------------------------------------------------
# Test: .git directory is skipped
# ---------------------------------------------------------------------------


class TestGitDirSkipped:
    def test_git_dir_is_skipped(self, tmp_path: Path) -> None:
        """Files inside .git/ are never returned."""
        _write(tmp_path / ".git" / "some-nested" / "package.json", "{}")

        result = discover_packages(tmp_path)

        assert result == []


# ---------------------------------------------------------------------------
# Test: empty repo
# ---------------------------------------------------------------------------


class TestEmptyRepo:
    def test_empty_repo_returns_empty_list(self, tmp_path: Path) -> None:
        """A directory with no known manifest files returns an empty list."""
        result = discover_packages(tmp_path)

        assert result == []

    def test_only_non_manifest_files_returns_empty(self, tmp_path: Path) -> None:
        """A repo containing only README.md returns empty list."""
        _write(tmp_path / "README.md", "# Hello")

        result = discover_packages(tmp_path)

        assert result == []


# ---------------------------------------------------------------------------
# Test: ecosystem detection
# ---------------------------------------------------------------------------


class TestEcosystemDetection:
    @pytest.mark.parametrize(
        "filename,expected_ecosystem",
        [
            ("package.json", "npm"),
            ("pyproject.toml", "python"),
            ("requirements.txt", "python"),
            ("Cargo.toml", "rust"),
            ("go.mod", "go"),
            ("Gemfile", "ruby"),
            ("pom.xml", "java"),
            ("build.gradle", "gradle"),
        ],
    )
    def test_manifest_maps_to_correct_ecosystem(
        self, tmp_path: Path, filename: str, expected_ecosystem: str
    ) -> None:
        """Each manifest filename maps to the correct ecosystem string."""
        _write(tmp_path / filename, "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].ecosystem == expected_ecosystem


# ---------------------------------------------------------------------------
# Test: multiple Python manifests in the same directory
# ---------------------------------------------------------------------------


class TestMultiplePythonManifestsInSameDir:
    def test_requirements_and_pyproject_both_returned(self, tmp_path: Path) -> None:
        """requirements.txt and pyproject.toml in the same dir → two PackageUnits."""
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        _write(tmp_path / "pyproject.toml", "[tool.poetry]\nname = 'svc'\n")

        result = discover_packages(tmp_path)

        assert len(result) == 2
        filenames = {unit.manifest.name for unit in result}
        assert "requirements.txt" in filenames
        assert "pyproject.toml" in filenames
        for unit in result:
            assert unit.ecosystem == "python"


# ---------------------------------------------------------------------------
# Test: deeply nested manifest
# ---------------------------------------------------------------------------


class TestDeeplyNestedManifest:
    def test_deeply_nested_package_json(self, tmp_path: Path) -> None:
        """A manifest at packages/scope/pkg/package.json is discovered correctly."""
        nested_dir = tmp_path / "packages" / "scope" / "pkg"
        _write(nested_dir / "package.json", "{}")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        unit = result[0]
        assert unit.root == nested_dir
        assert unit.manifest == nested_dir / "package.json"
        assert unit.ecosystem == "npm"

    def test_three_levels_deep_with_lockfile(self, tmp_path: Path) -> None:
        """Deep manifest with sibling lockfile: lockfile is correctly paired."""
        nested_dir = tmp_path / "packages" / "scope" / "pkg"
        _write(nested_dir / "package.json", "{}")
        _write(nested_dir / "yarn.lock", "")

        result = discover_packages(tmp_path)

        assert len(result) == 1
        assert result[0].lockfile == nested_dir / "yarn.lock"


# ---------------------------------------------------------------------------
# Test: additional skip directories
# ---------------------------------------------------------------------------


class TestSkipDirectories:
    @pytest.mark.parametrize(
        "skip_dir",
        ["vendor", "__pycache__", ".venv", ".claude", ".caliper", ".dogfood"],
    )
    def test_known_skip_dirs_are_excluded(self, tmp_path: Path, skip_dir: str) -> None:
        """Known skip directories are never traversed."""
        _write(tmp_path / skip_dir / "package.json", "{}")

        result = discover_packages(tmp_path)

        assert result == [], f"Expected {skip_dir}/ to be skipped"

    def test_custom_ignore_pattern_skips_dir(self, tmp_path: Path) -> None:
        """A custom ignore pattern passed to discover_packages is respected."""
        _write(tmp_path / "generated" / "package.json", "{}")

        result = discover_packages(tmp_path, ignore_patterns=["generated/"])

        assert result == []

    def test_real_manifest_not_caught_by_custom_pattern(self, tmp_path: Path) -> None:
        """Custom ignore pattern only skips matching dirs; others are still found."""
        _write(tmp_path / "src" / "package.json", "{}")
        _write(tmp_path / "generated" / "package.json", "{}")

        result = discover_packages(tmp_path, ignore_patterns=["generated/"])

        assert len(result) == 1
        assert result[0].root == tmp_path / "src"


# ---------------------------------------------------------------------------
# Test: PackageUnit is frozen (immutable)
# ---------------------------------------------------------------------------


class TestManifestDiscoveryFileSource:
    """Discovery enumerates through the shared FileSourcePort."""

    def test_uses_injected_file_source(self, tmp_path: Path) -> None:
        manifest = tmp_path / "svc" / "package.json"
        _write(manifest, "{}")

        class _StubSource:
            name = "stub"
            seen: list[Path] = []

            def is_available(self, root: Path) -> bool:
                return True

            def list_files(self, root: Path, *, suffixes=None) -> list[Path]:
                type(self).seen.append(root)
                return [manifest]

        units = discover_packages(tmp_path, file_source=_StubSource())

        assert _StubSource.seen == [tmp_path]
        assert len(units) == 1
        assert units[0].manifest == manifest

    def test_lockfile_pairing_via_source(self, tmp_path: Path) -> None:
        manifest = tmp_path / "package.json"
        lock = tmp_path / "package-lock.json"
        _write(manifest, "{}")
        _write(lock, "{}")

        class _StubSource:
            name = "stub"

            def is_available(self, root: Path) -> bool:
                return True

            def list_files(self, root: Path, *, suffixes=None) -> list[Path]:
                return [manifest, lock]

        units = discover_packages(tmp_path, file_source=_StubSource())

        assert len(units) == 1
        assert units[0].lockfile == lock


class TestPackageUnitFrozen:
    def test_package_unit_is_frozen(self, tmp_path: Path) -> None:
        """PackageUnit is immutable — assigning to a field raises ValidationError."""
        from pydantic import ValidationError

        unit = PackageUnit(
            root=tmp_path,
            manifest=tmp_path / "package.json",
            ecosystem="npm",
        )
        with pytest.raises((ValidationError, TypeError)):
            unit.ecosystem = "rust"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test: malformed ecosystem values are validated and skipped
# ---------------------------------------------------------------------------


class TestMalformedEcosystem:
    def test_empty_ecosystem_is_skipped(self, tmp_path: Path) -> None:
        """An empty ecosystem string must be skipped — not added to units."""
        from unittest.mock import patch

        _write(tmp_path / "package.json", '{"name": "test"}')
        malformed_map = {"package.json": ""}
        with patch("caliper.core.manifest_discovery.MANIFEST_MAP", malformed_map):
            units = discover_packages(tmp_path)
        assert len(units) == 0

    def test_ecosystem_with_slash_is_skipped(self, tmp_path: Path) -> None:
        """An ecosystem value containing '/' must be skipped."""
        from unittest.mock import patch

        _write(tmp_path / "package.json", '{"name": "test"}')
        malformed_map = {"package.json": "npm/malicious"}
        with patch("caliper.core.manifest_discovery.MANIFEST_MAP", malformed_map):
            units = discover_packages(tmp_path)
        assert len(units) == 0

    def test_valid_ecosystem_still_discovered(self, tmp_path: Path) -> None:
        """Valid ecosystems are unaffected by the validation guard."""
        _write(tmp_path / "package.json", '{"name": "test"}')
        units = discover_packages(tmp_path)
        assert len(units) == 1
        assert units[0].ecosystem == "npm"


# ---------------------------------------------------------------------------
# Test: path traversal via symlinks is rejected
# ---------------------------------------------------------------------------


class TestSymlinkPathTraversal:
    def test_symlink_to_outside_file_rejected(self, tmp_path: Path) -> None:
        """A package.json symlink pointing outside the repo root must be skipped."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        outside_manifest = outside_dir / "package.json"
        outside_manifest.write_text('{"name": "evil"}')

        # Symlink inside repo → outside file
        inside_dir = repo_root / "subdir"
        inside_dir.mkdir()
        (inside_dir / "package.json").symlink_to(outside_manifest)

        units = discover_packages(repo_root)

        assert len(units) == 0, "Symlink escaping repo root must be rejected"

    def test_symlink_via_relative_traversal_rejected(self, tmp_path: Path) -> None:
        """A symlink using ../../ traversal to escape the repo root must be skipped."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        subdir = repo_root / "subdir"
        subdir.mkdir()

        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_manifest = outside_dir / "package.json"
        outside_manifest.write_text('{"name": "evil"}')

        (subdir / "package.json").symlink_to("../../outside/package.json")

        units = discover_packages(repo_root)

        assert len(units) == 0, "Relative-traversal symlink must be rejected"

    def test_normal_manifest_inside_repo_still_discovered(self, tmp_path: Path) -> None:
        """A plain (non-symlink) manifest inside the repo is unaffected by the fix."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        _write(repo_root / "package.json", '{"name": "valid"}')

        units = discover_packages(repo_root)

        assert len(units) == 1
        assert units[0].manifest == repo_root / "package.json"


# ---------------------------------------------------------------------------
# Property-based tests (DPS-12)
# ---------------------------------------------------------------------------


class TestProperties:
    """Hypothesis coverage for the manifest-discovery boundary.

    Uses a hand-rolled ``tempfile.TemporaryDirectory`` per example rather than
    the ``tmp_path`` fixture: ``tmp_path`` is created once per test *function*
    invocation, not once per Hypothesis example, so reusing it here would leak
    files written by one example into the next.
    """

    @given(
        filenames=st.lists(
            st.one_of(near_miss_manifest_filename(), filesystem_safe_filename()),
            min_size=1,
            max_size=8,
            unique=True,
        )
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_near_miss_filenames_never_crash_and_never_misclassify(
        self, filenames: list[str]
    ) -> None:
        """Almost-but-not-quite manifest filenames never crash discovery.

        Every returned unit's manifest filename must be an *exact* MANIFEST_MAP
        key with the correspondingly correct ecosystem — a near-miss filename
        (wrong case, extra suffix/prefix, truncated) must never be discovered
        as if it were the real manifest.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in filenames:
                (root / name).write_text("")

            result = discover_packages(root)

            assert isinstance(result, list)
            written = set(filenames)
            for unit in result:
                assert unit.manifest.name in MANIFEST_MAP, (
                    f"{unit.manifest.name!r} was discovered but is not an exact "
                    "MANIFEST_MAP key — a near-miss filename was misclassified"
                )
                assert unit.manifest.name in written
                assert unit.ecosystem == MANIFEST_MAP[unit.manifest.name]

    @given(filenames=st.lists(near_miss_manifest_filename(), min_size=1, max_size=6, unique=True))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_pure_near_miss_set_yields_no_units_unless_exact_match(
        self, filenames: list[str]
    ) -> None:
        """A directory containing ONLY near-miss names discovers nothing extra.

        Any unit that *does* appear must be because the mutation happened to
        degenerate into an exact MANIFEST_MAP key (e.g. lower-casing an
        already-lowercase name) — never a genuine misclassification.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in filenames:
                (root / name).write_text("")

            result = discover_packages(root)

            discovered_names = {unit.manifest.name for unit in result}
            assert discovered_names <= set(filenames)
            assert discovered_names <= MANIFEST_MAP.keys()
