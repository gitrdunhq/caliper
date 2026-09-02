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

import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from caliper.core.manifest_discovery import (
    MANIFEST_MAP,
    ManifestCache,
    PackageUnit,
    _appears_in_lockfile,
    _lockfile_pattern,
    classify_dependency_kind,
    discover_packages,
)
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


# ---------------------------------------------------------------------------
# Test: classify_dependency_kind — direct / transitive / unknown, cross-ecosystem
#
# Property domains (DPS-12):
#   Determinism   INVARIANT  same (repo, package, manifest) always classifies
#                            the same way
# ---------------------------------------------------------------------------


class TestClassifyDependencyKindDirect:
    """AC1: classify_dependency_kind returns 'direct' for a top-level dep
    declared in the given manifest."""

    def test_direct_dependency_in_pyproject_toml(self, tmp_path: Path) -> None:
        """A package listed under [project.dependencies] in pyproject.toml is direct."""
        manifest = tmp_path / "pyproject.toml"
        _write(
            manifest,
            '[project]\nname = "app"\ndependencies = ["requests>=2.0"]\n',
        )

        result = classify_dependency_kind(tmp_path, "requests", manifest)

        assert result == "direct"


class TestClassifyDependencyKindTransitive:
    """AC2: classify_dependency_kind returns 'transitive' when the package is
    not declared directly in any discovered manifest but appears in a
    lockfile."""

    def test_transitive_dependency_only_in_lockfile(self, tmp_path: Path) -> None:
        """A package present only in uv.lock (not in pyproject.toml deps) is transitive."""
        manifest = tmp_path / "pyproject.toml"
        _write(
            manifest,
            '[project]\nname = "app"\ndependencies = ["requests>=2.0"]\n',
        )
        lockfile = tmp_path / "uv.lock"
        _write(
            lockfile,
            '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n',
        )

        result = classify_dependency_kind(tmp_path, "urllib3", manifest)

        assert result == "transitive"


class TestClassifyDependencyKindUnknown:
    """AC3: classify_dependency_kind returns 'unknown' when no manifest or
    lockfile evidence exists for the package."""

    def test_unknown_package_absent_from_manifest_and_lockfile(self, tmp_path: Path) -> None:
        """A package name that appears nowhere in the manifest or its lockfile is unknown."""
        manifest = tmp_path / "pyproject.toml"
        _write(
            manifest,
            '[project]\nname = "app"\ndependencies = ["requests>=2.0"]\n',
        )
        lockfile = tmp_path / "uv.lock"
        _write(
            lockfile,
            '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n',
        )

        result = classify_dependency_kind(tmp_path, "nonexistent-pkg-xyz", manifest)

        assert result == "unknown"


class TestClassifyDependencyKindCrossEcosystem:
    """AC4: classify_dependency_kind works across pyproject.toml,
    requirements*.txt, package.json, pom.xml, go.mod, and Cargo.toml."""

    def test_direct_dependency_in_requirements_txt(self, tmp_path: Path) -> None:
        """A package pinned in requirements.txt is direct."""
        manifest = tmp_path / "requirements.txt"
        _write(manifest, "flask==2.0.0\nrequests==2.31.0\n")

        result = classify_dependency_kind(tmp_path, "flask", manifest)

        assert result == "direct"

    def test_direct_dependency_in_package_json(self, tmp_path: Path) -> None:
        """A package listed under "dependencies" in package.json is direct."""
        manifest = tmp_path / "package.json"
        _write(
            manifest,
            '{"name": "app", "dependencies": {"lodash": "^4.17.21"}}',
        )

        result = classify_dependency_kind(tmp_path, "lodash", manifest)

        assert result == "direct"

    def test_direct_dependency_in_pom_xml(self, tmp_path: Path) -> None:
        """A package listed as a <dependency> artifactId in pom.xml is direct."""
        manifest = tmp_path / "pom.xml"
        _write(
            manifest,
            (
                "<project>\n"
                "  <dependencies>\n"
                "    <dependency>\n"
                "      <groupId>org.example</groupId>\n"
                "      <artifactId>example-lib</artifactId>\n"
                "      <version>1.0.0</version>\n"
                "    </dependency>\n"
                "  </dependencies>\n"
                "</project>\n"
            ),
        )

        result = classify_dependency_kind(tmp_path, "example-lib", manifest)

        assert result == "direct"

    def test_direct_dependency_in_go_mod(self, tmp_path: Path) -> None:
        """A package listed in a require directive in go.mod is direct."""
        manifest = tmp_path / "go.mod"
        _write(
            manifest,
            ("module example.com/app\n\n" "go 1.21\n\n" "require github.com/pkg/errors v0.9.1\n"),
        )

        result = classify_dependency_kind(tmp_path, "github.com/pkg/errors", manifest)

        assert result == "direct"

    def test_direct_dependency_in_cargo_toml(self, tmp_path: Path) -> None:
        """A package listed under [dependencies] in Cargo.toml is direct."""
        manifest = tmp_path / "Cargo.toml"
        _write(
            manifest,
            '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
        )

        result = classify_dependency_kind(tmp_path, "serde", manifest)

        assert result == "direct"

    def test_unknown_package_in_requirements_txt(self, tmp_path: Path) -> None:
        """A package name not pinned in requirements.txt and with no lockfile evidence is unknown."""
        manifest = tmp_path / "requirements.txt"
        _write(manifest, "flask==2.0.0\n")

        result = classify_dependency_kind(tmp_path, "django", manifest)

        assert result == "unknown"


class TestClassifyDependencyKindLockfileTarget:
    """CORR-001: trivy's ``Target`` is often the lockfile, not the manifest.

    A lockfile path must classify against its sibling manifest (LOCKFILE_MAP
    inverted): declared there -> direct; only in the lockfile -> transitive;
    manifest absent -> unknown (no evidence to tell direct from transitive).
    """

    def test_npm_package_lock_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "package.json", '{"dependencies": {"lodash": "^4"}}')
        lock = tmp_path / "package-lock.json"
        _write(lock, '{"packages": {"node_modules/lodash": {}, "node_modules/ms": {}}}')
        assert classify_dependency_kind(tmp_path, "lodash", lock) == "direct"

    def test_npm_package_lock_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "package.json", '{"dependencies": {"lodash": "^4"}}')
        lock = tmp_path / "package-lock.json"
        _write(lock, '{"packages": {"node_modules/lodash": {}, "node_modules/ms": {}}}')
        assert classify_dependency_kind(tmp_path, "ms", lock) == "transitive"

    def test_yarn_lock_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "package.json", '{"dependencies": {"lodash": "^4"}}')
        lock = tmp_path / "yarn.lock"
        _write(lock, 'ms@^2.1.2:\n  version "2.1.3"\n')
        assert classify_dependency_kind(tmp_path, "ms", lock) == "transitive"

    def test_pnpm_lock_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "package.json", '{"dependencies": {"lodash": "^4"}}')
        lock = tmp_path / "pnpm-lock.yaml"
        _write(lock, "packages:\n  /lodash@4.17.21: {}\n")
        assert classify_dependency_kind(tmp_path, "lodash", lock) == "direct"

    def test_cargo_lock_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "Cargo.toml", '[dependencies]\nserde = "1"\n')
        lock = tmp_path / "Cargo.lock"
        _write(lock, '[[package]]\nname = "serde"\n\n[[package]]\nname = "itoa"\n')
        assert classify_dependency_kind(tmp_path, "serde", lock) == "direct"

    def test_cargo_lock_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "Cargo.toml", '[dependencies]\nserde = "1"\n')
        lock = tmp_path / "Cargo.lock"
        _write(lock, '[[package]]\nname = "serde"\n\n[[package]]\nname = "itoa"\n')
        assert classify_dependency_kind(tmp_path, "itoa", lock) == "transitive"

    def test_poetry_lock_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", '[tool.poetry.dependencies]\nrequests = "^2"\n')
        lock = tmp_path / "poetry.lock"
        _write(lock, '[[package]]\nname = "requests"\n\n[[package]]\nname = "urllib3"\n')
        assert classify_dependency_kind(tmp_path, "requests", lock) == "direct"

    def test_poetry_lock_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", '[tool.poetry.dependencies]\nrequests = "^2"\n')
        lock = tmp_path / "poetry.lock"
        _write(lock, '[[package]]\nname = "requests"\n\n[[package]]\nname = "urllib3"\n')
        assert classify_dependency_kind(tmp_path, "urllib3", lock) == "transitive"

    def test_go_sum_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "go.mod", "module m\n\nrequire github.com/pkg/errors v0.9.1\n")
        lock = tmp_path / "go.sum"
        _write(lock, "github.com/pkg/errors v0.9.1 h1:x=\ngolang.org/x/sys v0.1.0 h1:y=\n")
        assert classify_dependency_kind(tmp_path, "github.com/pkg/errors", lock) == "direct"

    def test_go_sum_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "go.mod", "module m\n\nrequire github.com/pkg/errors v0.9.1\n")
        lock = tmp_path / "go.sum"
        _write(lock, "github.com/pkg/errors v0.9.1 h1:x=\ngolang.org/x/sys v0.1.0 h1:y=\n")
        assert classify_dependency_kind(tmp_path, "golang.org/x/sys", lock) == "transitive"

    def test_uv_lock_direct(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", '[project]\ndependencies = ["requests"]\n')
        lock = tmp_path / "uv.lock"
        _write(lock, '[[package]]\nname = "requests"\n\n[[package]]\nname = "urllib3"\n')
        assert classify_dependency_kind(tmp_path, "requests", lock) == "direct"

    def test_uv_lock_transitive(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", '[project]\ndependencies = ["requests"]\n')
        lock = tmp_path / "uv.lock"
        _write(lock, '[[package]]\nname = "requests"\n\n[[package]]\nname = "urllib3"\n')
        assert classify_dependency_kind(tmp_path, "urllib3", lock) == "transitive"

    def test_lockfile_without_sibling_manifest_is_unknown(self, tmp_path: Path) -> None:
        lock = tmp_path / "Cargo.lock"
        _write(lock, '[[package]]\nname = "serde"\n')
        assert classify_dependency_kind(tmp_path, "serde", lock) == "unknown"

    def test_lockfile_target_unlisted_package_is_unknown(self, tmp_path: Path) -> None:
        _write(tmp_path / "Cargo.toml", '[dependencies]\nserde = "1"\n')
        lock = tmp_path / "Cargo.lock"
        _write(lock, '[[package]]\nname = "serde"\n')
        assert classify_dependency_kind(tmp_path, "nope-xyz", lock) == "unknown"


# ---------------------------------------------------------------------------
# PERF-001/002/003 — per-scan read-once cache + memoized lockfile regex
# ---------------------------------------------------------------------------


class _CountingReader:
    """Fake reader that serves an in-memory tree and counts reads per path."""

    def __init__(self, files: dict[Path, str]) -> None:
        self.files = files
        self.reads: dict[Path, int] = {}

    def __call__(self, path: Path) -> str:
        self.reads[path] = self.reads.get(path, 0) + 1
        try:
            return self.files[path]
        except KeyError as exc:
            raise FileNotFoundError(str(path)) from exc


class TestManifestCache:
    """PERF-001/002: each manifest/lockfile is read from disk at most once per
    cache, however many packages are classified against it."""

    def test_fifty_packages_read_each_file_exactly_once(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        lockfile = tmp_path / "uv.lock"
        lock_text = "".join(f'[[package]]\nname = "dep{i}"\n\n' for i in range(50))
        reader = _CountingReader(
            {manifest: '[project]\ndependencies = ["dep0"]\n', lockfile: lock_text}
        )
        cache = ManifestCache(reader=reader)

        kinds = {
            classify_dependency_kind(tmp_path, f"dep{i}", manifest, cache=cache) for i in range(50)
        }

        assert kinds == {"direct", "transitive"}
        assert reader.reads[manifest] == 1
        assert reader.reads[lockfile] == 1
        # No other lockfile candidate (poetry.lock) is probed more than once either.
        assert all(count == 1 for count in reader.reads.values()), reader.reads

    def test_lockfile_target_reads_manifest_once_across_packages(self, tmp_path: Path) -> None:
        manifest = tmp_path / "Cargo.toml"
        lockfile = tmp_path / "Cargo.lock"
        reader = _CountingReader(
            {
                manifest: '[dependencies]\nserde = "1"\n',
                lockfile: '[[package]]\nname = "serde"\n\n[[package]]\nname = "itoa"\n',
            }
        )
        cache = ManifestCache(reader=reader)

        assert classify_dependency_kind(tmp_path, "serde", lockfile, cache=cache) == "direct"
        assert classify_dependency_kind(tmp_path, "itoa", lockfile, cache=cache) == "transitive"
        assert classify_dependency_kind(tmp_path, "nope", lockfile, cache=cache) == "unknown"

        assert reader.reads == {manifest: 1, lockfile: 1}

    def test_missing_file_is_probed_once(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        reader = _CountingReader({manifest: '[project]\ndependencies = ["a"]\n'})
        cache = ManifestCache(reader=reader)

        for name in ("x", "y", "z"):
            assert classify_dependency_kind(tmp_path, name, manifest, cache=cache) == "unknown"

        assert reader.reads[tmp_path / "uv.lock"] == 1
        assert reader.reads[tmp_path / "poetry.lock"] == 1

    def test_default_reader_hits_disk(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        _write(manifest, '[project]\ndependencies = ["requests"]\n')
        assert classify_dependency_kind(tmp_path, "requests", manifest, cache=ManifestCache()) == (
            "direct"
        )


class TestLockfilePatternMemoized:
    """PERF-003: the lockfile token regex is compiled once per package name."""

    def test_repeated_calls_do_not_recompile(self) -> None:
        _lockfile_pattern.cache_clear()
        with patch("caliper.core.manifest_discovery.re.compile", wraps=re.compile) as compile_:
            for _ in range(5):
                assert _appears_in_lockfile("requests", 'name = "requests"')
            assert compile_.call_count == 1


class TestLockfileMatchNormalized:
    """CORR-003: the transitive lookup normalizes both the package name and the
    lockfile tokens the same way the direct lookup does (case, ``_`` vs ``-``)."""

    def test_underscore_package_matches_hyphen_lockfile(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        _write(manifest, '[project]\ndependencies = ["requests"]\n')
        _write(tmp_path / "uv.lock", '[[package]]\nname = "foo-bar"\n')
        assert classify_dependency_kind(tmp_path, "Foo_Bar", manifest) == "transitive"

    def test_hyphen_package_matches_underscore_lockfile(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        _write(manifest, '[project]\ndependencies = ["requests"]\n')
        _write(tmp_path / "uv.lock", '[[package]]\nname = "Foo_Bar"\n')
        assert classify_dependency_kind(tmp_path, "foo-bar", manifest) == "transitive"

    def test_partial_token_still_does_not_match(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pyproject.toml"
        _write(manifest, '[project]\ndependencies = ["requests"]\n')
        _write(tmp_path / "uv.lock", '[[package]]\nname = "foo-bar-baz"\n')
        assert classify_dependency_kind(tmp_path, "foo_bar", manifest) == "unknown"
