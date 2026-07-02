"""Tests for caliper.core.sbom_diff.

# tested-by: tests/unit/test_sbom_diff.py

Covers example-based and property-based tests for parse_sbom_packages(),
diff_sboms(), and PackageInfo.

Property domains (DPS-12):
  Determinism   INVARIANT   same SBOM fragment always parses to the same result
  (fail-open)   SAFETY      malformed SBOM JSON fragments degrade gracefully —
                             never crash the whole pipeline
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.sbom_diff import PackageInfo, diff_sboms, parse_sbom_packages
from tests.unit._strategies import garbage_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sbom(*components: dict) -> dict:
    """Build a minimal CycloneDX-shaped SBOM dict."""
    return {"components": list(components)}


def _component(name: str, version: str, purl: str = "") -> dict:
    return {"name": name, "version": version, "purl": purl, "type": "library"}


# ---------------------------------------------------------------------------
# Example-based: parse_sbom_packages
# ---------------------------------------------------------------------------


class TestParseSbomPackages:
    def test_parse_sbom_extracts_packages(self) -> None:
        """CycloneDX JSON with 3 components yields 3 PackageInfo entries."""
        sbom = _make_sbom(
            _component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
            _component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),
            _component("numpy", "1.26.0", "pkg:pypi/numpy@1.26.0"),
        )

        result = parse_sbom_packages(sbom)

        assert len(result) == 3
        assert "pypi:requests" in result
        assert "pypi:flask" in result
        assert "pypi:numpy" in result

    def test_parse_sbom_empty_components(self) -> None:
        """Empty components list returns empty dict."""
        sbom = _make_sbom()
        result = parse_sbom_packages(sbom)
        assert result == {}

    def test_parse_sbom_missing_components_key(self) -> None:
        """SBOM without 'components' key returns empty dict (no crash)."""
        result = parse_sbom_packages({})
        assert result == {}

    def test_parse_sbom_extracts_ecosystem_from_purl(self) -> None:
        """pkg:pypi/requests@2.31.0 purl → ecosystem='pypi'."""
        sbom = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        result = parse_sbom_packages(sbom)
        assert result["pypi:requests"].ecosystem == "pypi"

    def test_parse_sbom_npm_ecosystem(self) -> None:
        """pkg:npm/lodash@4.17.21 purl → ecosystem='npm'."""
        sbom = _make_sbom(_component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"))
        result = parse_sbom_packages(sbom)
        assert "npm:lodash" in result
        assert result["npm:lodash"].ecosystem == "npm"

    def test_parse_sbom_fallback_ecosystem_from_type(self) -> None:
        """Component with no purl falls back to component's 'type' field."""
        component = {"name": "some-lib", "version": "1.0.0", "type": "library"}
        sbom = {"components": [component]}
        result = parse_sbom_packages(sbom)
        assert "library:some-lib" in result
        assert result["library:some-lib"].ecosystem == "library"

    def test_parse_sbom_skips_components_without_name(self) -> None:
        """Components missing 'name' are silently skipped."""
        sbom = {"components": [{"version": "1.0.0", "purl": "pkg:pypi/unknown@1.0.0"}]}
        result = parse_sbom_packages(sbom)
        assert result == {}

    def test_parse_sbom_package_info_fields(self) -> None:
        """PackageInfo fields are populated correctly from SBOM component."""
        sbom = _make_sbom(_component("boto3", "1.34.0", "pkg:pypi/boto3@1.34.0"))
        result = parse_sbom_packages(sbom)
        pkg = result["pypi:boto3"]
        assert isinstance(pkg, PackageInfo)
        assert pkg.name == "boto3"
        assert pkg.version == "1.34.0"
        assert pkg.ecosystem == "pypi"
        assert pkg.purl == "pkg:pypi/boto3@1.34.0"

    def test_parse_sbom_golang_ecosystem(self) -> None:
        """pkg:golang/... purl → ecosystem='golang'."""
        sbom = _make_sbom(
            _component("gopkg.in/yaml.v3", "3.0.1", "pkg:golang/gopkg.in/yaml.v3@3.0.1")
        )
        result = parse_sbom_packages(sbom)
        assert "golang:gopkg.in/yaml.v3" in result
        assert result["golang:gopkg.in/yaml.v3"].ecosystem == "golang"


# ---------------------------------------------------------------------------
# Example-based: diff_sboms
# ---------------------------------------------------------------------------


class TestDiffSboms:
    def test_diff_added_package(self) -> None:
        """Package in after but not before → action='added'."""
        before = _make_sbom()
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "added"
        assert changes[0]["package"] == "requests"
        assert changes[0]["new_version"] == "2.31.0"
        assert changes[0]["old_version"] is None

    def test_diff_removed_package(self) -> None:
        """Package in before but not after → action='removed'."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom()

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "removed"
        assert changes[0]["package"] == "requests"
        assert changes[0]["old_version"] == "2.31.0"
        assert changes[0]["new_version"] is None

    def test_diff_upgraded_package(self) -> None:
        """Same package, higher version in after → action='upgraded'."""
        before = _make_sbom(_component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"))
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "upgraded"
        assert changes[0]["old_version"] == "2.25.0"
        assert changes[0]["new_version"] == "2.31.0"

    def test_diff_downgraded_package(self) -> None:
        """Same package, lower version in after → action='downgraded'."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom(_component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "downgraded"
        assert changes[0]["old_version"] == "2.31.0"
        assert changes[0]["new_version"] == "2.25.0"

    def test_diff_unchanged_packages_not_in_output(self) -> None:
        """Package at same version on both sides does not appear in changes."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert changes == []

    def test_diff_multi_ecosystem(self) -> None:
        """npm + pypi packages mixed — diffs each ecosystem correctly."""
        before = _make_sbom(
            _component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
            _component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"),
        )
        after = _make_sbom(
            _component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),  # upgraded
            _component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"),  # unchanged
            _component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),  # added
        )

        changes = diff_sboms(before, after)

        actions = {c["package"]: c["action"] for c in changes}
        assert actions["lodash"] == "upgraded"
        assert actions["flask"] == "added"
        assert "requests" not in actions

    def test_diff_empty_sboms(self) -> None:
        """Both empty SBOMs produce no changes."""
        changes = diff_sboms(_make_sbom(), _make_sbom())
        assert changes == []

    def test_version_comparison_semantic(self) -> None:
        """1.9.0 → 1.10.0 must be 'upgraded', not 'downgraded' (semver-aware)."""
        before = _make_sbom(_component("mylib", "1.9.0", "pkg:pypi/mylib@1.9.0"))
        after = _make_sbom(_component("mylib", "1.10.0", "pkg:pypi/mylib@1.10.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "upgraded"

    def test_diff_change_includes_ecosystem(self) -> None:
        """Each change dict includes 'ecosystem' matching the SBOM purl."""
        before = _make_sbom()
        after = _make_sbom(_component("express", "4.18.0", "pkg:npm/express@4.18.0"))

        changes = diff_sboms(before, after)

        assert changes[0]["ecosystem"] == "npm"

    def test_diff_change_includes_purl(self) -> None:
        """Each change dict includes 'purl' from the package."""
        before = _make_sbom()
        after = _make_sbom(_component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"))

        changes = diff_sboms(before, after)

        assert changes[0]["purl"] == "pkg:pypi/flask@3.0.0"

    def test_diff_multiple_adds_and_removes(self) -> None:
        """Mixed adds and removes are all captured correctly."""
        before = _make_sbom(
            _component("pkg-a", "1.0.0", "pkg:pypi/pkg-a@1.0.0"),
            _component("pkg-b", "2.0.0", "pkg:pypi/pkg-b@2.0.0"),
        )
        after = _make_sbom(
            _component("pkg-b", "2.0.0", "pkg:pypi/pkg-b@2.0.0"),
            _component("pkg-c", "3.0.0", "pkg:pypi/pkg-c@3.0.0"),
        )

        changes = diff_sboms(before, after)
        actions = {c["package"]: c["action"] for c in changes}

        assert actions["pkg-a"] == "removed"
        assert actions["pkg-c"] == "added"
        assert "pkg-b" not in actions


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------

_purl_prefix_strategy = st.sampled_from(
    ["pkg:pypi/", "pkg:npm/", "pkg:maven/", "pkg:golang/", "pkg:cargo/"]
)

_valid_name_strategy = st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True)
_valid_version_strategy = st.from_regex(r"[0-9]+\.[0-9]+\.[0-9]+", fullmatch=True)


def _make_component_strategy():
    return st.builds(
        lambda name, version, prefix: {
            "name": name,
            "version": version,
            "purl": f"{prefix}{name}@{version}",
            "type": "library",
        },
        name=_valid_name_strategy,
        version=_valid_version_strategy,
        prefix=_purl_prefix_strategy,
    )


def _make_sbom_strategy(min_size: int = 0, max_size: int = 10):
    return st.builds(
        lambda components: {"components": components},
        components=st.lists(
            _make_component_strategy(),
            min_size=min_size,
            max_size=max_size,
            unique_by=lambda c: c["name"],
        ),
    )


@given(before=_make_sbom_strategy(), after=_make_sbom_strategy())
@settings(max_examples=200)
def test_diff_is_inverse(before: dict, after: dict) -> None:
    """If A→B produces N additions, then B→A produces N removals.

    The set of packages added going from A→B must equal the set of packages
    removed going from B→A.
    """
    a_to_b = diff_sboms(before, after)
    b_to_a = diff_sboms(after, before)

    added_fwd = {c["package"] for c in a_to_b if c["action"] == "added"}
    removed_rev = {c["package"] for c in b_to_a if c["action"] == "removed"}
    assert added_fwd == removed_rev

    removed_fwd = {c["package"] for c in a_to_b if c["action"] == "removed"}
    added_rev = {c["package"] for c in b_to_a if c["action"] == "added"}
    assert removed_fwd == added_rev


@given(before=_make_sbom_strategy(), after=_make_sbom_strategy())
@settings(max_examples=200)
def test_added_plus_removed_plus_changed_covers_all(before: dict, after: dict) -> None:
    """Total changed packages ≤ union of both package sets.

    No phantom packages can appear in changes that weren't in either SBOM.
    """
    before_pkgs = parse_sbom_packages(before)
    after_pkgs = parse_sbom_packages(after)
    all_package_names = {pkg.name for pkg in before_pkgs.values()} | {
        pkg.name for pkg in after_pkgs.values()
    }

    changes = diff_sboms(before, after)
    changed_names = {c["package"] for c in changes}

    assert changed_names <= all_package_names


@given(data=st.dictionaries(keys=st.text(max_size=20), values=st.text(max_size=20)))
@settings(max_examples=200)
def test_parse_never_crashes(data: dict) -> None:
    """parse_sbom_packages with random dict input must never raise."""
    # Should not raise — any malformed input is silently handled
    result = parse_sbom_packages(data)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Input validation: non-dict inputs must raise TypeError, not AttributeError
# ---------------------------------------------------------------------------


class TestSBOMInputValidation:
    """Untrusted / malformed SBOM inputs must fail fast with a clear TypeError."""

    def test_parse_sbom_packages_rejects_none(self) -> None:
        """None must raise TypeError, not AttributeError from .get() on None."""
        with pytest.raises(TypeError, match="dict"):
            parse_sbom_packages(None)  # type: ignore[arg-type]

    def test_parse_sbom_packages_rejects_string(self) -> None:
        """String input must raise TypeError, not silently produce wrong output."""
        with pytest.raises(TypeError, match="dict"):
            parse_sbom_packages("not a dict")  # type: ignore[arg-type]

    def test_parse_sbom_packages_rejects_list(self) -> None:
        """List input must raise TypeError even if it looks like a components list."""
        with pytest.raises(TypeError, match="dict"):
            parse_sbom_packages([{"name": "requests", "version": "1.0"}])  # type: ignore[arg-type]

    def test_diff_sboms_rejects_none_before(self) -> None:
        """None before-SBOM must raise TypeError before any diffing occurs."""
        valid = {"components": []}
        with pytest.raises(TypeError, match="dict"):
            diff_sboms(None, valid)  # type: ignore[arg-type]

    def test_diff_sboms_rejects_none_after(self) -> None:
        """None after-SBOM must raise TypeError before any diffing occurs."""
        valid = {"components": []}
        with pytest.raises(TypeError, match="dict"):
            diff_sboms(valid, None)  # type: ignore[arg-type]

    def test_diff_sboms_rejects_string_inputs(self) -> None:
        """Both non-dict args must raise TypeError, not crash with AttributeError."""
        with pytest.raises(TypeError, match="dict"):
            diff_sboms("before", "after")  # type: ignore[arg-type]


@given(prefix=_purl_prefix_strategy, name=_valid_name_strategy, version=_valid_version_strategy)
@settings(max_examples=200)
def test_ecosystem_detection_is_deterministic(prefix: str, name: str, version: str) -> None:
    """Same purl always returns the same ecosystem (pure function)."""
    component = {"name": name, "version": version, "purl": f"{prefix}{name}@{version}"}
    sbom = {"components": [component]}

    result1 = parse_sbom_packages(sbom)
    result2 = parse_sbom_packages(sbom)

    # Both calls must produce identical ecosystem values
    keys1 = list(result1.keys())
    keys2 = list(result2.keys())
    assert keys1 == keys2
    for k in keys1:
        assert result1[k].ecosystem == result2[k].ecosystem


# ---------------------------------------------------------------------------
# _make_change helper — structural consistency guard
# ---------------------------------------------------------------------------


class TestMakeChangeHelper:
    """Tests for the _make_change() private helper.

    Written RED-first: these fail until _make_change is added to sbom_diff.py.
    The helper must produce change dicts with identical structure regardless of
    action type, eliminating the duplication risk from three inline dict literals.
    """

    def test_make_change_added(self) -> None:
        """_make_change('added', None, new) produces correct structure."""
        from caliper.core.sbom_diff import _make_change

        new = PackageInfo(
            name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"
        )
        result = _make_change("added", None, new)

        assert result["action"] == "added"
        assert result["package"] == "requests"
        assert result["ecosystem"] == "pypi"
        assert result["old_version"] is None
        assert result["new_version"] == "2.31.0"
        assert result["purl"] == "pkg:pypi/requests@2.31.0"

    def test_make_change_removed(self) -> None:
        """_make_change('removed', old, None) produces correct structure."""
        from caliper.core.sbom_diff import _make_change

        old = PackageInfo(
            name="flask", version="2.0.0", ecosystem="pypi", purl="pkg:pypi/flask@2.0.0"
        )
        result = _make_change("removed", old, None)

        assert result["action"] == "removed"
        assert result["package"] == "flask"
        assert result["ecosystem"] == "pypi"
        assert result["old_version"] == "2.0.0"
        assert result["new_version"] is None
        assert result["purl"] == "pkg:pypi/flask@2.0.0"

    def test_make_change_upgraded(self) -> None:
        """_make_change('upgraded', old, new) uses new package info for name/ecosystem/purl."""
        from caliper.core.sbom_diff import _make_change

        old = PackageInfo(
            name="lodash", version="4.17.20", ecosystem="npm", purl="pkg:npm/lodash@4.17.20"
        )
        new = PackageInfo(
            name="lodash", version="4.17.21", ecosystem="npm", purl="pkg:npm/lodash@4.17.21"
        )
        result = _make_change("upgraded", old, new)

        assert result["action"] == "upgraded"
        assert result["old_version"] == "4.17.20"
        assert result["new_version"] == "4.17.21"
        assert result["purl"] == "pkg:npm/lodash@4.17.21"

    def test_make_change_all_actions_have_identical_key_set(self) -> None:
        """All action types produce dicts with exactly the same set of keys."""
        from caliper.core.sbom_diff import _make_change

        pkg = PackageInfo(name="x", version="1.0.0", ecosystem="pypi", purl="pkg:pypi/x@1.0.0")
        required_keys = {"action", "package", "ecosystem", "old_version", "new_version", "purl"}

        added = _make_change("added", None, pkg)
        removed = _make_change("removed", pkg, None)
        upgraded = _make_change("upgraded", pkg, pkg)

        assert set(added.keys()) == required_keys, "added change missing required keys"
        assert set(removed.keys()) == required_keys, "removed change missing required keys"
        assert set(upgraded.keys()) == required_keys, "upgraded change missing required keys"


class TestClassifyVersionChangeFallback:
    """Tests for _classify_version_change string-comparison fallback."""

    def test_fallback_returns_downgraded_when_old_greater(self) -> None:
        """When versions are not valid semver, string comparison must be used.

        Before fix: the fallback always returned "upgraded" regardless of the
        actual ordering.
        After fix: lexicographic string comparison determines the direction.
        """
        from caliper.core.sbom_diff import _classify_version_change

        # Lexicographically "z_ver" > "a_ver", so this is a downgrade
        result = _classify_version_change("z_ver", "a_ver")
        assert result == "downgraded", (
            "Expected 'downgraded' when old_ver > new_ver lexicographically; "
            f"got '{result}'. Fallback must use string comparison, not always return 'upgraded'."
        )

    def test_fallback_returns_upgraded_when_new_greater(self) -> None:
        """String comparison fallback must classify upgrade correctly."""
        from caliper.core.sbom_diff import _classify_version_change

        result = _classify_version_change("a_ver", "z_ver")
        assert result == "upgraded"

    def test_fallback_logs_string_comparison_indicator(self) -> None:
        """The fallback log message must mention string comparison so operators know."""
        from unittest.mock import patch

        from caliper.core.sbom_diff import _classify_version_change

        with patch("caliper.core.sbom_diff.logger") as mock_logger:
            _classify_version_change("not-semver-x", "not-semver-y")

            mock_logger.warning.assert_called_once()
            call_kwargs = mock_logger.warning.call_args
            # The log event name must reference 'fallback' or 'string' so operators
            # understand the comparison was lexicographic, not semantic.
            event_name = call_kwargs[0][0] if call_kwargs[0] else ""
            assert (
                "fallback" in event_name or "string" in event_name
            ), f"Log message '{event_name}' does not indicate string-comparison fallback"

    def test_valid_semver_uses_semver_comparison(self) -> None:
        """Valid semver versions must use semantic comparison, not string comparison."""
        from caliper.core.sbom_diff import _classify_version_change

        # "10.0.0" > "9.0.0" semantically but "10" < "9" lexicographically
        result = _classify_version_change("9.0.0", "10.0.0")
        assert result == "upgraded", (
            "Semantic version comparison must be used for valid semver — "
            "'10.0.0' is semantically greater than '9.0.0'"
        )


# ---------------------------------------------------------------------------
# Property-based tests (DPS-12)
# ---------------------------------------------------------------------------


class TestProperties:
    """Hypothesis coverage for the SBOM-parsing boundary.

    ``test_diff.py`` and ``test_ignore.py`` etc. import shared strategies from
    ``tests.unit._strategies``; this SBOM-specific strategy for a malformed
    ``"components"`` field lives here because it's only meaningful against
    this module's shape.
    """

    @given(
        components=st.one_of(
            st.integers(),
            st.floats(allow_nan=False),
            st.booleans(),
            st.none(),
            st.text(max_size=20),
            st.dictionaries(st.text(max_size=10), st.integers(), max_size=5),
        )
    )
    @settings(max_examples=200)
    def test_malformed_components_field_never_raises(self, components: object) -> None:
        """Regression: a non-list ``"components"`` value must degrade to {}, not crash.

        Before the fix, ``sbom.get("components", [])`` being an int/float/bool
        /None reached ``for component in components`` and raised an unhandled
        TypeError ("'int' object is not iterable"), instead of the graceful
        degradation the docstring promises for malformed SBOM fragments.
        """
        result = parse_sbom_packages({"components": components})
        assert isinstance(result, dict)

    @given(sbom=st.dictionaries(garbage_text(max_size=15), garbage_text(max_size=15), max_size=10))
    @settings(max_examples=200)
    def test_parse_sbom_packages_determinism(self, sbom: dict) -> None:
        """Same malformed-ish dict input always parses to an equal result."""
        first = parse_sbom_packages(sbom)
        second = parse_sbom_packages(sbom)
        assert first == second

    @given(
        before=st.dictionaries(garbage_text(max_size=10), garbage_text(max_size=10), max_size=5),
        after=st.dictionaries(garbage_text(max_size=10), garbage_text(max_size=10), max_size=5),
    )
    @settings(max_examples=100)
    def test_diff_sboms_never_raises_on_malformed_dicts(self, before: dict, after: dict) -> None:
        """diff_sboms on arbitrary (dict-shaped) malformed input must not crash."""
        result = diff_sboms(before, after)
        assert isinstance(result, list)
