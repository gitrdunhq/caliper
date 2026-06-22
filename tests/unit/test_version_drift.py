"""Version drift guard — ensures a single canonical version source.
# tested-by: tests/unit/test_version_drift.py

All tests in this file are RED. They drive implementation of eedom.core.version.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# 1. get_version() exists in eedom.core.version
# ---------------------------------------------------------------------------


def test_get_version_is_importable():
    """eedom.core.version must export get_version()."""
    from eedom.core.version import get_version  # noqa: F401 — existence check only

    assert callable(get_version)


# ---------------------------------------------------------------------------
# 2. renderer._VERSION matches get_version()
# ---------------------------------------------------------------------------


def test_renderer_version_matches_canonical():
    """renderer._VERSION must equal get_version() — no local override allowed."""
    import eedom.core.renderer as renderer
    from eedom.core.version import get_version

    canonical = get_version()
    assert canonical == renderer._VERSION, (
        f"renderer._VERSION={renderer._VERSION!r} diverges from "
        f"get_version()={canonical!r}. "
        "renderer._VERSION must be removed and replaced with get_version()."
    )


# ---------------------------------------------------------------------------
# 3. SARIF tool driver version matches get_version()
# ---------------------------------------------------------------------------


def test_sarif_tool_driver_version_matches_canonical():
    """SARIF tool driver must embed get_version() as the driver version."""
    from eedom.core.plugin import PluginResult
    from eedom.core.sarif import to_sarif
    from eedom.core.version import get_version

    result = PluginResult(plugin_name="test-plugin", findings=[])
    doc = to_sarif([result])

    canonical = get_version()
    runs = doc.get("runs", [])
    assert runs, "SARIF document must contain at least one run"

    driver = runs[0]["tool"]["driver"]
    driver_version = driver.get("version")
    assert driver_version == canonical, (
        f"SARIF tool driver version={driver_version!r} diverges from "
        f"get_version()={canonical!r}."
    )


# ---------------------------------------------------------------------------
# 4. get_version() returns a semver string (X.Y.Z)
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+")


def test_get_version_returns_semver():
    """get_version() must return a string matching X.Y.Z semver pattern."""
    from eedom.core.version import get_version

    version = get_version()
    assert isinstance(version, str), f"get_version() must return str, got {type(version)}"
    assert _SEMVER_RE.match(
        version
    ), f"get_version() returned {version!r} which does not match semver X.Y.Z"


# ---------------------------------------------------------------------------
# 5. get_version() reads from importlib.metadata, not a hardcoded literal
# ---------------------------------------------------------------------------


def test_get_version_reads_from_importlib_metadata():
    """get_version() must delegate to importlib.metadata, not return a literal."""
    sentinel = "9.9.9-sentinel"

    with patch("importlib.metadata.version", return_value=sentinel):
        # Re-import to bypass any module-level caching
        import importlib as _importlib

        import eedom.core.version as _version_mod

        _importlib.reload(_version_mod)
        from eedom.core.version import get_version

        result = get_version()

    assert result == sentinel, (
        f"get_version() returned {result!r} instead of the patched sentinel "
        f"{sentinel!r}. It must call importlib.metadata.version('eedom') at "
        "call-time (not cache a hardcoded literal at import time)."
    )


# ---------------------------------------------------------------------------
# 6. Regression P10-2 — PackageNotFoundError must not crash get_version()
# ---------------------------------------------------------------------------


def test_get_version_returns_fallback_when_package_not_found():
    """get_version() must return a non-empty string (not raise) when eedom is not
    installed as a distribution (regression for P10-2: PackageNotFoundError guard)."""
    import importlib.metadata

    with patch(
        "importlib.metadata.version",
        side_effect=importlib.metadata.PackageNotFoundError("eedom"),
    ):
        import importlib as _importlib

        import eedom.core.version as _version_mod

        _importlib.reload(_version_mod)
        from eedom.core.version import get_version

        try:
            result = get_version()
        except importlib.metadata.PackageNotFoundError:
            pytest.fail(
                "get_version() must not propagate PackageNotFoundError — "
                "it must return a fallback string"
            )

    assert isinstance(result, str), f"get_version() must return str, got {type(result)}"
    assert result, "get_version() must return a non-empty string when not installed"
