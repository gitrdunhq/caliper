"""Tests for caliper.data.pypi -- PyPI metadata scribe."""

from __future__ import annotations

from datetime import datetime

import httpx
import respx

from caliper.data.pypi import PyPIClient, _compute_first_published, _compute_last_published

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_PYPI_RESPONSE = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
        "summary": "Python HTTP for Humans.",
        "author": "Kenneth Reitz",
        "author_email": "me@kennethreitz.org",
        "license": "Apache 2.0",
        "home_page": "https://requests.readthedocs.io",
        "project_url": "https://pypi.org/project/requests/",
        "project_urls": {
            "Source": "https://github.com/psf/requests",
            "Documentation": "https://requests.readthedocs.io",
        },
        "classifiers": [
            "License :: OSI Approved :: Apache Software License",
            "Programming Language :: Python :: 3",
        ],
    },
    "releases": {
        "0.2.0": [{"upload_time_iso_8601": "2011-02-14T01:15:00+00:00"}],
        "2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:44+00:00"}],
    },
}


class TestPyPIClientFetchMetadata:
    """Test suite for PyPIClient.fetch_metadata."""

    @respx.mock
    def test_successful_fetch_parses_metadata(self) -> None:
        """A 200 response is parsed into a metadata dict with all expected keys."""
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("requests")

        assert result["available"] is True
        assert result["name"] == "requests"
        assert result["version"] == "2.31.0"
        assert result["summary"] == "Python HTTP for Humans."
        assert result["author"] == "Kenneth Reitz"
        assert result["license"] == "Apache 2.0"
        assert result["source_url"] == "https://github.com/psf/requests"
        assert "Apache Software License" in result["classifiers"][0]

    @respx.mock
    def test_successful_fetch_with_version(self) -> None:
        """When version is specified, the versioned URL is used."""
        respx.get("https://pypi.org/pypi/requests/2.31.0/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("requests", version="2.31.0")

        assert result["available"] is True
        assert result["name"] == "requests"

    @respx.mock
    def test_404_returns_not_found(self) -> None:
        """A 404 from PyPI returns available=False with a clear error."""
        respx.get("https://pypi.org/pypi/nonexistent-pkg-xyz/json").mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("nonexistent-pkg-xyz")

        assert result["available"] is False
        assert result["error"] == "package not found"

    @respx.mock
    def test_timeout_returns_error(self) -> None:
        """A timeout returns available=False with a timeout error message."""
        respx.get("https://pypi.org/pypi/slow-pkg/json").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )

        client = PyPIClient(timeout=1)
        result = client.fetch_metadata("slow-pkg")

        assert result["available"] is False
        assert result["error"] == "PyPI request timed out"

    @respx.mock
    def test_http_error_returns_error(self) -> None:
        """A connection error returns available=False with error detail."""
        respx.get("https://pypi.org/pypi/broken-pkg/json").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("broken-pkg")

        assert result["available"] is False
        assert "PyPI request failed" in result["error"]

    @respx.mock
    def test_unexpected_status_returns_error(self) -> None:
        """A 500 from PyPI returns available=False with the status code."""
        respx.get("https://pypi.org/pypi/broken-pkg/json").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("broken-pkg")

        assert result["available"] is False
        assert "500" in result["error"]


class TestFirstPublishedDate:
    """Test suite for first_published_date calculation."""

    def test_earliest_date_is_selected(self) -> None:
        """The earliest upload timestamp across all releases is selected."""
        releases = {
            "1.0": [{"upload_time_iso_8601": "2020-06-15T10:00:00+00:00"}],
            "0.1": [{"upload_time_iso_8601": "2018-01-01T00:00:00+00:00"}],
            "2.0": [{"upload_time_iso_8601": "2023-03-10T12:00:00+00:00"}],
        }

        result = _compute_first_published(releases)

        assert result is not None
        parsed = datetime.fromisoformat(result)
        assert parsed.year == 2018
        assert parsed.month == 1

    def test_empty_releases_returns_none(self) -> None:
        """No releases at all returns None."""
        assert _compute_first_published({}) is None

    def test_releases_without_timestamps_returns_none(self) -> None:
        """Releases with no upload_time fields return None."""
        releases = {"1.0": [{}], "2.0": [{"filename": "pkg.tar.gz"}]}
        assert _compute_first_published(releases) is None

    @respx.mock
    def test_package_age_days_is_positive(self) -> None:
        """A package with a known first-published date has positive age_days."""
        old_release = {
            "info": {
                "name": "ancient-pkg",
                "version": "1.0.0",
                "summary": "An old package",
                "author": "Somebody",
                "license": "MIT",
                "home_page": "",
                "project_urls": None,
                "classifiers": [],
            },
            "releases": {
                "0.1": [{"upload_time_iso_8601": "2015-01-01T00:00:00+00:00"}],
            },
        }

        respx.get("https://pypi.org/pypi/ancient-pkg/json").mock(
            return_value=httpx.Response(200, json=old_release)
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("ancient-pkg")

        assert result["available"] is True
        assert result["package_age_days"] is not None
        assert result["package_age_days"] > 3000  # published > 8 years ago


class TestLastPublishedDate:
    """Test suite for last_release_date calculation."""

    def test_latest_date_is_selected(self) -> None:
        """The latest upload timestamp across all releases is selected."""
        releases = {
            "1.0": [{"upload_time_iso_8601": "2020-06-15T10:00:00+00:00"}],
            "0.1": [{"upload_time_iso_8601": "2018-01-01T00:00:00+00:00"}],
            "2.0": [{"upload_time_iso_8601": "2023-03-10T12:00:00+00:00"}],
        }

        result = _compute_last_published(releases)

        assert result is not None
        parsed = datetime.fromisoformat(result)
        assert parsed.year == 2023
        assert parsed.month == 3

    def test_empty_releases_returns_none(self) -> None:
        """No releases at all returns None."""
        assert _compute_last_published({}) is None

    def test_releases_without_timestamps_returns_none(self) -> None:
        """Releases with no upload_time fields return None."""
        releases = {"1.0": [{}], "2.0": [{"filename": "pkg.tar.gz"}]}
        assert _compute_last_published(releases) is None

    @respx.mock
    def test_last_release_date_present_in_metadata(self) -> None:
        """fetch_metadata surfaces last_release_date alongside first_published_date."""
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )

        client = PyPIClient(timeout=5)
        result = client.fetch_metadata("requests")

        assert result["available"] is True
        assert result["last_release_date"] is not None
        parsed = datetime.fromisoformat(result["last_release_date"])
        assert parsed.year == 2023


class TestCountTransitiveDeps:
    """Test suite for the transitive dep counting stub."""

    def test_returns_none_for_poc(self) -> None:
        """The PoC stub returns None for any package."""
        client = PyPIClient()
        result = client.count_transitive_deps("requests", "2.31.0")
        assert result is None
