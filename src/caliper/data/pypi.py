"""PyPI metadata scribe client.
# tested-by: tests/unit/test_pypi.py

Fetches package metadata from the PyPI JSON API for use in review
decisions. All errors are absorbed and returned as structured dicts --
this module never raises on HTTP or parse failures.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog

logger = structlog.get_logger(__name__)


class PyPIClient:
    """Fetches package metadata from the PyPI JSON API.

    All methods return dicts with an ``available`` key indicating success.
    On any failure the dict contains ``available=False`` and an ``error``
    description -- never raises.
    """

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def fetch_metadata(self, package_name: str, version: str | None = None) -> dict:
        """Fetch metadata for a package from PyPI.

        Args:
            package_name: PyPI package name.
            version: Optional specific version. When None, fetches the latest.

        Returns:
            Dict with package metadata on success, or ``available=False`` with
            an ``error`` key on failure.
        """
        if version:
            url = f"https://pypi.org/pypi/{package_name}/{version}/json"
        else:
            url = f"https://pypi.org/pypi/{package_name}/json"

        try:
            response = self._client.get(url)
        except httpx.TimeoutException:
            logger.warning("pypi.timeout", package=package_name, version=version)
            return {"available": False, "error": "PyPI request timed out"}
        except httpx.HTTPError as exc:
            logger.warning("pypi.http_error", package=package_name, error=str(exc))
            return {"available": False, "error": f"PyPI request failed: {exc}"}

        if response.status_code == 404:
            logger.info("pypi.not_found", package=package_name, version=version)
            return {"available": False, "error": "package not found"}

        if response.status_code != 200:
            logger.warning(
                "pypi.unexpected_status",
                package=package_name,
                status=response.status_code,
            )
            return {
                "available": False,
                "error": f"PyPI returned status {response.status_code}",
            }

        try:
            data = response.json()
        except Exception as exc:
            logger.warning("pypi.parse_error", package=package_name, error=str(exc))
            return {"available": False, "error": f"failed to parse PyPI response: {exc}"}

        return self._extract_metadata(data)

    def count_transitive_deps(self, package_name: str, version: str) -> int | None:
        """Count transitive dependencies for a package.

        For PoC: returns None. Accurate transitive dep counting requires
        installing the package or resolving the full dependency tree.
        Transitive counts are obtained from SBOM instead.
        """
        # TODO(T-025): Implement transitive dep counting via SBOM data
        # instead of pip resolution. Remove this stub when SBOM-based
        # counting is wired up.
        logger.debug(
            "pypi.transitive_deps_not_implemented",
            package=package_name,
            version=version,
        )
        return None

    @staticmethod
    def _extract_metadata(data: dict) -> dict:
        """Extract relevant fields from PyPI JSON response."""
        info = data.get("info", {})
        project_urls = info.get("project_urls") or {}

        source_url = (
            project_urls.get("Source")
            or project_urls.get("Source Code")
            or project_urls.get("Repository")
            or project_urls.get("GitHub")
            or project_urls.get("Homepage")
        )

        releases = data.get("releases", {})
        first_published_date = _compute_first_published(releases)
        last_release_date = _compute_last_published(releases)
        package_age_days = _compute_age_days(first_published_date)

        return {
            "available": True,
            "name": info.get("name", ""),
            "version": info.get("version", ""),
            "summary": info.get("summary", ""),
            "author": info.get("author") or info.get("author_email", ""),
            "license": info.get("license", ""),
            "home_page": info.get("home_page") or info.get("project_url", ""),
            "source_url": source_url,
            "classifiers": info.get("classifiers", []),
            "first_published_date": first_published_date,
            "last_release_date": last_release_date,
            "package_age_days": package_age_days,
        }


def _compute_first_published(releases: dict) -> str | None:
    """Find the earliest upload_time across all releases.

    Returns ISO-formatted datetime string or None if no releases exist.
    """
    earliest: datetime | None = None

    for _version, files in releases.items():
        for file_info in files:
            upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            if not upload_time_str:
                continue
            try:
                ts = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                if earliest is None or ts < earliest:
                    earliest = ts
            except (ValueError, TypeError):
                continue

    if earliest is None:
        return None
    return earliest.isoformat()


def _compute_last_published(releases: dict) -> str | None:
    """Find the latest upload_time across all releases.

    Returns ISO-formatted datetime string or None if no releases exist.
    """
    latest: datetime | None = None

    for _version, files in releases.items():
        for file_info in files:
            upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            if not upload_time_str:
                continue
            try:
                ts = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                if latest is None or ts > latest:
                    latest = ts
            except (ValueError, TypeError):
                continue

    if latest is None:
        return None
    return latest.isoformat()


def _compute_age_days(first_published_date: str | None) -> int | None:
    """Calculate the number of days since the first published date."""
    if first_published_date is None:
        return None
    try:
        first = datetime.fromisoformat(first_published_date)
        if first.tzinfo is None:
            first = first.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        return (now - first).days
    except (ValueError, TypeError):
        return None


from caliper.core.registries import PACKAGE_INDEXES  # noqa: E402  (registration wiring)


@PACKAGE_INDEXES.register("pypi")
def build_pypi_index(*, timeout: int = 10) -> PyPIClient:
    """Construct the real PyPI package index client."""
    return PyPIClient(timeout=timeout)
