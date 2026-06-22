"""Tests for caliper.data.alternatives and scripts/bootstrap_alternatives.py."""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Schema model tests
# ---------------------------------------------------------------------------


class TestPackageEntry:
    """PackageEntry Pydantic model validation."""

    def test_valid_entry(self) -> None:
        from caliper.data.alternatives import PackageEntry

        entry = PackageEntry(
            package_name="requests",
            ecosystem="pypi",
            category="http-client",
            is_approved=True,
            alternatives=["httpx", "urllib3"],
        )
        assert entry.package_name == "requests"
        assert entry.ecosystem == "pypi"
        assert entry.category == "http-client"
        assert entry.is_approved is True
        assert entry.alternatives == ["httpx", "urllib3"]

    def test_rejects_invalid_category(self) -> None:
        from caliper.data.alternatives import PackageEntry

        with pytest.raises(ValidationError):
            PackageEntry(
                package_name="foo",
                ecosystem="pypi",
                category="invalid-category",
                is_approved=True,
                alternatives=[],
            )

    def test_accepts_all_valid_categories(self) -> None:
        from caliper.data.alternatives import PackageEntry

        valid_categories = [
            "http-client",
            "json",
            "auth",
            "testing",
            "logging",
            "cli",
            "web-framework",
            "database",
            "unknown",
        ]
        for cat in valid_categories:
            entry = PackageEntry(
                package_name="pkg",
                ecosystem="pypi",
                category=cat,
                is_approved=False,
                alternatives=[],
            )
            assert entry.category == cat

    def test_empty_alternatives_list(self) -> None:
        from caliper.data.alternatives import PackageEntry

        entry = PackageEntry(
            package_name="some-unique-pkg",
            ecosystem="pypi",
            category="unknown",
            is_approved=True,
            alternatives=[],
        )
        assert entry.alternatives == []


class TestAlternativesCatalog:
    """AlternativesCatalog Pydantic model validation."""

    def test_valid_catalog(self) -> None:
        from caliper.data.alternatives import AlternativesCatalog, PackageEntry

        catalog = AlternativesCatalog(
            schema_version="1.0",
            ecosystem="pypi",
            packages=[
                PackageEntry(
                    package_name="requests",
                    ecosystem="pypi",
                    category="http-client",
                    is_approved=True,
                    alternatives=["httpx"],
                ),
            ],
            generated_at=datetime(2026, 1, 1, 12, 0, 0),
        )
        assert catalog.schema_version == "1.0"
        assert catalog.ecosystem == "pypi"
        assert len(catalog.packages) == 1
        assert catalog.packages[0].package_name == "requests"

    def test_empty_packages_list(self) -> None:
        from caliper.data.alternatives import AlternativesCatalog

        catalog = AlternativesCatalog(
            schema_version="1.0",
            ecosystem="pypi",
            packages=[],
            generated_at=datetime(2026, 1, 1),
        )
        assert catalog.packages == []

    def test_round_trip_json(self) -> None:
        from caliper.data.alternatives import AlternativesCatalog, PackageEntry

        catalog = AlternativesCatalog(
            schema_version="1.0",
            ecosystem="pypi",
            packages=[
                PackageEntry(
                    package_name="flask",
                    ecosystem="pypi",
                    category="web-framework",
                    is_approved=True,
                    alternatives=["django", "fastapi"],
                ),
            ],
            generated_at=datetime(2026, 4, 22, 10, 30, 0),
        )
        dumped = catalog.model_dump(mode="json")
        restored = AlternativesCatalog.model_validate(dumped)
        assert restored.schema_version == "1.0"
        assert restored.packages[0].package_name == "flask"
        assert restored.packages[0].alternatives == ["django", "fastapi"]
        assert restored.generated_at == catalog.generated_at


# ---------------------------------------------------------------------------
# Parsing function tests
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    """parse_requirements_txt extracts package names from requirements files."""

    def test_basic_packages(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("requests==2.31.0\nflask>=2.0\nhttpx\n")
        result = parse_requirements_txt(reqs)
        assert result == {"requests", "flask", "httpx"}

    def test_comments_and_blank_lines(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text(textwrap.dedent("""\
            # This is a comment
            requests==2.31.0

            # Another comment
            flask>=2.0

            """))
        result = parse_requirements_txt(reqs)
        assert result == {"requests", "flask"}

    def test_version_specifiers(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("requests==2.31.0\nflask>=2.0,<3.0\nclick~=8.1\nurllib3!=1.25.0\n")
        result = parse_requirements_txt(reqs)
        assert result == {"requests", "flask", "click", "urllib3"}

    def test_r_includes_skipped(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("-r base.txt\nrequests==2.31.0\n")
        result = parse_requirements_txt(reqs)
        assert result == {"requests"}

    def test_extras_stripped(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("psycopg[binary]>=3.1\nuvicorn[standard]\n")
        result = parse_requirements_txt(reqs)
        assert result == {"psycopg", "uvicorn"}

    def test_inline_comments(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("requests==2.31.0  # HTTP client\nflask>=2.0 # web\n")
        result = parse_requirements_txt(reqs)
        assert result == {"requests", "flask"}


class TestParsePyprojectToml:
    """parse_pyproject_toml extracts package names from [project.dependencies]."""

    def test_basic_dependencies(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_pyproject_toml

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [project]
            name = "myapp"
            version = "1.0.0"
            dependencies = [
                "click>=8.1",
                "pydantic>=2.7",
                "structlog>=24.1",
            ]
            """))
        result = parse_pyproject_toml(pyproject)
        assert result == {"click", "pydantic", "structlog"}

    def test_extras_stripped(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_pyproject_toml

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [project]
            name = "myapp"
            version = "1.0.0"
            dependencies = [
                "psycopg[binary]>=3.1",
                "uvicorn[standard]>=0.29",
            ]
            """))
        result = parse_pyproject_toml(pyproject)
        assert result == {"psycopg", "uvicorn"}

    def test_no_dependencies_section(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_pyproject_toml

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [project]
            name = "myapp"
            version = "1.0.0"
            """))
        result = parse_pyproject_toml(pyproject)
        assert result == set()


# ---------------------------------------------------------------------------
# Category assignment tests
# ---------------------------------------------------------------------------


class TestCategorizePackage:
    """categorize_package assigns the correct category based on known mappings."""

    def test_http_clients(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("requests") == "http-client"
        assert categorize_package("httpx") == "http-client"
        assert categorize_package("urllib3") == "http-client"
        assert categorize_package("aiohttp") == "http-client"

    def test_json_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("orjson") == "json"
        assert categorize_package("ujson") == "json"
        assert categorize_package("simplejson") == "json"

    def test_auth_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("pyjwt") == "auth"
        assert categorize_package("authlib") == "auth"
        assert categorize_package("oauthlib") == "auth"
        assert categorize_package("python-jose") == "auth"

    def test_testing_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("pytest") == "testing"
        assert categorize_package("coverage") == "testing"
        assert categorize_package("hypothesis") == "testing"

    def test_logging_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("structlog") == "logging"
        assert categorize_package("loguru") == "logging"
        assert categorize_package("python-json-logger") == "logging"

    def test_cli_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("click") == "cli"
        assert categorize_package("typer") == "cli"
        assert categorize_package("fire") == "cli"

    def test_web_frameworks(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("flask") == "web-framework"
        assert categorize_package("django") == "web-framework"
        assert categorize_package("fastapi") == "web-framework"
        assert categorize_package("starlette") == "web-framework"
        assert categorize_package("tornado") == "web-framework"

    def test_database_libraries(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("sqlalchemy") == "database"
        assert categorize_package("psycopg") == "database"
        assert categorize_package("asyncpg") == "database"
        assert categorize_package("pymongo") == "database"
        assert categorize_package("redis") == "database"

    def test_unknown_package(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("some-random-package") == "unknown"
        assert categorize_package("pydantic") == "unknown"

    def test_case_insensitive(self) -> None:
        from caliper.data.alternatives import categorize_package

        assert categorize_package("Flask") == "web-framework"
        assert categorize_package("REQUESTS") == "http-client"


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------


class TestDeduplication:
    """Packages appearing in multiple input files are deduplicated."""

    def test_dedup_across_files(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import parse_requirements_txt

        reqs1 = tmp_path / "requirements1.txt"
        reqs1.write_text("requests==2.31.0\nflask>=2.0\n")
        reqs2 = tmp_path / "requirements2.txt"
        reqs2.write_text("requests==2.32.0\ndjango>=4.0\n")

        packages = parse_requirements_txt(reqs1) | parse_requirements_txt(reqs2)
        assert packages == {"requests", "flask", "django"}

    def test_dedup_across_file_types(self, tmp_path: Path) -> None:
        from caliper.data.alternatives import (
            parse_pyproject_toml,
            parse_requirements_txt,
        )

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("requests==2.31.0\nclick>=8.1\n")
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [project]
            name = "myapp"
            version = "1.0.0"
            dependencies = [
                "click>=8.1",
                "pydantic>=2.7",
            ]
            """))

        packages = parse_requirements_txt(reqs) | parse_pyproject_toml(pyproject)
        assert packages == {"requests", "click", "pydantic"}


# ---------------------------------------------------------------------------
# Catalog building tests
# ---------------------------------------------------------------------------


class TestBuildCatalog:
    """build_catalog produces a valid AlternativesCatalog from package names."""

    def test_same_category_packages_are_alternatives(self) -> None:
        from caliper.data.alternatives import build_catalog

        packages = {"requests", "httpx", "flask"}
        catalog = build_catalog(packages)

        by_name = {p.package_name: p for p in catalog.packages}
        assert "requests" in by_name
        assert "httpx" in by_name
        assert "flask" in by_name

        # requests and httpx are in same category, each should list the other
        assert "httpx" in by_name["requests"].alternatives
        assert "requests" in by_name["httpx"].alternatives
        # flask is alone in web-framework category from this set
        assert by_name["flask"].alternatives == []

    def test_all_packages_marked_approved(self) -> None:
        from caliper.data.alternatives import build_catalog

        packages = {"requests", "flask", "orjson"}
        catalog = build_catalog(packages)

        for entry in catalog.packages:
            assert entry.is_approved is True

    def test_catalog_metadata(self) -> None:
        from caliper.data.alternatives import build_catalog

        catalog = build_catalog({"requests"})
        assert catalog.schema_version == "1.0"
        assert catalog.ecosystem == "pypi"
        assert isinstance(catalog.generated_at, datetime)

    def test_catalog_json_output_matches_schema(self) -> None:
        from caliper.data.alternatives import build_catalog

        catalog = build_catalog({"requests", "httpx", "flask", "django"})
        dumped = catalog.model_dump(mode="json")

        assert dumped["schema_version"] == "1.0"
        assert dumped["ecosystem"] == "pypi"
        assert isinstance(dumped["generated_at"], str)
        assert isinstance(dumped["packages"], list)

        for pkg in dumped["packages"]:
            assert "package_name" in pkg
            assert "ecosystem" in pkg
            assert "category" in pkg
            assert "is_approved" in pkg
            assert "alternatives" in pkg

    def test_package_not_in_own_alternatives(self) -> None:
        from caliper.data.alternatives import build_catalog

        packages = {"requests", "httpx", "urllib3", "aiohttp"}
        catalog = build_catalog(packages)

        for entry in catalog.packages:
            assert entry.package_name not in entry.alternatives
