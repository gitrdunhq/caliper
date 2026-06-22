"""Alternatives catalog schema and parsing utilities.
# tested-by: tests/unit/test_alternatives.py

Provides Pydantic models for the package alternatives catalog, parsers for
requirements.txt and pyproject.toml, and a catalog builder that categorizes
packages and populates cross-references.
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Category enum and mapping
# ---------------------------------------------------------------------------

VALID_CATEGORIES = Literal[
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

# Canonical mapping: package name (lowercase) -> category
_PACKAGE_CATEGORY_MAP: dict[str, str] = {
    # http-client
    "requests": "http-client",
    "httpx": "http-client",
    "urllib3": "http-client",
    "aiohttp": "http-client",
    # json
    "orjson": "json",
    "ujson": "json",
    "simplejson": "json",
    # auth
    "pyjwt": "auth",
    "authlib": "auth",
    "oauthlib": "auth",
    "python-jose": "auth",
    # testing
    "pytest": "testing",
    "unittest": "testing",
    "nose": "testing",
    "coverage": "testing",
    "tox": "testing",
    "hypothesis": "testing",
    # logging
    "structlog": "logging",
    "loguru": "logging",
    "python-json-logger": "logging",
    # cli
    "click": "cli",
    "typer": "cli",
    "argparse": "cli",
    "fire": "cli",
    # web-framework
    "flask": "web-framework",
    "django": "web-framework",
    "fastapi": "web-framework",
    "starlette": "web-framework",
    "tornado": "web-framework",
    # database
    "sqlalchemy": "database",
    "psycopg": "database",
    "asyncpg": "database",
    "pymongo": "database",
    "redis": "database",
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class PackageEntry(BaseModel):
    """A single package in the alternatives catalog."""

    package_name: str
    ecosystem: str  # "pypi"
    category: VALID_CATEGORIES
    is_approved: bool
    alternatives: list[str]


class AlternativesCatalog(BaseModel):
    """Top-level catalog of packages with cross-referenced alternatives."""

    schema_version: str  # "1.0"
    ecosystem: str
    packages: list[PackageEntry]
    generated_at: datetime


# ---------------------------------------------------------------------------
# Parsing functions
# ---------------------------------------------------------------------------

# Regex to split a requirement line into name (with optional extras) and the rest
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(\[[^\]]*\])?"  # optional extras like [binary]
    r"(.*)$"  # version specifiers and remainder
)


def parse_requirements_txt(path: Path) -> set[str]:
    """Extract package names from a requirements.txt file.

    Handles version specifiers (==, >=, ~=, !=), extras ([binary]),
    comments (#), blank lines, -r includes (skipped), and inline comments.
    """
    packages: set[str] = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()
        match = _REQ_LINE_RE.match(line)
        if match:
            packages.add(match.group(1).lower())
    return packages


def parse_pyproject_toml(path: Path) -> set[str]:
    """Extract package names from [project.dependencies] in a pyproject.toml."""
    data = tomllib.loads(path.read_text())
    deps = data.get("project", {}).get("dependencies", [])
    packages: set[str] = set()
    for dep in deps:
        dep = dep.strip()
        match = _REQ_LINE_RE.match(dep)
        if match:
            packages.add(match.group(1).lower())
    return packages


# ---------------------------------------------------------------------------
# Categorization
# ---------------------------------------------------------------------------


def categorize_package(name: str) -> str:
    """Return the category for a package name, or 'unknown' if not recognized."""
    return _PACKAGE_CATEGORY_MAP.get(name.lower(), "unknown")


# ---------------------------------------------------------------------------
# Catalog builder
# ---------------------------------------------------------------------------


def build_catalog(package_names: set[str]) -> AlternativesCatalog:
    """Build an AlternativesCatalog from a set of package names.

    All packages are marked as approved (they're already in use). Packages
    in the same category are listed as alternatives for each other.
    """
    # Group packages by category
    by_category: dict[str, list[str]] = {}
    for name in sorted(package_names):
        cat = categorize_package(name)
        by_category.setdefault(cat, []).append(name)

    entries: list[PackageEntry] = []
    for name in sorted(package_names):
        cat = categorize_package(name)
        siblings = [s for s in by_category.get(cat, []) if s != name]
        entries.append(
            PackageEntry(
                package_name=name,
                ecosystem="pypi",
                category=cat,
                is_approved=True,
                alternatives=siblings,
            )
        )

    return AlternativesCatalog(
        schema_version="1.0",
        ecosystem="pypi",
        packages=entries,
        generated_at=datetime.now(UTC),
    )
