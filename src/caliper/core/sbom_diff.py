"""SBOM-based dependency diffing — ecosystem-agnostic via Syft CycloneDX.
# tested-by: tests/unit/test_sbom_diff.py

Replaces per-ecosystem lockfile parsers with a single approach:
run Syft twice (base branch + PR branch), diff the CycloneDX SBOMs.
Works for every ecosystem Syft supports: PyPI, npm, Maven, Go, Cargo, OCI.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from packaging.version import InvalidVersion, Version

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    ecosystem: str
    purl: str | None = None


def parse_sbom_packages(sbom: dict) -> dict[str, PackageInfo]:
    """Extract packages from a CycloneDX JSON SBOM.

    Returns a dict keyed by "{ecosystem}:{name}" for easy diffing.

    Raises
    ------
    TypeError
        If *sbom* is not a dict (e.g. None, str, list).  This turns a silent
        AttributeError from untrusted input into a clear boundary rejection.
    """
    if not isinstance(sbom, dict):
        raise TypeError(f"SBOM must be a dict, got {type(sbom).__name__}")

    packages: dict[str, PackageInfo] = {}

    for component in sbom.get("components", []):
        if not isinstance(component, dict):
            continue
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) or component.get("type", "library")

        if not name:
            continue

        key = f"{ecosystem}:{name}"
        packages[key] = PackageInfo(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or None,
        )

    return packages


def _make_change(
    action: str,
    old: PackageInfo | None,
    new: PackageInfo | None,
) -> dict:
    """Build a standardised change dict from old/new PackageInfo.

    Centralises the field layout so all three action branches (added, removed,
    upgraded/downgraded) are guaranteed to produce identical key sets.  Using
    one inline dict per branch made it easy to forget a field or mistype it in
    one branch but not the others.

    Args:
        action: One of ``"added"``, ``"removed"``, ``"upgraded"``, ``"downgraded"``.
        old:    The before-state PackageInfo, or None for additions.
        new:    The after-state PackageInfo, or None for removals.
    """
    canonical = new if new is not None else old
    assert canonical is not None, "at least one of old/new must be non-None"
    return {
        "action": action,
        "package": canonical.name,
        "ecosystem": canonical.ecosystem,
        "old_version": old.version if old is not None else None,
        "new_version": new.version if new is not None else None,
        "purl": canonical.purl,
    }


def diff_sboms(before: dict, after: dict) -> list[dict]:
    """Diff two CycloneDX SBOMs and return package changes.

    Returns list of dicts with keys:
        action: added | removed | upgraded | downgraded
        package: package name
        ecosystem: pypi | npm | maven | golang | cargo | etc.
        old_version: str | None
        new_version: str | None
        purl: str | None
    """
    before_pkgs = parse_sbom_packages(before)
    after_pkgs = parse_sbom_packages(after)

    changes: list[dict] = []
    all_keys = set(before_pkgs.keys()) | set(after_pkgs.keys())

    for key in sorted(all_keys):
        old = before_pkgs.get(key)
        new = after_pkgs.get(key)

        if new and not old:
            changes.append(_make_change("added", None, new))
        elif old and not new:
            changes.append(_make_change("removed", old, None))
        elif old and new and old.version != new.version:
            action = _classify_version_change(old.version, new.version)
            changes.append(_make_change(action, old, new))

    logger.info(
        "sbom_diff_complete",
        before_count=len(before_pkgs),
        after_count=len(after_pkgs),
        added=sum(1 for c in changes if c["action"] == "added"),
        removed=sum(1 for c in changes if c["action"] == "removed"),
        upgraded=sum(1 for c in changes if c["action"] == "upgraded"),
        downgraded=sum(1 for c in changes if c["action"] == "downgraded"),
    )

    return changes


def _classify_version_change(old_ver: str, new_ver: str) -> str:
    try:
        return "upgraded" if Version(old_ver) < Version(new_ver) else "downgraded"
    except InvalidVersion:
        logger.warning(
            "version_string_comparison_fallback",
            old_version=old_ver,
            new_version=new_ver,
        )
        return "upgraded" if old_ver < new_ver else "downgraded"


_PURL_ECOSYSTEM_MAP: dict[str, str] = {
    "pkg:pypi/": "pypi",
    "pkg:npm/": "npm",
    "pkg:maven/": "maven",
    "pkg:golang/": "golang",
    "pkg:cargo/": "cargo",
    "pkg:gem/": "gem",
    "pkg:nuget/": "nuget",
    "pkg:hex/": "hex",
    "pkg:composer/": "composer",
    "pkg:cocoapods/": "cocoapods",
    "pkg:swift/": "swift",
    "pkg:pub/": "pub",
    "pkg:deb/": "deb",
    "pkg:rpm/": "rpm",
    "pkg:apk/": "apk",
    "pkg:oci/": "oci",
    "pkg:docker/": "docker",
    "pkg:github/": "github",
}


def _ecosystem_from_purl(purl: str) -> str | None:
    if not purl:
        return None
    for prefix, ecosystem in _PURL_ECOSYSTEM_MAP.items():
        if purl.startswith(prefix):
            return ecosystem
    return None
