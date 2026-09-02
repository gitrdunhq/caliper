"""Dependency report renderer — advisory-grouped markdown + fix-first plan.
# tested-by: tests/unit/test_renderer.py

Pure functions over finding dicts. Split out of ``core/renderer.py`` (the PR
comment assembler) because they render a *dependency* report — grouped by
advisory id, with a deterministic "fix these direct packages first" list —
and share nothing with the comment sections/verdict/score path beyond
``finding_get``.
"""

from __future__ import annotations

from caliper.core.plugin import finding_get

_FIX_FIRST_SEVERITIES: set[str] = {"critical", "high"}
_DEPENDENCY_TREE_TOOL = "pip"


def render_markdown(findings: list[dict]) -> str:
    """Render a dependency report section, grouped by shared advisory id.

    Findings that share the same advisory ``id`` are rendered under a single
    heading. Each finding shows ``<package> <installed> -> <fixed>``, the
    declaring manifest path, and whether it is a ``direct``/``transitive``
    dependency.
    """
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        advisory_id = str(finding_get(finding, "id", "") or "")
        groups.setdefault(advisory_id, []).append(finding)

    lines: list[str] = []
    for advisory_id, group in groups.items():
        lines.append(f"### {advisory_id}")
        for finding in group:
            package = finding_get(finding, "package", "") or ""
            installed = finding_get(finding, "version", "") or ""
            fixed = finding_get(finding, "fixed_version", "") or ""
            manifest = finding_get(finding, "manifest", "") or ""
            is_direct = bool(finding_get(finding, "direct", False))
            direct_label = "direct" if is_direct else "transitive"
            line = f"- {package} {installed} -> {fixed} ({direct_label})"
            if manifest:
                line += f" — {manifest}"
            lines.append(line)
        lines.append("")

    scanner_db_dates: dict[str, str] = {}
    for finding in findings:
        db_updated_at = finding_get(finding, "db_updated_at", None)
        if not db_updated_at:
            continue
        plugin_name = str(finding_get(finding, "plugin", "") or "")
        scanner_db_dates.setdefault(plugin_name, str(db_updated_at))

    for plugin_name, db_updated_at in scanner_db_dates.items():
        prefix = f"_{plugin_name}" if plugin_name else "_scanner"
        lines.append(f"{prefix} vulnerability data as of {db_updated_at}_")

    return "\n".join(lines)


def compute_fix_first(findings: list[dict]) -> list[str]:
    """Return the minimal, deterministic set of direct package bumps.

    Walks every critical/high finding: direct findings contribute their own
    package name; transitive findings contribute their resolvable direct
    parent when known, or a ``"transitive: needs `<tool> dependency tree`"``
    fallback entry when the parent cannot be resolved. Duplicates are
    collapsed and the result is sorted for determinism.
    """
    direct_targets: set[str] = set()
    unresolved: set[str] = set()

    for finding in findings:
        severity = str(finding_get(finding, "severity", "")).lower()
        if severity not in _FIX_FIRST_SEVERITIES:
            continue

        is_direct = bool(finding_get(finding, "direct", False))
        if is_direct:
            package = str(finding_get(finding, "package", "") or "")
            if package:
                direct_targets.add(package)
            continue

        parent = finding_get(finding, "parent", None)
        if parent:
            direct_targets.add(str(parent))
        else:
            unresolved.add(f"transitive: needs `{_DEPENDENCY_TREE_TOOL} dependency tree`")

    return sorted(direct_targets) + sorted(unresolved)
