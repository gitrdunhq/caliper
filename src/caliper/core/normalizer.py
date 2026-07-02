"""Finding normalization and deduplication across scanners."""

# tested-by: tests/unit/test_normalizer.py

from __future__ import annotations

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
)

_SEVERITY_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.critical: 5,
    FindingSeverity.high: 4,
    FindingSeverity.medium: 3,
    FindingSeverity.low: 2,
    FindingSeverity.info: 1,
}


def normalize_findings(
    scan_results: list[ScanResult],
) -> tuple[list[Finding], dict[str, int]]:
    all_findings: list[Finding] = []
    for result in scan_results:
        all_findings.extend(result.findings)

    vuln_findings: list[Finding] = []
    non_vuln_findings: list[Finding] = []
    for f in all_findings:
        if f.category == FindingCategory.license:
            non_vuln_findings.append(f)
        else:
            vuln_findings.append(f)

    deduped: dict[tuple, Finding] = {}
    for f in vuln_findings:
        if f.advisory_id:
            key = (f.advisory_id, f.category, f.package_name, f.version)
        else:
            # No advisory ID means this isn't a vuln advisory (secret-scan /
            # code-smell / detector findings) — category/package_name/version
            # routinely collide across unrelated findings in that case, so
            # extend the key with the most specific fields Finding actually
            # carries (source_tool, description) to keep them from silently
            # collapsing into one (#234).
            key = (
                f.advisory_id,
                f.category,
                f.package_name,
                f.version,
                f.source_tool,
                f.description,
            )
        existing = deduped.get(key)
        if existing is None or _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(
            existing.severity, 0
        ):
            deduped[key] = f

    merged = list(deduped.values()) + non_vuln_findings

    summary: dict[str, int] = {s.value: 0 for s in FindingSeverity}
    for f in merged:
        summary[f.severity.value] += 1

    return merged, summary
