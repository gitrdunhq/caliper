# tested-by: tests/unit/test_vex.py
"""OpenVEX output format (https://openvex.dev) for finding disposition.

Pure function: no I/O. Converts plugin results (the same ``list[PluginResult]``
that feeds sarif.py/json_report.py) into an OpenVEX v0.2.0 document. Only
``category == "vulnerability"`` findings carrying an identifiable id become VEX
statements — license/code-smell/supply-chain findings have no VEX equivalent.

Status is derived per finding from severity (does it contribute to the blocking
verdict?) and the reachability scribe's metadata (ADR-009):

- ``reachability.reachable is False`` -> ``not_affected``, justification
  ``vulnerable_code_not_in_execute_path`` — mirrors the trust boundary the
  ``unreachable_vuln_exemption`` OPA rule already enforces: ``reachable=None``
  is never treated as evidence of absence.
- severity maps to the SARIF "error" level (``review_summary.level_for``)
  -> ``affected``, with an ``action_statement`` (upgrade guidance when
  ``fixed_version`` is known).
- everything else -> ``under_investigation`` (not yet confirmed either way).

Deliberately NOT sourced from the separate dependency-approval pipeline
(``core/pipeline.py`` ``ReviewPipeline``): that pipeline builds its own
ephemeral ``PluginFinding`` copies purely to feed OPA policy evaluation and
discards them right after, so no scribe/reachability metadata survives on a
persisted ``ReviewDecision`` for a renderer to read.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from caliper.core.plugin import PluginFinding, PluginResult
from caliper.core.review_summary import level_for

_VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_VEX_AUTHOR = "caliper"

# Worst status wins when the same (vulnerability, product) pair is reported more
# than once across plugin results — same spirit as normalizer.py's
# highest-severity-wins scanner-disagreement dedup.
_STATUS_PRECEDENCE = {"affected": 0, "under_investigation": 1, "not_affected": 2, "fixed": 3}


def _as_dict(finding: PluginFinding | dict) -> dict:
    if isinstance(finding, dict):
        return finding
    return finding.model_dump()


def _product_id(fd: dict) -> str:
    package = fd.get("package") or ""
    version = fd.get("version") or ""
    if not package:
        return "pkg:generic/unknown"
    return f"pkg:generic/{package}@{version}" if version else f"pkg:generic/{package}"


def _vuln_id(fd: dict) -> str:
    return str(fd.get("id") or fd.get("rule_id") or "")


def _reachable(fd: dict) -> bool | None:
    scribe = (fd.get("metadata") or {}).get("scribe") or {}
    reachability = scribe.get("reachability") or {}
    return reachability.get("reachable")


def _disposition(fd: dict) -> dict:
    if _reachable(fd) is False:
        return {
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }
    if level_for(fd.get("severity")) == "error":
        fixed_version = fd.get("fixed_version") or ""
        action = (
            f"Upgrade {fd.get('package')} to {fixed_version} or later."
            if fixed_version
            else "Review and remediate per the advisory."
        )
        return {"status": "affected", "action_statement": action}
    return {"status": "under_investigation"}


def to_vex(results: list[PluginResult], *, author: str = _VEX_AUTHOR) -> dict:
    """Build an OpenVEX document from *results* (pure, no I/O)."""
    by_key: dict[tuple[str, str], dict] = {}
    for result in results:
        for finding in result.findings:
            fd = _as_dict(finding)
            if fd.get("category") != "vulnerability":
                continue
            vuln_id = _vuln_id(fd)
            if not vuln_id:
                continue
            product_id = _product_id(fd)
            statement = {
                "vulnerability": {"name": vuln_id},
                "products": [{"@id": product_id}],
                **_disposition(fd),
            }
            key = (vuln_id, product_id)
            existing = by_key.get(key)
            if existing is None or (
                _STATUS_PRECEDENCE[statement["status"]] < _STATUS_PRECEDENCE[existing["status"]]
            ):
                by_key[key] = statement

    statements = sorted(
        by_key.values(), key=lambda s: (s["vulnerability"]["name"], s["products"][0]["@id"])
    )
    doc_id = (
        "urn:caliper:vex:"
        + hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()
    )
    return {
        "@context": _VEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "timestamp": datetime.now(UTC).isoformat(),
        "version": 1,
        "statements": statements,
    }


class VexRenderer:
    """ReportRendererPort implementation that produces an OpenVEX JSON string."""

    def render(self, report) -> str:  # report: ReviewReport
        doc = to_vex(report.plugin_results)
        return json.dumps(doc, indent=2)


from caliper.core.port_registries import RENDERERS  # noqa: E402  (registration wiring)


@RENDERERS.register("vex")
def build_vex_renderer() -> VexRenderer:
    return VexRenderer()
