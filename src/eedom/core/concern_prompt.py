"""Holistic review prompt, retry logic, and report renderer for concern audits.
# tested-by: tests/unit/test_concern_review.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx  # noqa: F401
import structlog

if TYPE_CHECKING:
    from eedom.core.concern_review import AuditReport

logger = structlog.get_logger(__name__)

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 529})


def post_with_retry(
    client: httpx.Client,
    url: str,
    payload: dict,
    headers: dict,
    is_anthropic: bool,
    timeout: int,
    max_retries: int = 3,
) -> str:
    """POST with exponential backoff on retryable errors. Returns text or ""."""
    import time

    for attempt in range(max_retries):
        try:
            resp = client.post(url, json=payload, headers=headers)
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.warning("concern_review.request_error", error=str(exc), attempt=attempt + 1)
            if attempt < max_retries - 1:
                time.sleep(2.0**attempt)
                continue
            return ""

        if resp.status_code in _RETRYABLE_STATUS:
            logger.warning(
                "concern_review.retryable",
                status=resp.status_code,
                attempt=attempt + 1,
            )
            if attempt < max_retries - 1:
                time.sleep(2.0**attempt)
                continue
            return ""

        if resp.status_code != 200:
            logger.warning(
                "concern_review.api_error", status=resp.status_code, body=resp.text[:200]
            )
            return ""

        try:
            data = resp.json()
            if is_anthropic:
                return data["content"][0]["text"]
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            # ValueError covers json.JSONDecodeError from resp.json() on a malformed body.
            logger.warning("concern_review.parse_error", error=str(exc))
            return ""

    return ""


SYSTEM_PROMPT = """\
You are a senior software engineer conducting a holistic codebase trust audit.

You are reviewing one concern cluster — a group of related source files in a \
single architectural tier. The project owner wants to TRUST this code. Your job \
is to surface anything that undermines that trust.

Review the code across ALL of these dimensions:

1. SECURITY
   - Injection risks (SQL, command, template, LDAP)
   - Auth/AuthZ gaps (privilege escalation, missing checks, token handling)
   - Data exposure (logging secrets, error messages leaking internals)
   - Input validation gaps (missing sanitization, type coercion, length limits)
   - Cryptography issues (weak algorithms, hardcoded secrets, improper key handling)
   - Deserialization risks (pickle, eval, yaml.load without SafeLoader)

2. ARCHITECTURE
   - Tier violations (does presentation leak into data? does data contain business logic?)
   - Coupling (tight coupling between modules that should be independent)
   - Dependency direction (imports flowing upward instead of downward)
   - Abstraction quality (leaky abstractions, god classes, SRP violations)
   - Error boundaries (are errors handled at the right layer?)

3. CODE QUALITY
   - Logic errors, off-by-one, null/None handling, race conditions
   - Dead code, unreachable branches, redundant checks
   - Naming clarity (misleading names, abbreviations that obscure intent)
   - Complexity hotspots (deeply nested logic, long methods, high cyclomatic complexity)
   - DRY violations vs premature abstraction
   - Type safety (untyped boundaries, Any abuse, missing return types)

4. PERFORMANCE
   - Time complexity issues (O(n^2) in hot paths, unnecessary iterations)
   - I/O in loops (database calls, file reads, HTTP requests inside iterations)
   - Memory concerns (large allocations, unbounded collections, missing generators)
   - Missing caching opportunities
   - Blocking calls in async contexts

5. TESTING & DOCUMENTATION
   - Files missing test coverage annotations (# tested-by:)
   - Gaps in what existing tests likely cover based on the code complexity
   - Missing or misleading docstrings on public APIs
   - Implicit contracts that should be documented

6. EDGE CASES & RELIABILITY
   - What inputs would break this code?
   - What happens on timeout, network failure, or partial failure?
   - Are there silent fallbacks masking real errors?
   - Missing retry/backoff on external calls

For each finding:
- **Severity**: Critical / High / Medium / Low
- **Dimension**: Which of the 6 above
- **File**: Which file (use relative path)
- **Line** (if identifiable): approximate line number
- **What's wrong**: Specific description
- **Why it matters**: Impact if left unfixed
- **Fix**: Concrete suggestion

Dom's deterministic scanners have already flagged some issues (included below). \
Do NOT repeat those — focus on what static analysis CANNOT catch: design flaws, \
logic errors, missing validation, architectural drift, and subtle security gaps.

Be harsh. The goal is trust, and trust requires honesty. But be specific — \
vague warnings like "could be improved" are worthless. Every finding must be \
actionable.

End with a TRUST VERDICT for this concern:
- TRUSTED — no significant issues found
- CONDITIONAL — issues exist but are bounded and fixable
- UNTRUSTED — significant issues that undermine confidence in this code\
"""


def render_audit_markdown(report: AuditReport) -> str:
    """Render an AuditReport as a single markdown document."""
    lines: list[str] = []
    lines.append("# Codebase Trust Audit")
    lines.append("")
    lines.append(f"**Concerns reviewed**: {report.concern_count}")
    lines.append(f"**Total files**: {report.total_files}")
    lines.append("")

    trust_counts = {"TRUSTED": 0, "CONDITIONAL": 0, "UNTRUSTED": 0, "UNKNOWN": 0}
    for v in report.verdicts:
        text_upper = v.review_text.upper()
        if "TRUST VERDICT" in text_upper:
            tail = text_upper.split("TRUST VERDICT")[-1]
            if "UNTRUSTED" in tail:
                trust_counts["UNTRUSTED"] += 1
            elif "CONDITIONAL" in tail:
                trust_counts["CONDITIONAL"] += 1
            elif "TRUSTED" in tail:
                trust_counts["TRUSTED"] += 1
            else:
                trust_counts["UNKNOWN"] += 1
        else:
            trust_counts["UNKNOWN"] += 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---------|-------|")
    for verdict, count in trust_counts.items():
        if count > 0:
            lines.append(f"| {verdict} | {count} |")
    lines.append("")

    for v in report.verdicts:
        lines.append("---")
        lines.append(f"## {v.concern} ({v.tier})")
        lines.append(f"*{v.file_count} files, {v.dom_finding_count} scanner findings*")
        lines.append("")
        if v.error:
            lines.append(f"> **Error**: {v.error}")
            lines.append("")
        if v.review_text:
            lines.append(v.review_text)
            lines.append("")

    if report.errors:
        lines.append("---")
        lines.append("## Errors")
        for e in report.errors:
            lines.append(f"- {e}")

    return "\n".join(lines)
