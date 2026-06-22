"""Concern-by-concern remediation via Haiku.
# tested-by: tests/unit/test_concern_remediate.py

Takes audit findings, sends each to Haiku with the source file +
fix suggestion, gets back a failing test + patch. Canary first,
then parallel fan-out.
"""

from __future__ import annotations

import os  # noqa: F401
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import httpx  # noqa: F401
import structlog

logger = structlog.get_logger(__name__)

_REMEDIATION_PROMPT = """\
You are a senior software engineer remediating a security/quality finding.

You will receive:
1. A finding from a holistic codebase audit (severity, description, fix suggestion)
2. The source file containing the vulnerable code

Your job is to produce TWO things:

--- TEST ---
A failing test that reproduces the vulnerability. The test MUST fail against
the current code and pass after the fix. Follow pytest conventions. Include
the test file path.

--- FIX ---
The minimum code change to remediate the finding. Show only the changed lines
with enough context to locate the edit. Include the source file path and
approximate line number.

Rules:
- Test MUST fail before the fix (red-green TDD)
- Fix MUST be minimal — change only what's needed
- No refactoring, no cleanup, no drive-by improvements
- If the fix requires adding an import, include it
- Use parameterized queries for SQL, Path.resolve() for paths,
  yaml.safe_load for YAML, autoescape=True for Jinja2
"""


@dataclass
class PatchResult:
    """Result from remediating one finding."""

    finding_title: str
    severity: str
    file: str
    response: str
    error: str = ""


@dataclass
class RemediationReport:
    """Full remediation run result."""

    total_findings: int
    patches: list[PatchResult]
    errors: list[str] = field(default_factory=list)


class Remediator:
    """Sends findings to Haiku for test + patch generation."""

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        timeout: int = 120,
        max_tokens: int = 4096,
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._client = httpx.Client(timeout=timeout)

    def remediate_finding(self, finding: dict, source_code: str) -> str:
        """Send one finding + source to Haiku, get back test + patch."""
        user_content = (
            f"Finding: {finding.get('title', 'unknown')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"File: {finding.get('file', 'unknown')}\n"
            f"Line: {finding.get('line', '?')}\n"
            f"Fix suggestion: {finding.get('fix_suggestion', 'none provided')}\n\n"
            f"Source code:\n```\n{source_code}\n```"
        )

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "prompt-caching-2024-07-31",
            "content-type": "application/json",
        }
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": [
                {
                    "type": "text",
                    "text": _REMEDIATION_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            "messages": [{"role": "user", "content": user_content}],
        }

        try:
            resp = self._client.post(self.API_URL, json=payload, headers=headers)
        except httpx.TimeoutException:
            logger.warning("remediate.timeout", timeout=self._timeout)
            return ""
        except httpx.HTTPError as exc:
            logger.warning("remediate.http_error", error=str(exc))
            return ""

        if resp.status_code != 200:
            logger.warning("remediate.api_error", status=resp.status_code, body=resp.text[:200])
            return ""

        try:
            return resp.json()["content"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("remediate.parse_error", error=str(exc))
            return ""

    def close(self) -> None:
        self._client.close()


def _remediate_one(
    remediator: Remediator,
    finding: dict,
    repo_path: Path,
) -> PatchResult:
    """Remediate a single finding. Never raises."""
    import contextlib

    file_rel = finding.get("file", "")
    source_code = ""
    with contextlib.suppress(OSError):
        source_code = (repo_path / file_rel).read_text(errors="replace")

    response = remediator.remediate_finding(finding, source_code)

    if not response:
        return PatchResult(
            finding_title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            file=file_rel,
            response="",
            error="Haiku returned empty response",
        )

    return PatchResult(
        finding_title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        file=file_rel,
        response=response,
    )


def run_remediation(
    findings: list[dict],
    repo_path: Path,
    model: str = "claude-haiku-4-5-20251001",
    api_key: str | None = None,
    timeout: int = 120,
    max_workers: int = 4,
) -> RemediationReport:
    """Remediate findings: canary first, then parallel fan-out."""
    if not findings:
        return RemediationReport(total_findings=0, patches=[])

    remediator = Remediator(model=model, api_key=api_key, timeout=timeout)

    # Canary
    canary = findings[0]
    logger.info("remediate.canary", title=canary.get("title", ""))
    canary_result = _remediate_one(remediator, canary, repo_path)

    if canary_result.error:
        logger.warning("remediate.canary_failed", title=canary.get("title", ""))
        skipped = [
            PatchResult(
                finding_title=f.get("title", ""),
                severity=f.get("severity", ""),
                file=f.get("file", ""),
                response="",
                error="Skipped — canary failed",
            )
            for f in findings[1:]
        ]
        remediator.close()
        return RemediationReport(
            total_findings=len(findings),
            patches=[canary_result, *skipped],
            errors=[f"Canary failed for: {canary.get('title', '')}"],
        )

    # Parallel fan-out
    remaining = findings[1:]
    patches: list[PatchResult] = [canary_result]

    if remaining:
        logger.info("remediate.parallel_fanout", count=len(remaining))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_remediate_one, remediator, f, repo_path): f.get("title", "")
                for f in remaining
            }
            for future in as_completed(futures):
                patches.append(future.result())

    remediator.close()
    errors = [f"Empty response for: {p.finding_title}" for p in patches if p.error]

    return RemediationReport(
        total_findings=len(findings),
        patches=patches,
        errors=errors,
    )
