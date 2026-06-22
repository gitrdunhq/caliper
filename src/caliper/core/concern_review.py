"""Concern-by-concern holistic codebase audit via LLM fan-out.
# tested-by: tests/unit/test_concern_review.py

Clusters source files into concern groups, runs dom's scanners,
then fans out each concern to a fast LLM (Haiku) for holistic review:
security, architecture, code quality, performance, and documentation.

The LLM is advisory only — dom's deterministic scanners remain the
decision authority.  The holistic review adds depth that regex and
AST-based tools cannot reach.
"""

from __future__ import annotations

import os  # noqa: F401 — used in HolisticReviewer
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import httpx  # noqa: F401 — used in HolisticReviewer
import structlog

from caliper.core.concern_prompt import SYSTEM_PROMPT as _SYSTEM_PROMPT
from caliper.core.concern_prompt import post_with_retry as _post_with_retry
from caliper.core.concern_prompt import render_audit_markdown as render_audit_markdown

if TYPE_CHECKING:
    from caliper.core.plugin import PluginResult

logger = structlog.get_logger(__name__)

TIER_MAP = {
    "cli": "presentation",
    "core": "logic",
    "data": "data",
    "plugins": "data",
    "agent": "presentation",
    "templates": "data",
    "webhook": "presentation",
}


@dataclass
class ConcernCluster:
    """A group of related source files forming one review unit."""

    name: str
    tier: str
    files: list[str]
    total_lines: int = 0
    total_tokens: int = 0
    findings: list[dict] = field(default_factory=list)
    source_snippets: dict[str, str] = field(default_factory=dict)


@dataclass
class ConcernVerdict:
    """Holistic review result for one concern cluster."""

    concern: str
    tier: str
    file_count: int
    dom_finding_count: int
    review_text: str
    error: str = ""


@dataclass
class AuditReport:
    """Full codebase trust audit result."""

    repo_path: str
    concern_count: int
    total_files: int
    verdicts: list[ConcernVerdict]
    errors: list[str] = field(default_factory=list)


def _estimate_tokens(text: str) -> int:
    words = len(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text))
    symbols = len(re.findall(r"[^a-zA-Z0-9_\s]", text))
    return int(words * 1.3 + symbols * 0.7)


def _classify_tier(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "caliper":
        return TIER_MAP.get(parts[2], "unknown")
    return "unknown"


def cluster_files(
    repo_path: Path,
    files: list[str],
    max_tokens_per_cluster: int = 12_000,
) -> list[ConcernCluster]:
    """Group source files into concern clusters by directory prefix."""
    buckets: dict[str, list[tuple[str, str, int]]] = {}

    for fpath in files:
        try:
            rel = str(Path(fpath).relative_to(repo_path))
        except ValueError:
            rel = fpath

        parts = Path(rel).parts
        # Only review source code — tests are the verification layer
        if len(parts) >= 3 and parts[0] == "src":
            key = "/".join(parts[:3])
        else:
            continue

        try:
            text = Path(fpath).read_text(errors="replace")
        except OSError:
            continue

        tokens = _estimate_tokens(text)
        buckets.setdefault(key, []).append((fpath, text, tokens))

    clusters: list[ConcernCluster] = []
    for key, members in sorted(buckets.items()):
        total_tokens = sum(t for _, _, t in members)
        if total_tokens <= max_tokens_per_cluster:
            clusters.append(
                ConcernCluster(
                    name=key,
                    tier=_classify_tier(key),
                    files=[f for f, _, _ in members],
                    total_lines=sum(text.count("\n") + 1 for _, text, _ in members),
                    total_tokens=total_tokens,
                    source_snippets={f: text for f, text, _ in members},
                )
            )
        else:
            chunk: list[tuple[str, str, int]] = []
            chunk_tokens = 0
            chunk_idx = 0
            for fpath, text, tokens in members:
                if chunk_tokens + tokens > max_tokens_per_cluster and chunk:
                    clusters.append(
                        ConcernCluster(
                            name=f"{key}:{chunk_idx}",
                            tier=_classify_tier(key),
                            files=[f for f, _, _ in chunk],
                            total_lines=sum(t.count("\n") + 1 for _, t, _ in chunk),
                            total_tokens=chunk_tokens,
                            source_snippets={f: t for f, t, _ in chunk},
                        )
                    )
                    chunk_idx += 1
                    chunk = []
                    chunk_tokens = 0
                chunk.append((fpath, text, tokens))
                chunk_tokens += tokens
            if chunk:
                clusters.append(
                    ConcernCluster(
                        name=f"{key}:{chunk_idx}" if chunk_idx > 0 else key,
                        tier=_classify_tier(key),
                        files=[f for f, _, _ in chunk],
                        total_lines=sum(t.count("\n") + 1 for _, t, _ in chunk),
                        total_tokens=chunk_tokens,
                        source_snippets={f: t for f, t, _ in chunk},
                    )
                )

    return clusters


def attach_findings(
    clusters: list[ConcernCluster],
    results: list[PluginResult],
    repo_path: Path,
) -> None:
    """Attach dom's plugin findings to each cluster's files in-place."""
    for cluster in clusters:
        cluster_rels = set()
        for f in cluster.files:
            try:
                cluster_rels.add(str(Path(f).relative_to(repo_path)))
            except ValueError:
                cluster_rels.add(f)

        for result in results:
            for finding in result.findings:
                fpath = finding.file if hasattr(finding, "file") else finding.get("file", "")
                if fpath in cluster_rels:
                    d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
                    d["plugin"] = result.plugin_name
                    cluster.findings.append(d)


def build_coverage_manifest(repo_path: Path) -> str:
    """Build a deterministic coverage manifest from semgrep rules + code graph checks.

    Returns a text block listing every pattern already caught by dom's
    deterministic scanners, so the LLM audit can skip those and focus
    on what's NOT covered.
    """
    import contextlib

    import yaml

    lines = ["DETERMINISTIC COVERAGE — do NOT report findings in these categories:\n"]

    semgrep_dir = repo_path / "policies" / "semgrep"
    if semgrep_dir.is_dir():
        for rule_file in sorted(semgrep_dir.glob("*.yaml")):
            with contextlib.suppress(Exception):
                data = yaml.safe_load(rule_file.read_text())
                for rule in data.get("rules", []):
                    rid = rule.get("id", "?")
                    msg = rule.get("message", "").strip().split("\n")[0][:100]
                    lines.append(f"- [{rid}] {msg}")

    checks_file = repo_path / "src" / "caliper" / "plugins" / "_runners" / "checks.yaml"
    if checks_file.exists():
        with contextlib.suppress(Exception):
            data = yaml.safe_load(checks_file.read_text())
            for check in data.get("checks", []):
                name = check.get("name", "?")
                desc = check.get("description", "")[:100]
                lines.append(f"- [graph:{name}] {desc}")

    lines.append("")
    lines.append(
        "If a finding is already covered by a rule above, SKIP IT. "
        "Only report issues that fall OUTSIDE deterministic coverage."
    )
    return "\n".join(lines)


def build_packet(cluster: ConcernCluster, repo_path: Path) -> dict:
    """Build a JSON packet for one Haiku agent."""
    source_contents: dict[str, str] = {}
    for fpath in cluster.files:
        try:
            rel = str(Path(fpath).relative_to(repo_path))
        except ValueError:
            rel = fpath
        source_contents[rel] = cluster.source_snippets.get(fpath, "")

    return {
        "concern": cluster.name,
        "tier": cluster.tier,
        "file_count": len(cluster.files),
        "total_tokens": cluster.total_tokens,
        "findings": cluster.findings,
        "source": source_contents,
    }


class HolisticReviewer:
    """Fans out concern clusters to an LLM for holistic review.

    Supports two backends:
    - Anthropic Messages API (api.anthropic.com) — for Haiku/Sonnet
    - OpenAI-compatible (OpenRouter, etc.) — for free models like GPT-OSS 120B

    All failures are absorbed with structured logging. Never raises.
    """

    FREE_FALLBACKS = (
        "openai/gpt-oss-120b:free",
        "nousresearch/hermes-3-llama-3.1-405b:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "google/gemma-4-31b-it:free",
    )

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        endpoint: str = "https://api.anthropic.com",
        timeout: int = 120,
        max_tokens: int = 4096,
        coverage_manifest: str = "",
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._endpoint = endpoint
        self._is_anthropic = "anthropic.com" in endpoint
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._client = httpx.Client(timeout=timeout)
        self._coverage = coverage_manifest

    def review_concern(self, packet: dict) -> str:
        """Send one concern packet to Haiku and return the review text."""
        source_block = ""
        for rel_path, content in packet.get("source", {}).items():
            source_block += f"\n--- {rel_path} ---\n{content}\n"

        findings_block = ""
        if packet.get("findings"):
            findings_block = "\n\nCaliper's scanner findings for this concern (DO NOT REPEAT):\n"
            for f in packet["findings"]:
                sev = f.get("severity", "info")
                msg = f.get("message", "")
                plugin = f.get("plugin", "")
                fpath = f.get("file", "")
                findings_block += f"- [{sev}] {plugin}: {msg} ({fpath})\n"

        coverage_block = f"\n\n{self._coverage}\n" if self._coverage else ""

        user_content = (
            f"Concern cluster: {packet['concern']}\n"
            f"Architectural tier: {packet['tier']}\n"
            f"Files: {packet['file_count']}\n"
            f"Estimated tokens: {packet['total_tokens']}\n"
            f"{findings_block}"
            f"{coverage_block}\n"
            f"Source code:\n{source_block}"
        )

        return self._call_api(user_content)

    def _call_api(self, user_content: str) -> str:
        if self._is_anthropic:
            url = f"{self._endpoint}/v1/messages"
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
                    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
                ],
                "messages": [{"role": "user", "content": user_content}],
            }
        else:
            url = f"{self._endpoint}/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
            }
            payload = {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
            }

        result = _post_with_retry(
            client=self._client,
            url=url,
            payload=payload,
            headers=headers,
            is_anthropic=self._is_anthropic,
            timeout=self._timeout,
        )
        if result or self._is_anthropic:
            return result

        for fallback in self.FREE_FALLBACKS:
            if fallback == self._model:
                continue
            logger.info("concern_review.fallback", model=fallback)
            payload["model"] = fallback
            result = _post_with_retry(
                client=self._client,
                url=url,
                payload=payload,
                headers=headers,
                is_anthropic=False,
                timeout=self._timeout,
            )
            if result:
                return result

        return ""

    def close(self) -> None:
        self._client.close()


def _review_one(
    reviewer: HolisticReviewer,
    cluster: ConcernCluster,
    repo_path: Path,
) -> ConcernVerdict:
    """Review a single concern cluster. Returns verdict (never raises)."""
    packet = build_packet(cluster, repo_path)
    logger.info(
        "concern_review.reviewing",
        concern=cluster.name,
        files=len(cluster.files),
        tokens=cluster.total_tokens,
        findings=len(cluster.findings),
    )
    review_text = reviewer.review_concern(packet)
    if not review_text:
        return ConcernVerdict(
            concern=cluster.name,
            tier=cluster.tier,
            file_count=len(cluster.files),
            dom_finding_count=len(cluster.findings),
            review_text="",
            error="LLM returned empty response",
        )
    return ConcernVerdict(
        concern=cluster.name,
        tier=cluster.tier,
        file_count=len(cluster.files),
        dom_finding_count=len(cluster.findings),
        review_text=review_text,
    )


def run_audit(
    repo_path: Path,
    results: list[PluginResult],
    files: list[str],
    model: str = "claude-haiku-4-5-20251001",
    api_key: str | None = None,
    endpoint: str = "https://api.anthropic.com",
    timeout: int = 120,
    max_tokens_per_cluster: int = 12_000,
    max_workers: int = 4,
) -> AuditReport:
    """Run a concern-by-concern holistic audit: canary first, then parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    clusters = cluster_files(repo_path, files, max_tokens_per_cluster)
    attach_findings(clusters, results, repo_path)

    if not clusters:
        return AuditReport(
            repo_path=str(repo_path), concern_count=0, total_files=len(files), verdicts=[]
        )

    manifest = build_coverage_manifest(repo_path)
    reviewer = HolisticReviewer(
        model=model,
        api_key=api_key,
        endpoint=endpoint,
        timeout=timeout,
        coverage_manifest=manifest,
    )

    canary = clusters[0]
    logger.info("concern_review.canary", concern=canary.name)
    canary_verdict = _review_one(reviewer, canary, repo_path)

    if canary_verdict.error:
        logger.warning("concern_review.canary_failed", concern=canary.name)
        skipped = [
            ConcernVerdict(
                concern=c.name,
                tier=c.tier,
                file_count=len(c.files),
                dom_finding_count=len(c.findings),
                review_text="",
                error="Skipped — canary failed",
            )
            for c in clusters[1:]
        ]
        return AuditReport(
            repo_path=str(repo_path),
            concern_count=len(clusters),
            total_files=len(files),
            verdicts=[canary_verdict, *skipped],
            errors=[f"Canary failed for: {canary.name}"],
        )

    remaining = clusters[1:]
    verdicts: list[ConcernVerdict] = [canary_verdict]

    if remaining:
        logger.info("concern_review.parallel_fanout", count=len(remaining))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_review_one, reviewer, c, repo_path): c.name for c in remaining}
            for future in as_completed(futures):
                verdicts.append(future.result())

    errors = [f"Empty response for concern: {v.concern}" for v in verdicts if v.error]

    return AuditReport(
        repo_path=str(repo_path),
        concern_count=len(clusters),
        total_files=len(files),
        verdicts=verdicts,
        errors=errors,
    )
