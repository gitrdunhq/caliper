"""Core data models for the caliper.
# tested-by: tests/unit/test_models.py

All domain objects are Pydantic models with strict enum validation,
auto-generated UUIDs, and JSON round-trip support via orjson.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

import orjson
from pydantic import BaseModel, ConfigDict, Field


def _orjson_dumps(v: object, *, default: object = None) -> str:
    """Serialize to JSON string using orjson for performance."""
    return orjson.dumps(v, default=default).decode()


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OperatingMode(enum.StrEnum):
    """System operating mode — monitor (log only) or advise (PR comment + build unstable)."""

    monitor = "monitor"
    advise = "advise"


class ScanResultStatus(enum.StrEnum):
    """Outcome status of a single scanner invocation."""

    success = "success"
    failed = "failed"
    timeout = "timeout"
    skipped = "skipped"


class DecisionVerdict(enum.StrEnum):
    """Final review decision for a package request."""

    approve = "approve"
    reject = "reject"
    needs_review = "needs_review"
    approve_with_constraints = "approve_with_constraints"


class FindingSeverity(enum.StrEnum):
    """Severity classification for a finding."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


_SEVERITY_ALIASES: dict[str, str] = {
    "error": "critical",
    "ERROR": "critical",
    "warning": "medium",
    "WARNING": "medium",
    "note": "info",
    "NOTE": "info",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "moderate": "medium",
    "MODERATE": "medium",
}


def normalize_severity(raw: str) -> FindingSeverity:
    """Convert any upstream severity string to a FindingSeverity enum value."""
    normalized = _SEVERITY_ALIASES.get(raw, raw.lower())
    try:
        return FindingSeverity(normalized)
    except ValueError:
        return FindingSeverity.info


class FindingCategory(enum.StrEnum):
    """Category of a scanner finding."""

    vulnerability = "vulnerability"
    license = "license"
    copyright = "copyright"
    malicious = "malicious"
    malware = "malware"
    age = "age"
    transitive_count = "transitive_count"
    behavioral = "behavioral"
    code_smell = "code_smell"
    security = "security"
    supply_chain = "supply_chain"


class RequestType(enum.StrEnum):
    """Type of review request."""

    new_package = "new_package"
    upgrade = "upgrade"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

_MODEL_CONFIG = ConfigDict(
    populate_by_name=True,
    use_enum_values=False,
)


class Finding(BaseModel):
    """A single finding from a scanner or analysis tool."""

    model_config = _MODEL_CONFIG

    severity: FindingSeverity
    category: FindingCategory
    description: str
    source_tool: str
    package_name: str
    version: str
    advisory_id: str | None = None
    advisory_url: str | None = None
    license_id: str | None = None
    confidence: float | None = None


class ScanResult(BaseModel):
    """Result of a single scanner invocation."""

    model_config = _MODEL_CONFIG

    tool_name: str
    status: ScanResultStatus
    findings: list[Finding] = Field(default_factory=list)
    raw_output_path: str | None = None
    message: str | None = None
    duration_seconds: float

    @classmethod
    def timeout(cls, tool_name: str, timeout_seconds: int) -> ScanResult:
        """Build a ScanResult for a scanner that exceeded its timeout."""
        return cls(
            tool_name=tool_name,
            status=ScanResultStatus.timeout,
            findings=[],
            message=f"{tool_name} timeout after {timeout_seconds}s",
            duration_seconds=float(timeout_seconds),
        )

    @classmethod
    def failed(cls, tool_name: str, message: str) -> ScanResult:
        """Build a ScanResult for a scanner that failed."""
        return cls(
            tool_name=tool_name,
            status=ScanResultStatus.failed,
            findings=[],
            message=message,
            duration_seconds=0,
        )

    @classmethod
    def not_installed(cls, tool_name: str) -> ScanResult:
        """Build a ScanResult for a scanner whose binary is not found."""
        return cls(
            tool_name=tool_name,
            status=ScanResultStatus.failed,
            findings=[],
            message=f"{tool_name} is not installed. Please install it and ensure it is on PATH.",
            duration_seconds=0,
        )

    @classmethod
    def skipped(cls, tool_name: str, message: str) -> ScanResult:
        """Build a ScanResult for a scanner that was skipped (e.g. combined timeout)."""
        return cls(
            tool_name=tool_name,
            status=ScanResultStatus.skipped,
            findings=[],
            message=message,
            duration_seconds=0,
        )


class ReviewRequest(BaseModel):
    """Inbound request to evaluate a dependency change."""

    model_config = _MODEL_CONFIG

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_type: RequestType
    ecosystem: str
    package_name: str
    target_version: str
    current_version: str | None = None
    team: str
    scope: str = "runtime"
    pr_url: str | None = None
    pr_number: int | None = None
    repo_name: str | None = None
    commit_sha: str | None = None
    use_case: str | None = None
    operating_mode: OperatingMode
    created_at: datetime = Field(default_factory=_utcnow)


class PolicyEvaluation(BaseModel):
    """Result of OPA policy evaluation."""

    model_config = _MODEL_CONFIG

    decision: DecisionVerdict
    triggered_rules: list[str]
    constraints: list[str] = Field(default_factory=list)
    policy_bundle_version: str
    note: str | None = None


def _compute_should_comment(operating_mode: OperatingMode, verdict: DecisionVerdict) -> bool:
    """Determine whether the system should post a PR comment.

    - monitor mode: never comment (log only)
    - advise mode: comment on reject, needs_review, approve_with_constraints
    """
    if operating_mode == OperatingMode.monitor:
        return False
    return verdict in (
        DecisionVerdict.reject,
        DecisionVerdict.needs_review,
        DecisionVerdict.approve_with_constraints,
    )


def _compute_should_mark_unstable(operating_mode: OperatingMode, verdict: DecisionVerdict) -> bool:
    """Determine whether the build should be marked unstable.

    - monitor mode: never mark unstable
    - advise mode: mark unstable on reject and needs_review (not approve_with_constraints)
    """
    if operating_mode == OperatingMode.monitor:
        return False
    return verdict in (DecisionVerdict.reject, DecisionVerdict.needs_review)


class ReviewDecision(BaseModel):
    """Aggregate root — the complete review decision for a package request."""

    model_config = _MODEL_CONFIG

    decision_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request: ReviewRequest
    decision: DecisionVerdict
    findings: list[Finding]
    scan_results: list[ScanResult]
    policy_evaluation: PolicyEvaluation
    evidence_bundle_path: str | None = None
    memo_text: str | None = None
    should_comment: bool = False
    should_mark_unstable: bool = False
    pipeline_duration_seconds: float
    created_at: datetime = Field(default_factory=_utcnow)

    def model_post_init(self, __context: object) -> None:
        """Compute should_comment and should_mark_unstable from operating mode and verdict."""
        mode = self.request.operating_mode
        verdict = self.decision
        object.__setattr__(self, "should_comment", _compute_should_comment(mode, verdict))
        object.__setattr__(
            self, "should_mark_unstable", _compute_should_mark_unstable(mode, verdict)
        )


class BypassRecord(BaseModel):
    """Record of a manual bypass of the review decision."""

    model_config = _MODEL_CONFIG

    bypass_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_id: uuid.UUID
    bypass_type: str
    invoked_by: str
    reason: str
    timestamp: datetime = Field(default_factory=_utcnow)
