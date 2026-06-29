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


# ---------------------------------------------------------------------------
# Parting (caliper part) — diff-cutting models
#
# Vocabulary: a *stock* (the whole diff) is cut into ordered *parts* (reviewable
# slices); a *kerf* is the boundary between two parts tagged with the rule that
# opened it; the ordered manifest of parts is the *cut list*. These models are
# the contract that the pure ``core.parting.part()`` decision consumes and emits.
# Parting is advisory: a CutList is a proposal, never a verdict, and never enters
# the decision audit lake.
# ---------------------------------------------------------------------------


class ChangeType(enum.StrEnum):
    """Classification of a single changed file in the stock.

    Drives bucketing in ``part()``. ``binary`` records (binary, mode-only, or
    symlink changes) have no meaningful size and are never accreted by the cap.
    """

    generated = "generated"
    move = "move"
    delete = "delete"
    binary = "binary"
    config = "config"
    test = "test"
    logic = "logic"


class PartTarget(enum.StrEnum):
    """Substrate handoff shape — affects only the emitted script, never the cut list."""

    stack = "stack"
    series = "series"


class Record(BaseModel):
    """One changed file in the stock — the unit of parting (no hunk-level split in v0).

    ``file`` is the canonical key: for a rename it is the *new* path, so old and
    new paths never double-count and the stock file set is well defined. ``size``
    is added+removed lines, or ``None`` for ``binary`` (size is undefined there).
    """

    model_config = _MODEL_CONFIG

    file: str
    change_type: ChangeType
    size: int | None = None
    old_path: str | None = None


class Kerf(BaseModel):
    """A boundary between two parts, tagged with the rule that opened the next part."""

    model_config = _MODEL_CONFIG

    fired_rule: str  # "R1" | "R2" | "R4" | "bucket-end"
    rationale: str = ""  # v1 scribe fills this deterministically


class Part(BaseModel):
    """One reviewable slice of the stock."""

    model_config = _MODEL_CONFIG

    id: str  # stable, derived from contents (sorted files + bucket)
    files: list[str]  # sorted
    bucket: ChangeType
    size: int
    opened_by: Kerf
    oversized: bool = False  # single record over the cap; cap promise cannot be kept


class Ambiguity(BaseModel):
    """A record the classifier could not place confidently (emitted as ``logic``)."""

    model_config = _MODEL_CONFIG

    file: str
    reason: str


class Provenance(BaseModel):
    """Stamps a cut list so it is independently reproducible.

    ``base_sha``/``head_sha`` and ``resolved_revsets`` come from git at run time
    (the producer/gate fills them); ``rename_threshold`` and ``config_digest`` are
    pure functions of the effective config.
    """

    model_config = _MODEL_CONFIG

    caliper_version: str
    base_sha: str
    head_sha: str
    rename_threshold: int
    config_digest: str
    resolved_revsets: dict[str, str] = Field(default_factory=dict)


class CutStats(BaseModel):
    """Summary statistics over a cut list (deterministic, derived from the parts)."""

    model_config = _MODEL_CONFIG

    part_count: int
    file_count: int
    size_p50: int
    size_p90: int
    move_logic_pure: bool  # no part mixes ``move`` with ``logic``


class CutList(BaseModel):
    """The ordered manifest of parts — bottom of stack first. A proposal, not a verdict."""

    model_config = _MODEL_CONFIG

    parts: list[Part]
    ambiguities: list[Ambiguity] = Field(default_factory=list)
    size_cap: int
    provenance: Provenance
    stats: CutStats
