"""Core data models for the caliper.
# tested-by: tests/unit/test_models.py

All domain objects are Pydantic models with strict enum validation,
auto-generated UUIDs, and JSON round-trip support via orjson.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Literal

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
    link_type: str = "unknown"
    confidence: float | None = None
    file_path: str | None = None
    line_number: int | None = None
    column: int | None = None


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

    Drives bucketing in ``part()``. Three axes share this one enum:

    * **structural** (from git, never overridable): ``move`` / ``delete`` /
      ``binary``. ``binary`` records (binary, mode-only, or symlink changes)
      have no meaningful size and are never accreted by the cap.
    * **content intent** (non-code, from globs): ``documentation`` /
      ``supply_chain`` / ``ci_cd`` / ``security_policy`` / ``config`` /
      ``schema_contracts`` / ``test`` / ``generated``.
    * **architectural tier** (code, from globs): ``frontend`` / ``business`` /
      ``data`` / ``infra``.

    ``logic`` is the residual: code that matched no tier glob. It is the honest
    "needs a tier" bucket the reclassify loop is meant to drain, not a failure.
    """

    generated = "generated"
    move = "move"
    delete = "delete"
    binary = "binary"
    config = "config"
    test = "test"
    logic = "logic"
    # Content intent (non-code) — new in the two-axis taxonomy.
    documentation = "documentation"
    supply_chain = "supply_chain"
    ci_cd = "ci_cd"
    security_policy = "security_policy"
    schema_contracts = "schema_contracts"
    # Architectural tier (code) — subdivides the old ``logic`` catch-all.
    frontend = "frontend"
    business = "business"
    data = "data"
    infra = "infra"


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
    size_cap: int | None = None  # None => uncapped: one part per labelled bucket
    provenance: Provenance
    stats: CutStats


# ---------------------------------------------------------------------------
# Inspect (caliper inspect) — per-part review models
#
# `caliper part` cuts a stock into parts; `caliper inspect` reviews each part in
# three tiers: Screen (deterministic gauges), Review (advisory LLM claims), and
# Adjudicate (a pure function that filters claims). The LLM never produces a
# verdict; only the deterministic adjudicator's survivors reach a human. Advisory
# and manual: never gates a build, never enters the decision audit lake.
# ---------------------------------------------------------------------------


class Severity(enum.StrEnum):
    """Claim severity. ``blocking`` requires a deterministic Screen witness."""

    blocking = "blocking"
    major = "major"
    minor = "minor"
    nit = "nit"


class Category(enum.StrEnum):
    """Claim category. The admissible set per part is decided by the bucket."""

    correctness = "correctness"
    security = "security"
    behavioral_change = "behavioral-change"
    maintainability = "maintainability"
    performance = "performance"
    style = "style"


class Confidence(enum.StrEnum):
    """Model self-reported confidence in a claim. Display/ranking only — never gates."""

    low = "low"
    medium = "medium"
    high = "high"


# Severity ordering for the floor and dedup rules (higher = more severe).
SEVERITY_RANK: dict[Severity, int] = {
    Severity.nit: 0,
    Severity.minor: 1,
    Severity.major: 2,
    Severity.blocking: 3,
}


class Claim(BaseModel):
    """One structured finding emitted by the LLM (Review). Never a verdict.

    The LLM must emit exactly this structure; freeform prose is rejected by the
    adjudicator's parse rule, not salvaged. ``evidence_ref`` is set deterministically
    by Adjudicate evidence-binding (the model is never asked to know rule ids).

    ``anchor_quote`` is the anti-hallucination keystone: a verbatim copy of the
    flagged source line(s). The anchor rule requires it to be a literal substring of
    the part's changed text before trusting ``line_range``. All three of
    ``anchor_quote``/``confidence``/``reasoning`` are optional so older cached claims
    still parse; ``confidence``/``reasoning`` are advisory (display + flywheel), never
    gating, and never part of the dedup identity.
    """

    model_config = _MODEL_CONFIG

    file: str
    line_range: tuple[int, int]
    severity: Severity
    category: Category
    assertion: str
    anchor_quote: str = ""  # verbatim source the claim flags; checked by the anchor rule
    confidence: Confidence | None = None  # model self-report; display/ranking only
    reasoning: str = ""  # why; captured for audit + flywheel, never gates
    suggested_fix: str | None = None
    evidence_ref: str | None = None  # id of a Screen finding, set by binding


class GaugeFinding(BaseModel):
    """A single Screen finding, each with a stable id a claim can bind to."""

    model_config = _MODEL_CONFIG

    id: str
    file: str = ""
    line_range: tuple[int, int] | None = None
    severity: str = "info"
    category: str = ""
    message: str = ""
    source: str = ""  # the gauge/analyzer that produced it


class GaugeResult(BaseModel):
    """The verdict of one Screen gauge over a part's file set."""

    model_config = _MODEL_CONFIG

    gauge: str
    verdict: Literal["pass", "fail"]
    findings: list[GaugeFinding] = Field(default_factory=list)


class DroppedClaim(BaseModel):
    """A claim removed by the adjudicator, logged with the rule that killed it."""

    model_config = _MODEL_CONFIG

    claim: dict  # the raw claim as received (may be malformed)
    # firing rule that killed/changed it:
    rule: str  # "parse"|"scope"|"anchor"|"substantiation"|"category"|"floor"|"collapse"|"dedup"
    reason: str = ""


class InspectionReport(BaseModel):
    """Per-part (or integration) output: Screen verdicts + adjudicated claims."""

    model_config = _MODEL_CONFIG

    part_id: str
    bucket: str = ""
    kind: Literal["part", "integration"] = "part"
    gauges: list[GaugeResult] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)  # adjudicated survivors only
    skipped_llm: bool = False
    dropped: list[DroppedClaim] = Field(default_factory=list)  # logged, not shown by default


# ---------------------------------------------------------------------------
# Gauge (caliper gauge) — the flywheel: recurring advisory claims become gauges
#
# Advisory claims accumulate in the claims ledger; recurring clusters are drafted
# by the LLM into candidate gauges; a deterministic backtest gates them; a human
# promotes survivors into the Screen tool crib. The LLM drafts but never promotes:
# a gauge is active only if a Promotion exists for it. The ledger is advisory data,
# never the decision audit lake.
# ---------------------------------------------------------------------------


class LedgerEntry(BaseModel):
    """One advisory/dropped claim recorded over time, with a content reference so
    the triggering code can be located later."""

    model_config = _MODEL_CONFIG

    claim: Claim
    repo: str
    sha: str
    content_hash: str  # hash of the triggering part's changed content
    inspected_at: datetime = Field(default_factory=_utcnow)
    author: str = ""  # PR/author proxy (optional; v0 falls back to sha)
    part_id: str = ""


class ClaimCluster(BaseModel):
    """A deterministic cluster of recurring ledger entries (a candidate pattern)."""

    model_config = _MODEL_CONFIG

    key: str  # deterministic, content-derived
    category: Category
    members: list[LedgerEntry]
    distinct_parts: int
    distinct_authors: int
    rank: float  # recurrence x severity, deterministic


class Backtest(BaseModel):
    """The deterministic validation a candidate gauge must pass to be promotable."""

    model_config = _MODEL_CONFIG

    recall: float
    precision: float
    deterministic: bool
    runtime_ms: int
    passed: bool


class CandidateGauge(BaseModel):
    """A drafted deterministic check derived from a cluster. Not yet trusted."""

    model_config = _MODEL_CONFIG

    cluster_key: str
    kind: Literal["semgrep", "ast", "manual"]
    draft: str  # rule text, or a description for a manual-implementation request
    model_version: str
    prompt_version: str
    backtest: Backtest | None = None


class Promotion(BaseModel):
    """The only artifact that activates a gauge — a deliberate human act with lineage."""

    model_config = _MODEL_CONFIG

    candidate: CandidateGauge
    backtest: Backtest
    promoted_by: str
    promoted_at: datetime = Field(default_factory=_utcnow)
