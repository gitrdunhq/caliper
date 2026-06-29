"""Tests for the pure Tier 2 adjudicator — ``core.inspect.adjudicate``.

# tested-by: tests/unit/test_inspect_adjudicator.py

The adjudicator is the deterministic gate between LLM claims and a human: no LLM
output reaches a report except through it. It is a pure function (sibling of
``part()``) — no IO, clock, or randomness — so it is property-tested first.

Property domains (DPS-12):
  Determinism   INVARIANT  same inputs -> identical output
  Integrity     SAFETY     no blocking claim survives without a Tier 0 witness
  Isolation     SAFETY     out-of-scope / unanchored claims never survive
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.inspect import adjudicate, bind_evidence
from caliper.core.models import (
    ChangeType,
    Claim,
    GaugeFinding,
    Kerf,
    Part,
    Severity,
)
from caliper.core.repo_config import InspectConfig

# A logic part with two files and a known changed-line map.
PART = Part(
    id="part-x",
    files=["a.py", "b.py"],
    bucket=ChangeType.logic,
    size=10,
    opened_by=Kerf(fired_rule="bucket-end"),
)
CHANGED = {"a.py": {1, 2, 3, 10, 11}, "b.py": {5, 6}}
CFG = InspectConfig()


def _part(bucket: ChangeType, files=("a.py",)) -> Part:
    return Part(
        id=f"part-{bucket}",
        files=list(files),
        bucket=bucket,
        size=10,
        opened_by=Kerf(fired_rule="bucket-end"),
    )


def _claim(file="a.py", lr=(1, 2), sev="major", cat="correctness", **kw) -> dict:
    base = {
        "file": file,
        "line_range": list(lr),
        "severity": sev,
        "category": cat,
        "assertion": "something is wrong",
    }
    base.update(kw)
    return base


def _finding(fid="f1", file="a.py", lr=(1, 2), cat="correctness") -> GaugeFinding:
    return GaugeFinding(
        id=fid, file=file, line_range=lr, category=cat, severity="high", message="m", source="s"
    )


# ---------------------------------------------------------------------------
# Unit rules
# ---------------------------------------------------------------------------


def test_scope_drops_claims_outside_part_file_set() -> None:
    """Rule 1: a claim on a file not in the part is a context leak and is dropped."""
    res = adjudicate([_claim(file="other.py")], PART, [], CFG, CHANGED)
    assert res.survivors == []
    assert any(d.rule == "scope" for d in res.dropped)


def test_anchor_drops_claims_not_on_a_changed_line() -> None:
    """Rule 2: a claim whose line range hits no changed line is hallucinated."""
    res = adjudicate([_claim(file="a.py", lr=(50, 51))], PART, [], CFG, CHANGED)
    assert res.survivors == []
    assert any(d.rule == "anchor" for d in res.dropped)


def test_unsubstantiated_blocking_is_downgraded_not_deleted() -> None:
    """Rule 3: a blocking claim with no Tier 0 evidence survives as advisory (major)."""
    res = adjudicate([_claim(sev="blocking")], PART, [], CFG, CHANGED)
    assert len(res.survivors) == 1
    assert res.survivors[0].severity == Severity.major  # downgraded, not removed
    assert res.survivors[0].evidence_ref is None


def test_substantiated_blocking_survives_as_blocking() -> None:
    """A blocking claim that binds to a Tier 0 finding keeps blocking severity."""
    tier0 = [_finding(fid="f1", file="a.py", lr=(1, 2), cat="correctness")]
    res = adjudicate([_claim(sev="blocking", lr=(1, 2))], PART, tier0, CFG, CHANGED)
    assert len(res.survivors) == 1
    assert res.survivors[0].severity == Severity.blocking
    assert res.survivors[0].evidence_ref == "f1"


def test_category_allow_list_per_bucket() -> None:
    """Rule 4: generated yields nothing; move admits only behavioral-change."""
    gen = adjudicate([_claim()], _part(ChangeType.generated), [], CFG, CHANGED)
    assert gen.survivors == []

    move_part = _part(ChangeType.move)
    only_behavioral = adjudicate(
        [_claim(cat="behavioral-change"), _claim(cat="correctness")],
        move_part,
        [],
        CFG,
        CHANGED,
    )
    assert [c.category.value for c in only_behavioral.survivors] == ["behavioral-change"]


def test_floor_drops_below_threshold() -> None:
    cfg = InspectConfig(severity_floor={**InspectConfig().severity_floor, "logic": "major"})
    res = adjudicate([_claim(sev="nit"), _claim(sev="major", lr=(10, 10))], PART, [], cfg, CHANGED)
    assert [c.severity for c in res.survivors] == [Severity.major]
    assert any(d.rule == "floor" for d in res.dropped)


def test_dedup_collapses_to_highest_severity() -> None:
    """Rule 6: same {file, line, category} collapses, keeping the highest severity."""
    res = adjudicate(
        [_claim(sev="minor", lr=(1, 1)), _claim(sev="major", lr=(1, 1))],
        PART,
        [],
        CFG,
        CHANGED,
    )
    assert len(res.survivors) == 1
    assert res.survivors[0].severity == Severity.major
    assert any(d.rule == "dedup" for d in res.dropped)


def test_bind_evidence_links_on_file_range_and_category() -> None:
    tier0 = [
        _finding(fid="f2", file="a.py", lr=(100, 200), cat="security"),
        _finding(fid="f1", file="a.py", lr=(1, 3), cat="correctness"),
    ]
    claims = [
        Claim(
            file="a.py",
            line_range=(1, 2),
            severity=Severity.major,
            category="correctness",
            assertion="x",
        )
    ]
    bound = bind_evidence(claims, tier0, CFG)
    assert bound[0].evidence_ref == "f1"  # overlapping range + compatible category


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

_FILES = ["a.py", "b.py", "other.py"]  # other.py is out of the part scope
_SEVS = ["blocking", "major", "minor", "nit"]
_CATS = ["correctness", "security", "behavioral-change", "maintainability", "performance", "style"]


@st.composite
def _raw_claims(draw: st.DrawFn) -> list[dict]:
    out: list[dict] = []
    for _ in range(draw(st.integers(min_value=0, max_value=8))):
        kind = draw(st.integers(min_value=0, max_value=3))
        if kind == 0:  # malformed: missing required fields / wrong types
            out.append(
                draw(st.sampled_from([{}, {"file": "a.py"}, {"severity": "boom"}, {"x": 1}]))
            )
        else:
            lo = draw(st.integers(min_value=1, max_value=60))
            hi = lo + draw(st.integers(min_value=0, max_value=3))
            c = {
                "file": draw(st.sampled_from(_FILES)),
                "line_range": [lo, hi],
                "severity": draw(st.sampled_from(_SEVS)),
                "category": draw(st.sampled_from(_CATS)),
                "assertion": "x",
            }
            if draw(st.booleans()):
                c["evidence_ref"] = draw(st.sampled_from(["f1", "bogus", None]))
            out.append(c)
    return out


@st.composite
def _tier0(draw: st.DrawFn) -> list[GaugeFinding]:
    out = []
    for i in range(draw(st.integers(min_value=0, max_value=3))):
        lo = draw(st.integers(min_value=1, max_value=12))
        out.append(
            GaugeFinding(
                id=f"f{i}",
                file=draw(st.sampled_from(["a.py", "b.py"])),
                line_range=(lo, lo + 2),
                category=draw(st.sampled_from(["correctness", "security", "code_smell"])),
                severity="high",
                message="m",
                source="s",
            )
        )
    return out


class TestProperties:
    @given(claims=_raw_claims(), tier0=_tier0())
    @settings(max_examples=300)
    def test_determinism(self, claims: list[dict], tier0: list[GaugeFinding]) -> None:
        """Determinism INVARIANT: same inputs -> identical output."""
        a = adjudicate(claims, PART, tier0, CFG, CHANGED)
        b = adjudicate(claims, PART, tier0, CFG, CHANGED)
        assert [c.model_dump() for c in a.survivors] == [c.model_dump() for c in b.survivors]
        assert [d.model_dump() for d in a.dropped] == [d.model_dump() for d in b.dropped]

    @given(claims=_raw_claims(), tier0=_tier0())
    @settings(max_examples=500)
    def test_no_unsubstantiated_blocking(
        self, claims: list[dict], tier0: list[GaugeFinding]
    ) -> None:
        """Integrity SAFETY: no surviving blocking claim lacks a Tier 0 witness."""
        res = adjudicate(claims, PART, tier0, CFG, CHANGED)
        for c in res.survivors:
            if c.severity == Severity.blocking:
                assert c.evidence_ref is not None

    @given(claims=_raw_claims(), tier0=_tier0())
    @settings(max_examples=300)
    def test_survivors_well_formed_and_in_scope(
        self, claims: list[dict], tier0: list[GaugeFinding]
    ) -> None:
        """Isolation SAFETY: every survivor is a valid Claim, in scope, on a changed line."""
        res = adjudicate(claims, PART, tier0, CFG, CHANGED)
        for c in res.survivors:
            assert isinstance(c, Claim)
            assert c.file in PART.files
            lo, hi = c.line_range
            assert any(ln in CHANGED[c.file] for ln in range(lo, hi + 1))

    @given(claims=_raw_claims())
    @settings(max_examples=200)
    def test_garbage_in_well_formed_out(self, claims: list[dict]) -> None:
        """Adversarial: hallucinated/out-of-scope/over-severe/malformed claims in,
        well-formed output with no unsubstantiated blocking out."""
        garbage = claims + [
            {"not": "a claim"},
            _claim(file="other.py", sev="blocking"),  # out of scope + over-severe
            _claim(lr=(999, 1000), sev="blocking"),  # hallucinated location
            "totally not even a dict",  # type-0 garbage
        ]
        res = adjudicate(garbage, PART, [], CFG, CHANGED)
        for c in res.survivors:
            assert isinstance(c, Claim)
            assert not (c.severity == Severity.blocking and c.evidence_ref is None)
