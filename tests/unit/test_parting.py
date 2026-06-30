"""Tests for the pure parting decision — ``core.parting.part()``.

# tested-by: tests/unit/test_parting.py

These construct ``Record`` objects directly (no git, no IO) and exercise the
deterministic ruleset (R1 generated/binary isolation, R2 move/logic separation,
R4 size cap) plus the formal invariants: determinism, idempotence, cap,
purity, completeness, disjointness.

Property domains (DPS-12):
  Determinism   INVARIANT  same stock -> byte-identical cut list
  Idempotency   INVARIANT  re-parting a cut list's records reproduces it
  Boundedness   PERFORMANCE no part exceeds the cap unless flagged oversized
  Isolation     SAFETY     generated/binary/move never mix with other kinds
  Integrity     SAFETY     union of parts == stock exactly; parts disjoint
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.models import ChangeType, CutList, Record
from caliper.core.parting import part
from caliper.core.repo_config import PartingConfig


def _by_bucket(cut: CutList, bucket: ChangeType):
    return [p for p in cut.parts if p.bucket == bucket]


# ---------------------------------------------------------------------------
# Unit fixtures (1-7)
# ---------------------------------------------------------------------------


def test_generated_isolated_from_logic_r1() -> None:
    """1. Lockfile + one logic file -> two parts; lockfile part is generated, kerf R1."""
    records = [
        Record(file="poetry.lock", change_type=ChangeType.generated, size=10),
        Record(file="app.py", change_type=ChangeType.logic, size=20),
    ]
    cut = part(records, PartingConfig(size_cap=400))

    assert len(cut.parts) == 2
    gen = _by_bucket(cut, ChangeType.generated)
    assert len(gen) == 1
    assert gen[0].files == ["poetry.lock"]
    assert gen[0].opened_by.fired_rule == "R1"
    # not mixed: the generated part holds only the lockfile
    assert all("app.py" not in p.files for p in gen)


def test_move_separated_from_logic_and_ordered_below_r2() -> None:
    """2. A pure rename + a logic file -> move is its own part, below logic, kerf R2."""
    records = [
        Record(file="new.py", change_type=ChangeType.move, size=0, old_path="old.py"),
        Record(file="app.py", change_type=ChangeType.logic, size=20),
    ]
    cut = part(records, PartingConfig(size_cap=400))

    move_parts = _by_bucket(cut, ChangeType.move)
    logic_parts = _by_bucket(cut, ChangeType.logic)
    assert len(move_parts) == 1
    assert move_parts[0].files == ["new.py"]
    assert move_parts[0].opened_by.fired_rule == "R2"

    move_idx = cut.parts.index(move_parts[0])
    logic_idx = cut.parts.index(logic_parts[0])
    # "ordered below" == lands first == earlier in the bottom-first cut list
    assert move_idx < logic_idx


def test_size_cap_splits_logic_r4() -> None:
    """3. Six logic files of 100 lines, cap 250 -> deterministic split, kerfs R4."""
    records = [Record(file=f"f{i}.py", change_type=ChangeType.logic, size=100) for i in range(6)]
    cut = part(records, PartingConfig(size_cap=250))

    assert all(p.bucket == ChangeType.logic for p in cut.parts)
    assert all(p.size <= 250 for p in cut.parts)
    # 100+100=200 ok, +100=300>250 -> split into 3 parts of two files each
    assert len(cut.parts) == 3
    assert [p.files for p in cut.parts] == [
        ["f0.py", "f1.py"],
        ["f2.py", "f3.py"],
        ["f4.py", "f5.py"],
    ]
    # the splits are opened by R4
    assert any(p.opened_by.fired_rule == "R4" for p in cut.parts)
    assert cut.parts[1].opened_by.fired_rule == "R4"


def test_ambiguous_rename_becomes_logic_and_is_recorded() -> None:
    """4. A rename with a 300-line content delta -> logic, present in ambiguities."""
    records = [
        Record(file="renamed.py", change_type=ChangeType.move, size=300, old_path="orig.py"),
    ]
    cut = part(records, PartingConfig())  # default move_ambiguity_size=50

    assert len(cut.parts) == 1
    assert cut.parts[0].bucket == ChangeType.logic
    assert "renamed.py" in cut.parts[0].files
    assert [a.file for a in cut.ambiguities] == ["renamed.py"]


def test_delete_bucket_ordered_last() -> None:
    """5. A deletion -> delete bucket, ordered last (flagged for cross-part deletion gap)."""
    records = [
        Record(file="gone.py", change_type=ChangeType.delete, size=5),
        Record(file="app.py", change_type=ChangeType.logic, size=10),
    ]
    cut = part(records, PartingConfig())

    delete_parts = _by_bucket(cut, ChangeType.delete)
    assert len(delete_parts) == 1
    assert delete_parts[0].files == ["gone.py"]
    # the delete bucket is ordered last in the cut list
    assert cut.parts[-1].bucket == ChangeType.delete


def test_binary_isolated_size_none_never_accreted() -> None:
    """6. A binary/mode-only change -> binary bucket, isolated, size 0, never accreted."""
    records = [
        Record(file="logo.png", change_type=ChangeType.binary, size=None),
        Record(file="app.py", change_type=ChangeType.logic, size=10),
    ]
    cut = part(records, PartingConfig())

    binary_parts = _by_bucket(cut, ChangeType.binary)
    assert len(binary_parts) == 1
    assert binary_parts[0].files == ["logo.png"]
    assert binary_parts[0].size == 0  # size undefined -> contributes nothing
    assert binary_parts[0].opened_by.fired_rule == "R1"
    # isolated: binary never mixes with logic
    assert all("app.py" not in p.files for p in binary_parts)


def test_single_oversized_record_flagged() -> None:
    """7. A single 3000-line logic file, cap 400 -> its own part with oversized=True."""
    records = [Record(file="huge.py", change_type=ChangeType.logic, size=3000)]
    cut = part(records, PartingConfig(size_cap=400))

    assert len(cut.parts) == 1
    assert cut.parts[0].oversized is True
    assert cut.parts[0].size == 3000
    assert cut.parts[0].files == ["huge.py"]


def test_oversized_flag_surfaces_in_serialized_output() -> None:
    """7 (honesty): the oversized flag is present in the SERIALIZED cut list, not
    merely on the in-memory object — a green cap test must not hide an oversized part."""
    import json

    records = [Record(file="huge.py", change_type=ChangeType.logic, size=3000)]
    cut = part(records, PartingConfig(size_cap=400))

    data = json.loads(cut.model_dump_json())
    oversized = [p for p in data["parts"] if p["oversized"]]
    assert len(oversized) == 1
    assert oversized[0]["files"] == ["huge.py"]
    # the flag is literally serialized as true
    assert '"oversized":true' in cut.model_dump_json().replace(" ", "")


# ---------------------------------------------------------------------------
# Documentation grouping — one part, cap-exempt, honest oversized flag
# ---------------------------------------------------------------------------


def test_documentation_grouped_into_single_part_over_cap() -> None:
    """Docs are grouped like generated/binary but stay cap-exempt: six 100-line
    docs with cap 250 land in ONE part (not size-split) and the part is flagged
    oversized=True because the group honestly exceeds the cap."""
    records = [
        Record(file=f"docs/d{i}.md", change_type=ChangeType.documentation, size=100)
        for i in range(6)
    ]
    cut = part(records, PartingConfig(size_cap=250))

    doc_parts = _by_bucket(cut, ChangeType.documentation)
    assert len(doc_parts) == 1, "documentation must group into a single part, never size-split"
    assert doc_parts[0].files == [f"docs/d{i}.md" for i in range(6)]
    assert doc_parts[0].size == 600
    assert doc_parts[0].oversized is True, "a docs group over the cap is honestly flagged oversized"


def test_documentation_grouped_under_cap_not_oversized() -> None:
    """A docs group whose total fits the cap is one part and NOT flagged oversized."""
    records = [
        Record(file="README.md", change_type=ChangeType.documentation, size=40),
        Record(file="docs/guide.md", change_type=ChangeType.documentation, size=50),
    ]
    cut = part(records, PartingConfig(size_cap=250))

    doc_parts = _by_bucket(cut, ChangeType.documentation)
    assert len(doc_parts) == 1
    assert doc_parts[0].files == ["README.md", "docs/guide.md"]
    assert doc_parts[0].oversized is False


# ---------------------------------------------------------------------------
# Bucket-order completeness — the load-bearing invariant for the taxonomy
# ---------------------------------------------------------------------------


def test_bucket_order_covers_every_change_type() -> None:
    """Every ChangeType must appear in _BUCKET_ORDER exactly once.

    ``part()`` does ``by_bucket[eff]`` keyed on the effective change type; a
    ChangeType missing from _BUCKET_ORDER is a KeyError at runtime, not a skip.
    """
    from caliper.core.parting import _BUCKET_ORDER

    assert set(_BUCKET_ORDER) == set(ChangeType), (
        "BUCKET_ORDER missing: " f"{set(ChangeType) - set(_BUCKET_ORDER)}"
    )
    assert len(_BUCKET_ORDER) == len(set(_BUCKET_ORDER)), "duplicate bucket in _BUCKET_ORDER"
    assert len(_BUCKET_ORDER) == len(ChangeType)


def test_new_taxonomy_buckets_partition_cleanly() -> None:
    """A stock spanning every new bucket parts without error and covers the stock."""
    records = [
        Record(file="ui/App.tsx", change_type=ChangeType.frontend, size=10),
        Record(file="svc/order.py", change_type=ChangeType.business, size=10),
        Record(file="db/repo.py", change_type=ChangeType.data, size=10),
        Record(file="infra/stack.ts", change_type=ChangeType.infra, size=10),
        Record(file="README.md", change_type=ChangeType.documentation, size=10),
        Record(file="package.json", change_type=ChangeType.supply_chain, size=10),
        Record(file="ci.yml", change_type=ChangeType.ci_cd, size=10),
        Record(file="policy.rego", change_type=ChangeType.security_policy, size=10),
        Record(file="api.proto", change_type=ChangeType.schema_contracts, size=10),
        Record(file="mystery.py", change_type=ChangeType.logic, size=10),
    ]
    cut = part(records, PartingConfig())
    union = sorted(f for p in cut.parts for f in p.files)
    assert union == sorted(r.file for r in records)
    # Buckets are preserved (no over-delta moves here, so effective == declared).
    assert {p.bucket for p in cut.parts} == {r.change_type for r in records}


# ---------------------------------------------------------------------------
# Property tests (8-13)
# ---------------------------------------------------------------------------

# Buckets never subject to the size cap: generated/binary are isolated and
# always oversized=False; documentation is grouped but honestly flagged when the
# group exceeds the cap.
_NON_CAPPED_BUCKETS = {ChangeType.generated, ChangeType.binary}
_GROUPED_CAP_EXEMPT = {ChangeType.documentation}


@st.composite
def _records(draw: st.DrawFn) -> list[Record]:
    files = draw(
        st.lists(
            st.text(alphabet="abcdefghijklmnop", min_size=1, max_size=8),
            min_size=0,
            max_size=12,
            unique=True,
        )
    )
    out: list[Record] = []
    for f in files:
        ct = draw(st.sampled_from(list(ChangeType)))
        size = None if ct == ChangeType.binary else draw(st.integers(min_value=0, max_value=2000))
        old = f + "~old" if ct == ChangeType.move else None
        out.append(Record(file=f, change_type=ct, size=size, old_path=old))
    return out


def _effective(rec: Record, cfg: PartingConfig) -> ChangeType:
    """Mirror part()'s only reclassification: an over-delta move becomes logic."""
    if rec.change_type == ChangeType.move and (rec.size or 0) > cfg.move_ambiguity_size:
        return ChangeType.logic
    return rec.change_type


class TestProperties:
    """Formal invariants the parting decision must hold for all inputs."""

    @given(records=_records())
    @settings(max_examples=200)
    def test_determinism_byte_identical(self, records: list[Record]) -> None:
        """Determinism INVARIANT: same stock -> byte-identical cut list, any order."""
        cfg = PartingConfig()
        a = part(records, cfg).model_dump_json()
        b = part(list(reversed(records)), cfg).model_dump_json()
        c = part(sorted(records, key=lambda r: (r.size or 0, r.file)), cfg).model_dump_json()
        assert a == b == c

    @given(records=_records())
    @settings(max_examples=200)
    def test_idempotence(self, records: list[Record]) -> None:
        """Idempotency INVARIANT: re-parting the cut list's records reproduces it."""
        cfg = PartingConfig()
        cut1 = part(records, cfg)
        by_file = {r.file: r for r in records}
        flattened = [by_file[f] for p in cut1.parts for f in p.files]
        cut2 = part(flattened, cfg)
        assert cut1.model_dump() == cut2.model_dump()

    @given(records=_records(), cap=st.integers(min_value=1, max_value=500))
    @settings(max_examples=200)
    def test_cap_respected(self, records: list[Record], cap: int) -> None:
        """Boundedness PERFORMANCE: no capped part exceeds cap unless flagged oversized."""
        cut = part(records, PartingConfig(size_cap=cap))
        for p in cut.parts:
            if p.bucket in _NON_CAPPED_BUCKETS:
                continue
            if p.bucket in _GROUPED_CAP_EXEMPT:
                # Grouped (never split): a single part may exceed the cap, but
                # only if it is honestly flagged oversized.
                assert p.size <= cap or p.oversized
                continue
            assert p.size <= cap or (p.oversized and len(p.files) == 1)

    @given(records=_records())
    @settings(max_examples=200)
    def test_purity(self, records: list[Record]) -> None:
        """Isolation SAFETY: every file's effective kind matches its part's bucket."""
        cfg = PartingConfig()
        cut = part(records, cfg)
        by_file = {r.file: r for r in records}
        for p in cut.parts:
            for f in p.files:
                assert _effective(by_file[f], cfg) == p.bucket
        assert cut.stats.move_logic_pure is True

    @given(records=_records())
    @settings(max_examples=200)
    def test_completeness(self, records: list[Record]) -> None:
        """Integrity SAFETY: union of part file sets equals the stock file set exactly."""
        cut = part(records, PartingConfig())
        union = sorted(f for p in cut.parts for f in p.files)
        assert union == sorted(r.file for r in records)

    @given(records=_records())
    @settings(max_examples=200)
    def test_disjointness(self, records: list[Record]) -> None:
        """Integrity SAFETY: no file appears in more than one part."""
        cut = part(records, PartingConfig())
        all_files = [f for p in cut.parts for f in p.files]
        assert len(all_files) == len(set(all_files))
