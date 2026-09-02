"""ADR status and path-reference guard (epic-next-10 R6 AC2/AC3).
# tested-by: tests/unit/test_adr_status.py

Every ``docs/adr/*.md`` must carry a ``## Status`` of Accepted, Superseded or
Proposed, and an Accepted ADR must not point at a ``src/caliper/`` path that no
longer exists — a decision that cites dead code is a decision nobody can check.
The four per-ADR tests pin the ADRs this epic added for current practice.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_ADR_DIR = _ROOT / "docs" / "adr"
_VALID_STATUSES = {"Accepted", "Superseded", "Proposed"}
_STATUS_RE = re.compile(r"^## Status\s*\n+(?P<value>[^\n]+)", re.MULTILINE)
_SRC_PATH_RE = re.compile(r"`(src/caliper/[^`\s]+)`")


def _adr_files() -> list[Path]:
    return sorted(p for p in _ADR_DIR.glob("*.md") if not p.name.startswith("000-"))


def _status_of(path: Path) -> str | None:
    match = _STATUS_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        return None
    # "Superseded (2026-09-01) — see ..." keeps the leading word as the value.
    return match.group("value").strip().split()[0].rstrip(".,;:")


def _assert_new_adr(filename: str, marker: str) -> None:
    path = _ADR_DIR / filename
    assert path.is_file(), f"missing ADR: docs/adr/{filename}"
    assert _status_of(path) == "Accepted", f"docs/adr/{filename}: status must be Accepted"
    body = path.read_text(encoding="utf-8")
    number = filename.split("-", 1)[0]
    assert body.startswith(f"# ADR-{number}: "), f"docs/adr/{filename}: house-format title"
    for heading in ("## Status", "## Context", "## Decision", "## Consequences"):
        assert heading in body, f"docs/adr/{filename}: missing {heading}"
    assert marker in body, f"docs/adr/{filename}: does not mention {marker!r}"


def test_adr_011_semgrep_rules_pinned_snapshot_is_accepted() -> None:
    _assert_new_adr("011-semgrep-rules-pinned-snapshot.md", "local snapshot")


def test_adr_012_test_code_excluded_by_default_is_accepted() -> None:
    _assert_new_adr("012-test-code-excluded-by-default.md", "include-tests")


def test_adr_013_single_severity_vocabulary_is_accepted() -> None:
    _assert_new_adr("013-single-severity-vocabulary.md", "ERROR")


def test_adr_014_tag_then_drop_decommissioning_is_accepted() -> None:
    _assert_new_adr("014-tag-then-drop-decommissioning.md", "decommission-log.md")


def test_new_adrs_use_the_next_free_numbers() -> None:
    numbers = sorted(int(p.name.split("-", 1)[0]) for p in _adr_files())
    assert numbers == list(range(1, numbers[-1] + 1)), f"ADR numbering has gaps: {numbers}"
    assert numbers[-1] == 14


def test_every_adr_has_valid_status() -> None:
    offenders = {
        p.name: _status_of(p) for p in _adr_files() if _status_of(p) not in _VALID_STATUSES
    }
    assert (
        not offenders
    ), f"ADRs without a valid '## Status' (Accepted/Superseded/Proposed): {offenders}"


def test_accepted_adrs_reference_existing_paths() -> None:
    offenders: list[str] = []
    for adr in _adr_files():
        if _status_of(adr) != "Accepted":
            continue
        for ref in sorted(set(_SRC_PATH_RE.findall(adr.read_text(encoding="utf-8")))):
            if not (_ROOT / ref).exists():
                offenders.append(f"{adr.name}: {ref}")
    assert not offenders, "Accepted ADRs reference paths missing from src/caliper/:\n" + "\n".join(
        offenders
    )
