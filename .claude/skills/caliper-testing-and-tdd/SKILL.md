---
name: caliper-testing-and-tdd
description: >-
  How tests actually get written and run on caliper: container-only test
  execution (`make test` vs the `make test-host` escape hatch, and why
  `CALIPER_ALLOW_HOST_TESTS=1` is a last resort not a habit), the mandatory
  `# tested-by: tests/unit/test_X.py` annotation every source file carries,
  the DPS-12 property-based testing domain table (Integrity/Confidentiality/
  Determinism/Uniqueness/Availability/Non-repudiation/Idempotency/Atomicity/
  Monotonicity/Ordering/Isolation/Boundedness/Linearity/Reversibility) and its
  SAFETY/LIVENESS/INVARIANT/PERFORMANCE property types, and the shared
  Hypothesis strategies module (`tests/unit/_strategies.py`) that fuzzes
  caliper's parser boundaries. Load this before writing or running any test,
  before adding a new source file (to write its `# tested-by:` line), before
  writing a `@given`/`TestProperties` Hypothesis test, or when asked "how do I
  run the tests", "why can't I run pytest directly", "what domain does this
  property test map to", or "where do I get a Hypothesis strategy for a path/
  version/URL". Do NOT load this for the RED/GREEN two-agent split protocol,
  commit prefixes, or acceptance-checklist format — see
  `caliper-change-control` for those. Do NOT load this for multi-agent
  Haiku→Sonnet→Opus adversarial code review orchestration — see
  `adversarial-review`.
---

# Caliper Testing & TDD

The mechanics of *running and writing* tests on caliper — as opposed to the
*process* around who writes which test when. If you came here looking for the
RED/GREEN two-agent split, the acceptance-checklist format, or commit-prefix
discipline, that's `caliper-change-control` — this skill assumes that process
and covers only the test-execution and test-authoring mechanics underneath
it.

**Jargon, defined once:**
- **Container-only tests** — the repo's tests refuse to run unless the process
  detects it's inside a Docker/Podman container (or the host escape hatch is
  explicitly set). Enforced by `tests/conftest.py`, not by convention.
- **`# tested-by:`** — a one-line comment near the top of every source file
  naming the test file(s) that exercise it. A grep-able traceability link,
  not a docstring nicety.
- **DPS-12** — the 14-domain property-based testing taxonomy from `CLAUDE.md`
  (`DPS` = the project's "Distilled Principles Steering" numbering). Every
  `hypothesis`-based property test should map to one of these 14 named
  domains plus a formal property type.
- **Hypothesis** — the property-based testing library (`hypothesis==6.155.3`
  in `pyproject.toml`, verified 2026-07-02) used for `@given`-decorated tests
  that fuzz input shapes instead of hand-picking examples.

## When to use this skill vs. a sibling

| You are about to... | Use this skill? | Otherwise use |
|---|---|---|
| Run the test suite, or explain why `pytest` bare fails | Yes | — |
| Add a new source file and need the `# tested-by:` line | Yes | — |
| Write a `@given`/`TestProperties` Hypothesis test and pick a DPS-12 domain | Yes | — |
| Reuse or add a shared fuzz strategy (paths, versions, URLs, garbage text) | Yes | — |
| Decide whether a task needs a RED agent and a GREEN agent | No | `caliper-change-control` |
| Write the RED/GREEN agent prompt templates or acceptance checklist | No | `caliper-change-control` |
| Pick a commit prefix (`feat:`/`fix:`/`chore:`/`test:`) | No | `caliper-change-control` |
| Orchestrate multi-agent Haiku→Sonnet→Opus adversarial review | No | `adversarial-review` |
| Understand tier boundaries (`core/` vs `data/` vs presentation) | No | `caliper-architecture-contract` |

---

## 1. Container-only tests — the one rule with no exceptions

**Always run `make test` from repo root.** Never run `uv run pytest` or bare
`pytest` directly — it will refuse.

```bash
make test
```

This is enforced in code, not just by convention. `tests/conftest.py`
(verified 2026-07-02) runs a `pytest_configure` hook that checks for
container markers and aborts the whole run otherwise:

```python
def pytest_configure(config: object) -> None:
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    bypass = os.environ.get("CALIPER_ALLOW_HOST_TESTS") == "1"
    if not in_container and not bypass:
        raise SystemExit(
            "\n\nERROR: caliper tests must run inside a container.\n"
            "\n"
            "  make test                            # uses podman/docker\n"
            "  podman run --rm -v .:/workspace:ro caliper:latest pytest tests/ -v\n"
            "\n"
            "Set CALIPER_ALLOW_HOST_TESTS=1 to override (not recommended).\n"
        )
```

**Why this exists — say it plainly:** the host machine you're developing on
(your Mac, your laptop, an agent's sandbox) cannot guarantee parity with CI
or with any other contributor's machine. Different OS, different arch
(arm64 vs amd64), different pre-installed tool versions (semgrep, osv-scanner,
opa, etc. — caliper shells out to a lot of external scanners), different
filesystem semantics. A test that passes on your host and fails in CI (or
vice versa) is worse than a test that never ran — it creates false
confidence. The container is the one environment everyone — human, CI, and
every agent — actually shares. Running tests anywhere else is answering a
different question than "does this pass."

### The escape hatch (and why it stays an escape hatch)

`make test-host` exists for genuine emergencies — no container runtime
available, fast local iteration on a test file you already know is
container-clean, etc. It sets the bypass var so `conftest.py` doesn't abort:

```bash
make test-host    # = CALIPER_ALLOW_HOST_TESTS=1 uv run pytest tests/ -v
```

**Never reach for this by default.** `AGENTS.md` lists it explicitly under
"What NOT to Do": *"Never use `CALIPER_ALLOW_HOST_TESTS=1`."* Treat `make
test-host` output as informative-only, never as the basis for "tests pass" in
a handoff, a PR, or a checklist item. If you used it, say so — don't launder
a host run as a container run.

### Commands you'll actually use

```bash
make test                              # full suite, container, native host arch
make test-amd64                        # full suite, container, explicit amd64 (CI parity on arm64 hosts)
bash scripts/build-test.sh -- tests/unit/test_diff.py -v   # one file, container
bash scripts/build-test.sh -- tests/unit/ -x               # stop on first failure, container
make test-host                         # escape hatch — see above, avoid by default
```

`make test` depends on `test-build`, which routes through
`scripts/build-test.sh` (handles the podman-vs-docker security-flag
divergence — see `caliper-build-and-env` for the full build-script story, not
duplicated here).

---

## 2. The `# tested-by:` annotation

Every source file under `src/caliper/` carries a one-line comment naming the
test file(s) that exercise it, near the top of the file (module docstring or
just below the imports):

```python
# tested-by: tests/unit/test_accessors.py
```

Real example, `src/caliper/core/accessors.py` (verified 2026-07-02):

```python
# tested-by: tests/unit/test_accessors.py
"""Dependency accessors — the seam between core and its injected collaborators.
```

A file tested by more than one test file lists them comma-separated. Real
example, `tests/unit/_strategies.py` (the shared strategies module itself
carries the annotation, even though it's a test-support file, not
production code — verified 2026-07-02):

```python
# tested-by: tests/unit/test_diff.py, test_sbom_diff.py, test_ignore.py,
#            test_pr_ref.py, test_manifest_discovery.py
```

**Why:** it's a grep-able traceability link. Given a source file, you can
find its test coverage in one command without a coverage tool running. Given
a bug report against a file, you know which test file to extend. Given a
refactor, you know which tests must still pass.

### Auditing coverage

A ready-made audit script ships with this skill:

```bash
bash .claude/skills/caliper-testing-and-tdd/scripts/check_tested_by_coverage.sh
```

Actual output on this repo, 2026-07-02 (`HEAD` = `c78154b`):

```
=== tested-by coverage: src/caliper ===
Total .py files:      211
Annotated:             192
Missing annotation:    19

--- Files missing '# tested-by:' ---
src/caliper/core/__init__.py
src/caliper/core/actionability.py
src/caliper/core/scribe_pass.py
src/caliper/plugins/_runners/semgrep_runner.py
src/caliper/plugins/_runners/cfn_nag_runner.py
src/caliper/plugins/_runners/__init__.py
src/caliper/plugins/_runners/kube_linter_runner.py
src/caliper/plugins/_runners/graph_builder.py
src/caliper/plugins/_runners/cdk_nag_runner.py
src/caliper/plugins/scribes/__init__.py
src/caliper/__init__.py
src/caliper/cli/query_cmd.py
src/caliper/cli/__init__.py
src/caliper/cli/inspect_cmds.py
src/caliper/composition/__init__.py
src/caliper/templates/__init__.py
src/caliper/detectors/_sample_detectors.py
src/caliper/detectors/scribes/__init__.py
src/caliper/data/__init__.py
```

**Read this honestly, don't oversell it.** Coverage is 192/211 (91%), not
100% — this is an *open* gap, not a solved problem. Most of the misses are
`__init__.py` files (no logic to test, arguably exempt by convention though
nothing enforces that exemption today) and a handful of real files —
`core/actionability.py`, `core/scribe_pass.py`, `cli/query_cmd.py`,
`cli/inspect_cmds.py`, the `plugins/_runners/*.py` shell-out wrappers — that
are missing the annotation and should get one next time they're touched. This
script does **not** fail CI and is not wired into any gate; it's a
self-audit tool. If you want it enforced, that's a deliberate change-control
decision for a human to make, not something to bolt on silently.

---

## 3. RED/GREEN in one paragraph (full protocol lives in `caliper-change-control`)

Every implementation task splits across two sequential agents so the tests
stay an honest check instead of a mirror of the implementation: a **RED
agent** writes only failing tests from acceptance criteria, commits, and
confirms the failure (`ImportError` or assertion failure — the container-only
rule above applies to this run too, use `make test` or the targeted
`scripts/build-test.sh -- <path>` form); a **GREEN agent** then reads those
tests, writes the minimum code to pass them, and runs the **full** suite
(`make test`) to confirm zero regressions before committing. Neither agent
writes the other's half. For the exact prompt templates, the acceptance
checklist format, the self-review/dogfood step, and commit-prefix rules for
the `test:` (RED) and `chore:`/`fix:`/`feat:` (GREEN) commits — load
`caliper-change-control`. This skill only owns the "how do you actually run
these tests" half of that split.

---

## 4. Property-based testing — the DPS-12 domain table

`CLAUDE.md` § "Property-Based Testing (DPS-12)" (verified 2026-07-02): code
at security, cryptographic, state, or trust boundaries requires a formal
property-domain mapping. Every property test states which of the 14 named
domains it covers and which formal property type that domain is:

| Type | Meaning |
|---|---|
| **SAFETY** | a bad thing never happens |
| **LIVENESS** | a good thing eventually happens |
| **INVARIANT** | always true |
| **PERFORMANCE** | stays within bounds |

**Core domains** (security/crypto):

| Domain | Type | Property |
|---|---|---|
| Integrity | SAFETY | Tampering never succeeds |
| Confidentiality | SAFETY | Secrets never leak to output |
| Determinism | INVARIANT | Same inputs → same output |
| Uniqueness | INVARIANT | Different inputs → different outputs |
| Availability | LIVENESS | Valid operations eventually succeed |

**Stateful domains** (state machines, workflows, pipelines):

| Domain | Type | Property |
|---|---|---|
| Non-repudiation | INVARIANT | Proof of action always exists once created |
| Idempotency | INVARIANT | Repeat always produces same result |
| Atomicity | SAFETY | Partial state never visible |
| Monotonicity | SAFETY | State never moves backward |

**System domains** (concurrency, resources, lifecycle):

| Domain | Type | Property |
|---|---|---|
| Ordering | SAFETY | Out-of-sequence never happens |
| Isolation | SAFETY | Parallel ops never interfere |
| Boundedness | PERFORMANCE | Resources stay within finite limits |
| Linearity | SAFETY | Token/resource never consumed twice |
| Reversibility | LIVENESS | Failed operations eventually clean up |

**Not every module needs all 14.** Pick the domains that match the boundary
you're actually testing. Group property tests in a `TestProperties` class
per test file. If you can't state the domain and property type for a test,
the test is incomplete — go back and name it.

As of 2026-07-02, 22 test files under `tests/unit/` carry a `TestProperties`
class (`grep -rl "class TestProperties" tests/unit/ | wc -l`).

### What this looks like in a real file

`tests/unit/test_diff.py` states its domains right in the module docstring
before a single test is written (verified 2026-07-02):

```python
"""Tests for caliper.core.diff — dependency diff detection.

Property domains (DPS-12):
  Determinism   INVARIANT   same requirement/pyproject/package.json line/content
                             always parses to the same result
  (fail-open)   SAFETY      malformed/truncated input never raises — the diff
                             pipeline must degrade to "no dependency change found"
                             rather than crash the whole review
"""
```

...then a `TestProperties` class groups the `@given`-decorated tests that
back those claims:

```python
class TestProperties:
    """Hypothesis coverage for the diff line/content parsing boundary."""

    @given(line=valid_requirement_line())
    @settings(max_examples=200)
    def test_valid_requirement_line_determinism(self, line: str) -> None:
        """Same well-formed requirement line always parses identically."""
        first = _parse_requirement_line(line)
        second = _parse_requirement_line(line)
        assert first == second

    @given(
        line=st.one_of(garbage_text(), malformed_requirement_line(), whitespace_and_control_text())
    )
    @settings(max_examples=300)
    def test_requirement_line_never_raises(self, line: str) -> None:
        """Malformed/garbage requirement-line text never raises — it parses or is None."""
        result = _parse_requirement_line(line)
        assert result is None or isinstance(result, tuple)
```

Note the pattern: one test asserts the **INVARIANT** (determinism) on
*valid* input, a separate test asserts the **SAFETY** property (fail-open,
never raises) on *garbage* input. Don't conflate the two into one test — a
parser can be deterministic on garbage while still raising, or fail-open
while non-deterministic; test each claim separately.

---

## 5. Shared Hypothesis strategies — `tests/unit/_strategies.py`

Commit `2308fb9` (2026-07-01, `chore(tests): add shared Hypothesis
strategies and property coverage for diff/path/manifest parsers`) introduced
`tests/unit/_strategies.py` as the single source of truth for input shapes
fuzzed against caliper's parser boundaries — 323 lines as of that commit,
verified 2026-07-02. **Before hand-rolling a new Hypothesis strategy for a
path, version string, requirement line, PR URL/number, or "garbage text"
shape, check this file first.**

Why a shared module instead of ad-hoc strategies per test file: a single
fix or tuning of e.g. "what does a plausible relative path look like"
propagates to every parser test that uses it, instead of drifting six
different ways across six test files. Strategies are grouped by *shape*, not
by which parser consumes them — several are shared across more than one
parser's test file already.

What's in there today (verified 2026-07-02, read the file for the full set
and docstrings):

| Category | Example strategies |
|---|---|
| Generic malformed/garbage text | `garbage_text()`, `whitespace_and_control_text()` |
| Paths | `path_segment()`, `plausible_relative_path()`, `path_traversal_shaped()` |
| Requirement lines | `valid_requirement_line()`, `malformed_requirement_line()` |

As of 2026-07-02, 6 test files import from `_strategies.py`:
`test_diff.py`, `test_sbom_diff.py`, `test_ignore.py`, `test_pr_ref.py`,
`test_manifest_discovery.py`, and `_strategies.py`'s own doctring lists a
5th consumer set — re-run the grep below, the count drifts as new parser
boundaries get fuzz coverage.

### How to add to it

1. Check `tests/unit/_strategies.py` for an existing strategy of the shape
   you need — grep the docstrings, they're written to be skimmed.
2. If nothing fits, add a new `@st.composite` (or plain `st.text`/`st.one_of`
   builder) function to `_strategies.py`, grouped under the relevant `# ---`
   section header (by shape — paths, requirement lines, garbage text, etc.),
   not under the name of the one parser that happens to need it first.
3. Import it into your test file: `from tests.unit._strategies import
   your_new_strategy`.
4. Write the `@given`/`TestProperties` test per §4 above — state the DPS-12
   domain and property type.
5. Run it container-only per §1: `bash scripts/build-test.sh --
   tests/unit/test_yourfile.py -v`.

---

## Provenance & maintenance

Everything above was verified against the repo at commit `c78154b`
(branch `arch-review-fixes-and-enhancements`), 2026-07-02. Re-run these to
catch drift:

```bash
# Re-check the container-only guard still reads the same env var / paths
grep -n "CALIPER_ALLOW_HOST_TESTS\|dockerenv\|containerenv" tests/conftest.py

# Re-check make test / make test-host targets haven't been renamed
grep -n "^test:\|^test-host:\|^test-amd64:" Makefile

# Re-audit tested-by coverage (the script this skill ships)
bash .claude/skills/caliper-testing-and-tdd/scripts/check_tested_by_coverage.sh

# Re-count TestProperties classes (property-test adoption)
grep -rl "class TestProperties" tests/unit/ | wc -l

# Re-count consumers of the shared Hypothesis strategies module
grep -rl "from tests.unit._strategies import" tests/unit/ | wc -l

# Re-check the DPS-12 table hasn't changed in CLAUDE.md
grep -n "Property-Based Testing (DPS-12)" CLAUDE.md

# Re-check the RED/GREEN protocol text hasn't drifted (owned by caliper-change-control)
grep -n "RED Agent Prompt Template\|GREEN Agent Prompt Template" AGENTS.md

# Re-check hypothesis pinned version
grep -n '"hypothesis==' pyproject.toml
```

**Known open gap (2026-07-02):** 19 of 211 source files under `src/caliper/`
lack a `# tested-by:` annotation (see §2). No automation currently blocks a
commit that adds an unannotated file — this is a convention enforced by
review discipline, not by a CI gate. If that changes, update this section.
