---
name: caliper-plugin-authoring-playbook
description: Step-by-step runbook for adding ONE new scanner plugin (src/caliper/plugins/) or ONE new deterministic detector (src/caliper/detectors/, CAL-NNN) to caliper. Load this when asked to "add a plugin", "write a new detector", "add a CAL rule", "wrap tool X as a caliper scanner", "how do I get my check into caliper review", or — critically — "why isn't my new detector showing up in `caliper review` output" / "my detector registered fine but caliper review doesn't report it" (see the CAL-NNN live-scan wiring gap in the STOP section) — it gives exact copy-pasteable commands, expected output at each gate, the RED/GREEN TDD split, the self-review dogfood step, and a validation script. For how the plugin *system* works internally (registries, depends_on, scribes, dedup) use caliper-plugin-architecture instead — this skill is "how do I add one," that skill is "how does the machine work."
---

# Caliper Plugin & Detector Authoring Playbook

A distinguished-fellow handoff document. Everything below was re-verified
against the repo at commit `c78154b` on branch `arch-review-fixes-and-enhancements`,
repo root `/Volumes/Extra/repos/gitrdunhq/eedom`, on **2026-07-02** — commands
were actually run, outputs below are the real output, not a guess. See
"Provenance & maintenance" at the bottom to re-check after that date.

## When NOT to use this skill

| You want to... | Use instead |
|---|---|
| Understand registries, `depends_on`, scribes, third-party SDK, dedup rules | `caliper-plugin-architecture` |
| Just run the test suite / understand RED-GREEN mechanics in general | `caliper-testing-and-tdd` |
| Understand commit-prefix / change-control rules in depth | `caliper-change-control` |
| Diagnose a scan that already ran but produced a surprising result | `caliper-debugging-playbook` |
| Understand fail-open/timeout philosophy project-wide | `caliper-fail-open-resilience` |
| Write/change an OPA policy rule | `caliper-opa-policy-playbook` |
| Multi-agent adversarial code review of an existing diff | `adversarial-review` |

This skill assumes you already know **which** plugin/detector you're adding
(a GitHub issue, a TASKS.md packet, or a direct ask). It does not help you
decide whether something belongs in caliper at all.

## Decide: plugin or detector?

| | **Plugin** (`src/caliper/plugins/`) | **Detector** (`src/caliper/detectors/`) |
|---|---|---|
| Wraps | An external tool/binary/database (subprocess, PyPI, OSV, license corpus) | Pure Python `ast`/text analysis of source already in the repo |
| Network / subprocess | Yes, typically | No — never |
| Registry | `ANALYZERS` (`src/caliper/plugins/__init__.py`) | `DETECTORS` (`src/caliper/detectors/_registry.py`) |
| ID scheme | free-form hyphenated name (`"typos"`, `"gitleaks"`) | stable `CAL-NNN` |
| Runs today via | `caliper review` (PluginRegistry, 19 plugins as of 2026-07-02) | unit-tested in isolation — **see the wiring-gap warning below before promising this will show up in a live scan** |
| Example | "does this CVE affect this package version" | "this `jwt.encode()` call has no `aud` claim" |

If you're unsure, read `docs/detectors.md` §"Detector vs. plugin" — it's the
canonical two-line distinction and matches the table above.

## STOP — read this before you start a detector

**Verified 2026-07-02, empirically, not from docs:** the 22 `CAL-NNN`
detectors and `DeterministicScanner` (`src/caliper/detectors/scanner.py`) are
fully implemented and unit-tested, but as of this date **they are not wired
into the live `caliper review` CLI path.** This contradicts `docs/detectors.md`
("Detectors and plugin findings flow into the **same** pipeline... the
orchestrator runs it in parallel alongside the plugins") and
`docs/CAPABILITIES.md` line 182 ("exposed to the pipeline").

Proof (reproduce yourself — see Provenance section for the exact repro):

```bash
uv run caliper review --repo-path .temp/verify --scanners deterministic
```

On a file containing a textbook `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
(a CAL-005 SQL-injection pattern), this prints `🟢 ALL CLEAR` with zero
findings — no `deterministic` row ever appears in `caliper plugins` or in a
`caliper review --all` table either. `grep -rln "DeterministicScanner"
src/caliper/` (excluding `__pycache__`) turns up only
`src/caliper/detectors/scanner.py` and `src/caliper/detectors/__init__.py` —
nothing in `core/pipeline.py`, `composition/bootstrap.py`, or any CLI command
imports or constructs it.

**What this means for you:**
- A new detector you add will pass its own unit tests and `detect_safe()` will
  work correctly in isolation — but it will **not** appear in `caliper review`
  output, will **not** affect the OPA verdict, and will **not** show up in
  `make dogfood`'s report, until this wiring gap is closed.
- Do not tell a reviewer/PR author "this will now be caught by caliper" for a
  new detector without first re-running the repro above to confirm the gap is
  still open.
- If you are asked to close this gap (wire `DeterministicScanner` into
  `context.scanners` / `ScanOrchestrator`), that is a different, larger task
  than "add one detector" — treat it as its own RED/GREEN packet, not a side
  effect of adding CAL-023.
- This is exactly the kind of thing worth a `[see-something]` issue if nobody
  has filed one yet — check open issues before filing a duplicate.

Plugins have no such gap: all 19 in-tree plugins run live through `caliper
review` today (verified via `uv run caliper plugins`, 19 rows, and a full
`--all` run, both reproduced below).

---

# Part A — Adding a scanner plugin

## Phase 0 — confirm the shape before writing code

1. Read `docs/PLUGIN_SDK.md` end to end (122 lines) — the authoritative
   contract third-party authors read too.
2. Read one existing plugin **fully**, not skimmed. `src/caliper/plugins/typos.py`
   (121 lines) is the shortest complete worked example with a subprocess call,
   fail-open error handling, and a custom `render()`. Read it now if you
   haven't.
3. **Ground-truth correction to `docs/plugin-sdk.md`'s Quick Start section**:
   that doc's `HelloPlugin` example (lines 22-46) does **not** include the
   registration step and will silently never load if copied verbatim. Every
   real in-tree plugin ends with:

   ```python
   from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


   @ANALYZERS.register("my-scanner")
   def build_my_scanner_plugin() -> MyScannerPlugin:
       """Register this analyzer with the ANALYZERS registry."""
       return MyScannerPlugin()
   ```

   Verified: `grep -c "ANALYZERS.register(" src/caliper/plugins/*.py` shows
   exactly one match per non-underscore plugin file (20 total 2026-07-02,
   including `_opa.py` and `_parting.py` which are deliberately NOT
   autodiscovered — see `caliper-plugin-architecture` for why). Without this
   decorator, `autodiscover()` still imports your module (no error) but
   `ANALYZERS` never gains your plugin, so it silently never appears in
   `caliper plugins` or `caliper review`. This is the single most common way
   a new plugin "does nothing."

## Phase 1 — RED: write the failing test first

Per `AGENTS.md` §"Split TDD — Two Agents Per Task", this is a **separate
agent turn** from Phase 2 if you're orchestrating agents. If you're a human,
still write the test file first and confirm it fails before writing the
plugin.

Test file convention (verified against `tests/unit/test_*.py`,
2026-07-02): `tests/unit/test_<name>_plugin.py` — dominant pattern (18 of 19
plugin test files match it exactly; the one exception is `semgrep`, tested
under `tests/unit/plugins/test_semgrep_plugin.py`). Use the flat
`tests/unit/` location unless you have a specific reason to nest.

Copy the test structure from `tests/unit/test_typos_plugin.py` (verified
real, all 12 tests passing 2026-07-02 — see Phase 3 for the exact command and
output). Minimum coverage for a subprocess-based plugin:

```python
"""Tests for MyScannerPlugin.
# tested-by: tests/unit/test_my_scanner_plugin.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory
from caliper.plugins.my_scanner import MyScannerPlugin


class TestMyScannerPluginBasics:
    def test_name_and_category(self):
        p = MyScannerPlugin()
        assert p.name == "my-scanner"
        assert p.category == PluginCategory.quality

    def test_can_run_with_files(self):
        assert MyScannerPlugin().can_run(["app.py"], Path(".")) is True

    def test_can_run_empty_files(self):
        assert MyScannerPlugin().can_run([], Path(".")) is False

    @patch("caliper.plugins.my_scanner.subprocess.run", side_effect=FileNotFoundError)
    def test_binary_not_found_returns_error(self, _mock):
        result = MyScannerPlugin().run(["app.py"], Path("."))
        assert "not installed" in result.error

    @patch("caliper.plugins.my_scanner.subprocess.run")
    def test_timeout_returns_error(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("my-tool", 60)
        result = MyScannerPlugin().run(["app.py"], Path("."))
        assert "timed out" in result.error

    @patch("caliper.plugins.my_scanner.subprocess.run")
    def test_finding_produced(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = '{"file": "app.py", "line": 3, "message": "bad thing"}'
        mock_run.return_value.stderr = ""
        result = MyScannerPlugin().run(["app.py"], Path("."))
        assert len(result.findings) == 1
        assert result.findings[0]["file"] == "app.py"
```

Confirm the tests fail with `ImportError`/`ModuleNotFoundError` (the module
doesn't exist yet) before moving on — this IS the RED gate.

```bash
bash scripts/build-test.sh -- tests/unit/test_my_scanner_plugin.py -v
```

## Phase 2 — GREEN: implement the plugin

Location: `src/caliper/plugins/<name>.py` — **no leading underscore** (those
are skipped by `autodiscover()`, see `caliper-plugin-architecture` Part 1).

Minimum skeleton (adapt from `docs/PLUGIN_SDK.md`'s example plus the
registration step from Phase 0):

```python
"""my-scanner plugin — <one line: what it wraps and why>.
# tested-by: tests/unit/test_my_scanner_plugin.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin

_TIMEOUT = 60


class MyScannerPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "my-scanner"

    @property
    def description(self) -> str:
        return "One-line summary shown in `caliper plugins`."

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality  # dependency|code|infra|quality|supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            r = subprocess.run(
                ["my-tool", "--json", *files],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                cwd=repo_path,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "my-tool"))
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "my-tool", timeout=_TIMEOUT),
            )

        findings: list[dict] = []
        # ... parse r.stdout into findings ...

        return PluginResult(plugin_name=self.name, findings=findings, summary={"total": len(findings)})


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("my-scanner")
def build_my_scanner_plugin() -> MyScannerPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return MyScannerPlugin()
```

Run the contract linter shipped with this skill before running the real
suite — it catches the two most common mistakes (missing registration,
missing timeout) in under a second, no container needed:

```bash
uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/plugins/my_scanner.py
```

Verified real output on the reference plugin (2026-07-02):

```
=== check_new_scanner: src/caliper/plugins/typos.py (plugin) ===
OK: matching test file exists at tests/unit/test_typos_plugin.py
PASS: no hard-failure contract violations found.
```

And on a deliberately broken fixture (missing `@ANALYZERS.register`, missing
`# tested-by`, `subprocess.run` with no `timeout=`, no `FileNotFoundError`
guard):

```
=== check_new_scanner: src/caliper/plugins/zz_broken_fixture_delete_me.py (plugin) ===
WARN: no matching test file found by naming convention (this is a warning, not a hard failure — RED/GREEN TDD may not have produced it yet, or your name deviates from convention).
FAIL: 4 hard-failure contract violation(s):
  - Missing '@ANALYZERS.register("<name>")' on a zero-arg factory function. ...
  - Missing '# tested-by: tests/unit/test_<name>_plugin.py' annotation ...
  - 1 subprocess.run(...) call(s) with no timeout= kwarg. ...
  - subprocess.run(...) is used but FileNotFoundError is never caught ...
```

## Phase 3 — GREEN gate: run the real suite in the container

```bash
bash scripts/build-test.sh -- tests/unit/test_my_scanner_plugin.py -v
```

Real, reproduced output for the reference plugin (2026-07-02, `podman`,
`caliper-test:arm64`, no rebuild needed if the image already exists):

```
Engine: podman | Image: caliper-test:arm64
Running pytest tests/unit/test_typos_plugin.py -v...
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.0, pluggy-1.6.0 -- /opt/test-venv/bin/python
collecting ... collected 12 items

tests/unit/test_typos_plugin.py::TestTyposPluginBasics::test_name_and_category PASSED [  8%]
tests/unit/test_typos_plugin.py::TestTyposPluginBasics::test_can_run_with_files PASSED [ 16%]
...
tests/unit/test_typos_plugin.py::TestTyposRender::test_render_findings_table PASSED [100%]

============================== 12 passed in 0.50s ===============================
```

Then run the **full** unit suite once (regression check, `AGENTS.md`
requires zero regressions):

```bash
make test
```

## Phase 4 — verify registration end to end

```bash
uv run caliper plugins
```

Your plugin's row must appear, sorted by `(category, name)`. Verified
2026-07-02 baseline (19 rows before your addition — yours makes 20):

```
Name                 Category        Binary       Depends On         Description
-----------------------------------------------------------------------------------------------
cpd                  code            —            —                  Copy-paste detection — token-based duplication (12 languages)
mypy                 code            ok           —                  Cross-file type checking (mypy/pyright)
...
supply-chain         supply_chain    —            —                  Unpinned dependency detection + lockfile integrity + Docker latest-tag detection

19 plugins registered
```

`uv run caliper plugins` is a plain script invocation (imports the package,
walks the registry, prints) — it is **not** a pytest run and has no container
guard, so it's fine to run on the host.

If your plugin does not appear: it's almost always the missing
`@ANALYZERS.register(...)` decorator (Phase 0, point 3) or a filename
starting with `_`.

## Phase 5 — self-review dogfood (mandatory, `AGENTS.md`)

```bash
uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)
```

- Fix any critical/high findings on files you changed.
- Re-run until clean. Do not hand back with known findings on your own diff.
- This is the same command every GREEN agent runs per `AGENTS.md`'s GREEN
  Agent Prompt Template — do not substitute a narrower invocation.

## Phase 6 — quality gate + capability matrix

```bash
make quality-check   # black + ruff, must pass clean
```

Update `docs/CAPABILITIES.md`: `CLAUDE.md` §"Capability Matrix" requires this
on every plugin add — bump the plugin count in the "Quick Numbers" section
and add a row under "Plugins by Category", and update the LAST VERIFIED date
at the top of that file.

## Phase 7 — commit discipline

Per `AGENTS.md` and `CLAUDE.md` §"Commit Message Discipline" — a brand-new
plugin is user-facing new capability, so it's `feat:`:

```
feat(plugins): add my-scanner — <one line, what it catches>
```

If you're following the two-agent split, the RED commit is `test:` and the
GREEN commit is `feat:` (not `chore:` — a new plugin is a new user-facing
capability, unlike most GREEN commits which are `chore:` per the template in
`AGENTS.md`). Use judgment; if in doubt, prefer `caliper-change-control` for
the disambiguation table.

## Fenced-off wrong paths — plugins

| Don't | Why | Do instead |
|---|---|---|
| Skip `try/except FileNotFoundError` / `subprocess.TimeoutExpired` around a subprocess call | Breaks the fail-open guarantee (`CLAUDE.md` "Fail-open: No scanner failure blocks a build") — an unhandled binary-missing or timeout becomes an uncaught exception instead of a typed `PluginResult(error=...)` | Always wrap per the Phase 2 skeleton; use `error_msg(ErrorCode.X, ...)` for consistent messages |
| Call `subprocess.run(...)` with no `timeout=` | No wall-clock bound — one hung external tool can stall a run | Pass `timeout=` (60s is the project convention for scanner subprocesses, per `docs/plugin-sdk.md`) |
| Copy `docs/plugin-sdk.md`'s Quick Start `HelloPlugin` verbatim and expect it to appear in `caliper plugins` | It omits the `@ANALYZERS.register(...)` factory decorator (verified gap, 2026-07-02) | Always end the file with the registration block from Phase 0 point 3 |
| Hand-write your own file-discovery / `rglob` inside a plugin | Bypasses the shared exclusion layer (`.caliperignore`, fixture dirs, `.venv`, etc.) | Consume the `files`/`repo_path` args you're given; if you need a repo-wide walk, use the resolved `FileSourcePort` (see `CLAUDE.md` §"File Enumeration") |
| Add `depends_on=["*"]` "to be safe" | That's the OPA-policy-plugin-only convention and today has zero live consumers (see `caliper-plugin-architecture` "Known fragility points" #1) — using it elsewhere adds unexplained ordering with no payoff | Leave `depends_on` at its default `[]` unless you have a specific, provable ordering need |
| Write the plugin implementation before the test, or write both in one agent turn | Violates `AGENTS.md` mandatory RED/GREEN split — the same agent tends to write tests that match its own planned implementation | RED agent writes failing tests and commits; a separate GREEN agent reads them and implements |
| Skip `make dogfood`/the self-review diff-scan step because "it's a small change" | `AGENTS.md`: "This is not optional. The agent loops until its changes pass its own tool." No size exception exists | Always run Phase 5 before handing back |

---

# Part B — Adding a deterministic detector (CAL-NNN)

Re-read the **STOP** warning above before starting — confirm the wiring gap
is still open (or closed) before promising live-scan visibility.

## Phase 0 — pick the next ID and category

Current range verified 2026-07-02: `CAL-001`..`CAL-022`, all IDs contiguous,
no gaps. **Next available ID is `CAL-023`.** Re-verify before you claim a
number — see Provenance section for the exact command; two people can pick
the same "next" number in parallel.

Pick a subpackage under `src/caliper/detectors/` matching your
`DetectorCategory` (`caliper.detectors.categories.DetectorCategory`):

| `DetectorCategory` | subpackage | existing examples |
|---|---|---|
| `security` | `detectors/security/` | `jwt_audience.py`, `sql_injection.py` |
| `reliability` | `detectors/reliability/` | `cache_eviction.py`, `subprocess_timeout.py` |
| `configuration` | `detectors/config/` | `config_merge.py`, `docker_pin_drift.py` |
| `process` | `detectors/process/` | `tested_by.py` |
| `performance`, `documentation`, `integration` | no subpackage exists yet as of 2026-07-02 (0 detectors) | create one following the same pattern if you're first |

## Phase 1 — RED: write the failing test first

Location convention (verified — every detector test file mirrors this
exactly): `tests/unit/detectors/<category>/test_<module_name>.py`.

Copy the structure of `tests/unit/detectors/security/test_jwt_audience.py`
(verified real, all 5 tests passing 2026-07-02 — command + output in Phase
3). The pattern: write source to a real temp `.py` file via
`tempfile.NamedTemporaryFile`, call `detector.detect(Path(f.name))`, assert
on concrete `DetectorFinding` fields (`detector_id`, `message`,
`line_number`) — never just `assert findings is not None`.

```python
"""Tests <Detector Name> detector.
# tested-by: tests/unit/detectors/security/test_my_detector.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.security.my_detector import MyDetector


class TestMyDetector:
    @pytest.fixture
    def detector(self):
        return MyDetector()

    def test_detects_the_bad_pattern(self, detector):
        code = """
        # ... source that should trigger a finding ...
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-023"
        assert "expected substring" in findings[0].message

    def test_ignores_the_safe_pattern(self, detector):
        code = "# ... source that should NOT trigger ..."
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))
        assert len(findings) == 0
```

Confirm RED:

```bash
bash scripts/build-test.sh -- tests/unit/detectors/security/test_my_detector.py -v
```

## Phase 2 — GREEN: implement the detector

```python
"""MyDetector - <one line: the bug pattern it catches>.
# tested-by: tests/unit/detectors/security/test_my_detector.py

GitHub issues: #NNN
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class MyDetector(BugDetector):
    @property
    def detector_id(self) -> str:
        return "CAL-023"

    @property
    def name(self) -> str:
        return "My Detector Name"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)  # override if you target Dockerfile*/*.yaml/etc.

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        # Use caliper.detectors.ast_utils helpers (parse_file_safe,
        # find_function_calls, get_call_name, has_decorator, ...) — don't
        # hand-roll ast.parse/ast.walk if a shared helper already does it.
        findings: list[DetectorFinding] = []
        # ... analysis ...
        return findings
```

Every source file under `src/caliper/detectors/` needs the `# tested-by:`
line — `CAL-014` (Missing Tested-By Annotation) will flag its own absence,
which is a delightfully self-referential way to find out you skipped it.

Run the contract linter:

```bash
uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/detectors/security/my_detector.py
```

Real output on the reference detector (2026-07-02):

```
=== check_new_scanner: src/caliper/detectors/security/jwt_audience.py (detector) ===
OK: matching test file exists at tests/unit/detectors/security/test_jwt_audience.py
PASS: no hard-failure contract violations found.
```

**Note on `detect()` never-raise**: `BugDetector.detect_safe()` already wraps
your `detect()` in `try/except Exception: return []` (see
`src/caliper/detectors/framework.py`), so a raised exception inside `detect()`
is caught by the framework — but write `detect()` as if it must not raise
anyway (defensive parsing, `parse_file_safe()` which returns `None` on a
parse error rather than raising). Relying on the outer safety net instead of
writing defensively hides bugs as silent empty-result skips.

## Phase 3 — GREEN gate: run the real suite in the container

```bash
bash scripts/build-test.sh -- tests/unit/detectors/security/test_my_detector.py -v
```

Real, reproduced output for the reference detector (2026-07-02):

```
Engine: podman | Image: caliper-test:arm64
Running pytest tests/unit/detectors/security/test_jwt_audience.py -v...
collecting ... collected 5 items

tests/unit/detectors/security/test_jwt_audience.py::TestJWTAudienceDetector::test_detects_missing_aud_in_dict_literal PASSED [ 20%]
tests/unit/detectors/security/test_jwt_audience.py::TestJWTAudienceDetector::test_ignores_when_aud_present PASSED [ 40%]
tests/unit/detectors/security/test_jwt_audience.py::TestJWTAudienceDetector::test_ignores_variable_payload PASSED [ 60%]
tests/unit/detectors/security/test_jwt_audience.py::TestJWTAudienceDetector::test_detects_multiple_violations PASSED [ 80%]
tests/unit/detectors/security/test_jwt_audience.py::TestJWTAudienceDetector::test_returns_line_numbers PASSED [100%]

============================== 5 passed in 0.44s ===============================
```

Then the full suite:

```bash
make test
```

## Phase 4 — verify registration (registry-level, not live-scan)

`discover_detectors()` recursively imports every `caliper.detectors.*`
subpackage so `@register_detector` decorators fire — placing the file under
the right subpackage is enough, no manual wiring step (unlike plugins, there
is no separate factory-decorator line to remember; `@register_detector`
decorates the class directly).

Confirm it's live in the registry:

```bash
bash scripts/build-test.sh -- tests/unit/detectors/test_registry.py -v
```

Given the wiring gap in the STOP warning, **this confirms your detector is
registered and runnable in isolation** — it does not confirm it participates
in `caliper review`. Don't skip the STOP-warning re-check.

## Phase 5-7 — same as plugins

Self-review dogfood (Phase 5), quality gate + `docs/detectors.md` /
`docs/CAPABILITIES.md` update (Phase 6 — both files list every `CAL-NNN` ID
by hand and must be updated together), and commit discipline (Phase 7) are
identical in mechanics to Part A — see those phases above, substituting
`docs/detectors.md`'s table for `docs/CAPABILITIES.md`'s plugin table.

A brand-new detector is also `feat:` (new user-facing capability).

## Fenced-off wrong paths — detectors

| Don't | Why | Do instead |
|---|---|---|
| Reuse an existing `CAL-NNN` id, or guess the next number without checking | Two IDs colliding breaks `# noqa: CAL-NNN` suppression semantics and confuses `docs/detectors.md` | Re-run the grep in Provenance section immediately before picking a number |
| Call `ast.parse`/`ast.walk` directly when a helper in `detectors/ast_utils.py` already does the job | Duplicates logic, misses the shared `ASTCache` (`content-addressed, parse once, reuse across detectors`) performance win | Use `find_function_calls`, `get_call_name`, `has_decorator`, `find_exception_handlers`, `is_secret_field_name`, or `BatchVisitor` from `ast_utils.py` |
| Assume your new detector will show up in `caliper review` output | Verified wiring gap, see STOP warning | Confirm via the repro command before promising this to anyone |
| Forget the `# tested-by:` line | `CAL-014` (Missing Tested-By Annotation) flags its own absence — but only once the wiring gap above is closed; until then nothing enforces it automatically | Add it by hand, verify with the `check_new_scanner.py` script |
| Skip the RED/GREEN split "because it's a small detector" | Same `AGENTS.md` rule as plugins — no size exception | RED agent, commit, confirm fail; GREEN agent, implement, commit |

---

## Validation checklist (both plugins and detectors)

Route every new plugin/detector through this checklist before handing back,
per `AGENTS.md`'s "Acceptance Checklist" format:

```
## Acceptance Checklist (check off before handing back)
- [ ] RED: test file written first, committed, confirmed to fail (ImportError)
- [ ] GREEN: implementation file written, all new tests pass
- [ ] uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py <path> → PASS
- [ ] bash scripts/build-test.sh -- <your test file> -v → all pass
- [ ] make test → full suite, zero regressions
- [ ] uv run caliper plugins (plugins only) → new row present
      OR bash scripts/build-test.sh -- tests/unit/detectors/test_registry.py -v (detectors only) → passes
- [ ] For a new detector: re-ran the STOP-warning repro, confirmed current
      wiring status, and did NOT overclaim live-scan visibility if the gap
      is still open
- [ ] uv run caliper review --repo-path . --all --diff <(git diff HEAD~1) → no unresolved critical/high on changed files
- [ ] make quality-check → black + ruff clean
- [ ] docs/CAPABILITIES.md updated (count + table row + LAST VERIFIED date)
- [ ] docs/detectors.md updated (detectors only — new CAL-NNN row)
- [ ] Committed with correct prefix (feat: for a new plugin/detector)
- [ ] Not pushed

Report: "Checklist: X/N" with details on any unchecked item.
```

If any item can't be checked off, report **why**, not a generic "done" — per
`AGENTS.md`.

## Provenance & maintenance

Everything above was verified against commit `c78154b` on branch
`arch-review-fixes-and-enhancements`, repo root
`/Volumes/Extra/repos/gitrdunhq/eedom`, on 2026-07-02. Re-run these before
trusting a number or claim in this file after that date:

```bash
# Re-count in-tree plugins (excludes underscore modules + __init__.py):
ls src/caliper/plugins/*.py | grep -v '/_' | grep -v __init__ | wc -l

# Re-count detectors and confirm the next free CAL-NNN id:
grep -rhoE "CAL-[0-9]{3}" src/caliper/detectors/*/*.py src/caliper/detectors/*.py 2>/dev/null | sort -u

# Re-confirm every non-underscore plugin file has the registration decorator:
grep -L "@ANALYZERS.register(" $(ls src/caliper/plugins/*.py | grep -v '/_' | grep -v __init__)
# (should print nothing — empty output means every file has it)

# Re-check plugin registration end to end (host-safe, not a pytest run):
uv run caliper plugins

# Re-check the detector-wiring gap is still open (or find out it's closed):
mkdir -p .temp/verify-cal005 && printf 'import sqlite3\ndef f(user_id):\n    c = sqlite3.connect("x").cursor()\n    c.execute(f"SELECT * FROM users WHERE id = {user_id}")\n' > .temp/verify-cal005/sqltest.py
uv run caliper review --repo-path .temp/verify-cal005 --scanners deterministic
rm -rf .temp/verify-cal005
# If this now reports a CAL-005 finding, the wiring gap has been closed —
# update the STOP warning section above.

# Re-run the shipped contract linter against a known-good reference file:
uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/plugins/typos.py
uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/detectors/security/jwt_audience.py

# Re-run the two reference test files for real, current pass counts:
bash scripts/build-test.sh -- tests/unit/test_typos_plugin.py -v
bash scripts/build-test.sh -- tests/unit/detectors/security/test_jwt_audience.py -v

# Re-check CAPABILITIES.md's LAST VERIFIED date and counts agree with the above:
grep -n "LAST VERIFIED\|Quick Numbers" -A 3 docs/CAPABILITIES.md
```

**Tests run in a container only.** `bash scripts/build-test.sh -- <pytest
args>` for a targeted run, `make test` for the full suite. Never
`CALIPER_ALLOW_HOST_TESTS=1` (enforced by `tests/conftest.py`, not a
suggestion — see `caliper-testing-and-tdd`). `uv run caliper plugins` and the
`check_new_scanner.py` script in this skill are plain script invocations, not
pytest runs, and are fine on the host.
