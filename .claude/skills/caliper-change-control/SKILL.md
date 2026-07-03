---
name: caliper-change-control
description: >-
  How every change on caliper gets classified, gated, and reviewed before it
  lands: conventional-commit prefixes for release-please semver (feat/fix/chore
  and why feat: is rationed), the mandatory RED/GREEN two-agent TDD split and why
  it exists (context-poisoning prevention), the acceptance-checklist format every
  agent prompt must carry, and the self-review-before-handoff dogfood step. Load
  this before drafting a commit message, before splitting an implementation task
  across agents, before writing an agent prompt/handoff, or when asked "what
  prefix do I use", "how do I structure a RED/GREEN task", "what goes in an
  acceptance checklist", or "do I need to dogfood this change". Do NOT load this
  for architecture/tier questions (see caliper-architecture-contract), for how to
  actually run the test suite (see caliper-testing-and-tdd), or for multi-agent
  adversarial code review orchestration (see adversarial-review).
---

# Caliper Change Control

Change control on this repo is deliberately boring and mechanical: one commit
prefix taxonomy, one two-agent TDD split, one checklist format, one self-review
step. None of it is optional, and none of it is a suggestion you get to
improve on in the moment. That's the point — it removes judgment calls from
places judgment calls cause bugs.

**Jargon, defined once:**
- **RED agent** — the agent that writes only failing tests, never production code.
- **GREEN agent** — the agent that reads those failing tests and writes only the
  minimum code to pass them, never writing its own tests.
- **Context poisoning** — the failure mode this split prevents: one agent writing
  both tests and implementation ends up writing tests that match what it *planned*
  to build, not tests that verify the *required* behavior. The tests stop being a
  check and become a mirror.
- **Dogfood** — running caliper's own review pipeline against caliper's own diff,
  before handing work back, so the tool catches its own regressions first.
- **semver bump** — the version-number change (`MAJOR.MINOR.PATCH`) that
  release-please computes automatically from commit prefixes in history.

## When to use this skill vs. a sibling

| You are about to... | Use this skill? | Otherwise use |
|---|---|---|
| Write a commit message and aren't sure `feat:` vs `fix:` vs `chore:` | Yes | — |
| Split an implementation task across two agent calls | Yes | — |
| Write an agent handoff prompt and need the checklist format | Yes | — |
| Decide whether to run `make dogfood` before handing back | Yes | — |
| Understand tier boundaries (`core/` vs `data/` vs `presentation`) | No | `caliper-architecture-contract` |
| Actually run tests, understand hypothesis property tests, container test mechanics | No | `caliper-testing-and-tdd` |
| Orchestrate a multi-agent Haiku→Sonnet→Opus adversarial review pass | No | `adversarial-review` |
| Write a new scanner/detector plugin | No | `caliper-plugin-authoring-playbook` / `caliper-plugin-architecture` |

## 1. Conventional-commit discipline (release-please semver)

Source of truth: `CLAUDE.md` § "Commit Message Discipline" and `AGENTS.md` §
"Commit Discipline" (both read 2026-07-02; they agree, AGENTS.md adds two extra
prefixes CLAUDE.md doesn't spell out — see table below).

release-please (`.github/workflows/release-please.yml`, config in
`release-please-config.json`, `release-type: "python"`, package name `caliper`,
`bump-minor-pre-major: true`) walks commit history on `main` and computes the
next version automatically. **The prefix on your commit subject IS the version
decision.** There is no separate "bump the version" step — get the prefix wrong
and you either ship a spurious minor release or silently swallow a bump users
needed to see.

| Prefix | Bump | Use for | Source |
|---|---|---|---|
| `feat:` | **minor** (0.x.0) | New user-facing capabilities ONLY | CLAUDE.md + AGENTS.md |
| `fix:` | **patch** (0.0.x) | Bug fixes, config fixes, CI fixes, behavior corrections | CLAUDE.md + AGENTS.md |
| `chore:` | none | Refactors, docs, test-only changes, housekeeping, dependency updates | CLAUDE.md + AGENTS.md |
| `test:` | none | Test-only commit (the RED half of a RED/GREEN pair) | AGENTS.md only |
| `docs:` | none | Documentation only | AGENTS.md only |

**The explicit warning, verbatim from `CLAUDE.md` (2026-07-02):**

> Do NOT use `feat:` for config tweaks, CI fixes, or internal refactors. If it
> doesn't change what a user sees or does, it's `fix:` or `chore:`.

Rule of thumb when you're unsure: **ask "did a user-facing capability appear
that wasn't there before?"** If no, it isn't `feat:` — full stop, even if the
diff is large or the work was hard. Effort and diff size are not the test;
user-visible capability is the test.

`AGENTS.md` § "Branch Rules" adds one more wrinkle: architecture-refactoring
commits landing on the `next` branch use `chore:` — it's internal
restructuring, not a new feature, even though it's a big lift.

A `Gate` job (`.github/workflows/foreman.yml`, job id `gate-release-please`)
auto-passes branch-protection for `release-please--*` PRs specifically because
those PRs only touch `CHANGELOG.md` and the version file — no code review is
needed on a bot-generated version bump.

### Check a commit message before you write it

```bash
bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh
```

Checks `HEAD`'s subject by default. Pass a ref (`... <sha>`) or a literal
message (`... -m "feat: add X"`) to check before committing. Actual output
observed against this repo on 2026-07-02:

```
$ bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh
Subject: feat: third-party plugin SDK via entry points
OK: prefix 'feat:' recognized.

REMINDER (CLAUDE.md "Commit Message Discipline"):
  feat: triggers a MINOR version bump. Use it ONLY for new user-facing
  capabilities. Config tweaks, CI fixes, and internal refactors are
  fix: or chore: — not feat:. Be conservative.
```

```
$ bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh -m "added a thing"
Subject: added a thing
FAIL: subject does not start with an allowed conventional-commit prefix.
...
exit=1
```

This script is advisory only — it is not wired into CI or a pre-commit hook.
It exists so a human or an agent can self-check before running `git commit`.

## 2. CODEOWNERS

`CODEOWNERS` (repo root) makes `@samfakhreddine` the owner of everything, with
explicit re-statements for a few high-sensitivity paths (so a diff review
never misses them even if the default-owner line is edited later):

```
* @samfakhreddine
src/admission_control/agent/ @samfakhreddine   # ⚠ see note below
policies/ @samfakhreddine
.github/ @samfakhreddine
action.yml @samfakhreddine
.github/agents/ @samfakhreddine
.github/actions-allowlist.yml @samfakhreddine
.github/workflows/workflow-policy.yml @samfakhreddine
tests/unit/test_copilot_agent_profiles.py @samfakhreddine
tests/unit/test_github_actions_policy.py @samfakhreddine
tests/unit/test_dependabot_policy.py @samfakhreddine
tests/unit/test_ruff_policy.py @samfakhreddine
docs/adr/005-github-actions-update-vetting-policy.md @samfakhreddine
```

**Known stale entry (found 2026-07-02, not fixed by this skill — this skill
does not edit files outside itself):** `CODEOWNERS` lists
`src/admission_control/agent/`, but that path does not exist in the repo.
`CLAUDE.md` and the actual filesystem agree the agent module lives at
`src/caliper/agent/` (confirmed with `ls -d src/caliper/agent` — exists).
This looks like a leftover from the eedom→caliper rename. Since everything is
already covered by the `*` default-owner line, this is cosmetic, not a gating
bug — but flag it if you're ever asked to fix CODEOWNERS.

The workflow-policy guardrail paths in CODEOWNERS are enforced by
`.github/workflows/workflow-policy.yml`, which runs
`tests/unit/test_github_actions_policy.py`,
`tests/unit/test_copilot_agent_profiles.py`,
`tests/unit/test_dependabot_policy.py`, and `tests/unit/test_ruff_policy.py`
inside a pinned Python container whenever a PR touches `.github/agents/**`,
`.github/actions-allowlist.yml`, `.github/dependabot.yml`, or
`.github/workflows/**`.

## 3. RED/GREEN — the mandatory two-agent TDD split

Source of truth: `AGENTS.md` § "Agent Execution Model" → "Split TDD — Two
Agents Per Task" (read in full 2026-07-02).

**The rule, verbatim intent:** every implementation task is done by two
*sequential, separate* agent invocations, never one:

1. **RED agent** — writes failing tests from the acceptance criteria only.
   No production code. Commits. Confirms the tests fail.
2. **GREEN agent** — reads the failing tests (never wrote them), implements
   the minimum code to pass them. Runs the full suite. Commits.

**Why this exists (the historical rationale, not just the rule):** if the same
agent writes both the tests and the implementation, it writes tests that
verify its own plan rather than tests that verify the required behavior. A
test suite produced that way passes trivially and proves nothing — it's
"context poisoning": the implementation-shaped thinking leaks backward into
the tests that were supposed to be an independent check on it. Two separate
agent contexts is the enforcement mechanism, not a suggestion — the RED
agent's context never contains an implementation to poison itself with, and
the GREEN agent's context never contains its own test-writing to rationalize
away.

**No exceptions clause, verbatim from `AGENTS.md`:**

> **No exceptions.** Not for small tasks. Not for "obvious" implementations.
> Not to save time. Every task, every time: RED agent → commit → GREEN agent
> → commit.

### RED agent prompt template (from `AGENTS.md`, reproduce verbatim in your handoff)

```
You are the RED agent. You write FAILING tests only. No production code.

## Task: #NNN — [title]
[acceptance criteria from GitHub issue]

## Acceptance Checklist (check off before handing back)
- [ ] Test file created at tests/unit/test_xxx.py
- [ ] Tests import from module that doesn't exist yet
- [ ] All tests FAIL with ImportError (confirmed by running pytest)
- [ ] At least N test cases covering the contract
- [ ] Committed with: `test: [description] (RED for #NNN)`
- [ ] Not pushed

Report: "Checklist: X/6"
```

### GREEN agent prompt template (from `AGENTS.md`, reproduce verbatim in your handoff)

```
You are the GREEN agent. Failing tests exist. Write MINIMUM code to pass them.

## Failing Tests
Read tests/unit/test_xxx.py — all N tests fail with [error].

## Acceptance Checklist (check off before handing back)
- [ ] Production file created
- [ ] All N tests pass
- [ ] Full suite passes with zero regressions
- [ ] Self-reviewed: `uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)`
- [ ] Fixed any critical/high findings on changed files
- [ ] Committed with: `chore: [description] (GREEN for #NNN)`
- [ ] Not pushed

Report: "Checklist: X/7"
```

Note the GREEN commit prefix in the template is `chore:` — the GREEN agent is
making failing tests pass, which is "internal" from a user's perspective
until a human/orchestrator layer decides the whole feature warrants `feat:`
at a higher level. Don't let a GREEN agent decide `feat:` on its own; that
decision belongs to whoever is assembling/squashing the final change (see
§1 above — same conservative-`feat:` rule applies).

Test mechanics (container-only `make test`, hypothesis property tests, the
`# tested-by:` annotation convention) are NOT re-explained here — that's
`caliper-testing-and-tdd`. This skill covers *who writes what, in what order,
and why*, not *how to run pytest*.

## 4. Acceptance checklist — mandatory format for every agent prompt

Source: `AGENTS.md` § "Acceptance Checklist" (read 2026-07-02).

**Every agent prompt, RED or GREEN or anything else, MUST include an
acceptance checklist in this literal format:**

```
## Acceptance Checklist (check off before handing back)
- [ ] item 1
- [ ] item 2
- [ ] all tests pass
- [ ] committed with correct prefix
- [ ] self-reviewed with caliper

Report: "Checklist: X/N" with details on any failures.
```

The reporting contract matters as much as the checklist itself: **if an item
can't be checked off, the agent reports WHY — never a generic "done."** A
report of `"Checklist: 5/7"` with no explanation for the missing two is not
an acceptable handback; the orchestrating agent/human should reject it and
ask for the specific blocker on each unchecked item.

## 5. Self-review before handoff — "eat your own dog food"

Source: `AGENTS.md` § "Self-Review — Agents Eat Their Own Dog Food" (read
2026-07-02) and `CLAUDE.md` § Commands (`make dogfood`).

**Every GREEN agent runs caliper against its own diff before handing back —
not optional, and the agent loops on findings rather than handing back with
known issues:**

```bash
uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)
```

- Fix any critical/high findings on changed files.
- Re-run caliper to confirm clean.
- Do not hand back with known findings.

This is the *per-task* self-review, scoped to the one diff the GREEN agent
just produced. There is a second, *repo-wide* dogfood mechanism that operates
on a longer cadence:

| Mechanism | Scope | When | Command |
|---|---|---|---|
| GREEN-agent self-review | The diff just written (`HEAD~1`) | Every GREEN handoff, no exceptions | `uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)` |
| `make dogfood` | Whole repo, current tree | On demand / before `make preflight` | `bash scripts/dogfood.sh` (via `make dogfood`) |
| `.github/workflows/dogfood.yml` | Whole repo, on `main` | Weekly cron (Monday 9am Edmonton / `0 15 * * 1` UTC) + manual `workflow_dispatch` | CI-only, uploads a SARIF artifact |

`make dogfood` (confirmed in `Makefile`, target at line 86) runs
`bash scripts/dogfood.sh`, which runs `caliper review` twice against the repo
root — once for a human-readable markdown report, once for SARIF — then fails
the run if any `error`-level (critical/high) findings are present, writing
timestamped artifacts to `.caliper/reports/`. `make preflight` chains
`quality-check test dogfood` — dogfooding is the last gate before you'd call
a body of work done, not a first pass.

**If you cross-reference multi-agent adversarial review** (fan-out reviewer
agents, a challenger pass, an adjudicator) — that is a different, heavier
mechanism than the dogfood step above and lives in the sibling skill
`adversarial-review`. Don't conflate the two: dogfooding here is "run our own
scanner on our own diff and don't ship known findings"; adversarial-review is
a full red-team/blue-team multi-model review pipeline with its own evidence
trail under `docs/reviews/`.

## 6. A note on `CONTRIBUTING.md` — partially stale, do not follow blindly

`CONTRIBUTING.md` (repo root, read 2026-07-02) predates several renames and
process changes and disagrees with `AGENTS.md`/`CLAUDE.md` in a few places.
Where they conflict, **`AGENTS.md` and `CLAUDE.md` win** — they are the
current, actively-maintained sources this skill is built from. Specifically:

- `CONTRIBUTING.md` still opens with the old project title ("Dependency
  Review") from before the eedom→caliper rename.
- It describes a `wfc-review` / `wfc-compound` review pipeline with reports
  living in `.wfc/reviews/` — that path/tooling does not match the
  `uv run caliper review` / `make dogfood` / `.caliper/reports/` flow
  described in §5 above and confirmed against `Makefile`/`scripts/dogfood.sh`.
- It says "squash before pushing... one commit per PR, no squash exemptions."
  That is a stricter, different rule than the RED-commit + GREEN-commit
  two-commit pattern `AGENTS.md` mandates in §3 above. Follow `AGENTS.md` —
  it's the newer, more specific instruction for agent-driven work.

Don't cite `CONTRIBUTING.md` as authoritative for anything covered by this
skill without cross-checking it against `AGENTS.md`/`CLAUDE.md` first.

## Quick-reference checklist for a full task

Use this as the top-level sequence; each row is one of the sections above.

- [ ] Confirm the task's user-facing-ness before picking a prefix (§1)
- [ ] RED agent writes failing tests, commits `test: ... (RED for #NNN)` (§3)
- [ ] GREEN agent implements, commits `chore: ... (GREEN for #NNN)` (§3)
- [ ] Both prompts carried a literal `## Acceptance Checklist` block (§4)
- [ ] GREEN agent ran `uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)` and fixed critical/high findings (§5)
- [ ] Final commit prefix reflects user-facing-ness, not effort (§1)
- [ ] `make dogfood` / `make preflight` run before calling the body of work done (§5)

## Provenance & maintenance

Everything above was verified against the live repo on 2026-07-02. Re-verify
with these commands if this skill feels stale:

```bash
# Re-check the two commit-discipline sources still agree
sed -n '/## Commit Message Discipline/,/^## /p' CLAUDE.md
grep -n -A10 '## Commit Discipline' AGENTS.md

# Re-check the RED/GREEN split text hasn't changed
grep -n -A20 '### Split TDD' AGENTS.md

# Re-check CODEOWNERS still has the stale src/admission_control path
grep -n 'admission_control' CODEOWNERS
ls -d src/caliper/agent   # should exist; src/admission_control should not

# Re-check the dogfood mechanism (Makefile target + script)
grep -n -A2 '^dogfood:' Makefile
head -20 scripts/dogfood.sh

# Re-check the Gate auto-pass job for release-please PRs still exists
grep -n -B3 'gate-release-please' .github/workflows/foreman.yml

# Re-check release-please config (package name, pre-1.0 bump behavior)
cat release-please-config.json

# Re-check current version (drifts every release)
grep -n '^version = ' pyproject.toml

# Re-run the commit-prefix checker against HEAD
bash .claude/skills/caliper-change-control/scripts/check-commit-prefix.sh
```

Facts date-stamped 2026-07-02: current version `0.2.27` (`pyproject.toml`),
CODEOWNERS stale-path finding, dogfood weekly cron `0 15 * * 1` UTC
(`.github/workflows/dogfood.yml`), CONTRIBUTING.md staleness assessment.
