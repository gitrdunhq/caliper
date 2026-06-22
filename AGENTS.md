# AGENTS.md

Rules for AI agents working on the caliper codebase. Read CLAUDE.md first — it has architecture, conventions, and testing rules that apply to all work.

## Agent Execution Model

**Quality over speed. Always.** Do not panic about throughput, do not combine phases to "save time," do not skip steps because a task looks small. A correct codebase built slowly is worth more than a broken one built fast. Every shortcut we take now becomes a bug we debug later.

Opus orchestrates. Sonnet implements. Never use Opus for mechanical code changes.

### Split TDD — Two Agents Per Task

Every implementation task uses two sequential agents to prevent context poisoning:

1. **RED agent** — writes failing tests from acceptance criteria. Commits. Confirms tests fail.
2. **GREEN agent** — reads the failing tests, implements minimum code to pass. Runs full suite. Commits.

The RED agent never sees the implementation. The GREEN agent never writes its own tests. If the same agent writes both, it writes tests that match its planned implementation rather than tests that verify behavior.

**No exceptions.** Not for small tasks. Not for "obvious" implementations. Not to save time. Every task, every time: RED agent → commit → GREEN agent → commit.

### Acceptance Checklist

Every agent prompt MUST include an acceptance checklist. The agent checks off each item and reports results before handing back. Format:

```
## Acceptance Checklist (check off before handing back)
- [ ] item 1
- [ ] item 2
- [ ] all tests pass
- [ ] committed with correct prefix
- [ ] self-reviewed with caliper

Report: "Checklist: X/N" with details on any failures.
```

If the agent can't check off an item, it reports WHY — not a generic "done."

### Self-Review — Agents Eat Their Own Dog Food

Every GREEN agent runs caliper against its own changes before handing back:

```bash
uv run caliper review --repo-path . --all --diff <(git diff HEAD~1)
```

- Fix any critical/high findings on changed files
- Re-run caliper to confirm clean
- Do not hand back with known findings

This is not optional. The agent loops until its changes pass its own tool.

### RED Agent Prompt Template

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

### GREEN Agent Prompt Template

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

## Testing Rules

- **Container only.** Use `make test`. Never `CALIPER_ALLOW_HOST_TESTS=1`.
- **TDD mandatory.** RED before GREEN. No exceptions.
- **Every source file** has `# tested-by: tests/unit/test_X.py`.
- **Regression check** after every change: full unit suite must pass.

## Commit Discipline

- `feat:` — new user-facing capabilities ONLY (triggers minor version bump)
- `fix:` — bug fixes, config fixes, behavior corrections (triggers patch bump)
- `chore:` — refactors, tests, docs, internal changes (no version bump)
- `test:` — test-only commits (RED phase)
- `docs:` — documentation only

Architecture refactoring on `next` branch uses `chore:` — it's internal restructuring, not new features.

## Dogfood Between Phases

After completing each architecture packet, run caliper against itself:

```bash
uv run caliper review --repo-path . --all --format json --output .scratch/dogfood-latest.json
```

Track findings in `DOGFOOD-FINDINGS.md`. Each finding produces a deterministic regression test.

## Branch Rules

- `main` — frozen during architecture refactoring. Release-please manages releases.
- `next` — active architecture work. All packets land here.
- Feature branches off `next` for individual tasks if needed.

## What NOT to Do

- Never write tests and implementation in the same agent
- Never use `CALIPER_ALLOW_HOST_TESTS=1`
- Never use `feat:` for internal refactoring
- Never hand back without running the acceptance checklist
- Never hand back with known caliper findings on changed files
- Never skip the self-review step
