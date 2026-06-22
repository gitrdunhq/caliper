---
name: adversarial-review
description: >-
  Run a full multi-agent adversarial code review by fanning out many cheap
  (Haiku) reviewer subagents across a codebase, then a second red-team pass of
  challenger agents that try to refute each finding, then synthesize a
  severity-ranked report. Use when the user asks for an "adversarial review",
  a "full / multi-agent code review", to "fan out review agents", or a deep
  bug/design sweep of a whole codebase or large diff. Parametrize via $ARGUMENTS
  (target, focus, model, output path).
---

# Adversarial Multi-Agent Review

A deterministic orchestration playbook. The value is the **two-pass red-team /
blue-team structure**: a broad fan-out of cheap reviewers (which over-report),
followed by challenger agents that **break the weak findings**, so only
defensible findings reach the report. Cheap models give breadth; the challenge
pass gives precision.

## Parameters (parse from $ARGUMENTS; otherwise ask, or use defaults)

| Param | Default | Meaning |
|-------|---------|---------|
| `target` | the repo / current dir | What to review (a dir, a package, or a diff range like `main..HEAD`). |
| `focus` | `correctness, design` | Any of: `correctness`, `design`, `security`, `tests`. Tell agents to report ONLY these. |
| `model` | `haiku` | Model for reviewer + challenger fan-out. |
| `verify-model` | `none` | If set (e.g. `sonnet`/`opus`), re-verify CONFIRMED high-severity findings with this stronger model before writing the report. |
| `output` | `docs/reviews/adversarial-<YYYY-MM-DD>.json` | Machine-readable report path (tracked). A human `.md` sibling is written alongside it. |
| `commit` | `ask` | `yes` / `no` / `ask` — whether to commit+push the report. |

Scratch lives under `.temp/review/` (must be gitignored). All agent outputs are
**JSON** (`json.loads()`-clean); only the final report is tracked. Every stage's
output is machine-readable so the pipeline can be scripted/validated end-to-end.

## Procedure

### 0. Setup
- `mkdir -p .temp/review/raw .temp/review/verified`.
- Confirm `.temp/` is gitignored (it is the standard eedom scratch mount). If not, use another ignored scratch dir.

### 1. Partition the target
Launch **one `Explore` agent** to map the target into review partitions. Rules:
- Each partition ≲ **2,000 lines** so a small model can read it fully.
- Group by cohesion (a subpackage, a feature, related files), not alphabetically.
- Every source file lands in exactly one partition. Exclude vendored code,
  generated files, and **test fixtures** (`tests/e2e/fixtures/**` in eedom — intentionally-pinned vuln inputs, never findings).
- Produce a numbered list `P01..PNN` each with an explicit file list.

For a diff target, partition only the changed files (+ their direct call sites).

### 2. Stage 1 — adversarial reviewers (parallel, `model`)
Launch **one agent per partition**, batched into single messages for concurrency,
`run_in_background: true`. Build each prompt from
`templates/reviewer-brief.md`, substituting: partition id, file list, the `focus`
set, and the project invariants (for eedom: pull the bullet list from `CLAUDE.md`
— fail-open, `cli→core→data` import direction, enums-not-strings, typed Pydantic
boundaries, config-driven timeouts, highest-severity-wins dedup, OPA `input.pkg`).
Each agent **writes** `.temp/review/raw/partition-NN.json` (one JSON object per the
reviewer-brief schema) and returns only its count.

Wait for every partition file to exist before Stage 2, then validate each parses
(`python -c "import json,glob; [json.load(open(f)) for f in glob.glob('.temp/review/raw/*.json')]"`).
Do NOT read the agents' JSONL transcript files; rely on completion notifications + the `ls`/validate check.

### 3. Stage 2 — challengers / verification (parallel, `model`)
Group the raw partitions into ~5 balanced batches. Launch one challenger agent per
batch from `templates/challenger-brief.md`. Each reads the candidate findings AND
the cited source, and emits a verdict per finding: `CONFIRMED` / `FALSE_POSITIVE`
/ `UNCERTAIN` with a one-line reason. Output `.temp/review/verified/batch-NN.md`.
Challengers are told the reviewers were incentivized to over-report and that their
job is to break weak findings. Findings on excluded fixtures → `FALSE_POSITIVE`.

### 4. Stage 2.5 — optional stronger-model re-verification
If `verify-model` is set: collect every `CONFIRMED` finding with `severity: high`,
and launch ONE agent with `model: verify-model` to independently re-judge just
those (same CONFIRMED/FALSE_POSITIVE/UNCERTAIN verdicts, with reasoning). This
buys Haiku's breadth with a stronger model's judgment on what matters most.

### 5. Stage 3 — synthesize the report (orchestrator)
Join the raw findings (by `id`) with their verdicts. Then:
1. Drop `FALSE_POSITIVE`s; dedup overlapping findings across partitions.
2. Re-normalize severity yourself (small-model high/med/low is noisy).
3. Rank by severity, then subpackage.
4. Write the machine-readable `output` (`.json`) per `schema/report.schema.json`:
   a top-level object with `schema_version`, `generated`, `target`, `focus`,
   `models`, `stats` (`raw`, `confirmed`, `false_positive`, `uncertain`,
   `by_severity`), `findings` (each: `id`, `file`, `line`, `severity`, `category`,
   `claim`, `evidence`, `fix`, `verdict`, `verdict_reason`, `partition`),
   `uncertain`, and `partitions`. Then write a human `.md` sibling rendering the
   same data: Summary, Confirmed findings table + detail, Uncertain/needs-human,
   Methodology, and the raw→confirmed funnel (demonstrates the pass filtered).
5. Validate the JSON parses, then spot-check 3–4 confirmed findings by opening `file:line`.
6. Per `commit`: commit with a `chore:` prefix (review artifact, no behavior change)
   and push `-u origin <current-branch>`. Never include a model identifier string
   in the report or commit message.

## Notes
- Review-only: never modify source/tests; record suggested fixes, don't apply them.
- Strengths: local correctness + design defects, broad cheap coverage. Blind spot:
  cross-file / emergent bugs (partitioning hides them) — flag this in the report.
- Tune fan-out width by repo size: ~1 agent per ≤2k LOC; ~5 challenger batches.
- See `templates/reviewer-brief.md` and `templates/challenger-brief.md` for the
  exact prompts and the canonical finding schema.
