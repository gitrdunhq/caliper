# Decommission Log

Features deliberately removed from caliper, with the archive point that still holds the code. The product thesis is a deterministic CI review gate with zero LLM in the decision path; anything below was cut because it was dead, off-thesis, or both.

**Recovery:** every entry names a git tag. `git show <tag>:<path>` prints a removed file; `git checkout <tag> -- <path>` restores it into the working tree. Tags are local until pushed.

## Archive tag: `archive/pre-cut-tier1`

Points at `17eb7d6` (main as of 2026-09-01, release 0.2.30 plus the pyrefly type-checker commit). Every cut listed under this tag is recoverable from it.

### 1. `caliper audit` and the concern-review LLM fan-out (2026-09-01)

**What it was.** A CLI command that clustered repo files into "concerns", ran the scanners, then fanned each cluster out to an LLM (default: a free OpenRouter model) for a holistic review. A sibling module asked the same LLM for a failing test plus a patch per finding.

**Why it was cut.**

- Contradicted the product thesis: an LLM code reviewer shipped in the binary whose README says "no AI detected a potential issue".
- Sent source to a third-party free model by default.
- Abandoned: docstrings still used pre-rename names ("dom", "Alley-Oop"); the only commits ever touching it were tree-wide mechanical refactors.
- Its two idempotency guard tests pointed at the files' old `core/` paths and had been silently skipping since the move to `data/`.
- The June 2026 LLM-review spec (`docs/llm-review/`) already concluded it was not the base for future work because of its direct-httpx-in-core leak.

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/cli/audit_cmd.py` | 79 |
| `src/caliper/data/concern_review.py` | 494 |
| `src/caliper/data/concern_prompt.py` | 199 |
| `src/caliper/data/concern_remediate.py` | 234 |
| `tests/unit/test_concern_review.py` | 571 |
| `tests/unit/test_concern_remediate.py` | 181 |

**Also cleaned.** The `audit` registration in `cli/main.py`; the `_AUDIT_SUFFIXES` constant in `cli/cli_shared.py`; the `default_llm_model` / `default_llm_endpoint` settings in `core/config.py` (only these modules read them) and their two tests in `test_config.py`; the two always-skipping guard tests in `test_deterministic_idempotency_guards.py`; a docstring in `tests/unit/plugins/test_semgrep_plugin.py` that named the remediation module as its consumer.

**Not touched.** `docs/llm-review/*` and `docs/reviews/*` still reference these modules as historical analysis; they are records, not live docs.

### 2. Issue solver (2026-09-01)

**What it was.** `data/solver.py` read a GitHub issue, built a prompt, and asked an OpenRouter-hosted model (free tier by default in the wrapper script) to generate a detector test, with a model fallback ladder and rate-limit backoff. Its only caller was `scripts/solve-issues.py`.

**Why it was cut.**

- Dev-automation experiment shipped inside the user-facing wheel under the `data` tier; no source, CLI, Action, README, or CAPABILITIES reference.
- Second module found that posts source-derived prompts to a third-party free model endpoint by default.
- Has an LLM write tests, which contradicts the repo's own RED-first TDD rule.
- No feature work after its first day (2026-04-29); only tree-wide sweeps touched it since.

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/data/solver.py` | 559 |
| `scripts/solve-issues.py` | 306 |
| `tests/unit/test_solver.py` | 557 |

**Also cleaned.** Nothing else referenced it.
