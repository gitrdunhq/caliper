# Current State

**Last updated:** 2026-09-04
**Epic:** #482 (parting epic), issue #524 ("part: PR flow — stacked push, re-cut on moved head, foreman comment mode")

---

## What shipped

- #524 bullet 2 — re-run on a moved-head `--pr`: durable overrides reused, cut re-run, diff since last cut shown (added/removed/moved files, part-count drift, head-sha vs. config-only-change labeling). Merged in PR #552.
- #524 bullet 3 — foreman/CI advisory comment mode: `--post-comment` posts the proposed cut as a restack-free advisory PR comment via `PullRequestPublisherPort`/`GitHubPublisher`. Requires `--pr`, incompatible with `--serve`. Merged in PR #555.
- Unrelated but adjacent: fixed a real bug in `SemgrepPlugin._resolve_org_rules_dir` — a relative `opa_policy_path` broke opengrep the moment `--repo-path` pointed at a different repo than the process cwd. Merged in PR #554.

## Active work

- #524 bullet 1 — stacked PR push. Design decided (see SPEC.md): open N new sequential-stack PRs (never force-push the original), original PR left untouched with a linking comment, push to the same remote as the original PR assuming existing write access. Not yet implemented — SPEC.md just authored, about to run through datum-plan decomposition.

## Known issues

- None outstanding from bullets 2/3 — both merged clean, full affected suite green at merge time.

## Architecture notes

- `PullRequestPublisherPort` (`core/ports.py`) currently exposes `post_comment`, `post_review`, `add_label` only — no PR-creation capability exists anywhere in the codebase. Bullet 1 is the first caller that needs it (SPEC.md R1).
- `caliper part`'s two execution backends (git-native vs. jj, `core/part_gate.detect_backend`, #520) already know how to materialize a part's files onto a branch for `restack.sh` — bullet 1 should reuse that rather than invent a third path (SPEC.md R3 AC2, flagged as an unverified assumption in SPEC.md's Assumption Audit).
- Established pattern for every `part` sub-feature so far: pure logic first (e.g. `core/parting.diff_cutlists`, `cli/part_comment.render_part_comment`), then a thin imperative-shell wrapper, then a CLI flag with explicit `UsageError` guards against unsafe flag combinations (`--serve` incompatibility, `--pr`-required). Bullet 1 should follow the same shape (SPEC.md R2/R3/R4).
- Strict TDD throughout this epic: RED test confirmed failing in-container (`bash scripts/test-run.sh --`) before every GREEN implementation, full affected suite (`--affected`) before merge, one PR per logical unit (never squashed unrelated fixes into a feature commit — see #554 vs #555 being split from what was originally one working tree).
