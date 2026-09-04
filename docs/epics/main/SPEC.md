# Spec: Stacked PR push for `caliper part --pr`

**Run ID:** <!-- filled by datum -->
**Phase:** Refine
**Status:** Draft

---

## 1. Summary

`caliper part --pr <url> --push` takes an already-computed cut list for a PR
and, gated behind the explicit `--push` flag, pushes each part as its own
branch and opens it as a GitHub PR — a sequential stack, bottom-of-stack-first,
each part's PR based on the previous part's branch. The original PR is left
open and untouched; caliper posts one comment on it linking to the new stack.

## 2. Context

Child issue of #482 (parting epic), issue #524 bullet 1: "`--pr` end-to-end:
after apply, offer to push the stack as a chain of PRs (or one PR with
stacked commits) via `PullRequestPublisherPort`; never pushes without an
explicit flag." Bullets 2 (re-cut-on-moved-head diff, #552) and 3 (foreman
advisory comment mode, #555) are already merged. This is the last bullet, and
the one flagged from the start as needing a real design decision: it requires
capability that doesn't exist anywhere in the codebase today (branch
creation, push, and opening a new PR — not just commenting on an existing
one).

Design decisions already made (see conversation preceding this spec):
- Open N new stacked PRs; do not force-push onto the original PR's branch.
- Sequential stack: part N's PR is based on part N-1's branch (part 1 bases
  on the PR's original base branch). Each PR shows only its own part's diff.
- Original PR is left alone; caliper posts a comment linking to the stack.
- Push target is the same remote as the original PR's head; assume the
  operator's existing `gh`/git auth already has write access there. Fail
  loudly (not silently) if a push is rejected — no fallback fork flow.

## 3. Requirements

### R1: `PullRequestPublisherPort` gains PR-creation capability

**Description:** The port currently exposes `post_comment`, `post_review`,
`add_label` — no way to open a new PR. Add `create_pull_request(repo, head,
base, title, body) -> str | None` (returns the new PR's URL, or `None` on
failure) to the port and to `GitHubPublisher` (`gh pr create`).

**Acceptance criteria:**
- [ ] AC1: `PullRequestPublisherPort` protocol declares `create_pull_request`.
- [ ] AC2: `GitHubPublisher.create_pull_request` shells out to `gh pr create
  --repo <repo> --head <head> --base <base> --title <title> --body <body>`
  and returns the created PR's URL on success, `None` on any failure
  (matching the existing fail-soft-bool convention of the other methods,
  adapted to return the URL instead of a bool since callers need it for
  chaining the next part's base).
- [ ] AC3: `NullPublisher.create_pull_request` returns a deterministic fake
  URL for tests/dry-run contexts, consistent with its other no-op methods.

### R2: Pure branch/commit plan for the stack (functional core)

**Description:** Given a `CutList` (already computed, ordered bottom-of-
stack-first) and the PR's base branch name, compute the ordered list of
`(branch_name, base_branch_name, part)` tuples the imperative shell will
create — pure, no IO. Branch names must be deterministic and collision-safe
(derived from the PR number + part index + bucket, not from wall-clock time
per DEV constraints on `Date.now()`-style nondeterminism carrying over to any
git ref naming here).

**Acceptance criteria:**
- [ ] AC1: A pure function (e.g. `core/part_stack.py:plan_stack`) takes
  `CutList` + PR number + original base branch, returns an ordered list of
  stack entries, part 1's `base_branch_name` == the PR's original base.
- [ ] AC2: Part N's `base_branch_name` == part N-1's `branch_name` for N > 1.
- [ ] AC3: Branch names are unique across the stack and stable across
  re-runs for the same PR + cut list (same inputs -> same names).
- [ ] AC4: Property test: for any valid `CutList` with 1..N parts, the plan
  has exactly `len(cut.parts)` entries and preserves cut order.

### R3: Imperative shell — push and open PRs (part_pr.py or a new module)

**Description:** For each stack entry in order: create the branch off the
prior part's already-pushed branch (or the PR's base for part 1), commit that
part's files (reusing whatever mechanism `restack.sh`/the execution backend
already uses to move files onto a branch — do not duplicate the git-native
vs jj backend split, reuse `core/part_gate.detect_backend` and the existing
apply machinery), push it, then call
`create_pull_request` with title/body derived from the part's bucket +
`part_comment`-style summary (reuse `cli/part_comment.py` conventions,
extended for a single-part body rather than the whole-stack advisory
comment).

**Acceptance criteria:**
- [ ] AC1: A push/PR-open failure on part K stops the stack at K (parts
  1..K-1 remain pushed and opened; K and beyond are not attempted) and
  reports clearly which part failed and why — no silent partial success.
- [ ] AC2: Reuses the existing backend detection (git-native / jj) rather
  than introducing a third code path for moving files onto a branch.
- [ ] AC3: Each opened PR's body links to the original PR and states its
  position in the stack (e.g. "part 2 of 4").

### R4: CLI wiring — `--push` flag

**Description:** New flag on `caliper part`, valid only with `--pr` (same
class of guard as `--post-comment`; also mutually exclusive with `--serve`,
same reasoning — `--serve` returns before any of this code would run).
Never pushes without this explicit flag.

**Acceptance criteria:**
- [ ] AC1: `--push` without `--pr` is a `UsageError`.
- [ ] AC2: `--push` with `--serve` is a `UsageError`.
- [ ] AC3: On success, CLI echoes the list of opened PR URLs in stack order.
- [ ] AC4: On partial failure (R3 AC1), CLI exits non-zero and echoes exactly
  which parts succeeded vs. where it stopped.

### R5: Original PR gets a linking comment

**Description:** After the stack is successfully opened (fully, not
partially — see R3 AC1), post one comment on the original PR (reusing
`post_comment`) listing the stack's PR URLs in order. Do not close or edit
the original PR.

**Acceptance criteria:**
- [ ] AC1: Comment is only posted when the full stack opened successfully.
- [ ] AC2: Comment lists all stack PR URLs in bottom-of-stack-first order.
- [ ] AC3: A failure to post this comment does not roll back the
  already-opened stack PRs (the stack existing is the durable outcome; the
  comment is a courtesy notification) — but it does surface as a CLI warning.

## 4. Failure Modes and Handling

| Failure | Handling |
|---|---|
| Push to part K's branch rejected (no write access, branch exists, etc.) | Stop the stack at K; parts 1..K-1 stay pushed/opened; CLI reports the exact failure and which parts succeeded (R3 AC1, R4 AC4). No automatic rollback of already-opened PRs — that's a second destructive action the operator should take deliberately, not something caliper does silently. |
| `gh pr create` succeeds but returns unparseable output | Treat as failure for that part (fail closed, same as R1 AC2's `None` return), stop the stack there. |
| Linking comment on the original PR fails to post | Non-fatal: stack stays as opened, CLI warns (R5 AC3). |
| Operator has push access to part 1's base but not to push new branches at all | First push fails immediately; zero PRs opened, zero comments posted — clean no-op failure. |
| `--push` invoked on a cut with only 1 part | Stack of length 1: opens exactly one PR based on the original PR's base branch; still posts the linking comment (a stack of one is still a valid, if trivial, stack). |

## 5. Non-Functional Requirements

| Requirement | Target |
|---|---|
| No new destructive default | `--push` must remain fully opt-in; every other `caliper part` invocation (with or without `--pr`) must be unaffected. |
| No duplicate branch-manipulation code path | R3 AC2 — reuse `core/part_gate.detect_backend` + existing apply machinery rather than a third way to move files onto a branch. |
| Deterministic branch naming | R2 AC3 — re-running `--push` against the same PR + cut list must not produce diverging branch names (idempotency for retries after a partial failure). |

## 6. Out of Scope

- Force-pushing or otherwise rewriting the original PR's branch (explicitly rejected design option).
- Auto-closing the original PR (explicitly rejected design option).
- Pushing to a fork other than the original PR's remote (explicitly rejected — "same remote, assume write access" was the chosen option).
- Re-running `--push` to *retry* a partially-failed stack from where it left off (R3 AC1 stops cleanly, but resuming a partial stack is not designed here — a retry currently means a fresh `--push` run, which per R2 AC3 will plan the same branch names and may collide with the parts that already succeeded; that collision-on-retry behavior is explicitly unresolved and out of scope for this spec).
- Any UI/`--serve` sidecar surface for this (`--push` is CLI-only, matching `--post-comment`'s CLI-only scope decision in #555).

## 7. Open Questions

### Q1: Retry semantics after a partial stack failure

R2 AC3 requires deterministic branch names (same inputs -> same names), which is right for normal idempotency. But it directly conflicts with "Out of Scope" item 4: if part 1 and 2 already pushed successfully and part 3 failed, a bare re-run of `--push` will re-plan the same branch name for part 1 and 2 and hit "branch already exists" — is that an acceptable no-op (detect existing branch, skip re-push, resume at 3), or should it hard-fail and require the operator to manually clean up before retrying? This changes R3 AC1's contract (does "stops the stack at K" mean callers must intervene, or is a resume built in?).

## 8. Assumption Audit

| # | Assumption | Justification | Status | Resolves |
|---|---|---|---|---|
| 1 | The operator's existing `gh auth`/git credentials have push access to the original PR's remote for the common case (org-internal PRs) | User-confirmed design decision in the preceding conversation ("Same remote as the original PR (Recommended)") | confirmed | n/a |
| 2 | Sequential (chained) stacking is preferred over parallel PRs against the same base | User-confirmed design decision ("Sequential stack (Recommended)") | confirmed | n/a |
| 3 | The original PR should never be auto-closed or edited beyond one comment | User-confirmed design decision ("Leave it alone, just comment with links (Recommended)") | confirmed | n/a |
| 4 | `core/part_gate.detect_backend` + the existing git-native/jj apply machinery can be reused to materialize a single part's files onto a fresh branch, without duplicating that logic | Inferred from the existing `restack.sh` design (#520's two-backend split); not yet verified against the actual apply code during this planning pass | guess | n/a (verify during Act phase) |
| 5 | A stack of length 1 (single-part cut) is a valid, non-degenerate case worth supporting rather than rejecting with a usage error | Reasonable default consistent with `--post-comment` working on any cut size; not explicitly asked of the user | guess | n/a |

## 9. Classification Metadata

```yaml
estimated_files: 6
estimated_loc: 450
clusters_touched: 3
new_public_api: true
dependency_additions: []
```
