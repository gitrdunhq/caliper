# ADR-014: Tag-then-drop decommissioning, with the decommission log as the record

## Status

Accepted (2026-09-02)

## Context

By September 2026 caliper carried several features that were dead, off-thesis, or both: an LLM concern-review command, an issue solver that posted source-derived prompts to a free third-party model, a task-fit advisory, an org-wide package catalog, the Foreman Copilot agent, opt-in telemetry, and a handful of scanner plugins nobody ran. Each contradicted the product thesis (a deterministic CI review gate with zero LLM in the decision path) or had no caller. Leaving them in the wheel cost image size, attack surface, and reviewer attention; deleting them outright risked losing work that a future decision might want back and left the ADRs that designed them describing code that no longer existed.

## Decision

A feature is removed in two steps, and the removal is recorded in one place.

1. **Tag first.** Before the cut, the commit that still holds the code is tagged `archive/pre-cut-<name>` (`archive/pre-cut-tier1`, `archive/pre-cut-foreman`, `archive/pre-cut-telemetry`, ...). The tag is the recovery point: `git show <tag>:<path>` prints a removed file and `git checkout <tag> -- <path>` restores it. Tags stay local until deliberately pushed.
2. **Then drop.** The code, its tests, its config settings, its CLI registration, and its documentation references are removed in one conventional-commit change. Nothing is left stubbed or feature-flagged off.
3. **Record it.** `docs/decommission-log.md` is the single record of every cut. Each entry names the archive tag, what the feature was, why it was cut, the exact paths and line counts removed, what else was cleaned, and what was deliberately left alone. Features that were reviewed and kept are logged too, so the decision not to cut is as visible as the cut.
4. **Retire the ADR.** Any ADR that designed the removed feature has its `## Status` set to `Superseded` with the date and a pointer to the log entry, never deleted. A guard test asserts every ADR carries a valid status and that no Accepted ADR references a `src/caliper/` path that no longer exists.

## Consequences

- Removal is cheap and reversible: the tag preserves the code, the log tells a future reader where and why, and the tree stays honest about what it contains.
- The log grows monotonically and is the first place to look before proposing a "new" feature that may already have been cut on purpose.
- Tags are local by default; anyone relying on recovery from a fresh clone must push the archive tags. The log states this explicitly.
- ADRs describe reality by construction: a design record for absent code is marked Superseded, and the path guard fails CI if an Accepted ADR drifts from the tree.
