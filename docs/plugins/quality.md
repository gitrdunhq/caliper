# Quality Plugins

These plugins are **advisory** — they never block a merge. They surface signals that help reviewers make informed decisions.

---

## blast-radius

Counts how many symbols depend on a given function, surfacing the change surface before a reviewer has to guess.

| Severity | Condition |
|----------|-----------|
| Critical | 20+ dependents |
| High | 10–19 dependents |
| Info | < 10 dependents |

> Note: test fixtures routinely have high blast radius — that is healthy coupling, not a smell.

Even advisory, this tells a reviewer whether a one-line change touches 2 callers or 40.

### Graph database location

Reviewing a repo never writes into the repo itself. The code graph SQLite db is resolved in this order:

1. `CALIPER_GRAPH_DB` environment variable — explicit override.
2. `thresholds.blast-radius.graph_db` in `.caliper.yaml` — relative paths resolve against the repo root.
3. A pre-existing legacy `<repo>/.caliper/code_graph.sqlite` keeps being used.
4. Default: `$XDG_CACHE_HOME/caliper/graphs/<repo-hash>/code_graph.sqlite` (`~/.cache` when `XDG_CACHE_HOME` is unset).

`caliper query` reads the same resolved location by default; pass `--db` to point elsewhere.

### Path conventions (library API)

`CodeGraph` stores `symbols.file` and `file_metadata.path` RELATIVE to the repo root. Once a repo root is known (constructor `repo_root=` or inferred by `index_directory()`), every public method — `run_checks`, `run_checks_for_file`, `needs_rebuild`, `rebuild_file`, `rebuild_incremental`, `purge_deleted_files` — accepts either repo-relative or absolute paths and normalizes at the API boundary. Absolute paths outside the repo root raise `ValueError`.

For per-file queries use the convenience API:

```python
graph = CodeGraph(db_path=db, repo_root="/path/to/repo")
findings = graph.run_checks_for_file("/path/to/repo/src/mod.py")  # or "src/mod.py"
```

Without a repo root (ad hoc `CodeGraph()`), paths are stored and matched exactly as given.

---

## complexity

Measures cyclomatic complexity and maintainability index, grading each unit A–F.

| Severity | Condition |
|----------|-----------|
| Warning | Grade C — consider refactoring |
| High | Grade D — refactor recommended |
| Critical | Grade F — significant complexity debt |

Grade C or below is a prompt to simplify, not a hard stop.

Complexity debt compounds silently; surfacing it early costs nothing and saves the next engineer from a maze.

---

## cpd

Detects copy-paste duplication — the same logic repeated across multiple locations.

| Severity | Condition |
|----------|-----------|
| High | 20+ duplicated lines across 3+ sites |
| Warning | 10–19 duplicated lines |

Duplicate code is a quality signal: it is unlikely to pass a thorough human review, and advisory flagging makes that conversation easier to start.

---

## cspell

Spell-checks identifiers and comments throughout the codebase.

| Severity | Condition |
|----------|-----------|
| Warning | Misspelled identifier or symbol name |
| Info | Typo in a comment |

Misspelled names are harder to grep, autocomplete, and explain in code review — a small fix with compounding payoff.

---

## ls-lint

Enforces file and directory naming conventions across the project tree.

| Severity | Condition |
|----------|-----------|
| Warning | File or directory name does not match the configured pattern |

Consistent naming makes navigation predictable and removes the cognitive load of guessing whether a file is `UserService`, `user-service`, or `user_service`.

---

## mypy

Runs cross-file type checking. Prefers pyright (faster, stricter) when available, falls back to mypy.

| Severity | Condition |
|----------|-----------|
| Error | Type incompatibility at a public API boundary |
| Warning | Missing type annotation on a public function |

Advisory — helps reviewers understand type contract violations early without blocking merges. Type mismatches are cheaper to fix in review than to trace in production.

---

## swiftlint

Detects Swift style and code smell violations using 200+ built-in rules plus 13 project-specific custom rules.

| Severity | Condition |
|----------|-----------|
| Warning | Swift style violation or code smell (e.g., force try/cast, NSLock in async context, weak self handling) |

Advisory — surfaces patterns that are unlikely to pass thorough code review, making the conversation about simplification and safety easier to start.

---

## swiftformat

Reports Swift source files that need reformatting. All findings are auto-fixable with `swiftformat .`.

| Severity | Condition |
|----------|-----------|
| Info | File does not match the configured formatting rules |

Advisory — purely informational. Formatting consistency improves readability and reduces review friction.

---

## See also

- [Deterministic detectors](../detectors.md) — 21 AST-based bug-pattern rules (CAL-001..CAL-021) that run alongside the plugins.
