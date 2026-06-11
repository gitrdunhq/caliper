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

1. `EEDOM_GRAPH_DB` environment variable — explicit override.
2. `thresholds.blast-radius.graph_db` in `.eagle-eyed-dom.yaml` — relative paths resolve against the repo root.
3. A pre-existing legacy `<repo>/.eedom/code_graph.sqlite` keeps being used.
4. Default: `$XDG_CACHE_HOME/eedom/graphs/<repo-hash>/code_graph.sqlite` (`~/.cache` when `XDG_CACHE_HOME` is unset).

`eedom query` reads the same resolved location by default; pass `--db` to point elsewhere.

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
