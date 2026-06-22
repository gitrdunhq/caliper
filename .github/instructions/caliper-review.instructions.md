---
description: 'Review focus areas for Copilot code review — what deterministic scanners cannot catch'
applyTo: '**'
excludeAgent: ["coding-agent"]
---
# Code Review Focus Areas

caliper's Foreman CI already covers CVEs, secrets, licenses, complexity, duplication, type errors, and AST patterns. Its findings appear as inline PR comments — do not restate them.

Focus on what requires judgment. Use the severity tiers and comment template below.

## Severity Tiers

- **CRITICAL** — Must fix before merge. Blocks ship.
- **IMPORTANT** — Requires discussion or fix this sprint.
- **SUGGESTION** — Non-blocking improvement.

## Comment Template

```
**[PRIORITY] Category: Brief title**

Description of the issue.

**Why this matters:**
Impact if shipped.

**Suggested fix:**
Direction or code example.
```

---

## CRITICAL

### Business logic correctness
- Off-by-one errors in loops and slices
- Incorrect boolean logic or missing match/switch branches
- Silent wrong answers from null/None handling

### Concurrency and race conditions
- Shared mutable state without synchronization
- Check-then-act (TOCTOU) patterns
- Async code that blocks the event loop

### Security logic
- Missing authorization checks on new endpoints
- Privilege escalation paths (user A accesses user B's data)
- Trust boundary violations

---

## IMPORTANT

### Error handling strategy
- Catching too broadly and masking the real error
- Missing rollback/cleanup on partial failure
- Retry logic that can amplify failures

### API and interface design
- Functions with >5 parameters
- Leaking internal types across module boundaries
- Breaking changes without migration

### Data model and migration safety
- Schema changes that lock large tables
- NOT NULL columns without defaults on existing data
- Data type changes that lose precision

### Performance
- N+1 query patterns
- Unbounded collection growth
- Quadratic algorithms where linear exists

### Test quality
- Tests that pass when implementation is deleted
- Only happy-path coverage
- Mocking the thing being tested

### Backwards compatibility
- Removed or renamed public exports
- Changed serialization formats
- Environment variable renames without migration

---

## SUGGESTION

### Naming and readability
- Names that mislead about what the code does
- Functions named "process" or "handle" that do too many things
- Comments that describe WHAT instead of WHY
