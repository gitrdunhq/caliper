## Summary

<!-- What does this PR do? 1-3 bullet points. -->

## Changes

<!-- List the key files/modules changed and why. -->

## Test Plan

- [ ] Unit tests pass (`uv run pytest tests/ -v`)
- [ ] Lint passes (`uv run ruff check src/ tests/`)
- [ ] Format passes (`uv run black --check src/ tests/`)
- [ ] OPA policy tests pass (`opa test policies/ --ignore '*.yaml' --ignore '*.yml'`)

## Evidence

<!-- For dependency changes: link to evidence artifacts or paste decision summary. -->

## Checklist

- [ ] No secrets in code or comments
- [ ] Fail-open contract maintained (no new blocking failure paths)
- [ ] `# tested-by:` annotation on new source files
- [ ] ADR written for significant architectural decisions
