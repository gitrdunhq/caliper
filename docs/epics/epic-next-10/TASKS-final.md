# Implementation Plan (TASKS.md)

## Dependency Graph
```mermaid
graph TD
```

## task-003: Golden-file and property-based tests for report ordering/shape
R1 AC8: a golden-file test renders a fixture list[PluginResult] and compares against a committed expected markdown file; a property test (Hypothesis) asserts AC6 ordering holds for arbitrary finding lists.

- **Acceptance Criteria**:
  - tests/unit/test_renderer_golden.py renders a fixed fixture list[PluginResult] via caliper.core.renderer.render_comment(results, repo='org/repo', pr_num=1, title='golden') and asserts byte-for-byte equality against the committed tests/fixtures/renderer_golden.md
  - tests/unit/test_plugin_properties.py holds a Hypothesis property test that builds arbitrary lists of PluginResult with random severities/files (unique (file,line,rule) per plugin) and asserts render_comment output lists severities in order critical, high, medium, low, info within each plugin section
- **Files**: tests/unit/test_renderer_golden.py, tests/fixtures/renderer_golden.md, tests/unit/test_plugin_properties.py
- **RED Note**: Use ONLY the existing public API caliper.core.renderer.render_comment(results, repo=..., pr_num=..., title=...); do not invent or import render_markdown or any other name (grep src/caliper/core/renderer.py for `def render_` first). Build a small fixed list[PluginResult] fixture with at least three plugins and mixed severities, run render_comment once to author tests/fixtures/renderer_golden.md, commit the fixture, and assert exact equality. The property test must generate findings with unique (file, line, rule_id) per plugin so dedup cannot reorder them, and must parse severity from the rendered lines.
- **Estimated LOC**: 90

## task-019: New ADRs for current practice plus the ADR status guard test
R6 AC2: new ADRs (next free numbers) documenting: semgrep rules pinned to a local snapshot never the registry; test code excluded by default; one severity vocabulary at the plugin boundary (ERROR->high); tag-then-drop decommissioning with the log as the record.

- **Acceptance Criteria**:
  - a new ADR file exists documenting semgrep rules pinned to a local snapshot, with '## Status' = 'Accepted'
  - a new ADR file exists documenting test code excluded by default, with '## Status' = 'Accepted'
  - a new ADR file exists documenting the single severity vocabulary at the plugin boundary (ERROR->high), with '## Status' = 'Accepted'
  - a new ADR file exists documenting tag-then-drop decommissioning with the decommission log as the record, with '## Status' = 'Accepted'
  - each new ADR uses the next free sequential number after the highest existing ADR number
  - test_adr_status parses every file in docs/adr/*.md and asserts each has a '## Status' section with value in {Accepted, Superseded, Proposed}
  - for every ADR whose Status is Accepted, any backtick-quoted path under src/caliper/ referenced in its body actually exists on disk; the test lists the offending ADR filename and path on failure
- **Files**: docs/adr/011-semgrep-rules-pinned-snapshot.md, docs/adr/012-test-code-excluded-by-default.md, docs/adr/013-single-severity-vocabulary.md, docs/adr/014-tag-then-drop-decommissioning.md, tests/unit/test_adr_status.py
- **RED Note**: RED writes tests/unit/test_adr_status.py FIRST with at least five test functions: one per new ADR (011 semgrep snapshot, 012 test-code excluded, 013 severity vocabulary, 014 tag-then-drop) asserting the file exists and has '## Status' == 'Accepted' (these fail until GREEN writes the ADRs), plus test_every_adr_has_valid_status (all docs/adr/*.md Status in {Accepted, Superseded, Proposed}) and test_accepted_adrs_reference_existing_paths (backtick paths under src/caliper/ exist). Confirm the highest existing ADR number in docs/adr/ before fixing the 011-014 names. GREEN then writes the four ADR files in the house format (# ADR-NNN: title / ## Status / ## Context / ## Decision / ## Consequences) with the decision content taken from docs/decommission-log.md, CLAUDE.md and the merged code, and touches nothing else.
- **Estimated LOC**: 110
