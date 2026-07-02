# Caliper Plugin SDK

Extend caliper without forking it. A third-party package publishes one or more
scanner plugins under the `caliper.plugins` `importlib.metadata` entry-point
group; caliper discovers and runs them alongside its own 19 in-tree plugins,
with the exact same execution, ordering, and fail-open guarantees.

## The contract

A plugin is any object satisfying the `AnalyzerPort` structural protocol
(`caliper.core.plugin.AnalyzerPort`). The simplest way to implement one is to
subclass `ScannerPlugin` (`caliper.core.plugin.ScannerPlugin`), an `abc.ABC`
that supplies sensible defaults:

```python
from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginFinding, PluginResult, ScannerPlugin


class MyPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "my-plugin"

    @property
    def description(self) -> str:
        return "One-line summary shown in --help / plugin listings."

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality  # dependency | code | infra | quality | supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        """Return False (and caliper records a skip) when your prerequisites aren't met."""
        return any(f.endswith(".py") for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        findings = [
            PluginFinding(
                id="my-plugin-001",
                severity="warning",  # maps through review_summary.level_for
                message="Something worth flagging",
                file=files[0] if files else "",
                line=1,
                category="code_smell",
            )
        ]
        return PluginResult(plugin_name=self.name, findings=findings)
```

### Required members

| Member | Type | Purpose |
|---|---|---|
| `name` | `str` | Stable identifier. Used as the registry key, `--enable`/`--disable` name, and the `plugin_name` on every `PluginResult`. |
| `description` | `str` | One-line summary. |
| `category` | `PluginCategory` | `dependency`, `code`, `infra`, `quality`, or `supply_chain`. Drives diff-scope file selection — `dependency`/`infra`/`supply_chain` always see the full repo file list even in diff mode; the others see only the changed files. |
| `can_run(files, repo_path) -> bool` | method | Gate. Return `False` to skip (caliper records `skip_reason()`/`skip_remediation()` and moves on — this is not an error). |
| `run(files, repo_path) -> PluginResult` | method | Do the scan. Any exception here is caught by the registry, logged, and turned into a `PluginResult(error=...)` — a plugin can never crash the pipeline. |

### Optional members

| Member | Default | Purpose |
|---|---|---|
| `depends_on` | `[]` | List of other plugin names that must run first. `["*"]` means "run after every other plugin in this batch" (the OPA policy-plugin convention). Unknown names are silently dropped; a cycle raises `ValueError` at execution time. |
| `skip_reason() -> (str, str)` | generic message | `(reason, remediation)` surfaced when `can_run` returns `False`. |
| `render(result, template_dir=None) -> str` | Jinja2 lookup + inline fallback | Markdown rendering for the PR-comment format. Only needed if you want custom formatting beyond the generic renderer. |

Every finding you emit is normalized to `PluginFinding` — a frozen value
object with `id`, `severity`, `message`, `file`, `line`, `url`, `category`,
`package`, `version`, `fixed_version`, `rule_id`, `fix_suggestion`, and a free
`metadata` dict. Raw dicts with the same keys are accepted too (they're
normalized on the way in).

## Publishing your plugin

Add an entry-points block to your package's `pyproject.toml` under the
`caliper.plugins` group. The value is a zero-argument callable — typically the
plugin class itself — that returns a plugin instance when called:

```toml
[project]
name = "caliper-plugin-mytool"
version = "0.1.0"
dependencies = ["caliper"]

[project.entry-points."caliper.plugins"]
mytool = "caliper_plugin_mytool.plugin:MyPlugin"
```

Once your package is installed alongside caliper (`pip install caliper-plugin-mytool`),
`caliper review` picks it up automatically — no config, no fork, no PR against
this repo.

## Fail-open guarantee

Discovery (`caliper.plugins._discover_entry_point_plugins`) never raises:

- If the entry-point metadata backend itself errors, caliper logs
  `plugin_sdk.entry_points_lookup_failed` and falls back to only its in-tree
  plugins.
- If loading or constructing one entry point raises, caliper logs
  `plugin_sdk.plugin_load_failed` for that entry point and skips it — every
  other third-party and in-tree plugin still runs.
- Once registered, your plugin gets the same per-run exception handling as
  every built-in plugin: a `run()` that raises becomes a logged,
  `error`-tagged `PluginResult`, never an uncaught exception.

## Minimal example package layout

```
caliper-plugin-mytool/
├── pyproject.toml
└── src/
    └── caliper_plugin_mytool/
        ├── __init__.py
        └── plugin.py        # defines MyPlugin(ScannerPlugin)
```

See `tests/unit/test_plugin_sdk.py` for a runnable fake-entry-point example
exercising discovery, registration, and the fail-open path.
