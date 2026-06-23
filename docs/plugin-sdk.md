# Plugin SDK Reference

Caliper's plugin system lets you add new scanners, linters, and analyzers
without touching the core pipeline. Every plugin is a Python class that implements
the `ScannerPlugin` ABC. Drop the file in the right directory and it is discovered
automatically on the next run.

---

## Quick Start

A minimal plugin that requires no external binary — paste this, drop it in
`src/caliper/plugins/`, and it will appear in `caliper plugins` on the next run.

```python
from __future__ import annotations

from pathlib import Path
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin


class HelloPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "hello"

    @property
    def description(self) -> str:
        return "Example plugin — greets every Python file"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(f.endswith(".py") for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        py_files = [f for f in files if f.endswith(".py")]
        findings = [{"file": f, "message": "hello from caliper", "severity": "info"} for f in py_files]
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )
```

That is the complete contract. The sections below explain every piece.

---

## ScannerPlugin ABC Contract

```python
# src/caliper/core/plugin.py
class ScannerPlugin(abc.ABC):
```

Every plugin must be a concrete subclass of `ScannerPlugin`. Five abstract
members must be implemented. Omitting any one raises `TypeError` at import time.

### `name: str` (abstract property)

The unique registry key for this plugin. Must be lowercase, hyphen-separated,
and stable — the CLI, config, and templates all reference it by this string.

```python
@property
def name(self) -> str:
    return "my-scanner"
```

Two plugins with the same name cannot coexist in a registry. The second
registration silently overwrites the first.

### `description: str` (abstract property)

One sentence. Shown in `caliper plugins` listings and in log output.

```python
@property
def description(self) -> str:
    return "Detects hardcoded credentials in source files"
```

### `category: PluginCategory` (abstract property)

Controls grouping and filter flags (`--category`). One of:

```python
class PluginCategory(StrEnum):
    dependency   = "dependency"   # package managers, SBOM, supply chain
    code         = "code"         # AST patterns, security, style
    infra        = "infra"        # Kubernetes, Docker, Terraform
    quality      = "quality"      # complexity, spelling, naming conventions
    supply_chain = "supply_chain" # license, malware, provenance
```

```python
@property
def category(self) -> PluginCategory:
    return PluginCategory.code
```

### `can_run(files, repo_path) -> bool`

Called before `run`. Return `True` only if this plugin has something to scan.
The registry skips `run` entirely when `can_run` returns `False`, recording a
`{"status": "skipped"}` summary.

```python
def can_run(self, files: list[str], repo_path: Path) -> bool:
    # Guard on file extensions
    return any(f.endswith(".py") for f in files)

# Or guard on a config file presence:
def can_run(self, files: list[str], repo_path: Path) -> bool:
    return (repo_path / ".my-tool.yml").exists()
```

`files` is the list of changed file paths (absolute or relative strings, as
passed by the caller). `repo_path` is the absolute `Path` to the repo root.

### `run(files, repo_path) -> PluginResult`

Execute the scan and return a `PluginResult`. This method **must not raise** —
catch all exceptions internally and encode failures in the returned result. The
registry catches any uncaught exception and wraps it in an error result, but
that is a safety net, not a contract.

```python
def run(self, files: list[str], repo_path: Path) -> PluginResult:
    findings = []
    # ... scan logic ...
    return PluginResult(
        plugin_name=self.name,
        findings=findings,
        summary={"total": len(findings)},
    )
```

---

## PluginResult

```python
@dataclass
class PluginResult:
    plugin_name: str
    findings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""
```

| Field | Type | Required | Purpose |
|---|---|---|---|
| `plugin_name` | `str` | yes | Must equal `self.name` |
| `findings` | `list[dict]` | no | One dict per finding |
| `summary` | `dict` | no | Aggregate stats shown in the header |
| `error` | `str` | no | Non-empty string signals a failed run |

When `error` is non-empty, `findings` should be empty. Templates and renderers
check `error` first and short-circuit to an error message.

### Constructing results

```python
# Clean run, no findings
return PluginResult(plugin_name=self.name, summary={"total": 0})

# Clean run with findings
return PluginResult(
    plugin_name=self.name,
    findings=[...],
    summary={"total": len(findings)},
)

# Failed run — binary not installed, parse error, etc.
return PluginResult(plugin_name=self.name, error="[NOT_INSTALLED] mytool not installed")
```

---

## Finding Dict Shape

Findings are plain dicts. There is no enforced schema — use whatever keys your
renderer needs. These are the keys that appear across the built-in plugins:

| Key | Type | Used by |
|---|---|---|
| `file` | `str` | Nearly every plugin |
| `line` | `int` | Line-level scanners |
| `message` | `str` | Human-readable description |
| `severity` | `str` | `critical`, `high`, `medium`, `low`, `info` |
| `rule_id` | `str` | Rule-based scanners (Semgrep, OPA) |
| `start_line` | `int` | Range-aware scanners |
| `end_line` | `int` | Range-aware scanners |
| `word` | `str` | Spell checker |
| `function` | `str` | Complexity analysis |

Use consistent keys within your plugin. The summary dict should contain totals
that let the template render a useful header without iterating findings.

---

## Error Handling

`ErrorCode` is a `StrEnum` with 10 codes. Use `error_msg()` to format them
consistently.

```python
from caliper.core.errors import ErrorCode, error_msg
```

### ErrorCode values

```python
class ErrorCode(StrEnum):
    NOT_INSTALLED    = "NOT_INSTALLED"     # binary not on PATH
    TIMEOUT          = "TIMEOUT"           # subprocess exceeded timeout
    PARSE_ERROR      = "PARSE_ERROR"       # could not parse tool output
    PERMISSION_DENIED = "PERMISSION_DENIED" # file system access denied
    BINARY_CRASHED   = "BINARY_CRASHED"    # non-zero exit with no output
    NO_OUTPUT        = "NO_OUTPUT"         # tool ran but produced nothing
    SCANNER_DEGRADED = "SCANNER_DEGRADED"  # partial failure, results unreliable
    CONFIG_MISSING   = "CONFIG_MISSING"    # required config file not found
    INDEX_FAILED     = "INDEX_FAILED"      # indexing / init step failed
    NETWORK_ERROR    = "NETWORK_ERROR"     # network call failed
```

### `error_msg(code, tool, **kwargs) -> str`

Returns a formatted error string with the code prefix: `[CODE] message`.

```python
error_msg(ErrorCode.NOT_INSTALLED, "mytool")
# "[NOT_INSTALLED] mytool not installed"

error_msg(ErrorCode.TIMEOUT, "mytool", timeout=60)
# "[TIMEOUT] mytool timed out after 60s"

error_msg(ErrorCode.BINARY_CRASHED, "mytool", exit_code=1)
# "[BINARY_CRASHED] mytool crashed (exit 1)"

error_msg(ErrorCode.CONFIG_MISSING, "mytool", path=".mytool.yml")
# "[CONFIG_MISSING] mytool config not found at .mytool.yml"
```

### Pattern for subprocess-based plugins

```python
def run(self, files: list[str], repo_path: Path) -> PluginResult:
    try:
        r = subprocess.run(
            ["mytool", "--json", *files],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(repo_path),
            check=False,
        )
    except FileNotFoundError:
        return PluginResult(
            plugin_name=self.name,
            error=error_msg(ErrorCode.NOT_INSTALLED, "mytool"),
        )
    except subprocess.TimeoutExpired:
        return PluginResult(
            plugin_name=self.name,
            error=error_msg(ErrorCode.TIMEOUT, "mytool", timeout=60),
        )

    if r.returncode != 0 and not r.stdout:
        return PluginResult(
            plugin_name=self.name,
            error=error_msg(ErrorCode.BINARY_CRASHED, "mytool", exit_code=r.returncode),
        )
    # ... parse r.stdout ...
```

---

## Auto-Discovery

`discover_plugins(plugin_dir)` in `src/caliper/core/registry.py` scans a directory
for concrete `ScannerPlugin` subclasses and returns one instantiated instance per
class found.

Rules:
- Only `*.py` files are loaded. Other file types are ignored.
- Files whose names start with `_` are skipped. (`__init__.py`, `_runners/` are safe.)
- Every class in the module that is a subclass of `ScannerPlugin` and is not
  `ScannerPlugin` itself is instantiated and included.
- Modules that fail to import are logged as warnings and skipped — a broken
  plugin never prevents other plugins from loading.

### Where to place plugins

```
src/caliper/plugins/
    my_scanner.py        # discovered — becomes "my-scanner" (via name property)
    _helpers.py          # skipped — underscore prefix
    _runners/            # skipped — directory, not *.py at this level
    __init__.py          # skipped — underscore prefix
```

The plugin's registry key is whatever `name` returns, not the filename. By
convention, use the filename to reflect the name (e.g., `my_scanner.py` for a
plugin named `"my-scanner"`), but it is not enforced.

---

## Jinja2 Templates

Plugins can render their results to markdown via a Jinja2 template. This is the
preferred path for plugins with structured output — tables, grouped sections,
conditional blocks.

### How rendering works

When `plugin.render(result)` is called (e.g., when building a PR comment):

1. The framework looks for `{template_dir}/{plugin.name}.md.j2`.
2. If found, the template is rendered with the context from `_template_context(result)`.
3. If not found, `_render_inline(result)` is called as a fallback.

The default template directory is `src/caliper/templates/`.

### Default template context

`_template_context` provides these variables to every template:

```python
{
    "result": result,         # the full PluginResult object
    "findings": result.findings,
    "summary": result.summary,
    "error": result.error,
    "plugin_name": result.plugin_name,
}
```

### Writing a template

Create `src/caliper/templates/{plugin-name}.md.j2`:

```jinja2
{% if error %}
**my-scanner**: {{ error }}
{% elif findings %}
<details open><summary><b>My Scanner ({{ findings | length }})</b></summary>

| File | Line | Message | Severity |
|------|------|---------|----------|
{% for f in findings %}
| `{{ f.file }}` | {{ f.line }} | {{ f.message }} | {{ f.severity }} |
{% endfor %}

</details>

{% endif %}
```

The template renders nothing when there are no findings and no error — the outer
pipeline concatenates all non-empty renders into the final PR comment.

### Adding custom template variables

Override `_template_context` to inject pre-processed data:

```python
def _template_context(self, result: PluginResult) -> dict:
    ctx = super()._template_context(result)   # always call super() first
    ctx["critical"] = [f for f in result.findings if f.get("severity") == "critical"]
    ctx["high"] = [f for f in result.findings if f.get("severity") == "high"]
    ctx["total_by_severity"] = {
        "critical": len(ctx["critical"]),
        "high": len(ctx["high"]),
    }
    return ctx
```

Then reference `critical`, `high`, and `total_by_severity` directly in the template.

### Inline fallback

If your plugin does not ship a template, override `_render_inline` instead of
`render`. The base class `render` calls `_render_inline` automatically when no
template file is found.

```python
def _render_inline(self, result: PluginResult) -> str:
    if result.error:
        return f"**{self.name}**: {result.error}"
    if not result.findings:
        return ""
    lines = ["<details>", f"<summary><b>{self.name} ({len(result.findings)})</b></summary>\n"]
    for f in result.findings:
        lines.append(f"- `{f['file']}:{f['line']}` — {f['message']}")
    lines.append("\n</details>\n")
    return "\n".join(lines)
```

---

## Subprocess Helpers

For plugins that call external binaries, use `run_subprocess_with_timeout` from
`caliper.data.scanners.base`. It wraps `subprocess.run` and returns a consistent
tuple — it never raises.

```python
from caliper.data.scanners.base import run_subprocess_with_timeout

returncode, stdout, stderr = run_subprocess_with_timeout(
    cmd=["mytool", "--json", str(repo_path)],
    timeout=60,
    cwd=repo_path,
)
```

Return value:

| Position | Type | Value |
|---|---|---|
| 0 | `int \| None` | Process exit code, or `None` on timeout / OS error |
| 1 | `str` | stdout |
| 2 | `str` | stderr |

`None` returncode signals that the process never completed — treat it the same
as a timeout or `NOT_INSTALLED` error depending on context.

### Direct `subprocess.run` is also acceptable

Many built-in plugins call `subprocess.run` directly (see `ls_lint.py`,
`typos.py`). Both approaches are valid. Use `run_subprocess_with_timeout` when
you want the structured return tuple and centralised timeout logging; use
`subprocess.run` directly when you need finer control over error handling.

---

## Testing Your Plugin

The pattern used across all built-in tests and in `examples/example-plugin/`:

### 1. Test `can_run`

```python
from pathlib import Path
from my_scanner import MyScannerPlugin

def test_can_run_returns_true_when_target_files_present(tmp_path: Path):
    plugin = MyScannerPlugin()
    assert plugin.can_run(["src/app.py"], tmp_path) is True

def test_can_run_returns_false_for_empty_list(tmp_path: Path):
    plugin = MyScannerPlugin()
    assert plugin.can_run([], tmp_path) is False
```

### 2. Test findings on real temp files

Write actual content to `tmp_path` (pytest's built-in fixture) and pass the
paths to `plugin.run`. This avoids subprocess mocking for pure-Python plugins.

```python
def test_detects_violation(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("# FIXME: this is broken\n")
    plugin = MyScannerPlugin()
    result = plugin.run([str(f)], tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "low"
```

### 3. Test subprocess-based plugins with `unittest.mock.patch`

```python
from unittest.mock import patch

def test_handles_not_installed(tmp_path: Path):
    plugin = MyScannerPlugin()
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = plugin.run(["src/app.py"], tmp_path)
    assert "NOT_INSTALLED" in result.error

def test_handles_timeout(tmp_path: Path):
    import subprocess
    plugin = MyScannerPlugin()
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("mytool", 60)):
        result = plugin.run(["src/app.py"], tmp_path)
    assert "TIMEOUT" in result.error
```

### 4. Assert on concrete values, not existence

```python
# WRONG — passes even if run() returns garbage
assert result is not None

# CORRECT — verifies the actual contract
assert result.findings[0]["file"] == str(f)
assert result.findings[0]["line"] == 3
assert result.summary["total"] == 1
```

### 5. sys.path for standalone example plugins

If your tests live outside the main package tree (e.g., in `examples/`), add a
`conftest.py` that puts the plugin file on `sys.path`:

```python
# conftest.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
```

Then import the plugin directly by filename: `from my_scanner import MyScannerPlugin`.

---

## Full Example: See `examples/example-plugin/`

The `examples/example-plugin/` directory contains a complete, working plugin:

- `todo_checker.py` — pure-Python plugin, no external binary
- `todo-checker.md.j2` — Jinja2 template for rendering findings
- `test_todo_checker.py` — 24 tests covering all the patterns above
- `conftest.py` — `sys.path` patch for standalone test runs
- `README.md` — installation walkthrough

Run the tests:

```bash
uv run pytest examples/example-plugin/test_todo_checker.py -v
```

To install the plugin and see it run against this repo:

```bash
cp examples/example-plugin/todo_checker.py src/caliper/plugins/
cp examples/example-plugin/todo-checker.md.j2 src/caliper/templates/
uv run caliper plugins                        # verify it appears
uv run caliper review --repo-path . --all     # see it in action
```
