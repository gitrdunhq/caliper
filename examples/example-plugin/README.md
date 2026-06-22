# todo-checker — Example Plugin

A minimal working plugin that flags `TODO`, `FIXME`, and `HACK` comments in
Python, TypeScript, and JavaScript files. No external binary required.

Use this as a reference when building your own plugin. The full authoring
guide is at `docs/plugin-sdk.md`.

---

## What It Does

Scans each changed `.py`, `.ts`, or `.js` file line-by-line and emits one
finding per matched pattern:

| Pattern | Severity |
|---------|----------|
| `HACK` | `medium` |
| `FIXME` | `low` |
| `TODO` | `info` |

---

## Files

```
examples/example-plugin/
    todo_checker.py         # plugin implementation
    todo-checker.md.j2      # Jinja2 template for PR comments
    test_todo_checker.py    # 24 tests demonstrating the testing pattern
    conftest.py             # sys.path patch for standalone test runs
    README.md               # this file
```

---

## Installing the Plugin

### Step 1 — Copy the plugin file

```bash
cp examples/example-plugin/todo_checker.py src/caliper/plugins/
```

### Step 2 — Copy the template

```bash
cp examples/example-plugin/todo-checker.md.j2 src/caliper/templates/
```

### Step 3 — Verify it appears in the registry

```bash
uv run caliper plugins
```

You should see `todo-checker` listed under the `quality` category.

### Step 4 — Run it against this repo

```bash
uv run caliper review --repo-path . --all
```

The plugin will scan all tracked files. Any `TODO`, `FIXME`, or `HACK`
comments in `.py`, `.ts`, or `.js` files will appear in the findings output.

---

## Running the Tests

The tests live alongside the plugin and run without installing it first:

```bash
uv run pytest examples/example-plugin/test_todo_checker.py -v
```

Expected output: 24 tests, all passing.

---

## How It Works

### Plugin class

`TodoCheckerPlugin` extends `ScannerPlugin` and implements the five required
members:

```python
class TodoCheckerPlugin(ScannerPlugin):
    name        = "todo-checker"
    description = "Flags TODO, FIXME, and HACK comments ..."
    category    = PluginCategory.quality

    def can_run(self, files, repo_path):
        # Only run when .py, .ts, or .js files are in the changeset
        return any(Path(f).suffix in _CODE_EXTENSIONS for f in files)

    def run(self, files, repo_path):
        # Read each file, scan line-by-line, return findings
        ...
```

### Template

`todo-checker.md.j2` renders findings as a collapsible markdown table in the
PR comment. If there are no findings and no error, the template renders nothing
— the plugin is invisible in a clean PR.

### Auto-discovery

Once `todo_checker.py` is placed in `src/caliper/plugins/`, caliper finds it
automatically. No registration call, no config change, no import to add.

---

## Building Your Own Plugin

1. Copy `todo_checker.py` and rename it to `your_scanner.py`.
2. Change `name`, `description`, `category`, `can_run`, and `run`.
3. Copy `todo-checker.md.j2`, rename it to `your-scanner.md.j2`, and update
   the template to match your finding shape.
4. Write tests following the patterns in `test_todo_checker.py`.
5. Drop the files in `src/caliper/plugins/` and `src/caliper/templates/`.

See `docs/plugin-sdk.md` for the complete reference.
