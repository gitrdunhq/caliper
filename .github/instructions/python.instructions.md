---
description: 'Python conventions for caliper codebase'
applyTo: '**/*.py'
---
# Python Conventions

## Style
- `structlog` for logging, never `print()`
- Enums for all state fields, never raw strings
- Typed Pydantic models at every boundary
- `orjson` over stdlib `json` for performance-sensitive paths
- `httpx` over `requests`

## Architecture
- Three-tier: cli → core → data. No upward imports.
- Presentation layers are thin — parse, delegate, format
- Business logic is pure functions where possible (no I/O)
- Every source file carries `# tested-by: tests/unit/test_X.py`

## Error Handling
- Let errors propagate from business logic — catch only at boundaries
- No bare `except:` — always specify the type
- Fail-open for scanner plugins: return `PluginResult(error=...)`, never raise

## Testing
- TDD: failing test first, then implementation
- `pytest` with `hypothesis` for property-based tests at trust boundaries
- Prefer fakes over mocks; mock at boundaries, not the SUT
- Assertions must verify concrete values, not just truthiness

## Example

```python
# Good — typed, structured, fail-open
def run(self, files: list[str], repo_path: Path, timeout: int = 60) -> PluginResult:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return PluginResult(plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "tool"))

# Bad — bare exception, silent failure
def run(self, files, repo_path):
    try:
        r = subprocess.run(cmd)
    except:
        return None
```
