"""Watch-mode utilities for the CLI.
# tested-by: tests/unit/test_cli.py
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

import click

_WATCH_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".ts", ".js", ".tf", ".yaml", ".yml", ".json"}
)
_IGNORE_DIRS: frozenset[str] = frozenset({"__pycache__", ".git", ".caliper", ".dogfood"})


class DebounceTimer:
    """Fires a callback once after a quiet period, resetting on each new event."""

    def __init__(self, delay: float, callback: Callable[[], None]) -> None:
        self._delay = delay
        self._callback = callback
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._delay, self._callback)
            self._timer.daemon = True
            self._timer.start()

    def cancel(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()


def watch_and_rerun(repo_path: Path, run_review: Callable[[], None]) -> None:
    """Start a watchdog observer and re-run review on relevant file changes."""
    try:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        click.echo("watchdog is required for --watch mode. Install with: uv add watchdog", err=True)
        return

    debounce = DebounceTimer(delay=0.5, callback=run_review)

    class _Handler(FileSystemEventHandler):
        def on_any_event(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            path = Path(str(event.src_path))
            if path.suffix not in _WATCH_EXTENSIONS:
                return
            for part in path.parts:
                if part in _IGNORE_DIRS:
                    return
            debounce.reset()

    observer = Observer()
    observer.schedule(_Handler(), str(repo_path), recursive=True)
    observer.start()

    click.echo(f"\nWatching {repo_path} for changes (Ctrl+C to exit)…")
    try:
        while observer.is_alive():
            observer.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        debounce.cancel()
        observer.stop()
